#include "monitor.h"
#include "analyzer.h"
#include "baseline.h"
#include "explain.h"
#include "report.h"
#include "util.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* What was flagged in one cycle: module name + a key made of its findings. */
typedef struct {
    char name[MAX_MODULE_NAME];
    char key[256];
    int score;
    risk_level_t level;
} flagged_t;

typedef struct {
    flagged_t *v;
    int n;
} snapshot_t;

static void snapshot_build(const analysis_t *an, snapshot_t *s)
{
    memset(s, 0, sizeof(*s));
    s->v = calloc((size_t)(an->count + 1), sizeof(*s->v));
    if (!s->v)
        return;
    for (int i = 0; i < an->count; i++) {
        const module_result_t *r = &an->items[i];
        if (r->score <= 0)
            continue;
        flagged_t *f = &s->v[s->n++];
        util_copy(f->name, sizeof(f->name), r->name);
        f->score = r->score;
        f->level = r->level;
        size_t off = 0;
        for (int k = 0; k < r->nfindings; k++) {
            int w = snprintf(f->key + off, sizeof(f->key) - off, "%s%s", k ? "," : "",
                             r->findings[k].rule);
            if (w < 0 || (size_t)w >= sizeof(f->key) - off)
                break;
            off += (size_t)w;
        }
    }
}

static const flagged_t *snapshot_find(const snapshot_t *s, const char *name)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->v[i].name, name) == 0)
            return &s->v[i];
    return NULL;
}

static void snapshot_free(snapshot_t *s)
{
    free(s->v);
    memset(s, 0, sizeof(*s));
}

static void clock_str(time_t t, char *buf, size_t sz)
{
    struct tm tmv;
    if (!localtime_r(&t, &tmv) || !strftime(buf, sz, "%H:%M:%S", &tmv))
        snprintf(buf, sz, "--:--:--");
}

static void json_str(FILE *out, const char *s)
{
    fputc('"', out);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            fprintf(out, "\\%c", c);
        else if (c < 0x20 || c >= 0x7f)
            fprintf(out, "\\u%04x", c);
        else
            fputc(c, out);
    }
    fputc('"', out);
}

static void log_line(const monitor_opts_t *o, const char *line)
{
    if (!o->log_path)
        return;
    FILE *f = fopen(o->log_path, "a");
    if (!f)
        return;
    fprintf(f, "%s\n", line);
    fclose(f);
}

typedef struct {
    const monitor_opts_t *o;
    int live;        /* a status line is currently shown on the terminal */
    int alerts;
    risk_level_t worst;
} mon_t;

static void clear_status(mon_t *m)
{
    if (m->live) {
        fputs("\r\033[K", stdout);
        m->live = 0;
    }
}

/* One alert (new / changed / initial finding) for a flagged module. */
static void emit_alert(mon_t *m, const char *label, const module_result_t *r,
                       const report_ctx_t *ctx, time_t now)
{
    const monitor_opts_t *o = m->o;
    const ui_t *ui = &o->ui;
    char ts[16], rules[256] = "", line[512];
    clock_str(now, ts, sizeof(ts));
    size_t off = 0;
    for (int k = 0; k < r->nfindings; k++) {
        int w = snprintf(rules + off, sizeof(rules) - off, "%s%s", k ? "," : "",
                         r->findings[k].rule);
        if (w < 0 || (size_t)w >= sizeof(rules) - off)
            break;
        off += (size_t)w;
    }
    m->alerts++;
    if (r->level > m->worst)
        m->worst = r->level;

    snprintf(line, sizeof(line), "[%s] %-8s %-8s %s score=%d rules=%s", ts, label,
             risk_level_name(r->level), r->name, r->score, rules);
    log_line(o, line);

    clear_status(m);
    if (o->json) {
        printf("{\"time\":%ld,\"event\":\"alert\",\"kind\":", (long)now);
        json_str(stdout, label);
        printf(",\"module\":");
        json_str(stdout, r->name);
        printf(",\"level\":\"%s\",\"score\":%d,\"rules\":[", risk_level_name(r->level),
               r->score);
        for (int k = 0; k < r->nfindings; k++) {
            if (k)
                putchar(',');
            json_str(stdout, r->findings[k].rule);
        }
        printf("]}\n");
        fflush(stdout);
        return;
    }
    if (!ui_fancy(ui)) {
        printf("%s\n", line);
        if (o->explain)
            for (int k = 0; k < r->nfindings; k++) {
                printf("          %s: %s\n", r->findings[k].rule, r->findings[k].reason);
                explain_finding(stdout, ctx, r, &r->findings[k], NULL, "            ");
            }
        fflush(stdout);
        return;
    }
    char bar[32];
    ui_bar(ui, bar, sizeof(bar), r->score, RISK_MAX_SCORE, 10);
    printf("\n %s%s%s %s%s %-8s%s %s%-24s%s %s%s%s %3d/100\n",
           ui_style(ui, UI_GREY), ts, ui_style(ui, UI_RESET), ui_level_style(ui, r->level),
           "", risk_level_name(r->level), ui_style(ui, UI_RESET), ui_style(ui, UI_BOLD),
           r->name, ui_style(ui, UI_RESET), ui_level_style(ui, r->level), bar,
           ui_style(ui, UI_RESET), r->score);
    printf("   %s%s%s %s\n", ui_style(ui, UI_YELLOW), ui_sym(ui, UI_SYM_WARN),
           ui_style(ui, UI_RESET), label);
    for (int k = 0; k < r->nfindings; k++) {
        printf("      %s+%-3d%s %-19s %s%s%s\n", ui_level_style(ui, r->level),
               r->findings[k].weight, ui_style(ui, UI_RESET), r->findings[k].rule,
               ui_style(ui, UI_DIM), r->findings[k].reason, ui_style(ui, UI_RESET));
        if (o->explain)
            explain_finding(stdout, ctx, r, &r->findings[k], ui, "            ");
    }
    fflush(stdout);
}

static void emit_note(mon_t *m, const char *event, const char *text, time_t now, int is_alert)
{
    const monitor_opts_t *o = m->o;
    const ui_t *ui = &o->ui;
    char ts[16], line[600];
    clock_str(now, ts, sizeof(ts));
    snprintf(line, sizeof(line), "[%s] %s %s", ts, event, text);
    log_line(o, line);
    clear_status(m);
    if (is_alert) {
        m->alerts++;
        m->worst = RISK_CRITICAL;
    }
    if (o->json) {
        printf("{\"time\":%ld,\"event\":", (long)now);
        json_str(stdout, event);
        printf(",\"detail\":");
        json_str(stdout, text);
        printf("}\n");
    } else if (ui_fancy(ui)) {
        const char *color = is_alert ? ui_level_style(ui, RISK_HIGH) : ui_style(ui, UI_GREEN);
        printf("\n %s%s%s %s%s %s%s%s %s\n", ui_style(ui, UI_GREY), ts, ui_style(ui, UI_RESET),
               color, ui_sym(ui, is_alert ? UI_SYM_FAIL : UI_SYM_OK), event, ui_style(ui, UI_RESET),
               "", text);
    } else {
        printf("%s\n", line);
    }
    fflush(stdout);
}

static void sleep_ms(int ms)
{
    while (ms > 0 && !g_stop) {
        int step = ms > 50 ? 50 : ms;
        struct timespec ts = {0, step * 1000000L};
        nanosleep(&ts, NULL);
        ms -= step;
    }
}

int monitor_run(const monitor_opts_t *o)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    g_stop = 0;

    mon_t m = {o, 0, 0, RISK_NONE};
    snapshot_t prev = {0, 0};
    int scans = 0, baseline_bad = 0;
    int tty = isatty(fileno(stdout)) && ui_fancy(&o->ui) && !o->json;

    while (!g_stop) {
        scan_result_t scan;
        char err[256];
        time_t now = time(NULL);
        if (scan_run(&o->scan, &scan, err, sizeof(err)) != 0) {
            if (scans == 0) {
                fprintf(stderr, "error: scan failed: %s\n", err);
                snapshot_free(&prev);
                return 2;
            }
            emit_note(&m, "SCAN-FAILED", err, now, 1);
            sleep_ms(o->interval_ms);
            continue;
        }

        baseline_t base;
        int have = 0;
        struct stat st;
        if (stat(o->baseline_path, &st) == 0) {
            char berr[256];
            if (baseline_load(o->baseline_path, &base, berr, sizeof(berr)) == 0) {
                have = 1;
                if (baseline_bad) {
                    baseline_bad = 0;
                    emit_note(&m, "BASELINE-OK", "baseline file is valid again", now, 0);
                }
            } else if (!baseline_bad) {
                baseline_bad = 1;
                emit_note(&m, "BASELINE-INVALID", berr, now, 1);
            }
        }

        analysis_t an;
        if (analyzer_run(&scan, have ? &base : NULL, &an) != 0) {
            scan_free(&scan);
            if (have)
                baseline_free(&base);
            snapshot_free(&prev);
            return 2;
        }
        scans++;

        int in_proc = 0;
        for (int i = 0; i < scan.records.count; i++)
            in_proc += scan.records.items[i].in_proc;

        if (scans == 1 && !o->json) {
            char ts[16], l1[128], l2[160];
            clock_str(now, ts, sizeof(ts));
            snprintf(l1, sizeof(l1), "monitoring %d modules every %.1f s", in_proc,
                     o->interval_ms / 1000.0);
            snprintf(l2, sizeof(l2), "baseline: %s", have ? o->baseline_path : "none (heuristics only)");
            if (ui_fancy(&o->ui)) {
                const char *lines[] = {"KMRD - live monitor", l1, l2, "Ctrl+C to stop"};
                printf("\n");
                ui_box(&o->ui, stdout, lines, 4, 52);
            } else {
                printf("[%s] %s (%s; Ctrl+C to stop)\n", ts, l1, l2);
            }
            fflush(stdout);
        }

        snapshot_t cur;
        snapshot_build(&an, &cur);
        report_ctx_t ctx = {&scan, &an, have ? &base : NULL, o->baseline_path, NULL, 0,
                            &o->ui, o->explain, o->scan.proc_path, o->scan.sys_root};

        for (int i = 0; i < an.count && an.items[i].score > 0; i++) {
            const module_result_t *r = &an.items[i];
            const flagged_t *was = snapshot_find(&prev, r->name);
            if (!was)
                emit_alert(&m, scans == 1 ? "INITIAL" : "ALERT", r, &ctx, now);
            else if (strcmp(was->key, snapshot_find(&cur, r->name)->key) != 0)
                emit_alert(&m, "CHANGED", r, &ctx, now);
        }
        for (int i = 0; i < prev.n; i++)
            if (!snapshot_find(&cur, prev.v[i].name)) {
                char text[96];
                snprintf(text, sizeof(text), "%s is no longer flagged", prev.v[i].name);
                emit_note(&m, "RESOLVED", text, now, 0);
            }

        if (tty) {
            char ts[16];
            clock_str(now, ts, sizeof(ts));
            printf("\r\033[K  %s%s%s watching %d modules  %s|%s  scan #%d  %s|%s  %s  %s|%s  %s%d flagged%s",
                   ui_level_style(&o->ui, an.flagged ? an.max_level : RISK_NONE),
                   ui_sym(&o->ui, UI_SYM_DOT), ui_style(&o->ui, UI_RESET), in_proc,
                   ui_style(&o->ui, UI_GREY), ui_style(&o->ui, UI_RESET), scans,
                   ui_style(&o->ui, UI_GREY), ui_style(&o->ui, UI_RESET), ts,
                   ui_style(&o->ui, UI_GREY), ui_style(&o->ui, UI_RESET),
                   ui_level_style(&o->ui, an.flagged ? an.max_level : RISK_NONE), an.flagged,
                   ui_style(&o->ui, UI_RESET));
            fflush(stdout);
            m.live = 1;
        }

        snapshot_free(&prev);
        prev = cur;
        analyzer_free(&an);
        scan_free(&scan);
        if (have)
            baseline_free(&base);

        if (o->max_scans && scans >= o->max_scans)
            break;
        sleep_ms(o->interval_ms);
    }

    clear_status(&m);
    time_t end = time(NULL);
    if (o->json) {
        printf("{\"time\":%ld,\"event\":\"stopped\",\"scans\":%d,\"alerts\":%d}\n", (long)end,
               scans, m.alerts);
    } else {
        char ts[16];
        clock_str(end, ts, sizeof(ts));
        printf("%s[%s] stopped after %d scan(s), %d alert(s)%s\n",
               ui_fancy(&o->ui) ? "\n" : "", ts, scans, m.alerts, "");
    }
    fflush(stdout);
    snapshot_free(&prev);
    return m.alerts && m.worst >= o->fail_on ? 1 : 0;
}
