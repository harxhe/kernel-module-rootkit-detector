#include "report.h"
#include "explain.h"
#include <string.h>
#include <time.h>

/* Styled report: the same facts as report_text(), laid out for a terminal.
   Only used when stdout is a terminal (or --ui fancy). */

#define BOX_INNER 64
#define BAR_WIDTH 10

static void fmt_time(time_t t, char *buf, size_t sz)
{
    struct tm tmv;
    if (!localtime_r(&t, &tmv) || !strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &tmv))
        snprintf(buf, sz, "%ld", (long)t);
}

static int count_in_proc(const scan_result_t *s)
{
    int n = 0;
    for (int i = 0; i < s->records.count; i++)
        n += s->records.items[i].in_proc;
    return n;
}

static void badge(FILE *out, const ui_t *ui, risk_level_t lvl, const char *text)
{
    fprintf(out, "%s %-8s %s", ui_level_style(ui, lvl), text, ui_style(ui, UI_RESET));
}

void report_fancy(FILE *out, const report_ctx_t *c)
{
    const ui_t *ui = c->ui;
    const scan_result_t *s = c->scan;
    const analysis_t *a = c->analysis;
    const char *R = ui_style(ui, UI_RESET), *B = ui_style(ui, UI_BOLD);
    const char *D = ui_style(ui, UI_DIM), *Y = ui_style(ui, UI_YELLOW);
    char when[32], l1[160], l2[160], l3[200];

    fmt_time(s->when, when, sizeof(when));
    snprintf(l1, sizeof(l1), "KMRD %s Kernel Module Rootkit Detector",
             ui->unicode ? "\xc2\xb7" : "-");
    snprintf(l2, sizeof(l2), "kernel %s  %s  %d modules  %s  %s", s->kernel,
             ui->unicode ? "\xc2\xb7" : "|", count_in_proc(s),
             ui->unicode ? "\xc2\xb7" : "|", when);
    if (a->env.has_baseline)
        snprintf(l3, sizeof(l3), "baseline %s (%d modules)", c->baseline_path,
                 c->baseline->count);
    else
        snprintf(l3, sizeof(l3), "baseline: none");
    const char *lines[] = {l1, l2, l3};
    fputc('\n', out);
    ui_box(ui, out, lines, 3, BOX_INNER);

    /* notes: checks that were skipped */
    fputc('\n', out);
    if (!a->env.has_baseline)
        fprintf(out, "  %s%s%s heuristic rules only (%s)\n", Y,
                ui_sym(ui, UI_SYM_WARN), R,
                c->baseline_note ? c->baseline_note : "no baseline");
    if (a->env.kernel_mismatch)
        fprintf(out, "  %s%s%s baseline is from kernel %s: size/srcversion/deps checks skipped\n",
                Y, ui_sym(ui, UI_SYM_WARN), R, c->baseline->kernel);
    if (!a->env.sysfs_available)
        fprintf(out, "  %s%s%s /sys/module unreadable: hidden-module cross-check skipped\n",
                Y, ui_sym(ui, UI_SYM_WARN), R);
    if (!a->env.moddep_available)
        fprintf(out, "  %s%s%s modules.dep not found: location check skipped\n", Y,
                ui_sym(ui, UI_SYM_WARN), R);
    if (s->proc_skipped)
        fprintf(out, "  %s%s%s %d malformed /proc/modules line(s) ignored\n", Y,
                ui_sym(ui, UI_SYM_WARN), R, s->proc_skipped);

    /* verdict */
    fputc('\n', out);
    if (!a->flagged) {
        fprintf(out, "  %sVERDICT%s  %s%s CLEAN%s   no suspicious modules detected\n", B, R,
                ui_level_style(ui, RISK_NONE), ui_sym(ui, UI_SYM_OK), R);
    } else {
        fprintf(out, "  %sVERDICT%s ", B, R);
        badge(out, ui, a->max_level, risk_level_name(a->max_level));
        fprintf(out, "  %d module(s) flagged   ", a->flagged);
        const risk_level_t order[] = {RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW};
        for (int i = 0; i < 4; i++)
            fprintf(out, "%s%s %d%s  ", ui_level_style(ui, order[i]),
                    risk_level_name(order[i]), a->counts[order[i]], R);
        fputc('\n', out);
    }

    /* flagged modules */
    char bar[BAR_WIDTH * 3 + 1];
    for (int i = 0; i < a->count; i++) {
        const module_result_t *r = &a->items[i];
        if (r->score == 0)
            continue;
        ui_bar(ui, bar, sizeof(bar), r->score, RISK_MAX_SCORE, BAR_WIDTH);
        fputc('\n', out);
        fputs("  ", out);
        badge(out, ui, r->level, risk_level_name(r->level));
        fprintf(out, " %s%-26s%s %s%s%s %3d/100\n", B, r->name, R,
                ui_level_style(ui, r->level), bar, R, r->score);
        for (int k = 0; k < r->nfindings; k++) {
            fprintf(out, "      %s+%-3d%s %-19s %s%s%s\n",
                    ui_level_style(ui, r->level), r->findings[k].weight, R,
                    r->findings[k].rule, D, r->findings[k].reason, R);
            if (c->explain)
                explain_finding(out, c, r, &r->findings[k], ui, "            ");
        }
    }

    if (c->full) {
        fprintf(out, "\n  %sAll modules%s\n", B, R);
        fprintf(out, "  %s%-24s %10s %4s  %-9s %s%s\n", D, "Module", "Size", "Ref",
                "Risk", "Origin", R);
        for (int i = 0; i < s->records.count; i++) {
            const module_record_t *m = &s->records.items[i];
            const module_result_t *res = NULL;
            for (int k = 0; k < a->count; k++)
                if (a->items[k].rec == m) {
                    res = &a->items[k];
                    break;
                }
            risk_level_t lv = res ? res->level : RISK_NONE;
            fprintf(out, "  %-24s %10lu %4lu  %s%-9s%s %s\n", m->base.name,
                    m->base.size, m->base.ref_count, ui_level_style(ui, lv),
                    risk_level_name(lv), R,
                    m->in_moddep ? m->path : (m->in_proc ? "(unknown)" : "(hidden)"));
        }
    }
    fprintf(out, "\n  %sscan took %.2f ms%s\n\n", D, s->elapsed_ms, R);
}
