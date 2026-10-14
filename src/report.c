#include "report.h"
#include <string.h>
#include <time.h>

static void fmt_time(time_t t, char *buf, size_t sz)
{
    struct tm tmv;
    if (!localtime_r(&t, &tmv) || !strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &tmv))
        snprintf(buf, sz, "%ld", (long)t);
}

static void rule(FILE *out, char c, int n)
{
    for (int i = 0; i < n; i++)
        fputc(c, out);
    fputc('\n', out);
}

void report_text(FILE *out, const report_ctx_t *c)
{
    const scan_result_t *s = c->scan;
    const analysis_t *a = c->analysis;
    char when[64];
    fmt_time(s->when, when, sizeof(when));

    int in_proc = 0;
    for (int i = 0; i < s->records.count; i++)
        in_proc += s->records.items[i].in_proc;

    fprintf(out, "=== Kernel Module Rootkit Detector - Scan Report ===\n");
    fprintf(out, "Scan time      : %s\n", when);
    fprintf(out, "Kernel         : %s\n", s->kernel);
    fprintf(out, "Modules loaded : %d (/proc/modules)\n", in_proc);
    fprintf(out, "Scan duration  : %.2f ms\n", s->elapsed_ms);

    if (a->env.has_baseline) {
        char bt[64];
        fmt_time(c->baseline->created, bt, sizeof(bt));
        fprintf(out, "Baseline       : %s (%d modules, kernel %s, created %s)\n",
                c->baseline_path, c->baseline->count,
                c->baseline->kernel[0] ? c->baseline->kernel : "?", bt);
    } else {
        fprintf(out, "Baseline       : none - %s\n",
                c->baseline_note ? c->baseline_note : "not loaded");
    }

    fprintf(out, "\nNotes:\n");
    int notes = 0;
    if (!a->env.has_baseline) {
        fprintf(out, "  - Heuristic rules only; baseline comparison skipped.\n");
        notes++;
    }
    if (a->env.kernel_mismatch) {
        fprintf(out, "  - Baseline was created on kernel %s, running %s: size/"
                     "srcversion/dependency comparison skipped.\n",
                c->baseline->kernel, s->kernel);
        notes++;
    }
    if (!a->env.sysfs_available) {
        fprintf(out, "  - /sys/module not readable: hidden-module cross-check skipped.\n");
        notes++;
    }
    if (!a->env.moddep_available) {
        fprintf(out, "  - modules.dep not found: module location check skipped.\n");
        notes++;
    }
    if (s->proc_skipped) {
        fprintf(out, "  - %d malformed /proc/modules line(s) ignored.\n",
                s->proc_skipped);
        notes++;
    }
    if (!notes)
        fprintf(out, "  (none)\n");

    fprintf(out, "\nSummary: %d flagged  |  CRITICAL %d  HIGH %d  MEDIUM %d  LOW %d\n",
            a->flagged, a->counts[RISK_CRITICAL], a->counts[RISK_HIGH],
            a->counts[RISK_MEDIUM], a->counts[RISK_LOW]);
    fprintf(out, "Overall risk: %s (max score %d/100)\n",
            a->flagged ? risk_level_name(a->max_level) : "CLEAN", a->max_score);

    fprintf(out, "\n");
    if (!a->flagged) {
        fprintf(out, "No suspicious modules detected.\n");
    } else {
        fprintf(out, "Suspicious modules:\n");
        rule(out, '-', 72);
        for (int i = 0; i < a->count; i++) {
            const module_result_t *r = &a->items[i];
            if (r->score == 0)
                continue;
            fprintf(out, "[%-8s] %-24s score %3d/100\n", risk_level_name(r->level),
                    r->name, r->score);
            for (int k = 0; k < r->nfindings; k++)
                fprintf(out, "    +%-3d %-18s %s\n", r->findings[k].weight,
                        r->findings[k].rule, r->findings[k].reason);
        }
        rule(out, '-', 72);
    }

    if (c->full) {
        fprintf(out, "\nAll modules:\n");
        rule(out, '-', 72);
        fprintf(out, "%-24s %10s %4s  %-8s %s\n", "Module", "Size", "Ref",
                "Risk", "Origin");
        for (int i = 0; i < s->records.count; i++) {
            const module_record_t *m = &s->records.items[i];
            const module_result_t *res = NULL;
            for (int k = 0; k < a->count; k++)
                if (a->items[k].rec == m) {
                    res = &a->items[k];
                    break;
                }
            fprintf(out, "%-24s %10lu %4lu  %-8s %s\n", m->base.name,
                    m->base.size, m->base.ref_count,
                    res ? risk_level_name(res->level) : "?",
                    m->in_moddep ? m->path : (m->in_proc ? "(unknown)" : "(hidden)"));
        }
        rule(out, '-', 72);
    }
    fprintf(out, "\nReport complete.\n");
}

static void json_str(FILE *out, const char *s)
{
    fputc('"', out);
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        switch (ch) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out); break;
        case '\t': fputs("\\t", out); break;
        default:
            if (ch < 0x20 || ch >= 0x7f)
                fprintf(out, "\\u%04x", ch);
            else
                fputc(ch, out);
        }
    }
    fputc('"', out);
}

void report_json(FILE *out, const report_ctx_t *c)
{
    const scan_result_t *s = c->scan;
    const analysis_t *a = c->analysis;
    int in_proc = 0;
    for (int i = 0; i < s->records.count; i++)
        in_proc += s->records.items[i].in_proc;

    fprintf(out, "{\n  \"scan_time\": %ld,\n  \"kernel\": ", (long)s->when);
    json_str(out, s->kernel);
    fprintf(out, ",\n  \"modules_loaded\": %d,\n  \"scan_ms\": %.3f,\n", in_proc,
            s->elapsed_ms);
    fprintf(out, "  \"baseline\": %s,\n  \"kernel_mismatch\": %s,\n",
            a->env.has_baseline ? "true" : "false",
            a->env.kernel_mismatch ? "true" : "false");
    fprintf(out, "  \"sysfs_available\": %s,\n  \"modules_dep_available\": %s,\n",
            a->env.sysfs_available ? "true" : "false",
            a->env.moddep_available ? "true" : "false");
    fprintf(out, "  \"flagged\": %d,\n  \"overall_risk\": ", a->flagged);
    json_str(out, a->flagged ? risk_level_name(a->max_level) : "CLEAN");
    fprintf(out, ",\n  \"max_score\": %d,\n  \"suspicious\": [", a->max_score);

    int first = 1;
    for (int i = 0; i < a->count; i++) {
        const module_result_t *r = &a->items[i];
        if (r->score == 0)
            continue;
        fprintf(out, "%s\n    {\"module\": ", first ? "" : ",");
        first = 0;
        json_str(out, r->name);
        fprintf(out, ", \"score\": %d, \"level\": ", r->score);
        json_str(out, risk_level_name(r->level));
        fprintf(out, ", \"findings\": [");
        for (int k = 0; k < r->nfindings; k++) {
            fprintf(out, "%s{\"rule\": ", k ? ", " : "");
            json_str(out, r->findings[k].rule);
            fprintf(out, ", \"weight\": %d, \"reason\": ", r->findings[k].weight);
            json_str(out, r->findings[k].reason);
            fputc('}', out);
        }
        fprintf(out, "]}");
    }
    fprintf(out, "%s]\n}\n", first ? "" : "\n  ");
}

int report_append_log(const char *path, const report_ctx_t *c)
{
    FILE *f = fopen(path, "a");
    if (!f)
        return -1;
    const analysis_t *a = c->analysis;
    char when[64];
    fmt_time(c->scan->when, when, sizeof(when));
    fprintf(f, "%s kernel=%s modules=%d flagged=%d overall=%s max_score=%d baseline=%s\n",
            when, c->scan->kernel, c->scan->records.count, a->flagged,
            a->flagged ? risk_level_name(a->max_level) : "CLEAN", a->max_score,
            a->env.has_baseline ? "yes" : "no");
    for (int i = 0; i < a->count; i++) {
        const module_result_t *r = &a->items[i];
        if (r->score == 0)
            continue;
        fprintf(f, "  %s %s score=%d rules=", risk_level_name(r->level), r->name,
                r->score);
        for (int k = 0; k < r->nfindings; k++)
            fprintf(f, "%s%s", k ? "," : "", r->findings[k].rule);
        fputc('\n', f);
    }
    return fclose(f) == 0 ? 0 : -1;
}
