#include "progress.h"
#include <string.h>

#define LABEL_WIDTH 42

static int count_rule(const analysis_t *an, const char *rule)
{
    int n = 0;
    for (int i = 0; i < an->count; i++)
        for (int k = 0; k < an->items[i].nfindings; k++)
            if (strcmp(an->items[i].findings[k].rule, rule) == 0)
                n++;
    return n;
}

static void step(FILE *out, const ui_t *ui, int n, const char *label,
                 const char *detail, ui_sym_t sym, ui_style_t color, double ms)
{
    char head[64];
    snprintf(head, sizeof(head), "  [%d/5] %s", n, label);
    fprintf(out, "%s", ui_style(ui, UI_GREY));
    ui_dots(out, head, LABEL_WIDTH);
    fprintf(out, "%s%-24s%s %s%s%s %s%6.2f ms%s\n", ui_style(ui, UI_RESET), detail,
            ui_style(ui, UI_RESET), ui_style(ui, color), ui_sym(ui, sym),
            ui_style(ui, UI_RESET), ui_style(ui, UI_GREY), ms, ui_style(ui, UI_RESET));
}

void progress_print(FILE *out, const ui_t *ui, const scan_result_t *s,
                    const analysis_t *an, double t_baseline_ms, double t_analyze_ms)
{
    char d[96];
    int in_proc = 0, in_sys = 0, hidden = 0, nosys = 0;
    for (int i = 0; i < s->records.count; i++) {
        const module_record_t *m = &s->records.items[i];
        in_proc += m->in_proc;
        in_sys += m->in_sysfs;
        if (!m->in_proc && m->in_sysfs)
            hidden++;
        if (m->in_proc && !m->in_sysfs)
            nosys++;
    }

    fputc('\n', out);
    snprintf(d, sizeof(d), "%d modules", in_proc);
    if (s->proc_skipped) {
        snprintf(d, sizeof(d), "%d modules, %d ignored", in_proc, s->proc_skipped);
        step(out, ui, 1, "Reading /proc/modules", d, UI_SYM_WARN, UI_YELLOW, s->t_proc_ms);
    } else {
        step(out, ui, 1, "Reading /proc/modules", d, UI_SYM_OK, UI_GREEN, s->t_proc_ms);
    }

    if (s->sysfs_available) {
        snprintf(d, sizeof(d), "%d loadable", in_sys);
        step(out, ui, 2, "Reading /sys/module", d, UI_SYM_OK, UI_GREEN, s->t_sys_ms);
    } else {
        step(out, ui, 2, "Reading /sys/module", "unavailable", UI_SYM_WARN, UI_YELLOW,
             s->t_sys_ms);
    }

    if (!s->sysfs_available) {
        step(out, ui, 3, "Cross-checking both views", "skipped", UI_SYM_WARN, UI_YELLOW,
             s->t_cross_ms);
    } else if (hidden + nosys > 0) {
        snprintf(d, sizeof(d), "%d mismatch%s", hidden + nosys,
                 hidden + nosys == 1 ? "" : "es");
        step(out, ui, 3, "Cross-checking both views", d, UI_SYM_FAIL, UI_RED, s->t_cross_ms);
    } else {
        step(out, ui, 3, "Cross-checking both views", "views agree", UI_SYM_OK, UI_GREEN,
             s->t_cross_ms);
    }

    if (!an->env.has_baseline) {
        step(out, ui, 4, "Comparing with baseline", "no baseline", UI_SYM_WARN, UI_YELLOW,
             t_baseline_ms);
    } else if (an->env.kernel_mismatch) {
        step(out, ui, 4, "Comparing with baseline", "other kernel: partial", UI_SYM_WARN,
             UI_YELLOW, t_baseline_ms);
    } else {
        int added = count_rule(an, "NOT_IN_BASELINE");
        int changed = count_rule(an, "SRCVERSION_CHANGED") + count_rule(an, "SIZE_CHANGED") +
                      count_rule(an, "DEPS_CHANGED");
        int missing = count_rule(an, "MISSING");
        snprintf(d, sizeof(d), "%d new, %d changed, %d gone", added, changed, missing);
        int drift = added + changed + missing > 0;
        step(out, ui, 4, "Comparing with baseline", d, drift ? UI_SYM_WARN : UI_SYM_OK,
             drift ? UI_YELLOW : UI_GREEN, t_baseline_ms);
    }

    snprintf(d, sizeof(d), "%d flagged", an->flagged);
    step(out, ui, 5, "Applying rules and scoring", d,
         an->flagged ? (an->max_level >= RISK_HIGH ? UI_SYM_FAIL : UI_SYM_WARN) : UI_SYM_OK,
         an->flagged ? (an->max_level >= RISK_HIGH ? UI_RED : UI_YELLOW) : UI_GREEN,
         t_analyze_ms);
}
