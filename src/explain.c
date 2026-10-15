#include "explain.h"
#include <string.h>

#define WHERE_WIDTH 30

static void line(FILE *out, const ui_t *ui, const char *indent, ui_sym_t sym,
                 const char *where, const char *detail)
{
    ui_style_t color = sym == UI_SYM_OK ? UI_GREEN : sym == UI_SYM_FAIL ? UI_RED : UI_GREY;
    fprintf(out, "%s%s%s%s %-*s %s\n", indent, ui_style(ui, color), ui_sym(ui, sym),
            ui_style(ui, UI_RESET), WHERE_WIDTH, where, detail);
}

void explain_finding(FILE *out, const report_ctx_t *c, const module_result_t *res,
                     const finding_t *f, const ui_t *ui, const char *indent)
{
    const module_record_t *m = res->rec;
    const baseline_entry_t *b = res->base;
    const char *proc = c->proc_path ? c->proc_path : "/proc/modules";
    const char *sys = c->sys_root ? c->sys_root : "/sys/module";
    const char *bpath = c->baseline_path ? c->baseline_path : "baseline";
    char where[256], d[320];
    const char *rule = f->rule;

    snprintf(where, sizeof(where), "%s/%s", sys, res->name);

    if (strcmp(rule, "HIDDEN_FROM_PROC") == 0) {
        line(out, ui, indent, UI_SYM_FAIL, proc, "not listed");
        snprintf(d, sizeof(d), "present (initstate: %s, size %lu)",
                 m && m->initstate[0] ? m->initstate : "?", m ? m->base.size : 0);
        line(out, ui, indent, UI_SYM_OK, where, d);
    } else if (strcmp(rule, "HIDDEN_FROM_SYSFS") == 0) {
        snprintf(d, sizeof(d), "listed (size %lu, refcount %lu)", m ? m->base.size : 0,
                 m ? m->base.ref_count : 0);
        line(out, ui, indent, UI_SYM_OK, proc, d);
        line(out, ui, indent, UI_SYM_FAIL, where, "directory does not exist");
    } else if (strcmp(rule, "NOT_IN_BASELINE") == 0) {
        snprintf(d, sizeof(d), "no entry for %s", res->name);
        line(out, ui, indent, UI_SYM_FAIL, bpath, d);
        snprintf(d, sizeof(d), "loaded (size %lu, srcversion %s)", m ? m->base.size : 0,
                 m && m->srcversion[0] ? m->srcversion : "none");
        line(out, ui, indent, UI_SYM_OK, "now", d);
    } else if (strcmp(rule, "SRCVERSION_CHANGED") == 0 && m && b) {
        snprintf(d, sizeof(d), "srcversion %s", b->srcversion[0] ? b->srcversion : "none");
        line(out, ui, indent, UI_SYM_DOT, "baseline", d);
        snprintf(d, sizeof(d), "srcversion %s", m->srcversion[0] ? m->srcversion : "none");
        line(out, ui, indent, UI_SYM_FAIL, "now", d);
    } else if (strcmp(rule, "SIZE_CHANGED") == 0 && m && b) {
        snprintf(d, sizeof(d), "size %lu bytes", b->size);
        line(out, ui, indent, UI_SYM_DOT, "baseline", d);
        snprintf(d, sizeof(d), "size %lu bytes", m->base.size);
        line(out, ui, indent, UI_SYM_FAIL, "now", d);
    } else if (strcmp(rule, "DEPS_CHANGED") == 0 && m && b) {
        snprintf(d, sizeof(d), "deps %s", b->deps);
        line(out, ui, indent, UI_SYM_DOT, "baseline", d);
        snprintf(d, sizeof(d), "deps %s", m->base.deps);
        line(out, ui, indent, UI_SYM_FAIL, "now", d);
    } else if (strcmp(rule, "NO_MODULE_FILE") == 0) {
        snprintf(d, sizeof(d), "no entry for %s", res->name);
        line(out, ui, indent, UI_SYM_FAIL, "modules.dep", d);
        line(out, ui, indent, UI_SYM_DOT, "origin",
             "not installed by the distribution (e.g. loaded with insmod)");
    } else if (strcmp(rule, "NONSTANDARD_PATH") == 0 && m) {
        snprintf(d, sizeof(d), "%s (outside kernel/)", m->path);
        line(out, ui, indent, UI_SYM_DOT, "modules.dep path", d);
    } else if (strcmp(rule, "SUSPICIOUS_NAME") == 0) {
        const char *tok = "?";
        analyzer_name_is_suspicious(res->name, &tok);
        snprintf(d, sizeof(d), "name contains '%s'", tok);
        line(out, ui, indent, UI_SYM_FAIL, "name", d);
    } else if (strcmp(rule, "DUPLICATE_NAME") == 0) {
        snprintf(d, sizeof(d), "lists %s more than once", res->name);
        line(out, ui, indent, UI_SYM_FAIL, proc, d);
    } else if (strcmp(rule, "ABNORMAL_STATE") == 0 && m) {
        snprintf(where, sizeof(where), "%s/%s/initstate", sys, res->name);
        snprintf(d, sizeof(d), "%s (expected live)", m->initstate);
        line(out, ui, indent, UI_SYM_FAIL, where, d);
    } else if ((strcmp(rule, "UNSIGNED") == 0 || strcmp(rule, "OUT_OF_TREE") == 0 ||
                strcmp(rule, "PROPRIETARY") == 0) && m) {
        snprintf(where, sizeof(where), "%s/%s/taint", sys, res->name);
        line(out, ui, indent, UI_SYM_DOT, where, m->taint);
    } else if (strcmp(rule, "MISSING") == 0) {
        snprintf(d, sizeof(d), "entry exists (size %lu)", b ? b->size : 0);
        line(out, ui, indent, UI_SYM_OK, bpath, d);
        line(out, ui, indent, UI_SYM_FAIL, "now", "in neither /proc/modules nor /sys/module");
    }
}
