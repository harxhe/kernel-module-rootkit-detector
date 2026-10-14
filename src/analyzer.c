#include "analyzer.h"
#include "util.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------ */
/* helpers                                                              */
/* ------------------------------------------------------------------ */

void analysis_add_finding(module_result_t *res, const char *rule, int weight,
                          const char *fmt, ...)
{
    if (res->nfindings >= MAX_FINDINGS)
        return;
    finding_t *f = &res->findings[res->nfindings++];
    f->rule = rule;
    f->weight = weight;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(f->reason, sizeof(f->reason), fmt, ap);
    va_end(ap);
}

static const char *const k_suspicious_tokens[] = {
    "diamorphine", "reptile",  "suterusu", "kovid",     "knark",
    "adore",       "kbeast",   "sebek",    "enyelkm",   "rkduck",
    "phalanx",     "synapsys", "singularity", "nuk3gh0st", "rootkit",
    "hidemod",     "keylogger", "backdoor", NULL};

int analyzer_name_is_suspicious(const char *name, const char **token_out)
{
    char low[MAX_MODULE_NAME];
    util_copy(low, sizeof(low), name);
    for (char *p = low; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    for (int i = 0; k_suspicious_tokens[i]; i++)
        if (strstr(low, k_suspicious_tokens[i])) {
            if (token_out)
                *token_out = k_suspicious_tokens[i];
            return 1;
        }
    return 0;
}

static int baseline_comparable(const rule_ctx_t *c)
{
    return c->env->has_baseline && !c->env->kernel_mismatch;
}

/* ------------------------------------------------------------------ */
/* rules - each one independent                                         */
/* ------------------------------------------------------------------ */

/* Visible in sysfs but not in /proc/modules. */
static void rule_hidden_from_proc(const rule_ctx_t *c, module_result_t *r)
{
    if (!c->rec->in_proc && c->rec->in_sysfs)
        analysis_add_finding(r, "HIDDEN_FROM_PROC", W_HIDDEN_FROM_PROC,
                             "loaded (present in /sys/module) but missing from /proc/modules");
}

/* Listed in /proc/modules but has no sysfs directory. */
static void rule_hidden_from_sysfs(const rule_ctx_t *c, module_result_t *r)
{
    if (c->env->sysfs_available && c->rec->in_proc && !c->rec->in_sysfs)
        analysis_add_finding(r, "HIDDEN_FROM_SYSFS", W_HIDDEN_FROM_SYSFS,
                             "listed in /proc/modules but has no /sys/module entry");
}

static void rule_duplicate_name(const rule_ctx_t *c, module_result_t *r)
{
    if (c->rec->duplicate)
        analysis_add_finding(r, "DUPLICATE_NAME", W_DUPLICATE_NAME,
                             "module name appears more than once in /proc/modules");
}

static void rule_suspicious_name(const rule_ctx_t *c, module_result_t *r)
{
    const char *tok;
    if (analyzer_name_is_suspicious(c->rec->base.name, &tok))
        analysis_add_finding(r, "SUSPICIOUS_NAME", W_SUSPICIOUS_NAME,
                             "name contains known rootkit token '%s'", tok);
}

static void rule_not_in_baseline(const rule_ctx_t *c, module_result_t *r)
{
    if (c->env->has_baseline && c->rec->in_proc && !c->base)
        analysis_add_finding(r, "NOT_IN_BASELINE", W_NOT_IN_BASELINE,
                             "module was not present when the baseline was created");
}

static void rule_changed_vs_baseline(const rule_ctx_t *c, module_result_t *r)
{
    if (!baseline_comparable(c) || !c->base || !c->rec->in_proc)
        return;
    int m = baseline_entry_diff(c->base, c->rec);
    if (m & DIFF_SRCVER)
        analysis_add_finding(r, "SRCVERSION_CHANGED", W_SRCVERSION_CHANGED,
                             "srcversion changed (%s -> %s): module binary differs from baseline",
                             c->base->srcversion[0] ? c->base->srcversion : "none",
                             c->rec->srcversion[0] ? c->rec->srcversion : "none");
    if (m & DIFF_SIZE)
        analysis_add_finding(r, "SIZE_CHANGED", W_SIZE_CHANGED,
                             "size changed (%lu -> %lu bytes)", c->base->size,
                             c->rec->base.size);
    if (m & DIFF_DEPS)
        analysis_add_finding(r, "DEPS_CHANGED", W_DEPS_CHANGED,
                             "dependency list changed (%s -> %s)", c->base->deps,
                             c->rec->base.deps);
}

/* Unexpected module location: not installed by the distribution, or
   installed outside the stock kernel tree. */
static void rule_location(const rule_ctx_t *c, module_result_t *r)
{
    if (!c->env->moddep_available || !c->rec->in_proc)
        return;
    if (!c->rec->in_moddep)
        analysis_add_finding(r, "NO_MODULE_FILE", W_NO_MODULE_FILE,
                             "not listed in modules.dep: no installed module file (loaded from an unusual location?)");
    else if (strncmp(c->rec->path, "kernel/", 7) != 0)
        analysis_add_finding(r, "NONSTANDARD_PATH", W_NONSTANDARD_PATH,
                             "installed outside the stock kernel tree (%s)",
                             c->rec->path);
}

static void rule_state(const rule_ctx_t *c, module_result_t *r)
{
    const module_record_t *m = c->rec;
    if (m->initstate[0] && strcmp(m->initstate, "live") != 0)
        analysis_add_finding(r, "ABNORMAL_STATE", W_ABNORMAL_STATE,
                             "sysfs initstate is '%s' (expected live)",
                             m->initstate);
}

static void rule_taint(const rule_ctx_t *c, module_result_t *r)
{
    const char *t = c->rec->taint;
    if (strchr(t, 'E'))
        analysis_add_finding(r, "UNSIGNED", W_UNSIGNED,
                             "taint flag E: module is unsigned");
    if (strchr(t, 'O'))
        analysis_add_finding(r, "OUT_OF_TREE", W_OUT_OF_TREE,
                             "taint flag O: out-of-tree module");
    if (strchr(t, 'P'))
        analysis_add_finding(r, "PROPRIETARY", W_PROPRIETARY,
                             "taint flag P: proprietary license");
}

const rule_fn g_rules[] = {
    rule_hidden_from_proc,
    rule_hidden_from_sysfs,
    rule_duplicate_name,
    rule_suspicious_name,
    rule_not_in_baseline,
    rule_changed_vs_baseline,
    rule_location,
    rule_state,
    rule_taint,
};
const int g_rule_count = (int)(sizeof(g_rules) / sizeof(g_rules[0]));

/* ------------------------------------------------------------------ */
/* engine                                                               */
/* ------------------------------------------------------------------ */

static void finalize_result(module_result_t *r)
{
    int sum = 0;
    for (int i = 0; i < r->nfindings; i++)
        sum += r->findings[i].weight;
    r->score = risk_cap(sum);
    r->level = risk_level_from_score(r->score);
}

static int cmp_result(const void *a, const void *b)
{
    const module_result_t *x = a, *y = b;
    if (x->score != y->score)
        return y->score - x->score;
    return strcmp(x->name, y->name);
}

int analyzer_run(const scan_result_t *scan, const baseline_t *baseline,
                 analysis_t *out)
{
    memset(out, 0, sizeof(*out));
    out->env.has_baseline = baseline != NULL;
    out->env.kernel_mismatch =
        baseline && baseline->kernel[0] && strcmp(baseline->kernel, scan->kernel) != 0;
    out->env.sysfs_available = scan->sysfs_available;
    out->env.moddep_available = scan->moddep_available;

    int extra = baseline ? baseline->count : 0;
    out->items = calloc((size_t)(scan->records.count + extra + 1),
                        sizeof(*out->items));
    if (!out->items)
        return -1;

    for (int i = 0; i < scan->records.count; i++) {
        const module_record_t *rec = &scan->records.items[i];
        module_result_t *res = &out->items[out->count++];
        util_copy(res->name, sizeof(res->name), rec->base.name);
        res->rec = rec;
        res->base = baseline ? baseline_find(baseline, rec->base.name) : NULL;

        rule_ctx_t ctx = {rec, res->base, &out->env};
        for (int r = 0; r < g_rule_count; r++)
            g_rules[r](&ctx, res);
        finalize_result(res);
    }

    /* Modules that were in the baseline but are not present any more. */
    for (int j = 0; baseline && j < baseline->count; j++) {
        const module_record_t *rec =
            records_find(&scan->records, baseline->items[j].name);
        if (rec)
            continue;
        module_result_t *res = &out->items[out->count++];
        util_copy(res->name, sizeof(res->name), baseline->items[j].name);
        res->base = &baseline->items[j];
        analysis_add_finding(res, "MISSING", W_MISSING,
                             "was in the baseline but is no longer loaded");
        finalize_result(res);
    }

    qsort(out->items, (size_t)out->count, sizeof(*out->items), cmp_result);

    for (int i = 0; i < out->count; i++) {
        module_result_t *r = &out->items[i];
        out->counts[r->level]++;
        if (r->score > 0)
            out->flagged++;
        if (r->score > out->max_score) {
            out->max_score = r->score;
            out->max_level = r->level;
        }
    }
    return 0;
}

void analyzer_free(analysis_t *a)
{
    free(a->items);
    memset(a, 0, sizeof(*a));
}
