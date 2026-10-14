#ifndef ANALYZER_H
#define ANALYZER_H

#include "baseline.h"
#include "risk.h"
#include "scan.h"

/* Phase 5 - rule based anomaly detection.
   Each rule is an independent function that inspects one module and may add
   findings. To add a rule: write the function and append it to g_rules[]
   in analyzer.c. Phase 6 (risk.h) turns the findings into a score.        */

#define MAX_FINDINGS 12

typedef struct {
    const char *rule;   /* stable id, e.g. "NOT_IN_BASELINE" */
    int weight;
    char reason[200];   /* human readable explanation */
} finding_t;

typedef struct module_result {
    char name[MAX_MODULE_NAME];
    const module_record_t *rec;     /* NULL when the module vanished */
    const baseline_entry_t *base;   /* NULL if absent from the baseline */
    finding_t findings[MAX_FINDINGS];
    int nfindings;
    int score;                      /* 0-100 */
    risk_level_t level;
} module_result_t;

typedef struct {
    int has_baseline;
    int kernel_mismatch;    /* baseline made on a different kernel release */
    int sysfs_available;
    int moddep_available;
} analysis_env_t;

typedef struct {
    module_result_t *items;     /* flagged first (score desc), then clean */
    int count;
    int flagged;                /* modules with score > 0 */
    analysis_env_t env;
    int counts[RISK_CRITICAL + 1]; /* modules per level */
    int max_score;
    risk_level_t max_level;
} analysis_t;

typedef struct {
    const module_record_t *rec;
    const baseline_entry_t *base;
    const analysis_env_t *env;
} rule_ctx_t;

typedef void (*rule_fn)(const rule_ctx_t *ctx, module_result_t *res);

extern const rule_fn g_rules[];
extern const int g_rule_count;

void analysis_add_finding(module_result_t *res, const char *rule, int weight,
                          const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/* baseline may be NULL (heuristic rules only). Returns 0 or -1 (OOM). */
int analyzer_run(const scan_result_t *scan, const baseline_t *baseline,
                 analysis_t *out);
void analyzer_free(analysis_t *a);

/* True if name contains a known rootkit-like token. */
int analyzer_name_is_suspicious(const char *name, const char **token_out);

#endif /* ANALYZER_H */
