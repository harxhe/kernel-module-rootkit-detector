#ifndef REPORT_H
#define REPORT_H

#include "analyzer.h"
#include <stdio.h>

/* Phase 7 - reporting. */

typedef struct {
    const scan_result_t *scan;
    const analysis_t *analysis;
    const baseline_t *baseline;      /* NULL if none loaded */
    const char *baseline_path;
    const char *baseline_note;       /* why there is no baseline, or NULL */
    int full;                        /* list every module, not only flagged */
} report_ctx_t;

void report_text(FILE *out, const report_ctx_t *ctx);
void report_json(FILE *out, const report_ctx_t *ctx);

/* Append a short history entry (one summary line + one line per flagged
   module) to a log file. Returns 0 or -1. */
int report_append_log(const char *path, const report_ctx_t *ctx);

#endif /* REPORT_H */
