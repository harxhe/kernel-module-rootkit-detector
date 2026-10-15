#ifndef PROGRESS_H
#define PROGRESS_H

#include "analyzer.h"
#include "ui.h"
#include <stdio.h>

/* Five-step summary of what a scan did, with the real time each stage took:

     [1/5] Reading /proc/modules ........ 138 modules   ok  0.4 ms
     [2/5] Reading /sys/module .......... 138 loadable  ok  0.3 ms
     ...

   Printed to stderr by the CLI only when styling is active, so reports and
   JSON on stdout stay clean. t_baseline_ms / t_analyze_ms are measured by
   the caller. */
void progress_print(FILE *out, const ui_t *ui, const scan_result_t *scan,
                    const analysis_t *an, double t_baseline_ms, double t_analyze_ms);

#endif /* PROGRESS_H */
