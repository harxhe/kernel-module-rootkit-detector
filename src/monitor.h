#ifndef MONITOR_H
#define MONITOR_H

#include "risk.h"
#include "scan.h"
#include "ui.h"

/* Live monitoring: re-scan every interval and report only what changed.

   An ALERT is printed when a module starts being flagged, or its set of
   findings changes; RESOLVED when it stops being flagged. The baseline file
   is re-read on every cycle, so tampering with it while the monitor runs is
   itself an alert. Returns 0 (nothing at or above fail_on was seen),
   1 (something was), 2 (first scan failed). Stops on SIGINT/SIGTERM or after
   max_scans scans. */

typedef struct {
    scan_config_t scan;       /* proc/sys/moddep paths, kernel release */
    const char *baseline_path;
    int interval_ms;          /* pause between scans */
    int max_scans;            /* 0 = until interrupted */
    ui_t ui;                  /* styling for stdout */
    int json;                 /* one JSON object per line instead of text */
    int explain;              /* print raw evidence under alerts */
    risk_level_t fail_on;
    const char *log_path;     /* append plain event lines, may be NULL */
} monitor_opts_t;

int monitor_run(const monitor_opts_t *opts);

#endif /* MONITOR_H */
