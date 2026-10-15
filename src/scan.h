#ifndef SCAN_H
#define SCAN_H

#include "sysfs.h"
#include <time.h>

typedef struct {
    const char *proc_path;      /* /proc/modules */
    const char *sys_root;       /* /sys/module */
    const char *moddep_path;    /* /lib/modules/<release>/modules.dep, may be NULL */
    const char *kernel_release; /* uname -r, overridable for tests */
} scan_config_t;

typedef struct {
    record_set_t records;       /* sorted by name */
    moddep_t moddep;
    int proc_skipped;           /* malformed /proc/modules lines */
    int sysfs_available;        /* /sys/module could be enumerated */
    int moddep_available;
    char kernel[64];
    time_t when;
    double elapsed_ms;
    double t_proc_ms;           /* reading /proc/modules */
    double t_sys_ms;            /* reading /sys/module and modules.dep */
    double t_cross_ms;          /* building records, cross-view, sorting */
} scan_result_t;

/* Run a complete scan: /proc/modules, /sys/module, modules.dep.
   /proc/modules is read before and after the sysfs enumeration so that a
   module loaded or unloaded mid-scan is not mistaken for a hidden one.
   Returns 0 on success, -1 on fatal error (message in err). */
int scan_run(const scan_config_t *cfg, scan_result_t *out, char *err,
             size_t errsz);

void scan_free(scan_result_t *r);

#endif /* SCAN_H */
