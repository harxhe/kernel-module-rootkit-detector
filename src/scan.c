#include "scan.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int cmp_record(const void *a, const void *b)
{
    return strcmp(((const module_record_t *)a)->base.name,
                  ((const module_record_t *)b)->base.name);
}

static int in_list(const module_list_t *l, const char *name)
{
    for (int i = 0; i < l->count; i++)
        if (strcmp(l->items[i].name, name) == 0)
            return 1;
    return 0;
}

static int add_proc_record(scan_result_t *r, const module_info_t *mi,
                           const moddep_t *md, const char *sys_root)
{
    module_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.base = *mi;
    rec.in_proc = 1;
    metadata_populate(&rec, sys_root, md);
    return records_push(&r->records, &rec);
}

int scan_run(const scan_config_t *cfg, scan_result_t *out, char *err,
             size_t errsz)
{
    double t0 = now_ms();
    memset(out, 0, sizeof(*out));
    out->when = time(NULL);
    util_copy(out->kernel, sizeof(out->kernel),
              cfg->kernel_release ? cfg->kernel_release : "unknown");

    module_list_t first = {0}, second = {0};
    if (scanner_read_modules(cfg->proc_path, &first) != 0) {
        snprintf(err, errsz, "cannot read %s", cfg->proc_path);
        return -1;
    }
    out->proc_skipped = first.skipped;

    if (cfg->moddep_path && moddep_load(cfg->moddep_path, &out->moddep) == 0)
        out->moddep_available = 1;

    char **sysnames = NULL;
    int nsys = 0;
    out->sysfs_available =
        metadata_list_sysfs_modules(cfg->sys_root, &sysnames, &nsys) == 0;

    /* Second look at /proc/modules, after sysfs, to close the race window. */
    int have_second = scanner_read_modules(cfg->proc_path, &second) == 0;

    int rc = 0;
    for (int i = 0; i < first.count && rc == 0; i++) {
        int dup = 0;
        for (int j = 0; j < i; j++)
            if (strcmp(first.items[j].name, first.items[i].name) == 0)
                dup = 1;
        if (add_proc_record(out, &first.items[i], &out->moddep,
                            cfg->sys_root) != 0) {
            rc = -1;
            break;
        }
        if (dup) {
            out->records.items[out->records.count - 1].duplicate = 1;
            /* flag the earlier instance too */
            for (int j = 0; j < out->records.count - 1; j++)
                if (strcmp(out->records.items[j].base.name,
                           first.items[i].name) == 0)
                    out->records.items[j].duplicate = 1;
        }
    }
    if (rc == 0 && have_second) {
        for (int i = 0; i < second.count && rc == 0; i++) {
            if (in_list(&first, second.items[i].name))
                continue; /* loaded while we were scanning */
            rc = add_proc_record(out, &second.items[i], &out->moddep,
                                 cfg->sys_root);
        }
    }

    /* Cross-view: loadable modules sysfs knows about but /proc/modules does
       not list are hidden from /proc/modules (classic LKM rootkit trick). */
    for (int i = 0; i < nsys && rc == 0; i++) {
        if (in_list(&first, sysnames[i]) ||
            (have_second && in_list(&second, sysnames[i])))
            continue;
        if (!metadata_sysfs_has(cfg->sys_root, sysnames[i]))
            continue; /* unloaded in the meantime */

        module_record_t rec;
        memset(&rec, 0, sizeof(rec));
        util_copy(rec.base.name, sizeof(rec.base.name), sysnames[i]);
        rec.in_proc = 0;
        metadata_populate(&rec, cfg->sys_root, &out->moddep);
        rec.base.size = rec.coresize + rec.initsize;
        rc = records_push(&out->records, &rec);
    }

    metadata_free_names(sysnames, nsys);
    scanner_free_modules(&first);
    scanner_free_modules(&second);

    if (rc != 0) {
        snprintf(err, errsz, "out of memory");
        scan_free(out);
        return -1;
    }

    if (out->records.count > 1)
        qsort(out->records.items, (size_t)out->records.count,
              sizeof(*out->records.items), cmp_record);

    out->elapsed_ms = now_ms() - t0;
    return 0;
}

void scan_free(scan_result_t *r)
{
    records_free(&r->records);
    moddep_free(&r->moddep);
}
