#include "scan.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* /proc/modules is parsed by scanner_read_modules() from module_scanner.c.
   This layer adds what the detector needs on top of it: name validation
   (names become sysfs path components), duplicate detection, a second read
   to close the load/unload race, and the /proc vs /sys cross-view. */

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

typedef struct {
    module_info_t *items;
    int count;
    int skipped; /* non-blank lines that did not yield a valid module */
} proc_view_t;

static void proc_view_free(proc_view_t *v)
{
    scanner_free_modules(v->items);
    memset(v, 0, sizeof(*v));
}

/* ---- input normalisation --------------------------------------------------
   scanner_read_modules() is deliberately simple and has three limits that
   matter on real kernels, so each line is normalised before it sees it:

   * the refcount column is "-" for modules that cannot be unloaded (no exit
     function); the scanner needs a number there and silently drops the
     module, which would make it look hidden - or let a rootkit vanish from
     the scan. "-" is rewritten to "0".
   * a line with only three fields leaves the deps buffer uninitialised;
     a "-" deps field is always supplied.
   * lines longer than 255 bytes are split by its fgets(); the deps field is
     cut to a fixed length so every module is exactly one short line.

   Lines with an invalid module name are dropped here, before the name can
   reach a filesystem path. The state/address/taint columns are not used by
   the scanner and are not forwarded. */

#define DEPS_KEEP 200

static int all_digits(const char *s)
{
    if (!*s)
        return 0;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return 0;
    return 1;
}

/* Writes one normalised line to out. Returns 1 if written, 0 if dropped. */
static int normalise_line(char *line, FILE *out)
{
    char *save = NULL;
    char *name = strtok_r(line, " \t\r\n", &save);
    char *size = strtok_r(NULL, " \t\r\n", &save);
    char *refc = strtok_r(NULL, " \t\r\n", &save);
    char *deps = strtok_r(NULL, " \t\r\n", &save);
    if (!name || !size || !refc)
        return 0;
    if (strlen(name) >= MAX_MODULE_NAME || !util_valid_module_name(name))
        return 0;
    if (strlen(size) > 20 || !all_digits(size))
        return 0;
    if (strlen(refc) > 20 || !all_digits(refc))
        refc = "0";
    char d[DEPS_KEEP + 1];
    util_copy(d, sizeof(d), deps ? deps : "-");
    fprintf(out, "%s %s %s %s\n", name, size, refc, d);
    return 1;
}

/* Returns 0 on success, -1 if the file cannot be read. */
static int proc_view_read(const char *path, proc_view_t *v)
{
    memset(v, 0, sizeof(*v));

    FILE *in = fopen(path, "r");
    if (!in)
        return -1;
    FILE *tmp = tmpfile(); /* anonymous: unlinked at creation, no race */
    if (!tmp) {
        fclose(in);
        return -1;
    }

    char *line = NULL;
    size_t cap = 0;
    int nonblank = 0;
    while (getline(&line, &cap, in) != -1) {
        char *q = line;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')
            q++;
        if (!*q)
            continue;
        nonblank++;
        normalise_line(line, tmp);
    }
    free(line);
    fclose(in);
    if (fflush(tmp) != 0) {
        fclose(tmp);
        return -1;
    }

    module_info_t *raw = NULL;
    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fileno(tmp));
    int n = scanner_read_modules(fdpath, &raw);
    if (n < 0) {
        /* no /proc/self/fd (not Linux?): fall back to the original file */
        n = scanner_read_modules(path, &raw);
    }
    fclose(tmp);
    if (n < 0)
        return -1;

    int kept = 0;
    for (int i = 0; i < n; i++) {
        raw[i].name[sizeof(raw[i].name) - 1] = '\0';
        raw[i].deps[sizeof(raw[i].deps) - 1] = '\0';
        util_sanitize_field(raw[i].deps);
        if (!util_valid_module_name(raw[i].name))
            continue;
        if (kept != i)
            raw[kept] = raw[i];
        kept++;
    }
    v->items = raw;
    v->count = kept;
    v->skipped = nonblank - kept;
    if (v->skipped < 0)
        v->skipped = 0;
    return 0;
}

static int view_has(const proc_view_t *v, const char *name)
{
    for (int i = 0; i < v->count; i++)
        if (strcmp(v->items[i].name, name) == 0)
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
    sysfs_populate(&rec, sys_root, md);
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

    proc_view_t first, second;
    if (proc_view_read(cfg->proc_path, &first) != 0) {
        snprintf(err, errsz, "cannot read %s", cfg->proc_path);
        return -1;
    }
    memset(&second, 0, sizeof(second));
    out->proc_skipped = first.skipped;
    out->t_proc_ms = now_ms() - t0;
    double t1 = now_ms();

    if (cfg->moddep_path && moddep_load(cfg->moddep_path, &out->moddep) == 0)
        out->moddep_available = 1;

    char **sysnames = NULL;
    int nsys = 0;
    out->sysfs_available =
        sysfs_list_modules(cfg->sys_root, &sysnames, &nsys) == 0;

    /* Second look at /proc/modules, after sysfs, to close the race window. */
    int have_second = proc_view_read(cfg->proc_path, &second) == 0;
    out->t_sys_ms = now_ms() - t1;
    double t2 = now_ms();

    int rc = 0;
    for (int i = 0; i < first.count && rc == 0; i++) {
        int dup = 0;
        for (int j = 0; j < i; j++)
            if (strcmp(first.items[j].name, first.items[i].name) == 0)
                dup = 1;
        rc = add_proc_record(out, &first.items[i], &out->moddep, cfg->sys_root);
        if (rc != 0)
            break;
        if (dup) {
            /* flag every instance of the repeated name */
            for (int j = 0; j < out->records.count; j++)
                if (strcmp(out->records.items[j].base.name,
                           first.items[i].name) == 0)
                    out->records.items[j].duplicate = 1;
        }
    }
    if (rc == 0 && have_second) {
        for (int i = 0; i < second.count && rc == 0; i++) {
            if (view_has(&first, second.items[i].name))
                continue; /* loaded while we were scanning */
            rc = add_proc_record(out, &second.items[i], &out->moddep,
                                 cfg->sys_root);
        }
    }

    /* Cross-view: loadable modules sysfs knows about but /proc/modules does
       not list are hidden from /proc/modules (classic LKM rootkit trick). */
    for (int i = 0; i < nsys && rc == 0; i++) {
        if (view_has(&first, sysnames[i]) ||
            (have_second && view_has(&second, sysnames[i])))
            continue;
        if (!sysfs_has(cfg->sys_root, sysnames[i]))
            continue; /* unloaded in the meantime */

        module_record_t rec;
        memset(&rec, 0, sizeof(rec));
        util_copy(rec.base.name, sizeof(rec.base.name), sysnames[i]);
        rec.in_proc = 0;
        sysfs_populate(&rec, cfg->sys_root, &out->moddep);
        rec.base.size = rec.coresize + rec.initsize;
        util_copy(rec.base.deps, sizeof(rec.base.deps), "-");
        rc = records_push(&out->records, &rec);
    }

    sysfs_free_names(sysnames, nsys);
    proc_view_free(&first);
    proc_view_free(&second);

    if (rc != 0) {
        snprintf(err, errsz, "out of memory");
        scan_free(out);
        return -1;
    }

    if (out->records.count > 1)
        qsort(out->records.items, (size_t)out->records.count,
              sizeof(*out->records.items), cmp_record);

    out->t_cross_ms = now_ms() - t2;
    out->elapsed_ms = now_ms() - t0;
    return 0;
}

void scan_free(scan_result_t *r)
{
    records_free(&r->records);
    moddep_free(&r->moddep);
}
