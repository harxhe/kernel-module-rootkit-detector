/* Reads the files that really exist under /sys/module/<name>/ (initstate,
   taint, version, srcversion, coresize, initsize, holders/). The root is a
   parameter so the logic can be tested against a fabricated tree. */

#include "sysfs.h"
#include "util.h"
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_SYSFS_ENTRIES 65536

static int sysfs_read(const char *root, const char *name, const char *file,
                      char *buf, size_t sz)
{
    char path[1024];
    if (util_path_join(path, sizeof(path), root, name, file) != 0)
        return -1;
    return util_read_file(path, buf, sz);
}

static unsigned long sysfs_read_ulong(const char *root, const char *name,
                                      const char *file)
{
    char buf[64];
    if (sysfs_read(root, name, file, buf, sizeof(buf)) <= 0)
        return 0;
    char *end;
    errno = 0;
    unsigned long v = strtoul(buf, &end, 10);
    return (end == buf || errno == ERANGE) ? 0 : v;
}

static int count_dir_entries(const char *root, const char *name, const char *sub)
{
    char path[1024];
    if (util_path_join(path, sizeof(path), root, name, sub) != 0)
        return 0;
    DIR *d = opendir(path);
    if (!d)
        return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        n++;
    }
    closedir(d);
    return n;
}

int sysfs_has(const char *sys_root, const char *name)
{
    char path[1024];
    struct stat st;
    if (!util_valid_module_name(name) ||
        util_path_join(path, sizeof(path), sys_root, name, NULL) != 0)
        return 0;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

void sysfs_populate(module_record_t *rec, const char *sys_root,
                       const moddep_t *md)
{
    const char *name = rec->base.name;

    rec->in_sysfs = sysfs_has(sys_root, name);
    if (rec->in_sysfs) {
        sysfs_read(sys_root, name, "initstate", rec->initstate,
                   sizeof(rec->initstate));
        sysfs_read(sys_root, name, "taint", rec->taint, sizeof(rec->taint));
        sysfs_read(sys_root, name, "version", rec->version,
                   sizeof(rec->version));
        sysfs_read(sys_root, name, "srcversion", rec->srcversion,
                   sizeof(rec->srcversion));
        rec->coresize = sysfs_read_ulong(sys_root, name, "coresize");
        rec->initsize = sysfs_read_ulong(sys_root, name, "initsize");
        rec->holders = count_dir_entries(sys_root, name, "holders");
    }
    util_sanitize_field(rec->version);
    util_sanitize_field(rec->srcversion);
    util_sanitize_field(rec->taint);
    util_sanitize_field(rec->initstate);

    const char *p = moddep_lookup(md, name);
    if (p) {
        rec->in_moddep = 1;
        util_copy(rec->path, sizeof(rec->path), p);
    }
}

int sysfs_list_modules(const char *sys_root, char ***names, int *count)
{
    *names = NULL;
    *count = 0;

    DIR *d = opendir(sys_root);
    if (!d)
        return -1;

    char **arr = NULL;
    int n = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < MAX_SYSFS_ENTRIES) {
        if (!util_valid_module_name(e->d_name))
            continue;
        char probe[1024];
        struct stat st;
        if (util_path_join(probe, sizeof(probe), sys_root, e->d_name,
                           "initstate") != 0 ||
            stat(probe, &st) != 0)
            continue; /* built-in module or not a module directory */

        if (n == cap) {
            int ncap = cap ? cap * 2 : 64;
            char **tmp = realloc(arr, (size_t)ncap * sizeof(*tmp));
            if (!tmp) {
                sysfs_free_names(arr, n);
                closedir(d);
                return -1;
            }
            arr = tmp;
            cap = ncap;
        }
        arr[n] = strdup(e->d_name);
        if (!arr[n]) {
            sysfs_free_names(arr, n);
            closedir(d);
            return -1;
        }
        n++;
    }
    closedir(d);
    *names = arr;
    *count = n;
    return 0;
}

void sysfs_free_names(char **names, int count)
{
    for (int i = 0; i < count; i++)
        free(names[i]);
    free(names);
}

int records_push(record_set_t *rs, const module_record_t *rec)
{
    if (rs->count == rs->capacity) {
        int ncap = rs->capacity ? rs->capacity * 2 : 64;
        module_record_t *tmp = realloc(rs->items, (size_t)ncap * sizeof(*tmp));
        if (!tmp)
            return -1;
        rs->items = tmp;
        rs->capacity = ncap;
    }
    rs->items[rs->count++] = *rec;
    return 0;
}

void records_free(record_set_t *rs)
{
    free(rs->items);
    memset(rs, 0, sizeof(*rs));
}

const module_record_t *records_find(const record_set_t *rs, const char *name)
{
    for (int i = 0; i < rs->count; i++)
        if (strcmp(rs->items[i].base.name, name) == 0)
            return &rs->items[i];
    return NULL;
}

int sysfs_compare(const module_record_t *a, const module_record_t *b)
{
    if (!a && !b)
        return 1;
    if (!a || !b)
        return 0;
    return strcmp(a->base.name, b->base.name) == 0 &&
           a->base.size == b->base.size &&
           strcmp(a->srcversion, b->srcversion) == 0 &&
           strcmp(a->base.deps, b->base.deps) == 0;
}
