#ifndef SYSFS_H
#define SYSFS_H

#include "moddep.h"
#include "scanner_decl.h"

/* Everything the detector knows about one module: the /proc/modules view
   (module_info_t from module_scanner.h) plus what /sys/module/<name>/ and
   modules.dep say about it. */
typedef struct {
    module_info_t base;
    int in_proc;               /* listed in /proc/modules */
    int in_sysfs;              /* /sys/module/<name>/ exists */
    int duplicate;             /* name appears more than once in /proc/modules */
    char initstate[16];        /* sysfs: live / coming / going, "" if unknown */
    char taint[32];            /* sysfs taint flags, falls back to /proc flags */
    char version[64];
    char srcversion[64];
    unsigned long coresize;
    unsigned long initsize;
    int holders;               /* modules that depend on this one */
    int in_moddep;             /* listed in modules.dep */
    char path[MODDEP_PATH_LEN];/* path from modules.dep, "" if unknown */
} module_record_t;

typedef struct {
    module_record_t *items;
    int count;
    int capacity;
} record_set_t;

/* Fill the sysfs/modules.dep derived fields of rec (rec->base.name must be
   set). sys_root is normally "/sys/module"; md may be NULL. */
void sysfs_populate(module_record_t *rec, const char *sys_root,
                       const moddep_t *md);

/* List loadable modules visible in sysfs (directories containing an
   "initstate" file; built-in modules do not have one).
   Returns 0 on success, -1 if sys_root cannot be opened.
   On success *names is a malloc'ed array of malloc'ed strings. */
int sysfs_list_modules(const char *sys_root, char ***names, int *count);

/* True if /sys/module/<name> is currently a directory. */
int sysfs_has(const char *sys_root, const char *name);

void sysfs_free_names(char **names, int count);

int records_push(record_set_t *rs, const module_record_t *rec);
void records_free(record_set_t *rs);
const module_record_t *records_find(const record_set_t *rs, const char *name);

/* Equality of the identity-relevant fields (used by tests/diffing). */
int sysfs_compare(const module_record_t *a, const module_record_t *b);

#endif /* SYSFS_H */
