#ifndef MODDEP_H
#define MODDEP_H

#include "module_scanner.h"

/* Index of /lib/modules/<release>/modules.dep: which module files the
   distribution installed, and where. A loaded module that is not listed
   here was loaded from somewhere unusual (insmod of a stray .ko, etc.). */

#define MODDEP_PATH_LEN 256

typedef struct {
    char name[MAX_MODULE_NAME]; /* normalized: '-' -> '_' */
    char path[MODDEP_PATH_LEN]; /* relative, e.g. kernel/fs/ext4/ext4.ko */
} moddep_entry_t;

typedef struct {
    moddep_entry_t *items;
    int count;
    int loaded; /* 1 if modules.dep was read successfully */
} moddep_t;

/* Returns 0 on success, -1 if the file is unavailable (md->loaded = 0). */
int moddep_load(const char *path, moddep_t *md);

/* name need not be normalized. Returns relative path or NULL. */
const char *moddep_lookup(const moddep_t *md, const char *name);

void moddep_free(moddep_t *md);

#endif /* MODDEP_H */
