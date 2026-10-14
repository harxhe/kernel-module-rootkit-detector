#ifndef BASELINE_H
#define BASELINE_H

#include "scan.h"
#include <time.h>

/* Phase 4 - trusted baseline.

   File format (UTF-8, LF, tab separated):

     # kmrd-baseline 1
     # kernel <release>
     # created <epoch seconds>
     # modules <count>
     <name> TAB <size> TAB <deps> TAB <srcversion> TAB <version> TAB <taint> TAB <path>
     ...
     # checksum <16 hex digits>        (FNV-1a 64 over every preceding byte)

   Empty fields are written as "-". The checksum and count let the loader
   reject truncated or hand-edited files instead of trusting them.        */

/* same size as module_info_t.deps in module_scanner.h */
#define MAX_DEPS_LEN 256

#define BASELINE_MAGIC "kmrd-baseline"
#define BASELINE_VERSION 1
/* Not baseline/modules.txt: that file belongs to the phase-2 CLI
   (src/main.c) and uses a different, header-less format. */
#define BASELINE_DEFAULT_PATH "baseline/trusted.baseline"

typedef struct {
    char name[MAX_MODULE_NAME];
    unsigned long size;
    char deps[MAX_DEPS_LEN];
    char srcversion[64];
    char version[64];
    char taint[32];
    char path[MODDEP_PATH_LEN];
} baseline_entry_t;

typedef struct {
    baseline_entry_t *items; /* sorted by name */
    int count;
    char kernel[64];
    time_t created;
} baseline_t;

/* Save all modules that are present in /proc/modules. Written atomically
   (temp file + rename). Returns 0 or -1 with a message in err. */
int baseline_save(const char *path, const scan_result_t *scan, char *err,
                  size_t errsz);

/* Load and validate. Returns 0 or -1 with a message in err. */
int baseline_load(const char *path, baseline_t *b, char *err, size_t errsz);

const baseline_entry_t *baseline_find(const baseline_t *b, const char *name);
void baseline_free(baseline_t *b);

/* Differences between a baseline and a scan. */
#define DIFF_SIZE     0x1
#define DIFF_SRCVER   0x2
#define DIFF_DEPS     0x4
#define DIFF_VERSION  0x8

typedef struct {
    int *added;     /* indices into scan->records */
    int n_added;
    int *removed;   /* indices into baseline->items */
    int n_removed;
    int *changed;   /* indices into scan->records */
    int *changed_mask;
    int n_changed;
} baseline_diff_t;

int baseline_diff(const baseline_t *b, const scan_result_t *scan,
                  baseline_diff_t *d);
void baseline_diff_free(baseline_diff_t *d);

/* Bitmask of DIFF_* flags between a baseline entry and a record. */
int baseline_entry_diff(const baseline_entry_t *e, const module_record_t *r);

#endif /* BASELINE_H */
