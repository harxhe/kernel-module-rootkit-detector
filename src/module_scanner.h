#ifndef MOD_SCANNER_H
#define MOD_SCANNER_H

#include <stdio.h>

#define MAX_MODULE_NAME 64
#define MAX_DEPS_LEN 512

/* One line of /proc/modules:
     name size refcnt deps state address [(taint flags)]            */
typedef struct {
    char name[MAX_MODULE_NAME];
    unsigned long size;
    unsigned long ref_count;
    char deps[MAX_DEPS_LEN];  /* "-" when none */
    char state[16];           /* Live / Loading / Unloading, "" if absent */
    unsigned long address;
    char proc_flags[16];      /* taint flags from "(OE)" without parens */
} module_info_t;

typedef struct {
    module_info_t *items;
    int count;
    int capacity;
    int skipped;              /* malformed lines that were ignored */
} module_list_t;

/* Parse a single /proc/modules line (modified in place).
   Returns 0 on success, -1 if the line is malformed. */
int scanner_parse_line(char *line, module_info_t *out);

/* Read and parse a /proc/modules style file.
   Returns 0 on success (list may be empty), -1 if the file cannot be read.
   Malformed lines are skipped and counted in list->skipped. */
int scanner_read_modules(const char *path, module_list_t *list);

void scanner_print_modules(FILE *out, const module_list_t *list);
void scanner_free_modules(module_list_t *list);

#endif /* MOD_SCANNER_H */
