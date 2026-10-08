#include "module_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read /proc/modules and parse module information.
   Returns number of modules read, or -1 on error. */
int scanner_read_modules(const char *path, module_info_t **modules_out)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen /proc/modules");
        return -1;
    }

    int capacity = 64;
    int count = 0;
    *modules_out = malloc(capacity * sizeof(module_info_t));
    if (!*modules_out) {
        fclose(f);
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        /* /proc/modules format: name size refcount deps ... */
        module_info_t *mod = &(*modules_out)[count];

        /* Parse: module_name  size  refcount  deps */
        if (sscanf(line, "%63s %lu %lu %255s",
                   mod->name, &mod->size, &mod->ref_count, mod->deps) < 3) {
            /* Skip lines we can't parse */
            continue;
        }

        count++;

        if (count >= capacity) {
            capacity *= 2;
            *modules_out = realloc(*modules_out, capacity * sizeof(module_info_t));
            if (!*modules_out) {
                fclose(f);
                return -1;
            }
        }
    }

    fclose(f);
    return count;
}

/* Print module list to stdout */
void scanner_print_modules(module_info_t *modules, int count)
{
    printf("Module                  Size    RefCount  Depends\n");
    printf("---------------------------------------------------\n");
    for (int i = 0; i < count; i++) {
        printf("%-20s %8lu %9lu  %s\n",
               modules[i].name, modules[i].size,
               modules[i].ref_count, modules[i].deps);
    }
}

/* Free module array */
void scanner_free_modules(module_info_t *modules)
{
    free(modules);
}