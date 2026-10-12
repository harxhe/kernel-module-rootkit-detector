#include "module_scanner.h"
#include "util.h"
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PROC_LINES 1000000 /* sanity bound against hostile input */

static char *next_token(char **p)
{
    char *s = *p;
    while (*s && isspace((unsigned char)*s))
        s++;
    if (!*s) {
        *p = s;
        return NULL;
    }
    char *e = s;
    while (*e && !isspace((unsigned char)*e))
        e++;
    if (*e)
        *e++ = '\0';
    *p = e;
    return s;
}

static int parse_ulong(const char *s, int base, unsigned long *out)
{
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, base);
    if (end == s || *end != '\0' || errno == ERANGE)
        return -1;
    *out = v;
    return 0;
}

int scanner_parse_line(char *line, module_info_t *out)
{
    char *p = line;
    char *name = next_token(&p);
    char *size = next_token(&p);
    char *refc = next_token(&p);

    if (!name || !size || !refc)
        return -1;
    if (strlen(name) >= MAX_MODULE_NAME || !util_valid_module_name(name))
        return -1;

    memset(out, 0, sizeof(*out));
    util_copy(out->name, sizeof(out->name), name);

    if (parse_ulong(size, 10, &out->size) != 0)
        return -1;
    /* Some kernels print a non-numeric refcount; treat it as 0 rather than
       rejecting an otherwise valid record. */
    if (parse_ulong(refc, 10, &out->ref_count) != 0)
        out->ref_count = 0;

    char *deps = next_token(&p);
    util_copy(out->deps, sizeof(out->deps), deps ? deps : "-");

    char *state = next_token(&p);
    if (state)
        util_copy(out->state, sizeof(out->state), state);

    char *addr = next_token(&p);
    if (addr && parse_ulong(addr, 16, &out->address) != 0)
        out->address = 0;

    char *flags = next_token(&p);
    if (flags && flags[0] == '(') {
        size_t n = strlen(flags);
        if (n > 1 && flags[n - 1] == ')')
            flags[n - 1] = '\0';
        util_copy(out->proc_flags, sizeof(out->proc_flags), flags + 1);
    }
    return 0;
}

static int list_push(module_list_t *list, const module_info_t *mod)
{
    if (list->count == list->capacity) {
        int ncap = list->capacity ? list->capacity * 2 : 64;
        module_info_t *tmp = realloc(list->items, (size_t)ncap * sizeof(*tmp));
        if (!tmp)
            return -1;
        list->items = tmp;
        list->capacity = ncap;
    }
    list->items[list->count++] = *mod;
    return 0;
}

int scanner_read_modules(const char *path, module_list_t *list)
{
    memset(list, 0, sizeof(*list));

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char *line = NULL;
    size_t cap = 0;
    long lines = 0;
    while (getline(&line, &cap, f) != -1) {
        if (++lines > MAX_PROC_LINES) {
            list->skipped++;
            break;
        }
        char *q = line;
        while (*q && isspace((unsigned char)*q))
            q++;
        if (!*q)
            continue; /* blank line */

        module_info_t mod;
        if (scanner_parse_line(line, &mod) != 0) {
            list->skipped++;
            continue;
        }
        if (list_push(list, &mod) != 0) {
            free(line);
            fclose(f);
            scanner_free_modules(list);
            return -1;
        }
    }
    free(line);
    fclose(f);
    return 0;
}

void scanner_print_modules(FILE *out, const module_list_t *list)
{
    fprintf(out, "%-24s %10s %4s  %-8s %s\n", "Module", "Size", "Ref",
            "State", "Depends");
    for (int i = 0; i < list->count; i++) {
        const module_info_t *m = &list->items[i];
        fprintf(out, "%-24s %10lu %4lu  %-8s %s\n", m->name, m->size,
                m->ref_count, m->state[0] ? m->state : "?", m->deps);
    }
}

void scanner_free_modules(module_list_t *list)
{
    free(list->items);
    memset(list, 0, sizeof(*list));
}
