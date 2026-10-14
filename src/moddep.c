#include "moddep.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const k_suffixes[] = {".ko.xz", ".ko.gz", ".ko.zst",
                                         ".ko.bz2", ".ko", NULL};

/* "kernel/fs/ext4/ext4.ko.xz" -> "ext4". Returns 0 on success. */
static int module_name_from_path(const char *path, char *name, size_t sz)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    size_t len = strlen(base);
    for (int i = 0; k_suffixes[i]; i++) {
        size_t sl = strlen(k_suffixes[i]);
        if (len > sl && strcmp(base + len - sl, k_suffixes[i]) == 0) {
            len -= sl;
            break;
        }
    }
    if (len == 0 || len >= sz)
        return -1;
    memcpy(name, base, len);
    name[len] = '\0';
    util_normalize_name(name);
    return util_valid_module_name(name) ? 0 : -1;
}

static int cmp_entry(const void *a, const void *b)
{
    return strcmp(((const moddep_entry_t *)a)->name,
                  ((const moddep_entry_t *)b)->name);
}

int moddep_load(const char *path, moddep_t *md)
{
    memset(md, 0, sizeof(*md));
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    int cap = 0;
    char *line = NULL;
    size_t lcap = 0;
    while (getline(&line, &lcap, f) != -1) {
        char *colon = strchr(line, ':');
        if (!colon)
            continue;
        *colon = '\0';

        moddep_entry_t e;
        if (module_name_from_path(line, e.name, sizeof(e.name)) != 0)
            continue;
        util_copy(e.path, sizeof(e.path), line);

        if (md->count == cap) {
            int ncap = cap ? cap * 2 : 256;
            moddep_entry_t *tmp = realloc(md->items, (size_t)ncap * sizeof(*tmp));
            if (!tmp) {
                free(line);
                fclose(f);
                moddep_free(md);
                return -1;
            }
            md->items = tmp;
            cap = ncap;
        }
        md->items[md->count++] = e;
    }
    free(line);
    fclose(f);

    if (md->count > 1)
        qsort(md->items, (size_t)md->count, sizeof(*md->items), cmp_entry);
    md->loaded = 1;
    return 0;
}

const char *moddep_lookup(const moddep_t *md, const char *name)
{
    if (!md || !md->loaded || md->count == 0 || !name)
        return NULL;
    moddep_entry_t key;
    util_copy(key.name, sizeof(key.name), name);
    util_normalize_name(key.name);
    const moddep_entry_t *hit = bsearch(&key, md->items, (size_t)md->count,
                                        sizeof(*md->items), cmp_entry);
    return hit ? hit->path : NULL;
}

void moddep_free(moddep_t *md)
{
    free(md->items);
    memset(md, 0, sizeof(*md));
}
