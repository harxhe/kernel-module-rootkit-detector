#include "baseline.h"
#include "util.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_BASELINE_BYTES (32L * 1024 * 1024)
#define MAX_BASELINE_MODULES 100000

#define set_err(err, sz, ...) \
    do { if ((err) && (sz)) snprintf((err), (sz), __VA_ARGS__); } while (0)

/* Field writer: empty -> "-", control chars scrubbed. */
static void put_field(FILE *f, const char *s, uint64_t *h, int last)
{
    char tmp[MAX_DEPS_LEN + 8];
    util_copy(tmp, sizeof(tmp), s && *s ? s : "-");
    util_sanitize_field(tmp);
    char out[MAX_DEPS_LEN + 16];
    int n = snprintf(out, sizeof(out), "%s%c", tmp, last ? '\n' : '\t');
    fwrite(out, 1, (size_t)n, f);
    *h = util_fnv1a(*h, out, (size_t)n);
}

static void put_line(FILE *f, uint64_t *h, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#include <stdarg.h>
static void put_line(FILE *f, uint64_t *h, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof(buf))
        n = (int)sizeof(buf) - 1;
    fwrite(buf, 1, (size_t)n, f);
    *h = util_fnv1a(*h, buf, (size_t)n);
}

int baseline_save(const char *path, const scan_result_t *scan, char *err,
                  size_t errsz)
{
    char tmp_path[1100];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path) >=
        (int)sizeof(tmp_path)) {
        set_err(err, errsz, "baseline path too long");
        return -1;
    }

    /* create the parent directory if it is missing (one level) */
    char dir[1100];
    util_copy(dir, sizeof(dir), path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
            set_err(err, errsz, "cannot create directory %s", dir);
            return -1;
        }
    }

    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        set_err(err, errsz, "cannot write %s", tmp_path);
        return -1;
    }

    int n = 0;
    for (int i = 0; i < scan->records.count; i++)
        if (scan->records.items[i].in_proc)
            n++;

    uint64_t h = UTIL_FNV_INIT;
    put_line(f, &h, "# %s %d\n", BASELINE_MAGIC, BASELINE_VERSION);
    put_line(f, &h, "# kernel %s\n", scan->kernel);
    put_line(f, &h, "# created %ld\n", (long)scan->when);
    put_line(f, &h, "# modules %d\n", n);

    for (int i = 0; i < scan->records.count; i++) {
        const module_record_t *r = &scan->records.items[i];
        if (!r->in_proc)
            continue;
        char size[32];
        snprintf(size, sizeof(size), "%lu", r->base.size);
        put_field(f, r->base.name, &h, 0);
        put_field(f, size, &h, 0);
        put_field(f, r->base.deps, &h, 0);
        put_field(f, r->srcversion, &h, 0);
        put_field(f, r->version, &h, 0);
        put_field(f, r->taint, &h, 0);
        put_field(f, r->path, &h, 1);
    }
    fprintf(f, "# checksum %016llx\n", (unsigned long long)h);

    int bad = ferror(f);
    if (fclose(f) != 0)
        bad = 1;
    if (bad) {
        unlink(tmp_path);
        set_err(err, errsz, "write error on %s", tmp_path);
        return -1;
    }
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        set_err(err, errsz, "cannot replace %s", path);
        return -1;
    }
    return 0;
}

static int cmp_entry(const void *a, const void *b)
{
    return strcmp(((const baseline_entry_t *)a)->name,
                  ((const baseline_entry_t *)b)->name);
}

static void unfield(char *s)
{
    if (strcmp(s, "-") == 0)
        s[0] = '\0';
}

int baseline_load(const char *path, baseline_t *b, char *err, size_t errsz)
{
    memset(b, 0, sizeof(*b));

    FILE *f = fopen(path, "rb");
    if (!f) {
        set_err(err, errsz, "cannot open baseline %s", path);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0 || len > MAX_BASELINE_BYTES) {
        fclose(f);
        set_err(err, errsz, "baseline %s is empty or too large", path);
        return -1;
    }
    char *buf = malloc((size_t)len + 1);
    if (!buf || fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        set_err(err, errsz, "cannot read baseline %s", path);
        return -1;
    }
    fclose(f);
    buf[len] = '\0';
    if (memchr(buf, '\0', (size_t)len)) {
        free(buf);
        set_err(err, errsz, "baseline %s contains NUL bytes (corrupt)", path);
        return -1;
    }

    /* Locate the trailing checksum line. */
    char *last = NULL;
    for (char *p = buf; (p = strstr(p, "# checksum ")) != NULL; p++)
        if (p == buf || p[-1] == '\n')
            last = p;
    unsigned long long want = 0;
    char *tail_end;
    if (!last || (want = strtoull(last + 11, &tail_end, 16), tail_end == last + 11)) {
        free(buf);
        set_err(err, errsz, "baseline %s has no checksum (truncated?)", path);
        return -1;
    }
    uint64_t h = util_fnv1a(UTIL_FNV_INIT, buf, (size_t)(last - buf));
    if ((unsigned long long)h != want) {
        free(buf);
        set_err(err, errsz,
                "baseline %s failed checksum - modified or corrupt", path);
        return -1;
    }
    *last = '\0';

    int expected = -1, version = -1, cap = 0;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (line[0] == '#') {
            char tmp[128];
            long v;
            if (sscanf(line, "# %*s %ld", &v) == 1 &&
                strncmp(line, "# " BASELINE_MAGIC, 2 + sizeof(BASELINE_MAGIC) - 1) == 0)
                version = (int)v;
            else if (sscanf(line, "# kernel %127s", tmp) == 1)
                util_copy(b->kernel, sizeof(b->kernel), tmp);
            else if (sscanf(line, "# created %ld", &v) == 1)
                b->created = (time_t)v;
            else if (sscanf(line, "# modules %ld", &v) == 1)
                expected = (int)v;
            continue;
        }
        if (version != BASELINE_VERSION) {
            baseline_free(b);
            free(buf);
            set_err(err, errsz, "baseline %s: unsupported or missing header", path);
            return -1;
        }

        char *fld[7];
        int nf = 0;
        char *p = line;
        while (nf < 7) {
            fld[nf++] = p;
            char *t = strchr(p, '\t');
            if (!t)
                break;
            *t = '\0';
            p = t + 1;
        }
        if (nf != 7 || strchr(fld[6], '\t')) {
            baseline_free(b);
            free(buf);
            set_err(err, errsz, "baseline %s: malformed entry", path);
            return -1;
        }
        baseline_entry_t e;
        memset(&e, 0, sizeof(e));
        char *end;
        errno = 0;
        e.size = strtoul(fld[1], &end, 10);
        if (strlen(fld[0]) >= MAX_MODULE_NAME ||
            !util_valid_module_name(fld[0]) || *end != '\0' || end == fld[1] ||
            errno == ERANGE || strlen(fld[2]) >= MAX_DEPS_LEN ||
            strlen(fld[3]) >= sizeof(e.srcversion) ||
            strlen(fld[4]) >= sizeof(e.version) ||
            strlen(fld[5]) >= sizeof(e.taint) ||
            strlen(fld[6]) >= sizeof(e.path)) {
            util_sanitize_field(fld[0]);
            set_err(err, errsz, "baseline %s: invalid entry '%.40s'", path, fld[0]);
            baseline_free(b);
            free(buf);
            return -1;
        }
        util_copy(e.name, sizeof(e.name), fld[0]);
        util_copy(e.deps, sizeof(e.deps), fld[2]);
        util_copy(e.srcversion, sizeof(e.srcversion), fld[3]);
        util_copy(e.version, sizeof(e.version), fld[4]);
        util_copy(e.taint, sizeof(e.taint), fld[5]);
        util_copy(e.path, sizeof(e.path), fld[6]);
        unfield(e.srcversion);
        unfield(e.version);
        unfield(e.taint);
        unfield(e.path);

        if (b->count >= MAX_BASELINE_MODULES) {
            baseline_free(b);
            free(buf);
            set_err(err, errsz, "baseline %s has too many entries", path);
            return -1;
        }
        if (b->count == cap) {
            int ncap = cap ? cap * 2 : 64;
            baseline_entry_t *tmp = realloc(b->items, (size_t)ncap * sizeof(*tmp));
            if (!tmp) {
                baseline_free(b);
                free(buf);
                set_err(err, errsz, "out of memory");
                return -1;
            }
            b->items = tmp;
            cap = ncap;
        }
        b->items[b->count++] = e;
    }
    free(buf);

    if (version != BASELINE_VERSION) {
        baseline_free(b);
        set_err(err, errsz, "baseline %s: unsupported or missing header", path);
        return -1;
    }
    if (expected != b->count) {
        baseline_free(b);
        set_err(err, errsz, "baseline %s: entry count does not match header", path);
        return -1;
    }
    if (b->count > 1)
        qsort(b->items, (size_t)b->count, sizeof(*b->items), cmp_entry);
    for (int i = 1; i < b->count; i++)
        if (strcmp(b->items[i - 1].name, b->items[i].name) == 0) {
            baseline_free(b);
            set_err(err, errsz, "baseline %s: duplicate module entry", path);
            return -1;
        }
    return 0;
}

const baseline_entry_t *baseline_find(const baseline_t *b, const char *name)
{
    if (!b || b->count == 0)
        return NULL;
    baseline_entry_t key;
    util_copy(key.name, sizeof(key.name), name);
    return bsearch(&key, b->items, (size_t)b->count, sizeof(*b->items),
                   cmp_entry);
}

void baseline_free(baseline_t *b)
{
    free(b->items);
    memset(b, 0, sizeof(*b));
}

int baseline_entry_diff(const baseline_entry_t *e, const module_record_t *r)
{
    int m = 0;
    if (e->size != r->base.size)
        m |= DIFF_SIZE;
    if (strcmp(e->deps, r->base.deps) != 0)
        m |= DIFF_DEPS;
    /* srcversion/version come from sysfs: without a sysfs entry they are
       unknown, not "changed" (a missing entry is reported by its own rule). */
    if (r->in_sysfs) {
        if (strcmp(e->srcversion, r->srcversion) != 0)
            m |= DIFF_SRCVER;
        if (strcmp(e->version, r->version) != 0)
            m |= DIFF_VERSION;
    }
    return m;
}

int baseline_diff(const baseline_t *b, const scan_result_t *scan,
                  baseline_diff_t *d)
{
    memset(d, 0, sizeof(*d));
    int nr = scan->records.count, nb = b->count;
    d->added = calloc((size_t)(nr ? nr : 1), sizeof(int));
    d->changed = calloc((size_t)(nr ? nr : 1), sizeof(int));
    d->changed_mask = calloc((size_t)(nr ? nr : 1), sizeof(int));
    d->removed = calloc((size_t)(nb ? nb : 1), sizeof(int));
    if (!d->added || !d->changed || !d->changed_mask || !d->removed) {
        baseline_diff_free(d);
        return -1;
    }

    for (int i = 0; i < nr; i++) {
        const module_record_t *r = &scan->records.items[i];
        if (!r->in_proc)
            continue; /* hidden modules are reported by the analyzer */
        const baseline_entry_t *e = baseline_find(b, r->base.name);
        if (!e) {
            d->added[d->n_added++] = i;
            continue;
        }
        int mask = baseline_entry_diff(e, r);
        if (mask) {
            d->changed[d->n_changed] = i;
            d->changed_mask[d->n_changed++] = mask;
        }
    }
    for (int j = 0; j < nb; j++) {
        const module_record_t *r = records_find(&scan->records, b->items[j].name);
        if (!r || !r->in_proc)
            d->removed[d->n_removed++] = j;
    }
    return 0;
}

void baseline_diff_free(baseline_diff_t *d)
{
    free(d->added);
    free(d->removed);
    free(d->changed);
    free(d->changed_mask);
    memset(d, 0, sizeof(*d));
}
