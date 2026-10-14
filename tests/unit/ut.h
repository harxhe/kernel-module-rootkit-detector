#ifndef UT_H
#define UT_H

/* Minimal unit-test harness: each ut_*.c file registers its own tests with
   TEST(name) { ... } and the runner in ut_main.c executes them all. */

#include "sysfs.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void ut_register(const char *name, void (*fn)(void));
void ut_check(int ok, const char *file, int line, const char *expr);

#define TEST(name)                                                           \
    static void name(void);                                                  \
    __attribute__((constructor)) static void ut_reg_##name(void)             \
    {                                                                        \
        ut_register(#name, name);                                            \
    }                                                                        \
    static void name(void)

#define CHECK(cond) ut_check(!!(cond), __FILE__, __LINE__, #cond)

/* ---- shared helpers ---- */

static inline char *ut_write_temp(const char *content)
{
    static char path[8][64];
    static int slot;
    char *p = path[slot++ % 8];
    strcpy(p, "/tmp/kmrd-ut-XXXXXX");
    int fd = mkstemp(p);
    if (fd < 0) {
        perror("mkstemp");
        exit(2);
    }
    size_t n = strlen(content);
    if (write(fd, content, n) != (ssize_t)n)
        exit(2);
    close(fd);
    return p;
}

static inline void ut_sh(const char *cmd)
{
    if (system(cmd) != 0) {
        fprintf(stderr, "ut_sh failed: %s\n", cmd);
        exit(2);
    }
}

static inline void ut_put(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        perror(path);
        exit(2);
    }
    fputs(content, f);
    fclose(f);
}

static inline module_record_t ut_rec(const char *name, unsigned long size,
                                     const char *deps, const char *src)
{
    module_record_t r;
    memset(&r, 0, sizeof(r));
    util_copy(r.base.name, sizeof(r.base.name), name);
    r.base.size = size;
    util_copy(r.base.deps, sizeof(r.base.deps), deps);
    util_copy(r.srcversion, sizeof(r.srcversion), src);
    util_copy(r.initstate, sizeof(r.initstate), "live");
    r.in_proc = 1;
    r.in_sysfs = 1;
    r.in_moddep = 1;
    util_copy(r.path, sizeof(r.path), "kernel/x/y.ko");
    return r;
}

#endif /* UT_H */
