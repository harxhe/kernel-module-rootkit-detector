#include "ut.h"

#define MAX_TESTS 256

typedef struct {
    const char *name;
    void (*fn)(void);
} ut_case_t;

static ut_case_t g_tests[MAX_TESTS];
static int g_ntests, g_checks, g_failed;

void ut_register(const char *name, void (*fn)(void))
{
    if (g_ntests < MAX_TESTS) {
        g_tests[g_ntests].name = name;
        g_tests[g_ntests].fn = fn;
        g_ntests++;
    }
}

void ut_check(int ok, const char *file, int line, const char *expr)
{
    g_checks++;
    if (!ok) {
        g_failed++;
        printf("  FAIL %s:%d: %s\n", file, line, expr);
    }
}

static int cmp_tests(const void *a, const void *b)
{
    return strcmp(((const ut_case_t *)a)->name, ((const ut_case_t *)b)->name);
}

int main(void)
{
    qsort(g_tests, (size_t)g_ntests, sizeof(g_tests[0]), cmp_tests);
    for (int i = 0; i < g_ntests; i++) {
        int before = g_failed;
        g_tests[i].fn();
        printf("%-4s %s\n", g_failed == before ? "ok" : "FAIL", g_tests[i].name);
    }
    printf("\n%d tests, %d checks, %d failed\n", g_ntests, g_checks, g_failed);
    return g_failed ? 1 : 0;
}
