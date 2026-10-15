#include "demo.h"
#include "ut.h"
#include <dirent.h>

static char *run_demo(const ui_t *ui, int *rc)
{
    FILE *f = tmpfile();
    *rc = demo_run(f, ui);
    fflush(f);
    long n = ftell(f);
    rewind(f);
    char *t = malloc((size_t)n + 1);
    if (fread(t, 1, (size_t)n, f) != (size_t)n)
        exit(2);
    t[n] = '\0';
    fclose(f);
    return t;
}

static int entries_in(const char *dir)
{
    DIR *d = opendir(dir);
    int n = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
            n++;
    if (d)
        closedir(d);
    return n;
}

TEST(demo_every_scan_gets_the_expected_verdict)
{
    ui_t plain = {0, 0};
    int rc;
    char *t = run_demo(&plain, &rc);
    CHECK(rc == 0);
    CHECK(strstr(t, "9/9 scans gave the expected verdict") != NULL);
    const char *rows[] = {
        "Clean system, nothing changed",
        "New driver installed the normal way",
        "Unknown module loaded with insmod",
        "Module hides itself from /proc/modules",
        "Module hides itself from /sys/module",
        "Driver binary replaced",
        "Known rootkit name, unsigned module",
        "Module disappeared since the baseline",
        "Baseline file edited by an attacker"};
    for (unsigned i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
        CHECK(strstr(t, rows[i]) != NULL);
    /* the verdicts the design promises */
    CHECK(strstr(t, "CLEAN") != NULL && strstr(t, "MEDIUM") != NULL);
    CHECK(strstr(t, "HIGH") != NULL && strstr(t, "CRITICAL") != NULL);
    CHECK(strstr(t, "REFUSED") != NULL && strstr(t, "LOW") != NULL);
    CHECK(strstr(t, "stealth: HIDDEN_FROM_PROC") != NULL);
    CHECK(strstr(t, "evilmod: NOT_IN_BASELINE + NO_MODULE_FILE") != NULL);
    CHECK(strstr(t, "This machine") != NULL);
    CHECK(strstr(t, "sudo ./detector monitor") != NULL);
    free(t);
}

TEST(demo_plain_is_ascii_and_fancy_is_styled)
{
    ui_t plain = {0, 0}, fancy = {1, 1};
    int rc;
    char *t = run_demo(&plain, &rc);
    for (const char *p = t; *p; p++)
        CHECK((unsigned char)*p < 0x80);
    free(t);
    t = run_demo(&fancy, &rc);
    CHECK(strchr(t, '\033') != NULL && strstr(t, "\xe2\x9c\x94") != NULL); /* colour + check mark */
    CHECK(strstr(t, "\xe2\x95\xad") != NULL);                               /* box */
    free(t);
}

TEST(demo_cleans_up_its_temporary_files)
{
    ut_sh("rm -rf /tmp/kmrd-ut-demotmp && mkdir -p /tmp/kmrd-ut-demotmp");
    setenv("TMPDIR", "/tmp/kmrd-ut-demotmp", 1);
    ui_t plain = {0, 0};
    int rc;
    char *t = run_demo(&plain, &rc);
    free(t);
    CHECK(rc == 0);
    CHECK(entries_in("/tmp/kmrd-ut-demotmp") == 0);   /* nothing left behind */
    unsetenv("TMPDIR");
    ut_sh("rm -rf /tmp/kmrd-ut-demotmp");
}

TEST(demo_fails_cleanly_without_a_temp_directory)
{
    setenv("TMPDIR", "/nonexistent-tmp-dir", 1);
    ui_t plain = {0, 0};
    FILE *f = tmpfile();
    fflush(stderr);
    int saved = dup(2);                       /* keep the expected error message out of the log */
    if (!freopen("/dev/null", "w", stderr))
        exit(2);
    int rc = demo_run(f, &plain);
    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    CHECK(rc == 2);
    fclose(f);
    unsetenv("TMPDIR");
}
