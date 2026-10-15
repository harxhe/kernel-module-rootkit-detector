#include "report.h"
#include "ut.h"

static char *render(const ui_t *ui, int add_hidden, int full)
{
    scan_result_t s;
    memset(&s, 0, sizeof(s));
    util_copy(s.kernel, sizeof(s.kernel), "6.1.0-test");
    s.sysfs_available = s.moddep_available = 1;
    s.when = 1700000000;
    module_record_t a = ut_rec("ext4", 1000, "-", "A");
    records_push(&s.records, &a);
    if (add_hidden) {
        module_record_t h = ut_rec("test_hide", 5, "-", "");
        h.in_proc = 0;
        records_push(&s.records, &h);
    }
    analysis_t an;
    CHECK(analyzer_run(&s, NULL, &an) == 0);
    report_ctx_t ctx = {&s, &an, NULL, "none", "no baseline in this test", full, ui};
    FILE *f = tmpfile();
    report_fancy(f, &ctx);
    fflush(f);
    long n = ftell(f);
    rewind(f);
    char *b = malloc((size_t)n + 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n)
        exit(2);
    b[n] = '\0';
    fclose(f);
    analyzer_free(&an);
    scan_free(&s);
    return b;
}

TEST(report_fancy_flagged_has_colour_box_and_bar)
{
    ui_t ui = {1, 1};
    char *t = render(&ui, 1, 0);
    CHECK(strstr(t, "\033[") != NULL);                         /* colour */
    CHECK(strstr(t, "\xe2\x95\xad") != NULL);                  /* box corner */
    CHECK(strstr(t, "Kernel Module Rootkit Detector") != NULL);
    CHECK(strstr(t, "VERDICT") != NULL && strstr(t, "CRITICAL") != NULL);
    CHECK(strstr(t, "test_hide") != NULL && strstr(t, " 80/100") != NULL);
    CHECK(strstr(t, "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88") != NULL); /* 8 filled cells */
    CHECK(strstr(t, "HIDDEN_FROM_PROC") != NULL);
    free(t);
}

TEST(report_fancy_clean_system)
{
    ui_t ui = {1, 1};
    char *t = render(&ui, 0, 0);
    CHECK(strstr(t, "CLEAN") != NULL && strstr(t, "no suspicious modules detected") != NULL);
    CHECK(strstr(t, "test_hide") == NULL);
    free(t);
}

TEST(report_fancy_without_styling_is_ascii_only)
{
    ui_t ui = {0, 0};
    char *t = render(&ui, 1, 1);
    for (const char *p = t; *p; p++)
        CHECK((unsigned char)*p < 0x80);      /* no escape bytes, no Unicode */
    CHECK(strchr(t, '\033') == NULL);
    CHECK(strstr(t, " +-") != NULL);          /* ASCII box */
    CHECK(strstr(t, "All modules") != NULL && strstr(t, "kernel/x/y.ko") != NULL);
    free(t);
}
