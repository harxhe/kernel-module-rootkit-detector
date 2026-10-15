#include "report.h"
#include "ut.h"

static char *slurp_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n)
        exit(2);
    b[n] = '\0';
    fclose(f);
    return b;
}

static void with_report(int full, int json, char **text, int add_hidden)
{
    scan_result_t s;
    memset(&s, 0, sizeof(s));
    util_copy(s.kernel, sizeof(s.kernel), "6.1.0-test");
    s.sysfs_available = s.moddep_available = 1;
    s.when = 1700000000;
    module_record_t a = ut_rec("ext4", 1000, "-", "A");
    records_push(&s.records, &a);
    if (add_hidden) {
        module_record_t h = ut_rec("evil\"mod\\x", 5, "-", "");
        h.in_proc = 0;
        records_push(&s.records, &h);
    }
    analysis_t an;
    CHECK(analyzer_run(&s, NULL, &an) == 0);
    report_ctx_t ctx = {&s, &an, NULL, "none", "no baseline in this test", full, NULL, 0, NULL, NULL};
    const char *p = "/tmp/kmrd-ut-report";
    FILE *f = fopen(p, "w");
    if (json)
        report_json(f, &ctx);
    else
        report_text(f, &ctx);
    fclose(f);
    *text = slurp_file(p);
    unlink(p);
    analyzer_free(&an);
    scan_free(&s);
}

TEST(report_text_clean_and_flagged)
{
    char *t;
    with_report(0, 0, &t, 0);
    CHECK(strstr(t, "Overall risk: CLEAN") != NULL);
    CHECK(strstr(t, "No suspicious modules detected") != NULL);
    CHECK(strstr(t, "All modules:") == NULL);
    free(t);

    with_report(0, 0, &t, 1);
    CHECK(strstr(t, "Overall risk: CRITICAL") != NULL);
    CHECK(strstr(t, "HIDDEN_FROM_PROC") != NULL);
    CHECK(strstr(t, "Summary: 1 flagged") != NULL);
    free(t);

    with_report(1, 0, &t, 0);
    CHECK(strstr(t, "All modules:") != NULL && strstr(t, "ext4") != NULL);
    free(t);
}

TEST(report_json_is_escaped_and_structured)
{
    char *t;
    with_report(0, 1, &t, 1);
    CHECK(strstr(t, "\"overall_risk\": \"CRITICAL\"") != NULL);
    CHECK(strstr(t, "\"module\": \"evil\\\"mod\\\\x\"") != NULL); /* escaped */
    CHECK(strstr(t, "\"rule\": \"HIDDEN_FROM_PROC\"") != NULL);
    CHECK(t[0] == '{');
    int depth = 0;
    for (char *p = t; *p; p++)
        depth += (*p == '{') - (*p == '}');
    CHECK(depth == 0);
    free(t);

    with_report(0, 1, &t, 0);
    CHECK(strstr(t, "\"suspicious\": []") != NULL);
    free(t);
}

TEST(report_log_appends)
{
    scan_result_t s;
    memset(&s, 0, sizeof(s));
    util_copy(s.kernel, sizeof(s.kernel), "6.1.0-test");
    s.when = 1700000000;
    module_record_t h = ut_rec("rogue", 5, "-", "");
    h.in_proc = 0;
    records_push(&s.records, &h);
    analysis_t an;
    CHECK(analyzer_run(&s, NULL, &an) == 0);
    report_ctx_t ctx = {&s, &an, NULL, "x", NULL, 0, NULL, 0, NULL, NULL};
    const char *p = "/tmp/kmrd-ut-log";
    unlink(p);
    CHECK(report_append_log(p, &ctx) == 0);
    CHECK(report_append_log(p, &ctx) == 0);
    char *t = slurp_file(p);
    int lines = 0;
    for (char *q = t; *q; q++)
        lines += *q == '\n';
    CHECK(lines == 4); /* 2 entries x (summary + 1 flagged module) */
    CHECK(strstr(t, "CRITICAL rogue score=80 rules=HIDDEN_FROM_PROC") != NULL);
    free(t);
    CHECK(report_append_log("/nonexistent-dir/x.log", &ctx) == -1);
    unlink(p);
    analyzer_free(&an);
    scan_free(&s);
}
