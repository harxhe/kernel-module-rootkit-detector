#include "explain.h"
#include "ut.h"

/* Run the analyzer over a scenario and return the evidence text printed for
   one rule of one module (plain ASCII, no ui). */
static char *evidence(const analysis_t *an, const scan_result_t *scan, const baseline_t *b,
                      const char *module, const char *rule)
{
    report_ctx_t ctx = {scan, an, b, "/tmp/base.file", NULL, 0, NULL, 1, "/proc/modules", "/sys/module"};
    FILE *f = tmpfile();
    for (int i = 0; i < an->count; i++) {
        const module_result_t *r = &an->items[i];
        if (strcmp(r->name, module) != 0)
            continue;
        for (int k = 0; k < r->nfindings; k++)
            if (strcmp(r->findings[k].rule, rule) == 0)
                explain_finding(f, &ctx, r, &r->findings[k], NULL, "> ");
    }
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

static void mk_scan(scan_result_t *s)
{
    memset(s, 0, sizeof(*s));
    util_copy(s->kernel, sizeof(s->kernel), "6.1.0-test");
    s->sysfs_available = s->moddep_available = 1;
    s->when = 1700000000;
}

TEST(explain_shows_evidence_for_every_rule)
{
    /* baseline: good, changed, gone */
    scan_result_t s0;
    mk_scan(&s0);
    module_record_t g = ut_rec("good", 100, "-", "S1");
    module_record_t ch = ut_rec("changed", 100, "-", "OLDSRC");
    module_record_t gone = ut_rec("gone", 100, "-", "S3");
    records_push(&s0.records, &g);
    records_push(&s0.records, &ch);
    records_push(&s0.records, &gone);
    char err[256];
    baseline_t b;
    CHECK(baseline_save("/tmp/kmrd-ut-ex", &s0, err, sizeof(err)) == 0);
    CHECK(baseline_load("/tmp/kmrd-ut-ex", &b, err, sizeof(err)) == 0);
    unlink("/tmp/kmrd-ut-ex");
    scan_free(&s0);

    scan_result_t s;
    mk_scan(&s);
    module_record_t chg = ut_rec("changed", 150, "x,", "NEWSRC");
    module_record_t hp = ut_rec("test_hide", 12288, "-", "");
    hp.in_proc = 0;
    module_record_t hs = ut_rec("nosys", 10, "-", "");
    hs.in_sysfs = 0;
    module_record_t nm = ut_rec("diamorphine", 10, "-", "");
    nm.in_moddep = 0;
    util_copy(nm.taint, sizeof(nm.taint), "OE");
    module_record_t dup = ut_rec("dupe", 10, "-", "");
    dup.duplicate = 1;
    module_record_t ld = ut_rec("loading", 10, "-", "");
    util_copy(ld.initstate, sizeof(ld.initstate), "coming");
    module_record_t ex = ut_rec("extra_dir", 10, "-", "");
    util_copy(ex.path, sizeof(ex.path), "extra/foo.ko");
    module_record_t ok = ut_rec("good", 100, "-", "S1");
    module_record_t *all[] = {&chg, &hp, &hs, &nm, &dup, &ld, &ex, &ok};
    for (unsigned i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        records_push(&s.records, all[i]);
    analysis_t an;
    CHECK(analyzer_run(&s, &b, &an) == 0);

    char *t = evidence(&an, &s, &b, "test_hide", "HIDDEN_FROM_PROC");
    CHECK(strstr(t, "!! /proc/modules") != NULL && strstr(t, "not listed") != NULL);
    CHECK(strstr(t, "ok /sys/module/test_hide") != NULL);
    CHECK(strstr(t, "initstate: live, size 12288") != NULL);
    CHECK(strncmp(t, "> ", 2) == 0);                       /* indent applied */
    free(t);

    t = evidence(&an, &s, &b, "nosys", "HIDDEN_FROM_SYSFS");
    CHECK(strstr(t, "ok /proc/modules") != NULL && strstr(t, "directory does not exist") != NULL);
    free(t);

    t = evidence(&an, &s, &b, "diamorphine", "NOT_IN_BASELINE");
    CHECK(strstr(t, "!! /tmp/base.file") != NULL && strstr(t, "no entry for diamorphine") != NULL);
    free(t);

    t = evidence(&an, &s, &b, "changed", "SRCVERSION_CHANGED");
    CHECK(strstr(t, "srcversion OLDSRC") != NULL && strstr(t, "srcversion NEWSRC") != NULL);
    free(t);
    t = evidence(&an, &s, &b, "changed", "SIZE_CHANGED");
    CHECK(strstr(t, "size 100 bytes") != NULL && strstr(t, "size 150 bytes") != NULL);
    free(t);
    t = evidence(&an, &s, &b, "changed", "DEPS_CHANGED");
    CHECK(strstr(t, "deps -") != NULL && strstr(t, "deps x,") != NULL);
    free(t);

    t = evidence(&an, &s, &b, "diamorphine", "NO_MODULE_FILE");
    CHECK(strstr(t, "modules.dep") != NULL && strstr(t, "insmod") != NULL);
    free(t);
    t = evidence(&an, &s, &b, "diamorphine", "SUSPICIOUS_NAME");
    CHECK(strstr(t, "name contains 'diamorphine'") != NULL);
    free(t);
    t = evidence(&an, &s, &b, "diamorphine", "UNSIGNED");
    CHECK(strstr(t, "/sys/module/diamorphine/taint") != NULL && strstr(t, "OE") != NULL);
    free(t);
    t = evidence(&an, &s, &b, "dupe", "DUPLICATE_NAME");
    CHECK(strstr(t, "lists dupe more than once") != NULL);
    free(t);
    t = evidence(&an, &s, &b, "loading", "ABNORMAL_STATE");
    CHECK(strstr(t, "initstate") != NULL && strstr(t, "coming (expected live)") != NULL);
    free(t);
    t = evidence(&an, &s, &b, "extra_dir", "NONSTANDARD_PATH");
    CHECK(strstr(t, "extra/foo.ko (outside kernel/)") != NULL);
    free(t);
    t = evidence(&an, &s, &b, "gone", "MISSING");
    CHECK(strstr(t, "entry exists (size 100)") != NULL && strstr(t, "in neither") != NULL);
    free(t);

    analyzer_free(&an);
    baseline_free(&b);
    scan_free(&s);
}

TEST(explain_uses_styling_only_when_asked)
{
    scan_result_t s;
    mk_scan(&s);
    module_record_t hp = ut_rec("test_hide", 12288, "-", "");
    hp.in_proc = 0;
    records_push(&s.records, &hp);
    analysis_t an;
    CHECK(analyzer_run(&s, NULL, &an) == 0);
    const module_result_t *r = &an.items[0];
    report_ctx_t ctx = {&s, &an, NULL, "x", NULL, 0, NULL, 1, NULL, NULL};
    ui_t fancy = {1, 1};
    FILE *f = tmpfile();
    explain_finding(f, &ctx, r, &r->findings[0], &fancy, "");
    fflush(f);
    long n = ftell(f);
    rewind(f);
    char *t = malloc((size_t)n + 1);
    if (fread(t, 1, (size_t)n, f) != (size_t)n)
        exit(2);
    t[n] = '\0';
    fclose(f);
    CHECK(strstr(t, "\033[") != NULL && strstr(t, "\xe2\x9c\x97") != NULL); /* colour + ✗ */
    CHECK(strstr(t, "/proc/modules") != NULL);   /* NULL path falls back to the default */
    free(t);
    analyzer_free(&an);
    scan_free(&s);
}
