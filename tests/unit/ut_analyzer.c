#include "analyzer.h"
#include "ut.h"

static void mk_scan(scan_result_t *s, const char *kernel)
{
    memset(s, 0, sizeof(*s));
    util_copy(s->kernel, sizeof(s->kernel), kernel);
    s->sysfs_available = 1;
    s->moddep_available = 1;
    s->when = 1700000000;
}

static const module_result_t *find_res(const analysis_t *a, const char *name)
{
    for (int i = 0; i < a->count; i++)
        if (strcmp(a->items[i].name, name) == 0)
            return &a->items[i];
    return NULL;
}

static int has_rule(const module_result_t *r, const char *rule)
{
    for (int i = 0; r && i < r->nfindings; i++)
        if (strcmp(r->findings[i].rule, rule) == 0)
            return 1;
    return 0;
}

/* baseline of three modules: good, changed, gone */
static void make_baseline(baseline_t *b)
{
    scan_result_t s;
    mk_scan(&s, "6.1.0-test");
    module_record_t ok = ut_rec("good", 100, "-", "S1");
    module_record_t chg = ut_rec("changed", 100, "-", "S2");
    module_record_t gone = ut_rec("gone", 100, "-", "S3");
    records_push(&s.records, &ok);
    records_push(&s.records, &chg);
    records_push(&s.records, &gone);
    char err[256];
    CHECK(baseline_save("/tmp/kmrd-ut-ab", &s, err, sizeof(err)) == 0);
    CHECK(baseline_load("/tmp/kmrd-ut-ab", b, err, sizeof(err)) == 0);
    unlink("/tmp/kmrd-ut-ab");
    scan_free(&s);
}

TEST(analyzer_clean_system_has_no_findings)
{
    scan_result_t s;
    mk_scan(&s, "6.1.0-test");
    module_record_t a = ut_rec("ext4", 1000, "mbcache,", "A");
    module_record_t b2 = ut_rec("mbcache", 200, "-", "B");
    records_push(&s.records, &a);
    records_push(&s.records, &b2);
    char err[256];
    baseline_t b;
    CHECK(baseline_save("/tmp/kmrd-ut-b4", &s, err, sizeof(err)) == 0);
    CHECK(baseline_load("/tmp/kmrd-ut-b4", &b, err, sizeof(err)) == 0);
    unlink("/tmp/kmrd-ut-b4");

    analysis_t an;
    CHECK(analyzer_run(&s, &b, &an) == 0);
    CHECK(an.flagged == 0 && an.count == 2);
    analyzer_free(&an);
    baseline_free(&b);
    scan_free(&s);
}

TEST(analyzer_each_rule_fires)
{
    baseline_t b;
    make_baseline(&b);

    scan_result_t s;
    mk_scan(&s, "6.1.0-test");
    module_record_t chg2 = ut_rec("changed", 150, "x,", "S2-DIFFERENT");
    module_record_t newmod = ut_rec("brandnew", 10, "-", "N");
    newmod.in_moddep = 0;
    newmod.path[0] = '\0';
    module_record_t sus = ut_rec("diamorphine", 10, "-", "N");
    sus.in_moddep = 0;
    util_copy(sus.taint, sizeof(sus.taint), "OE");
    module_record_t hp = ut_rec("hidden_p", 10, "-", "");
    hp.in_proc = 0;
    module_record_t hs = ut_rec("hidden_s", 10, "-", "");
    hs.in_sysfs = 0;
    module_record_t dup = ut_rec("dupe", 10, "-", "");
    dup.duplicate = 1;
    module_record_t ld = ut_rec("loading", 10, "-", "");
    util_copy(ld.initstate, sizeof(ld.initstate), "coming");
    module_record_t ex = ut_rec("extra_dir", 10, "-", "");
    util_copy(ex.path, sizeof(ex.path), "extra/foo.ko");
    module_record_t prop = ut_rec("prop", 10, "-", "");
    util_copy(prop.taint, sizeof(prop.taint), "P");
    module_record_t ok2 = ut_rec("good", 100, "-", "S1");
    module_record_t *all[] = {&chg2, &newmod, &sus, &hp, &hs, &dup, &ld, &ex, &prop, &ok2};
    for (unsigned i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        records_push(&s.records, all[i]);

    analysis_t a;
    CHECK(analyzer_run(&s, &b, &a) == 0);
    const module_result_t *r;

    r = find_res(&a, "good");
    CHECK(r && r->nfindings == 0);

    r = find_res(&a, "changed");
    CHECK(has_rule(r, "SRCVERSION_CHANGED") && has_rule(r, "SIZE_CHANGED") &&
          has_rule(r, "DEPS_CHANGED"));

    r = find_res(&a, "brandnew");
    CHECK(has_rule(r, "NOT_IN_BASELINE") && has_rule(r, "NO_MODULE_FILE"));

    r = find_res(&a, "diamorphine");
    CHECK(has_rule(r, "SUSPICIOUS_NAME") && has_rule(r, "UNSIGNED") &&
          has_rule(r, "OUT_OF_TREE"));

    r = find_res(&a, "hidden_p");
    CHECK(has_rule(r, "HIDDEN_FROM_PROC"));
    CHECK(!has_rule(r, "NOT_IN_BASELINE")); /* not double counted */

    r = find_res(&a, "hidden_s");
    CHECK(has_rule(r, "HIDDEN_FROM_SYSFS") && has_rule(r, "NOT_IN_BASELINE"));

    CHECK(has_rule(find_res(&a, "dupe"), "DUPLICATE_NAME"));
    CHECK(has_rule(find_res(&a, "loading"), "ABNORMAL_STATE"));
    CHECK(has_rule(find_res(&a, "extra_dir"), "NONSTANDARD_PATH"));
    CHECK(has_rule(find_res(&a, "prop"), "PROPRIETARY"));

    r = find_res(&a, "gone");
    CHECK(r && r->rec == NULL && has_rule(r, "MISSING"));

    CHECK(a.flagged == 10); /* every module but "good" (ordering: see ut_scoring.c) */
    analyzer_free(&a);

    /* kernel mismatch: comparison-based rules must be skipped */
    util_copy(s.kernel, sizeof(s.kernel), "6.2.0-other");
    CHECK(analyzer_run(&s, &b, &a) == 0);
    CHECK(a.env.kernel_mismatch);
    CHECK(find_res(&a, "changed")->nfindings == 0);
    CHECK(has_rule(find_res(&a, "brandnew"), "NOT_IN_BASELINE")); /* still reported */
    analyzer_free(&a);

    /* without a baseline only the heuristic rules run */
    CHECK(analyzer_run(&s, NULL, &a) == 0);
    r = find_res(&a, "brandnew");
    CHECK(!has_rule(r, "NOT_IN_BASELINE") && has_rule(r, "NO_MODULE_FILE"));
    CHECK(find_res(&a, "gone") == NULL);
    analyzer_free(&a);

    /* environment limits: no sysfs / no modules.dep -> those rules skip */
    s.sysfs_available = 0;
    s.moddep_available = 0;
    CHECK(analyzer_run(&s, NULL, &a) == 0);
    CHECK(!has_rule(find_res(&a, "hidden_s"), "HIDDEN_FROM_SYSFS"));
    CHECK(!has_rule(find_res(&a, "brandnew"), "NO_MODULE_FILE"));
    CHECK(has_rule(find_res(&a, "hidden_p"), "HIDDEN_FROM_PROC"));
    analyzer_free(&a);

    baseline_free(&b);
    scan_free(&s);
}

TEST(analyzer_hidden_module_without_sysfs_srcversion_is_not_changed)
{
    /* a module hidden from sysfs has an unreadable (empty) srcversion; that
       must not also be reported as "binary changed" */
    baseline_t b;
    make_baseline(&b);
    scan_result_t s;
    mk_scan(&s, "6.1.0-test");
    module_record_t chg = ut_rec("changed", 100, "-", "");
    chg.in_sysfs = 0;
    records_push(&s.records, &chg);
    analysis_t a;
    CHECK(analyzer_run(&s, &b, &a) == 0);
    const module_result_t *r = find_res(&a, "changed");
    CHECK(has_rule(r, "HIDDEN_FROM_SYSFS") && !has_rule(r, "SRCVERSION_CHANGED"));
    CHECK(r && r->nfindings == 1);
    analyzer_free(&a);
    baseline_free(&b);
    scan_free(&s);
}

TEST(analyzer_suspicious_names)
{
    const char *tok;
    CHECK(analyzer_name_is_suspicious("diamorphine", &tok));
    CHECK(analyzer_name_is_suspicious("My_ReptiLe_v2", &tok));
    CHECK(analyzer_name_is_suspicious("rootkit", NULL));
    CHECK(!analyzer_name_is_suspicious("ext4", &tok));
    CHECK(!analyzer_name_is_suspicious("nf_conntrack", &tok));
    CHECK(!analyzer_name_is_suspicious("snd_hda_intel", &tok));
    CHECK(!analyzer_name_is_suspicious("usbcore", &tok));
}

TEST(analyzer_rule_table_is_populated)
{
    CHECK(g_rule_count >= 8);
    for (int i = 0; i < g_rule_count; i++)
        CHECK(g_rules[i] != NULL);
}
