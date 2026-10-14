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
    CHECK(baseline_save("/tmp/kmrd-ut-sb", &s, err, sizeof(err)) == 0);
    CHECK(baseline_load("/tmp/kmrd-ut-sb", b, err, sizeof(err)) == 0);
    unlink("/tmp/kmrd-ut-sb");
    scan_free(&s);
}

TEST(scoring_sums_weights_and_maps_levels)
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
    module_record_t ok2 = ut_rec("good", 100, "-", "S1");
    module_record_t *all[] = {&chg2, &newmod, &sus, &hp, &hs, &ok2};
    for (unsigned i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        records_push(&s.records, all[i]);

    analysis_t a;
    CHECK(analyzer_run(&s, &b, &a) == 0);
    const module_result_t *r;

    r = find_res(&a, "good");
    CHECK(r && r->score == 0 && r->level == RISK_NONE);

    r = find_res(&a, "changed");
    CHECK(r && r->score == W_SRCVERSION_CHANGED + W_SIZE_CHANGED + W_DEPS_CHANGED);
    CHECK(r && r->level == RISK_HIGH);
    for (int i = 0; r && i < r->nfindings; i++)
        CHECK(r->findings[i].weight > 0); /* every indicator carries its weight */

    r = find_res(&a, "brandnew");
    CHECK(r && r->score == W_NOT_IN_BASELINE + W_NO_MODULE_FILE && r->level == RISK_HIGH);

    r = find_res(&a, "diamorphine");
    CHECK(r && r->score == 100 && r->level == RISK_CRITICAL); /* capped */

    r = find_res(&a, "hidden_p");
    CHECK(r && r->score == W_HIDDEN_FROM_PROC && r->level == RISK_CRITICAL);

    r = find_res(&a, "hidden_s");
    CHECK(r && r->score == W_HIDDEN_FROM_SYSFS + W_NOT_IN_BASELINE); /* 100 */

    r = find_res(&a, "gone");
    CHECK(r && r->rec == NULL && r->score == W_MISSING && r->level == RISK_LOW);

    /* highest score first */
    for (int i = 1; i < a.count; i++)
        CHECK(a.items[i - 1].score >= a.items[i].score);
    CHECK(a.max_score == 100 && a.max_level == RISK_CRITICAL);
    CHECK(a.counts[RISK_CRITICAL] == 3); /* diamorphine, hidden_p, hidden_s */
    CHECK(a.counts[RISK_NONE] == 1 && a.flagged == a.count - 1);
    analyzer_free(&a);

    /* kernel mismatch: comparison-based rules are skipped, so no score */
    util_copy(s.kernel, sizeof(s.kernel), "6.2.0-other");
    CHECK(analyzer_run(&s, &b, &a) == 0);
    CHECK(find_res(&a, "changed")->score == 0);
    analyzer_free(&a);

    baseline_free(&b);
    scan_free(&s);
}

TEST(scoring_clean_system_scores_zero)
{
    scan_result_t s;
    mk_scan(&s, "6.1.0-test");
    module_record_t a1 = ut_rec("ext4", 1000, "-", "A");
    records_push(&s.records, &a1);
    analysis_t a;
    CHECK(analyzer_run(&s, NULL, &a) == 0);
    CHECK(a.flagged == 0 && a.max_score == 0 && a.max_level == RISK_NONE);
    analyzer_free(&a);
    scan_free(&s);
}

TEST(scoring_hidden_from_sysfs_is_not_also_changed)
{
    baseline_t b;
    make_baseline(&b);
    scan_result_t s;
    mk_scan(&s, "6.1.0-test");
    module_record_t chg = ut_rec("changed", 100, "-", "");
    chg.in_sysfs = 0;
    records_push(&s.records, &chg);
    analysis_t a;
    CHECK(analyzer_run(&s, &b, &a) == 0);
    CHECK(find_res(&a, "changed")->score == W_HIDDEN_FROM_SYSFS);
    analyzer_free(&a);
    baseline_free(&b);
    scan_free(&s);
}
