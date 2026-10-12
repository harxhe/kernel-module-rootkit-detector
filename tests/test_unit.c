/* Unit tests for the detector library (no kernel access needed). */

#include "analyzer.h"
#include "baseline.h"
#include "metadata.h"
#include "moddep.h"
#include "module_scanner.h"
#include "risk.h"
#include "scan.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_checks, g_failed;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failed++;                                                      \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                    \
    } while (0)

#define RUN(fn)                                                              \
    do {                                                                     \
        int before = g_failed;                                               \
        fn();                                                                \
        printf("%-4s %s\n", g_failed == before ? "ok" : "FAIL", #fn);        \
    } while (0)

/* ---- helpers --------------------------------------------------------- */

static char *write_temp(const char *content)
{
    static char path[4][64];
    static int slot;
    char *p = path[slot++ % 4];
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

static module_record_t mk_rec(const char *name, unsigned long size,
                              const char *deps, const char *src)
{
    module_record_t r;
    memset(&r, 0, sizeof(r));
    util_copy(r.base.name, sizeof(r.base.name), name);
    r.base.size = size;
    util_copy(r.base.deps, sizeof(r.base.deps), deps);
    util_copy(r.base.state, sizeof(r.base.state), "Live");
    util_copy(r.srcversion, sizeof(r.srcversion), src);
    util_copy(r.initstate, sizeof(r.initstate), "live");
    r.in_proc = 1;
    r.in_sysfs = 1;
    r.in_moddep = 1;
    util_copy(r.path, sizeof(r.path), "kernel/x/y.ko");
    return r;
}

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

/* ---- util ------------------------------------------------------------ */

static void test_valid_names(void)
{
    CHECK(util_valid_module_name("ext4"));
    CHECK(util_valid_module_name("nf_conntrack-ipv4.x"));
    CHECK(!util_valid_module_name(""));
    CHECK(!util_valid_module_name("."));
    CHECK(!util_valid_module_name(".."));
    CHECK(!util_valid_module_name("../etc/passwd"));
    CHECK(!util_valid_module_name("a/b"));
    CHECK(!util_valid_module_name("a b"));
    CHECK(!util_valid_module_name("a\nb"));
    CHECK(!util_valid_module_name(NULL));
}

static void test_util_copy_and_join(void)
{
    char b[8];
    util_copy(b, sizeof(b), "0123456789");
    CHECK(strcmp(b, "0123456") == 0);
    util_copy(b, sizeof(b), "ab");
    CHECK(strcmp(b, "ab") == 0);
    char p[16];
    CHECK(util_path_join(p, sizeof(p), "/sys", "ext4", "taint") == 0);
    CHECK(strcmp(p, "/sys/ext4/taint") == 0);
    CHECK(util_path_join(p, sizeof(p), "/sys/module", "longername", "x") == -1);
    char t[] = "a\tb\nc";
    util_sanitize_field(t);
    CHECK(strcmp(t, "a b c") == 0);
}

/* ---- scanner --------------------------------------------------------- */

static void test_parse_line(void)
{
    module_info_t m;
    char l1[] = "nf_tables 286720 91 nft_chain_nat,nft_ct, Live 0xffffffffc0b2e000";
    CHECK(scanner_parse_line(l1, &m) == 0);
    CHECK(strcmp(m.name, "nf_tables") == 0);
    CHECK(m.size == 286720 && m.ref_count == 91);
    CHECK(strcmp(m.deps, "nft_chain_nat,nft_ct,") == 0);
    CHECK(strcmp(m.state, "Live") == 0);
    CHECK(m.address == 0xffffffffc0b2e000UL);
    CHECK(m.proc_flags[0] == '\0');

    char l2[] = "vboxdrv 618496 3 vboxnetadp,vboxnetflt, Live 0x0000000000000000 (OE)";
    CHECK(scanner_parse_line(l2, &m) == 0);
    CHECK(strcmp(m.proc_flags, "OE") == 0);

    char l3[] = "tiny 100 0";                 /* only the 3 mandatory fields */
    CHECK(scanner_parse_line(l3, &m) == 0);
    CHECK(strcmp(m.deps, "-") == 0 && m.state[0] == '\0');

    char l4[] = "perm 100 0 [permanent], Live 0x0";
    CHECK(scanner_parse_line(l4, &m) == 0);
    CHECK(strcmp(m.deps, "[permanent],") == 0);

    char l5[] = "odd 100 - - Live 0x1";        /* non-numeric refcount */
    CHECK(scanner_parse_line(l5, &m) == 0 && m.ref_count == 0);
}

static void test_parse_line_malformed(void)
{
    module_info_t m;
    char a[] = "onlyname";
    char b[] = "name notanumber 1 - Live 0x0";
    char c[] = "../../etc/passwd 100 1 - Live 0x0";
    char d[] = "name 99999999999999999999999999 1 - Live 0x0";
    char e[] = "";
    char f[] = "   \t  ";
    char g[] = "name -5 1";
    char longname[200];
    memset(longname, 'a', sizeof(longname));
    memcpy(longname + 150, " 100 1 - Live 0x0", 18);
    CHECK(scanner_parse_line(a, &m) == -1);
    CHECK(scanner_parse_line(b, &m) == -1);
    CHECK(scanner_parse_line(c, &m) == -1);
    CHECK(scanner_parse_line(d, &m) == -1);
    CHECK(scanner_parse_line(e, &m) == -1);
    CHECK(scanner_parse_line(f, &m) == -1);
    CHECK(scanner_parse_line(g, &m) == -1 || m.size > 0); /* strtoul accepts '-' */
    CHECK(scanner_parse_line(longname, &m) == -1);
}

static void test_read_modules(void)
{
    const char *content =
        "ext4 1000 1 mbcache,jbd2, Live 0x1\n"
        "garbage line here that is not a module\n"
        "\n"
        "../evil 5 1 - Live 0x0\n"
        "mbcache 200 1 ext4, Live 0x2\n"
        "no_newline_at_end 300 0 - Live 0x3";
    char *p = write_temp(content);
    module_list_t l;
    CHECK(scanner_read_modules(p, &l) == 0);
    CHECK(l.count == 3);
    CHECK(l.skipped == 2);
    CHECK(strcmp(l.items[2].name, "no_newline_at_end") == 0);
    scanner_free_modules(&l);
    unlink(p);

    CHECK(scanner_read_modules("/nonexistent/file", &l) == -1);

    p = write_temp("");
    CHECK(scanner_read_modules(p, &l) == 0 && l.count == 0);
    scanner_free_modules(&l);
    unlink(p);
}

static void test_read_many_modules(void)
{
    /* exercises list growth well past the initial capacity */
    FILE *f = fopen("/tmp/kmrd-ut-many", "w");
    for (int i = 0; i < 5000; i++)
        fprintf(f, "mod%d %d 0 - Live 0x%x\n", i, 1000 + i, i);
    fclose(f);
    module_list_t l;
    CHECK(scanner_read_modules("/tmp/kmrd-ut-many", &l) == 0);
    CHECK(l.count == 5000 && l.skipped == 0);
    CHECK(strcmp(l.items[4999].name, "mod4999") == 0);
    scanner_free_modules(&l);
    unlink("/tmp/kmrd-ut-many");
}

/* ---- modules.dep ----------------------------------------------------- */

static void test_moddep(void)
{
    char *p = write_temp(
        "kernel/fs/ext4/ext4.ko.xz: kernel/fs/jbd2/jbd2.ko.xz kernel/fs/mbcache.ko.xz\n"
        "kernel/fs/jbd2/jbd2.ko.xz:\n"
        "kernel/net/netfilter/nf-tables.ko.zst:\n"
        "extra/vboxdrv.ko:\n"
        "updates/dkms/foo.ko.gz:\n"
        "this line has no colon\n"
        "kernel/weird/..ko:\n");
    moddep_t md;
    CHECK(moddep_load(p, &md) == 0 && md.loaded);
    CHECK(md.count == 5);
    CHECK(moddep_lookup(&md, "ext4") != NULL);
    CHECK(strcmp(moddep_lookup(&md, "ext4"), "kernel/fs/ext4/ext4.ko.xz") == 0);
    CHECK(moddep_lookup(&md, "nf_tables") != NULL);  /* '-' vs '_' */
    CHECK(moddep_lookup(&md, "nf-tables") != NULL);
    CHECK(strcmp(moddep_lookup(&md, "vboxdrv"), "extra/vboxdrv.ko") == 0);
    CHECK(moddep_lookup(&md, "foo") != NULL);
    CHECK(moddep_lookup(&md, "rogue") == NULL);
    moddep_free(&md);
    unlink(p);

    CHECK(moddep_load("/nonexistent", &md) == -1 && !md.loaded);
    CHECK(moddep_lookup(&md, "ext4") == NULL);
}

/* ---- risk ------------------------------------------------------------ */

static void test_risk_levels(void)
{
    CHECK(risk_level_from_score(0) == RISK_NONE);
    CHECK(risk_level_from_score(1) == RISK_LOW);
    CHECK(risk_level_from_score(24) == RISK_LOW);
    CHECK(risk_level_from_score(25) == RISK_MEDIUM);
    CHECK(risk_level_from_score(49) == RISK_MEDIUM);
    CHECK(risk_level_from_score(50) == RISK_HIGH);
    CHECK(risk_level_from_score(74) == RISK_HIGH);
    CHECK(risk_level_from_score(75) == RISK_CRITICAL);
    CHECK(risk_level_from_score(100) == RISK_CRITICAL);
    CHECK(risk_cap(250) == 100 && risk_cap(-5) == 0 && risk_cap(42) == 42);
    CHECK(strcmp(risk_level_name(RISK_HIGH), "HIGH") == 0);

    risk_level_t l;
    CHECK(risk_level_parse("High", &l) == 0 && l == RISK_HIGH);
    CHECK(risk_level_parse("CRITICAL", &l) == 0 && l == RISK_CRITICAL);
    CHECK(risk_level_parse("bogus", &l) == -1);
    CHECK(risk_level_parse(NULL, &l) == -1);
}

/* ---- baseline -------------------------------------------------------- */

static void build_scan(scan_result_t *s)
{
    mk_scan(s, "6.1.0-test");
    module_record_t a = mk_rec("ext4", 1000, "mbcache,jbd2,", "AAAA1111");
    module_record_t b = mk_rec("mbcache", 200, "-", "");
    util_copy(b.version, sizeof(b.version), "1.0 beta");
    module_record_t c = mk_rec("hidden_one", 50, "-", "");
    c.in_proc = 0;
    records_push(&s->records, &a);
    records_push(&s->records, &b);
    records_push(&s->records, &c);
}

static void test_baseline_roundtrip(void)
{
    scan_result_t s;
    build_scan(&s);
    char err[256];
    const char *path = "/tmp/kmrd-ut-baseline";
    CHECK(baseline_save(path, &s, err, sizeof(err)) == 0);

    baseline_t b;
    CHECK(baseline_load(path, &b, err, sizeof(err)) == 0);
    CHECK(b.count == 2); /* hidden (not in /proc) modules are never baselined */
    CHECK(strcmp(b.kernel, "6.1.0-test") == 0);
    CHECK(b.created == 1700000000);
    const baseline_entry_t *e = baseline_find(&b, "ext4");
    CHECK(e && e->size == 1000 && strcmp(e->deps, "mbcache,jbd2,") == 0);
    CHECK(e && strcmp(e->srcversion, "AAAA1111") == 0);
    const baseline_entry_t *m = baseline_find(&b, "mbcache");
    CHECK(m && strcmp(m->deps, "-") == 0 && m->srcversion[0] == '\0');
    CHECK(m && strcmp(m->version, "1.0 beta") == 0);
    CHECK(baseline_find(&b, "hidden_one") == NULL);
    CHECK(baseline_find(&b, "nope") == NULL);

    /* a freshly saved baseline must produce no differences */
    baseline_diff_t d;
    CHECK(baseline_diff(&b, &s, &d) == 0);
    CHECK(d.n_added == 0 && d.n_removed == 0 && d.n_changed == 0);
    baseline_diff_free(&d);

    /* ... and a change must be reported */
    s.records.items[0].base.size = 2000;
    CHECK(baseline_diff(&b, &s, &d) == 0);
    CHECK(d.n_changed == 1 && (d.changed_mask[0] & DIFF_SIZE));
    baseline_diff_free(&d);

    baseline_free(&b);
    scan_free(&s);
    unlink(path);
}

static char *slurp(const char *path, long *len)
{
    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)*len + 1);
    if (fread(buf, 1, (size_t)*len, f) != (size_t)*len)
        exit(2);
    fclose(f);
    buf[*len] = '\0';
    return buf;
}

static void spit(const char *path, const char *buf, long len)
{
    FILE *f = fopen(path, "wb");
    fwrite(buf, 1, (size_t)len, f);
    fclose(f);
}

/* write a baseline body and append a *correct* checksum, to test the
   structural validators independently of the checksum */
static void spit_with_checksum(const char *path, const char *body)
{
    uint64_t h = util_fnv1a(UTIL_FNV_INIT, body, strlen(body));
    FILE *f = fopen(path, "wb");
    fputs(body, f);
    fprintf(f, "# checksum %016llx\n", (unsigned long long)h);
    fclose(f);
}

static void test_baseline_rejects_tampering(void)
{
    scan_result_t s;
    build_scan(&s);
    char err[256];
    const char *path = "/tmp/kmrd-ut-baseline2";
    CHECK(baseline_save(path, &s, err, sizeof(err)) == 0);
    long len;
    char *orig = slurp(path, &len);
    baseline_t b;

    /* flip one digit of a size */
    char *copy = malloc((size_t)len + 1);
    memcpy(copy, orig, (size_t)len + 1);
    char *pos = strstr(copy, "\t1000\t");
    CHECK(pos != NULL);
    if (pos)
        pos[1] = '9';
    spit(path, copy, len);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);
    CHECK(strstr(err, "checksum") != NULL);

    /* truncated: lose the checksum line */
    spit(path, orig, len - 30);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);

    /* empty / missing */
    spit(path, "", 0);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);
    CHECK(baseline_load("/nonexistent/baseline", &b, err, sizeof(err)) == -1);

    /* binary garbage */
    spit(path, "\x01\x02\x03\xff\xfe garbage", 14);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);

    free(copy);
    free(orig);
    scan_free(&s);
    unlink(path);
}

static void test_baseline_structure_checks(void)
{
    baseline_t b;
    char err[256];
    const char *path = "/tmp/kmrd-ut-baseline3";
    const char *hdr = "# kmrd-baseline 1\n# kernel k\n# created 1\n";

    char body[1024];

    /* count in header does not match entries */
    snprintf(body, sizeof(body), "%s# modules 2\nfoo\t1\t-\t-\t-\t-\t-\n", hdr);
    spit_with_checksum(path, body);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);
    CHECK(strstr(err, "count") != NULL);

    /* duplicate module */
    snprintf(body, sizeof(body),
             "%s# modules 2\nfoo\t1\t-\t-\t-\t-\t-\nfoo\t2\t-\t-\t-\t-\t-\n", hdr);
    spit_with_checksum(path, body);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);
    CHECK(strstr(err, "duplicate") != NULL);

    /* wrong number of fields */
    snprintf(body, sizeof(body), "%s# modules 1\nfoo\t1\t-\n", hdr);
    spit_with_checksum(path, body);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);

    /* path-traversal module name */
    snprintf(body, sizeof(body), "%s# modules 1\n../x\t1\t-\t-\t-\t-\t-\n", hdr);
    spit_with_checksum(path, body);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);

    /* bad size */
    snprintf(body, sizeof(body), "%s# modules 1\nfoo\tabc\t-\t-\t-\t-\t-\n", hdr);
    spit_with_checksum(path, body);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);

    /* unsupported version */
    snprintf(body, sizeof(body),
             "# kmrd-baseline 99\n# kernel k\n# created 1\n# modules 1\nfoo\t1\t-\t-\t-\t-\t-\n");
    spit_with_checksum(path, body);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == -1);

    /* valid minimal file loads */
    snprintf(body, sizeof(body), "%s# modules 1\nfoo\t1\t-\t-\t-\t-\t-\n", hdr);
    spit_with_checksum(path, body);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == 0 && b.count == 1);
    baseline_free(&b);

    /* zero modules is a valid (if odd) baseline */
    snprintf(body, sizeof(body), "%s# modules 0\n", hdr);
    spit_with_checksum(path, body);
    CHECK(baseline_load(path, &b, err, sizeof(err)) == 0 && b.count == 0);
    baseline_free(&b);
    unlink(path);
}

static void test_entry_diff_without_sysfs(void)
{
    baseline_entry_t e;
    memset(&e, 0, sizeof(e));
    util_copy(e.name, sizeof(e.name), "m");
    e.size = 100;
    util_copy(e.deps, sizeof(e.deps), "-");
    util_copy(e.srcversion, sizeof(e.srcversion), "ABC");
    util_copy(e.version, sizeof(e.version), "1.0");

    module_record_t r = mk_rec("m", 100, "-", "ABC");
    util_copy(r.version, sizeof(r.version), "1.0");
    CHECK(baseline_entry_diff(&e, &r) == 0);

    r.in_sysfs = 0;              /* srcversion/version unreadable, not changed */
    r.srcversion[0] = '\0';
    r.version[0] = '\0';
    CHECK(baseline_entry_diff(&e, &r) == 0);

    r.in_sysfs = 1;              /* readable and different -> changed */
    CHECK((baseline_entry_diff(&e, &r) & DIFF_SRCVER) != 0);
    r.base.size = 5;
    CHECK((baseline_entry_diff(&e, &r) & DIFF_SIZE) != 0);
}

static void test_baseline_save_failure(void)
{
    scan_result_t s;
    build_scan(&s);
    char err[256] = "";
    CHECK(baseline_save("/nonexistent-dir/deeper/baseline", &s, err, sizeof(err)) == -1);
    CHECK(err[0] != '\0');
    scan_free(&s);
}

/* ---- analyzer -------------------------------------------------------- */

static void test_analyzer_clean(void)
{
    scan_result_t s;
    build_scan(&s);
    s.records.items[2].in_proc = 1;  /* make "hidden_one" an ordinary module */
    s.records.items[2].in_moddep = 1;
    char err[256];
    baseline_t b;
    CHECK(baseline_save("/tmp/kmrd-ut-b4", &s, err, sizeof(err)) == 0);
    CHECK(baseline_load("/tmp/kmrd-ut-b4", &b, err, sizeof(err)) == 0);

    analysis_t a;
    CHECK(analyzer_run(&s, &b, &a) == 0);
    CHECK(a.flagged == 0 && a.max_score == 0);
    CHECK(a.count == 3);
    analyzer_free(&a);

    baseline_free(&b);
    scan_free(&s);
    unlink("/tmp/kmrd-ut-b4");
}

static void test_analyzer_rules(void)
{
    scan_result_t s;
    mk_scan(&s, "6.1.0-test");
    module_record_t ok = mk_rec("good", 100, "-", "S1");
    module_record_t chg = mk_rec("changed", 100, "-", "S2");
    module_record_t gone = mk_rec("gone", 100, "-", "S3");
    records_push(&s.records, &ok);
    records_push(&s.records, &chg);
    records_push(&s.records, &gone);
    char err[256];
    baseline_t b;
    CHECK(baseline_save("/tmp/kmrd-ut-b5", &s, err, sizeof(err)) == 0);
    CHECK(baseline_load("/tmp/kmrd-ut-b5", &b, err, sizeof(err)) == 0);
    unlink("/tmp/kmrd-ut-b5");

    /* mutate the "current" state */
    records_free(&s.records);
    module_record_t chg2 = mk_rec("changed", 150, "x,", "S2-DIFFERENT");
    module_record_t newmod = mk_rec("brandnew", 10, "-", "N");
    newmod.in_moddep = 0;
    newmod.path[0] = '\0';
    module_record_t sus = mk_rec("diamorphine", 10, "-", "N");
    sus.in_moddep = 0;
    util_copy(sus.taint, sizeof(sus.taint), "OE");
    module_record_t hp = mk_rec("hidden_p", 10, "-", "");
    hp.in_proc = 0;
    module_record_t hs = mk_rec("hidden_s", 10, "-", "");
    hs.in_sysfs = 0;
    module_record_t dup = mk_rec("dupe", 10, "-", "");
    dup.duplicate = 1;
    module_record_t ld = mk_rec("loading", 10, "-", "");
    util_copy(ld.base.state, sizeof(ld.base.state), "Loading");
    module_record_t ex = mk_rec("extra_dir", 10, "-", "");
    util_copy(ex.path, sizeof(ex.path), "extra/foo.ko");
    module_record_t ok2 = mk_rec("good", 100, "-", "S1");
    module_record_t *all[] = {&chg2, &newmod, &sus, &hp, &hs, &dup, &ld, &ex, &ok2};
    for (unsigned i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        records_push(&s.records, all[i]);

    analysis_t a;
    CHECK(analyzer_run(&s, &b, &a) == 0);

    const module_result_t *r;
    r = find_res(&a, "good");
    CHECK(r && r->score == 0 && r->level == RISK_NONE);

    r = find_res(&a, "changed");
    CHECK(has_rule(r, "SRCVERSION_CHANGED") && has_rule(r, "SIZE_CHANGED") &&
          has_rule(r, "DEPS_CHANGED"));
    CHECK(r && r->score == W_SRCVERSION_CHANGED + W_SIZE_CHANGED + W_DEPS_CHANGED);
    CHECK(r && r->level == RISK_HIGH);

    r = find_res(&a, "brandnew");
    CHECK(has_rule(r, "NOT_IN_BASELINE") && has_rule(r, "NO_MODULE_FILE"));
    CHECK(r && r->score == W_NOT_IN_BASELINE + W_NO_MODULE_FILE && r->level == RISK_HIGH);

    r = find_res(&a, "diamorphine");
    CHECK(has_rule(r, "SUSPICIOUS_NAME") && has_rule(r, "UNSIGNED") &&
          has_rule(r, "OUT_OF_TREE"));
    CHECK(r && r->score == 100 && r->level == RISK_CRITICAL); /* capped */

    r = find_res(&a, "hidden_p");
    CHECK(has_rule(r, "HIDDEN_FROM_PROC") && r->level == RISK_CRITICAL);
    CHECK(!has_rule(r, "NOT_IN_BASELINE")); /* not double counted */

    r = find_res(&a, "hidden_s");
    CHECK(has_rule(r, "HIDDEN_FROM_SYSFS") && has_rule(r, "NOT_IN_BASELINE"));
    CHECK(r && r->score == W_HIDDEN_FROM_SYSFS + W_NOT_IN_BASELINE); /* 100 */

    r = find_res(&a, "dupe");
    CHECK(has_rule(r, "DUPLICATE_NAME"));

    r = find_res(&a, "loading");
    CHECK(has_rule(r, "ABNORMAL_STATE"));

    r = find_res(&a, "extra_dir");
    CHECK(has_rule(r, "NONSTANDARD_PATH"));

    r = find_res(&a, "gone");
    CHECK(r && r->rec == NULL && has_rule(r, "MISSING") && r->level == RISK_LOW);

    /* sorted: highest score first */
    for (int i = 1; i < a.count; i++)
        CHECK(a.items[i - 1].score >= a.items[i].score);
    CHECK(a.max_level == RISK_CRITICAL);
    CHECK(a.counts[RISK_CRITICAL] == 3); /* diamorphine, hidden_p, hidden_s */
    analyzer_free(&a);

    /* kernel mismatch: comparison-based rules must be skipped */
    util_copy(s.kernel, sizeof(s.kernel), "6.2.0-other");
    CHECK(analyzer_run(&s, &b, &a) == 0);
    CHECK(a.env.kernel_mismatch);
    r = find_res(&a, "changed");
    CHECK(r && r->score == 0);
    r = find_res(&a, "brandnew");
    CHECK(has_rule(r, "NOT_IN_BASELINE")); /* still reported */
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

static void test_suspicious_names(void)
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

static void test_rule_table(void)
{
    CHECK(g_rule_count >= 8);
    for (int i = 0; i < g_rule_count; i++)
        CHECK(g_rules[i] != NULL);
}

/* ---- scan against a fabricated sysfs tree ---------------------------- */

static void mkdirs(const char *p)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", p);
    if (system(cmd) != 0)
        exit(2);
}

static void test_scan_cross_view(void)
{
    mkdirs("/tmp/kmrd-ut-sys/ext4/holders");
    mkdirs("/tmp/kmrd-ut-sys/ghost/holders");
    mkdirs("/tmp/kmrd-ut-sys/builtin_thing"); /* no initstate: built-in, ignored */
    FILE *f = fopen("/tmp/kmrd-ut-sys/ext4/initstate", "w"); fputs("live\n", f); fclose(f);
    f = fopen("/tmp/kmrd-ut-sys/ghost/initstate", "w"); fputs("live\n", f); fclose(f);
    f = fopen("/tmp/kmrd-ut-sys/ext4/srcversion", "w"); fputs("ABC123\n", f); fclose(f);
    f = fopen("/tmp/kmrd-ut-sys/ghost/coresize", "w"); fputs("4096\n", f); fclose(f);
    f = fopen("/tmp/kmrd-ut-proc", "w");
    fputs("ext4 1000 0 - Live 0x1\nno_sysfs 10 0 - Live 0x2\n", f);
    fclose(f);

    scan_config_t cfg = {"/tmp/kmrd-ut-proc", "/tmp/kmrd-ut-sys", NULL, "6.1.0"};
    scan_result_t s;
    char err[128];
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0);
    CHECK(s.sysfs_available && !s.moddep_available);
    CHECK(s.records.count == 3);

    const module_record_t *r = records_find(&s.records, "ext4");
    CHECK(r && r->in_proc && r->in_sysfs && strcmp(r->srcversion, "ABC123") == 0);
    r = records_find(&s.records, "no_sysfs");
    CHECK(r && r->in_proc && !r->in_sysfs);
    r = records_find(&s.records, "ghost");
    CHECK(r && !r->in_proc && r->in_sysfs && r->base.size == 4096);
    CHECK(records_find(&s.records, "builtin_thing") == NULL);
    scan_free(&s);

    /* unreadable sysfs is reported, not fatal */
    scan_config_t cfg2 = {"/tmp/kmrd-ut-proc", "/nonexistent-sys", NULL, "6.1.0"};
    CHECK(scan_run(&cfg2, &s, err, sizeof(err)) == 0 && !s.sysfs_available);
    scan_free(&s);

    /* unreadable /proc/modules is fatal */
    scan_config_t cfg3 = {"/nonexistent-proc", "/tmp/kmrd-ut-sys", NULL, "6.1.0"};
    CHECK(scan_run(&cfg3, &s, err, sizeof(err)) == -1 && err[0]);

    if (system("rm -rf /tmp/kmrd-ut-sys /tmp/kmrd-ut-proc") != 0)
        exit(2);
}

int main(void)
{
    RUN(test_valid_names);
    RUN(test_util_copy_and_join);
    RUN(test_parse_line);
    RUN(test_parse_line_malformed);
    RUN(test_read_modules);
    RUN(test_read_many_modules);
    RUN(test_moddep);
    RUN(test_risk_levels);
    RUN(test_baseline_roundtrip);
    RUN(test_baseline_rejects_tampering);
    RUN(test_baseline_structure_checks);
    RUN(test_entry_diff_without_sysfs);
    RUN(test_baseline_save_failure);
    RUN(test_analyzer_clean);
    RUN(test_analyzer_rules);
    RUN(test_suspicious_names);
    RUN(test_rule_table);
    RUN(test_scan_cross_view);

    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
