#include "baseline.h"
#include "ut.h"

static void build_scan(scan_result_t *s)
{
    memset(s, 0, sizeof(*s));
    util_copy(s->kernel, sizeof(s->kernel), "6.1.0-test");
    s->sysfs_available = 1;
    s->moddep_available = 1;
    s->when = 1700000000;
    module_record_t a = ut_rec("ext4", 1000, "mbcache,jbd2,", "AAAA1111");
    module_record_t b = ut_rec("mbcache", 200, "-", "");
    util_copy(b.version, sizeof(b.version), "1.0 beta");
    module_record_t c = ut_rec("hidden_one", 50, "-", "");
    c.in_proc = 0;
    records_push(&s->records, &a);
    records_push(&s->records, &b);
    records_push(&s->records, &c);
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

/* write a body and append a *correct* checksum, to test the structural
   validators independently of the checksum */
static void spit_with_checksum(const char *path, const char *body)
{
    uint64_t h = util_fnv1a(UTIL_FNV_INIT, body, strlen(body));
    FILE *f = fopen(path, "wb");
    fputs(body, f);
    fprintf(f, "# checksum %016llx\n", (unsigned long long)h);
    fclose(f);
}

TEST(baseline_roundtrip)
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

TEST(baseline_diff_added_removed)
{
    scan_result_t s;
    build_scan(&s);
    char err[256];
    CHECK(baseline_save("/tmp/kmrd-ut-baseline-d", &s, err, sizeof(err)) == 0);
    baseline_t b;
    CHECK(baseline_load("/tmp/kmrd-ut-baseline-d", &b, err, sizeof(err)) == 0);
    unlink("/tmp/kmrd-ut-baseline-d");

    /* current system: mbcache gone, newcomer appears */
    records_free(&s.records);
    module_record_t a = ut_rec("ext4", 1000, "mbcache,jbd2,", "AAAA1111");
    module_record_t n = ut_rec("newcomer", 9, "-", "");
    records_push(&s.records, &a);
    records_push(&s.records, &n);

    baseline_diff_t d;
    CHECK(baseline_diff(&b, &s, &d) == 0);
    CHECK(d.n_added == 1 && strcmp(s.records.items[d.added[0]].base.name, "newcomer") == 0);
    CHECK(d.n_removed == 1 && strcmp(b.items[d.removed[0]].name, "mbcache") == 0);
    CHECK(d.n_changed == 0);
    baseline_diff_free(&d);
    baseline_free(&b);
    scan_free(&s);
}

TEST(baseline_rejects_tampering)
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

TEST(baseline_structure_checks)
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

    /* old phase-2 style file (no header) */
    snprintf(body, sizeof(body), "overlay 15000 3 overlayfs\n");
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

TEST(baseline_entry_diff_without_sysfs)
{
    baseline_entry_t e;
    memset(&e, 0, sizeof(e));
    util_copy(e.name, sizeof(e.name), "m");
    e.size = 100;
    util_copy(e.deps, sizeof(e.deps), "-");
    util_copy(e.srcversion, sizeof(e.srcversion), "ABC");
    util_copy(e.version, sizeof(e.version), "1.0");

    module_record_t r = ut_rec("m", 100, "-", "ABC");
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

TEST(baseline_save_failure)
{
    scan_result_t s;
    build_scan(&s);
    char err[256] = "";
    CHECK(baseline_save("/nonexistent-dir/deeper/baseline", &s, err, sizeof(err)) == -1);
    CHECK(err[0] != '\0');
    scan_free(&s);
}
