#include "ut.h"

#define ROOT "/tmp/kmrd-ut-sysfs"

static void make_module(const char *name, const char *state, const char *taint,
                        const char *src)
{
    char cmd[256], path[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p " ROOT "/%s/holders", name);
    ut_sh(cmd);
    snprintf(path, sizeof(path), ROOT "/%s/initstate", name);
    if (state)
        ut_put(path, state);
    snprintf(path, sizeof(path), ROOT "/%s/taint", name);
    if (taint)
        ut_put(path, taint);
    snprintf(path, sizeof(path), ROOT "/%s/srcversion", name);
    if (src)
        ut_put(path, src);
}

TEST(sysfs_populate_reads_fields)
{
    ut_sh("rm -rf " ROOT);
    make_module("ext4", "live\n", "OE\n", "ABC123\n");
    ut_put(ROOT "/ext4/version", "1.0 beta\n");
    ut_put(ROOT "/ext4/coresize", "4096\n");
    ut_put(ROOT "/ext4/initsize", "512\n");
    ut_sh("mkdir " ROOT "/ext4/holders/jbd2 " ROOT "/ext4/holders/mbcache");

    module_record_t r;
    memset(&r, 0, sizeof(r));
    util_copy(r.base.name, sizeof(r.base.name), "ext4");
    sysfs_populate(&r, ROOT, NULL);
    CHECK(r.in_sysfs);
    CHECK(strcmp(r.initstate, "live") == 0);
    CHECK(strcmp(r.taint, "OE") == 0);
    CHECK(strcmp(r.srcversion, "ABC123") == 0);
    CHECK(strcmp(r.version, "1.0 beta") == 0);
    CHECK(r.coresize == 4096 && r.initsize == 512);
    CHECK(r.holders == 2);
    CHECK(!r.in_moddep && r.path[0] == '\0');
    ut_sh("rm -rf " ROOT);
}

TEST(sysfs_populate_missing_pieces)
{
    ut_sh("rm -rf " ROOT);
    make_module("bare", "live\n", NULL, NULL); /* no taint/srcversion files */

    module_record_t r;
    memset(&r, 0, sizeof(r));
    util_copy(r.base.name, sizeof(r.base.name), "bare");
    sysfs_populate(&r, ROOT, NULL);
    CHECK(r.in_sysfs && r.srcversion[0] == '\0' && r.taint[0] == '\0');
    CHECK(r.coresize == 0 && r.holders == 0);

    memset(&r, 0, sizeof(r));
    util_copy(r.base.name, sizeof(r.base.name), "absent");
    sysfs_populate(&r, ROOT, NULL);
    CHECK(!r.in_sysfs);
    ut_sh("rm -rf " ROOT);
}

TEST(sysfs_populate_rejects_traversal)
{
    ut_sh("rm -rf " ROOT " /tmp/kmrd-ut-outside && mkdir -p " ROOT " /tmp/kmrd-ut-outside");
    ut_put("/tmp/kmrd-ut-outside/srcversion", "LEAK\n");
    module_record_t r;
    memset(&r, 0, sizeof(r));
    util_copy(r.base.name, sizeof(r.base.name), "../kmrd-ut-outside");
    sysfs_populate(&r, ROOT, NULL);
    CHECK(!r.in_sysfs && r.srcversion[0] == '\0');
    CHECK(!sysfs_has(ROOT, ".."));
    CHECK(!sysfs_has(ROOT, "a/b"));
    ut_sh("rm -rf " ROOT " /tmp/kmrd-ut-outside");
}

TEST(sysfs_list_modules_filters)
{
    ut_sh("rm -rf " ROOT);
    make_module("loadable_a", "live\n", NULL, NULL);
    make_module("loadable_b", "coming\n", NULL, NULL);
    ut_sh("mkdir -p " ROOT "/builtin_thing " ROOT "/bad\\ name");
    ut_put(ROOT "/bad name/initstate", "live\n");
    ut_put(ROOT "/plain_file", "x");

    char **names;
    int n;
    CHECK(sysfs_list_modules(ROOT, &names, &n) == 0);
    CHECK(n == 2); /* built-in (no initstate), invalid name and files skipped */
    int a = 0, b = 0;
    for (int i = 0; i < n; i++) {
        a += strcmp(names[i], "loadable_a") == 0;
        b += strcmp(names[i], "loadable_b") == 0;
    }
    CHECK(a == 1 && b == 1);
    sysfs_free_names(names, n);

    CHECK(sysfs_list_modules("/nonexistent-sys", &names, &n) == -1);
    ut_sh("rm -rf " ROOT);
}

TEST(sysfs_records_container)
{
    record_set_t rs;
    memset(&rs, 0, sizeof(rs));
    for (int i = 0; i < 200; i++) {
        char name[32];
        snprintf(name, sizeof(name), "m%d", i);
        module_record_t r = ut_rec(name, (unsigned long)i, "-", "S");
        CHECK(records_push(&rs, &r) == 0);
    }
    CHECK(rs.count == 200);
    CHECK(records_find(&rs, "m199") != NULL);
    CHECK(records_find(&rs, "nope") == NULL);
    records_free(&rs);
    CHECK(rs.count == 0 && rs.items == NULL);
}
