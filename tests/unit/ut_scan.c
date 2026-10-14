#include "scan.h"
#include "ut.h"

#define SYS "/tmp/kmrd-ut-scan-sys"
#define PROC "/tmp/kmrd-ut-scan-proc"

static scan_config_t cfg_for(const char *proc, const char *sys)
{
    scan_config_t c = {proc, sys, NULL, "6.1.0-test"};
    return c;
}

static void module_dir(const char *name, const char *src)
{
    char cmd[256], path[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p " SYS "/%s/holders", name);
    ut_sh(cmd);
    snprintf(path, sizeof(path), SYS "/%s/initstate", name);
    ut_put(path, "live\n");
    if (src) {
        snprintf(path, sizeof(path), SYS "/%s/srcversion", name);
        ut_put(path, src);
    }
}

TEST(scan_cross_view)
{
    ut_sh("rm -rf " SYS);
    module_dir("ext4", "ABC123\n");
    module_dir("ghost", NULL);
    ut_sh("mkdir -p " SYS "/builtin_thing"); /* no initstate: built-in, ignored */
    ut_put(SYS "/ghost/coresize", "4096\n");
    ut_put(PROC, "ext4 1000 0 - Live 0x1\nno_sysfs 10 0 - Live 0x2\n");

    scan_config_t cfg = cfg_for(PROC, SYS);
    scan_result_t s;
    char err[128];
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0);
    CHECK(s.sysfs_available && !s.moddep_available);
    CHECK(s.records.count == 3);

    const module_record_t *r = records_find(&s.records, "ext4");
    CHECK(r && r->in_proc && r->in_sysfs && strcmp(r->srcversion, "ABC123") == 0);
    CHECK(r && r->base.size == 1000);
    r = records_find(&s.records, "no_sysfs");
    CHECK(r && r->in_proc && !r->in_sysfs);
    r = records_find(&s.records, "ghost");
    CHECK(r && !r->in_proc && r->in_sysfs && r->base.size == 4096);
    CHECK(records_find(&s.records, "builtin_thing") == NULL);

    /* sorted by name */
    for (int i = 1; i < s.records.count; i++)
        CHECK(strcmp(s.records.items[i - 1].base.name,
                     s.records.items[i].base.name) < 0);
    scan_free(&s);

    scan_config_t cfg2 = cfg_for(PROC, "/nonexistent-sys");
    CHECK(scan_run(&cfg2, &s, err, sizeof(err)) == 0 && !s.sysfs_available);
    scan_free(&s);

    scan_config_t cfg3 = cfg_for("/nonexistent-proc", SYS);
    CHECK(scan_run(&cfg3, &s, err, sizeof(err)) == -1 && err[0]);

    ut_sh("rm -rf " SYS " " PROC);
}

TEST(scan_rejects_hostile_names_and_counts_bad_lines)
{
    ut_sh("rm -rf " SYS " && mkdir -p " SYS);
    ut_put(PROC,
           "ext4 1000 1 mbcache, Live 0x1\n"
           "garbage line here that is not a module\n"
           "\n"
           "../../etc/passwd 100 1 - Live 0x0\n"
           "$(touch_pwned) 5 0 - Live 0x0\n"
           "name_only\n"
           "mbcache 200 1 ext4, Live 0x2\n"
           "no_newline_at_end 300 0 - Live 0x3");
    scan_config_t cfg = cfg_for(PROC, SYS);
    scan_result_t s;
    char err[128];
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0);
    CHECK(s.records.count == 3);
    CHECK(records_find(&s.records, "ext4") != NULL);
    CHECK(records_find(&s.records, "no_newline_at_end") != NULL);
    CHECK(s.proc_skipped == 4);
    scan_free(&s);
    ut_sh("rm -f " PROC);
}

TEST(scan_flags_duplicate_names)
{
    ut_sh("rm -rf " SYS " && mkdir -p " SYS);
    ut_put(PROC, "dup 10 0 - Live 0x1\nother 20 0 - Live 0x2\ndup 30 0 - Live 0x3\n");
    scan_config_t cfg = cfg_for(PROC, SYS);
    scan_result_t s;
    char err[128];
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0);
    int dups = 0;
    for (int i = 0; i < s.records.count; i++)
        dups += s.records.items[i].duplicate;
    CHECK(s.records.count == 3 && dups == 2);
    CHECK(!records_find(&s.records, "other")->duplicate);
    scan_free(&s);
    ut_sh("rm -f " PROC);
}

TEST(scan_handles_empty_and_large_proc)
{
    ut_sh("rm -rf " SYS " && mkdir -p " SYS);
    ut_put(PROC, "");
    scan_config_t cfg = cfg_for(PROC, SYS);
    scan_result_t s;
    char err[128];
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0 && s.records.count == 0);
    scan_free(&s);

    FILE *f = fopen(PROC, "w");
    for (int i = 0; i < 5000; i++)
        fprintf(f, "mod%d %d 0 - Live 0x%x\n", i, 1000 + i, i);
    fclose(f);
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0);
    CHECK(s.records.count == 5000 && s.proc_skipped == 0);
    scan_free(&s);
    ut_sh("rm -f " PROC);
}

TEST(scan_reads_modules_dep)
{
    ut_sh("rm -rf " SYS " && mkdir -p " SYS);
    ut_put(PROC, "ext4 1000 0 - Live 0x1\nstray 10 0 - Live 0x2\n");
    char *dep = ut_write_temp("kernel/fs/ext4/ext4.ko.xz:\n");
    scan_config_t cfg = {PROC, SYS, dep, "6.1.0-test"};
    scan_result_t s;
    char err[128];
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0 && s.moddep_available);
    CHECK(records_find(&s.records, "ext4")->in_moddep);
    CHECK(!records_find(&s.records, "stray")->in_moddep);
    scan_free(&s);
    unlink(dep);
    ut_sh("rm -f " PROC);
}

TEST(scan_keeps_modules_with_dash_refcount)
{
    /* real kernels print "-" as the refcount of modules that cannot be
       unloaded; dropping them would make them look hidden */
    ut_sh("rm -rf " SYS " && mkdir -p " SYS);
    ut_put(PROC,
           "selfowner 32768 - - Live 0x0000000000000000 (O)\n"
           "shiftfs 32768 - - Live 0x0000000000000000 (O)\n"
           "ext4 1000 3 mbcache, Live 0x1\n");
    scan_config_t cfg = cfg_for(PROC, SYS);
    scan_result_t s;
    char err[128];
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0);
    CHECK(s.records.count == 3 && s.proc_skipped == 0);
    const module_record_t *r = records_find(&s.records, "selfowner");
    CHECK(r && r->in_proc && r->base.ref_count == 0 && r->base.size == 32768);
    CHECK(records_find(&s.records, "ext4")->base.ref_count == 3);
    scan_free(&s);
    ut_sh("rm -f " PROC);
}

TEST(scan_defines_deps_for_short_lines)
{
    ut_sh("rm -rf " SYS " && mkdir -p " SYS);
    ut_put(PROC, "tiny 100 0\n");
    scan_config_t cfg = cfg_for(PROC, SYS);
    scan_result_t s;
    char err[128];
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0 && s.records.count == 1);
    CHECK(strcmp(s.records.items[0].base.deps, "-") == 0);
    scan_free(&s);
    ut_sh("rm -f " PROC);
}

TEST(scan_handles_very_long_dependency_lines)
{
    ut_sh("rm -rf " SYS " && mkdir -p " SYS);
    FILE *f = fopen(PROC, "w");
    fputs("chainy 4096 1 ", f);
    for (int i = 0; i < 400; i++)
        fprintf(f, "dep%d,", i);
    fputs(" Live 0xffffffffc0001000\nafter 10 0 - Live 0x2\n", f);
    fclose(f);
    scan_config_t cfg = cfg_for(PROC, SYS);
    scan_result_t s;
    char err[128];
    CHECK(scan_run(&cfg, &s, err, sizeof(err)) == 0);
    /* one module per line: the long line neither splits nor swallows its
       neighbour, and produces no phantom "modules" */
    CHECK(s.records.count == 2 && s.proc_skipped == 0);
    CHECK(records_find(&s.records, "chainy") != NULL);
    CHECK(records_find(&s.records, "after") != NULL);
    CHECK(strlen(records_find(&s.records, "chainy")->base.deps) <= 200);
    scan_free(&s);
    ut_sh("rm -f " PROC);
}
