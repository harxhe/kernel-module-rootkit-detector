#include "moddep.h"
#include "ut.h"

TEST(moddep_load_and_lookup)
{
    char *p = ut_write_temp(
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
    CHECK(moddep_lookup(&md, NULL) == NULL);
    moddep_free(&md);
    unlink(p);
}

TEST(moddep_unavailable)
{
    moddep_t md;
    CHECK(moddep_load("/nonexistent", &md) == -1 && !md.loaded);
    CHECK(moddep_lookup(&md, "ext4") == NULL);
    CHECK(moddep_lookup(NULL, "ext4") == NULL);
}

TEST(moddep_large_file)
{
    FILE *f = fopen("/tmp/kmrd-ut-bigdep", "w");
    for (int i = 0; i < 3000; i++)
        fprintf(f, "kernel/drivers/mod%d.ko.xz:\n", i);
    fclose(f);
    moddep_t md;
    CHECK(moddep_load("/tmp/kmrd-ut-bigdep", &md) == 0 && md.count == 3000);
    CHECK(moddep_lookup(&md, "mod0") != NULL);
    CHECK(moddep_lookup(&md, "mod2999") != NULL);
    CHECK(moddep_lookup(&md, "mod3000") == NULL);
    moddep_free(&md);
    unlink("/tmp/kmrd-ut-bigdep");
}
