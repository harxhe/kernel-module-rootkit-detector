#include "ut.h"

TEST(util_valid_names)
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
    CHECK(!util_valid_module_name("$(touch x)"));
    CHECK(!util_valid_module_name(NULL));
}

TEST(util_copy_join_sanitize)
{
    char b[8];
    util_copy(b, sizeof(b), "0123456789");
    CHECK(strcmp(b, "0123456") == 0);
    util_copy(b, sizeof(b), "ab");
    CHECK(strcmp(b, "ab") == 0);
    util_copy(b, sizeof(b), NULL);
    CHECK(b[0] == '\0');

    char p[16];
    CHECK(util_path_join(p, sizeof(p), "/sys", "ext4", "taint") == 0);
    CHECK(strcmp(p, "/sys/ext4/taint") == 0);
    CHECK(util_path_join(p, sizeof(p), "/sys/module", "longername", "x") == -1);
    CHECK(util_path_join(p, sizeof(p), "/sys", "ext4", NULL) == 0);
    CHECK(strcmp(p, "/sys/ext4") == 0);

    char t[] = "a\tb\nc";
    util_sanitize_field(t);
    CHECK(strcmp(t, "a b c") == 0);

    char n[] = "nf-tables-ipv4";
    util_normalize_name(n);
    CHECK(strcmp(n, "nf_tables_ipv4") == 0);
}

TEST(util_read_file_trims)
{
    char *p = ut_write_temp("live\n\n");
    char buf[32];
    CHECK(util_read_file(p, buf, sizeof(buf)) == 4);
    CHECK(strcmp(buf, "live") == 0);
    unlink(p);
    CHECK(util_read_file("/nonexistent/file", buf, sizeof(buf)) == -1);
    p = ut_write_temp("");
    CHECK(util_read_file(p, buf, sizeof(buf)) == 0);
    unlink(p);
    p = ut_write_temp("0123456789012345678901234567890123456789");
    CHECK(util_read_file(p, buf, 8) == 7); /* bounded read */
    unlink(p);
}

TEST(util_fnv1a_known_values)
{
    /* FNV-1a 64 test vectors */
    CHECK(util_fnv1a(UTIL_FNV_INIT, "", 0) == 0xcbf29ce484222325ULL);
    CHECK(util_fnv1a(UTIL_FNV_INIT, "a", 1) == 0xaf63dc4c8601ec8cULL);
    CHECK(util_fnv1a(UTIL_FNV_INIT, "foobar", 6) == 0x85944171f73967e8ULL);
}
