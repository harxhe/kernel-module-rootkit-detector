#include "ui.h"
#include "ut.h"
#include <stdlib.h>

static char *slurp_tmp(FILE *f)
{
    fflush(f);
    long n = ftell(f);
    rewind(f);
    char *b = malloc((size_t)n + 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n)
        exit(2);
    b[n] = '\0';
    return b;
}

TEST(ui_mode_parse_values)
{
    ui_mode_t m;
    CHECK(ui_mode_parse("auto", &m) == 0 && m == UI_AUTO);
    CHECK(ui_mode_parse("PLAIN", &m) == 0 && m == UI_PLAIN);
    CHECK(ui_mode_parse("fancy", &m) == 0 && m == UI_FANCY);
    CHECK(ui_mode_parse("rainbow", &m) == -1);
    CHECK(ui_mode_parse(NULL, &m) == -1);
}

TEST(ui_detect_never_styles_a_pipe_or_file)
{
    FILE *f = tmpfile();
    setenv("TERM", "xterm-256color", 1);
    setenv("LANG", "en_US.UTF-8", 1);
    unsetenv("NO_COLOR");
    ui_t u = ui_detect(UI_AUTO, f);          /* a file is not a terminal */
    CHECK(!u.color && !u.unicode && !ui_fancy(&u));
    u = ui_detect(UI_PLAIN, f);
    CHECK(!u.color && !u.unicode);
    u = ui_detect(UI_FANCY, f);              /* forced */
    CHECK(u.color && u.unicode && ui_fancy(&u));
    u = ui_detect(UI_AUTO, NULL);
    CHECK(!ui_fancy(&u));
    fclose(f);
}

TEST(ui_plain_style_has_no_escape_codes)
{
    ui_t plain = {0, 0};
    CHECK(strcmp(ui_style(&plain, UI_RED), "") == 0);
    CHECK(strcmp(ui_level_style(&plain, RISK_CRITICAL), "") == 0);
    CHECK(strcmp(ui_style(NULL, UI_BOLD), "") == 0);
    CHECK(strcmp(ui_sym(&plain, UI_SYM_OK), "ok") == 0);
    CHECK(strcmp(ui_sym(&plain, UI_SYM_FAIL), "!!") == 0);
    ui_t fancy = {1, 1};
    CHECK(strstr(ui_style(&fancy, UI_RED), "\033[") != NULL);
    CHECK(strcmp(ui_sym(&fancy, UI_SYM_OK), "\xe2\x9c\x94") == 0);
    CHECK(strcmp(ui_level_style(&fancy, RISK_LOW),
                 ui_level_style(&fancy, RISK_HIGH)) != 0);
}

TEST(ui_bar_proportions)
{
    ui_t fancy = {1, 1}, ascii = {0, 0};
    char b[128];
    ui_bar(&ascii, b, sizeof(b), 50, 100, 10);
    CHECK(strcmp(b, "#####-----") == 0);
    ui_bar(&ascii, b, sizeof(b), 0, 100, 10);
    CHECK(strcmp(b, "----------") == 0);
    ui_bar(&ascii, b, sizeof(b), 100, 100, 10);
    CHECK(strcmp(b, "##########") == 0);
    ui_bar(&ascii, b, sizeof(b), 1, 100, 10);    /* tiny but non-zero stays visible */
    CHECK(strcmp(b, "#---------") == 0);
    ui_bar(&ascii, b, sizeof(b), 999, 100, 10);  /* clamped */
    CHECK(strcmp(b, "##########") == 0);
    ui_bar(&ascii, b, sizeof(b), -5, 100, 4);
    CHECK(strcmp(b, "----") == 0);
    ui_bar(&fancy, b, sizeof(b), 80, 100, 10);
    CHECK(strncmp(b, "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88", 12) == 0);
    CHECK(strlen(b) == 8 * 3 + 2 * 3);
    ui_bar(&fancy, b, 5, 80, 100, 10);           /* never overruns a small buffer */
    CHECK(strlen(b) < 5);
}

TEST(ui_box_aligns_lines)
{
    ui_t ascii = {0, 0}, fancy = {1, 1};
    const char *lines[] = {"short", "a longer line of text"};
    FILE *f = tmpfile();
    ui_box(&ascii, f, lines, 2, 24);
    char *t = slurp_tmp(f);
    CHECK(strstr(t, " +--------------------------+\n") != NULL);
    CHECK(strstr(t, " | short                    |\n") != NULL);
    free(t);
    fclose(f);

    f = tmpfile();
    const char *u[] = {"caf\xc3\xa9 \xe2\x9c\x94"};  /* multibyte text keeps alignment */
    ui_box(&fancy, f, u, 1, 10);
    t = slurp_tmp(f);
    CHECK(strstr(t, "caf\xc3\xa9 \xe2\x9c\x94     ") != NULL);
    free(t);
    fclose(f);

    f = tmpfile();                                   /* overlong text is cut, not overflowed */
    const char *l[] = {"0123456789ABCDEF"};
    ui_box(&ascii, f, l, 1, 8);
    t = slurp_tmp(f);
    CHECK(strstr(t, " | 01234567 |\n") != NULL);
    free(t);
    fclose(f);
}

TEST(ui_dots_pads_to_width)
{
    FILE *f = tmpfile();
    ui_dots(f, "Reading", 12);
    char *t = slurp_tmp(f);
    CHECK(strcmp(t, "Reading .... ") == 0);
    free(t);
    fclose(f);
}
