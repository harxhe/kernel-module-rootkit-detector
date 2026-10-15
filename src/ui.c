#include "ui.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

int ui_mode_parse(const char *s, ui_mode_t *out)
{
    if (!s)
        return -1;
    if (strcasecmp(s, "auto") == 0)  { *out = UI_AUTO;  return 0; }
    if (strcasecmp(s, "plain") == 0) { *out = UI_PLAIN; return 0; }
    if (strcasecmp(s, "fancy") == 0) { *out = UI_FANCY; return 0; }
    return -1;
}

static int locale_is_utf8(void)
{
    const char *vars[] = {"LC_ALL", "LC_CTYPE", "LANG"};
    for (unsigned i = 0; i < sizeof(vars) / sizeof(vars[0]); i++) {
        const char *v = getenv(vars[i]);
        if (v && *v) {
            for (const char *p = v; *p; p++)
                if (strncasecmp(p, "utf-8", 5) == 0 || strncasecmp(p, "utf8", 4) == 0)
                    return 1;
            return 0; /* the first set variable decides */
        }
    }
    return 0;
}

ui_t ui_detect(ui_mode_t mode, FILE *stream)
{
    ui_t u = {0, 0};
    if (mode == UI_PLAIN)
        return u;
    if (mode == UI_FANCY) {
        u.color = 1;
        u.unicode = 1;
        return u;
    }
    const char *term = getenv("TERM");
    int tty = stream && isatty(fileno(stream));
    int no_color = getenv("NO_COLOR") != NULL && *getenv("NO_COLOR");
    int dumb = !term || strcmp(term, "dumb") == 0;
    if (tty && !dumb) {
        u.color = !no_color;
        u.unicode = locale_is_utf8();
    }
    return u;
}

int ui_fancy(const ui_t *ui)
{
    return ui && (ui->color || ui->unicode);
}

const char *ui_style(const ui_t *ui, ui_style_t s)
{
    if (!ui || !ui->color)
        return "";
    switch (s) {
    case UI_RESET:  return "\033[0m";
    case UI_BOLD:   return "\033[1m";
    case UI_DIM:    return "\033[2m";
    case UI_RED:    return "\033[91m";
    case UI_GREEN:  return "\033[92m";
    case UI_YELLOW: return "\033[93m";
    case UI_BLUE:   return "\033[94m";
    case UI_CYAN:   return "\033[96m";
    case UI_GREY:   return "\033[90m";
    }
    return "";
}

const char *ui_level_style(const ui_t *ui, risk_level_t lvl)
{
    if (!ui || !ui->color)
        return "";
    switch (lvl) {
    case RISK_NONE:     return "\033[92m";
    case RISK_LOW:      return "\033[96m";
    case RISK_MEDIUM:   return "\033[93m";
    case RISK_HIGH:     return "\033[91m";
    case RISK_CRITICAL: return "\033[1;97;41m";
    }
    return "";
}

const char *ui_sym(const ui_t *ui, ui_sym_t s)
{
    int u = ui && ui->unicode;
    switch (s) {
    case UI_SYM_OK:    return u ? "\xe2\x9c\x94" : "ok";   /* ✔ */
    case UI_SYM_FAIL:  return u ? "\xe2\x9c\x97" : "!!";   /* ✗ */
    case UI_SYM_WARN:  return u ? "\xe2\x9a\xa0" : "!";    /* ⚠ */
    case UI_SYM_DOT:   return u ? "\xe2\x97\x8f" : "*";    /* ● */
    case UI_SYM_ARROW: return u ? "\xe2\x86\x92" : "->";   /* → */
    }
    return "";
}

void ui_bar(const ui_t *ui, char *buf, size_t bufsz, int value, int max, int width)
{
    if (max <= 0)
        max = 1;
    if (value < 0)
        value = 0;
    if (value > max)
        value = max;
    int fill = (value * width + max / 2) / max;
    if (value > 0 && fill == 0)
        fill = 1; /* a non-zero score is always visible */
    const char *on = ui && ui->unicode ? "\xe2\x96\x88" : "#"; /* █ */
    const char *off = ui && ui->unicode ? "\xe2\x96\x91" : "-"; /* ░ */
    size_t n = 0, ol = strlen(on), fl = strlen(off);
    for (int i = 0; i < width; i++) {
        const char *g = i < fill ? on : off;
        size_t gl = i < fill ? ol : fl;
        if (n + gl + 1 > bufsz)
            break;
        memcpy(buf + n, g, gl);
        n += gl;
    }
    buf[n] = '\0';
}

/* number of terminal cells in a UTF-8 string (counts code points) */
static int cells(const char *s)
{
    int n = 0;
    for (; *s; s++)
        if (((unsigned char)*s & 0xC0) != 0x80)
            n++;
    return n;
}

void ui_box(const ui_t *ui, FILE *out, const char *const *lines, int nlines, int inner)
{
    int u = ui && ui->unicode;
    const char *tl = u ? "\xe2\x95\xad" : "+", *tr = u ? "\xe2\x95\xae" : "+";
    const char *bl = u ? "\xe2\x95\xb0" : "+", *br = u ? "\xe2\x95\xaf" : "+";
    const char *h = u ? "\xe2\x94\x80" : "-", *v = u ? "\xe2\x94\x82" : "|";
    const char *dim = ui_style(ui, UI_CYAN), *rst = ui_style(ui, UI_RESET);

    fprintf(out, " %s%s", dim, tl);
    for (int i = 0; i < inner + 2; i++)
        fputs(h, out);
    fprintf(out, "%s%s\n", tr, rst);
    for (int i = 0; i < nlines; i++) {
        int c = cells(lines[i]);
        fprintf(out, " %s%s%s %s", dim, v, rst, c > inner ? "" : lines[i]);
        if (c > inner) {
            /* truncate by code points */
            int k = 0;
            for (const char *p = lines[i]; *p && k < inner; p++) {
                fputc(*p, out);
                if (((unsigned char)p[1] & 0xC0) != 0x80)
                    k++;
            }
            c = inner;
        }
        for (int k = c; k < inner; k++)
            fputc(' ', out);
        fprintf(out, " %s%s%s\n", dim, v, rst);
    }
    fprintf(out, " %s%s", dim, bl);
    for (int i = 0; i < inner + 2; i++)
        fputs(h, out);
    fprintf(out, "%s%s\n", br, rst);
}

void ui_dots(FILE *out, const char *label, int width)
{
    int n = (int)strlen(label);
    fputs(label, out);
    fputc(' ', out);
    for (int i = n + 1; i < width; i++)
        fputc('.', out);
    fputc(' ', out);
}
