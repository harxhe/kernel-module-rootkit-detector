#ifndef UI_H
#define UI_H

#include "risk.h"
#include <stddef.h>
#include <stdio.h>

/* Terminal styling with automatic fallback.

   ui_detect() decides per output stream whether to use colour and Unicode:
     auto  (default)  colour only on a real terminal, never when NO_COLOR is
                      set or TERM is "dumb"; Unicode only if the locale is
                      UTF-8, otherwise ASCII look-alikes
     plain            never
     fancy            always (used by tests and for screenshots)
   Piped output, --json and log files therefore never contain escape codes. */

typedef enum { UI_AUTO, UI_PLAIN, UI_FANCY } ui_mode_t;

typedef struct {
    int color;    /* emit ANSI colour sequences */
    int unicode;  /* emit box-drawing / check-mark glyphs */
} ui_t;

typedef enum {
    UI_RESET, UI_BOLD, UI_DIM, UI_RED, UI_GREEN, UI_YELLOW, UI_BLUE,
    UI_CYAN, UI_GREY
} ui_style_t;

typedef enum { UI_SYM_OK, UI_SYM_FAIL, UI_SYM_WARN, UI_SYM_DOT, UI_SYM_ARROW } ui_sym_t;

/* Parse "auto|plain|fancy". Returns 0, or -1 if unknown. */
int ui_mode_parse(const char *s, ui_mode_t *out);

ui_t ui_detect(ui_mode_t mode, FILE *stream);
int ui_fancy(const ui_t *ui); /* colour or unicode enabled */

/* ANSI sequence for a style ("" when colour is off). */
const char *ui_style(const ui_t *ui, ui_style_t s);
/* Style used for a risk level (CRITICAL is reverse-video red). */
const char *ui_level_style(const ui_t *ui, risk_level_t lvl);
const char *ui_sym(const ui_t *ui, ui_sym_t s);

/* "████████░░" (or "########--"): value/max drawn in `width` cells.
   buf must hold at least width*3+1 bytes. */
void ui_bar(const ui_t *ui, char *buf, size_t bufsz, int value, int max, int width);

/* Print a rounded box around the lines, `inner` cells wide (text is padded
   or truncated; no ANSI codes may be inside the lines). */
void ui_box(const ui_t *ui, FILE *out, const char *const *lines, int nlines, int inner);

/* Print `label` followed by dots up to `width`, e.g. "Reading /proc .... ". */
void ui_dots(FILE *out, const char *label, int width);

#endif /* UI_H */
