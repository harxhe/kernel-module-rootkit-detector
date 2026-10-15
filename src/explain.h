#ifndef EXPLAIN_H
#define EXPLAIN_H

#include "report.h"

/* Print the raw evidence behind one finding, one fact per line, e.g. for a
   module hidden from /proc/modules:

     !!  /proc/modules          not listed
     ok  /sys/module/stealth    present (initstate: live, size 12288)

   This is the "show your work" view: each line can be checked by hand with
   grep / ls. `ui` may be NULL for plain ASCII. `indent` prefixes every line. */
void explain_finding(FILE *out, const report_ctx_t *ctx, const module_result_t *res,
                     const finding_t *f, const ui_t *ui, const char *indent);

#endif /* EXPLAIN_H */
