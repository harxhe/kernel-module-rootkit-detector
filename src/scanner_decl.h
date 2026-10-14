#ifndef SCANNER_DECL_H
#define SCANNER_DECL_H

/* module_scanner.h defines module_info_t but does not declare the scanner
   functions implemented in module_scanner.c. They are declared here, with
   the exact signatures of that file, so callers get type checking without
   module_scanner.h having to change. */

#include "module_scanner.h"

/* Read /proc/modules-style file; returns module count or -1.
   *modules_out is malloc'ed (free with scanner_free_modules). */
int scanner_read_modules(const char *path, module_info_t **modules_out);
void scanner_print_modules(module_info_t *modules, int count);
void scanner_free_modules(module_info_t *modules);

#endif /* SCANNER_DECL_H */
