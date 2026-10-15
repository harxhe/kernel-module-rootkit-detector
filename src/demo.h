#ifndef DEMO_H
#define DEMO_H

#include "ui.h"
#include <stdio.h>

/* One-command showcase: `detector demo`.

   Builds nine small fake Linux systems in a temporary directory (a clean one
   and eight with a typical problem: a rogue insmod, a module hiding from
   /proc, a replaced driver, a known rootkit name, ... plus a tampered
   baseline), runs the real detector on each and prints one line per scan
   with its verdict and why. It then scans this machine for real.

   Nothing is loaded into the kernel and nothing outside the temporary
   directory is touched; the directory is removed afterwards.

   Returns 0 if every simulated scan produced the expected verdict, 1 if not,
   2 if the temporary directory could not be created. */
int demo_run(FILE *out, const ui_t *ui);

#endif /* DEMO_H */
