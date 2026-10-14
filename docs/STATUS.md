# Project status

Phases 1-4 were written by Harsh Vardhan; phases 5-8 were taken over from
there. **None of the existing files were modified** - everything below was
added as new files (the original `Makefile`, `README.md`,
`docs/implementation.md`, `.gitignore`, `baseline/modules.txt` and every file
in `src/` that existed are byte-identical). `git diff --stat main` shows only
additions.

| Phase | Status | Where |
|---|---|---|
| 1. Environment setup | Done (original) | skeleton, `module_scanner.h` |
| 2. Kernel module scanner | Done (original) | `src/module_scanner.c`, `src/main.c` (phase-2 CLI, builds with `make legacy`) |
| 3. Metadata collection | Completed here | `src/sysfs.c`, `src/moddep.c`, `src/scan.c` - reads the files that exist in `/sys/module`, install paths from `modules.dep` |
| 4. Trusted baseline | Completed here | `src/baseline.c` - versioned, checksummed, validated, diff |
| 5. Anomaly detection engine | New | `src/analyzer.c` - 9 rule functions, 15 finding types |
| 6. Risk scoring | New | `src/risk.c/.h` - weights, 0-100 score, levels |
| 7. CLI and reporting | New | `src/cli.c`, `src/report.c` - text/JSON/log, exit codes |
| 8. Testing and demonstration | Done in simulation; real-VM run pending | `tests/`, `scripts/demo.sh`, `Dockerfile` |

How the original code is used: `src/cli.c` calls the original
`scanner_read_modules()` for all `/proc/modules` parsing and uses
`module_info_t` as the base of every module record.

## Observations about the phase 1-4 code

Offered as hand-off notes, not criticism; each one is worked around in new
code so the original files did not need to change. Fixing them upstream would
let some of the workarounds be deleted.

1. **Source encoding.** `main.c`, `metadata.c`, `metadata.h`, `utilities.c`,
   `finalize.c`, `report_helper.c`, `.gitignore` and `baseline/modules.txt`
   are UTF-16 with BOM/CRLF (PowerShell `>` redirection), which gcc/clang
   reject; the `.gitignore` has no effect either. `make legacy` converts them
   to `build/legacy/` with `scripts/to_utf8.sh` at build time. `iconv -f
   UTF-16 -t UTF-8` over those files is the fix.
2. **`module_scanner.h` has no function prototypes**, only the type, so
   `main.c` calls undeclared functions. `src/scanner_decl.h` declares them;
   `make legacy` force-includes it.
3. **Modules with refcount `-` are dropped by `scanner_read_modules()`.**
   Real kernels print `-` for modules that cannot be unloaded (seen on the
   Docker Desktop kernel: all 5 modules). The scanner's `sscanf("%lu")` fails
   on them and silently skips the line, so they vanish from the scan - and a
   rootkit module without an exit function would be invisible. `src/scan.c`
   normalises each line (`-` -> `0`) before handing it to the scanner.
   Related: a 3-field line leaves `deps` uninitialised, and lines over 255
   bytes are split by `fgets`; the same normaliser handles both.
4. **`metadata_populate()`** ignores its `sys_dir` argument (hard-coded
   `/sys/module`) and reads `filename`, `author`, `license`, `flags`,
   `refcount`, which do not exist in `/sys/module/<name>/` (the real files
   are `initstate`, `taint`, `srcversion`, `coresize`, `initsize`,
   `holders/`, ...). `src/sysfs.c` reads the real files from an injectable
   root so it can be tested without a kernel.
5. **`Makefile`** lists `baseline.c`, `analyzer.c`, `risk.c` (missing then)
   and omits other files. It is untouched; `GNUmakefile` takes precedence
   under GNU make. `make legacy` builds the phase-2 CLI.
6. **`src/main.c`** keeps scan results in process globals, so `list`,
   `create-baseline`, `compare` and `report` only work inside the same
   process that ran `scan`; `src/cli.c` makes every command stateless and
   keeps the baseline on disk. The `utilities.c`, `finalize.c`,
   `report_helper.c` functions are not referenced by anything.
7. **Baseline format.** `main.c` writes `name size refcount deps` lines to
   `baseline/modules.txt`; the new baseline has a header, more fields and a
   checksum and defaults to `baseline/trusted.baseline` so the two never
   overwrite each other.

## Known limits / possible extensions

* A rootkit that falsifies both `/proc/modules` and `/sys/module`, or tampers
  with the detector or the baseline's location, cannot be ruled out from user
  space.
* `tests/kmod/` (a harmless module for the real-VM demonstration) has not
  been compiled: the development kernel (Docker Desktop LinuxKit) has no
  headers. The real-VM run in [TESTING.md](TESTING.md) is still to do.
* Optional extensions from the plan are not done: real-time monitoring,
  module file hashing, signed-module checks, dashboard.
