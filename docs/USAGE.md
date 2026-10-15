# Using the detector

This documents the integrated detector built in phases 5-8 (`make` produces
`./detector`). The original phase-2 command skeleton (`src/main.c`) is kept
unchanged and can still be built with `make legacy`; see [STATUS.md](STATUS.md).

## How it detects rootkits

Loadable-kernel-module (LKM) rootkits run with full kernel privilege and
usually try to hide, so the detector combines three signals:

1. **Cross-view comparison** - `/proc/modules` and `/sys/module/` are two
   independent views of the same kernel state. A module that appears in one
   but not the other is hiding.
2. **Trusted baseline** - a checksummed snapshot of the modules (size,
   dependencies, `srcversion` build hash) on a known-good system. New modules
   and modified module binaries stand out.
3. **Heuristics** - module not installed by the distribution (`modules.dep`),
   unsigned / out-of-tree taint flags, abnormal state, duplicate names,
   known rootkit names.

Every finding carries a weight; a module's weights add up to a 0-100 score
mapped to LOW / MEDIUM / HIGH / CRITICAL, and the report always shows *why*.

## Build and run

Requires Linux, `gcc` and GNU `make` (no other dependencies). On macOS or
Windows use Docker (`make docker-test`).

```bash
make                                   # builds ./detector
sudo ./detector create-baseline        # on a known-good system
sudo ./detector scan                   # compare, score, report
```

Root is optional. The `--scan` / `--create-baseline` spellings used in the
README work as well.

### Commands

| Command | What it does |
|---|---|
| `list` | List loaded modules with state, srcversion and origin |
| `create-baseline` | Save the trusted baseline (refuses if the system already looks compromised, unless `--force`) |
| `compare` | Show modules added / removed / changed since the baseline |
| `scan` | Full pipeline: scan, baseline comparison, anomaly rules, risk score, report |
| `report` | Like `scan` but also lists every module |
| `monitor` | Keep watching: re-scan every few seconds and alert when something changes |

Options:

```
--baseline FILE   baseline path (default baseline/trusted.baseline)
--json            JSON output (scan, report)
--output FILE     also write the report to FILE
--log FILE        append a history entry (summary + flagged modules)
--fail-on LEVEL   exit 1 when a module reaches low|medium|high|critical (default high)
--force           create-baseline even if the system looks compromised
--quiet           do not print the report on stdout
--explain         show the raw evidence under each finding (scan, report, monitor)
--ui MODE         auto|plain|fancy (default auto, see "Terminal output")
--interval SEC    monitor: pause between scans (default 2)
--count N         monitor: stop after N scans (default: until Ctrl+C)
--proc FILE --sys DIR --moddep FILE --kernel REL    point at fabricated inputs (tests)
```

The default baseline path is *not* `baseline/modules.txt`: that file is used by
the phase-2 CLI with a different, header-less format.

Exit codes: `0` clean (nothing at/above `--fail-on`), `1` findings (or
differences for `compare`), `2` error - handy for cron or CI:

```bash
sudo ./detector scan --quiet --log /var/log/kmrd.log || mail -s "module alert" root
```

### Terminal output

On a terminal the detector shows a styled report (boxed header, verdict, a
colour-coded risk bar per module) and a five-step progress summary with the
real time of each stage on stderr:

```
  [1/5] Reading /proc/modules ............ 138 modules          ok    0.40 ms
  [2/5] Reading /sys/module .............. 138 loadable         ok    0.31 ms
  [3/5] Cross-checking both views ........ 1 mismatch           !!    0.25 ms
  [4/5] Comparing with baseline .......... 1 new, 0 changed...  !     0.02 ms
  [5/5] Applying rules and scoring ....... 2 flagged            !!    0.02 ms
```

`--ui auto` (default) styles only a real terminal: never when output is piped
or redirected, never with `--json`, `--output` files or `--log`, and not when
`NO_COLOR` is set or `TERM=dumb`. Unicode boxes and symbols need a UTF-8
locale, otherwise ASCII look-alikes are used. `--ui plain` turns styling off,
`--ui fancy` forces it (useful for screenshots).

### Evidence view (`--explain`)

Each finding can be backed by the raw facts, so a verdict can be checked by
hand with `grep` and `ls`:

```
[CRITICAL] test_hide     score  80/100
    +80  HIDDEN_FROM_PROC   loaded (present in /sys/module) but missing from /proc/modules
          !! /proc/modules               not listed
          ok /sys/module/test_hide       present (initstate: live, size 12288)
```

### Live monitor

`detector monitor` re-scans every `--interval` seconds and prints only what
changed: `INITIAL` (already present at start), `ALERT` (a module starts being
flagged), `CHANGED` (its findings change), `RESOLVED` (no longer flagged). The
baseline is re-read every cycle, so editing it while the monitor runs raises
`BASELINE-INVALID`. `--json` prints one JSON object per line, `--log FILE`
appends plain event lines, Ctrl+C prints a summary. A demo: run
`sudo ./detector monitor --explain` in one terminal, load a module in another
and watch the alert appear.

### Example

```
$ ./detector scan
=== Kernel Module Rootkit Detector - Scan Report ===
Kernel         : 6.1.0-test
Modules loaded : 10 (/proc/modules)

Summary: 2 flagged  |  CRITICAL 1  HIGH 1  MEDIUM 0  LOW 0
Overall risk: CRITICAL (max score 100/100)

[CRITICAL] diamorphine              score 100/100
    +80  HIDDEN_FROM_PROC   loaded (present in /sys/module) but missing from /proc/modules
    +50  SUSPICIOUS_NAME    name contains known rootkit token 'diamorphine'
    +10  UNSIGNED           taint flag E: module is unsigned
    +5   OUT_OF_TREE        taint flag O: out-of-tree module
[HIGH    ] test_rogue               score  65/100
    +40  NOT_IN_BASELINE    module was not present when the baseline was created
    +25  NO_MODULE_FILE     not listed in modules.dep: ...
```

## Detection rules and risk weights

Rules are independent functions in `src/analyzer.c`; weights live in `src/risk.h`.

| Rule | Weight | Fires when |
|---|---|---|
| `HIDDEN_FROM_PROC` | 80 | in `/sys/module` (has `initstate`) but absent from `/proc/modules` |
| `HIDDEN_FROM_SYSFS` | 60 | in `/proc/modules` but no `/sys/module/<name>` |
| `SUSPICIOUS_NAME` | 50 | name contains a known rootkit token (diamorphine, reptile, ...) |
| `NOT_IN_BASELINE` | 40 | module did not exist when the baseline was made |
| `SRCVERSION_CHANGED` | 40 | module build hash differs from the baseline |
| `DUPLICATE_NAME` | 30 | name listed twice in `/proc/modules` |
| `NO_MODULE_FILE` | 25 | not in `modules.dep` (loaded from an unusual location) |
| `SIZE_CHANGED` | 20 | size differs from the baseline |
| `ABNORMAL_STATE` | 15 | sysfs `initstate` is not `live` |
| `UNSIGNED` | 10 | taint flag `E` |
| `DEPS_CHANGED` | 10 | dependency list differs from the baseline |
| `MISSING` | 10 | baseline module is no longer loaded |
| `OUT_OF_TREE` / `PROPRIETARY` / `NONSTANDARD_PATH` | 5 | taint `O` / taint `P` / installed outside `kernel/` |

Score = sum of weights capped at 100 → **LOW** 1-24, **MEDIUM** 25-49,
**HIGH** 50-74, **CRITICAL** 75-100.

False-positive guards: `/proc/modules` is read before *and* after the sysfs
scan so a module loaded mid-scan is not "hidden"; comparison rules are skipped
when the baseline is from a different kernel release; hidden-module checks are
skipped when `/sys/module` is unreadable; a module hidden from sysfs is not
also reported as "binary changed".

### Baseline file

Versioned, tab separated, written atomically (temp file + rename) with a
trailing FNV-1a checksum and a module count. A modified, truncated or
corrupt baseline is a hard error (exit 2) rather than a silent downgrade,
because a quietly edited baseline would whitelist a rootkit.
`create-baseline` also refuses to bless a system that already shows
HIGH/CRITICAL indicators.

## Layout (files added in phases 5-8)

```
src/scanner_decl.h  prototypes for module_scanner.c (its header only has the type)
src/util.c          safe string/file helpers, module-name validation
src/moddep.c        modules.dep index (where modules should live)
src/sysfs.c         /sys/module/<name>/ reader with injectable root     (Phase 5 data layer)
src/scan.c          scan orchestration, input normalisation, cross-view (Phase 5 data layer)
src/baseline.c      checksummed baseline save/load/diff                 (Phase 5 data layer)
src/risk.c          weights, 0-100 score, levels                        (Phase 6)
src/analyzer.c      independent anomaly rules                           (Phase 5)
src/report.c        text / JSON / history log                           (Phase 7)
src/ui.c            colour/Unicode detection, boxes, bars              (terminal UI)
src/report_ui.c     styled report                                      (terminal UI)
src/progress.c      five-step stage summary with real timings          (terminal UI)
src/explain.c       raw evidence behind each finding                   (terminal UI)
src/monitor.c       live monitor mode                                  (terminal UI)
src/cli.c           integrated command line                             (Phase 7)
tests/unit/         unit tests, one file per module
tests/run_tests.sh  integration tests against fabricated /proc and /sys (Phase 8)
tests/fuzz.sh       mutation fuzzer
scripts/demo.sh     controlled demonstration                            (Phase 8)
tests/kmod/         harmless test module for a real VM                  (Phase 8)
GNUmakefile         build (overrides the original Makefile, which is untouched)
```

## Limitations

This detects the common class of LKM rootkits that hide via `/proc/modules`
or load from unusual places, and any modification of a baselined module. A
rootkit with full kernel control can in principle lie in both views at once,
and one that tampers with the detector or the baseline file's location cannot
be ruled out from user space. Treat a clean report as "no evidence found",
keep the baseline read-only or off-box, and use signed modules / Secure Boot
for stronger guarantees.
