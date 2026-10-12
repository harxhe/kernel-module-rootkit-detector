# Kernel Module Rootkit Detector

Defensive Linux security tool that detects suspicious or unauthorized kernel
modules. Loadable-kernel-module (LKM) rootkits run with full kernel privilege
and usually try to hide, so the detector combines three signals:

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

Requires Linux, `gcc` and `make` (no dependencies). On macOS/Windows use Docker.

```bash
make                                   # builds ./detector
sudo ./detector create-baseline        # on a known-good system
sudo ./detector scan                   # compare, score, report
```

Root is optional; without it `/proc/modules` addresses are hidden but
everything the detector needs is still readable.

### Commands

| Command | What it does |
|---|---|
| `list` | List loaded modules with state, srcversion and origin |
| `create-baseline` | Save the trusted baseline (refuses if the system already looks compromised, unless `--force`) |
| `compare` | Show modules added / removed / changed since the baseline |
| `scan` | Full pipeline: scan, baseline comparison, anomaly rules, risk score, report |
| `report` | Like `scan` but also lists every module |

`--scan`, `--list`, ... spellings work too. Options:

```
--baseline FILE   baseline path (default baseline/modules.txt)
--json            JSON output (scan, report)
--output FILE     also write the report to FILE
--log FILE        append a history entry (summary + flagged modules)
--fail-on LEVEL   exit 1 when a module reaches low|medium|high|critical (default high)
--force           create-baseline even if the system looks compromised
--quiet           do not print the report on stdout
```

Exit codes: `0` clean (nothing at/above `--fail-on`), `1` findings (or
differences for `compare`), `2` error. That makes it easy to use from cron or CI:

```bash
sudo ./detector scan --quiet --log /var/log/kmrd.log || mail -s "module alert" root
```

### Example

```
$ ./detector scan
=== Kernel Module Rootkit Detector - Scan Report ===
Scan time      : 2026-10-12 07:29:52
Kernel         : 6.1.0-test
Modules loaded : 10 (/proc/modules)
Baseline       : baseline/modules.txt (9 modules, kernel 6.1.0-test, ...)

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
| `ABNORMAL_STATE` | 15 | state not `Live` |
| `UNSIGNED` | 10 | taint flag `E` |
| `DEPS_CHANGED` | 10 | dependency list differs from the baseline |
| `MISSING` | 10 | baseline module is no longer loaded |
| `OUT_OF_TREE` / `PROPRIETARY` / `NONSTANDARD_PATH` | 5 | taint `O` / taint `P` / installed outside `kernel/` |

Score = sum of weights capped at 100 → **LOW** 1-24, **MEDIUM** 25-49,
**HIGH** 50-74, **CRITICAL** 75-100.

Deliberate false-positive guards: `/proc/modules` is read before *and* after
the sysfs scan so a module loaded mid-scan is not "hidden"; comparison rules
are skipped when the baseline is from a different kernel release; hidden-module
checks are skipped when `/sys/module` is unreadable; the baseline loader
rejects modified / truncated / corrupt files instead of trusting them.

## Testing (Docker)

Everything is verified on Linux inside Docker; no root or real kernel module
is needed because tests fabricate `/proc/modules`, `/sys/module` and
`modules.dep` trees (see `tests/lib_fixture.sh`).

```bash
make docker-test     # build image; unit + integration tests; then the same
                     # under AddressSanitizer/UBSan plus mutation fuzzing
make docker-demo     # scripted controlled demonstration (see scripts/demo.sh)
make docker-shell    # interactive shell in the build environment
```

Or natively on Linux: `make test`, `make asan`, `make fuzz`, `make demo`.
Details, plus the procedure for a real VM with a real harmless module, are in
[docs/TESTING.md](docs/TESTING.md).

## Layout

```
src/util.c            safe string/file helpers, module-name validation
src/module_scanner.c  /proc/modules parser                      (Phase 2)
src/moddep.c          modules.dep index (where modules should live)
src/metadata.c        /sys/module/<name>/ metadata              (Phase 3)
src/scan.c            scan orchestration + cross-view + race handling
src/baseline.c        checksummed baseline save/load/diff       (Phase 4)
src/analyzer.c        independent anomaly rules                 (Phase 5)
src/risk.c            weights, 0-100 score, levels              (Phase 6)
src/report.c          text / JSON / history log                 (Phase 7)
src/main.c            CLI
tests/                unit tests, integration tests, fuzzer, fake-system fixtures
scripts/demo.sh       controlled demonstration                  (Phase 8)
tests/kmod/           harmless test module for a real VM        (Phase 8)
docs/                 implementation plan and status, testing guide
```

## Limitations

This detects the common class of LKM rootkits that hide via `/proc/modules`
or load from unusual places, and any modification of a baselined module. A
rootkit with full kernel control can in principle lie in both views at once;
a user-space tool cannot rule that out. Treat a clean report as "no evidence
found", and use signed modules / Secure Boot / offline memory forensics for
stronger guarantees.

## Phases

1. Environment Setup and Linux Module Study
2. Kernel Module Scanner
3. Metadata Collection
4. Trusted Baseline
5. Anomaly Detection Engine
6. Risk Scoring
7. CLI and Reporting
8. Testing and Controlled Demonstration

Status of each phase: [docs/implementation.md](docs/implementation.md#implementation-status).

## Team

- Member 1: System Scanner & Baseline
- Member 2: Detection & Reporting
