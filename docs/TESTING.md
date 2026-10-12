# Testing guide

## What is tested, and how

| Layer | Command | What it covers |
|---|---|---|
| Unit tests | `make unit` | `/proc/modules` parsing (valid, malformed, hostile names), `modules.dep`, baseline round-trip / tampering / structural validation, every analyzer rule, risk thresholds, cross-view scan against a fabricated sysfs |
| Integration tests | `make integration` | the real `detector` binary against fabricated systems: every command, every rule end-to-end, exit codes, JSON validity, report/log files, corrupt baselines, missing `/sys` or `modules.dep`, 2000-module scale, the full demo scenario, and a round trip on the *live* host kernel |
| Sanitizers | `make asan` | the whole suite rebuilt with AddressSanitizer + UBSan (found and fixed a use-after-free in the baseline loader during development) |
| Fuzzing | `make fuzz [ITER=300]` | random byte-level corruption of `/proc/modules`, the baseline (half re-signed with a valid checksum so the structural parser is reached) and `modules.dep`; asserts no crash |
| Demonstration | `make demo` | scripted incident walk-through (`scripts/demo.sh`) |

`make check` runs everything; `make docker-test` does the same inside a clean
Linux container (this is how the project was verified from a Mac):

```bash
make docker-test       # image kmrd-detector: build, test, sanitizers, fuzz
make docker-demo       # run the demonstration in the container
make docker-shell      # poke around interactively
```

### Why the tests use fabricated `/proc` and `/sys`

Containers share the host's (virtual machine's) kernel, cannot `insmod`, and
loading modules in CI would be dangerous and non-deterministic. The detector
takes `--proc`, `--sys`, `--moddep` and `--kernel` overrides, and
`tests/lib_fixture.sh` builds complete fake systems:

```bash
. tests/lib_fixture.sh
fx_init /tmp/sys1 && fx_base_system           # a clean 9-module system
fx_add evil 20480 0 - 0123456789ABCDEF "" none  # "insmod" a rogue module
fx_hide_proc evil                              # ... that hides from /proc/modules
./detector scan $(detector_args)
```

The live-kernel test inside the integration suite additionally runs the real
paths (`/proc/modules`, `/sys/module`) so path handling and the parser are
exercised against what a real kernel emits.

## Real VM demonstration (Phase 8)

Use a **throw-away** Ubuntu VM (VirtualBox/UTM/multipass), never your host.

```bash
sudo apt update && sudo apt install -y build-essential linux-headers-$(uname -r)
make
sudo ./detector create-baseline
sudo ./detector scan                        # expect: CLEAN

make -C tests/kmod                          # builds test_rogue.ko
sudo insmod tests/kmod/test_rogue.ko        # "unauthorized" module appears
sudo ./detector scan                        # expect: test_rogue HIGH
                                            #   NOT_IN_BASELINE + NO_MODULE_FILE
sudo ./detector compare                     # expect: [ADDED] test_rogue

sudo rmmod test_rogue
sudo ./detector scan                        # expect: CLEAN again
```

`NO_MODULE_FILE` fires because the `.ko` was loaded with `insmod` from the
build directory and is not listed in `/lib/modules/<release>/modules.dep`. If
you instead `sudo cp test_rogue.ko /lib/modules/$(uname -r)/extra/ && sudo
depmod -a && sudo modprobe test_rogue`, the module is registered, only
`NOT_IN_BASELINE` (MEDIUM) fires, and `NONSTANDARD_PATH` adds 5.

Measure scan time and resources:

```bash
sudo ./detector scan --quiet --log reports/scan.log     # duration is in the log/report
/usr/bin/time -v ./detector scan --quiet                # peak memory, CPU time
```

> **Status:** `tests/kmod/` was written but could not be compiled in the
> development environment (Docker Desktop's LinuxKit kernel ships no headers);
> everything else in this document was executed. Verify the real-VM steps once.

## Adding tests

* New rule: add a `static void rule_x(...)` in `src/analyzer.c`, append it to
  `g_rules[]`, add its weight to `src/risk.h`, then a unit test in
  `tests/test_unit.c` (`test_analyzer_rules`) and a scenario in
  `tests/run_tests.sh`.
* New scenario: build the system with `fx_*` helpers, run `run_fx <command>`,
  assert with `expect_rc`, `expect_has`, `expect_no`.
