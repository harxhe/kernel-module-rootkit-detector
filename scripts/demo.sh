#!/usr/bin/env bash
# Controlled demonstration of the full detection workflow.
#
# Simulates a Linux system (fake /proc/modules + /sys/module + modules.dep) so
# it runs anywhere, needs no root and loads no real kernel module:
#
#   1. take a trusted baseline of a clean system
#   2. scan                         -> clean
#   3. "load" a rogue module        -> detected, HIGH
#   4. "load" a rootkit that hides itself from /proc/modules -> CRITICAL
#   5. remove both                  -> clean again
#
#   make story           (the quick one-line-per-scan version is: make demo)

set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DETECTOR="${DETECTOR:-$HERE/detector}"
# shellcheck source=tests/lib_fixture.sh
. "$HERE/tests/lib_fixture.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kmrd-demo.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
fx_init "$WORK/system"
fx_base_system

# shellcheck disable=SC2046
det() { "$DETECTOR" "$@" $(detector_args); }
step() { printf '\n\033[1m### %s\033[0m\n' "$1"; }
run()  { printf '$ detector %s\n' "$*"; det "$@"; local rc=$?; printf '(exit code %d)\n' "$rc"; }

step "1. Create the trusted baseline on a clean system"
run create-baseline

step "2. Scan with no changes - expect CLEAN"
run scan

step "3. Someone insmod's an unknown module (not installed by the distribution)"
fx_add test_rogue 24576 0 "-" "FEEDFACEFEEDFACEFEEDFAC" "" none
run scan

step "4. A rootkit loads and hides itself from /proc/modules"
fx_add diamorphine 16384 0 "-" "" "OE" none
fx_hide_proc diamorphine
run scan

step "5. The same incident through 'compare'"
run compare

step "6. Remove the test changes and scan again - expect CLEAN"
fx_remove test_rogue
fx_remove diamorphine
run scan

step "7. Tamper with the baseline file - the detector refuses to trust it"
sed -i.bak 's/	729088	/	1	/' "$WORK/system/baseline.txt"; rm -f "$WORK/system/baseline.txt.bak"
run scan
