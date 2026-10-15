#!/usr/bin/env bash
# Integration tests for the terminal UI features (styling, progress,
# evidence view, monitor mode) against fabricated /proc and /sys systems.
#
#   DETECTOR=./detector bash tests/run_ui_tests.sh

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
DETECTOR="${DETECTOR:-./detector}"
# shellcheck source=tests/lib_fixture.sh
. "$HERE/lib_fixture.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kmrd-ui.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; CASE=""; OUT=""; ERR=""; RC=0
ESC=$(printf '\033')

begin() { CASE="$1"; }
ok()    { PASS=$((PASS + 1)); }
bad()   { FAIL=$((FAIL + 1)); printf 'FAIL [%s] %s\n' "$CASE" "$1"; if [ -n "${2:-}" ]; then printf '%s\n' "$2" | sed 's/^/      | /' | head -25; fi; }

# run_fx ARGS...: stdout -> OUT, stderr -> ERR (separate, like a terminal split)
run_fx() {
    # shellcheck disable=SC2046
    OUT="$("$DETECTOR" $(detector_args) "$@" 2>"$WORK/err")"; RC=$?
    ERR="$(cat "$WORK/err")"
}
expect_rc()  { if [ "$RC" -eq "$1" ]; then ok; else bad "exit code $RC, expected $1" "$OUT"; fi; }
has()        { if printf '%s' "$1" | grep -qE -- "$2"; then ok; else bad "lacks /$2/" "$1"; fi; }
hasnt()      { if printf '%s' "$1" | grep -qE -- "$2"; then bad "unexpectedly has /$2/" "$1"; else ok; fi; }
has_esc()    { if printf '%s' "$1" | grep -q "$ESC"; then ok; else bad "no ANSI escape found" "$1"; fi; }
no_esc()     { if printf '%s' "$1" | grep -q "$ESC"; then bad "ANSI escape found" "$(printf '%s' "$1" | cat -v | head -8)"; else ok; fi; }

baselined_system() {
    fx_init "$WORK/fx"; fx_base_system
    run_fx create-baseline --ui plain
    [ "$RC" -eq 0 ] || bad "setup: create-baseline failed" "$OUT"
}

# ---------------------------------------------------------------------------
begin "ui: piped output is plain by default (no colour, no Unicode)"
baselined_system
fx_add stealth 12288 0 "-" "AAAAAAAAAAAAAAAAAAAAAAA" "" none
fx_hide_proc stealth
run_fx scan
no_esc "$OUT"
has "$OUT" "=== Kernel Module Rootkit Detector - Scan Report ==="
if printf '%s' "$OUT" | LC_ALL=C grep -q '[^ -~]'; then bad "non-ASCII bytes in piped output"; else ok; fi

begin "ui: --ui fancy gives colour, box, risk bar and verdict"
run_fx scan --ui fancy
expect_rc 1
has_esc "$OUT"
has "$OUT" "Kernel Module Rootkit Detector"
has "$OUT" "VERDICT"
has "$OUT" "CRITICAL"
has "$OUT" "stealth"
has "$OUT" "80/100"
has "$OUT" "HIDDEN_FROM_PROC"
has "$OUT" "█"                        # score bar
has "$OUT" "╭"                        # box

begin "ui: --ui plain overrides everything, NO_COLOR is respected"
run_fx scan --ui plain
no_esc "$OUT"
has "$OUT" "Overall risk: CRITICAL"
OUT="$(NO_COLOR=1 "$DETECTOR" $(detector_args) scan --ui auto 2>/dev/null)"
no_esc "$OUT"

begin "ui: clean system verdict, report/--output files stay plain"
baselined_system
run_fx scan --ui fancy --output "$WORK/report.txt"
expect_rc 0
has "$OUT" "CLEAN"
has "$OUT" "no suspicious modules detected"
no_esc "$(cat "$WORK/report.txt")"
has "$(cat "$WORK/report.txt")" "Overall risk: CLEAN"

begin "ui: --json is never styled"
run_fx scan --ui fancy --json
no_esc "$OUT"
has "$OUT" '"overall_risk": "CLEAN"'

begin "ui: 'report' full table in fancy mode, bad --ui value rejected"
run_fx report --ui fancy
has "$OUT" "All modules"
has "$OUT" "kernel/fs/ext4/ext4.ko.xz"
run_fx scan --ui rainbow
expect_rc 2
has "$ERR" "--ui expects"

# ---------------------------------------------------------------------------
begin "progress: five stages with real timings on stderr (fancy only)"
baselined_system
run_fx scan --ui fancy
has "$ERR" "\\[1/5\\].*Reading /proc/modules.*9 modules"
has "$ERR" "\\[2/5\\].*Reading /sys/module.*9 loadable"
has "$ERR" "\\[3/5\\].*Cross-checking both views.*views agree"
has "$ERR" "\\[4/5\\].*Comparing with baseline.*0 new, 0 changed, 0 gone"
has "$ERR" "\\[5/5\\].*Applying rules and scoring.*0 flagged"
has "$ERR" "[0-9]+\\.[0-9]{2} ms"
hasnt "$OUT" "\\[1/5\\]"                # progress never mixes into the report

begin "progress: reflects findings (mismatch, new module, flagged)"
fx_add stealth 12288 0 "-" "AAAAAAAAAAAAAAAAAAAAAAA" "" none
fx_hide_proc stealth
fx_add rogue 4096 0 "-" "BBBBBBBBBBBBBBBBBBBBBBB" "" none
run_fx scan --ui fancy
has "$ERR" "Cross-checking both views.*1 mismatch"
has "$ERR" "Comparing with baseline.*1 new"
has "$ERR" "Applying rules and scoring.*2 flagged"

begin "progress: silent for plain, --json, --quiet and when piped"
run_fx scan --ui plain;               [ -z "$ERR" ] && ok || bad "plain wrote to stderr" "$ERR"
run_fx scan --ui fancy --json;        [ -z "$ERR" ] && ok || bad "--json wrote to stderr" "$ERR"
run_fx scan --ui fancy --quiet;       [ -z "$ERR" ] && ok || bad "--quiet wrote to stderr" "$ERR"
run_fx scan;                          [ -z "$ERR" ] && ok || bad "piped run wrote to stderr" "$ERR"

begin "progress: notes missing baseline and unreadable /sys"
fx_init "$WORK/fx2"; fx_base_system
run_fx scan --ui fancy --baseline "$WORK/none" --sys "$WORK/no-such-sys"
has "$ERR" "Comparing with baseline.*no baseline"
has "$ERR" "Reading /sys/module.*unavailable"
has "$ERR" "Cross-checking both views.*skipped"

# ---------------------------------------------------------------------------
echo
echo "ui integration: $PASS checks passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
