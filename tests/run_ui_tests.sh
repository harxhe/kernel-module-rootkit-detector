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
begin "explain: raw evidence for a module hidden from /proc/modules"
baselined_system
fx_add stealth 12288 0 "-" "AAAAAAAAAAAAAAAAAAAAAAA" "" none
fx_hide_proc stealth
run_fx scan --explain
expect_rc 1
no_esc "$OUT"                                   # plain unless a terminal asks for more
has "$OUT" "HIDDEN_FROM_PROC"
has "$OUT" "!! +$FX/proc_modules +not listed"
has "$OUT" "ok +$FX/sys/stealth +present \\(initstate: live, size 12288\\)"
hasnt "$OUT" "\\[1/5\\]"

begin "explain: not shown unless asked"
run_fx scan
hasnt "$OUT" "not listed"

begin "explain: changed binary shows both values"
baselined_system
fx_set_srcversion e1000 "DEADBEEFDEADBEEFDEADBEE"
fx_set_size e1000 200000
run_fx scan --explain
has "$OUT" "baseline +srcversion F6A7B8C9D0E1F2A3B4C5D6E"
has "$OUT" "now +srcversion DEADBEEFDEADBEEFDEADBEE"
has "$OUT" "baseline +size 155648 bytes"
has "$OUT" "now +size 200000 bytes"

begin "explain: fancy mode adds colour and symbols; unloaded baseline module"
baselined_system
fx_remove br_netfilter
run_fx scan --explain --ui fancy
has_esc "$OUT"
has "$OUT" "MISSING"
has "$OUT" "entry exists \\(size 32768\\)"
has "$OUT" "in neither /proc/modules nor /sys/module"
has "$OUT" "✔"

begin "explain: also works with 'report' and never leaks into --json"
fx_add diamorphine 16384 0 "-" "" "OE" none
run_fx report --explain
has "$OUT" "name contains 'diamorphine'"
has "$OUT" "taint"
run_fx scan --explain --json
hasnt "$OUT" "loaded with insmod|no entry for|initstate:"

# ---------------------------------------------------------------------------
# monitor mode
mon_bg() { # start a monitor in the background: output in $WORK/mon.out
    # shellcheck disable=SC2046
    "$DETECTOR" $(detector_args) monitor --ui plain "$@" > "$WORK/mon.out" 2>&1 &
    MP=$!
}
mon_wait() { wait "$MP"; RC=$?; OUT="$(cat "$WORK/mon.out")"; }
lineno() { printf '%s\n' "$OUT" | grep -n -m1 -E -- "$1" | cut -d: -f1; }

begin "monitor: clean system -> no alerts, exit 0"
baselined_system
run_fx monitor --count 2 --interval 0 --ui plain
expect_rc 0
has "$OUT" "monitoring 9 modules every 0.0 s"
has "$OUT" "baseline: $FX/baseline.txt"
hasnt "$OUT" "ALERT|INITIAL|CHANGED"
has "$OUT" "stopped after 2 scan\\(s\\), 0 alert\\(s\\)"

begin "monitor: pre-existing finding reported once; --fail-on respected"
fx_add rogue 4096 0 "-" "BBBBBBBBBBBBBBBBBBBBBBB" "" none
run_fx monitor --count 3 --interval 0 --ui plain
expect_rc 1
has "$OUT" "INITIAL +HIGH +rogue score=65 rules=NOT_IN_BASELINE,NO_MODULE_FILE"
[ "$(printf '%s\n' "$OUT" | grep -c 'INITIAL')" = "1" ] && ok || bad "finding repeated on every scan" "$OUT"
run_fx monitor --count 1 --interval 0 --ui plain --fail-on critical
expect_rc 0

begin "monitor: a module loaded while watching raises an ALERT, then RESOLVED"
baselined_system
mon_bg --interval 0.2 --count 22
sleep 0.9
fx_add liverogue 8192 0 "-" "CCCCCCCCCCCCCCCCCCCCCCC" "" none
sleep 1.3
fx_remove liverogue
mon_wait
expect_rc 1
has "$OUT" "(ALERT|CHANGED) +[A-Z]+ +liverogue score="
has "$OUT" "RESOLVED liverogue is no longer flagged"
a=$(lineno "(ALERT|CHANGED) .*liverogue"); r=$(lineno "RESOLVED liverogue")
if [ -n "$a" ] && [ -n "$r" ] && [ "$a" -lt "$r" ]; then ok; else bad "ALERT must come before RESOLVED ($a,$r)" "$OUT"; fi

begin "monitor: a module that hides itself while watching is flagged CRITICAL"
baselined_system
mon_bg --interval 0.2 --count 14 --explain
sleep 0.7
fx_add stealth 12288 0 "-" "AAAAAAAAAAAAAAAAAAAAAAA" "" none
sleep 0.5
fx_hide_proc stealth
mon_wait
expect_rc 1
has "$OUT" "(ALERT|CHANGED) +CRITICAL +stealth score=80 rules=HIDDEN_FROM_PROC"
has "$OUT" "!! +$FX/proc_modules +not listed"          # --explain evidence

begin "monitor: tampering with the baseline file while running is an alert"
baselined_system
mon_bg --interval 0.2 --count 15
sleep 0.8
sed -i.bak 's/	729088	/	729089	/' "$FX/baseline.txt"; rm -f "$FX/baseline.txt.bak"
mon_wait
expect_rc 1
has "$OUT" "BASELINE-INVALID .*checksum"

begin "monitor: --json emits one valid JSON object per line"
baselined_system
fx_add rogue 4096 0 "-" "BBBBBBBBBBBBBBBBBBBBBBB" "" none
run_fx monitor --json --count 2 --interval 0
expect_rc 1
if command -v python3 >/dev/null 2>&1; then
    if printf '%s\n' "$OUT" | python3 -c '
import json,sys
ev=[json.loads(l) for l in sys.stdin if l.strip()]
a=[e for e in ev if e["event"]=="alert"]
assert len(a)==1 and a[0]["module"]=="rogue" and a[0]["level"]=="HIGH" and a[0]["score"]==65, ev
assert a[0]["rules"]==["NOT_IN_BASELINE","NO_MODULE_FILE"], a
assert ev[-1]["event"]=="stopped" and ev[-1]["scans"]==2 and ev[-1]["alerts"]==1, ev
' 2>/dev/null; then ok; else bad "monitor JSON invalid or wrong" "$OUT"; fi
else
    has "$OUT" '"event":"alert"'
fi
no_esc "$OUT"

begin "monitor: fancy mode and --log"
run_fx monitor --count 1 --interval 0 --ui fancy --log "$WORK/mon.log"
has_esc "$OUT"
has "$OUT" "live monitor"
has "$OUT" "rogue"
has "$OUT" "INITIAL"
has "$(cat "$WORK/mon.log")" "INITIAL +HIGH +rogue score=65"
no_esc "$(cat "$WORK/mon.log")"

begin "monitor: stops cleanly on SIGINT and SIGTERM"
baselined_system
mon_bg --interval 0.2
sleep 0.7; kill -INT "$MP"; mon_wait
expect_rc 0
has "$OUT" "stopped after [0-9]+ scan"
mon_bg --interval 0.2 --json
sleep 0.7; kill -TERM "$MP"; mon_wait
expect_rc 0
has "$OUT" '"event":"stopped"'

begin "monitor: argument and input errors"
run_fx monitor --interval abc;          expect_rc 2; has "$ERR" "--interval expects"
run_fx monitor --count -1;              expect_rc 2; has "$ERR" "--count expects"
run_fx monitor --count 1 --proc "$WORK/none"; expect_rc 2; has "$ERR" "scan failed"

# ---------------------------------------------------------------------------
begin "demo: one command lists every scan with its verdict"
mkdir -p "$WORK/tmpd"
OUT="$(TMPDIR="$WORK/tmpd" "$DETECTOR" demo --ui plain 2>"$WORK/err")"; RC=$?; ERR="$(cat "$WORK/err")"
expect_rc 0
no_esc "$OUT"
has "$OUT" "9/9 scans gave the expected verdict"
has "$OUT" "Clean system, nothing changed.* CLEAN +0 +nothing flagged"
has "$OUT" "New driver installed the normal way.* MEDIUM +40 +dummy: NOT_IN_BASELINE"
has "$OUT" "Unknown module loaded with insmod.* HIGH +65 +evilmod: NOT_IN_BASELINE \+ NO_MODULE_FILE"
has "$OUT" "hides itself from /proc/modules.* CRITICAL +80 +stealth: HIDDEN_FROM_PROC"
has "$OUT" "hides itself from /sys/module.* HIGH +60 +usbhid: HIDDEN_FROM_SYSFS"
has "$OUT" "Driver binary replaced.* HIGH +60 +e1000: SRCVERSION_CHANGED"
has "$OUT" "Known rootkit name.* CRITICAL +100 +diamorphine: SUSPICIOUS_NAME"
has "$OUT" "Module disappeared.* LOW +10 +br_netfilter: MISSING"
has "$OUT" "Baseline file edited by an attacker.* REFUSED"
has "$OUT" "This machine"
[ -z "$(ls -A "$WORK/tmpd")" ] && ok || bad "demo left files behind in TMPDIR" "$(ls -A "$WORK/tmpd")"
[ -z "$ERR" ] && ok || bad "demo wrote to stderr" "$ERR"

begin "demo: fancy mode, speed, and unwritable TMPDIR"
OUT="$("$DETECTOR" demo --ui fancy 2>&1)"; RC=$?
expect_rc 0
has_esc "$OUT"
has "$OUT" "✔"
has "$OUT" "╭"
S=$(date +%s)
"$DETECTOR" demo --ui plain >/dev/null 2>&1
E=$(date +%s)
[ $((E - S)) -le 3 ] && ok || bad "demo took $((E - S))s, should be near-instant"
OUT="$(TMPDIR=/nonexistent-tmp "$DETECTOR" demo --ui plain 2>&1)"; RC=$?
expect_rc 2
has "$OUT" "cannot create a temporary directory"

# ---------------------------------------------------------------------------
echo
echo "ui integration: $PASS checks passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
