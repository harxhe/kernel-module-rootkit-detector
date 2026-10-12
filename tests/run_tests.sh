#!/usr/bin/env bash
# Integration tests: drive the real ./detector binary against fabricated
# /proc + /sys environments and assert on exit codes and output.
#
#   DETECTOR=./detector bash tests/run_tests.sh

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
DETECTOR="${DETECTOR:-./detector}"
# shellcheck source=tests/lib_fixture.sh
. "$HERE/lib_fixture.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kmrd-it.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
CASE=""
OUT=""
RC=0

begin() { CASE="$1"; }
ok()    { PASS=$((PASS + 1)); }
bad()   { FAIL=$((FAIL + 1)); printf 'FAIL [%s] %s\n' "$CASE" "$1"; if [ -n "${2:-}" ]; then printf '%s\n' "$2" | sed 's/^/      | /' | head -25; fi; }

# run_det ARGS...  -> sets OUT and RC (stderr merged)
run_det() { OUT="$("$DETECTOR" "$@" 2>&1)"; RC=$?; }
# run against the current fixture
# (fixture flags come first so per-test options such as --sys override them)
run_fx() { # shellcheck disable=SC2046
    OUT="$("$DETECTOR" $(detector_args) "$@" 2>&1)"; RC=$?; }

expect_rc()  { if [ "$RC" -eq "$1" ]; then ok; else bad "exit code $RC, expected $1" "$OUT"; fi; }
expect_has() { if printf '%s' "$OUT" | grep -qE -- "$1"; then ok; else bad "output lacks /$1/" "$OUT"; fi; }
expect_no()  { if printf '%s' "$OUT" | grep -qE -- "$1"; then bad "output unexpectedly has /$1/" "$OUT"; else ok; fi; }

fresh_baselined_system() {
    fx_init "$WORK/fx"
    fx_base_system
    run_fx create-baseline
    [ "$RC" -eq 0 ] || { bad "setup: create-baseline failed" "$OUT"; }
}

# ---------------------------------------------------------------------------
begin "cli: help, version, bad usage"
run_det --help;           expect_rc 0; expect_has "create-baseline"
run_det --version;        expect_rc 0; expect_has "detector 1\\."
run_det;                  expect_rc 2
run_det bogus;            expect_rc 2; expect_has "unknown argument"
run_det scan list;        expect_rc 2; expect_has "more than one command"
run_det scan --fail-on;   expect_rc 2; expect_has "needs a value"
run_det scan --fail-on nope; expect_rc 2; expect_has "expects low"

begin "cli: both 'scan' and '--scan' spellings"
fx_init "$WORK/fx"; fx_base_system
run_fx create-baseline;   expect_rc 0
run_fx --scan;            expect_rc 0; expect_has "No suspicious modules"
run_fx --list;            expect_rc 0; expect_has "ext4"
run_fx --compare;         expect_rc 0
run_fx scan --baseline="$WORK/fx/baseline.txt"; expect_rc 0

begin "list: shows modules with origin and srcversion"
run_fx list; expect_rc 0
expect_has "ext4 .*kernel/fs/ext4/ext4.ko.xz"
expect_has "9 module\\(s\\)"

begin "create-baseline: file format"
B="$WORK/fx/baseline.txt"
head -1 "$B" | grep -q '^# kmrd-baseline 1$' && ok || bad "missing magic header"
grep -q '^# kernel 6.1.0-test$' "$B" && ok || bad "missing kernel line"
grep -q '^# modules 9$' "$B" && ok || bad "wrong module count line"
tail -1 "$B" | grep -qE '^# checksum [0-9a-f]{16}$' && ok || bad "missing checksum line"
grep -q "^ext4	729088	mbcache,jbd2,	A1B2C3D4E5F6A7B8C9D0E1F" "$B" && ok || bad "ext4 entry malformed"
[ ! -e "$B.tmp" ] && ok || bad "temp file left behind"

# ---------------------------------------------------------------------------
begin "scan: clean system, no findings"
fresh_baselined_system
run_fx scan
expect_rc 0
expect_has "Overall risk: CLEAN"
expect_has "No suspicious modules detected"
expect_has "Baseline +: .*9 modules"

begin "scan: DKMS-style module (extra/, unsigned, out-of-tree) is only LOW noise"
fx_init "$WORK/fx"; fx_base_system
fx_add vboxdrv 618496 3 "-" "C9D0E1F2A3B4C5D6E7F8A9B" "OE" "extra/vboxdrv.ko"
run_fx create-baseline; expect_rc 0
run_fx scan
expect_rc 0
expect_has "\\[LOW +\\] vboxdrv +score +20"
expect_has "UNSIGNED"
expect_has "OUT_OF_TREE"
expect_has "NONSTANDARD_PATH"
run_fx scan --fail-on low; expect_rc 1

begin "scan: no baseline -> heuristics only, with a note"
fx_init "$WORK/fx"; fx_base_system
run_fx scan
expect_has "Baseline +: none"
expect_has "Heuristic rules only"
expect_no "NOT_IN_BASELINE"

begin "scan: new legitimately installed module -> MEDIUM, exit 0 by default"
fresh_baselined_system
fx_add dummy 16384 0 "-" "FFFFFFFFFFFFFFFFFFFFFFF" "" "kernel/drivers/dummy.ko.xz"
run_fx scan
expect_rc 0
expect_has "\\[MEDIUM +\\] dummy +score +40"
expect_has "NOT_IN_BASELINE"
run_fx scan --fail-on medium; expect_rc 1

begin "scan: rogue module loaded from nowhere -> HIGH, exit 1"
fresh_baselined_system
fx_add evilmod 20480 0 "-" "0123456789ABCDEF0123456" "" none
run_fx scan
expect_rc 1
expect_has "\\[HIGH +\\] evilmod +score +65"
expect_has "NOT_IN_BASELINE"
expect_has "NO_MODULE_FILE"

begin "scan: known rootkit name + unsigned + out-of-tree -> CRITICAL (capped at 100)"
fresh_baselined_system
fx_add diamorphine 16384 0 "-" "" "OE" none
run_fx scan
expect_rc 1
expect_has "\\[CRITICAL\\] diamorphine +score +100/100"
expect_has "SUSPICIOUS_NAME"
expect_has "known rootkit token 'diamorphine'"
expect_has "Overall risk: CRITICAL"

begin "scan: module hidden from /proc/modules -> CRITICAL"
fresh_baselined_system
fx_add stealth 12288 0 "-" "AAAAAAAAAAAAAAAAAAAAAAA" "" none
fx_hide_proc stealth
run_fx scan
expect_rc 1
expect_has "\\[CRITICAL\\] stealth"
expect_has "HIDDEN_FROM_PROC"
expect_has "missing from /proc/modules"

begin "scan: module hidden from /sys/module -> flagged HIGH+"
fresh_baselined_system
fx_hide_sys usbhid
run_fx scan
expect_rc 1
expect_has "\\[HIGH +\\] usbhid +score +60"
expect_has "HIDDEN_FROM_SYSFS"

begin "scan: replaced module binary (srcversion + size) -> HIGH"
fresh_baselined_system
fx_set_srcversion e1000 "DEADBEEFDEADBEEFDEADBEE"
fx_set_size e1000 200000
run_fx scan
expect_rc 1
expect_has "\\[HIGH +\\] e1000 +score +60"
expect_has "SRCVERSION_CHANGED"
expect_has "DEADBEEFDEADBEEFDEADBEE"
expect_has "SIZE_CHANGED +size changed \\(155648 -> 200000"

begin "scan: unloaded baseline module -> LOW 'MISSING'"
fresh_baselined_system
fx_remove br_netfilter
run_fx scan
expect_rc 0
expect_has "\\[LOW +\\] br_netfilter"
expect_has "MISSING"

begin "scan: module stuck in Loading state"
fresh_baselined_system
fx_remove usbhid
fx_add usbhid 65536 0 "-" "B8C9D0E1F2A3B4C5D6E7F8A" "" "kernel/drivers/hid/usbhid/usbhid.ko.xz" "Loading"
run_fx scan
expect_has "ABNORMAL_STATE"

begin "scan: duplicate module names"
fresh_baselined_system
echo "jbd2 163840 1 ext4, Live 0xffffffffc0001000" >> "$WORK/fx/proc_modules"
run_fx scan
expect_has "DUPLICATE_NAME"

begin "scan: multiple findings sort highest score first"
fresh_baselined_system
fx_add evilmod 20480 0 "-" "0123456789ABCDEF0123456" "" none
fx_add diamorphine 16384 0 "-" "" "OE" none
fx_remove br_netfilter
run_fx scan
LINE_D=$(printf '%s\n' "$OUT" | grep -n 'diamorphine ' | head -1 | cut -d: -f1)
LINE_E=$(printf '%s\n' "$OUT" | grep -n 'evilmod ' | head -1 | cut -d: -f1)
LINE_M=$(printf '%s\n' "$OUT" | grep -n 'br_netfilter ' | head -1 | cut -d: -f1)
if [ -n "$LINE_D" ] && [ "$LINE_D" -lt "$LINE_E" ] && [ "$LINE_E" -lt "$LINE_M" ]; then ok; else bad "ordering wrong ($LINE_D,$LINE_E,$LINE_M)" "$OUT"; fi

# ---------------------------------------------------------------------------
begin "compare: clean -> exit 0"
fresh_baselined_system
run_fx compare
expect_rc 0
expect_has "No differences from baseline"

begin "compare: added / removed / changed listed -> exit 1"
fresh_baselined_system
fx_add newmod 8192 0 "-" "" "" none
fx_remove br_netfilter
fx_set_srcversion e1000 "CHANGEDCHANGEDCHANGEDCH"
run_fx compare
expect_rc 1
expect_has "\\[ADDED\\] +newmod"
expect_has "\\[REMOVED\\] br_netfilter"
expect_has "\\[CHANGED\\] e1000 +\\(srcversion\\)"
expect_has "Differences found"

begin "compare: no baseline -> error"
fx_init "$WORK/fx"; fx_base_system
run_fx compare
expect_rc 2
expect_has "create-baseline"

# ---------------------------------------------------------------------------
begin "create-baseline: refuses a compromised system, --force overrides"
fx_init "$WORK/fx"; fx_base_system
fx_add stealth 12288 0 "-" "AAAAAAAAAAAAAAAAAAAAAAA" "" none
fx_hide_proc stealth
run_fx create-baseline
expect_rc 2
expect_has "refusing to create a baseline"
[ ! -e "$WORK/fx/baseline.txt" ] && ok || bad "baseline written despite refusal"
run_fx create-baseline --force
expect_rc 0
grep -q '^stealth' "$WORK/fx/baseline.txt" && bad "hidden module must not be baselined" || ok

begin "create-baseline: creates the parent directory, overwrites atomically"
fx_init "$WORK/fx"; fx_base_system
run_fx create-baseline --baseline "$WORK/fx/newdir/b.txt"
expect_rc 0
[ -s "$WORK/fx/newdir/b.txt" ] && ok || bad "baseline in new dir missing"
run_fx create-baseline --baseline "$WORK/fx/newdir/b.txt"
expect_rc 0

begin "create-baseline: unwritable destination -> exit 2"
run_fx create-baseline --baseline /proc/nope/baseline.txt
expect_rc 2

# ---------------------------------------------------------------------------
begin "baseline integrity: modified entry"
fresh_baselined_system
sed -i.bak 's/	729088	/	729089	/' "$WORK/fx/baseline.txt"; rm -f "$WORK/fx/baseline.txt.bak"
run_fx scan
expect_rc 2
expect_has "checksum"
expect_has "refusing to continue"

begin "baseline integrity: truncated file"
fresh_baselined_system
head -c 200 "$WORK/fx/baseline.txt" > "$WORK/fx/b.tmp"; mv "$WORK/fx/b.tmp" "$WORK/fx/baseline.txt"
run_fx scan;    expect_rc 2
run_fx compare; expect_rc 2

begin "baseline integrity: empty and garbage files"
fresh_baselined_system
: > "$WORK/fx/baseline.txt"
run_fx scan; expect_rc 2
printf '\001\002\003 binary \377 junk\n' > "$WORK/fx/baseline.txt"
run_fx scan; expect_rc 2
echo "ext4 729088 1 mbcache,jbd2," > "$WORK/fx/baseline.txt"   # old v0 format
run_fx scan; expect_rc 2

begin "baseline from another kernel: comparison rules skipped, note shown"
fresh_baselined_system
fx_set_srcversion e1000 "NEWBUILDNEWBUILDNEWBUIL"
fx_set_size e1000 160000
OUT="$("$DETECTOR" scan --proc "$FX/proc_modules" --sys "$FX/sys" --moddep "$FX/modules.dep" \
        --kernel 6.2.0-other --baseline "$FX/baseline.txt" 2>&1)"; RC=$?
expect_rc 0
expect_has "created on kernel 6.1.0-test, running 6.2.0-other"
expect_no "SRCVERSION_CHANGED"
expect_no "SIZE_CHANGED"

# ---------------------------------------------------------------------------
begin "robustness: malformed /proc/modules lines"
fresh_baselined_system
cat >> "$WORK/fx/proc_modules" <<'EOF'
this is garbage
../../etc/passwd 100 1 - Live 0x0
name_only
bad_size notnum 1 - Live 0x0
$(touch /tmp/pwned) 10 0 - Live 0x0
EOF
run_fx scan
expect_rc 0
expect_has "5 malformed /proc/modules line"
expect_no "passwd"
[ ! -e /tmp/pwned ] && ok || bad "command injection via module name!"

begin "robustness: empty /proc/modules"
fresh_baselined_system
: > "$WORK/fx/proc_modules"
run_fx scan
# modules still visible in /sys/module but absent from /proc/modules = hiding
expect_rc 1
expect_has "HIDDEN_FROM_PROC"

begin "robustness: unreadable /proc/modules"
fresh_baselined_system
run_det scan --proc "$WORK/does-not-exist" --sys "$FX/sys" --moddep "$FX/modules.dep" --baseline "$FX/baseline.txt"
expect_rc 2
expect_has "cannot read"

begin "robustness: no /sys/module -> note, no false 'hidden' alarms"
fresh_baselined_system
run_fx scan --sys "$WORK/no-such-sys"
expect_has "hidden-module cross-check skipped"
expect_no "HIDDEN_FROM_SYSFS"
expect_rc 0

begin "robustness: no modules.dep -> note, no false 'NO_MODULE_FILE'"
fresh_baselined_system
run_fx scan --moddep "$WORK/no-such-dep"
expect_has "modules.dep not found"
expect_no "NO_MODULE_FILE"
expect_rc 0

begin "robustness: hostile /sys/module entries (spaces, symlinks) are ignored"
fresh_baselined_system
mkdir -p "$WORK/fx/sys/not a module" "$WORK/fx/sys/.hidden"
touch "$WORK/fx/sys/not a module/initstate" "$WORK/fx/sys/.hidden/initstate"
ln -s /etc "$WORK/fx/sys/etc_link" 2>/dev/null || true
run_fx scan
expect_no "not a module"
expect_no "etc_link"
# a dot-directory with an initstate file is a (suspicious) module nobody lists
expect_has "\\[CRITICAL\\] \\.hidden"

begin "robustness: very long dependency list and 2000 modules"
fx_init "$WORK/big"
FX="$WORK/big"
i=0
while [ $i -lt 2000 ]; do
    fx_add "mod$i" $((4096 + i)) 0 "-" "SRC$i" "" "kernel/drivers/mod$i.ko"
    i=$((i + 1))
done
fx_add chainy 4096 1 "$(printf 'dep%d,' $(seq 1 120))" "X" "" "kernel/drivers/chainy.ko"
START=$(date +%s)
run_fx create-baseline; expect_rc 0
run_fx scan;            expect_rc 0
expect_has "Modules loaded : 2001"
END=$(date +%s)
[ $((END - START)) -le 20 ] && ok || bad "2001-module scan too slow ($((END - START))s)"
FX="$WORK/fx"

# ---------------------------------------------------------------------------
begin "output: --json is valid JSON with the expected fields"
fresh_baselined_system
fx_add diamorphine 16384 0 "-" "" "OE" none
run_fx scan --json
expect_rc 1
if command -v python3 >/dev/null 2>&1; then
    if printf '%s' "$OUT" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["overall_risk"]=="CRITICAL", d["overall_risk"]
assert d["suspicious"][0]["module"]=="diamorphine"
assert d["suspicious"][0]["score"]==100
assert any(f["rule"]=="SUSPICIOUS_NAME" for f in d["suspicious"][0]["findings"])
assert d["kernel"]=="6.1.0-test"
' 2>/dev/null; then ok; else bad "JSON invalid or wrong" "$OUT"; fi
else
    expect_has '"overall_risk": "CRITICAL"'
fi
fresh_baselined_system
run_fx scan --json
if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$OUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["suspicious"]==[] and d["overall_risk"]=="CLEAN"' 2>/dev/null && ok || bad "clean JSON wrong" "$OUT"
fi

begin "output: --output writes a file, --log appends history"
fresh_baselined_system
run_fx scan --output "$WORK/fx/r.txt" --log "$WORK/fx/h.log" --quiet
expect_rc 0
grep -q "Scan Report" "$WORK/fx/r.txt" && ok || bad "report file missing"
fx_add diamorphine 16384 0 "-" "" "OE" none
run_fx scan --log "$WORK/fx/h.log" --quiet
[ "$(grep -c 'kernel=6.1.0-test' "$WORK/fx/h.log")" = "2" ] && ok || bad "log should have 2 entries" "$(cat "$WORK/fx/h.log")"
grep -q 'CRITICAL diamorphine score=100 rules=.*SUSPICIOUS_NAME' "$WORK/fx/h.log" && ok || bad "log detail missing" "$(cat "$WORK/fx/h.log")"
run_fx scan --output /proc/nope/report.txt; expect_rc 2

begin "output: 'report' lists every module"
fresh_baselined_system
run_fx report
expect_has "All modules:"
expect_has "br_netfilter"
expect_has "kernel/net/bridge/br_netfilter.ko.xz"
run_fx scan; expect_no "All modules:"

begin "scenario: controlled demonstration (baseline -> clean -> inject -> detect -> remove -> clean)"
fx_init "$WORK/fx"; fx_base_system
run_fx create-baseline;                              expect_rc 0
run_fx scan;                                         expect_rc 0
expect_has "Overall risk: CLEAN"
fx_add test_rogue 24576 0 "-" "FEEDFACEFEEDFACEFEEDFAC" "" none
run_fx scan;                                         expect_rc 1
expect_has "test_rogue"
fx_remove test_rogue
run_fx scan;                                         expect_rc 0
expect_has "Overall risk: CLEAN"

# ---------------------------------------------------------------------------
begin "live kernel: real /proc/modules and /sys/module round trip"
if [ -r /proc/modules ] && [ -d /sys/module ]; then
    LB="$WORK/live-baseline.txt"
    run_det list;                         expect_rc 0
    run_det create-baseline --baseline "$LB"
    if [ "$RC" -eq 0 ]; then
        ok
        run_det scan --baseline "$LB"
        expect_no "NOT_IN_BASELINE"
        expect_no "SRCVERSION_CHANGED"
        expect_no "DEPS_CHANGED"
        expect_no "SIZE_CHANGED"
        expect_no "HIDDEN_FROM"
        if [ "$RC" -ne 0 ] && [ "$RC" -ne 1 ]; then bad "exit $RC on live scan" "$OUT"; else ok; fi
        run_det compare --baseline "$LB"
        expect_rc 0
        expect_has "No differences"
    else
        # a real system may already look suspicious (e.g. hidden-module false
        # positives in odd container sysfs); that must be a clean refusal
        expect_rc 2
    fi
    echo "      (live host: $(wc -l < /proc/modules | tr -d ' ') modules, kernel $(uname -r))"
else
    echo "      (skipped: no /proc/modules on this host)"
fi

# ---------------------------------------------------------------------------
echo
echo "integration: $PASS checks passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
