#!/usr/bin/env bash
# Mutation fuzzing: corrupt /proc/modules, baseline and modules.dep files in
# random ways and make sure the detector never crashes (ASan/UBSan abort with
# exit code 99 here; a normal run only ever exits 0, 1 or 2).
#
#   make fuzz [ITER=300]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
DETECTOR="${DETECTOR:-./detector}"
ITER="${ITER:-300}"
. "$HERE/lib_fixture.sh"
export ASAN_OPTIONS=exitcode=99:detect_leaks=1
export UBSAN_OPTIONS=halt_on_error=1:exitcode=99

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kmrd-fuzz.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
fx_init "$WORK/fx"; fx_base_system
"$DETECTOR" create-baseline $(detector_args) >/dev/null || { echo "fuzz setup failed"; exit 1; }
cp "$FX/proc_modules" "$WORK/proc.orig"
cp "$FX/baseline.txt" "$WORK/base.orig"
cp "$FX/modules.dep"  "$WORK/dep.orig"

mutate() { python3 - "$1" "$2" "$3" <<'PY'
import random, sys
src, dst, seed = sys.argv[1], sys.argv[2], int(sys.argv[3])
random.seed(seed)
d = bytearray(open(src, 'rb').read())
for _ in range(random.randint(1, 12)):
    if not d: break
    op = random.randint(0, 5)
    i = random.randrange(len(d))
    if op == 0:   d[i] = random.randrange(256)                       # flip byte
    elif op == 1: del d[i:i + random.randint(1, 40)]                  # delete run
    elif op == 2: d[i:i] = bytes(random.randrange(256) for _ in range(random.randint(1, 30)))
    elif op == 3: d[i:i] = b'A' * random.choice([60, 70, 300, 600, 5000])   # long token
    elif op == 4: d[i:i] = random.choice([b'\n', b'\t', b'\0', b' ', b'-', b'0x', b'99999999999999999999'])
    else:         d[i:] = d[:i][-random.randint(0, 50):]              # duplicate tail
open(dst, 'wb').write(d)
PY
}

# Give a mutated baseline a *valid* checksum so the fuzzer reaches the
# structural parser instead of always stopping at the integrity check.
resign() { python3 - "$1" <<'PY'
import sys
p = sys.argv[1]
d = open(p, 'rb').read()
i = d.rfind(b'# checksum ')
if i > 0: d = d[:i]
h = 14695981039346656037
for b in d:
    h = ((h ^ b) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
open(p, 'wb').write(d + b'# checksum %016x\n' % h)
PY
}

crashes=0
for n in $(seq 1 "$ITER"); do
    mutate "$WORK/proc.orig" "$FX/proc_modules" "$n"
    mutate "$WORK/base.orig" "$FX/baseline.txt" $((n + 100000))
    [ $((n % 2)) -eq 0 ] && resign "$FX/baseline.txt"
    mutate "$WORK/dep.orig"  "$FX/modules.dep"  $((n + 200000))
    for cmd in scan compare list report "scan --json" "scan --explain --ui fancy" "monitor --count 1 --interval 0 --ui plain"; do
        # shellcheck disable=SC2086,SC2046
        "$DETECTOR" $cmd $(detector_args) >"$WORK/out" 2>&1
        rc=$?
        if [ "$rc" -gt 2 ]; then
            crashes=$((crashes + 1))
            echo "CRASH rc=$rc iteration=$n cmd='$cmd'"
            head -20 "$WORK/out"
            mkdir -p "$WORK/keep$n"; cp "$FX/proc_modules" "$FX/baseline.txt" "$FX/modules.dep" "$WORK/keep$n/"
            cp -r "$WORK/keep$n" "/tmp/kmrd-fuzz-crash-$n"
        fi
    done
done
echo "fuzz: $ITER iterations x 7 commands, $crashes crash(es)"
[ "$crashes" -eq 0 ]
