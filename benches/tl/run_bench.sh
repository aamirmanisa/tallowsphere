#!/bin/bash
# Run Tallow benchmark programs (.tl) with the already-built debug binary.
#
# This runner does NOT build the tallow binary (build is gated by the
# coordinator) — it executes the pre-built target/debug/tallow. Each program is
# run N times and the wall-clock time is captured via bash `time`.
#
# INTEGRITY (added 2026-09-09): `tallow run` is NATIVE-FIRST with a silent
# interpreter fallback. If the native path crashes or can't build, it re-runs
# the SAME program in the tree-walking interpreter and still exits 0 — so a
# reported time can secretly be interpreter time, not native. This runner:
#   - DETECTS and records which engine ran (native / interp-fallback) by
#     scanning stderr for the fallback markers.
#   - INDEPENDENTLY probes native soundness per program via `tallow build` +
#     direct binary execution, because `tallow run` hides a native signal-crash
#     behind its fallback.
#   - FAILS LOUDLY: a program whose native binary crashes is reported as
#     NATIVE-CRASH (a real finding), never silently passed as interpreter time.
#     A program that fell back to the interpreter is reported as WARN (the time
#     logged is interpreter time) but not counted as a clean native pass.
#
# Categories covered:
#   bench_fib_iter.tl     compute-bound (iterative fibonacci + nested numeric loop)
#   bench_recursive.tl    compute-bound (recursion; call depth bounded, call count high)
#   bench_alloc.tl        alloc-heavy   (string concat, array growth, map build)
#   bench_io.tl           io-ish        (temp file write/read/delete in a loop)
#
# Usage:
#   bash benches/tl/run_bench.sh              # default 3 iterations
#   bash benches/tl/run_bench.sh 5            # 5 iterations per program
#   bash benches/tl/run_bench.sh 3 --quiet    # suppress per-run engine chatter

set -u

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO_DIR/target/debug/tallow"
TL_DIR="$REPO_DIR/benches/tl"
ITERATIONS="${1:-3}"
QUIET="${2:-}"

# The interpreter's recursive evaluation needs a large native stack.
export RUST_MIN_STACK=67108864

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found at $BIN (build is gated; not running cargo)" >&2
    exit 1
fi

echo "=== Tallow (.tl) benchmark runner ==="
echo "Binary: $BIN"
echo "Programs dir: $TL_DIR"
echo "Iterations per program: $ITERATIONS"
echo ""

pass=0
fail=0
warn=0

# ── Detect which engine `tallow run` actually executed. ──────────────────────
# $1 = combined stdout+stderr from a `tallow run`. Prints NATIVE or INTERP-FALLBACK.
engine_of() {
    if echo "$1" | grep -Eq '\* native run crashed|\* native build unavailable'; then
        echo "INTERP-FALLBACK"
    else
        echo "NATIVE"
    fi
}

# ── Independent native-soundness probe: build + run the raw binary. ──────────
# `tallow run` masks a native signal-crash behind its interpreter fallback, so
# this probes the binary directly. $1 = program path, $2 = program name.
# Prints NATIVE-OK / NATIVE-CRASH / BUILD-FAIL.
probe_native() {
    local tl="$1" name="$2"
    local tmp; tmp="$(mktemp -d)"
    cp "$tl" "$tmp/prog.tl"
    if ! "$BIN" build "$tmp/prog.tl" >"$tmp/build.log" 2>&1; then
        echo "BUILD-FAIL"; rm -rf "$tmp"; return
    fi
    # Run the raw native binary. A kill-by-signal yields rc>=128 (139=SEGV);
    # a zero exit means the native binary is sound for this program.
    timeout 60 "$tmp/prog" >/dev/null 2>&1
    local rc=$?
    rm -rf "$tmp"
    if [ $rc -ge 128 ]; then
        echo "NATIVE-CRASH(rc=$rc)"
    else
        echo "NATIVE-OK"
    fi
}

for tl in "$TL_DIR"/bench_*.tl; do
    name="$(basename "$tl")"
    echo "──────────────────────────────────────────"
    echo "PROGRAM: $name"

    # Verify it parses/runs once. Capture BOTH stdout+stderr so the engine
    # markers (native crash / fallback) are visible — the old harness discarded
    # stderr here and so never saw the fallback.
    first_out="$("$BIN" run "$tl" 2>&1)"
    first_rc=$?
    if [ $first_rc -ne 0 ]; then
        echo "  PARSE/RUN: FAIL (exit $first_rc)"
        echo "$first_out" | sed 's/^/    /'
        fail=$((fail + 1))
        continue
    fi

    eng="$(engine_of "$first_out")"

    # Independent native-soundness probe (surfaces crashes `tallow run` hides).
    native_probe="$(probe_native "$tl" "$name")"

    print_verdict() {
        echo "  PARSE/RUN: ok"
        echo "$first_out" | grep -E 'OK|verified' | sed 's/^/    /'
        echo "  ENGINE: $eng (from 'tallow run')"
        echo "  NATIVE PROBE: $native_probe"
    }

    case "$native_probe" in
        NATIVE-CRASH*)
            print_verdict
            echo "  NATIVE PATH: CRASHED. The native binary dies by signal; the reported"
            echo "              time below is the INTERPRETER (fallback), NOT native. Treat"
            echo "              this as a codegen defect, not a passing benchmark."
            warn=$((warn + 1))
            ;;
        BUILD-FAIL)
            print_verdict
            echo "  NATIVE PATH: build unavailable. Time below is the INTERPRETER."
            warn=$((warn + 1))
            ;;
        NATIVE-OK)
            if [ "$eng" = "NATIVE" ]; then
                print_verdict
                echo "  NATIVE PATH: sound (build succeeded + binary ran clean)."
                pass=$((pass + 1))
            else
                print_verdict
                echo "  NATIVE PATH: probe clean but 'tallow run' fell back — engine mismatch."
                warn=$((warn + 1))
            fi
            ;;
    esac

    echo "  TIMINGS over $ITERATIONS run(s) [${eng}${native_probe#NATIVE}]:"
    i=1
    while [ $i -le "$ITERATIONS" ]; do
        # `time` writes to stderr; capture it and parse the `real` line.
        metric="$( { time "$BIN" run "$tl" >/dev/null 2>&1 ; } 2>&1 )"
        real_s="$(echo "$metric" | sed -n 's/^real[[:space:]]\{1,\}\([0-9.]*\)m\([0-9.]*\)s.*/\1 \2/p')"
        if [ -n "$real_s" ]; then
            mins="${real_s% *}"; secs="${real_s##* }"
            total="$(awk -v m="$mins" -v s="$secs" 'BEGIN { printf "%.3f", m*60 + s }')"
        else
            total="?"
        fi
        printf '      run %d/%d: %s s\n' "$i" "$ITERATIONS" "$total"
        i=$((i + 1))
    done
    echo ""
done

echo "──────────────────────────────────────────"
echo "SUMMARY: $pass native-sound pass(es), $warn warning(s), $fail failed"
echo "  WARN = native path crashed or unbuildable for that program;"
echo "         any time logged for it is INTERPRETER time, not native."
echo "  A non-zero WARN count is an honest finding, not a pass."
[ $fail -eq 0 ]
