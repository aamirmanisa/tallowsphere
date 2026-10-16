#!/bin/bash
# C1d / E4 — capped release-build benchmark measurement for benches/tl/*.tl
#
# ADAPTS the integrity logic of benches/tl/run_bench.sh (engine-marker detection
# + independent `tallow build` native probe) and adds what E4 requires:
#   - per-invocation fleet INCIDENT caps (ulimit -v 2000000 KB + timeout 120 s)
#   - wall + max-RSS capture via /usr/bin/time -v
#   - median / min / max / mean over N iterations
#   - three modes: run (tallow run), elf (build once, time the raw ELF),
#     interp (tree-walker via cross --target)
#
# Usage:
#   bash benches/tl/run_bench_release.sh [ITER] [MODE] [BIN]
#     ITER  iterations per program (default 5)
#     MODE  run | elf | interp | repeat   (default run; see note per mode below)
#           run    = tallow run  (native build + execute; user-facing wall)
#           elf    = tallow build once, then time the raw emitted ELF
#           interp = tree-walker via cross --target (default x86_64-linux)
#           repeat = supplementary sub-10ms timing: inner loop of the ELF,
#                    /bin/true loop floor subtracted
#     BIN   compiler binary (default $REPO/target/release/tallow)
# Env:
#   C1D_OUT        output dir for raw logs + summary.tsv
#                  (default artifacts/to-100-2026-09-16/C1d-evidence/<mode>)
#   CROSS_TARGET   target used by MODE=interp to force the tree-walker (default x86_64-linux)
#
# Repo is read-only for this script: writes only under C1D_OUT and a mktemp dir.
# No cargo. No commits.

set -u

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TL_DIR="$REPO_DIR/benches/tl"
ITER="${1:-5}"
MODE="${2:-run}"
BIN="${3:-$REPO_DIR/target/release/tallow}"
CAP_KB=2000000
TMO=120
CROSS_TARGET="${CROSS_TARGET:-x86_64-linux}"
OUT="${C1D_OUT:-$REPO_DIR/artifacts/to-100-2026-09-16/C1d-evidence/$MODE}"
mkdir -p "$OUT"
SUMMARY="$OUT/summary.tsv"

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found/executable: $BIN" >&2
    exit 1
fi

echo "=== C1d/E4 capped .tl benchmark ==="
echo "binary=$BIN ($(sha256sum "$BIN" 2>/dev/null | cut -c1-16))"
echo "mode=$MODE iterations=$ITER caps=(ulimit -v ${CAP_KB}KB; timeout ${TMO}s)"
echo "out=$OUT"
printf 'program\tengine\tn\trc_ok\tmedian_s\tmin_s\tmax_s\tmean_s\trss_median_kb\trss_max_kb\tnative_probe\n' > "$SUMMARY"

# ── run one capped invocation with /usr/bin/time -v; log to $1 ──────────────
# usage: timed <logfile> <cmd...>   → echoes rc
timed() {
    local log="$1"; shift
    ( ulimit -v "$CAP_KB"; timeout "$TMO" /usr/bin/time -v "$@" ) >"$log" 2>&1
    echo $?
}

wall_of() { sed -n 's/^[[:space:]]*Elapsed (wall clock) time (h:mm:ss or m:ss): //p' "$1" | tail -1; }
rss_of()  { sed -n 's/^[[:space:]]*Maximum resident set size (kbytes): //p' "$1" | tail -1; }

# seconds from "h:mm:ss.ss" / "m:ss.ss" / "ss.ss"
to_secs() {
    awk -F: '{ if (NF==3) printf "%.3f", $1*3600+$2*60+$3; else if (NF==2) printf "%.3f", $1*60+$2; else printf "%.3f", $1 }' <<<"$1"
}

engine_of() {
    if grep -qE 'native build unavailable|native run crashed' "$1"; then echo "INTERP-FALLBACK"
    elif grep -qE 'Cross-compiled binary for' "$1"; then echo "CROSS-INTERP"
    else echo "NATIVE"; fi
}

# independent native probe (same verdicts as run_bench.sh)
probe_native() {
    local tl="$1" tmp; tmp="$(mktemp -d)"
    cp "$tl" "$tmp/prog.tl"
    local rc
    rc=$(timed "$tmp/build.log" "$BIN" build "$tmp/prog.tl")
    if [ "$rc" -ne 0 ]; then echo "BUILD-FAIL"; rm -rf "$tmp"; return; fi
    rc=$(timed "$tmp/run.log" "$tmp/prog")
    rm -rf "$tmp"
    if [ "$rc" -ge 128 ]; then echo "NATIVE-CRASH(rc=$rc)"; else echo "NATIVE-OK"; fi
}

# ── supplementary mode: inner-repeat timing (sub-10 ms programs) ─────────────
# time -v's wall display has 10 ms resolution, so a ~2 ms native program reads
# 0.00 s. This mode runs the ELF N times inside one capped shell loop, times the
# loop with /usr/bin/time -v, and subtracts the measured /bin/true loop floor
# (fork+exec overhead) for a per-run estimate. Clearly labelled as supplementary.
if [ "$MODE" = "repeat" ]; then
    REP_SUMMARY="$OUT/summary_repeat.tsv"
    printf 'program\tn_inner\twall_total_s\tfloor_total_s\tper_run_ms\trss_max_kb\tbuild_wall_s\n' > "$REP_SUMMARY"
    for tl in "$TL_DIR"/bench_*.tl; do
        name="$(basename "$tl" .tl)"; prog="$OUT/$name"; mkdir -p "$prog"
        tmp="$(mktemp -d)"; cp "$tl" "$tmp/$name.tl"
        brc=$(timed "$prog/build.log" "$BIN" build "$tmp/$name.tl")
        if [ "$brc" -ne 0 ] || [ ! -x "$tmp/$name" ]; then
            echo "  $name: BUILD-FAIL(rc=$brc) — no ELF"
            printf '%s\t0\t-\t-\t-\t-\t-\n' "$name" >> "$REP_SUMMARY"; rm -rf "$tmp"; continue
        fi
        bw="$(to_secs "$(wall_of "$prog/build.log")")"
        # size N from a single coarse timed run
        rc=$(timed "$prog/single.log" "$tmp/$name")
        w="$(to_secs "$(wall_of "$prog/single.log")")"
        N="$(awk -v w="$w" 'BEGIN { if (w<=0.005) print 500; else if (w<=0.02) print 200; else if (w<=0.05) print 100; else if (w<=0.2) print 20; else print 5 }')"
        frc=$(timed "$prog/floor.log" bash -c "for k in \$(seq 1 $N); do /bin/true; done")
        prc=$(timed "$prog/repeat.log" bash -c "for k in \$(seq 1 $N); do $tmp/$name; done")
        T="$(to_secs "$(wall_of "$prog/repeat.log")")"; F="$(to_secs "$(wall_of "$prog/floor.log")")"
        rss="$(rss_of "$prog/repeat.log")"
        per="$(awk -v T="$T" -v F="$F" -v N="$N" 'BEGIN { printf "%.3f", (T-F)*1000.0/N }')"
        printf '  %s: N=%s per-run≈%s ms (total %ss − floor %ss) rss_max=%sKB build_wall=%ss rc=%s/%s\n' \
               "$name" "$N" "$per" "$T" "$F" "$rss" "$bw" "$prc" "$frc"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$N" "$T" "$F" "$per" "${rss:-0}" "$bw" >> "$REP_SUMMARY"
        rm -rf "$tmp"
    done
    echo; echo "=== summary_repeat.tsv ==="; column -t -s "$(printf '\t')" "$REP_SUMMARY" || cat "$REP_SUMMARY"
    exit 0
fi

for tl in "$TL_DIR"/bench_*.tl; do
    name="$(basename "$tl" .tl)"
    prog="$OUT/$name"
    mkdir -p "$prog"
    echo "────────────────────────────── $name"
    probe="$(probe_native "$tl")"

    case "$MODE" in
      elf)
        # build once into a temp dir, then time the raw ELF directly
        tmp="$(mktemp -d)"
        cp "$tl" "$tmp/$name.tl"
        brc=$(timed "$prog/build.log" "$BIN" build "$tmp/$name.tl")
        if [ "$brc" -ne 0 ] || [ ! -x "$tmp/$name" ]; then
            echo "  BUILD-FAIL (rc=$brc) — no ELF to time"; echo -e "$name\tBUILD-FAIL\t0\t-\t-\t-\t-\t-\t-\t-\t$probe" >> "$SUMMARY"
            rm -rf "$tmp"; continue
        fi
        target_bin="$tmp/$name"
        for i in $(seq 1 "$ITER"); do
            rc=$(timed "$prog/run$i.log" "$target_bin")
            printf '  run %d/%d rc=%s wall=%ss rss=%sKB\n' "$i" "$ITER" "$rc" "$(wall_of "$prog/run$i.log")" "$(rss_of "$prog/run$i.log")"
        done
        rm -rf "$tmp"
        ;;
      interp)
        for i in $(seq 1 "$ITER"); do
            rc=$(timed "$prog/run$i.log" "$BIN" run --target "$CROSS_TARGET" "$tl")
            printf '  run %d/%d rc=%s wall=%ss rss=%sKB\n' "$i" "$ITER" "$rc" "$(wall_of "$prog/run$i.log")" "$(rss_of "$prog/run$i.log")"
        done
        ;;
      run|*)
        for i in $(seq 1 "$ITER"); do
            rc=$(timed "$prog/run$i.log" "$BIN" run "$tl")
            printf '  run %d/%d rc=%s wall=%ss rss=%sKB\n' "$i" "$ITER" "$rc" "$(wall_of "$prog/run$i.log")" "$(rss_of "$prog/run$i.log")"
        done
        ;;
    esac

    # ── stats over the run logs that produced a wall value ──
    for i in $(seq 1 "$ITER"); do
        [ -f "$prog/run$i.log" ] || continue
        w=$(wall_of "$prog/run$i.log"); [ -n "$w" ] || continue
        r=$(rss_of "$prog/run$i.log")
        printf '%s\t%s\t%s\n' "$(to_secs "$w")" "${r:-0}" "$(grep -c 'Exit status: 0' "$prog/run$i.log")"
    done | sort -t "$(printf '\t')" -k1,1n > "$prog/walls.tsv"
    awk -F'\t' -v name="$name" -v eng="$(engine_of "$prog/run1.log" 2>/dev/null || echo UNKNOWN)" -v probe="$probe" '
      { n++; w[n]=$1+0; r[n]=$2+0; if ($3+0==1) ok++ }
      END {
        if (n==0) { printf "%s\t%s\t0\t-\t-\t-\t-\t-\t-\t-\t%s\n", name, eng, probe; exit }
        for (i=1;i<=n;i++) for (j=i+1;j<=n;j++) { if (w[j]<w[i]) {t=w[i];w[i]=w[j];w[j]=t} if (r[j]<r[i]) {t=r[i];r[i]=r[j];r[j]=t} }
        med = (n%2) ? w[(n+1)/2] : (w[n/2]+w[n/2+1])/2
        rmed = (n%2) ? r[(n+1)/2] : (r[n/2]+r[n/2+1])/2
        mean=0; for (i=1;i<=n;i++) mean+=w[i]; mean/=n
        printf "%s\t%s\t%d\t%d\t%.3f\t%.3f\t%.3f\t%.3f\t%d\t%d\t%s\n", name, eng, n, ok, med, w[1], w[n], mean, rmed, r[n], probe
      }' "$prog/walls.tsv" >> "$SUMMARY"
done

echo
echo "=== summary.tsv ==="
column -t -s "$(printf '\t')" "$SUMMARY" || cat "$SUMMARY"
echo
echo "note: engine is read from the run-1 log (fallback markers); native_probe is an"
echo "      independent tallow-build + raw-ELF execution capped the same way."
