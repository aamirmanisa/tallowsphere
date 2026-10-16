#!/bin/bash
# PGO for the tallow release binary — sheet item U-C11 ("PGO + BOLT in the release pipeline").
#
# This is the **PGO half**. The BOLT half is *not* implemented here because the tool is absent on
# this box (`llvm-bolt` is not installed and there is no `perf` to collect a BOLT profile with) —
# documented in docs/PGO.md rather than faked.
#
# Usage: scripts/pgo_ab.sh base|inst|workload|merge|use|all [corpus-dir]
#
#   base      release build, no profile              -> the comparison point
#   inst      release build with -Cprofile-generate  -> the instrumented binary
#   workload  run the instrumented binary over the corpus -> writes .profraw files
#   merge     llvm-profdata merge -> merged.profdata
#   use       release build with -Cprofile-use        -> the PGO binary
#
# THE TRAP THIS ENCODES: the .profraw files must be merged by the `llvm-profdata` that ships WITH
# the toolchain, not the system one. rustc 1.98.1 is built on LLVM 22.1.8; this box's
# /usr/bin/llvm-profdata-18 is LLVM 18.1.3. Handing 22-format profraws to an 18 merge fails, and the
# failure looks like corrupt profile data rather than a version mismatch. The toolchain's copy is
# located dynamically below so a toolchain bump cannot silently pick the wrong merger.
set -u

ARM="${1:?usage: pgo_ab.sh base|inst|workload|merge|use|all [corpus-dir]}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${TMPDIR:-/tmp}/pgo-$$"
BASE_SCRATCH="${PGO_SCRATCH:-$HERE/benchmarks/out/pgo}"
mkdir -p "$BASE_SCRATCH"
PROFRAW_DIR="$BASE_SCRATCH/profraw"
PROFDATA="$BASE_SCRATCH/merged.profdata"
LOG="$BASE_SCRATCH/$ARM.log"

export HOME=/root
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
TC="${RUSTUP_TOOLCHAIN:-1.98.1-aarch64-unknown-linux-gnu}"
export RUSTUP_TOOLCHAIN="$TC"
export CARGO_NET_OFFLINE=true

# The merger that matches rustc's LLVM, found rather than assumed.
TC_BIN="$(dirname "$(readlink -f "$HOME/.rustup/toolchains/$TC/bin/rustc")")/../lib/rustlib/aarch64-unknown-linux-gnu/bin"
PROFDATA_BIN="$(readlink -f "$TC_BIN/llvm-profdata" 2>/dev/null || true)"
if [ -z "$PROFDATA_BIN" ] || [ ! -x "$PROFDATA_BIN" ]; then
  PROFDATA_BIN="$(find "$HOME/.rustup/toolchains/$TC" -name llvm-profdata -type f 2>/dev/null | head -1)"
fi

build() { # $1=arm  $2=RUSTFLAGS  $3=target-subdir
  local arm="$1" flags="$2" tgt="${TMPDIR:-/tmp}/pgo-$1${PGO_TAG:-}"
  rm -rf "$tgt"
  echo "== $arm: RUSTFLAGS='$flags' target=$tgt" | tee -a "$LOG"
  local t0 t1
  t0=$(date +%s)
  systemd-run --scope --collect -q \
    -p MemoryMax=13G -p MemorySwapMax=4G -p IOWeight=50 \
    --setenv HOME=/root --setenv CARGO_NET_OFFLINE=true \
    --setenv RUSTUP_TOOLCHAIN="$TC" \
    --setenv RUSTFLAGS="$flags" --setenv CARGO_TARGET_DIR="$tgt" \
    --working-directory="$HERE" \
    "$CARGO" build --locked --profile release --bin tallow >> "$LOG" 2>&1
  local rc=$?
  t1=$(date +%s)
  echo "   rc=$rc wall_s=$((t1-t0)) binary=$(stat -c%s "$tgt/release/tallow" 2>/dev/null || echo ABSENT)" | tee -a "$LOG"
  return $rc
}

case "$ARM" in
  base) build base "" ;;
  inst)
    rm -rf "$PROFRAW_DIR"; mkdir -p "$PROFRAW_DIR"
    build inst "-Cprofile-generate=$PROFRAW_DIR" ;;
  use)  build use  "-Cprofile-use=$PROFDATA -Cllvm-args=-pgo-warn-missing-function" ;;
  workload)
    BIN="${TMPDIR:-/tmp}/pgo-inst/release/tallow"
    CORPUS="$2"
    [ -x "$BIN" ] || { echo "no instrumented binary at $BIN — run 'inst' first" >&2; exit 2; }
    # THE WORKLOAD MUST MATCH WHAT YOU WILL MEASURE. This is the one way to get PGO wrong in a way
    # that looks like a result: an unrepresentative profile actively MISoptimizes, because the
    # layout and branch hints are chosen for the workload you profiled, not the one you care about.
    # The first version of this arm checked the tiny benchmarks/run-engines/*.tl files, which fail
    # fast — and the resulting binary was 27% SLOWER on a real 20k-function check. Profile the
    # workload you intend to measure: a large file that actually passes `check`, and real bytes
    # through `copy`.
    mkdir -p "$CORPUS"
    FE="$CORPUS/fe-20000.tl"
    if [ ! -f "$FE" ]; then
      python3 - "$FE" <<'PY'
import sys
lines = ["// front-end corpus (generated)", ""]
for i in range(20000):
    lines += [f"fn f{i}(a: Int) -> Int {{", f"    return a + {i}", "}", ""]
open(sys.argv[1], "w").write("\n".join(lines))
PY
    fi
    BIG="$CORPUS/big.bin"
    if [ ! -f "$BIG" ]; then
      head -c 1073741824 /dev/urandom > "$BIG"
    fi
    : > "$LOG"
    for i in 1 2 3 4 5; do
      "$BIN" check "$FE" >/dev/null 2>&1
      "$BIN" copy "$BIG" "$CORPUS/out-$i.bin" >/dev/null 2>&1
      rm -f "$CORPUS/out-$i.bin"
    done
    echo "profraw files: $(ls -1 "$PROFRAW_DIR" 2>/dev/null | wc -l), bytes: $(du -sb "$PROFRAW_DIR" 2>/dev/null | cut -f1)" | tee -a "$LOG"
    ;;
  merge)
    [ -n "$PROFDATA_BIN" ] || { echo "no toolchain llvm-profdata found for $TC" >&2; exit 2; }
    echo "merger: $PROFDATA_BIN ($("$PROFDATA_BIN" --version | tail -1))" | tee -a "$LOG"
    "$PROFDATA_BIN" merge -o "$PROFDATA" "$PROFRAW_DIR" >> "$LOG" 2>&1
    echo "merge rc=$? profdata_bytes=$(stat -c%s "$PROFDATA" 2>/dev/null || echo ABSENT)" | tee -a "$LOG"
    ;;
  all)
    for a in base inst workload merge use; do
      bash "$0" "$a" "${2:-}" || { echo "ARM $a FAILED" | tee -a "$LOG"; exit 1; }
    done
    echo "ALL ARMS DONE" | tee -a "$LOG"
    ;;
  *) echo "unknown arm: $ARM" >&2; exit 64 ;;
esac
