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

# THE AES TRAP, AND WHY EVERY ARM CARRIES THESE FLAGS EXPLICITLY.
# `.cargo/config.toml` puts `-C target-feature=+aes --cfg aes_armv8` in the [target.*] table, and
# cargo IGNORES that whole table the moment RUSTFLAGS is exported — even when RUSTFLAGS is the empty
# string. Verified with a nested probe crate (2026-10-16):
#     RUSTFLAGS unset              -> target-feature=+aes, --cfg aes_armv8   present
#     RUSTFLAGS=""                 -> both ABSENT
#     RUSTFLAGS="-Ccodegen-units=16" -> both ABSENT
# Without them the AES-256-GCM backend silently assembles its bitsliced fallback: measured
# 2026-10-21 on aarch64 (8 MiB x 16, benchmarks/cliff-probe) at 65.6 MB/s vs 128.3 MB/s for
# RustCrypto aes-gcm 0.10, the backend in use since the libcrux 0.0.8 removal.
# So a PGO build that "just adds -Cprofile-use" would ship an ~8.8x crypto regression, and a PGO A/B
# that only sets RUSTFLAGS on some arms would compare two different configurations. These two flags
# are therefore re-stated here for EVERY arm, and the `flags` arm below asserts they reach rustc.
AES_FLAGS="-C target-feature=+aes --cfg aes_armv8"

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
  base) build base "$AES_FLAGS" ;;
  inst)
    rm -rf "$PROFRAW_DIR"; mkdir -p "$PROFRAW_DIR"
    build inst "$AES_FLAGS -Cprofile-generate=$PROFRAW_DIR" ;;
  use)  build use  "$AES_FLAGS -Cprofile-use=$PROFDATA -Cllvm-args=-pgo-warn-missing-function" ;;
  flags)
    # Regression guard for the trap above: build a throwaway crate INSIDE this tree (so it inherits
    # .cargo/config.toml) under each arm's RUSTFLAGS and assert the AES flags reach rustc. Cheap
    # enough to run before every PGO build, and it fails loudly rather than shipping a slow binary.
    PROBE="$HERE/tmp_aesprobe"
    rm -rf "$PROBE"; mkdir -p "$PROBE/src"
    printf '[package]\nname = "aesprobe"\nversion = "0.1.0"\nedition = "2021"\n\n[workspace]\n' > "$PROBE/Cargo.toml"
    echo 'fn main() {}' > "$PROBE/src/main.rs"
    rc=0
    # unset -> the config table works. empty -> the trap (informational). pgo -> OUR fix must restore
    # the flags, which is the assertion that matters.
    for spec in "unset:" "empty:" "pgo:$AES_FLAGS -Cprofile-generate=$PROFRAW_DIR"; do
      name="${spec%%:*}"; flags="${spec#*:}"
      if [ "$name" = "unset" ]; then
        out=$($CARGO build -v --manifest-path "$PROBE/Cargo.toml" 2>&1 | rg -o 'target-feature=\+aes|--cfg aes_armv8' | sort -u)
      else
        out=$(RUSTFLAGS="$flags" $CARGO build -v --manifest-path "$PROBE/Cargo.toml" 2>&1 | rg -o 'target-feature=\+aes|--cfg aes_armv8' | sort -u)
      fi
      n=$(printf '%s\n' "$out" | rg -c . || true)
      n=${n:-0}   # rg -c prints nothing when there are no matches; an empty n breaks the [ ] test
      echo "  $name -> aes flags present: $n/2" | tee -a "$LOG"
      # BOTH arms this script actually builds must have them; a bare exported RUSTFLAGS must not,
      # which is precisely why AES_FLAGS exists.
      case "$name" in
        unset|pgo) [ "$n" -ge 2 ] || { rc=1; echo "  FAIL: $name lost the AES flags" >&2; } ;;
        empty)     [ "$n" -eq 0 ] || echo "  note: exported RUSTFLAGS kept the AES flags on this cargo — the AES_FLAGS restatement is then redundant but harmless" | tee -a "$LOG" ;;
      esac
    done
    rm -rf "$PROBE"
    [ $rc -eq 0 ] && echo "  guard OK: an arm built by this script carries the AES flags" || echo "  GUARD FAILED" >&2
    exit $rc
    ;;
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
