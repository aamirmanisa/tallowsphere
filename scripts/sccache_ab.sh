#!/bin/bash
# sccache A/B for the tallow cold build (sheet U-C16).
#
# The question is not "does sccache help" but "UNDER WHAT CONDITION does it help", because the
# answer turned out to hinge on the target-dir path (see docs/BUILD-CACHE.md):
#
#   baseline  empty cache, fresh target dir at path P    -> the cold, no-cache cost
#   cached    warm cache,  fresh target dir at a NEW path -> 0 Rust hits (path is in the key)
#   repath    warm cache,  fresh target dir at path P     -> full hits: the real reduction
#
# All arms: same source, same profile, same jobs (the repo's own [build] jobs = 8), same
# freshness. The only intended variable is the state of the compilation cache -- and the
# `cached` vs `repath` pair exists to isolate the path sensitivity, which is otherwise
# invisible and reads as "sccache doesn't work".
#
# Usage: scripts/sccache_ab.sh baseline|cached|repath [scratch-dir]
set -u
ARM="${1:?usage: sccache_ab.sh baseline|cached|repath [scratch-dir]}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${2:-$HERE/benchmarks/out}"
mkdir -p "$SCRATCH"
LOG="$SCRATCH/sccache_ab_${ARM}.log"
RES="$SCRATCH/sccache_ab_${ARM}.result"

# repath deliberately reuses the BASELINE arm's target path: that is the whole point of the
# third arm, so it is not a copy-paste slip.
if [ "$ARM" = "repath" ]; then TGT="${TMPDIR:-/tmp}/sccache-ab-baseline"; else TGT="${TMPDIR:-/tmp}/sccache-ab-${ARM}"; fi

command -v sccache >/dev/null || { echo "sccache not installed (apt-get install -y sccache)" >&2; exit 2; }

sccache --stop-server >/dev/null 2>&1 || true
if [ "$ARM" = "baseline" ]; then rm -rf "${SCCACHE_DIR:-$HOME/.cache/sccache}"; fi
rm -rf "$TGT"
sccache --start-server >/dev/null 2>&1
sleep 1
sccache --zero-stats >/dev/null 2>&1

echo "arm=$ARM target=$TGT cache=$(sccache --show-stats | grep -o 'Local disk: \"[^\"]*\"')" > "$RES"

cd "$HERE" || exit 3
t0=$(date +%s)
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}" \
CARGO_TARGET_DIR="$TGT" \
CARGO_NET_OFFLINE=true \
RUSTC_WRAPPER="$(command -v sccache)" \
  "${CARGO:-$HOME/.cargo/bin/cargo}" build --locked --profile release --bin tallow > "$LOG" 2>&1
rc=$?
t1=$(date +%s)

{
  echo "arm=$ARM rc=$rc wall_s=$((t1-t0))"
  echo "binary_bytes=$(stat -c%s "$TGT/release/tallow" 2>/dev/null || echo ABSENT)"
  echo "target_dir=$(du -sh "$TGT" 2>/dev/null | cut -f1)"
  echo "log_tail:"; tail -2 "$LOG" | sed 's/^/  /'
  echo "sccache:"; sccache --show-stats | grep -E 'Compile requests |Cache hits |Cache misses |Cache size' | sed 's/^/  /'
} >> "$RES"
cat "$RES"
