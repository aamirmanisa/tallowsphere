#!/usr/bin/env bash
# Sync the four vendored canonical crates from THIS repository (canonical) into the product.
#
#   tallow-crypto · tallow-net · tallow-protocol · tallow-svid
#
# Canonical source of truth: this repository (Tallowsphere, the Tallow language/runtime repo).
# The product vendors these crates so it can build and test standalone. Canonical edits land here
# first; sync second.
#
# Usage:
#   TALLOW_PRODUCT_ROOT=/path/to/product bash scripts/sync-canonical-crates.sh [--check]
#
#   --check   report drift and change nothing (exit 1 if the product is behind)
#
# DESIGN RULES — each exists because the obvious version of this script caused a real problem:
#
#  1. MANIFEST-DRIVEN. crates/CANONICAL-SYNC.sha256 is the contract; only the files it names are
#     copied. The previous script synced whole crate directories.
#  2. NON-DESTRUCTIVE. There is no `--delete`, here or anywhere. A file that exists only in the
#     product is REPORTED, never removed: the product's tallow-protocol/src/wire/capabilities.rs is
#     committed there (1e85ac592) and is referenced by kex.rs, wire/messages.rs, wire/mod.rs and a
#     relay test — deleting it silently, which is what a `--delete` sync would do, removes live
#     security code and breaks the product's build.
#  3. REPOSITORIES, NEVER PATHS. No default source directory is hard-coded; the location of either
#     repository is nobody's business but the caller's.
#  4. PER-RUN ARTIFACTS ARE NOT SOURCE. `target/`, `Cargo.lock` and `*.cdx.json` are excluded;
#     vendoring them is how two stale SBOMs came to be tracked in the product.
#  5. THE RESULT IS VERIFIABLE. The manifest is installed alongside the files, so the product can
#     check its own copies against the same contract this repository holds.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$HERE/crates/CANONICAL-SYNC.sha256"
CRATES="tallow-crypto tallow-net tallow-protocol tallow-svid"
MODE="${1:-sync}"

if [ -z "${TALLOW_PRODUCT_ROOT:-}" ]; then
  echo "error: set TALLOW_PRODUCT_ROOT to the product repository root" >&2
  exit 64
fi
DST_ROOT="$TALLOW_PRODUCT_ROOT"
[ -f "$DST_ROOT/Cargo.toml" ] || { echo "error: $DST_ROOT has no Cargo.toml — wrong root?" >&2; exit 64; }
[ -f "$MANIFEST" ] || { echo "error: $MANIFEST missing — run scripts/gen-canonical-pins.sh first" >&2; exit 64; }

copied=0; added=0; same=0; behind=0

while read -r sum path; do
  case "$sum" in \#*|"") continue ;; esac
  src="$HERE/crates/$path"
  dst="$DST_ROOT/crates/$path"
  [ -f "$src" ] || { echo "  ! missing in canonical: $path" >&2; continue; }
  if [ ! -f "$dst" ]; then
    added=$((added+1)); [ "$MODE" = "--check" ] || { mkdir -p "$(dirname "$dst")"; cp "$src" "$dst"; }
    echo "  + $path"
  elif [ "$(sha256sum "$dst" | cut -d' ' -f1)" = "$sum" ]; then
    same=$((same+1))
  else
    behind=$((behind+1)); [ "$MODE" = "--check" ] || cp "$src" "$dst"
    echo "  ~ $path"
  fi
done < "$MANIFEST"

# Product-local files inside the canonical crates: report them, never touch them.
echo
echo "Product-local files inside the vendored crates (NOT synced, NOT removed):"
local_count=0
for c in $CRATES; do
  [ -d "$DST_ROOT/crates/$c" ] || continue
  while IFS= read -r f; do
    rel="${f#"$DST_ROOT/crates/"}"
    case "$rel" in */target/*|*/Cargo.lock|*.cdx.json|*/.git/*) continue ;; esac
    grep -q "  $rel\$" "$MANIFEST" || { echo "  * $rel"; local_count=$((local_count+1)); }
  done < <(find "$DST_ROOT/crates/$c" -type f)
done
[ "$local_count" -eq 0 ] && echo "  (none)"

if [ "$MODE" = "--check" ]; then
  echo
  echo "CHECK: identical=$same behind=$behind missing=$added product-local=$local_count"
  [ "$behind" -eq 0 ] && [ "$added" -eq 0 ] || exit 1
  exit 0
fi

# Install the contract so the product verifies against the same manifest this repository holds.
cp "$MANIFEST" "$DST_ROOT/crates/CANONICAL-SYNC.sha256"
cat > "$DST_ROOT/crates/VENDORED-CANONICAL.md" <<EOF
# Vendored Canonical Crates — Provenance

**Canonical source:** this project's language/runtime repository (named, not pathed — see the
manifest header for the sync procedure). Synced by \`scripts/sync-canonical-crates.sh\`, which does
the copying manifest-driven and non-destructively.

**Snapshot:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Canonical revision:** \`$(git -C "$HERE" rev-parse HEAD)\`
**Vendored set:** tallow-crypto, tallow-net, tallow-protocol, tallow-svid (MIT).

**Drift policy:** canonical edits land in the language repository first; sync second. Verify with
\`cd crates && sha256sum -c CANONICAL-SYNC.sha256\`. Review with \`git status --short crates/\`.

**Known product-local file inside the vendored set:** \`tallow-protocol/src/wire/capabilities.rs\`.
It exists only here and is load-bearing (\`kex.rs\`, \`wire/messages.rs\`, \`wire/mod.rs\`, a relay
test). Under canonical-first it should be ported up; until then the sync script treats it as a named
exception and never deletes it.
EOF

echo
echo "synced: identical=$same updated=$behind added=$added product-local=$local_count"
echo "verify: (cd $DST_ROOT/crates && sha256sum -c CANONICAL-SYNC.sha256)"
