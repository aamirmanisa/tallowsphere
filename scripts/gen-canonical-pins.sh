#!/usr/bin/env bash
# Regenerate crates/CANONICAL-SYNC.sha256 — the pin set for the vendored canonical crates.
#
# Canonical source of truth: THIS repository (Tallowsphere). The four crates below are
# vendored into the sendtallow product repo so it can build standalone. This manifest is
# engine-side and authoritative; the product's drift is measured by comparing its files
# against these pins (scripts/sync-canonical-crates.sh --check), not by trusting a manifest
# of its own.
#
#   verify:      cd crates && sha256sum -c CANONICAL-SYNC.sha256
#   regenerate:  scripts/gen-canonical-pins.sh
#
# Excluded by policy, because a pin is only meaningful for sources:
#   target/, .git/                  build output and VCS metadata
#   fuzz/corpus/, fuzz/artifacts/   per-repo fuzz inputs — reproduce differently in each repo
#   per-crate Cargo.lock            the product uses its workspace lock
#   *.cdx.json, *.sbom.json         generated SBOM artifacts, not sources (they were pinned
#                                   before and were the bulk of the failures this replaces)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATES=(tallow-crypto tallow-net tallow-protocol tallow-svid)

cd "$ROOT/crates"

{
  echo "# CANONICAL-SYNC sha256 pins — vendored canonical crates:"
  echo "#   tallow-crypto, tallow-net, tallow-protocol, tallow-svid"
  echo "# Paths are relative to this crates/ directory."
  echo "#   verify:      cd crates && sha256sum -c CANONICAL-SYNC.sha256"
  echo "#   regenerate:  scripts/gen-canonical-pins.sh"
  echo "#"
  echo "# Excluded by policy: target/, .git/, fuzz/corpus/, fuzz/artifacts/, per-crate Cargo.lock,"
  echo "# and generated SBOM artifacts (*.cdx.json, *.sbom.json) — build outputs, not sources."
  for c in "${CRATES[@]}"; do
    find "$c" -type f \
      ! -path "*/target/*" ! -path "*/.git/*" \
      ! -path "*/fuzz/corpus/*" ! -path "*/fuzz/artifacts/*" \
      ! -name "Cargo.lock" ! -name "*.cdx.json" ! -name "*.sbom.json" \
      -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
  done
} > CANONICAL-SYNC.sha256

grep -cE '^[0-9a-f]{64}  ' CANONICAL-SYNC.sha256 | xargs echo "pinned files:"
