#!/bin/bash
# Run Tallow performance benchmarks.
#
# Usage:
#   bash benches/run_benchmarks.sh            # release build (production numbers)
#   bash benches/run_benchmarks.sh --debug    # debug build (slower but catches issues)
#
# Sections:
#   1. compiler benches  (tests/compiler_bench.rs, greps compiler lines)
#   2. browser reliability benches (benches/reliability_bench.rs, criterion)

set -e

PROFILE="${1:---release}"
echo "=== Tallow Compiler Benchmarks ==="
echo "Profile: $PROFILE"
echo ""

cd "$(dirname "$0")/.."
RUST_MIN_STACK=8388608 cargo test --test compiler_bench $PROFILE -- --nocapture 2>&1 | grep -E '^\s+(lexer|parser|interp|blake3|aes|chacha|pipeline)/|throughput:'

echo ""
echo "=== Browser Reliability Benches (pool / classify_failure / pipeline dispatch / delta) ==="
# Criterion benches always build in release mode; the $PROFILE flag above
# only affects the compiler_bench test section.
cargo bench --bench reliability_bench 2>&1 | grep -E '^retry_intelligence/|^crawl_pipeline/|^pool/|^delta/' || true

echo ""
echo "=== Done ==="
