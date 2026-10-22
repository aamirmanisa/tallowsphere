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
# --test-threads=1 is REQUIRED, not cosmetic: the suite hashes 100 MB and runs
# fib(15), so concurrent tests inflate every latency 1.7-3.3x (measured
# 2026-10-22: lexer/simple 0.319 us serialised vs 1.010 us in parallel).
RUST_MIN_STACK=8388608 cargo test --test compiler_bench $PROFILE -- --nocapture --test-threads=1 2>&1 | grep -E 'us/iter|throughput:'

echo ""
echo "=== Browser Reliability Benches (pool / classify_failure / pipeline dispatch / delta) ==="
# Criterion benches always build in release mode; the $PROFILE flag above
# only affects the compiler_bench test section.
# Criterion prints the bench id on one line and `time: [...]` on the NEXT, so
# both patterns must match or every figure is silently dropped.
cargo bench --bench reliability_bench 2>&1 | grep -E '^(retry_intelligence|delta|crawl_pipeline|pool)/|^\s+time:\s+\[' || true

echo ""
echo "=== Done ==="
