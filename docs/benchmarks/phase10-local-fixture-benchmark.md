# Phase 10 Local Fixture Benchmark

Status: Linux/CachyOS local/offline Phase 10 proof profile.

This document explains the autonomous Phase 10 closure slice. It proves benchmark protocol tooling, validation accounting, artifact integrity, and offline Firecrawl comparison scaffolding without live external scraping or Firecrawl service/API use.

## What this profile proves

- The official benchmark artifact names can be generated locally:
  - `config.json`
  - `summary.json`
  - `kpi.csv`
  - `errors.csv`
  - `raw.jsonl`
  - `system-metrics.json`
- Every `raw.jsonl` row contains the fixed protocol fields from `benchmark-protocol.md`.
- Validation quality is tracked separately from artifact or launcher completion.
- At least one negative fixture produces a `validation` error so `errors.csv` and validation-failure metrics are exercised.
- Tallow-local and Firecrawl-mock fixture outputs can be compared through one normalized offline harness.
- Hash-checked `tallow.artifact_manifest.v1` manifests make the proof artifacts byte-verifiable.

## What this profile does not claim

- No live external scraping or crawling.
- No Firecrawl service startup.
- No Firecrawl hosted/cloud API call.
- No paid API, proxy, credential, vault, or secret use.
- No throughput, latency, cost, 1000x/10000x, or provider-superiority claim.
- No production scraper readiness, deploy/release readiness, or Windows support claim.

Live benchmarks, paid APIs, Firecrawl service startup, proxy/secret-backed runs, production target corpora, or official monthly matrix execution require explicit human approval and separate evidence.

## Local fixture corpus

Corpus path:

- `docs/benchmarks/fixtures/phase10-local-corpus.json`

The corpus uses only `fixture://` URLs. The benchmark generator refuses any non-fixture URL before writing run artifacts.

The current fixture set includes:

| Target | Category | Purpose |
| --- | --- | --- |
| `static-product-001` | `static` | successful product-card validation |
| `graphql-product-001` | `graphql` | successful JSON/GraphQL-style validation |
| `validation-fail-001` | `static` | expected validation failure for quality accounting |

## Generate local benchmark artifacts

Tallow-local fixture projection:

```bash
python3 scripts/benchmark_phase10_fixture.py \
  --corpus docs/benchmarks/fixtures/phase10-local-corpus.json \
  --provider tallow-local \
  --run-id phase10-local-tallow \
  --window-id A \
  --concurrency-level 1 \
  --output-dir artifacts/phase10/local-fixture-benchmark/tallow-local
```

Firecrawl-mock fixture projection:

```bash
python3 scripts/benchmark_phase10_fixture.py \
  --corpus docs/benchmarks/fixtures/phase10-local-corpus.json \
  --provider firecrawl-mock \
  --run-id phase10-local-firecrawl-mock \
  --window-id A \
  --concurrency-level 1 \
  --output-dir artifacts/phase10/local-fixture-benchmark/firecrawl-mock
```

The Firecrawl side is a mock fixture projection. It is not Firecrawl service output and is not hosted Firecrawl API output.

## Compare Tallow-local and Firecrawl-mock offline

```bash
python3 scripts/compare_tallow_firecrawl_offline.py \
  --tallow-run-dir artifacts/phase10/local-fixture-benchmark/tallow-local \
  --firecrawl-run-dir artifacts/phase10/local-fixture-benchmark/firecrawl-mock \
  --output-dir artifacts/phase10/local-fixture-comparison
```

The comparator fails closed unless both runs use:

- `mode: local_fixture`
- `protocol_version: 1.0-local-offline`
- matching corpus/manifest IDs
- matching target IDs
- `fixture://` URLs only
- verified input artifact manifests

It reports target coverage, validation parity, extracted-field parity, and error-class parity. It marks speed/cost/performance as `not_claimed`.

## Verify artifacts and tests

Focused tests:

```bash
python3 -B -m unittest tests.test_phase10_benchmark_protocol -v
```

Compile check:

```bash
python3 -m py_compile scripts/benchmark_phase10_fixture.py scripts/compare_tallow_firecrawl_offline.py tests/test_phase10_benchmark_protocol.py
```

Comparison manifest verification:

```bash
python3 scripts/compare_tallow_firecrawl_offline.py \
  --verify-manifest artifacts/phase10/local-fixture-comparison/artifact_manifest.json
```

Required regression smoke before Phase 10 acceptance:

```bash
python3 scripts/phase1_smoke_ladder.py --skip-build --skip-targeted-tests
```

## Blocker mapping

- `BLK-013`: closed for the local/offline Phase 10 path by emitting the official artifact names and fixed row fields. Official live matrix parity remains human-gated.
- `BLK-014`: closed for fixture quality accounting by recording validation pass/failure metrics and an expected negative fixture instead of equating launcher completion with extraction quality.
- `BLK-016`: closed for offline/mock comparison scaffolding by adding a fail-closed `scripts/compare_*` harness. Live Tallow-vs-Firecrawl benchmarking remains human-gated.

## Acceptance wording

Phase 10 local/offline acceptance means: benchmark protocol tooling, local fixture proof artifacts, validation quality accounting, artifact manifest integrity, and offline Firecrawl comparison scaffolding passed on Linux/CachyOS. It does not mean live benchmark readiness or performance superiority.
