# Benchmark Protocol

> **Docs truth label:** Authoritative benchmark artifact protocol. Current accepted implementation is the Phase 10 local/offline fixture profile and P2-005 scaffold only; live benchmarks, paid APIs, Firecrawl service/API comparisons, performance-superiority claims, and release gating remain human-gated until a later accepted live benchmark gate.

## Purpose
Define a repeatable, controlled benchmark for Tallow scraper performance so month-over-month and release-over-release comparisons are valid.

## Scope
- In scope: throughput, latency, success rate, error profile, resource usage, and cost proxies.
- Out of scope: ad-hoc one-off stress tests that do not follow this protocol.

## Controlled Test Conditions
All benchmark runs must use the exact same control set unless a versioned protocol update is approved.

### 1) Targets (Fixed Set)
- Use the same target manifest file for all official runs: `benchmarks/targets/v1-targets.json`.
- Manifest includes:
  - `target_id`
  - `url`
  - `category` (`static`, `dynamic`, `graphql`, `auth-wall`, `rate-limited`)
  - `expected_content_type`
  - `validation_rule_id`
- Any target additions/removals require:
  - New manifest version (`v2`, `v3`, ...)
  - Changelog entry
  - One month overlap reporting (old + new manifests side by side)

### 2) Time Windows (Fixed Schedule)
- Run only in approved windows to reduce internet volatility bias.
- Default windows (America/Chicago):
  - Window A: 09:00-11:00
  - Window B: 21:00-23:00
- Monthly report must include both windows.
- Do not compare an A-window run against a B-window run as a primary claim.

### 3) Retry Budget (Fixed Policy)
- Global retry budget per request: max `3` attempts total (`1 initial + 2 retries`).
- Backoff policy:
  - Retry 1: `+500ms`
  - Retry 2: `+1500ms`
- Retryable errors:
  - Network timeout
  - `429`
  - `5xx`
- Non-retryable:
  - `401`, `403`, validation-failed payloads, malformed configuration errors.

### 4) Output Schema (Fixed Contract)
All benchmark runs must produce JSONL rows that conform to this schema:

```json
{
  "run_id": "string",
  "protocol_version": "string",
  "manifest_version": "string",
  "window_id": "A|B",
  "timestamp_utc": "ISO-8601",
  "target_id": "string",
  "url": "string",
  "attempt": 1,
  "status_code": 200,
  "success": true,
  "duration_ms": 1234,
  "bytes_received": 45678,
  "error_class": "none|timeout|http_4xx|http_5xx|validation|other",
  "validation_passed": true,
  "worker_id": "string",
  "concurrency_level": 500
}
```

Required aggregates per run:
- `summary.json`
- `kpi.csv`
- `errors.csv`

## Execution Matrix
Each official run must execute the matrix below:
- Concurrency levels: `50`, `100`, `250`, `500`
- Time windows: `A`, `B`
- Repetitions per cell: `3`

Total runs per monthly cycle: `4 x 2 x 3 = 24`.

## Measurement Definitions
- Throughput (req/s): completed attempts / wall-clock seconds.
- P50/P95 latency: percentile of `duration_ms` over successful requests.
- Success rate: `success=true` / total terminal attempts.
- Validation pass rate: `validation_passed=true` / successful requests.
- Error rate by class: count(error_class) / total terminal attempts.
- Memory footprint:
  - `rss_peak_mb` and `rss_p95_mb` from runtime telemetry.
- CPU efficiency:
  - `cpu_seconds / 1000 successful requests`.

## Regression Gating Thresholds
Release is blocked if any threshold is violated versus baseline (previous stable monthly median at same window + concurrency).

- Throughput regression: fail if decrease is `> 10%`.
- P95 latency regression: fail if increase is `> 15%`.
- Success rate regression: fail if absolute drop is `> 1.0 percentage point`.
- Validation pass regression: fail if absolute drop is `> 0.5 percentage point`.
- Error budget breach: fail if `timeout + 5xx + 429` increases by `> 20%` relative.
- Memory ceiling breach: fail if `rss_peak_mb` exceeds approved ceiling by any amount.
- Stability breach: fail if coefficient of variation for throughput across 3 repetitions is `> 0.12`.

## Baseline Policy
- Baseline source: last approved monthly report marked `stable`.
- If no stable baseline exists:
  - Use current month as calibration only.
  - Mark all gates as `N/A (bootstrap)` and do not claim regression pass.

## Environment Lock Requirements
- Pin and record:
  - Tallow commit SHA
  - Runtime binary version
  - OS version
  - Host SKU (CPU/RAM/network)
  - Proxy provider + plan + region policy
- Disallow mixed environments within the same official run set.

## Run Artifacts
Store under:
- `artifacts/benchmarks/{yyyy-mm}/{run_id}/`

Minimum artifact set:
- `config.json`
- `summary.json`
- `kpi.csv`
- `errors.csv`
- `raw.jsonl`
- `system-metrics.json`

## Local/offline Phase 10 closure profile

The official live benchmark matrix above remains unchanged and still requires
approved target windows, reviewed live targets, and production-grade environment
locks before it can support throughput, latency, cost, or vendor-comparison
claims.

For the Phase 10 autonomous gate, a narrower local/offline profile may be used to
prove protocol tooling and truthfulness without live external I/O:

- Protocol profile: `protocol_version: 1.0-local-offline`.
- Measurement scope: `local_fixture_only`.
- Corpus: `docs/benchmarks/fixtures/phase10-local-corpus.json` with only
  `fixture://` URLs.
- Artifact location: `artifacts/phase10/local-fixture-benchmark/<provider>/`.
- Required artifact names are the same as the official protocol:
  `config.json`, `summary.json`, `kpi.csv`, `errors.csv`, `raw.jsonl`, and
  `system-metrics.json`.
- `raw.jsonl` rows must still contain every fixed protocol row field from the
  Output Schema section.
- The local fixture corpus must include at least one validation failure so
  reports distinguish launcher/artifact completion from extraction or validation
  quality.
- Offline Firecrawl comparison, when used, must be labeled
  `comparison_mode: offline_fixture` and `firecrawl_mode: mock_fixture_projection`.

Local/offline Phase 10 artifacts must include explicit non-claims: no live
external scraping/crawling, no Firecrawl service startup, no hosted or paid API
use, no secrets, no throughput/latency/cost or vendor superiority claim, no
production readiness claim, and no Windows support claim. Any live benchmark,
Firecrawl service/API comparison, paid API use, proxy/secret-backed run, or
official monthly matrix execution remains a human-gated follow-up.

## Change Management
- Protocol versioning format: `major.minor`.
- Bump `major` for incompatible schema/policy changes.
- Bump `minor` for additive metrics.
- Every change requires:
  - rationale
  - expected impact
  - effective date
  - owner approval

