# Run Metrics Extraction

> status: verified 2026-09-05 (C6 docs wave — Phase 7 Linux-native `scripts/extract_run_metrics.py` path documented; PS1 twin correctly labeled legacy).

`TSK-1102` output helper for run-level and launch-level metrics.

## Purpose

`scripts/extract_run_metrics.py` parses a local request-plan execution report for the Phase 7 Linux/CachyOS proof. The legacy `scripts/extract_run_metrics.ps1` parses older launch batches when PowerShell is available.

The Linux-native Phase 7 tool computes:

- Throughput proxies
- Success rate
- Retry rate
- P95 latency when latency samples exist

If latency fields are not present in artifacts, latency is explicitly marked as unavailable.

## Linux/CachyOS Phase 7 usage

```bash
python3 scripts/extract_run_metrics.py \
  --execution-report artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/execution_report.json \
  --output-json artifacts/phase7/local-artifacts-replay-observability/run_metrics.json \
  --output-markdown artifacts/phase7/local-artifacts-replay-observability/run_metrics.md
```

Phase 7 proof output uses `schema_version: tallow.run_metrics.v1` and includes explicit non-claims: no live replay, no external scraping/crawling, and no benchmark/production SLO claim.

## Legacy PowerShell inputs

- Launch directory path containing `launch_report.json`, or
- Direct path to `launch_report.json`

The script reads per-run artifacts from each `run_XX` directory:

- `*summary*.txt`
- `*.csv`
- `*full*.json`
- `stdout.log`
- `stderr.log`

## Outputs

By default, output files are written into the launch root:

- `run_metrics.json`
- `run_metrics.md`

You can override both paths:

```powershell
.\scripts\extract_run_metrics.ps1 `
  -LaunchPath .\artifacts\scraper_runs\parallel10_20260427-223954 `
  -OutputJsonPath .\artifacts\scraper_runs\parallel10_20260427-223954\metrics\run_metrics.json `
  -OutputMarkdownPath .\artifacts\scraper_runs\parallel10_20260427-223954\metrics\run_metrics.md
```

## Default Usage

```powershell
.\scripts\extract_run_metrics.ps1 `
  -LaunchPath .\artifacts\scraper_runs\parallel10_20260427-223954
```

## Metric Definitions

- `success_rate`: `targets_success_json / targets_total`
- `retry_rate`: `retry_attempts / attempts_total`
- `retry_per_target_rate`: `retry_attempts / targets_total`
- `throughput_proxy.targets_per_sec` (run): `targets_total / run_duration_proxy_seconds`
- `throughput_proxy.attempts_per_sec` (run): `attempts_total / run_duration_proxy_seconds`
- `aggregate.throughput_proxy.by_worker_time`: totals divided by sum of per-run duration proxies
- `aggregate.throughput_proxy.by_wallclock`: totals divided by launch wallclock proxy

Retry attempts are derived from `l2_total + l3_total` when summary keys exist; otherwise they fall back to counting non-`L1` CSV rows.

## Latency Behavior

Latency samples are detected from known fields:

- CSV columns: `latency_ms`, `elapsed_ms`, `duration_ms`, `response_ms`, `time_ms`, `request_latency_ms`
- Full JSON per-row fields under `rows`/`responses`
- Full JSON arrays: `latencies_ms`, `latency_samples_ms`
- Summary fallback: `p95_latency_ms`

When no latency samples are found:

- `latency.p95_ms = null`
- `latency.status = "unavailable"`
- `latency.reason` explains why

## Determinism

Output is deterministic for a fixed artifact set:

- Runs are sorted (`run_01`, `run_02`, ...)
- File selection within each run is lexicographically stable
- Percentile method is fixed (nearest-rank p95)
- Numeric rounding is stable (`-RoundDigits`, default `6`)

The script does not inject runtime `now` timestamps into output payloads.

