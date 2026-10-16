# Monthly Benchmark Report - 2026-04

## Metadata
- Report month: `2026-04`
- Protocol version: `1.0`
- Manifest/version in use: `Apollo GraphQL probe set (5 URLs)` via `config_500_test2.json`
- Report scope: `TSK-1205 first concrete monthly report`
- Generated at (UTC): `2026-04-28T03:36:35Z` (latest included launch timestamp)

## Executive Summary
- Overall status: `CALIBRATION`
- Primary finding: 500-connection parallel launch completed reliably (artifacts generated for all runs), but JSON/GraphQL success remained `0%`.
- Biggest improvement: Launcher stability and artifact completeness at scale (`10/10` runs complete with summary/csv/full artifacts).
- Biggest regression: No functional extraction gain (`targets_success_json` still `0/50`).

## KPI Table (Latest Launch Data)
Source launch: `artifacts/scraper_runs/parallel10_20260427-223635`

| KPI | Value | Calculation | Evidence |
|---|---:|---|---|
| Workers | 10 | from launch metadata | `launch_report.json` |
| Connections | 500 | from launch metadata | `launch_report.json` |
| Run completion rate | 100% | `10/10` runs exited | `launch_report.json` |
| Artifact completeness rate | 100% | `10/10` runs have `summary+csv+full` | `launch_report.json` |
| Targets attempted | 50 | `10 runs * 5 targets` | run summaries |
| JSON success rate | 0.00% | `targets_success_json=0 / 50` | run summaries |
| Unresolved rate | 100.00% | `targets_unresolved=50 / 50` | run summaries |
| L1 HTTP success rate | 40.00% | `l1_ok=20 / l1_total=50` | run summaries |
| HTTP 200 rate | 40.00% | `20 / 50 rows` | run CSVs |
| HTTP 404 rate | 60.00% | `30 / 50 rows` | run CSVs |
| Validation availability | Unavailable | field reports `validation_status=Unavailable` | run summaries |
| Timeout indicator | No timeout | `timed_out=false` | `launch_report.json` |

## Trend Line (Compared Launches)
Compared launches:
- `parallel10_20260427-223532` (`config_500_test.json`)
- `parallel10_20260427-223635` (`config_500_test2.json`) - latest

| Metric | 223532 | 223635 (latest) | Delta |
|---|---:|---:|---:|
| Workers | 10 | 10 | 0 |
| Connections | 500 | 500 | 0 |
| Runs completed | 10/10 | 10/10 | 0 |
| Artifact-complete runs | 10/10 | 10/10 | 0 |
| Targets attempted | 50 | 50 | 0 |
| JSON successes | 0 | 0 | 0 |
| JSON success rate | 0.00% | 0.00% | 0.00 pp |
| Unresolved targets | 50 | 50 | 0 |
| L1 HTTP 200 count | 20 | 20 | 0 |
| L1 HTTP 404 count | 30 | 30 | 0 |

Trend interpretation:
- Operational reliability at 500 connections is stable across both launches.
- Data extraction outcome is flat (no improvement): GraphQL endpoints still return non-JSON-success outcomes in this target set.

## Risks
1. `Functional risk`: sustained `0%` JSON success means benchmark currently validates launcher mechanics more than extraction capability.
2. `Benchmark quality risk`: all runs use a narrow 5-URL Apollo-focused set, so month-over-month signal may be biased and low-diversity.
3. `Metric coverage risk`: protocol KPIs like throughput/p95/rss are not yet emitted in current artifacts, blocking full gate evaluation.
4. `Endpoint drift risk`: high `404` share (60%) suggests stale or unsuitable target endpoints for GraphQL success goals.

## Next Actions
1. Add protocol-grade metrics output (`throughput`, `p50/p95`, memory telemetry) into per-run artifacts and monthly aggregation.
2. Implement manifest-driven target rotation from benchmark corpus categories (`static/dynamic/graphql/auth-wall/rate-limited`) and re-run April matrix.
3. Add GraphQL POST payload/auth-path tests so success metric is measured against reachable, valid operations.
4. Introduce per-target outcome taxonomy (`reachable`, `auth-required`, `not-found`, `schema-error`) to separate infra success from business-data success.
5. Re-baseline once diversified target set and telemetry are in place; then switch from `CALIBRATION` to pass/fail gating.

## Evidence Links
- Latest launch report: `artifacts/scraper_runs/parallel10_20260427-223635/launch_report.json`
- Prior compared launch report: `artifacts/scraper_runs/parallel10_20260427-223532/launch_report.json`
- Latest sample summary: `artifacts/scraper_runs/parallel10_20260427-223635/run_01/tallow_max_scraper_graphql_json_parallel_summary.txt`
- Latest sample CSV: `artifacts/scraper_runs/parallel10_20260427-223635/run_01/tallow_max_scraper_graphql_json_parallel.csv`
