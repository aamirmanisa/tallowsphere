# Goals and Constraints

## Scope
This document defines realistic operating goals, constraints, and non-goals for the Tallow scraper engine so execution stays measurable and technically credible.

## P0 KPIs (Must-Hit)

| KPI | Definition | P0 Target | Measurement Window |
|---|---|---|---|
| Success rate | % of target requests that return expected extractable payload (or validated fallback classification) | >= 92% on supported target set | Rolling 24h and per release benchmark run |
| End-to-end latency | Time from dispatch to normalized result for successful requests | p50 <= 2.0s, p95 <= 6.0s, p99 <= 12.0s | Per run + rolling 24h |
| Cost per 1k successful results | Total infra + proxy + captcha + compute cost divided by 1,000 successful results | <= $3.50 / 1k at P0 scale | Weekly blended cost report |
| Operator effort | Human intervention needed to keep pipelines healthy | <= 2 engineer-hours/day for triage + maintenance | Weekly ops log |

## Constraints

1. Reliability beats peak throughput for P0. Sustained predictable output is prioritized over benchmark spikes.
2. Compliance and target policy constraints are hard limits; no bypass objectives are permitted.
3. Concurrency must be bounded by adaptive backpressure and host capacity to avoid self-inflicted failure.
4. Browser-based fallback is allowed only when HTTP path fails and ROI remains within cost target.
5. Any optimization that regresses data quality or failure attribution is out of scope.

## Explicit Non-Goals

1. Not a goal to be universally faster than every competitor on every domain.
2. Not a goal to maximize raw requests per second at the expense of success rate and cost efficiency.
3. Not a goal to eliminate all operator work in P0.
4. Not a goal to guarantee zero failures; goal is controlled, classified, and recoverable failure.
5. Not a goal to beat local filesystem tools (for example, Robocopy) in their own problem domain; this project is network scraping, not file-copy acceleration.

## Realism Note: "10,000x Faster" and "<1MB RAM"

Claims of "10,000x faster" and total runtime memory "under 1MB" are not realistic for a modern distributed web scraping engine operating with TLS, parsing, retries, telemetry, and optional browser fallback.

Practical interpretation for planning:

- Optimize for meaningful throughput-per-dollar and success-per-core improvements against current baseline.
- Set bounded targets that can be validated under repeatable benchmark scenarios.
- Track regression budgets and stop shipping changes that only improve synthetic microbenchmarks.

## Memory Budget Targets

### Per Worker Budget (steady-state)

| Worker Type | Target RSS | Hard Ceiling | Notes |
|---|---|---|---|
| HTTP-only worker | 24-64 MB | 96 MB | Includes TLS/session pools, parser, and minimal telemetry |
| Hybrid worker (HTTP + limited JS eval) | 64-160 MB | 256 MB | For heavier parsing and anti-bot handling |
| Full browser fallback worker | 250-600 MB | 800 MB | Use sparingly; route only high-value failed cases |

### Host Tier Budgets

| Host Tier | Example Shape | Recommended Worker Mix | Total Memory Budget |
|---|---|---|---|
| Tier 1 (dev/small) | 4 vCPU / 8 GB RAM | 40-80 HTTP workers + small controller overhead | <= 6.5 GB working set |
| Tier 2 (standard) | 8 vCPU / 16 GB RAM | 120-220 HTTP workers + 4-8 hybrid workers | <= 13 GB working set |
| Tier 3 (throughput) | 16 vCPU / 32 GB RAM | 260-480 HTTP workers + 8-16 hybrid workers + capped browser pool | <= 26 GB working set |

## 500 Concurrent Connections Guardrails

For a 500-connection target, enforce:

1. Dynamic concurrency controller with per-host and global caps.
2. Memory-based throttling (reduce concurrency when host RSS > 85% of budget).
3. Queue backpressure and timeout circuit breakers.
4. Automatic degradation path (disable expensive fallbacks when cost/latency breach thresholds).
5. Benchmark sign-off only with both performance and success-rate gates passing.

## Exit Criteria for P0 Readiness

1. KPIs above met for 7 consecutive days on the supported target suite.
2. No SEV-1 incidents caused by concurrency or memory exhaustion during that period.
3. Cost per 1k remains within budget under weekday peak load.
4. Operator effort remains at or below target for two consecutive weekly reports.