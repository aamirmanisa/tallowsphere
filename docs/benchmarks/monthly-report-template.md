# Monthly Benchmark Report Template

## Metadata
- Report month: `YYYY-MM`
- Protocol version: `x.y`
- Manifest version: `vN-targets`
- Baseline report used: `[YYYY-MM stable]`
- Owner: `<name>`
- Generated at (UTC): `<timestamp>`

## Executive Summary
- Overall status: `PASS | FAIL | CALIBRATION`
- Primary finding (1 line): `<text>`
- Biggest improvement: `<metric + delta>`
- Biggest regression: `<metric + delta>`

## Test Matrix Coverage
| Dimension | Planned | Executed | Missing | Notes |
|---|---:|---:|---:|---|
| Concurrency levels (50/100/250/500) | 4 |  |  |  |
| Time windows (A/B) | 2 |  |  |  |
| Repetitions per cell (3) | 3 |  |  |  |
| Total runs | 24 |  |  |  |

## KPI Summary (All Runs)
| KPI | Baseline | Current | Delta | Gate | Status |
|---|---:|---:|---:|---|---|
| Throughput (req/s) |  |  |  | >= -10% |  |
| P50 latency (ms) |  |  |  | Informational |  |
| P95 latency (ms) |  |  |  | <= +15% |  |
| Success rate (%) |  |  |  | >= -1.0 pp |  |
| Validation pass rate (%) |  |  |  | >= -0.5 pp |  |
| Timeout+5xx+429 rate (%) |  |  |  | <= +20% rel |  |
| RSS peak (MB) |  |  |  | <= ceiling |  |
| Throughput CV (stability) |  |  |  | <= 0.12 |  |

## KPI by Concurrency
| Concurrency | Throughput Baseline | Throughput Current | Delta | P95 Baseline | P95 Current | Success Rate Current | Gate Status |
|---:|---:|---:|---:|---:|---:|---:|---|
| 50 |  |  |  |  |  |  |  |
| 100 |  |  |  |  |  |  |  |
| 250 |  |  |  |  |  |  |  |
| 500 |  |  |  |  |  |  |  |

## KPI by Time Window
| Window | Throughput (req/s) | P95 (ms) | Success Rate (%) | Validation Pass (%) | Notes |
|---|---:|---:|---:|---:|---|
| A (09:00-11:00 CT) |  |  |  |  |  |
| B (21:00-23:00 CT) |  |  |  |  |  |

## Regression Gate Results
| Gate | Threshold | Result | Pass/Fail | Evidence |
|---|---|---|---|---|
| Throughput | decrease <= 10% |  |  | `summary.json` |
| P95 latency | increase <= 15% |  |  | `kpi.csv` |
| Success rate | drop <= 1.0 pp |  |  | `kpi.csv` |
| Validation pass | drop <= 0.5 pp |  |  | `kpi.csv` |
| Error budget | increase <= 20% rel |  |  | `errors.csv` |
| RSS ceiling | <= approved ceiling |  |  | `system-metrics.json` |
| Stability CV | <= 0.12 |  |  | repetition stats |

## Error Breakdown
| Error Class | Count | Rate (%) | Baseline Rate (%) | Delta | Comment |
|---|---:|---:|---:|---:|---|
| timeout |  |  |  |  |  |
| http_429 |  |  |  |  |  |
| http_5xx |  |  |  |  |  |
| http_4xx_non_retryable |  |  |  |  |  |
| validation |  |  |  |  |  |
| other |  |  |  |  |  |

## Resource Usage
| Metric | Baseline | Current | Delta | Status |
|---|---:|---:|---:|---|
| RSS peak (MB) |  |  |  |  |
| RSS p95 (MB) |  |  |  |  |
| CPU sec / 1000 successes |  |  |  |  |
| Network egress (GB) |  |  |  |  |

## Target-Class Performance
| Target Class | Requests | Success Rate (%) | P95 (ms) | Validation Pass (%) | Top Failure Mode |
|---|---:|---:|---:|---:|---|
| static |  |  |  |  |  |
| dynamic |  |  |  |  |  |
| graphql |  |  |  |  |  |
| auth-wall |  |  |  |  |  |
| rate-limited |  |  |  |  |  |

## Incidents / Anomalies
| ID | Date | Description | Impact | Mitigation | Follow-up Owner |
|---|---|---|---|---|---|
|  |  |  |  |  |  |

## Decisions
- Release gate decision: `APPROVE | BLOCK | CONDITIONAL`
- Rationale:
  - `<bullet 1>`
  - `<bullet 2>`

## Action Items
| Priority | Action | Owner | Due Date | Tracking ID |
|---|---|---|---|---|
| P0 |  |  |  |  |
| P1 |  |  |  |  |
| P2 |  |  |  |  |

## Evidence Links
- Raw artifacts root: `artifacts/benchmarks/YYYY-MM/`
- Run summaries: `<path list>`
- Dashboard snapshot: `<url/path>`
- Commit SHA: `<sha>`
- Runtime binary version: `<version>`

