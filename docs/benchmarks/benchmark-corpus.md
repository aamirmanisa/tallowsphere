# Benchmark Corpus Specification

## Purpose
Define a repeatable benchmark corpus for measuring scraper reliability, latency, retry behavior, and unit economics across target difficulty classes.

## Target Difficulty Classes
| Class | Definition | Typical Site Traits | Expected Scraper Behavior |
|---|---|---|---|
| Easy | Low-friction public pages with stable HTML and minimal bot defenses. | Static HTML, predictable paths, no JS requirement, permissive rate limits. | Near-max success with low retries and low variance latency. |
| Medium | Moderately protected targets requiring headers/session handling and occasional JS rendering. | Dynamic endpoints, occasional WAF checks, inconsistent markup, soft throttling. | High success with controlled retries; moderate p95 latency spread. |
| Hard | High-friction targets with strong anti-bot controls and frequent structure/flow changes. | Aggressive WAF/challenges, auth walls, rotating fingerprints, strict per-IP limits. | Lower success ceiling, higher retries, and higher p95 latency/cost unless specialized bypass is used. |

## Dataset Size Tiers
| Tier | Easy Targets | Medium Targets | Hard Targets | Total Targets | Intended Use |
|---|---:|---:|---:|---:|---|
| Smoke | 10 | 5 | 2 | 17 | Fast validation of regressions after code/config changes. |
| Standard | 40 | 25 | 10 | 75 | Daily health/performance tracking and tuning. |
| Full | 120 | 80 | 40 | 240 | Weekly release-gate benchmark and major architecture comparison. |

## Run Cadence
| Tier | Cadence | Trigger |
|---|---|---|
| Smoke | Every commit/PR | CI and pre-merge checks |
| Standard | Daily | Scheduled run (off-peak + peak windows) |
| Full | Weekly and before release | Release candidate and major infra/proxy/runtime changes |

## Required Metrics and Result Columns
Minimum columns for each benchmark result row:

| Column | Type | Description |
|---|---|---|
| `run_id` | string | Unique benchmark run identifier. |
| `timestamp_utc` | datetime | Run start time in UTC. |
| `tier` | enum | `smoke`, `standard`, `full`. |
| `target_class` | enum | `easy`, `medium`, `hard`. |
| `target_id` | string | Stable ID for benchmark target. |
| `attempts_total` | integer | Total attempts sent. |
| `success_count` | integer | Successful responses matching validation criteria. |
| `success_rate` | float | `success_count / attempts_total`. |
| `p50_latency_ms` | number | 50th percentile end-to-end latency in ms. |
| `p95_latency_ms` | number | 95th percentile end-to-end latency in ms. |
| `retries_total` | integer | Total retries issued for this target/run. |
| `retries_per_success` | float | `retries_total / max(success_count, 1)`. |
| `cost_total_usd` | number | Total run cost attributed to this target. |
| `cost_per_1k_success_usd` | number | `(cost_total_usd / max(success_count,1)) * 1000`. |

Recommended aggregate rollups:
- By tier
- By target class
- By provider/strategy (if multiple proxy/unblock paths are tested)

## Legal and Compliance Requirements for Target Selection
Only include targets that pass legal/compliance review. At minimum:
- Respect each target's Terms of Service, robots directives, and applicable contractual restrictions.
- Do not include targets requiring unauthorized access, credential sharing, paywall bypass, or technical circumvention of explicit access controls.
- Do not benchmark against personal/sensitive data flows; avoid collecting or storing personal data unless approved under documented lawful basis and data-handling policy.
- Keep a target allowlist with owner, purpose, legal basis, and review date; remove targets immediately if terms/policies change.

