# Alerting Thresholds

> status: reviewed 2026-09-05 (C6 docs wave) — **legacy Windows-era spec (TSK-1104, `.ps1`-only).** `scripts/alert_success_drop.ps1` has no Linux-native equivalent; Phase 6/7 local metrics (Python) do not implement alerting. Do not treat this as a current Linux/CachyOS gate.

`TSK-1104` alerting is implemented in `scripts/alert_success_drop.ps1`.

This script evaluates run metrics JSON and emits an alert JSON payload. It exits:

- `0` when no alert criteria are met
- `1` when one or more alert criteria are met

## Inputs

- Required:
  - `-CurrentMetricsPath` path to `run_metrics.json` (from `scripts/extract_run_metrics.ps1`)
- Optional:
  - `-BaselineMetricsPath` second metrics JSON for delta-based checks
  - `-OutputJsonPath` alert output path (default: sibling `alert_success_drop.json`)

## Alert Checks

1. Success-rate below floor (absolute):
   - `current.success_rate_pct < MinCurrentSuccessRatePct`
2. Success-rate drop (baseline delta):
   - `(baseline.success_rate_pct - current.success_rate_pct) > MaxSuccessRateDropPctPoints`
3. Block/challenge rate too high (absolute):
   - `current.block_challenge_rate_pct > MaxBlockChallengeRatePct`
4. Block/challenge spike (baseline delta):
   - `(current.block_challenge_rate_pct - baseline.block_challenge_rate_pct) > MaxBlockChallengeSpikePctPoints`

## Default Thresholds

- `MaxSuccessRateDropPctPoints = 2.0`
- `MinCurrentSuccessRatePct = 0.0`
- `MaxBlockChallengeRatePct = 10.0`
- `MaxBlockChallengeSpikePctPoints = 3.0`

## Block/Challenge Classification

The script computes block/challenge counts from `runs[].error_kinds` and matches keys by case-insensitive substring against:

- `401`, `403`, `429`
- `block`, `blocked`
- `challenge`, `captcha`
- `forbidden`, `unauthorized`
- `rate_limit`, `ratelimit`
- `waf`, `cf_`, `cloudflare`

Override with `-BlockChallengePattern`.

## Usage

Baseline + current (recommended):

```powershell
.\scripts\alert_success_drop.ps1 `
  -BaselineMetricsPath .\artifacts\scraper_runs\baseline\run_metrics.json `
  -CurrentMetricsPath .\artifacts\scraper_runs\candidate\run_metrics.json `
  -MaxSuccessRateDropPctPoints 1.0 `
  -MaxBlockChallengeSpikePctPoints 2.0 `
  -MaxBlockChallengeRatePct 8.0 `
  -OutputJsonPath .\artifacts\scraper_runs\candidate\alert_success_drop.json
```

Current-only (absolute checks only):

```powershell
.\scripts\alert_success_drop.ps1 `
  -CurrentMetricsPath .\artifacts\scraper_runs\candidate\run_metrics.json `
  -MinCurrentSuccessRatePct 92.0 `
  -MaxBlockChallengeRatePct 5.0
```

## Output JSON

The alert file includes:

- `status` (`OK` or `ALERT`)
- `alert` (`true/false`)
- `thresholds`
- `current` snapshot metrics
- optional `baseline` snapshot metrics
- `deltas`
- `alerts[]` with machine-readable alert codes and thresholds

## Suggested Starting Values

For tighter production gating:

- `MinCurrentSuccessRatePct = 90.0`
- `MaxSuccessRateDropPctPoints = 1.0`
- `MaxBlockChallengeRatePct = 5.0`
- `MaxBlockChallengeSpikePctPoints = 1.5`

Tune by target class and provider mix after collecting at least 2-4 weeks of baseline data.
