# No-Regression Gate Thresholds (TSK-1206)

## Purpose
`scripts/no_regression_gate.ps1` blocks release promotion when benchmark quality regresses versus a baseline summary JSON.

The gate evaluates two required checks:
- success-rate regression
- unresolved-count regression

## Inputs
- Baseline summary JSON: `-BaselineSummaryPath`
- Current summary JSON: `-CurrentSummaryPath`

Supported summary fields are flexible. The script can read common variants including:
- success: `success_rate_pct`, `metrics.success_rate`, `targets_success_json`
- unresolved: `targets_unresolved`, `unresolved_count`, `unresolved`
- totals (for derived rates): `targets_total`, `total_targets`, `config.request_count`

## Threshold Parameters
- `-MaxSuccessRateDropPctPoints` (default: `1.0`)
- `-MaxUnresolvedIncreaseCount` (default: `0`)

Interpretation:
- Pass success gate when:
  - `baseline_success_rate_pct - current_success_rate_pct <= MaxSuccessRateDropPctPoints`
- Pass unresolved gate when:
  - `current_unresolved_count - baseline_unresolved_count <= MaxUnresolvedIncreaseCount`

Release gate fails if either condition is violated.

## Usage

### 1) Strict gate (no unresolved increase allowed)
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\no_regression_gate.ps1 `
  -BaselineSummaryPath .\artifacts\benchmarks\2026-03\stable\summary.json `
  -CurrentSummaryPath .\artifacts\benchmarks\2026-04\candidate\summary.json `
  -MaxSuccessRateDropPctPoints 1.0 `
  -MaxUnresolvedIncreaseCount 0 `
  -OutputJsonPath .\artifacts\benchmarks\2026-04\candidate\no_regression_gate.json
```

### 2) Looser unresolved allowance
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\no_regression_gate.ps1 `
  -BaselineSummaryPath .\baseline.json `
  -CurrentSummaryPath .\current.json `
  -MaxSuccessRateDropPctPoints 0.5 `
  -MaxUnresolvedIncreaseCount 3
```

## Exit Codes
- `0`: gate pass
- `1`: gate fail (regression over threshold)
- script error: invalid JSON, missing files, or missing required metrics

## Output
The script prints a JSON result to stdout and optionally writes it via `-OutputJsonPath`.

Result includes:
- `status` (`PASS`/`FAIL`)
- `thresholds`
- baseline/current resolved metrics
- deltas (`success_rate_drop_pct_points`, `unresolved_increase_count`)
- per-check pass/fail details
- `blocking_reasons`
