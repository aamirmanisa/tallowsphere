# Retry Budget Engine

> status: reviewed 2026-09-05 (C6 docs wave) — **legacy Windows-era spec (.ps1-only).** `scripts/retry_budget_engine.ps1` has no Linux-native equivalent; the real Rust retry machinery (`src/browser/retry_intelligence.rs`, ~1,956 LOC) is implemented but has zero production call sites (MASTER-GAPS B9, 2026-09-05) — do not cite this doc as current Linux behavior.

`scripts/retry_budget_engine.ps1` implements:

- `TSK-0404`: retry budget by domain and by error class.
- `TSK-0405`: exponential backoff with jitter for retryable failures.

The script reads existing run config/manifest JSON, computes a retry plan, and emits `tallow.retry.plan.v1` JSON that launcher/orchestration tools can consume.

## Supported Input Shapes

The script accepts `-ConfigPath` pointing to either:

1. A manifest-style config (`targets`, optional `retry`, optional `per_domain`).
2. A launch config produced by `prepare_tallow_run_config.ps1`:
   - If `manifest.source_path` exists, it loads that manifest.
   - Otherwise, it synthesizes policy from launch config defaults.

## Command

```powershell
.\scripts\retry_budget_engine.ps1 `
  -ConfigPath .\artifacts\scraper_runs\config_500.json `
  -OutputPlanPath .\artifacts\scraper_runs\config_500.retry_plan.json `
  -JitterRatio 0.20 `
  -BackoffFactor 2.0 `
  -BackoffBaseMs 500 `
  -BackoffCapMs 30000
```

Dry-run (validate/compute, no write):

```powershell
.\scripts\retry_budget_engine.ps1 `
  -ConfigPath .\artifacts\scraper_runs\config_500.json `
  -DryRun
```

## Output Contract

Top-level:

- `schema_version`: `tallow.retry.plan.v1`
- `generated_at_utc`
- `source`:
  - `config_path`
  - `config_sha256`
  - `source_kind` (`manifest`, `launch_config_with_manifest`, `synthetic_from_launch_config`)
  - `manifest_path` (if available)
- `engine.task_ids`: `["TSK-0404","TSK-0405"]`
- `defaults` (jitter/backoff controls)
- `summary` (target/domain counts, attempt range)
- `global_policy`
- `domains[]`
- `targets[]`
- `launcher_hints`

Per-domain policy object (`domains[].policy`):

- `max_attempts`
- `retry_budget_per_request` (computed as `max_attempts - 1`)
- `wave_concurrency`
- `retry_on_status`
- `retry_on_transport_errors`
- `backoff_source_ms` (configured seed delays)

Per-domain error-class budget (`domains[].error_class`):

- `retryable` map for:
  - `transport`
  - `timeout`
  - `rate_limited`
  - `server`
  - `auth`
  - `other`
- `budget_per_request` map for same classes.

Per-domain backoff schedule (`domains[].backoff_schedule[]`):

- `retry_number`
- `applies_to_attempt`
- `base_delay_ms`
- `jitter_window_ms`
- `jitter_ms`
- `delay_ms`
- `min_delay_ms`
- `max_delay_ms`

## Error-Class Mapping

Status/transport policy is mapped to classes as follows:

- `retry_on_transport_errors=true` -> `transport` retryable.
- `408` -> `timeout` retryable.
- `429` -> `rate_limited` retryable.
- `5xx` -> `server` retryable.
- `401/403` -> `auth` retryable only if explicitly listed in `retry_on_status`.
- Any other listed `retry_on_status` -> `other` retryable.

If explicit class budgets are not provided, each retryable class gets full per-request retry budget (`max_attempts - 1`) and non-retryable classes get `0`.

Optional explicit overrides are read from:

- `retry.retry_budget_by_error_class`
- `retry.budget_by_error_class`
- `retry.retry_budget`

Values are clamped to per-request retry budget.

## Backoff + Jitter Behavior

- If `retry.backoff_ms` is present, values seed initial retry delays.
- Missing later retries are extrapolated exponentially by `BackoffFactor`.
- If no `backoff_ms` is provided, schedule starts at `BackoffBaseMs` and grows exponentially.
- Delays are capped at `BackoffCapMs`.
- Jitter is deterministic per `(domain, attempt, config hash)` so plans are reproducible.
- Jitter window is `base_delay_ms * JitterRatio`.

## Launcher Integration

The plan includes:

- `launcher_hints.expected_env.TALLOW_RETRY_PLAN_PATH`

Current launcher can be run normally; orchestration tools can inject:

```powershell
$env:TALLOW_RETRY_PLAN_PATH = ".\artifacts\scraper_runs\config_500.retry_plan.json"
.\scripts\launch_tallow_parallel.ps1 -ConfigPath .\artifacts\scraper_runs\config_500.json
```

