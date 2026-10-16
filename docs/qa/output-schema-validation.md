# Output Schema Validation

Status: Implements partial coverage for `TSK-0901` and `TSK-1005`.

## Scope

`scripts/validate_output_schema.ps1` validates run artifacts for:

- deterministic CSV header ordering (`TSK-1005` partial),
- required keys in each `full.json` row (`TSK-0901` partial),
- machine-readable pass/fail report JSON.

Current checks are structural only for the older fetch/probe `full.json` row shape. Value typing/coercion, anomaly scoring, and quarantine workflows are out of scope for this PowerShell structural validator.

Phase 5 schema-defined extraction rows are covered separately by `schemas/tallow/extraction-row.schema.json` and the Linux-native `scripts/validate_extraction_rows.py` proof under `artifacts/phase5/extraction_rows/`.

## Script

Path: `scripts/validate_output_schema.ps1`

Required input:

- `-InputPath` can point to:
  - a launch folder containing `run_*` directories, or
  - a single `run_*` directory.

Optional input:

- `-ReportPath` to override output path.
- `-ExpectedCsvHeaders` to override canonical header order.
- `-RequiredFullJsonRowKeys` to override required per-row JSON keys.

## Canonical Defaults

Default expected CSV headers (exact order):

1. `wave`
2. `url`
3. `status`
4. `body_len`
5. `is_json`
6. `is_graphql`
7. `auth_blocked`
8. `rate_limited`
9. `retryable`
10. `error_kind`

Default required keys in each full JSON row:

1. `wave`
2. `url`
3. `status`
4. `body`
5. `body_len`
6. `is_json`
7. `is_graphql`
8. `auth_blocked`
9. `rate_limited`
10. `retryable`
11. `error_kind`

## Usage

Validate entire launch:

```powershell
.\scripts\validate_output_schema.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260427-223635
```

Validate single run:

```powershell
.\scripts\validate_output_schema.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260427-223635\run_01
```

Write report to explicit path:

```powershell
.\scripts\validate_output_schema.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260427-223635 `
  -ReportPath .\artifacts\scraper_runs\parallel10_20260427-223635\qa\output_schema_validation_report.json
```

## Report JSON

The validator writes JSON with:

- top-level `passed` boolean,
- aggregate run counts (`runs_total`, `runs_passed`, `runs_failed`),
- per-run details including:
  - `csv_header_valid`,
  - `csv_header_mismatches`,
  - `full_json_required_keys_valid`,
  - `full_json_key_violations`,
  - `errors`,
  - `passed`.

Default report location when `-ReportPath` is omitted:

- `<InputPath>\output_schema_validation_report.json`
