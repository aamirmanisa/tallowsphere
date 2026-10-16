# CSV Column Normalization (`TSK-1005`)

`scripts/normalize_csv_columns.ps1` rewrites CSV output with deterministic column order while preserving row order and row values.

## Behavior

- Uses an expected header list as the canonical front of the CSV.
- Appends any extra/unexpected columns after canonical headers.
- Sorts extra columns with ordinal sort for deterministic output.
- Preserves row order exactly as read.
- Rewrites in place by default.

## Parameters

- `-InputPath` (required): CSV file path, or directory containing CSV files.
- `-ExpectedHeaders` (optional): Canonical header order. Defaults to:
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
- `-OutputPath` (optional): Output file path for single-file input only.
- `-Recurse` (optional): When `-InputPath` is a directory, include subdirectories.

## Usage

Normalize one file in place:

```powershell
.\scripts\normalize_csv_columns.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260427-223635\run_01\tallow_max_scraper_graphql_json_parallel.csv
```

Normalize one file to a new path:

```powershell
.\scripts\normalize_csv_columns.ps1 `
  -InputPath .\run.csv `
  -OutputPath .\run.normalized.csv
```

Normalize all CSV files under a launch directory:

```powershell
.\scripts\normalize_csv_columns.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260427-223635 `
  -Recurse
```

Normalize with explicit header list:

```powershell
.\scripts\normalize_csv_columns.ps1 `
  -InputPath .\run.csv `
  -ExpectedHeaders wave,url,status,body_len,is_json,is_graphql,auth_blocked,rate_limited,retryable,error_kind
```

## Output

The script emits a JSON summary to stdout with:

- `normalized_at_utc`
- `files_total`
- `files[]` entries containing:
  - `csv_path`
  - `output_path`
  - `rows`
  - `expected_headers`
  - `output_headers`
