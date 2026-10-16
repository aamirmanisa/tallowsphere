# Full JSON Schema

Status: Canonical full-run schema for `<pipeline>_full.json` (`schema_version=1.0.0`).

## File Location

- Schema file: `schemas/tallow/full-run.schema.json`
- Artifact file: `<launch_dir>/<run_id>/<pipeline_slug>_full.json`

## Purpose

This schema standardizes the full run artifact so downstream tooling can parse runs consistently across waves (`L1/L2/L3`) and error classes.

It is aligned to the current runtime shape:

- `captured_at`
- `target_urls`
- `headers`
- `l1_concurrency`, `l2_concurrency`, `l3_concurrency`
- `rows[]` with per-request diagnostics

And it adds one required field for schema stability:

- `schema_version` (`"1.0.0"`)

## Required Top-Level Keys

- `schema_version`
- `captured_at`
- `target_urls`
- `headers`
- `l1_concurrency`
- `l2_concurrency`
- `l3_concurrency`
- `rows`

## Required `rows[]` Keys

- `wave`
- `url`
- `status`
- `body`
- `body_len`
- `is_json`
- `is_graphql`
- `auth_blocked`
- `rate_limited`
- `retryable`
- `error_kind`

## Notes

- `status` is integer HTTP status, with `0` reserved for transport failures.
- Flag fields currently use `"0"`/`"1"` strings; schema also permits boolean flags for forward compatibility.
- `error_kind` is constrained to:
  - `none`
  - `transport`
  - `server`
  - `rate_limited`
  - `auth`
  - `other`

## Validation Commands

### 1) Validate a canonical v1 artifact (AJV CLI)

```powershell
npx ajv-cli validate --spec=draft2020 `
  -s schemas/tallow/full-run.schema.json `
  -d artifacts/scraper_runs/<launch_id>/run_01/<pipeline_slug>_full.json
```

### 2) Validate a legacy artifact missing `schema_version`

```powershell
$src = "artifacts/scraper_runs/<launch_id>/run_01/<pipeline_slug>_full.json"
$tmp = Join-Path $env:TEMP "tallow-full-v1.json"

$j = Get-Content $src -Raw | ConvertFrom-Json
if (-not $j.PSObject.Properties.Name.Contains("schema_version")) {
  $j | Add-Member -NotePropertyName schema_version -NotePropertyValue "1.0.0"
}
$j | ConvertTo-Json -Depth 100 | Set-Content -Path $tmp -Encoding utf8

npx ajv-cli validate --spec=draft2020 `
  -s schemas/tallow/full-run.schema.json `
  -d $tmp
```
