# NDJSON Export (`TSK-1003`)

> status: reviewed 2026-09-05 (C6 docs wave) — **legacy Windows-era doc: the only NDJSON exporter is `scripts/export_run_ndjson.ps1` (no Linux twin).** The Phase 7 Linux artifact path is `scripts/package_artifact_bundle.py` + `scripts/extract_run_metrics.py` over request-plan reports; map caution "confirm export output matches artifact bundle expectations" is still open. Do not treat as a current Linux gate.

Status: implemented.

## Purpose

`scripts/export_run_ndjson.ps1` converts run `*_full.json` artifacts into newline-delimited JSON (NDJSON) with deterministic row ordering.

Deterministic behavior:

- Input run files are resolved in stable order.
- If a launch folder has `launch_report.json`, its `runs[]` ordering is used first.
- Remaining files are added in lexicographic path order.
- Rows inside each run are emitted by `source_row_index` ascending (original row order).

## Script

- Path: `scripts/export_run_ndjson.ps1`
- Input: one `*_full.json` file or a launch directory containing run folders.
- Default file pattern: `*_full.json`

## Output Modes

Two output modes are supported:

- Per-run NDJSON (`-PerRun`)
- Combined NDJSON (`-Combined`)

If no mode switch is provided, both are exported.

## Output Schema

Each NDJSON line is a single flattened row with stable key order:

- `schema_version` (`tallow.ndjson.row.v1`)
- `exported_at_utc`
- `launch_id`
- `run_id`
- `run_index`
- `full_json_path`
- `full_json_sha256`
- `captured_at`
- `target_count`
- `source_row_index`
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
- `l1_concurrency`
- `l2_concurrency`
- `l3_concurrency`

## Usage

Export both per-run and combined NDJSON from a launch directory:

```powershell
.\scripts\export_run_ndjson.ps1 `
  -InputPath "artifacts\scraper_runs\parallel10_20260427-223635"
```

Export per-run only (writes `*.ndjson` next to each `*_full.json`):

```powershell
.\scripts\export_run_ndjson.ps1 `
  -InputPath "artifacts\scraper_runs\parallel10_20260427-223635" `
  -PerRun
```

Export combined only with explicit path:

```powershell
.\scripts\export_run_ndjson.ps1 `
  -InputPath "artifacts\scraper_runs\parallel10_20260427-223635" `
  -Combined `
  -CombinedOutputPath "artifacts\scraper_runs\parallel10_20260427-223635\all_runs.ndjson"
```

Export per-run into a separate output root:

```powershell
.\scripts\export_run_ndjson.ps1 `
  -InputPath "artifacts\scraper_runs\parallel10_20260427-223635" `
  -PerRun `
  -PerRunOutputDir "artifacts\scraper_runs\parallel10_20260427-223635\ndjson"
```

Process one specific full JSON file:

```powershell
.\scripts\export_run_ndjson.ps1 `
  -InputPath "artifacts\scraper_runs\parallel10_20260427-223635\run_01\tallow_max_scraper_graphql_json_parallel_full.json" `
  -Combined
```

Overwrite existing outputs:

```powershell
.\scripts\export_run_ndjson.ps1 `
  -InputPath "artifacts\scraper_runs\parallel10_20260427-223635" `
  -Force
```

## Notes

- NDJSON files are written UTF-8 without BOM.
- Existing outputs are protected by default; pass `-Force` to overwrite.
- The script prints a JSON summary to stdout with files processed and rows written.
