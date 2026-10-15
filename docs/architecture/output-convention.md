# Output Convention

> status: reviewed 2026-09-05 (C6 docs wave). Still the canonical contract for the launcher-era batch layout it describes; the Phase 10 official artifact names (`config.json`, `summary.json`, `kpi.csv`, `errors.csv`, `raw.jsonl`, `system-metrics.json`, per `docs/benchmarks/benchmark-protocol.md`) supersede it for new fixture/benchmark runs. Map caution "naming appears stricter in validator script than in docs" remains open.

Status: Canonical specification for scraper launch output (`v1.0.0`).

## Scope

This document defines the canonical on-disk layout, naming rules, and artifact expectations for parallel scraper launches.

## Canonical Launch Folder

Each launch must create exactly one folder under:

`artifacts/scraper_runs/`

Launch folder naming pattern:

`<launch_id> = <profile>_<timestamp>`

- `<profile>`: lowercase `[a-z0-9_]+` (example: `parallel10_ok`, `benchmark500_http`).
- `<timestamp>`: `YYYYMMDD-HHMMSS` (host local clock for compatibility).
- Authoritative timing must be stored in ISO-8601 UTC fields in JSON metadata.

Example launch IDs:

- `parallel10_ok_20260427-220243`
- `benchmark500_http_20260428-091500`

## Canonical Tree

```text
artifacts/
  scraper_runs/
    <launch_id>/
      launch_report.json
      launch_stdout.log                       # optional
      launch_stderr.log                       # optional
      run_01/
        stdout.log
        stderr.log
        <pipeline_slug>.csv
        <pipeline_slug>_summary.txt
        <pipeline_slug>_full.json
        artifact_manifest.json
      run_02/
        ...
```

Run directory naming pattern:

- `run_<NN>` where `NN` is zero-padded integer (`01`, `02`, ...).
- Regex: `^run_[0-9]{2,}$`

## Canonical Artifact Names

For pipeline slug `tallow_max_scraper_graphql_json_parallel`:

- `tallow_max_scraper_graphql_json_parallel.csv`
- `tallow_max_scraper_graphql_json_parallel_summary.txt`
- `tallow_max_scraper_graphql_json_parallel_full.json`

`stdout.log` and `stderr.log` are mandatory run logs.

`artifact_manifest.json` is mandatory and must include file metadata (paths, sizes, hashes, timestamps, existence flags).

## Required Metadata

Launch-level metadata must include:

- `schema_version`
- `launch_id`
- `script_path`
- `tallow_bin_path`
- `started_at` (UTC ISO-8601)
- `finished_at` (UTC ISO-8601)
- `duration_ms`
- `parallel_requested`
- `runs_total`

Run-level metadata must include:

- `run` (1-based index)
- `run_id` (example: `run_01`)
- `run_dir`
- `pid` (nullable)
- `has_exited`
- `exit_code` (nullable)
- `started_at` (UTC ISO-8601)
- `finished_at` (UTC ISO-8601)
- `duration_ms`
- `status` (`success | partial | failed`)
- `summary_exists`
- `csv_exists`
- `full_exists`
- `stdout_exists`
- `stderr_exists`
- `artifact_manifest_exists`

## Portability Rules

- Store relative artifact paths in JSON when possible.
- If absolute paths are included, they must be Windows-normalized (`E:\\...`) and accompanied by relative path fields.
- Use UTF-8 without BOM for all text and JSON artifacts.

## Minimal Sample (Run Artifact Manifest)

```json
{
  "schema_version": "1.0.0",
  "launch_id": "parallel10_ok_20260427-220243",
  "run": 1,
  "run_id": "run_01",
  "pipeline_slug": "tallow_max_scraper_graphql_json_parallel",
  "started_at": "2026-04-28T03:02:43Z",
  "finished_at": "2026-04-28T03:02:44Z",
  "duration_ms": 1302,
  "status": "partial",
  "artifacts": {
    "csv": {
      "path": "run_01/tallow_max_scraper_graphql_json_parallel.csv",
      "exists": true,
      "size_bytes": 371,
      "sha256": "6f24cdbb..."
    },
    "full_json": {
      "path": "run_01/tallow_max_scraper_graphql_json_parallel_full.json",
      "exists": true,
      "size_bytes": 592995,
      "sha256": "0a9f2e9d..."
    }
  }
}
```
