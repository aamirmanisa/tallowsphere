# Operator Checklist

> status: reviewed 2026-09-05 (C6 docs wave). Per the docs contract map this is a **legacy/local checklist** — the artifact-contract and run-metadata sections describe the April 2026 launcher-batch (`artifacts/scraper_runs/<batch>/run_*`) layout and are NOT reconciled with the Phase 2–11 manifest/request-plan/artifact-bundle gates. The "Pre-Run Checklist" Phase 1 Linux/CachyOS substrate items (doctor + smoke ladder) remain current. Use for legacy launch batches only.

Use this checklist for every scraper batch run. Check each box as completed.

## Run Metadata (fill before starting)
- [ ] Operator:
- [ ] Date/Time (local):
- [ ] Batch ID (example: `parallel10_ok_20260427-220243`):
- [ ] Script path:
- [ ] Binary path:

## Artifact Contract (must exist after run)
For batch root `artifacts/scraper_runs/<batch_id>/` the required artifacts are:
- [ ] `artifacts/scraper_runs/<batch_id>/launch_report.json`
- [ ] `artifacts/scraper_runs/<batch_id>/run_01/tallow_max_scraper_graphql_json_parallel.csv`
- [ ] `artifacts/scraper_runs/<batch_id>/run_01/tallow_max_scraper_graphql_json_parallel_full.json`
- [ ] `artifacts/scraper_runs/<batch_id>/run_01/tallow_max_scraper_graphql_json_parallel_summary.txt`
- [ ] Same 3 files exist for every run directory: `run_02` through `run_10`

## Pre-Run Checklist
- [ ] Confirm Linux/CachyOS Phase 1 runtime substrate is green before high-parallel scraper work:
  - `./target/debug/tallow doctor` passes.
  - `python3 scripts/phase1_smoke_ladder.py` passes, or the latest accepted report is attached.
  - Reports exist under `artifacts/doctor/` and `artifacts/phase1/`.
- [ ] Confirm binary is the validated Linux runtime (`~/Nixe/target/debug/tallow`) unless a newer runtime was explicitly certified.
- [ ] Confirm script exists and is readable (example: `scripts/tallow_max_scraper_graphql_json_parallel_v2.tl`).
- [ ] Confirm output batch directory does not already exist.
- [ ] Confirm write access to `artifacts/scraper_runs/`.
- [ ] Confirm target manifest/URL list is correct for this run.
- [ ] Confirm legal/compliance mode for target set (especially auth-protected endpoints).
- [ ] Run one smoke check before high parallel launch.
- [ ] Record planned parallelism and concurrency settings in run notes.

## In-Run Checks (every 5-10 minutes)
- [ ] Confirm all expected worker processes are alive.
- [ ] Confirm no immediate crash signatures in console output.
- [ ] Confirm host is not resource-saturated (CPU pinned + memory pressure + disk full).
- [ ] Confirm network path/proxy path is healthy (no widespread connect failures).
- [ ] Confirm run folders are being created under `artifacts/scraper_runs/<batch_id>/run_*`.
- [ ] Capture incident notes with timestamps for any retries, throttling, or auth blocks.

## Post-Run Validation
- [ ] `launch_report.json` exists and is valid JSON.
- [ ] In `launch_report.json`, each run has `has_exited=true`.
- [ ] In `launch_report.json`, each run has `summary_exists=true`, `csv_exists=true`, and `full_exists=true`.
- [ ] Each `run_XX` directory contains exactly these files:
  - `tallow_max_scraper_graphql_json_parallel.csv`
  - `tallow_max_scraper_graphql_json_parallel_full.json`
  - `tallow_max_scraper_graphql_json_parallel_summary.txt`
- [ ] Every `*_summary.txt` contains at minimum: `targets_total`, `targets_success_json`, `targets_unresolved`, `validation_status`.
- [ ] Every `*.csv` has expected header:
  - `wave,url,status,body_len,is_json,is_graphql,auth_blocked,rate_limited,retryable,error_kind`
- [ ] Every `*_full.json` contains at minimum: `captured_at`, `target_urls`, `rows`.
- [ ] Aggregate outcome is recorded (total targets, success_json, unresolved, dominant status codes).
- [ ] Run notes include final decision: pass / needs rerun / escalate.

## Escalation Triggers (page runtime owner immediately)
- [ ] Missing `launch_report.json` after run completion window.
- [ ] Any run missing one of the 3 required output files.
- [ ] Repeated runtime capability errors (example: `undefined function: http.batch`).
- [ ] More than 20% runs fail artifact checks.
- [ ] More than 50% of target URLs unresolved across the batch.
- [ ] Sustained `401/403` auth blocks on endpoints expected to return data.
- [ ] Sustained `429` rate limits or broad transport/TLS failures.
- [ ] Schema drift (missing required fields in CSV/full JSON/summary).
- [ ] Host instability (OOM, repeated process termination, disk exhaustion).

## Escalation Packet (attach before handoff)
- [ ] Batch ID and launch timestamp.
- [ ] `artifacts/scraper_runs/<batch_id>/launch_report.json`
- [ ] At least one failing run folder (`run_XX`) with all three artifacts.
- [ ] Error excerpts and exact timestamps.
- [ ] What was attempted (rerun, reduced parallelism, binary swap, proxy change).

## Quick Verification Commands (PowerShell)
```powershell
# 1) Validate launch report exists and inspect summary flags
$batch = "artifacts/scraper_runs/<batch_id>"
Get-Content "$batch/launch_report.json" | ConvertFrom-Json |
  Select-Object run,has_exited,summary_exists,csv_exists,full_exists

# 2) Ensure required files exist for run_01..run_10
1..10 | ForEach-Object {
  $r = "{0:D2}" -f $_
  $base = "$batch/run_$r"
  [PSCustomObject]@{
    run = $r
    csv = Test-Path "$base/tallow_max_scraper_graphql_json_parallel.csv"
    full = Test-Path "$base/tallow_max_scraper_graphql_json_parallel_full.json"
    summary = Test-Path "$base/tallow_max_scraper_graphql_json_parallel_summary.txt"
  }
}
```
