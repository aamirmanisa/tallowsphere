# Failure Replay Tool

`TSK-1105` operator tool for replaying failed requests from saved run metadata.

Scripts:

- Linux/CachyOS local proof path: `scripts/replay_failed_requests.py`
- Legacy PowerShell operator tool: `scripts/replay_failed_requests.ps1`

Phase 7 status: the Linux-native tool defaults to dry-run candidate reporting and refuses live replay without a future explicit human gate. This is local replay planning only; it is not production incident automation.

## What It Does

1. Reads run artifacts from a launch directory, run directory, `launch_report.json`, `*_full.json`, or `*.csv`.
2. Selects only rows where `retryable=1`.
3. Replays those requests with saved request metadata when available:
   - URL
   - method (`request_method`/`method`/`http_method` when present; defaults to `GET`)
   - request body (`request_body`/`request_payload`/`payload`/`graphql_payload` when present)
   - headers from `*_full.json` top-level `headers` block
4. Writes `failure_replay_report.json` with per-request replay outcomes and aggregate counters.

If both CSV and full JSON contain the same failed row, full JSON metadata is preferred.

## Linux/CachyOS Phase 7 usage

Dry-run candidate selection from a local request-plan execution report; no network I/O is performed:

```bash
python3 scripts/replay_failed_requests.py \
  --execution-report artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/execution_report.json \
  --report-path artifacts/phase7/local-artifacts-replay-observability/failure_replay_report.json
```

Phase 7 proof output:

- `artifacts/phase7/local-artifacts-replay-observability/failure_replay_report.json`
- `schema_version`: `tallow.failure_replay.v1`
- `dry_run`: `true`
- `non_claims.no_network_io_performed`: `true`

`--execute --network-scope live` intentionally exits `2` with `live replay requires explicit human approval...`.

## Legacy PowerShell usage

Run from repo root when PowerShell is available:

Non-dry-run PowerShell replay is a human-gated operation for the active Linux/CachyOS Phase Autopilot. Prefer `-DryRun` unless the operator explicitly approves live replay.

Dry-run candidate selection only (no network replay):

```powershell
.\scripts\replay_failed_requests.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260427-223954 `
  -DryRun
```

Custom report output path:

```powershell
.\scripts\replay_failed_requests.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260427-223954 `
  -ReportPath .\artifacts\scraper_runs\parallel10_20260427-223954\replay\failure_replay_report.json
```

## Parameters

- `InputPath` (required): launch dir, run dir, `launch_report.json`, `*_full.json`, or `*.csv`.
- `ReportPath` (optional): output JSON path. Default: `<input_dir>\failure_replay_report.json`.
- `TimeoutSec` (default `30`): request timeout per replay.
- `MaximumRedirection` (default `5`): redirect cap.
- `MaxReplay` (default `1000000`): max replay attempts after filtering/deduping.
- `BodySnippetChars` (default `512`): max characters kept for response snippet in report.
- `DryRun`: build candidate list and report without replaying network calls.

## Report Output

Top-level report fields:

- `schema_version`
- `generated_at_utc`
- `input_path`
- `dry_run`
- `timeout_sec`
- `maximum_redirection`
- `max_replay`
- `body_snippet_chars`
- `counts`
- `runs`
- `replay_items`

`counts` includes:

- `runs_scanned`
- `candidates_total`
- `replay_attempted`
- `replay_success_status`
- `replay_transport_error`
- `replay_still_retryable`
- `replay_resolved`

Each `replay_items[]` row includes:

- source metadata (`run_id`, `wave`, `url`, `source`, `source_row_index`)
- original status/classification (`original_status`, `original_error_kind`, `original_retryable`)
- replay result (`replay_status`, `replay_error_kind`, `replay_retryable`, `resolved`)
- timings/body diagnostics (`replay_duration_ms`, `replay_body_len`, `replay_body_snippet`)
- `response_headers`
- `replay_error` (exception message when request fails)

## Notes

- The script only replays rows marked retryable in artifacts.
- For PowerShell 5.1 safety, restricted headers are filtered from `-Headers`; `User-Agent` is applied via the dedicated parameter.
- This tool is for operational triage and replay validation, not for bypassing auth or policy controls.
