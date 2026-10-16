# Launch Report Schema

Status: Canonical launch report schema (`v1.0.0`).

## Phase 6 scheduler report relationship

The fixed launcher schema in this document remains the canonical target for `launch_report.json`
producer/consumer migration. Phase 6 does not claim that the legacy PowerShell launcher already emits
this full shape.

The Linux/CachyOS Phase 6 scheduler proof emits separate queue-native contracts:

- `tallow.queue.scheduler_state.v1` at `artifacts/phase6/*/queue_state.json`
- `tallow.queue.scheduler_run_report.v1` at `artifacts/phase6/*/queue_run_report.json`
- `tallow.artifact_manifest.v1` at `artifacts/phase6/*/artifact_manifest.json`
- `tallow.queue.dead_letter.v1` rows in `dead_letter.jsonl`
- `tallow.queue.blocked_target.v1` rows in `blocked_targets.jsonl`

Those scheduler reports link to local/mock proof artifacts and preserve the Phase 6 boundary: no live
external scraping, no vault/secrets, no destructive purge, no deploy/release, no benchmark claim, and no
Windows support. If a future phase makes the adaptive scheduler launch real workers, that phase should
either emit this `launch_report.json` shape for worker launches or provide a tested adapter from legacy
launcher reports into the canonical fields below.

## File Location

- Launch report file: `<launch_dir>/launch_report.json`
- Per-run artifact metadata file: `<launch_dir>/<run_id>/artifact_manifest.json`

## Canonical `launch_report.json` Shape

```json
{
  "schema_version": "1.0.0",
  "launch_id": "parallel10_ok_20260427-220243",
  "script_path": "scripts/tallow_max_scraper_graphql_json_parallel_v2.tl",
  "script_sha256": "08a9...",
  "tallow_bin_path": "/mnt/Personal/Nixe\\.tallow-bin\\tallow.exe",
  "binary_sha256": "81b7...",
  "binary_version": {
    "ok": true,
    "exit_code": 0,
    "text": "tallow 0.1.0",
    "error": ""
  },
  "config_sha256": "902f...",
  "launcher_working_directory": "/mnt/Personal/Nixe",
  "command": "tallow run scripts/tallow_max_scraper_graphql_json_parallel_v2.tl",
  "workspace_root": "/mnt/Personal/Nixe",
  "started_at": "2026-04-28T03:02:43Z",
  "finished_at": "2026-04-28T03:02:44Z",
  "duration_ms": 1102,
  "parallel_requested": 10,
  "runs_total": 10,
  "runs": [
    {
      "run": 1,
      "run_id": "run_01",
      "pid": 23104,
      "has_exited": true,
      "exit_code": null,
      "run_dir": "/mnt/Personal/Nixe\\artifacts\\scraper_runs\\parallel10_ok_20260427-220243\\run_01",
      "started_at": "2026-04-28T03:02:43Z",
      "finished_at": "2026-04-28T03:02:44Z",
      "duration_ms": 1302,
      "status": "partial",
      "summary_exists": true,
      "csv_exists": true,
      "full_exists": true,
      "stdout_exists": true,
      "stderr_exists": true,
      "artifact_manifest_exists": true
    }
  ],
  "aggregate": {
    "runs_success": 0,
    "runs_partial": 10,
    "runs_failed": 0,
    "targets_total": 50,
    "targets_success_json": 0,
    "targets_unresolved": 50,
    "http_status_counts": {
      "200": 20,
      "404": 30
    }
  }
}
```

## Required Launch Fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | string | yes | Semver-like (`1.0.0`) |
| `launch_id` | string | yes | Must match folder name |
| `script_path` | string | yes | Relative path preferred |
| `tallow_bin_path` | string | yes | Runtime executable path |
| `binary_sha256` | string or null | yes | SHA-256 of runtime executable when readable |
| `binary_version` | object | yes | Non-fatal preflight probe result for `tallow --version` |
| `script_sha256` | string or null | yes | SHA-256 of launch script when readable |
| `config_sha256` | string or null | yes | SHA-256 of launch config file bytes, distinct from effective `config_hash` |
| `launcher_working_directory` | string | yes | Directory from which the launcher was invoked |
| `command` | string | yes | Full command used |
| `workspace_root` | string | yes | Root working directory |
| `started_at` | string | yes | UTC ISO-8601 |
| `finished_at` | string | yes | UTC ISO-8601 |
| `duration_ms` | integer | yes | Non-negative |
| `parallel_requested` | integer | yes | Requested parallel runs |
| `runs_total` | integer | yes | Total runs launched |
| `runs` | array | yes | One item per run |
| `aggregate` | object | yes | Rollup counters |

## Required Run Entry Fields (`launch_report.json:runs[]`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `run` | integer | yes | 1-based index |
| `run_id` | string | yes | `run_01`, `run_02`, ... |
| `pid` | integer or null | yes | Process ID if available |
| `has_exited` | boolean | yes | Process completion observed |
| `exit_code` | integer or null | yes | `null` allowed if unavailable |
| `run_dir` | string | yes | Absolute or normalized path |
| `started_at` | string | yes | UTC ISO-8601 |
| `finished_at` | string | yes | UTC ISO-8601 |
| `duration_ms` | integer | yes | Non-negative |
| `status` | string | yes | `success`, `partial`, `failed` |
| `summary_exists` | boolean | yes | Summary artifact present |
| `csv_exists` | boolean | yes | CSV artifact present |
| `full_exists` | boolean | yes | Full JSON artifact present |
| `stdout_exists` | boolean | yes | `stdout.log` present |
| `stderr_exists` | boolean | yes | `stderr.log` present |
| `artifact_manifest_exists` | boolean | yes | `artifact_manifest.json` present |

## Required `artifact_manifest.json` Fields (Run Artifacts)

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
  "counters": {
    "targets_total": 5,
    "targets_success_json": 0,
    "targets_unresolved": 5
  },
  "artifacts": {
    "stdout_log": {
      "path": "run_01/stdout.log",
      "exists": true,
      "size_bytes": 499,
      "sha256": "f3e2..."
    },
    "stderr_log": {
      "path": "run_01/stderr.log",
      "exists": true,
      "size_bytes": 1705,
      "sha256": "7a91..."
    },
    "csv": {
      "path": "run_01/tallow_max_scraper_graphql_json_parallel.csv",
      "exists": true,
      "size_bytes": 371,
      "sha256": "6f24..."
    },
    "summary_txt": {
      "path": "run_01/tallow_max_scraper_graphql_json_parallel_summary.txt",
      "exists": true,
      "size_bytes": 534,
      "sha256": "053a..."
    },
    "full_json": {
      "path": "run_01/tallow_max_scraper_graphql_json_parallel_full.json",
      "exists": true,
      "size_bytes": 592995,
      "sha256": "0a9f..."
    }
  }
}
```

Required `artifact_manifest.json` keys:

- `schema_version`
- `launch_id`
- `run`
- `run_id`
- `pipeline_slug`
- `started_at`
- `finished_at`
- `duration_ms`
- `status`
- `counters`
- `artifacts`

Each object under `artifacts` must contain:

- `path`
- `exists`
- `size_bytes`
- `sha256`

## Backward Compatibility

Current legacy reports in this repository are a JSON array of run entries:

```json
[
  {
    "run": 1,
    "pid": 23104,
    "has_exited": true,
    "exit_code": null,
    "run_dir": "/mnt/Personal/Nixe\\artifacts\\scraper_runs\\parallel10_ok_20260427-220243\\run_01",
    "summary_exists": true,
    "csv_exists": true,
    "full_exists": true
  }
]
```

Consumers should support both formats during migration. Producers should write canonical `v1.0.0` format for new launches.
