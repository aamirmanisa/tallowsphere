# Queue Dispatcher

> status: verified 2026-09-05 (C6 docs wave — Phase 6 Linux-native `scripts/queue_scheduler.py` path documented; no stale claims found).

## Linux/CachyOS Phase 6 scheduler status

The canonical Phase 6 path is the Linux-native local/mock scheduler proof in `scripts/queue_scheduler.py`.
It consumes `tallow.request_plan.v1` directly, writes durable scheduler state and reports under
`artifacts/phase6/**`, computes per-domain local budgets, checkpoints transitions, supports
`--resume`, and classifies blocked/dead-letter targets without live external I/O.

This Phase 6 proof is intentionally narrow:

- local/mock execution only;
- no live external scraping or crawling;
- no real secrets or vault resolution;
- no destructive queue purge;
- no deploy/release/remote service changes;
- no Windows/PowerShell support claim;
- no production queue readiness or benchmark claim.

Local completed-run proof:

```bash
python3 scripts/queue_scheduler.py \
  --plan artifacts/phase2/request-plans/local-get-post-graphql-runtime.request-plan.v1.json \
  --output-dir artifacts/phase6/adaptive-scheduler-local \
  --network-scope local \
  --mock-base-url http://127.0.0.1:1 \
  --simulate \
  --max-attempts 2 \
  --force
```

Resume proof:

```bash
python3 scripts/queue_scheduler.py \
  --plan artifacts/phase6/fixtures/local-resume.request-plan.v1.json \
  --output-dir artifacts/phase6/resume-proof \
  --network-scope local \
  --mock-base-url http://127.0.0.1:1 \
  --simulate \
  --stop-after 1 \
  --force

python3 scripts/queue_scheduler.py \
  --plan artifacts/phase6/fixtures/local-resume.request-plan.v1.json \
  --output-dir artifacts/phase6/resume-proof \
  --network-scope local \
  --mock-base-url http://127.0.0.1:1 \
  --simulate \
  --resume
```

DLQ and blocked-target proof packets live at:

- `artifacts/phase6/dlq-proof/`
- `artifacts/phase6/blocked-proof/`

The legacy PowerShell dispatcher below remains useful as a deterministic shard/checkpoint compatibility helper,
but it is not the Linux/CachyOS Phase 6 canonical scheduler and it is not production/live ready.

## Legacy PowerShell shard dispatcher

`scripts/queue_dispatcher.ps1` turns a large target manifest into deterministic shard manifests, per-shard launch configs, launch commands, and a checkpoint file.

It is intended for large runs where fixed wave batching is too coarse and the operator needs resumable shard-level progress, but it still delegates execution to the fixed PowerShell launcher and does not provide the Phase 6 adaptive/local scheduler proof.

## Command

Plan a queue for a 500-connection run without launching workers:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\queue_dispatcher.ps1 `
  -ManifestPath .\configs\tallow\targets.example.json `
  -QueueRoot .\artifacts\queue_dispatcher `
  -ShardSize 1000 `
  -Workers 10 `
  -Connections 500
```

Dry-run the same queue without writing files:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\queue_dispatcher.ps1 `
  -ManifestPath .\configs\tallow\targets.example.json `
  -ShardSize 1000 `
  -Workers 10 `
  -Connections 500 `
  -DryRun
```

Execute queued shards sequentially:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\queue_dispatcher.ps1 `
  -ManifestPath .\configs\tallow\targets.example.json `
  -ShardSize 1000 `
  -Workers 10 `
  -Connections 500 `
  -Execute
```

Resume incomplete shards from the checkpoint:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\queue_dispatcher.ps1 `
  -ManifestPath .\configs\tallow\targets.example.json `
  -ShardSize 1000 `
  -Workers 10 `
  -Connections 500 `
  -Execute `
  -Resume
```

## Outputs

Default layout:

```text
artifacts/queue_dispatcher/<queue_id>/
  queue_state.json
  launch_commands.ps1
  STOP
  shards/
    shard_0001_of_0010.manifest.json
    shard_0002_of_0010.manifest.json
  configs/
    shard_0001_of_0010.config.json
    shard_0002_of_0010.config.json
```

Shard launch artifacts are written under:

```text
artifacts/scraper_runs/queued/<queue_id>/<shard_id>/
```

Each shard command calls:

```powershell
.\scripts\launch_tallow_parallel.ps1 -ConfigPath <shard-config> -Connections 500 -Workers 10
```

## Checkpoint State

`queue_state.json` uses schema version `tallow.queue.state.v1`.

Required top-level fields:

- `queue_id`
- `status`
- `manifest_path`
- `manifest_sha256`
- `queue_root`
- `state_path`
- `stop_file`
- `shard_size`
- `shard_count`
- `target_count`
- `workers`
- `connections`
- `connections_per_worker`
- `script_path`
- `launcher_path`
- `binary_path`
- `run_output_root`
- `commands_path`
- `shards`

Per-shard fields:

- `shard_id`
- `shard_index`
- `target_start_index`
- `target_count`
- `status`
- `manifest_path`
- `config_path`
- `run_output_root`
- `launch_report_path`
- `exit_code`
- `command`

Shard statuses:

- `pending`: planned but not started
- `running`: currently executing
- `completed`: launch finished with all run artifacts present
- `failed`: launcher failed or produced incomplete artifacts
- `deferred`: skipped because the stop marker was present

## Resume Rules

Use `-Resume` when `queue_state.json` already exists.

Resume verifies:

- current manifest SHA-256 matches the checkpoint
- current `-ShardSize` matches the checkpoint

Completed shards are skipped. Incomplete shards are regenerated deterministically and executed again when `-Execute` is used.

The dispatcher also infers completion from a shard `launch_report.json` when the checkpoint has a report path and all runs have:

- `has_exited = true`
- `exit_code = 0`
- `summary_exists = true`
- `csv_exists = true`
- `full_exists = true`
- `timed_out = false`

## Graceful Stop

The default stop marker is:

```text
artifacts/queue_dispatcher/<queue_id>/STOP
```

Create that file to stop before the next shard starts:

```powershell
New-Item -ItemType File .\artifacts\queue_dispatcher\<queue_id>\STOP
```

When the marker exists, the dispatcher:

- marks the queue `stopped`
- marks remaining pending shards `deferred`
- writes `queue_state.json`
- exits with code `3`

The currently running shard is allowed to finish because cancellation is shard-boundary graceful.

## Determinism

For the same manifest, shard size, worker count, and connection count, the dispatcher produces stable:

- `queue_id`
- shard IDs
- shard target ordering
- shard config paths
- launch command ordering
- dry-run JSON output

The generated default `queue_id` is:

```text
queue_<manifest_sha256_12>_s<shard_size>_w<workers>_c<connections>
```

Use `-QueueId` to pin a custom queue name.

## Safety Guard

The dispatcher blocks unsafe fanout above 100 connections per worker.

For the standard 500-connection run, use:

```powershell
-Workers 10 -Connections 500
```

This resolves to `50` connections per worker.
