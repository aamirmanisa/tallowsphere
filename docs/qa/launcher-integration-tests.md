# Launcher Integration Tests (TSK-1502)

## Phase 6 status

These PowerShell launcher tests are legacy fixed-wave smoke/regression coverage. They are not the
Phase 6 Linux/CachyOS adaptive scheduler acceptance gate, and the live tiny mode is not run by
default inside Phase Autopilot because live external execution remains human-gated.

The Phase 6 local scheduler gate is:

```bash
python3 -B -m unittest tests.test_phase6_queue_scheduler -v
python3 -B -m unittest discover -s tests -p '*queue*.py' -v
python3 -B -m unittest discover -s tests -p '*scheduler*.py' -v
```

The durable local proof artifacts are under:

- `artifacts/phase6/adaptive-scheduler-local/`
- `artifacts/phase6/resume-proof/`
- `artifacts/phase6/dlq-proof/`
- `artifacts/phase6/blocked-proof/`

The tests and artifacts prove local/mock scheduling, checkpoint/resume, per-domain budget accounting,
DLQ, blocked-target classification, and artifact-manifest integrity. They do not claim production/live
queue execution, live scraping, vault/secrets, destructive purge support, deploy readiness, benchmarks,
or Windows support.

## Legacy PowerShell launcher test

This test validates `scripts/launch_tallow_parallel.ps1` in two modes:
- `Dry-run` mode: verifies launch report schema without network execution.
- `Live tiny run` mode: launches one worker and verifies `launch_report.json` plus run artifacts.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\launcher_integration_test.ps1
```

## Optional Parameters

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\launcher_integration_test.ps1 `
  -RepoRoot E:\Nixe `
  -LauncherPath scripts\launch_tallow_parallel.ps1 `
  -BinaryPath .tallow-bin\tallow.exe `
  -ScriptPath scripts\tallow_max_scraper_graphql_json_parallel_v2.tl `
  -OutputRoot artifacts\integration\launcher `
  -LiveTimeoutMinutes 10
```

## Pass/Fail Behavior

- Returns `0` on success.
- Returns non-zero (`1`) on assertion failure.
- Fails if required `launch_report.json` fields are missing.
- Fails if live run does not produce `summary`, `csv`, and `full` artifacts.

## Output Location

By default, outputs are written under:

`artifacts\integration\launcher`

The script creates separate subfolders for:
- `dry_run`
- `live_tiny`
