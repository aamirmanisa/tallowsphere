# E2E Mock Targets (TSK-1504)

This test runs an end-to-end scrape flow against a controlled local mock target set and emits a machine-readable pass/fail summary.

## Script

`scripts/run_e2e_mock_targets.ps1`

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_e2e_mock_targets.ps1
```

## Optional Parameters

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_e2e_mock_targets.ps1 `
  -RepoRoot tallowsphere `
  -BinaryPath .tallow-bin\tallow.exe `
  -BenchmarkScriptPath scripts\benchmark_batch_http.tl `
  -MockServerScriptPath scripts\line246_mock_server.py `
  -OutputRoot artifacts\integration\e2e_mock_targets `
  -Connections 500 `
  -Waves 10 `
  -MockDelayMs 10 `
  -Port 18765 `
  -ServerReadyTimeoutSeconds 15 `
  -RunTimeoutSeconds 120
```

## Mock Provider Behavior

- Primary path: uses `scripts\line246_mock_server.py` if Python is available and runnable.
- Fallback path: auto-generates and runs a local Node-based mock server when Python is unavailable.

Both providers serve deterministic local JSON responses on `127.0.0.1`.

## Pass/Fail Rules

The script returns:

- `0` when all checks pass.
- `1` when any check fails.

Checks include:

- mock server becomes reachable (`HTTP 200`),
- Tallow process exits before timeout,
- Tallow exit code is `0`,
- required artifacts exist (`*_report.json`, `*_summary.txt`, `*_responses.csv`),
- report parses as JSON,
- report status is `PASS`,
- expected status count equals request count,
- empty body count is zero.

## Output Artifacts

Per run, the script creates a timestamped directory under:

`artifacts\integration\e2e_mock_targets`

Primary output files:

- `benchmark_config.json`
- `mock_stdout.log`
- `mock_stderr.log`
- `tallow_stdout.log`
- `tallow_stderr.log`
- `e2e_mock_targets_report.json`
- `e2e_mock_targets_summary.txt`
- `e2e_mock_targets_responses.csv`
- `e2e_mock_targets_result.json` (final pass/fail summary)
