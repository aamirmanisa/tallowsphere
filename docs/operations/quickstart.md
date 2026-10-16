# Tallow Scraper Operator Quickstart

> status: verified 2026-09-05 (C1/C6 docs wave — content matches the current Linux/Phase-1 flow; PowerShell examples are correctly labeled legacy).

Active target: Linux/CachyOS from repo root (`~/Nixe`). Windows/PowerShell examples below are legacy scraper-ops helpers unless Windows support is explicitly requested.

## Phase 1 Linux/CachyOS Preflight

Before high-parallel scraper work, verify the runtime/toolchain substrate:

```bash
cargo build --locked --bin tallow
./target/debug/tallow doctor
python3 scripts/phase1_smoke_ladder.py
```

Expected Phase 1 reports:

```text
artifacts/doctor/tallow_doctor_report.json
artifacts/phase1/phase1_smoke_ladder_report.json
```

Current accepted Phase 1 gate evidence is recorded in `docs/mega/phase1-linux-doctor-smoke-report.md`. A passing full smoke ladder reports `pass=17 warn=0 fail=0` and no active blockers.

## Legacy PowerShell scraper presets

The commands below document existing scraper launcher helpers. They are not the active Linux/CachyOS Phase 1 bootstrap gate.

## One-Command Presets

### 10x

```powershell
.\scripts\launch_tallow_parallel.ps1 `
  -ScriptPath .\scripts\tallow_max_scraper_graphql_json_parallel_v2.tl `
  -Preset 10x
```

### 50x

```powershell
.\scripts\launch_tallow_parallel.ps1 `
  -ScriptPath .\scripts\tallow_max_scraper_graphql_json_parallel_v2.tl `
  -Preset 50x
```

### 100x

```powershell
.\scripts\launch_tallow_parallel.ps1 `
  -ScriptPath .\scripts\tallow_max_scraper_graphql_json_parallel_v2.tl `
  -Preset 100x
```

## 500 Connections (10 Workers)

1) Build a normalized run config:

```powershell
.\scripts\prepare_tallow_run_config.ps1 `
  -ManifestPath .\configs\tallow\targets.example.json `
  -ScriptPath .\scripts\tallow_max_scraper_graphql_json_parallel_v2.tl `
  -Workers 10 `
  -Connections 500 `
  -OutputConfigPath .\artifacts\scraper_runs\config_500.json
```

2) Launch from that config:

```powershell
.\scripts\launch_tallow_parallel.ps1 -ConfigPath .\artifacts\scraper_runs\config_500.json
```

## Artifact Layout

Each launch writes to:

```text
artifacts/scraper_runs/<launch_name>/
  launch_report.json
  run_01/
    stdout.log
    stderr.log
    tallow_max_scraper_graphql_json_parallel.csv
    tallow_max_scraper_graphql_json_parallel_full.json
    tallow_max_scraper_graphql_json_parallel_summary.txt
  run_02/
  ...
```

## Failure Inspection

1) Non-empty stderr logs:

```powershell
Get-ChildItem artifacts/scraper_runs/*/run_*/stderr.log |
  Where-Object { $_.Length -gt 0 } |
  Select-Object FullName, Length
```

2) Summary-level unresolved counts:

```powershell
Get-ChildItem artifacts/scraper_runs/*/run_*/tallow_max_scraper_graphql_json_parallel_summary.txt |
  Select-String "validation_status=|targets_unresolved="
```

3) Request-level error kinds:

```powershell
Get-ChildItem artifacts/scraper_runs/*/run_*/tallow_max_scraper_graphql_json_parallel.csv |
  Select-String ",transport$|,server$|,rate_limited$|,auth$|,other$"
```

