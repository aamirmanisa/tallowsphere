# Manifest Injection for Run-Local TL Scripts

This helper externalizes hardcoded `target_urls`, `headers`, and `l1/l2/l3` concurrency from the base TL template by generating a **new run-local TL file**.

It never edits the base template in place.

Script:

- `scripts/inject_manifest_into_tl.ps1`

## What It Injects

- `let target_urls = [...]`
- `let headers = {...}`
- `let l1_concurrency = <int>`
- `let l2_concurrency = <int>`
- `let l3_concurrency = <int>`

## Inputs

At least one input is required:

- `-ManifestPath <json>`
- `-ConfigPath <json>`

Optional:

- `-TemplatePath <tl>` (defaults to `scripts/tallow_max_scraper_graphql_json_parallel_v2.tl`)
- `-OutputPath <tl>` (auto-generated under `artifacts/generated_tl/` if omitted)
- `-DryRun`

## Source Precedence

Targets:

1. `config.input.targets` (if present)
2. otherwise `manifest.targets`
3. plus `manifest.per_domain.<host>.extra_targets` when present

Headers:

1. `manifest.headers`
2. overridden by `config.input.headers` when present
3. then `manifest.auth` is applied (`bearer`, `basic`, `api_key`, `custom_headers`)

Concurrency:

1. `config.retry.wave_concurrency` when present
2. otherwise `manifest.retry.wave_concurrency` when present
3. otherwise existing template `l1/l2/l3` defaults are retained

## Commands

Manifest only:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\inject_manifest_into_tl.ps1 `
  -ManifestPath .\configs\tallow\targets.example.json `
  -OutputPath .\artifacts\generated_tl\tallow_injected.tl
```

Prepared config only (auto-loads `config.manifest.source_path` when available):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\inject_manifest_into_tl.ps1 `
  -ConfigPath .\artifacts\scraper_runs\config_500_test2.json `
  -OutputPath .\artifacts\generated_tl\tallow_injected_from_config.tl
```

Dry run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\inject_manifest_into_tl.ps1 `
  -ManifestPath .\configs\tallow\targets.example.json `
  -DryRun
```

## Expected Output

The script prints JSON with resolved paths and effective settings, including:

- `target_count`
- `header_count`
- `l1_concurrency`, `l2_concurrency`, `l3_concurrency`
- `concurrency_source`
- `template_modified_in_place` (always `false`)

## Launching the Generated TL

Use the generated TL script path with the launcher:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\launch_tallow_parallel.ps1 `
  -ScriptPath .\artifacts\generated_tl\tallow_injected.tl `
  -Preset 10x `
  -Connections 500
```

## Current Limitations

- Base template still executes `http.batch(urls, concurrency, headers)` with global headers only.
- Per-domain header overrides are detected and warned, but not directly representable in this global-header template.
- Non-GET or payload-based target entries are detected and warned, but not executed as per-target method/payload in this template.

