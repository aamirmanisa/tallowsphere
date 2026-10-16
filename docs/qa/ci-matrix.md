# CI Matrix

The scraper tool workflow runs on:

- `windows-latest`
- `ubuntu-latest`

It only uses local dry-run or environment checks. It does not call external targets and does not require secrets.

Local equivalent:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\tallow_doctor.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\prepare_tallow_run_config.ps1 `
  -ManifestPath .\configs\tallow\targets.example.json `
  -ScriptPath .\scripts\tallow_max_scraper_graphql_json_parallel_v2.tl `
  -Workers 10 `
  -Connections 500 `
  -OutputConfigPath .\artifacts\ci\config_500.json `
  -DryRun
```
