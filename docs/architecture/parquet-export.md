# Parquet Export

> status: reviewed 2026-09-05 (C6 docs wave) — **legacy Windows-era doc: the only Parquet exporter is `scripts/export_run_parquet.ps1` (no Linux twin).** Map caution "task list status may lag script/doc reality" is still open. Do not treat as a current Linux gate.

`scripts/export_run_parquet.ps1` converts existing run output to Parquet when local Python dependencies are available.

```powershell
.\scripts\export_run_parquet.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260428-100748
```

The script prefers `combined_runs.ndjson`, then falls back to CSV. It writes a companion report even when Parquet dependencies are missing.

Use `-RequireParquet` in CI if missing dependencies should fail the run.

