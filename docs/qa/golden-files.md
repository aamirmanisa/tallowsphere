# Golden Files

Golden summaries give CI a deterministic way to detect changes in scraper output shape.

Generate:

```powershell
.\scripts\generate_golden_files.ps1 `
  -LaunchPath .\artifacts\scraper_runs\parallel10_20260428-100748 `
  -OutputRoot .\artifacts\golden `
  -Force
```

Verify:

```powershell
.\scripts\generate_golden_files.ps1 `
  -LaunchPath .\artifacts\scraper_runs\parallel10_20260428-100748 `
  -OutputRoot .\artifacts\golden `
  -GoldenPath .\artifacts\golden\parallel10_20260428-100748\golden_summary.json `
  -Verify
```

The golden file records launch report hash, CSV headers, row counts, artifact hashes, and summary key/value data.

