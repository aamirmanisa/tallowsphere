# Output Migration

> status: reviewed 2026-09-05 (C6 docs wave) — **legacy Windows-era doc:** the validator shown (`scripts/validate_output_convention.ps1`) is .ps1-only; Linux-native Phase 2/5 contract validators (`scripts/validate_tallow_contracts.py`, `validate_extraction_rows.py`) validate the newer manifest/extraction contracts, not this launcher layout. Cross-generation reconciliation deferred.

This project now treats the launcher output layout as the canonical format for scraper runs.

## Canonical Launch Directory

```text
artifacts/scraper_runs/parallel<workers>_YYYYMMDD-HHMMSS/
  launch_report.json
  run_01/
    stdout.log
    stderr.log
    *.csv
    *summary*.txt
    *full*.json
```

The validator is:

```powershell
.\scripts\validate_output_convention.ps1 `
  -LaunchPath .\artifacts\scraper_runs\parallel10_20260428-095543 `
  -FailOnViolation
```

## Legacy Reports

Older reports may be a raw JSON array instead of an object with launch metadata. Keep readers compatible with that shape during migration, but new launch producers should emit the canonical object form with:

- `launched_at_utc`
- `binary_path`
- `binary_sha256`
- `binary_version`
- `script_path`
- `script_sha256`
- `git_commit`
- `config_hash`
- `config_sha256`
- `launcher_working_directory`
- `workers`
- `connections`
- `launch_root`
- `runs`

## Deprecation Rule

New automation should read from the canonical layout first. Legacy output should be converted or bundled before release gates depend on it.
