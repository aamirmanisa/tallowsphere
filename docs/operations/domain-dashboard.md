# Domain Dashboard

`TSK-1103` helper for domain-level operational metrics from launcher artifacts. Phase 7 adds a Linux-native local proof path for request-plan execution reports.

## Purpose

`scripts/build_domain_dashboard.py` reads a `tallow.request_plan_run_report.v1` execution report and produces local Phase 7 dashboard artifacts. The legacy `scripts/build_domain_dashboard.ps1` reads older launcher artifacts when PowerShell is available.

- Per-domain JSON dashboard
- Per-domain CSV dashboard

Both outputs include:

- `success_count`
- `fail_count`
- `unresolved_count`
- HTTP `status_distribution`

## Linux/CachyOS Phase 7 usage

```bash
python3 scripts/build_domain_dashboard.py \
  --execution-report artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/execution_report.json \
  --output-json artifacts/phase7/local-artifacts-replay-observability/domain_dashboard.json \
  --output-csv artifacts/phase7/local-artifacts-replay-observability/domain_dashboard.csv
```

Phase 7 proof output uses `schema_version: tallow.domain_dashboard.v1`, rolls subdomains up to a root-domain key, and carries explicit non-claims for no live replay/external scraping and no production dashboard readiness.

## Legacy PowerShell inputs

Pass either:

- Launch directory containing `launch_report.json`, or
- Direct path to `launch_report.json`

The script reads per-run artifacts from discovered `run_*` folders:

- `*.csv`
- `*summary*.txt`

## Success, Failure, and Unresolved Rules

- `success_count`: CSV rows where `is_json` is truthy (`1/true/yes/y`).
- `fail_count`: CSV rows where `is_json` is not truthy.
- `unresolved_count`: unresolved URL entries parsed from summary key `unresolved_urls` (pipe-delimited list).
- `status_distribution`: counts by `status` in CSV rows (for example `200`, `404`, `429`).

Domain key is normalized from URL host and rolled up to root domain (for example `vendor.example` -> `vendor.example`).

## Default Output Paths

By default, both outputs are written into the launch folder:

- `domain_dashboard.json`
- `domain_dashboard.csv`

## Usage

```powershell
.\scripts\build_domain_dashboard.ps1 `
  -LaunchPath .\artifacts\scraper_runs\parallel10_20260427-223954
```

Custom output directory:

```powershell
.\scripts\build_domain_dashboard.ps1 `
  -LaunchPath .\artifacts\scraper_runs\parallel10_20260427-223954 `
  -OutputDirectory .\artifacts\scraper_runs\parallel10_20260427-223954\dashboards
```

Custom output files:

```powershell
.\scripts\build_domain_dashboard.ps1 `
  -LaunchPath .\artifacts\scraper_runs\parallel10_20260427-223954 `
  -OutputJsonPath .\artifacts\reports\domain_dashboard.json `
  -OutputCsvPath .\artifacts\reports\domain_dashboard.csv
```

Dry-run (no file writes):

```powershell
.\scripts\build_domain_dashboard.ps1 `
  -LaunchPath .\artifacts\scraper_runs\parallel10_20260427-223954 `
  -DryRun
```

## JSON Shape

Top-level keys:

- `schema_version`
- `generated_at_utc`
- `launch_root`
- `launch_report_path`
- `runs_total`
- `runs_processed`
- `rows_total`
- `domains_total`
- `outputs`
- `runs`
- `domains`

Per-domain object keys:

- `domain`
- `attempts_total`
- `success_count`
- `fail_count`
- `unresolved_count`
- `success_rate`
- `status_distribution`
- `status_distribution_json`

## CSV Columns

- `domain`
- `attempts_total`
- `success_count`
- `fail_count`
- `unresolved_count`
- `success_rate`
- `status_distribution_json`

