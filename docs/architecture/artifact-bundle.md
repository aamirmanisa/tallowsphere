# Artifact Bundle Specification

Status: Bundle packaging spec for `TSK-1001` and `TSK-1006`; Phase 7 has a Linux/CachyOS local proof path, while production incident automation remains unclaimed.

## Purpose

`scripts/package_artifact_bundle.py` packages one local artifact directory into a hash-checked bundle for the Phase 7 Linux/CachyOS proof. The legacy `scripts/package_artifact_bundle.ps1` packages older launcher directories when PowerShell is available.

The bundle may include:

- Manifest artifacts (`launch_report.json`, per-run `artifact_manifest.json`, plus generated `bundle_manifest.json`)
- Raw response artifacts (`*_full.json`, `*_full.ndjson`, `*_full.combined.ndjson`)
- Normalized row artifacts (`*.csv`, `*.ndjson`, `all_runs.ndjson`)
- Metrics artifacts (`*_summary.txt`, `run_metrics.json`, `run_metrics.md`, benchmark/output validation reports)
- Logs (`stdout.log`, `stderr.log`, and other `*.log`)

The script can also produce an optional zip archive for large bundles.

## Scripts

Paths:

- Linux/CachyOS Phase 7 proof: `scripts/package_artifact_bundle.py`
- Legacy PowerShell: `scripts/package_artifact_bundle.ps1`

## Linux/CachyOS Phase 7 proof

```bash
python3 scripts/package_artifact_bundle.py \
  --source-dir artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof \
  --output-root artifacts/phase7/local-artifacts-replay-observability/bundles \
  --bundle-name local-get-post-graphql-runtime-proof-bundle \
  --include-file artifacts/phase7/local-artifacts-replay-observability/run_metrics.json \
  --include-file artifacts/phase7/local-artifacts-replay-observability/run_metrics.md \
  --include-file artifacts/phase7/local-artifacts-replay-observability/domain_dashboard.json \
  --include-file artifacts/phase7/local-artifacts-replay-observability/domain_dashboard.csv \
  --include-file artifacts/phase7/local-artifacts-replay-observability/failure_replay_report.json \
  --include-file artifacts/phase7/local-artifacts-replay-observability/command-log.txt \
  --artifact-manifest-output artifacts/phase7/local-artifacts-replay-observability/artifact_manifest.json \
  --artifact-id phase7-local-artifacts-replay-observability
```

Phase 7 proof artifacts:

- `artifacts/phase7/local-artifacts-replay-observability/bundles/local-get-post-graphql-runtime-proof-bundle/bundle_manifest.json`
- `artifacts/phase7/local-artifacts-replay-observability/artifact_manifest.json`

The artifact manifest is `tallow.artifact_manifest.v1`, marks `replay.safe_to_replay=false`, requires approval for replay, and hash-checks final local proof files. This does not claim live replay, production retention/purge, compliance enforcement, or benchmark readiness.

### Parameters

- `-LaunchDir` (required): source launch directory (for example: `artifacts/scraper_runs/parallel10_20260427-223635`)
- `-OutputRoot` (optional): output root for bundle directories. Default: `artifacts/artifact_bundles`
- `-BundleName` (optional): explicit bundle folder name. Default: `<launch_id>_bundle_<timestamp>`
- `-Compress` (optional): create a zip archive for the bundle (`TSK-1006`)
- `-ZipPath` (optional): override zip output path. Default: `<OutputRoot>\<BundleName>.zip`
- `-Force` (optional): overwrite existing bundle dir and existing zip output

## Standard Behavior

1. Validate `LaunchDir` exists and contains files.
2. Create bundle output directory.
3. Copy all launch files to bundle directory preserving relative layout.
4. Compute SHA-256 for source and bundled copy; fail on mismatch.
5. Classify each file into artifact classes (`manifest`, `raw_responses`, `normalized_rows`, `metrics`, `logs`, fallback classes).
6. Emit `bundle_manifest.json` in bundle root.
7. If `-Compress` is set, create zip and record its hash/size in manifest.

## Output Layout

```text
artifacts/
  artifact_bundles/
    <bundle_name>/
      bundle_manifest.json
      launch_report.json
      run_01/
        stdout.log
        stderr.log
        *.csv
        *_summary.txt
        *_full.json
        *_full.ndjson
      run_02/
        ...
    <bundle_name>.zip        # optional when -Compress is enabled
```

## `bundle_manifest.json` (Schema)

```json
{
  "schema_version": "tallow.artifact.bundle.v1",
  "generated_at_utc": "2026-04-28T03:40:00.123Z",
  "bundle": {
    "bundle_name": "parallel10_20260427-223635_bundle_20260428-034000",
    "bundle_dir": "/mnt/Personal/Nixe\\artifacts\\artifact_bundles\\parallel10_20260427-223635_bundle_20260428-034000",
    "manifest_path": "/mnt/Personal/Nixe\\artifacts\\artifact_bundles\\parallel10_20260427-223635_bundle_20260428-034000\\bundle_manifest.json"
  },
  "source": {
    "launch_id": "parallel10_20260427-223635",
    "launch_dir": "/mnt/Personal/Nixe\\artifacts\\scraper_runs\\parallel10_20260427-223635",
    "has_launch_report": true,
    "launch_report_path": "/mnt/Personal/Nixe\\artifacts\\scraper_runs\\parallel10_20260427-223635\\launch_report.json"
  },
  "summary": {
    "files_total": 61,
    "runs_detected": ["run_01", "run_02"],
    "classes": {
      "counts": {
        "manifest": 1,
        "raw_responses": 20,
        "normalized_rows": 11,
        "metrics": 10,
        "logs": 20
      },
      "bytes": {
        "manifest": 1234
      }
    },
    "bytes_source_total": 4567890,
    "bytes_bundled_total": 4567890
  },
  "compression": {
    "enabled": true,
    "zip_path": "/mnt/Personal/Nixe\\artifacts\\artifact_bundles\\parallel10_20260427-223635_bundle_20260428-034000.zip",
    "size_bytes": 1234567,
    "sha256": "abc123..."
  },
  "files": [
    {
      "relative_path": "run_01\\tallow_max_scraper_graphql_json_parallel_full.json",
      "run_id": "run_01",
      "artifact_class": "raw_responses",
      "source": {
        "path": "/mnt/Personal/Nixe\\artifacts\\scraper_runs\\parallel10_20260427-223635\\run_01\\tallow_max_scraper_graphql_json_parallel_full.json",
        "size_bytes": 592995,
        "last_write_time_utc": "2026-04-28T03:36:44.0000000Z",
        "sha256": "..."
      },
      "bundled": {
        "path": "/mnt/Personal/Nixe\\artifacts\\artifact_bundles\\parallel10_20260427-223635_bundle_20260428-034000\\run_01\\tallow_max_scraper_graphql_json_parallel_full.json",
        "size_bytes": 592995,
        "sha256": "..."
      }
    }
  ]
}
```

## Usage Examples

Bundle without zip:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\package_artifact_bundle.ps1 `
  -LaunchDir artifacts\scraper_runs\parallel10_20260427-223635
```

Bundle with zip compression:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\package_artifact_bundle.ps1 `
  -LaunchDir artifacts\scraper_runs\parallel10_20260427-223635 `
  -Compress
```

Bundle with explicit outputs:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\package_artifact_bundle.ps1 `
  -LaunchDir artifacts\scraper_runs\parallel10_20260427-223635 `
  -OutputRoot artifacts\artifact_bundles `
  -BundleName parallel10_apollo_may01 `
  -ZipPath artifacts\artifact_bundles\parallel10_apollo_may01.zip `
  -Compress `
  -Force
```
