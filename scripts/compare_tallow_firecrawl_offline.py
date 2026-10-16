#!/usr/bin/env python3
"""Compare Phase 10 Tallow-local and Firecrawl-mock fixture benchmark artifacts.

The comparator is offline-only. It validates both inputs are local fixture runs over
the same corpus and emits parity/quality results without making speed, cost, live
Firecrawl, or provider-superiority claims.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_SCHEMA = "tallow.artifact_manifest.v1"
COMPARISON_SCHEMA = "tallow.phase10_firecrawl_comparison.v1"
PROTOCOL_VERSION = "1.0-local-offline"
FALSE_VALUES = {"", "0", "false", "no", "off"}
LIVE_ENV_FLAGS = (
    "TALLOW_RUN_LIVE_BENCHMARKS",
    "TALLOW_LIVE_BENCHMARK_APPROVAL",
    "TALLOW_ENABLE_PAID_APIS",
    "FIRECRAWL_API_KEY",
    "FIRECRAWL_TOKEN",
    "FIRECRAWL_BASE_URL",
)
NON_CLAIMS = {
    "no_live_external_scraping": True,
    "no_live_firecrawl": True,
    "no_firecrawl_service_startup": True,
    "no_firecrawl_hosted_api": True,
    "no_paid_api": True,
    "no_real_secrets": True,
    "no_performance_claim": True,
    "no_provider_superiority_claim": True,
    "no_production_readiness_claim": True,
    "no_windows_support_claim": True,
}


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resolve_path(path_arg: str) -> Path:
    path = Path(path_arg)
    return path if path.is_absolute() else ROOT / path


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(data), encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def is_false(value: str | None) -> bool:
    return (value or "").strip().lower() in FALSE_VALUES


def live_benchmark_env_errors() -> list[str]:
    errors: list[str] = []
    for name in LIVE_ENV_FLAGS:
        if not is_false(os.environ.get(name)):
            errors.append(f"{name} must be unset/false for offline benchmark comparison")
    return errors


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid JSONL in {path}:{line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise SystemExit(f"invalid JSONL row in {path}:{line_number}: expected object")
        rows.append(row)
    return rows


def manifest_item_path(item: dict[str, Any]) -> Path:
    raw = Path(str(item.get("path", "")))
    return raw if raw.is_absolute() else ROOT / raw


def verify_manifest(manifest_path: Path) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not manifest_path.exists():
        return False, [f"manifest not found: {manifest_path}"]
    try:
        manifest = read_json(manifest_path)
    except Exception as exc:  # noqa: BLE001
        return False, [f"manifest parse failed: {exc}"]
    if manifest.get("schema_version") != ARTIFACT_SCHEMA:
        errors.append(f"unexpected schema_version: {manifest.get('schema_version')}")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        errors.append("manifest files must be a non-empty array")
        return False, errors
    for item in files:
        if not isinstance(item, dict):
            errors.append("manifest file entry must be object")
            continue
        path = manifest_item_path(item)
        if not path.exists():
            errors.append(f"missing file: {item.get('path')}")
            continue
        size = path.stat().st_size
        digest = sha256_file(path)
        if item.get("size_bytes") != size:
            errors.append(f"size mismatch: {item.get('path')}")
        if item.get("sha256") != digest:
            errors.append(f"sha256 mismatch: {item.get('path')}")
    return not errors, errors


def load_run(run_dir: Path, expected_provider: str) -> dict[str, Any]:
    required = ["config.json", "summary.json", "raw.jsonl", "artifact_manifest.json"]
    missing = [name for name in required if not (run_dir / name).exists()]
    if missing:
        raise SystemExit(f"missing required input files in {run_dir}: {', '.join(missing)}")
    config = read_json(run_dir / "config.json")
    summary = read_json(run_dir / "summary.json")
    rows = read_jsonl(run_dir / "raw.jsonl")
    if config.get("provider") != expected_provider:
        raise SystemExit(f"expected provider {expected_provider}, got {config.get('provider')} in {run_dir}")
    if config.get("mode") != "local_fixture" or summary.get("mode") != "local_fixture":
        raise SystemExit(f"input run is not local_fixture mode: {run_dir}")
    if config.get("protocol_version") != PROTOCOL_VERSION or summary.get("protocol_version") != PROTOCOL_VERSION:
        raise SystemExit(f"input run is not protocol {PROTOCOL_VERSION}: {run_dir}")
    if any(not str(row.get("url", "")).startswith("fixture://") for row in rows):
        raise SystemExit(f"input run contains non-fixture URL: {run_dir}")
    ok, errors = verify_manifest(run_dir / "artifact_manifest.json")
    if not ok:
        raise SystemExit("input artifact manifest failed verification for " + str(run_dir) + ": " + "; ".join(errors))
    return {"run_dir": run_dir, "config": config, "summary": summary, "rows": rows}


def compare_runs(tallow: dict[str, Any], firecrawl: dict[str, Any]) -> dict[str, Any]:
    t_config = tallow["config"]
    f_config = firecrawl["config"]
    if t_config.get("corpus_id") != f_config.get("corpus_id"):
        raise SystemExit(f"corpus mismatch: {t_config.get('corpus_id')} != {f_config.get('corpus_id')}")
    if t_config.get("manifest_version") != f_config.get("manifest_version"):
        raise SystemExit(f"manifest mismatch: {t_config.get('manifest_version')} != {f_config.get('manifest_version')}")
    t_rows = {str(row["target_id"]): row for row in tallow["rows"]}
    f_rows = {str(row["target_id"]): row for row in firecrawl["rows"]}
    if set(t_rows) != set(f_rows):
        raise SystemExit("target coverage mismatch between tallow-local and firecrawl-mock runs")

    rows: list[dict[str, Any]] = []
    validation_parity_count = 0
    field_parity_count = 0
    error_class_parity_count = 0
    for target_id in sorted(t_rows):
        t_row = t_rows[target_id]
        f_row = f_rows[target_id]
        t_fields = t_row.get("fixture", {}).get("extracted_fields", {})
        f_fields = f_row.get("fixture", {}).get("extracted_fields", {})
        expected = t_row.get("fixture", {}).get("expected_fields", {})
        validation_parity = bool(t_row.get("validation_passed")) == bool(f_row.get("validation_passed"))
        field_parity = t_fields == f_fields
        error_class_parity = t_row.get("error_class") == f_row.get("error_class")
        validation_parity_count += int(validation_parity)
        field_parity_count += int(field_parity)
        error_class_parity_count += int(error_class_parity)
        rows.append(
            {
                "target_id": target_id,
                "category": t_row.get("fixture", {}).get("category"),
                "expected_fields": expected,
                "tallow_validation_passed": bool(t_row.get("validation_passed")),
                "firecrawl_validation_passed": bool(f_row.get("validation_passed")),
                "validation_parity": validation_parity,
                "field_parity": field_parity,
                "error_class_parity": error_class_parity,
                "tallow_error_class": t_row.get("error_class"),
                "firecrawl_error_class": f_row.get("error_class"),
            }
        )
    total = len(rows)
    return {
        "target_count": total,
        "validation_parity_count": validation_parity_count,
        "field_parity_count": field_parity_count,
        "error_class_parity_count": error_class_parity_count,
        "all_target_ids_match": True,
        "all_validation_outcomes_match": validation_parity_count == total,
        "all_extracted_fields_match": field_parity_count == total,
        "all_error_classes_match": error_class_parity_count == total,
        "rows": rows,
    }


def artifact_item(path: Path, artifact_class: str) -> dict[str, Any]:
    return {
        "path": display_path(path),
        "artifact_class": artifact_class,
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "sha256": sha256_file(path) if path.exists() else "",
        "redaction_status": "no_sensitive_data_expected_local_fixture",
    }


def write_outputs(output_dir: Path, tallow: dict[str, Any], firecrawl: dict[str, Any], comparison: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_at = iso_now()
    status = "PASS" if (
        comparison["all_target_ids_match"]
        and comparison["all_validation_outcomes_match"]
        and comparison["all_extracted_fields_match"]
        and comparison["all_error_classes_match"]
    ) else "WARN"
    payload = {
        "schema_version": COMPARISON_SCHEMA,
        "generated_at_utc": generated_at,
        "status": status,
        "comparison_mode": "offline_fixture",
        "tallow_mode": "local_fixture",
        "firecrawl_mode": "mock_fixture_projection",
        "protocol_version": PROTOCOL_VERSION,
        "manifest_version": tallow["config"]["manifest_version"],
        "corpus_id": tallow["config"]["corpus_id"],
        "inputs": {
            "tallow_run_dir": display_path(tallow["run_dir"]),
            "firecrawl_run_dir": display_path(firecrawl["run_dir"]),
            "tallow_run_id": tallow["config"]["run_id"],
            "firecrawl_run_id": firecrawl["config"]["run_id"],
        },
        "target_coverage": {
            "target_count": comparison["target_count"],
            "all_target_ids_match": comparison["all_target_ids_match"],
        },
        "validation_parity": {
            "matching_targets": comparison["validation_parity_count"],
            "target_count": comparison["target_count"],
            "all_match": comparison["all_validation_outcomes_match"],
        },
        "field_parity": {
            "matching_targets": comparison["field_parity_count"],
            "target_count": comparison["target_count"],
            "all_match": comparison["all_extracted_fields_match"],
        },
        "error_class_parity": {
            "matching_targets": comparison["error_class_parity_count"],
            "target_count": comparison["target_count"],
            "all_match": comparison["all_error_classes_match"],
        },
        "speed_cost_claim": "not_claimed",
        "performance_claim": "not_claimed",
        "rows": comparison["rows"],
        "non_claims": NON_CLAIMS,
    }
    write_json(output_dir / "comparison.json", payload)

    with (output_dir / "comparison.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "target_id",
                "tallow_validation_passed",
                "firecrawl_validation_passed",
                "validation_parity",
                "field_parity",
                "error_class_parity",
            ]
        )
        for row in comparison["rows"]:
            writer.writerow(
                [
                    row["target_id"],
                    row["tallow_validation_passed"],
                    row["firecrawl_validation_passed"],
                    row["validation_parity"],
                    row["field_parity"],
                    row["error_class_parity"],
                ]
            )

    md = f"""# Phase 10 Offline Tallow vs Firecrawl Fixture Comparison

Status: `{status}`

Comparison mode: `offline_fixture`
Firecrawl mode: `mock_fixture_projection`
Protocol version: `{PROTOCOL_VERSION}`
Corpus: `{tallow['config']['corpus_id']}`

## Results

- Targets compared: {comparison['target_count']}
- Validation parity: {comparison['validation_parity_count']}/{comparison['target_count']}
- Extracted-field parity: {comparison['field_parity_count']}/{comparison['target_count']}
- Error-class parity: {comparison['error_class_parity_count']}/{comparison['target_count']}

## Non-claims

- Firecrawl service was not started.
- Firecrawl hosted/cloud API was not called.
- No live external scraping or crawling was performed.
- No paid API, proxy, credential, or secret was used.
- No throughput, latency, cost, vendor superiority, or production readiness claim is made.
- This comparison is a fixture-schema and validation-parity proof only.
"""
    (output_dir / "comparison.md").write_text(md, encoding="utf-8")

    manifest = {
        "schema_version": ARTIFACT_SCHEMA,
        "artifact_id": "phase10-offline-firecrawl-comparison",
        "launch_id": "phase10-offline-firecrawl-comparison",
        "run_id": "phase10-offline-firecrawl-comparison",
        "mode": "offline_fixture",
        "measurement_scope": "local_fixture_only",
        "generated_at_utc": generated_at,
        "files": [
            artifact_item(output_dir / "comparison.json", "comparison_report"),
            artifact_item(output_dir / "comparison.csv", "comparison_rows"),
            artifact_item(output_dir / "comparison.md", "comparison_summary"),
        ],
        "input_manifests": [
            display_path(tallow["run_dir"] / "artifact_manifest.json"),
            display_path(firecrawl["run_dir"] / "artifact_manifest.json"),
        ],
        "redaction": {
            "status": "passed",
            "pii_policy": "phase10_local_fixture_no_pii_expected",
            "notes": "Offline fixture comparison contains only synthetic benchmark rows.",
        },
        "retention": {"retention_days": 7, "destructive_action_performed": False},
        "replay": {
            "safe_to_replay": False,
            "requires_approval": True,
            "replay_reason": "Live Firecrawl or Tallow benchmarking remains human-gated.",
        },
        "non_claims": NON_CLAIMS,
    }
    write_json(output_dir / "artifact_manifest.json", manifest)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tallow-run-dir", help="Directory containing tallow-local fixture benchmark artifacts")
    parser.add_argument("--firecrawl-run-dir", help="Directory containing firecrawl-mock fixture benchmark artifacts")
    parser.add_argument("--output-dir", help="Output directory for comparison artifacts")
    parser.add_argument("--verify-manifest", help="Verify a tallow.artifact_manifest.v1 file and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    env_errors = live_benchmark_env_errors()
    if env_errors:
        for error in env_errors:
            print(error, file=sys.stderr)
        return 2
    if args.verify_manifest:
        ok, errors = verify_manifest(resolve_path(args.verify_manifest))
        if not ok:
            for error in errors:
                print(error, file=sys.stderr)
            return 2
        print(f"artifact manifest verified: {args.verify_manifest}")
        return 0
    if not args.tallow_run_dir or not args.firecrawl_run_dir or not args.output_dir:
        print("--tallow-run-dir, --firecrawl-run-dir, and --output-dir are required unless --verify-manifest is used", file=sys.stderr)
        return 2
    try:
        tallow = load_run(resolve_path(args.tallow_run_dir), "tallow-local")
        firecrawl = load_run(resolve_path(args.firecrawl_run_dir), "firecrawl-mock")
        comparison = compare_runs(tallow, firecrawl)
        write_outputs(resolve_path(args.output_dir), tallow, firecrawl, comparison)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 2
        raise
    print(f"wrote Phase 10 offline comparison: {display_path(resolve_path(args.output_dir))}")
    print("comparison_mode=offline_fixture")
    print("performance_claim=not_claimed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
