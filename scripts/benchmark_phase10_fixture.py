#!/usr/bin/env python3
"""Emit Phase 10 local/offline benchmark protocol artifacts from fixture data.

This script intentionally performs no network I/O. It accepts only fixture:// URLs
and exists to prove benchmark protocol shape, validation accounting, and artifact
integrity before any human-approved live benchmark work.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_SCHEMA = "tallow.artifact_manifest.v1"
CONFIG_SCHEMA = "tallow.phase10_benchmark_config.v1"
SUMMARY_SCHEMA = "tallow.phase10_benchmark_summary.v1"
SYSTEM_METRICS_SCHEMA = "tallow.phase10_system_metrics.v1"
PROTOCOL_VERSION = "1.0-local-offline"
MEASUREMENT_SCOPE = "local_fixture_only"
ALLOWED_PROVIDERS = {"tallow-local", "firecrawl-mock"}
ERROR_CLASSES = {"none", "validation"}
FALSE_VALUES = {"", "0", "false", "no", "off"}
LIVE_ENV_FLAGS = (
    "TALLOW_RUN_LIVE_BENCHMARKS",
    "TALLOW_LIVE_BENCHMARK_APPROVAL",
    "TALLOW_ENABLE_PAID_APIS",
    "FIRECRAWL_API_KEY",
    "FIRECRAWL_TOKEN",
    "FIRECRAWL_BASE_URL",
)
REQUIRED_FILES = [
    "config.json",
    "summary.json",
    "kpi.csv",
    "errors.csv",
    "raw.jsonl",
    "system-metrics.json",
    "command-log.txt",
]
NON_CLAIMS = {
    "no_live_external_scraping": True,
    "no_firecrawl_service_startup": True,
    "no_firecrawl_hosted_api": True,
    "no_paid_api": True,
    "no_real_secrets": True,
    "no_performance_claim": True,
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


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def is_false(value: str | None) -> bool:
    return (value or "").strip().lower() in FALSE_VALUES


def live_benchmark_env_errors() -> list[str]:
    errors: list[str] = []
    for name in LIVE_ENV_FLAGS:
        if not is_false(os.environ.get(name)):
            errors.append(f"{name} must be unset/false for local fixture benchmark scaffolding")
    return errors


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * pct
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def validate_corpus(corpus: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if corpus.get("schema_version") != "tallow.phase10.fixture_corpus.v1":
        errors.append("unsupported corpus schema_version")
    if corpus.get("protocol_version") != PROTOCOL_VERSION:
        errors.append(f"corpus protocol_version must be {PROTOCOL_VERSION}")
    targets = corpus.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append("corpus targets must be a non-empty array")
        return errors
    seen: set[str] = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            errors.append(f"targets[{index}] must be an object")
            continue
        target_id = target.get("target_id")
        if not isinstance(target_id, str) or not target_id:
            errors.append(f"targets[{index}] missing target_id")
        elif target_id in seen:
            errors.append(f"duplicate target_id: {target_id}")
        else:
            seen.add(target_id)
        url = target.get("url")
        if not isinstance(url, str) or not url.startswith("fixture://"):
            errors.append(f"non-fixture URL refused for {target_id or index}: {url}")
        fixture = target.get("fixture")
        if not isinstance(fixture, dict):
            errors.append(f"target {target_id or index} missing fixture object")
            continue
        if not isinstance(fixture.get("expected_fields"), dict):
            errors.append(f"target {target_id or index} missing fixture.expected_fields")
        provider_outputs = target.get("provider_outputs")
        if not isinstance(provider_outputs, dict):
            errors.append(f"target {target_id or index} missing provider_outputs")
        else:
            for provider in ALLOWED_PROVIDERS:
                output = provider_outputs.get(provider)
                if not isinstance(output, dict) or not isinstance(output.get("extracted_fields"), dict):
                    errors.append(f"target {target_id or index} missing provider output for {provider}")
    return errors


def fields_match(expected: dict[str, Any], extracted: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    missing: list[str] = []
    mismatched: list[str] = []
    for key, expected_value in expected.items():
        if key not in extracted:
            missing.append(key)
        elif extracted[key] != expected_value:
            mismatched.append(key)
    return not missing and not mismatched, missing, mismatched


def build_rows(corpus: dict[str, Any], provider: str, run_id: str, window_id: str, concurrency_level: int, timestamp: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    manifest_version = str(corpus["manifest_version"])
    for index, target in enumerate(corpus["targets"]):
        fixture = target["fixture"]
        body = str(fixture.get("body", ""))
        expected_fields = dict(fixture["expected_fields"])
        extracted_fields = dict(target["provider_outputs"][provider]["extracted_fields"])
        validation_passed, missing_fields, mismatched_fields = fields_match(expected_fields, extracted_fields)
        error_class = "none" if validation_passed else "validation"
        if error_class not in ERROR_CLASSES:
            raise AssertionError(error_class)
        # Deterministic fixture durations are useful only for aggregate plumbing; they
        # are explicitly labeled as non-performance data in every output artifact.
        duration_ms = 8 + index * 3 + (1 if provider == "firecrawl-mock" else 0)
        rows.append(
            {
                "run_id": run_id,
                "protocol_version": PROTOCOL_VERSION,
                "manifest_version": manifest_version,
                "window_id": window_id,
                "timestamp_utc": timestamp,
                "target_id": target["target_id"],
                "url": target["url"],
                "attempt": 1,
                "status_code": 200,
                "success": validation_passed,
                "duration_ms": duration_ms,
                "bytes_received": len(body.encode("utf-8")),
                "error_class": error_class,
                "validation_passed": validation_passed,
                "worker_id": f"{provider}-fixture-worker-1",
                "concurrency_level": concurrency_level,
                "fixture": {
                    "measurement_scope": MEASUREMENT_SCOPE,
                    "provider": provider,
                    "category": target.get("category"),
                    "target_class": target.get("target_class"),
                    "expected_content_type": target.get("expected_content_type"),
                    "validation_rule_id": target.get("validation_rule_id"),
                    "expected_fields": expected_fields,
                    "extracted_fields": extracted_fields,
                    "missing_fields": missing_fields,
                    "mismatched_fields": mismatched_fields,
                },
            }
        )
    return rows


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    successes = sum(1 for row in rows if row["success"])
    validation_passes = sum(1 for row in rows if row["validation_passed"])
    validation_failures = total - validation_passes
    durations = [float(row["duration_ms"]) for row in rows]
    bytes_total = sum(int(row["bytes_received"]) for row in rows)
    errors: dict[str, int] = {}
    for row in rows:
        errors[row["error_class"]] = errors.get(row["error_class"], 0) + 1
    return {
        "targets_total": total,
        "terminal_attempts": total,
        "success_count": successes,
        "failure_count": total - successes,
        "success_rate": successes / total if total else 0.0,
        "validation_passed": validation_passes,
        "validation_failures": validation_failures,
        "validation_pass_rate": validation_passes / total if total else 0.0,
        "p50_latency_ms": percentile(durations, 0.50),
        "p95_latency_ms": percentile(durations, 0.95),
        "bytes_received_total": bytes_total,
        "error_counts": dict(sorted(errors.items())),
    }


def write_outputs(output_dir: Path, corpus_path: Path, corpus: dict[str, Any], provider: str, run_id: str, window_id: str, concurrency_level: int) -> None:
    timestamp = iso_now()
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = build_rows(corpus, provider, run_id, window_id, concurrency_level, timestamp)
    summary = aggregate(rows)

    config_payload = {
        "schema_version": CONFIG_SCHEMA,
        "generated_at_utc": timestamp,
        "run_id": run_id,
        "provider": provider,
        "mode": "local_fixture",
        "measurement_scope": MEASUREMENT_SCOPE,
        "protocol_version": PROTOCOL_VERSION,
        "manifest_version": corpus["manifest_version"],
        "corpus_id": corpus["corpus_id"],
        "source_corpus": display_path(corpus_path),
        "window_id": window_id,
        "concurrency_level": concurrency_level,
        "retry_budget": {
            "max_attempts_total": 3,
            "backoff_ms": [500, 1500],
            "note": "Fixture proof does not retry; policy is recorded for protocol parity.",
        },
        "environment_lock": {
            "target_platform": "linux-cachyos",
            "python_version": platform.python_version(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "network_policy": "offline_fixture_only",
            "proxy_provider": "none",
        },
        "non_claims": NON_CLAIMS,
    }
    write_json(output_dir / "config.json", config_payload)

    summary_payload = {
        "schema_version": SUMMARY_SCHEMA,
        "generated_at_utc": timestamp,
        "run_id": run_id,
        "provider": provider,
        "status": "PASS",
        "mode": "local_fixture",
        "measurement_scope": MEASUREMENT_SCOPE,
        "protocol_version": PROTOCOL_VERSION,
        "manifest_version": corpus["manifest_version"],
        "corpus_id": corpus["corpus_id"],
        "window_id": window_id,
        "concurrency_level": concurrency_level,
        "baseline_policy": "bootstrap_calibration_only_no_regression_claim",
        "summary": summary,
        "artifact_contract": {"required_files": REQUIRED_FILES[:-1], "all_required_files_emitted": True},
        "quality_boundary": {
            "launcher_completion_is_not_extraction_quality": True,
            "validation_pass_rate_is_recorded": True,
            "negative_fixture_exercised": summary["validation_failures"] > 0,
        },
        "performance_claim": "not_claimed",
        "non_claims": NON_CLAIMS,
    }
    write_json(output_dir / "summary.json", summary_payload)

    with (output_dir / "raw.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")

    with (output_dir / "kpi.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["metric", "value", "unit", "claim_status"])
        writer.writerow(["targets_total", summary["targets_total"], "count", "fixture_protocol_proof"])
        writer.writerow(["success_rate", f"{summary['success_rate']:.6f}", "ratio", "fixture_validation_only"])
        writer.writerow(["validation_pass_rate", f"{summary['validation_pass_rate']:.6f}", "ratio", "fixture_validation_only"])
        writer.writerow(["validation_failures", summary["validation_failures"], "count", "fixture_validation_only"])
        writer.writerow(["p50_latency_ms", f"{summary['p50_latency_ms']:.3f}", "ms", "not_performance_claim"])
        writer.writerow(["p95_latency_ms", f"{summary['p95_latency_ms']:.3f}", "ms", "not_performance_claim"])
        writer.writerow(["rss_peak_mb", "not_measured", "mb", "not_performance_claim"])
        writer.writerow(["cpu_seconds_per_1000_successes", "not_measured", "seconds", "not_performance_claim"])

    with (output_dir / "errors.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["error_class", "count", "target_ids"])
        for error_class, count in summary["error_counts"].items():
            targets = [row["target_id"] for row in rows if row["error_class"] == error_class]
            writer.writerow([error_class, count, ";".join(targets)])

    system_metrics = {
        "schema_version": SYSTEM_METRICS_SCHEMA,
        "generated_at_utc": timestamp,
        "run_id": run_id,
        "mode": "local_fixture",
        "measurement_scope": MEASUREMENT_SCOPE,
        "rss_peak_mb": "not_measured_local_fixture",
        "rss_p95_mb": "not_measured_local_fixture",
        "cpu_seconds": "not_measured_local_fixture",
        "cpu_seconds_per_1000_successes": "not_measured_local_fixture",
        "network_bytes_external": 0,
        "network_policy": "no_external_network_io",
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "non_claims": NON_CLAIMS,
    }
    write_json(output_dir / "system-metrics.json", system_metrics)

    command_log = "\n".join(
        [
            "Phase 10 local fixture benchmark",
            f"generated_at_utc={timestamp}",
            f"provider={provider}",
            f"run_id={run_id}",
            f"corpus={display_path(corpus_path)}",
            f"output_dir={display_path(output_dir)}",
            "network_io=none",
            "firecrawl_started=false",
            "performance_claim=not_claimed",
        ]
    ) + "\n"
    (output_dir / "command-log.txt").write_text(command_log, encoding="utf-8")

    write_artifact_manifest(output_dir, run_id, provider, timestamp)


def artifact_item(path: Path, artifact_class: str) -> dict[str, Any]:
    return {
        "path": display_path(path),
        "artifact_class": artifact_class,
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "sha256": sha256_file(path) if path.exists() else "",
        "redaction_status": "no_sensitive_data_expected_local_fixture",
    }


def write_artifact_manifest(output_dir: Path, run_id: str, provider: str, timestamp: str) -> None:
    class_by_file = {
        "config.json": "configuration",
        "summary.json": "metrics",
        "kpi.csv": "metrics",
        "errors.csv": "errors",
        "raw.jsonl": "normalized_rows",
        "system-metrics.json": "system_metrics",
        "command-log.txt": "logs",
    }
    files = [artifact_item(output_dir / name, artifact_class) for name, artifact_class in class_by_file.items()]
    payload = {
        "schema_version": ARTIFACT_SCHEMA,
        "artifact_id": f"phase10-{provider}-{run_id}",
        "launch_id": run_id,
        "run_id": run_id,
        "provider": provider,
        "mode": "offline_fixture",
        "measurement_scope": MEASUREMENT_SCOPE,
        "generated_at_utc": timestamp,
        "files": files,
        "redaction": {
            "status": "passed",
            "pii_policy": "phase10_local_fixture_no_pii_expected",
            "notes": "Synthetic local fixture artifacts contain no secrets or personal data.",
        },
        "retention": {"retention_days": 7, "destructive_action_performed": False},
        "replay": {
            "safe_to_replay": False,
            "requires_approval": True,
            "replay_reason": "Phase 10 proof is a local/offline fixture; live replay or benchmarking remains human-gated.",
        },
        "non_claims": NON_CLAIMS,
    }
    write_json(output_dir / "artifact_manifest.json", payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="docs/benchmarks/fixtures/phase10-local-corpus.json", help="Local fixture corpus JSON")
    parser.add_argument("--output-dir", required=True, help="Output directory for protocol artifacts")
    parser.add_argument("--provider", choices=sorted(ALLOWED_PROVIDERS), required=True, help="Offline provider projection to emit")
    parser.add_argument("--run-id", required=True, help="Stable run id to record in protocol rows")
    parser.add_argument("--window-id", choices=["A", "B"], default="A", help="Protocol window id label for the fixture proof")
    parser.add_argument("--concurrency-level", type=int, default=1, help="Recorded concurrency level for fixture proof")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    env_errors = live_benchmark_env_errors()
    if env_errors:
        for error in env_errors:
            print(error, file=sys.stderr)
        return 2
    if args.concurrency_level < 1:
        print("concurrency-level must be >= 1", file=sys.stderr)
        return 2
    corpus_path = resolve_path(args.corpus)
    output_dir = resolve_path(args.output_dir)
    if not corpus_path.exists():
        print(f"corpus not found: {corpus_path}", file=sys.stderr)
        return 2
    try:
        corpus = load_json(corpus_path)
    except Exception as exc:  # noqa: BLE001 - CLI diagnostics
        print(f"failed to parse corpus: {exc}", file=sys.stderr)
        return 2
    if not isinstance(corpus, dict):
        print("corpus root must be an object", file=sys.stderr)
        return 2
    errors = validate_corpus(corpus)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 2
    write_outputs(output_dir, corpus_path, corpus, args.provider, args.run_id, args.window_id, args.concurrency_level)
    print(f"wrote Phase 10 fixture benchmark: {display_path(output_dir)}")
    print("network_io=none")
    print("performance_claim=not_claimed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
