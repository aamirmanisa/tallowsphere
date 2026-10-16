#!/usr/bin/env python3
"""Package a local Phase 7 artifact bundle and optional hash-checked manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_SCHEMA = "tallow.artifact_bundle.v1"
ARTIFACT_SCHEMA = "tallow.artifact_manifest.v1"


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_utc(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def resolve_path(path_arg: str) -> Path:
    path = Path(path_arg)
    return path if path.is_absolute() else ROOT / path


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify_bundle_file(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if "manifest" in name or name.endswith("report.json"):
        return "manifest"
    if suffix in {".csv", ".jsonl", ".ndjson"}:
        return "normalized_rows"
    if "metric" in name or "dashboard" in name or "summary" in name:
        return "metrics"
    if suffix == ".log" or "log" in name:
        return "logs"
    if "response" in name or "body" in name:
        return "raw_response"
    return "other"


def classify_artifact_file(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if "manifest" in name:
        return "manifest"
    if "metric" in name or "dashboard" in name or "replay" in name or suffix == ".md":
        return "metrics"
    if suffix in {".jsonl", ".ndjson", ".csv"}:
        return "normalized_rows"
    if suffix == ".log" or "log" in name:
        return "logs"
    return "other"


def bundle_source(source_dir: Path, bundle_dir: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for source_path in sorted(path for path in source_dir.rglob("*") if path.is_file()):
        relative = source_path.relative_to(source_dir)
        bundled_path = bundle_dir / relative
        bundled_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, bundled_path)
        source_sha = sha256_file(source_path)
        bundled_sha = sha256_file(bundled_path)
        if source_sha != bundled_sha:
            raise SystemExit(f"hash mismatch after copy: {source_path} -> {bundled_path}")
        files.append(
            {
                "relative_path": relative.as_posix(),
                "artifact_class": classify_bundle_file(source_path),
                "source": {
                    "path": str(source_path.resolve()),
                    "size_bytes": source_path.stat().st_size,
                    "sha256": source_sha,
                },
                "bundled": {
                    "path": str(bundled_path.resolve()),
                    "size_bytes": bundled_path.stat().st_size,
                    "sha256": bundled_sha,
                },
            }
        )
    return files


def write_bundle_manifest(source_dir: Path, output_root: Path, bundle_name: str, files: list[dict[str, Any]], generated_at: datetime) -> Path:
    bundle_dir = output_root / bundle_name
    counts: dict[str, int] = {}
    bytes_by_class: dict[str, int] = {}
    for item in files:
        cls = str(item["artifact_class"])
        counts[cls] = counts.get(cls, 0) + 1
        bytes_by_class[cls] = bytes_by_class.get(cls, 0) + int(item["source"]["size_bytes"])
    payload = {
        "schema_version": BUNDLE_SCHEMA,
        "generated_at_utc": iso_utc(generated_at),
        "bundle": {
            "bundle_name": bundle_name,
            "bundle_dir": str(bundle_dir.resolve()),
            "manifest_path": str((bundle_dir / "bundle_manifest.json").resolve()),
        },
        "source": {
            "launch_id": source_dir.name,
            "launch_dir": str(source_dir.resolve()),
            "has_launch_report": (source_dir / "launch_report.json").exists(),
            "launch_report_path": str((source_dir / "launch_report.json").resolve()) if (source_dir / "launch_report.json").exists() else None,
        },
        "summary": {
            "files_total": len(files),
            "classes": {"counts": dict(sorted(counts.items())), "bytes": dict(sorted(bytes_by_class.items()))},
            "bytes_source_total": sum(int(item["source"]["size_bytes"]) for item in files),
            "bytes_bundled_total": sum(int(item["bundled"]["size_bytes"]) for item in files),
        },
        "compression": {"enabled": False, "zip_path": None, "size_bytes": None, "sha256": None},
        "files": files,
    }
    manifest_path = bundle_dir / "bundle_manifest.json"
    manifest_path.write_text(stable_json(payload), encoding="utf-8")
    return manifest_path


def artifact_item(path: Path, artifact_class: str | None = None) -> dict[str, Any]:
    return {
        "path": display_path(path),
        "artifact_class": artifact_class or classify_artifact_file(path),
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "sha256": sha256_file(path) if path.exists() else "",
        "redaction_status": "redacted" if path.suffix.lower() in {".json", ".jsonl", ".ndjson", ".txt", ".md", ".csv"} else "not_applicable",
    }


def write_artifact_manifest(path: Path, artifact_id: str, bundle_manifest: Path, include_files: list[Path], generated_at: datetime) -> None:
    files = [artifact_item(bundle_manifest, "manifest")]
    files.extend(artifact_item(include_file) for include_file in include_files)
    payload = {
        "schema_version": ARTIFACT_SCHEMA,
        "artifact_id": artifact_id,
        "launch_id": artifact_id,
        "run_id": "phase7-local-artifacts-replay-observability",
        "generated_at_utc": iso_utc(generated_at),
        "files": files,
        "redaction": {
            "status": "passed",
            "pii_policy": "phase7_local_no_pii_expected_redacted_artifacts",
            "notes": "Phase 7 proof manifests only local/redacted reports and bundle manifests.",
        },
        "retention": {
            "retention_days": 7,
            "delete_after_utc": iso_utc(generated_at + timedelta(days=7)),
        },
        "replay": {
            "safe_to_replay": False,
            "requires_approval": True,
            "replay_reason": "Phase 7 proof defaults to dry-run replay; live replay remains human-gated.",
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(payload), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, help="Source run/artifact directory to copy into a bundle")
    parser.add_argument("--output-root", required=True, help="Bundle output root")
    parser.add_argument("--bundle-name", required=True, help="Bundle directory name")
    parser.add_argument("--include-file", action="append", default=[], help="Extra proof file to include in artifact manifest")
    parser.add_argument("--artifact-manifest-output", help="Optional tallow.artifact_manifest.v1 output path")
    parser.add_argument("--artifact-id", default="phase7-local-artifact-bundle", help="Artifact ID for optional artifact manifest")
    parser.add_argument("--force", action="store_true", help="Overwrite the target bundle directory if it already exists")
    args = parser.parse_args()

    source_dir = resolve_path(args.source_dir)
    output_root = resolve_path(args.output_root)
    bundle_dir = output_root / args.bundle_name
    include_files = [resolve_path(path) for path in args.include_file]
    if not source_dir.is_dir():
        print(f"source directory not found: {source_dir}", file=sys.stderr)
        return 2
    missing = [path for path in include_files if not path.exists()]
    if missing:
        print("included file(s) not found: " + ", ".join(str(path) for path in missing), file=sys.stderr)
        return 2
    if bundle_dir.exists():
        if not args.force:
            print(f"bundle directory already exists: {bundle_dir}; pass --force to overwrite", file=sys.stderr)
            return 2
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    generated_at = utc_now_dt()
    files = bundle_source(source_dir, bundle_dir)
    bundle_manifest = write_bundle_manifest(source_dir, output_root, args.bundle_name, files, generated_at)
    if args.artifact_manifest_output:
        write_artifact_manifest(resolve_path(args.artifact_manifest_output), args.artifact_id, bundle_manifest, include_files, generated_at)
    print(f"wrote bundle manifest: {display_path(bundle_manifest)}")
    if args.artifact_manifest_output:
        print(f"wrote artifact manifest: {display_path(resolve_path(args.artifact_manifest_output))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
