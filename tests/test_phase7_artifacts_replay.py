#!/usr/bin/env python3
"""Tests for Phase 7 local artifact/replay/observability tooling."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
METRICS_SCRIPT = ROOT / "scripts" / "extract_run_metrics.py"
DASHBOARD_SCRIPT = ROOT / "scripts" / "build_domain_dashboard.py"
REPLAY_SCRIPT = ROOT / "scripts" / "replay_failed_requests.py"
BUNDLE_SCRIPT = ROOT / "scripts" / "package_artifact_bundle.py"


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_execution_report() -> dict[str, Any]:
    return {
        "schema_version": "tallow.request_plan_run_report.v1",
        "generated_at_utc": "2026-06-13T00:00:00Z",
        "passed": False,
        "dry_run": False,
        "plan": {"manifest_id": "phase7-test-fixture", "request_count": 3},
        "summary": {
            "planned": 3,
            "executed": 3,
            "succeeded": 2,
            "failed": 1,
            "attempts": 4,
            "blocked": 0,
            "unsupported": 0,
        },
        "requests": [
            {
                "index": 0,
                "target_id": "ok_get",
                "method": "GET",
                "original_url": "https://shop.example.com/status",
                "executed_url": "http://127.0.0.1:9/status",
                "status": "succeeded",
                "http_status": 200,
                "error_kind": "none",
                "retryable": False,
                "attempts": 1,
                "attempt_records": [{"attempt": 1, "duration_ms": 10, "http_status": 200, "error_kind": "none", "success": True}],
                "is_graphql": False,
                "artifacts": {"response_body": "requests/0000/response.body.redacted.txt"},
            },
            {
                "index": 1,
                "target_id": "ok_graphql",
                "method": "POST",
                "original_url": "https://api.example.com/graphql",
                "executed_url": "http://127.0.0.1:9/graphql",
                "status": "succeeded",
                "http_status": 200,
                "error_kind": "none",
                "retryable": False,
                "attempts": 1,
                "attempt_records": [{"attempt": 1, "duration_ms": 20, "http_status": 200, "error_kind": "none", "success": True}],
                "is_graphql": True,
                "graphql": {"operation_type": "query", "operation_name": "Products"},
                "artifacts": {"response_body": "requests/0001/response.body.redacted.txt"},
            },
            {
                "index": 2,
                "target_id": "retryable_failure",
                "method": "GET",
                "original_url": "https://other.test/retry",
                "executed_url": "http://127.0.0.1:9/retry",
                "status": "failed",
                "http_status": 500,
                "error_kind": "http_5xx",
                "retryable": True,
                "attempts": 2,
                "attempt_records": [
                    {"attempt": 1, "duration_ms": 30, "http_status": 500, "error_kind": "http_5xx", "success": False},
                    {"attempt": 2, "duration_ms": 40, "http_status": 500, "error_kind": "http_5xx", "success": False},
                ],
                "is_graphql": False,
                "artifacts": {"response_body": "requests/0002/response.body.redacted.txt"},
            },
        ],
    }


class Phase7ToolingTests(unittest.TestCase):
    def run_script(self, script: Path, *args: str, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(script), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )

    def assert_manifest_hashes(self, manifest_path: Path) -> None:
        manifest = read_json(manifest_path)
        self.assertEqual(manifest["schema_version"], "tallow.artifact_manifest.v1")
        self.assertFalse(manifest["replay"]["safe_to_replay"])
        self.assertTrue(manifest["replay"]["requires_approval"])
        for item in manifest["files"]:
            path = ROOT / item["path"]
            self.assertTrue(path.exists(), item["path"])
            self.assertEqual(item["size_bytes"], path.stat().st_size, item["path"])
            self.assertEqual(item["sha256"], sha256_file(path), item["path"])

    def test_cli_help_exists_for_linux_native_phase7_tools(self) -> None:
        for script in (METRICS_SCRIPT, DASHBOARD_SCRIPT, REPLAY_SCRIPT, BUNDLE_SCRIPT):
            result = self.run_script(script, "--help")
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("usage:", result.stdout)

    def test_extract_metrics_and_dashboard_from_request_plan_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            report_path = temp / "execution_report.json"
            metrics_json = temp / "run_metrics.json"
            metrics_md = temp / "run_metrics.md"
            dashboard_json = temp / "domain_dashboard.json"
            dashboard_csv = temp / "domain_dashboard.csv"
            write_json(report_path, fixture_execution_report())

            metrics = self.run_script(
                METRICS_SCRIPT,
                "--execution-report",
                str(report_path),
                "--output-json",
                str(metrics_json),
                "--output-markdown",
                str(metrics_md),
            )
            dashboard = self.run_script(
                DASHBOARD_SCRIPT,
                "--execution-report",
                str(report_path),
                "--output-json",
                str(dashboard_json),
                "--output-csv",
                str(dashboard_csv),
            )

            self.assertEqual(metrics.returncode, 0, metrics.stderr + metrics.stdout)
            self.assertEqual(dashboard.returncode, 0, dashboard.stderr + dashboard.stdout)
            metrics_payload = read_json(metrics_json)
            dashboard_payload = read_json(dashboard_json)
            self.assertEqual(metrics_payload["schema_version"], "tallow.run_metrics.v1")
            self.assertEqual(metrics_payload["summary"]["planned"], 3)
            self.assertEqual(metrics_payload["summary"]["attempts"], 4)
            self.assertEqual(metrics_payload["quality"]["success_rate"], 2 / 3)
            self.assertEqual(metrics_payload["quality"]["retry_rate"], 1 / 4)
            self.assertEqual(metrics_payload["latency"]["p95_ms"], 40)
            self.assertIn("tallow.run_metrics.v1", metrics_md.read_text(encoding="utf-8"))
            self.assertEqual(dashboard_payload["schema_version"], "tallow.domain_dashboard.v1")
            self.assertEqual(dashboard_payload["domains_total"], 2)
            domains = {item["domain"]: item for item in dashboard_payload["domains"]}
            self.assertEqual(domains["example.com"]["success_count"], 2)
            self.assertEqual(domains["other.test"]["fail_count"], 1)
            self.assertIn("domain,attempts_total,success_count", dashboard_csv.read_text(encoding="utf-8"))

    def test_replay_defaults_to_dry_run_and_refuses_live_execute(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            report_path = temp / "execution_report.json"
            replay_report = temp / "failure_replay_report.json"
            live_report = temp / "live_replay_report.json"
            write_json(report_path, fixture_execution_report())

            dry_run = self.run_script(
                REPLAY_SCRIPT,
                "--execution-report",
                str(report_path),
                "--report-path",
                str(replay_report),
            )
            live_refusal = self.run_script(
                REPLAY_SCRIPT,
                "--execution-report",
                str(report_path),
                "--report-path",
                str(live_report),
                "--execute",
                "--network-scope",
                "live",
            )

            self.assertEqual(dry_run.returncode, 0, dry_run.stderr + dry_run.stdout)
            payload = read_json(replay_report)
            self.assertEqual(payload["schema_version"], "tallow.failure_replay.v1")
            self.assertTrue(payload["dry_run"])
            self.assertEqual(payload["counts"]["candidates_total"], 1)
            self.assertEqual(payload["counts"]["replay_attempted"], 0)
            self.assertTrue(payload["non_claims"]["no_network_io_performed"])
            self.assertEqual(live_refusal.returncode, 2, live_refusal.stderr + live_refusal.stdout)
            self.assertIn("live replay requires explicit human approval", live_refusal.stderr + live_refusal.stdout)

    def test_package_bundle_writes_hash_checked_bundle_and_artifact_manifest(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase7" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            source = temp / "source_run"
            source.mkdir()
            write_json(source / "execution_report.json", fixture_execution_report())
            (source / "requests.jsonl").write_text('{"target_id":"ok_get"}\n', encoding="utf-8")
            metrics = temp / "run_metrics.json"
            replay = temp / "failure_replay_report.json"
            write_json(metrics, {"schema_version": "tallow.run_metrics.v1", "summary": {"planned": 3}})
            write_json(replay, {"schema_version": "tallow.failure_replay.v1", "dry_run": True})
            output_root = temp / "bundles"
            manifest_path = temp / "artifact_manifest.json"

            result = self.run_script(
                BUNDLE_SCRIPT,
                "--source-dir",
                str(source),
                "--output-root",
                str(output_root),
                "--bundle-name",
                "phase7-test-bundle",
                "--include-file",
                str(metrics),
                "--include-file",
                str(replay),
                "--artifact-manifest-output",
                str(manifest_path),
                "--artifact-id",
                "phase7-test-artifacts",
                "--force",
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            bundle_manifest = output_root / "phase7-test-bundle" / "bundle_manifest.json"
            self.assertTrue(bundle_manifest.exists())
            bundle_payload = read_json(bundle_manifest)
            self.assertEqual(bundle_payload["schema_version"], "tallow.artifact_bundle.v1")
            self.assertEqual(bundle_payload["summary"]["files_total"], 2)
            for item in bundle_payload["files"]:
                bundled_path = Path(item["bundled"]["path"])
                self.assertTrue(bundled_path.exists())
                self.assertEqual(item["source"]["sha256"], item["bundled"]["sha256"])
            self.assert_manifest_hashes(manifest_path)
            artifact_payload = read_json(manifest_path)
            manifest_paths = {item["path"] for item in artifact_payload["files"]}
            self.assertIn(str(bundle_manifest.resolve().relative_to(ROOT)), manifest_paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)
