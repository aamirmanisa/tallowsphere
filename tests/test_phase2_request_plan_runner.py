#!/usr/bin/env python3
"""Tests for the Phase 2 request-plan runtime runner."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_tallow_request_plan.py"


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compliance() -> dict[str, Any]:
    return {
        "source_authority": "public_web",
        "purpose": "phase2_runner_test",
        "legal_basis": "legitimate_interest",
        "pii_policy": "no_pii_expected",
        "retention_days": 7,
        "robots_mode": "strict",
    }


def base_plan(requests: list[dict[str, Any]], source_manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    for index, request in enumerate(requests):
        request.setdefault("index", index)
        request.setdefault("headers", {"Accept": "application/json"})
        request.setdefault("compliance", compliance())
    plan = {
        "schema_version": "tallow.request_plan.v1",
        "manifest_id": "runner-test-plan",
        "request_count": len(requests),
        "requests": requests,
        "legacy_http_batch": {
            "compatible": False,
            "blocked_reasons": ["runner test uses direct request-plan execution"],
            "headers": {},
            "target_urls": [request["url"] for request in requests],
        },
        "status_boundary": "test fixture for direct request-plan runner",
    }
    if source_manifest is not None:
        plan["source_manifest"] = source_manifest
    return plan


def source_manifest_ref(manifest_path: Path) -> dict[str, Any]:
    raw = manifest_path.read_bytes()
    return {
        "path": str(manifest_path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "schema_version": "tallow.target_manifest.v2",
    }


def policy_manifest(url: str, *, deny_patterns: list[str] | None = None, robots_mode: str = "strict") -> dict[str, Any]:
    host = urllib.parse.urlparse(url).hostname or "127.0.0.1"
    return {
        "schema_version": "tallow.target_manifest.v2",
        "manifest_id": "runner-test-policy-manifest",
        "targets": [
            {
                "id": "local_status",
                "url": url,
                "method": "GET",
                "headers": {},
                "compliance": {**compliance(), "requires_approval": False, "robots_mode": robots_mode},
            }
        ],
        "policy": {
            "allowlist": {"domains": [host], "url_patterns": [f"{url.rsplit('/', 1)[0]}/*"]},
            "denylist": {"domains": [], "url_patterns": deny_patterns or []},
            "robots": {"mode": robots_mode},
            "rate_limits": {"per_domain": {host: {"requests_per_minute": 60, "concurrent": 1}}},
        },
    }


def compliance_gate_report(source_manifest_path: Path, *, target_id: str = "local_status") -> dict[str, Any]:
    return {
        "schema_version": "tallow.compliance_gate_report.v1",
        "generated_at_utc": "2026-06-22T00:00:00Z",
        "passed": True,
        "mode": "local_no_secret_proof",
        "network_scope": "local",
        "target_manifest": {
            "path": str(source_manifest_path),
            "schema_version": "tallow.target_manifest.v2",
            "manifest_id": "runner-test-policy-manifest",
            "sha256": hashlib.sha256(source_manifest_path.read_bytes()).hexdigest(),
        },
        "summary": {
            "targets_total": 1,
            "targets_with_auth_ref": 0,
            "violations_count": 0,
            "warnings_count": 0,
            "redaction_findings_total": 0,
            "retention_plans_total": 1,
        },
        "production_gate": {
            "approval_id": "",
            "legal_metadata_status": "complete",
            "redaction_status": "passed",
            "retention_status": "dry_run_only",
            "accepted_for_live_preflight": True,
            "accepted_for_live_execution": False,
            "network_io_performed": False,
            "destructive_retention_performed": False,
        },
        "legal": {"targets": [{"target_id": target_id, **compliance()}]},
        "gates": [],
        "violations": [],
        "warnings": [],
        "vault": {
            "resolver": "fake_local_reference_only",
            "references_total": 0,
            "references": [],
            "no_secret_material_resolved": True,
            "secret_material_serialized": False,
            "real_vault_contacted": False,
        },
        "redaction": {
            "scanner": "test_fixture",
            "paths_scanned": [],
            "findings_total": 0,
            "findings": [],
            "raw_values_emitted": False,
        },
        "retention": {
            "dry_run": True,
            "requested_action": "dry-run",
            "destructive_action_performed": False,
            "plans": [{"target_id": target_id, "retention_days": 7, "delete_after_utc": "2026-06-29T00:00:00Z", "action": "plan_only_no_delete"}],
        },
        "non_claims": {
            "no_live_external_scraping": True,
            "no_real_secret_material": True,
            "no_real_vault_configuration": True,
            "no_destructive_retention_purge": True,
            "no_production_compliance_readiness": True,
        },
    }


class RecordingHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def _record_and_reply(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length) if length else b""
        body_text = raw_body.decode("utf-8", errors="replace")
        parsed_json: Any = None
        if body_text:
            try:
                parsed_json = json.loads(body_text)
            except json.JSONDecodeError:
                parsed_json = None
        server = cast(RecordingServer, self.server)
        with server.lock:
            server.requests.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "headers": {key: value for key, value in self.headers.items()},
                    "body": body_text,
                    "json": parsed_json,
                }
            )
            count_for_path = sum(1 for request in server.requests if request["path"] == self.path)
        if self.path.startswith("/retry") and count_for_path == 1:
            status = 500
            payload = {"ok": False, "method": self.command, "path": self.path, "attempt": count_for_path}
        elif self.path.startswith("/products"):
            status = 200
            host = self.headers.get("Host") or "127.0.0.1"
            payload = {
                "products": [
                    {
                        "name": "Local Mock Granola",
                        "price": {"amount": 4.99, "currency": "USD", "cents": 499},
                        "url": f"http://{host}/products/granola",
                    }
                ]
            }
        else:
            status = 200
            payload = {
                "ok": True,
                "method": self.command,
                "path": self.path,
                "json": parsed_json,
                "attempt": count_for_path,
            }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback
        self._record_and_reply()

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback
        self._record_and_reply()


class RecordingServer(ThreadingHTTPServer):
    requests: list[dict[str, Any]]
    lock: threading.Lock


class LoopbackServer:
    def __enter__(self) -> "LoopbackServer":
        self.httpd = RecordingServer(("127.0.0.1", 0), RecordingHandler)
        self.httpd.requests = []
        self.httpd.lock = threading.Lock()
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.httpd.shutdown()
        self.thread.join(timeout=3)
        self.httpd.server_close()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}"

    @property
    def requests(self) -> list[dict[str, Any]]:
        with self.httpd.lock:
            return list(self.httpd.requests)


class RequestPlanRunnerTests(unittest.TestCase):
    def run_runner(self, *args: str, timeout: float = 8.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )

    def test_dry_run_writes_report_without_hitting_local_server(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            write_json(
                plan_path,
                base_plan(
                    [
                        {"target_id": "local_status", "url": f"{server.base_url}/status", "method": "GET"},
                        {
                            "target_id": "local_graphql",
                            "url": f"{server.base_url}/graphql",
                            "method": "POST",
                            "body": {
                                "kind": "json",
                                "value": {"query": "query Products { products { name } }"},
                                "content_type": "application/json",
                                "redaction": "hash",
                            },
                            "graphql": {"operation_type": "query", "operation_name": "Products"},
                        },
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir), "--dry-run")

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], "tallow.request_plan_run_report.v1")
            self.assertTrue(report["dry_run"])
            self.assertEqual(report["summary"]["planned"], 2)
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertEqual([request["status"] for request in report["requests"]], ["planned", "planned"])

    def test_live_preflight_network_scope_validates_policy_without_hitting_server(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            manifest_path = temp / "manifest.json"
            report_path = temp / "report.json"
            compliance_report_path = temp / "compliance_audit_report.json"
            output_dir = temp / "run"
            url = f"{server.base_url}/status"
            write_json(manifest_path, policy_manifest(url, deny_patterns=[]))
            write_json(
                plan_path,
                base_plan(
                    [{"target_id": "local_status", "url": url, "method": "GET"}],
                    source_manifest=source_manifest_ref(manifest_path),
                ),
            )
            write_json(compliance_report_path, compliance_gate_report(manifest_path, target_id="local_status"))

            result = self.run_runner(
                "--plan",
                str(plan_path),
                "--report-path",
                str(report_path),
                "--output-dir",
                str(output_dir),
                "--network-scope",
                "live-preflight",
                "--compliance-gate-report",
                str(compliance_report_path),
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["mode"]["network_scope"], "live-preflight")
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertEqual(report["summary"]["blocked"], 0)
            self.assertEqual(report["requests"][0]["status"], "policy_preflight_passed")
            self.assertEqual(report["gates"][-1]["name"], "live_policy_preflight")
            self.assertEqual(report["gates"][-1]["status"], "pass")

    def test_p1_010_live_preflight_requires_compliance_gate_report_before_network(self) -> None:
        """RED/P1-010: no live/live-preflight run may pass without a gate report."""
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            manifest_path = temp / "manifest.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            url = f"{server.base_url}/status"
            write_json(manifest_path, policy_manifest(url, deny_patterns=[]))
            write_json(
                plan_path,
                base_plan(
                    [{"target_id": "local_status", "url": url, "method": "GET"}],
                    source_manifest=source_manifest_ref(manifest_path),
                ),
            )

            result = self.run_runner(
                "--plan",
                str(plan_path),
                "--report-path",
                str(report_path),
                "--output-dir",
                str(output_dir),
                "--network-scope",
                "live-preflight",
            )

            self.assertEqual(server.requests, [])
            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertFalse(report["passed"])
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertEqual(report["summary"]["blocked"], 1)
            self.assertEqual(report["requests"][0]["status"], "blocked")
            codes = {reason["code"] for reason in report["requests"][0]["blocked_reasons"]}
            self.assertIn("compliance_gate_report_required", codes)
            self.assertEqual(report["gates"][-1]["name"], "production_compliance_gate")
            self.assertEqual(report["gates"][-1]["status"], "fail")

    def test_p1_010_live_preflight_rejects_gate_report_missing_legal_metadata_before_network(self) -> None:
        """RED/P1-010: an attached but incomplete compliance report is fail-closed."""
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            manifest_path = temp / "manifest.json"
            compliance_report_path = temp / "compliance_audit_report.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            url = f"{server.base_url}/status"
            write_json(manifest_path, policy_manifest(url, deny_patterns=[]))
            source_ref = source_manifest_ref(manifest_path)
            write_json(
                plan_path,
                base_plan(
                    [{"target_id": "local_status", "url": url, "method": "GET"}],
                    source_manifest=source_ref,
                ),
            )
            write_json(
                compliance_report_path,
                {
                    "schema_version": "tallow.compliance_gate_report.v1",
                    "passed": True,
                    "network_scope": "local",
                    "target_manifest": {"sha256": source_ref["sha256"]},
                    "summary": {"violations_count": 0, "redaction_findings_total": 0},
                    "redaction": {"raw_values_emitted": False, "findings_total": 0, "findings": []},
                    "retention": {"destructive_action_performed": False, "dry_run": True, "plans": []},
                    "vault": {"real_vault_contacted": False, "no_secret_material_resolved": True},
                    "non_claims": {"no_real_secret_material": True},
                },
            )

            result = self.run_runner(
                "--plan",
                str(plan_path),
                "--report-path",
                str(report_path),
                "--output-dir",
                str(output_dir),
                "--network-scope",
                "live-preflight",
                "--compliance-gate-report",
                str(compliance_report_path),
            )

            self.assertEqual(server.requests, [])
            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["executed"], 0)
            codes = {reason["code"] for reason in report["requests"][0]["blocked_reasons"]}
            self.assertIn("compliance_gate_legal_metadata_missing", codes)

    def test_manifest_denylist_blocks_before_local_network_io(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            manifest_path = temp / "manifest.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            url = f"{server.base_url}/status"
            write_json(manifest_path, policy_manifest(url, deny_patterns=[url]))
            write_json(
                plan_path,
                base_plan(
                    [{"target_id": "local_status", "url": url, "method": "GET"}],
                    source_manifest=source_manifest_ref(manifest_path),
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["passed"], False)
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertEqual(report["summary"]["blocked"], 1)
            self.assertEqual(report["requests"][0]["status"], "blocked")
            self.assertEqual(report["requests"][0]["blocked_reasons"][0]["code"], "policy_denylist")
            self.assertEqual(report["gates"][-1]["name"], "request_policy")
            self.assertEqual(report["gates"][-1]["status"], "fail")

    def test_attached_missing_source_manifest_blocks_before_local_network_io(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            missing_manifest = temp / "missing.target-manifest.v2.json"
            write_json(
                plan_path,
                base_plan(
                    [{"target_id": "local_status", "url": f"{server.base_url}/status", "method": "GET"}],
                    source_manifest={
                        "path": str(missing_manifest),
                        "sha256": "0" * 64,
                        "schema_version": "tallow.target_manifest.v2",
                    },
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["passed"], False)
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertEqual(report["summary"]["blocked"], 1)
            self.assertEqual(report["requests"][0]["status"], "blocked")
            self.assertEqual(report["requests"][0]["blocked_reasons"][0]["code"], "source_manifest_missing")
            self.assertIn("source manifest file does not exist", result.stderr)

    def test_attached_directory_source_manifest_blocks_with_report(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            write_json(
                plan_path,
                base_plan(
                    [{"target_id": "local_status", "url": f"{server.base_url}/status", "method": "GET"}],
                    source_manifest={
                        "path": str(temp),
                        "sha256": "0" * 64,
                        "schema_version": "tallow.target_manifest.v2",
                    },
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["passed"], False)
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertEqual(report["summary"]["blocked"], 1)
            self.assertEqual(report["requests"][0]["status"], "blocked")
            self.assertEqual(report["requests"][0]["blocked_reasons"][0]["code"], "source_manifest_invalid")

    def test_attached_invalid_json_source_manifest_blocks_with_report(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            manifest_path = temp / "invalid.target-manifest.v2.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            manifest_path.write_text("{not json", encoding="utf-8")
            write_json(
                plan_path,
                base_plan(
                    [{"target_id": "local_status", "url": f"{server.base_url}/status", "method": "GET"}],
                    source_manifest=source_manifest_ref(manifest_path),
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["blocked"], 1)
            self.assertEqual(report["requests"][0]["blocked_reasons"][0]["code"], "source_manifest_invalid")

    def test_plan_level_source_manifest_block_applies_to_every_request(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            missing_manifest = temp / "missing.target-manifest.v2.json"
            write_json(
                plan_path,
                base_plan(
                    [
                        {"target_id": "local_status", "url": f"{server.base_url}/status", "method": "GET"},
                        {"target_id": "local_other", "url": f"{server.base_url}/other", "method": "GET"},
                    ],
                    source_manifest={
                        "path": str(missing_manifest),
                        "sha256": "0" * 64,
                        "schema_version": "tallow.target_manifest.v2",
                    },
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["blocked"], 2)
            self.assertEqual([row["status"] for row in report["requests"]], ["blocked", "blocked"])
            self.assertEqual([row["blocked_reasons"][0]["code"] for row in report["requests"]], ["source_manifest_missing", "source_manifest_missing"])

    def test_runner_reports_versioned_execution_core_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            write_json(
                plan_path,
                base_plan([
                    {"target_id": "local_status", "url": f"{server.base_url}/status", "method": "GET"},
                ]),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir), "--dry-run")

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            core = report["execution_core"]
            self.assertEqual(core["schema_version"], "tallow.request_plan_execution_contract.v1")
            self.assertEqual(core["version"], "request-plan-execution-core-v1")
            self.assertEqual(core["source"], "schemas/tallow/request-plan-execution-contract.v1.json")
            self.assertEqual(core["role"], "python_compatibility_bridge")
            self.assertEqual(len(core["sha256"]), 64)
            self.assertTrue(all(char in "0123456789abcdef" for char in core["sha256"]))
            self.assertIn("GET", core["supported_methods"])
            self.assertIn("POST", core["supported_methods"])
            self.assertEqual(core["max_response_bytes_default"], 1_048_576)

    def test_get_and_post_graphql_loopback_execution_records_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            graphql_body = {"query": "query Products($limit:Int!){ products(limit:$limit){ name } }", "variables": {"limit": 2}}
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "local_status",
                            "url": f"{server.base_url}/status?x=1",
                            "method": "GET",
                            "headers": {"Accept": "application/json", "X-Target": "status"},
                        },
                        {
                            "target_id": "local_graphql",
                            "url": f"{server.base_url}/graphql",
                            "method": "POST",
                            "headers": {"Accept": "application/json", "X-Target": "graphql"},
                            "body": {
                                "kind": "json",
                                "value": graphql_body,
                                "content_type": "application/json",
                                "redaction": "hash",
                            },
                            "artifact_policy": {
                                "capture_body": "redacted",
                                "response_snippet_bytes": 4096,
                                "screenshots": "never",
                                "har": "never",
                            },
                            "graphql": {
                                "operation_type": "query",
                                "operation_name": "Products",
                                "variables": {"limit": 2},
                            },
                        },
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(len(server.requests), 2)
            self.assertEqual(server.requests[0]["method"], "GET")
            self.assertEqual(server.requests[0]["path"], "/status?x=1")
            self.assertEqual(server.requests[0]["headers"].get("X-Target"), "status")
            self.assertEqual(server.requests[1]["method"], "POST")
            self.assertEqual(server.requests[1]["path"], "/graphql")
            self.assertIn("application/json", server.requests[1]["headers"].get("Content-Type", ""))
            self.assertEqual(server.requests[1]["json"], graphql_body)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["summary"]["executed"], 2)
            self.assertEqual(report["summary"]["succeeded"], 2)
            self.assertEqual(report["requests"][1]["is_graphql"], True)
            self.assertEqual(report["requests"][1]["graphql"]["operation_name"], "Products")
            self.assertNotIn("query Products", json.dumps(report), "raw GraphQL body should not be embedded in report JSON")
            response_body_rel = report["requests"][1]["artifacts"]["response_body"]
            self.assertIsNotNone(response_body_rel)
            response_body = (output_dir / response_body_rel).read_text(encoding="utf-8")
            self.assertNotIn("query Products", response_body)
            self.assertNotIn("products(limit", response_body)
            self.assertIn("<redacted:sha256:", response_body)

    def test_retry_and_artifact_manifest_for_local_retryable_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "local_retry",
                            "url": f"{server.base_url}/retry",
                            "method": "GET",
                            "retry": {"max_attempts": 2, "retry_on_error_kinds": ["http_5xx"], "backoff_ms": [0]},
                            "artifact_policy": {
                                "capture_body": "redacted",
                                "response_snippet_bytes": 120,
                                "screenshots": "never",
                                "har": "never",
                            },
                        }
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(len(server.requests), 2)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["attempts"], 2)
            self.assertEqual(report["requests"][0]["attempts"], 2)
            self.assertEqual(report["requests"][0]["http_status"], 200)
            manifest_path = output_dir / "artifact_manifest.json"
            self.assertTrue(manifest_path.exists())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], "tallow.artifact_manifest.v1")
            body_rel = report["requests"][0]["artifacts"]["response_body"]
            self.assertTrue((output_dir / body_rel).exists())

    def test_unsupported_browser_auth_artifact_policy_fail_closed_without_requests(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "needs_browser",
                            "url": f"{server.base_url}/browser",
                            "method": "GET",
                            "browser_fallback": {"mode": "reasoned", "reasons": ["requires_javascript"]},
                        },
                        {
                            "target_id": "needs_null_browser_mode",
                            "url": f"{server.base_url}/null-browser-mode",
                            "method": "GET",
                            "browser_fallback": {"mode": None},
                        },
                        {
                            "target_id": "needs_bool_browser_mode",
                            "url": f"{server.base_url}/bool-browser-mode",
                            "method": "GET",
                            "browser_fallback": {"mode": True},
                        },
                        {"target_id": "needs_auth", "url": f"{server.base_url}/auth", "method": "GET", "auth_ref": "vault://phase2/test"},
                        {
                            "target_id": "needs_har",
                            "url": f"{server.base_url}/har",
                            "method": "GET",
                            "artifact_policy": {"capture_body": "redacted", "screenshots": "never", "har": "always"},
                        },
                        {
                            "target_id": "needs_dom",
                            "url": f"{server.base_url}/dom",
                            "method": "GET",
                            "artifact_policy": {"capture_body": "redacted", "screenshots": "never", "har": "never", "dom": "always"},
                        },
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            self.assertIn("request plan refused", result.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertFalse(report["passed"])
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertGreaterEqual(report["summary"]["blocked"], 6)
            reasons = "\n".join(reason["field"] for reason in report["unsupported"])
            self.assertIn("browser_fallback.mode", reasons)
            self.assertIn("auth_ref", reasons)
            self.assertIn("artifact_policy.har", reasons)
            self.assertIn("artifact_policy.dom", reasons)
            codes = {reason["code"] for reason in report["unsupported"]}
            self.assertIn("live_browser_fallback_not_enabled", codes)
            self.assertIn("browser_artifact_capture_not_enabled", codes)
            self.assertIn("invalid_browser_fallback", codes)
            self.assertEqual(report["browser_fallback"]["websocket_cdp"], "not_implemented")
            self.assertEqual(report["browser_fallback"]["pipe_transport"], "fail_closed")
            self.assertEqual(report["non_claims"]["browser_execution"], False)

    def test_extraction_schema_ref_executes_and_writes_validated_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            schema_ref = "schemas/tallow/examples/product-listing.extraction.schema.json"
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "local_product",
                            "url": f"{server.base_url}/products",
                            "method": "GET",
                            "extraction_schema_ref": schema_ref,
                        }
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(len(server.requests), 1)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["summary"]["executed"], 1)
            self.assertEqual(report["summary"]["extraction_rows"], 1)
            self.assertEqual(report["summary"]["extraction_quarantined"], 0)
            extraction = report["output"]["extraction"]
            rows_path = output_dir / extraction["rows"]
            quarantine_path = output_dir / extraction["quarantine"]
            validation_path = output_dir / extraction["validation_report"]
            self.assertTrue(rows_path.exists())
            self.assertTrue(quarantine_path.exists())
            self.assertTrue(validation_path.exists())
            rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["schema_version"], "tallow.extraction_row.v1")
            self.assertEqual(row["status"], "accepted")
            self.assertEqual(row["target_id"], "local_product")
            self.assertEqual(row["fields"]["name"]["value"], "Local Mock Granola")
            self.assertEqual(row["fields"]["name"]["selector_kind"], "json_path")
            self.assertEqual(row["fields"]["price"]["value"]["cents"], 499)
            self.assertEqual(row["fields"]["url"]["value"], f"{server.base_url}/products/granola")
            validation = json.loads(validation_path.read_text(encoding="utf-8"))
            self.assertTrue(validation["passed"])
            self.assertEqual(validation["rows_valid"], 1)
            manifest = json.loads((output_dir / "artifact_manifest.json").read_text(encoding="utf-8"))
            manifest_paths = {entry["path"] for entry in manifest["files"]}
            self.assertIn(extraction["rows"], manifest_paths)
            self.assertIn(extraction["quarantine"], manifest_paths)
            self.assertIn(extraction["validation_report"], manifest_paths)

    def test_extraction_schema_ref_quarantines_required_selector_misses(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            schema_ref = "schemas/tallow/examples/product-listing.extraction.schema.json"
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "missing_product_name",
                            "url": f"{server.base_url}/status",
                            "method": "GET",
                            "extraction_schema_ref": schema_ref,
                        }
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(len(server.requests), 1)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["summary"]["extraction_rows"], 1)
            self.assertEqual(report["summary"]["extraction_quarantined"], 1)
            extraction = report["output"]["extraction"]
            rows = [
                json.loads(line)
                for line in (output_dir / extraction["rows"]).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            quarantined = [
                json.loads(line)
                for line in (output_dir / extraction["quarantine"]).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(rows[0]["status"], "quarantined")
            self.assertEqual(quarantined[0]["row_id"], rows[0]["row_id"])
            self.assertIn("required_field_null:name", rows[0]["quality"]["quarantine_reasons"])
            validation = json.loads((output_dir / extraction["validation_report"]).read_text(encoding="utf-8"))
            self.assertTrue(validation["passed"])
            self.assertEqual(validation["rows_quarantined"], 1)
            self.assertEqual(validation["error_counts"]["required_field_null"], 1)

    def test_sensitive_literal_headers_fail_closed_and_snapshot_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            secret = "Bearer phase2-secret-canary"
            api_key = "phase2-api-key-canary"
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "literal_secret_header",
                            "url": f"{server.base_url}/secret",
                            "method": "GET",
                            "headers": {"Accept": "application/json", "Authorization": secret, "X-Api-Key": api_key},
                        }
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("sensitive_header", report_text)
            self.assertNotIn(secret, report_text)
            self.assertNotIn(api_key, report_text)
            snapshot_text = (output_dir / "request_plan.v1.json").read_text(encoding="utf-8")
            self.assertNotIn(secret, snapshot_text)
            self.assertNotIn(api_key, snapshot_text)
            self.assertIn("<redacted:sha256:", snapshot_text)

    def test_token_like_literal_header_names_fail_closed_and_snapshot_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            token = "phase2-access-token-canary"
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "literal_token_header",
                            "url": f"{server.base_url}/secret",
                            "method": "GET",
                            "headers": {"Accept": "application/json", "X-Access-Token": token},
                        }
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("sensitive_header", report_text)
            self.assertNotIn(token, report_text)
            snapshot_text = (output_dir / "request_plan.v1.json").read_text(encoding="utf-8")
            self.assertNotIn(token, snapshot_text)
            self.assertIn("<redacted:sha256:", snapshot_text)

    def test_real_vault_auth_ref_fails_closed_with_redacted_resolution_report(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            raw_auth_ref = "vault://aws-sm/prod/phase2-canary-token"
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "real_vault_ref",
                            "url": f"{server.base_url}/secret",
                            "method": "GET",
                            "auth_ref": raw_auth_ref,
                        }
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("unsupported_vault_provider", report_text)
            self.assertNotIn(raw_auth_ref, report_text)
            snapshot_text = (output_dir / "request_plan.v1.json").read_text(encoding="utf-8")
            self.assertNotIn(raw_auth_ref, snapshot_text)
            vault_text = (output_dir / "vault_resolution_report.json").read_text(encoding="utf-8")
            self.assertNotIn(raw_auth_ref, vault_text)
            vault_report = json.loads(vault_text)
            self.assertFalse(vault_report["secret_material_serialized"])
            self.assertFalse(vault_report["real_vault_contacted"])
            self.assertEqual(vault_report["references_total"], 1)
            reference = vault_report["references"][0]
            self.assertEqual(reference["provider_id"], "aws-sm")
            self.assertEqual(reference["resolution_status"], "unsupported_provider_fail_closed")
            self.assertEqual(reference["reference_hash"], hashlib.sha256(raw_auth_ref.encode("utf-8")).hexdigest())
            self.assertFalse(reference["secret_material_serialized"])
            self.assertFalse(reference["real_vault_contacted"])

    def test_fake_local_vault_auth_ref_dry_run_serializes_only_redacted_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            raw_auth_ref = "vault://local/phase2-demo-token"
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "fake_local_vault_ref",
                            "url": f"{server.base_url}/status",
                            "method": "GET",
                            "auth_ref": raw_auth_ref,
                        }
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir), "--dry-run")

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            for path in (report_path, output_dir / "request_plan.v1.json", output_dir / "vault_resolution_report.json", output_dir / "requests.jsonl"):
                self.assertNotIn(raw_auth_ref, path.read_text(encoding="utf-8"), str(path))
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertFalse(report["vault_resolution"]["secret_material_serialized"])
            self.assertFalse(report["vault_resolution"]["real_vault_contacted"])
            reference = report["vault_resolution"]["references"][0]
            self.assertEqual(reference["provider_id"], "local")
            self.assertEqual(reference["resolution_status"], "accepted_local_reference")
            self.assertFalse(reference["secret_material_serialized"])
            self.assertFalse(reference["auth_ref_serialized"])

    def test_live_policy_preflight_passes_without_network_requests(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            source_manifest_path = temp / "source.target-manifest.v2.json"
            source_manifest = {
                "schema_version": "tallow.target_manifest.v2",
                "manifest_id": "live-policy-test",
                "targets": [
                    {
                        "id": "external_status",
                        "url": "https://example.com/status",
                        "method": "GET",
                        "headers": {"Accept": "application/json"},
                        "compliance": {**compliance(), "requires_approval": False},
                    }
                ],
                "policy": {
                    "allowlist": {"domains": ["example.com"], "url_patterns": ["https://example.com/*"]},
                    "denylist": {"domains": [], "url_patterns": []},
                    "robots": {"mode": "strict"},
                    "rate_limits": {"per_domain": {"example.com": {"requests_per_minute": 60, "concurrent": 1}}},
                },
            }
            write_json(source_manifest_path, source_manifest)
            manifest_sha = hashlib.sha256(source_manifest_path.read_bytes()).hexdigest()
            plan = base_plan([{"target_id": "external_status", "url": "https://example.com/status", "method": "GET"}])
            plan["source_manifest"] = {"path": str(source_manifest_path), "sha256": manifest_sha, "schema_version": "tallow.target_manifest.v2"}
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            compliance_report_path = temp / "compliance_audit_report.json"
            output_dir = temp / "run"
            write_json(plan_path, plan)
            write_json(compliance_report_path, compliance_gate_report(source_manifest_path, target_id="external_status"))

            result = self.run_runner(
                "--plan",
                str(plan_path),
                "--report-path",
                str(report_path),
                "--output-dir",
                str(output_dir),
                "--network-scope",
                "live",
                "--live-policy-preflight",
                "--compliance-gate-report",
                str(compliance_report_path),
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertEqual(report["requests"][0]["status"], "policy_preflight_passed")
            self.assertIn("live_policy_preflight", json.dumps(report["gates"]))

    def test_p1_010_live_preflight_rejects_gate_report_missing_target_manifest_sha_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            url = f"{server.base_url}/status"
            source_manifest_path = temp / "source.target-manifest.v2.json"
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            compliance_report_path = temp / "compliance_audit_report.json"
            output_dir = temp / "run"
            write_json(source_manifest_path, policy_manifest(url))
            manifest_sha = hashlib.sha256(source_manifest_path.read_bytes()).hexdigest()
            plan = base_plan([{"target_id": "local_status", "url": url, "method": "GET"}])
            plan["source_manifest"] = {"path": str(source_manifest_path), "sha256": manifest_sha, "schema_version": "tallow.target_manifest.v2"}
            write_json(plan_path, plan)
            incomplete_report = compliance_gate_report(source_manifest_path)
            incomplete_report.pop("target_manifest")
            write_json(compliance_report_path, incomplete_report)

            result = self.run_runner(
                "--plan",
                str(plan_path),
                "--report-path",
                str(report_path),
                "--output-dir",
                str(output_dir),
                "--network-scope",
                "live",
                "--live-policy-preflight",
                "--compliance-gate-report",
                str(compliance_report_path),
            )

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertFalse(report["passed"])
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertIn("compliance_gate_report_invalid", json.dumps(report))
            self.assertIn("compliance_gate_report.target_manifest.sha256", json.dumps(report))

    def test_live_policy_preflight_denylist_blocks_without_network_requests(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            source_manifest_path = temp / "source.target-manifest.v2.json"
            source_manifest = {
                "schema_version": "tallow.target_manifest.v2",
                "manifest_id": "live-policy-deny-test",
                "targets": [
                    {
                        "id": "external_status",
                        "url": "https://example.com/status",
                        "method": "GET",
                        "headers": {"Accept": "application/json"},
                        "compliance": {**compliance(), "requires_approval": False},
                    }
                ],
                "policy": {
                    "allowlist": {"domains": ["example.com"], "url_patterns": ["https://example.com/*"]},
                    "denylist": {"domains": ["example.com"], "url_patterns": []},
                    "robots": {"mode": "strict"},
                    "rate_limits": {"per_domain": {"example.com": {"requests_per_minute": 60, "concurrent": 1}}},
                },
            }
            write_json(source_manifest_path, source_manifest)
            manifest_sha = hashlib.sha256(source_manifest_path.read_bytes()).hexdigest()
            plan = base_plan([{"target_id": "external_status", "url": "https://example.com/status", "method": "GET"}])
            plan["source_manifest"] = {"path": str(source_manifest_path), "sha256": manifest_sha, "schema_version": "tallow.target_manifest.v2"}
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            compliance_report_path = temp / "compliance_audit_report.json"
            output_dir = temp / "run"
            write_json(plan_path, plan)
            write_json(compliance_report_path, compliance_gate_report(source_manifest_path, target_id="external_status"))

            result = self.run_runner(
                "--plan",
                str(plan_path),
                "--report-path",
                str(report_path),
                "--output-dir",
                str(output_dir),
                "--network-scope",
                "live",
                "--live-policy-preflight",
                "--compliance-gate-report",
                str(compliance_report_path),
            )

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertFalse(report["passed"])
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertIn("policy_denylist", json.dumps(report))

    def test_external_network_is_blocked_by_default_before_any_request(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            report_path = temp / "report.json"
            output_dir = temp / "run"
            write_json(
                plan_path,
                base_plan(
                    [
                        {"target_id": "external", "url": "https://example.com/", "method": "GET"},
                        {"target_id": "local_after_external", "url": f"{server.base_url}/should-not-run", "method": "GET"},
                    ]
                ),
            )

            result = self.run_runner("--plan", str(plan_path), "--report-path", str(report_path), "--output-dir", str(output_dir), timeout=5)

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertIn("external_network_disabled", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
