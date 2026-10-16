#!/usr/bin/env python3
"""Tests for the Phase 6 Linux-native adaptive queue scheduler proof."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "queue_scheduler.py"


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compliance() -> dict[str, Any]:
    return {
        "source_authority": "public_web",
        "purpose": "phase6_queue_scheduler_test",
        "legal_basis": "legitimate_interest",
        "pii_policy": "no_pii_expected",
        "retention_days": 7,
        "robots_mode": "strict",
        "requires_approval": False,
    }


def base_plan(requests: list[dict[str, Any]], *, manifest_id: str = "phase6-test-plan") -> dict[str, Any]:
    for index, request in enumerate(requests):
        request.setdefault("index", index)
        request.setdefault("target_id", f"target_{index}")
        request.setdefault("method", "GET")
        request.setdefault("headers", {"Accept": "application/json"})
        request.setdefault("browser_fallback", {"mode": "never"})
        request.setdefault("artifact_policy", {"capture_body": "redacted", "screenshots": "never", "har": "never"})
        request.setdefault("compliance", compliance())
    return {
        "schema_version": "tallow.request_plan.v1",
        "manifest_id": manifest_id,
        "source_manifest": {
            "path": "tests/generated/phase6-test.target-manifest.v2.json",
            "sha256": "0" * 64,
            "schema_version": "tallow.target_manifest.v2",
        },
        "request_count": len(requests),
        "requests": requests,
        "legacy_http_batch": {
            "compatible": False,
            "blocked_reasons": ["phase6 tests use direct request-plan scheduling"],
            "headers": {},
            "target_urls": [request["url"] for request in requests],
        },
        "status_boundary": "phase6 local scheduler test fixture",
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
        elif self.path.startswith("/always500"):
            status = 500
            payload = {"ok": False, "method": self.command, "path": self.path, "attempt": count_for_path}
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


class QueueSchedulerTests(unittest.TestCase):
    def run_scheduler(self, *args: str, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )

    def assert_manifest_hashes(self, output_dir: Path) -> None:
        manifest_path = output_dir / "artifact_manifest.json"
        self.assertTrue(manifest_path.exists(), f"missing {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "tallow.artifact_manifest.v1")
        self.assertGreaterEqual(len(manifest["files"]), 3)
        for item in manifest["files"]:
            path = ROOT / item["path"]
            self.assertTrue(path.exists(), item["path"])
            data = path.read_bytes()
            self.assertEqual(item["size_bytes"], len(data), item["path"])
            self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest(), item["path"])

    def test_cli_help_exists(self) -> None:
        result = self.run_scheduler("--help")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("--plan", result.stdout)
        self.assertIn("--network-scope", result.stdout)

    def test_dry_run_writes_state_report_manifest_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            plan_path = temp / "plan.json"
            output_dir = temp / "scheduler"
            write_json(
                plan_path,
                base_plan(
                    [
                        {"target_id": "status", "url": "http://127.0.0.1:9/status", "method": "GET"},
                        {"target_id": "graphql", "url": "http://127.0.0.1:9/graphql", "method": "POST"},
                    ]
                ),
            )

            result = self.run_scheduler("--plan", str(plan_path), "--output-dir", str(output_dir), "--dry-run")

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            state = json.loads((output_dir / "queue_state.json").read_text(encoding="utf-8"))
            report = json.loads((output_dir / "queue_run_report.json").read_text(encoding="utf-8"))
            self.assertEqual(state["schema_version"], "tallow.queue.scheduler_state.v1")
            self.assertEqual(state["status"], "planned")
            self.assertEqual(report["schema_version"], "tallow.queue.scheduler_run_report.v1")
            self.assertTrue(report["dry_run"])
            self.assertEqual(report["summary"]["planned"], 2)
            self.assertEqual(report["summary"]["executed"], 0)
            self.assertEqual({job["status"] for job in state["jobs"]}, {"planned"})
            self.assert_manifest_hashes(output_dir)

    def test_local_execution_adaptive_budget_retry_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            output_dir = temp / "scheduler"
            graphql_body = {"query": "query Products($limit:Int!){ products(limit:$limit){ name } }", "variables": {"limit": 2}}
            write_json(
                plan_path,
                base_plan(
                    [
                        {"target_id": "status", "url": f"{server.base_url}/status?x=1", "method": "GET"},
                        {
                            "target_id": "graphql",
                            "url": f"{server.base_url}/graphql",
                            "method": "POST",
                            "body": {"kind": "json", "value": graphql_body, "content_type": "application/json", "redaction": "hash"},
                            "graphql": {"operation_type": "query", "operation_name": "Products", "variables": {"limit": 2}},
                        },
                        {
                            "target_id": "retry",
                            "url": f"{server.base_url}/retry",
                            "method": "GET",
                            "retry": {"max_attempts": 2, "retry_on_error_kinds": ["http_5xx"], "backoff_ms": [0]},
                        },
                    ]
                ),
            )

            result = self.run_scheduler("--plan", str(plan_path), "--output-dir", str(output_dir), "--network-scope", "local", "--max-attempts", "2")

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(len(server.requests), 4)
            report = json.loads((output_dir / "queue_run_report.json").read_text(encoding="utf-8"))
            state = json.loads((output_dir / "queue_state.json").read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["summary"]["completed"], 3)
            self.assertEqual(report["summary"]["attempts"], 4)
            self.assertEqual(report["summary"]["dead_letter"], 0)
            domain_budget = next(iter(state["budgets"]["domains"].values()))
            self.assertEqual(domain_budget["successes"], 3)
            self.assertEqual(domain_budget["failures"], 1)
            self.assertEqual({job["status"] for job in state["jobs"]}, {"completed"})
            self.assert_manifest_hashes(output_dir)

    def test_external_live_url_refused_without_mock_base_url(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            plan_path = temp / "plan.json"
            output_dir = temp / "scheduler"
            write_json(plan_path, base_plan([{"target_id": "external", "url": "https://example.com/status", "method": "GET"}]))

            result = self.run_scheduler("--plan", str(plan_path), "--output-dir", str(output_dir), "--network-scope", "local")

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            report_text = (output_dir / "queue_run_report.json").read_text(encoding="utf-8")
            self.assertIn("external_network_disabled", report_text)
            report = json.loads(report_text)
            self.assertEqual(report["summary"]["blocked"], 1)
            self.assertEqual(report["summary"]["executed"], 0)

    def test_unsupported_and_sensitive_inputs_block_without_requests_or_secret_leak(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            output_dir = temp / "scheduler"
            secret = "Bearer phase6-secret-canary"
            write_json(
                plan_path,
                base_plan(
                    [
                        {"target_id": "needs_auth", "url": f"{server.base_url}/auth", "auth_ref": "vault://phase6/test"},
                        {"target_id": "needs_browser", "url": f"{server.base_url}/browser", "browser_fallback": {"mode": "reasoned"}},
                        {"target_id": "needs_har", "url": f"{server.base_url}/har", "artifact_policy": {"capture_body": "redacted", "screenshots": "never", "har": "always"}},
                        {"target_id": "secret_header", "url": f"{server.base_url}/secret", "headers": {"Authorization": secret}},
                    ]
                ),
            )

            result = self.run_scheduler("--plan", str(plan_path), "--output-dir", str(output_dir), "--network-scope", "local")

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(server.requests, [])
            report_text = (output_dir / "queue_run_report.json").read_text(encoding="utf-8")
            state_text = (output_dir / "queue_state.json").read_text(encoding="utf-8")
            blocked_text = (output_dir / "blocked_targets.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(secret, report_text)
            self.assertNotIn(secret, state_text)
            self.assertNotIn(secret, blocked_text)
            self.assertIn("unsupported_auth_ref", report_text)
            self.assertIn("unsupported_browser_fallback", report_text)
            self.assertIn("unsupported_har_capture", report_text)
            self.assertIn("sensitive_header", report_text)

    def test_resume_skips_completed_work_and_rejects_mutated_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            output_dir = temp / "scheduler"
            plan = base_plan(
                [
                    {"target_id": "one", "url": f"{server.base_url}/one", "method": "GET"},
                    {"target_id": "two", "url": f"{server.base_url}/two", "method": "GET"},
                ]
            )
            write_json(plan_path, plan)

            stopped = self.run_scheduler("--plan", str(plan_path), "--output-dir", str(output_dir), "--stop-after", "1")
            self.assertEqual(stopped.returncode, 3, stopped.stderr + stopped.stdout)
            self.assertEqual(len(server.requests), 1)

            resumed = self.run_scheduler("--plan", str(plan_path), "--output-dir", str(output_dir), "--resume")
            self.assertEqual(resumed.returncode, 0, resumed.stderr + resumed.stdout)
            self.assertEqual(len(server.requests), 2)
            state = json.loads((output_dir / "queue_state.json").read_text(encoding="utf-8"))
            self.assertEqual({job["status"] for job in state["jobs"]}, {"completed"})
            self.assertIn("resume_loaded", [event["event"] for event in state["checkpoints"]])

            mutated = base_plan([{"target_id": "one", "url": f"{server.base_url}/one?mutated=1", "method": "GET"}])
            write_json(plan_path, mutated)
            rejected = self.run_scheduler("--plan", str(plan_path), "--output-dir", str(output_dir), "--resume")
            self.assertEqual(rejected.returncode, 2, rejected.stderr + rejected.stdout)
            self.assertIn("plan hash mismatch", rejected.stderr)
            unchanged_state = json.loads((output_dir / "queue_state.json").read_text(encoding="utf-8"))
            self.assertEqual(unchanged_state["plan"]["request_count"], 2)

    def test_retry_exhaustion_moves_job_to_dead_letter_queue(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            plan_path = temp / "plan.json"
            output_dir = temp / "scheduler"
            write_json(
                plan_path,
                base_plan(
                    [
                        {
                            "target_id": "always500",
                            "url": f"{server.base_url}/always500",
                            "method": "GET",
                            "retry": {"max_attempts": 2, "retry_on_error_kinds": ["http_5xx"], "backoff_ms": [0]},
                        }
                    ]
                ),
            )

            result = self.run_scheduler("--plan", str(plan_path), "--output-dir", str(output_dir), "--max-attempts", "2")

            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            self.assertEqual(len(server.requests), 2)
            report = json.loads((output_dir / "queue_run_report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["dead_letter"], 1)
            dlq_text = (output_dir / "dead_letter.jsonl").read_text(encoding="utf-8")
            self.assertIn("retry_exhausted", dlq_text)
            self.assertIn("always500", dlq_text)


if __name__ == "__main__":
    unittest.main()
