#!/usr/bin/env python3
"""End-to-end test for generated public-source request packages."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "public_source_manifest_minimal.json"
BUILDER = ROOT / "scripts" / "build_tallow_request_plan.py"
RUNNER = ROOT / "scripts" / "run_tallow_request_plan.py"
VALIDATOR = ROOT / "scripts" / "validate_tallow_contracts.py"
TALLOW_BIN = ROOT / "target" / "debug" / "tallow"


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class RecordingHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback
        server = cast(RecordingServer, self.server)
        with server.lock:
            server.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers.items())})
        payload = json.dumps({"ok": True, "path": self.path}, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


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


class GeneratedPublicSourcePackageTests(unittest.TestCase):
    maxDiff = 2000

    def run_cmd(self, args: list[str], *, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["NO_PROXY"] = "127.0.0.1,localhost"
        # The legacy `.tl` leg fetches the loopback fixture, and this runtime's default plane is
        # Tor-first (`TOR_SOCKS_URL` = socks5h://127.0.0.1:9050): on a box that runs a Tor SOCKS
        # listener, a proxied loopback fetch cannot reach the test server, so the request-count
        # assertions below would see the runner's requests alone. Loopback inside a test is not
        # third-party egress, so the direct plane is allowed here — the same environment the
        # runtime's own fetch unit tests set (src/runtime/fetch.rs). The python runner neither
        # reads nor forwards this variable.
        env["TALLOW_ALLOW_DIRECT"] = "1"
        return subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env=env,
        )

    def tallow_cmd(self, subcommand: str, path: Path) -> list[str]:
        if TALLOW_BIN.exists() and os.access(TALLOW_BIN, os.X_OK):
            return [str(TALLOW_BIN), subcommand, str(path)]
        return ["cargo", "run", "--quiet", "--bin", "tallow", "--", subcommand, str(path)]

    def load_loopback_manifest(self, base_url: str) -> dict[str, Any]:
        manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
        for suffix, target in zip(("alpha", "beta"), manifest["targets"], strict=True):
            target["url"] = f"{base_url}/{suffix}"
        return manifest

    def assert_success(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def assert_artifact_manifest_consistent(self, output_dir: Path) -> None:
        manifest_path = output_dir / "artifact_manifest.json"
        self.assertTrue(manifest_path.exists(), "runner must write artifact_manifest.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "tallow.artifact_manifest.v1")
        self.assertTrue(manifest["files"], "artifact manifest should list files")
        for item in manifest["files"]:
            if not item.get("exists"):
                continue
            file_path = output_dir / item["path"] if not Path(item["path"]).is_absolute() else Path(item["path"])
            self.assertTrue(file_path.exists(), f"listed artifact is missing: {item}")
            if item.get("sha256"):
                digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
                self.assertEqual(digest, item["sha256"], f"artifact hash mismatch for {file_path}")

    def test_generated_public_source_package_checks_runs_and_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackServer() as server:
            temp = Path(td)
            manifest_path = temp / "public_source_manifest_minimal.json"
            contract_report = temp / "contract-validation-report.json"
            plan_path = temp / "request-plan.v1.json"
            builder_report = temp / "request-plan-report.json"
            legacy_tl = temp / "legacy-http-batch.tl"
            runner_report = temp / "request-plan-run-report.json"
            runner_output = temp / "runner-artifacts"

            manifest = self.load_loopback_manifest(server.base_url)
            write_json(manifest_path, manifest)

            validate = self.run_cmd(
                [sys.executable, "-B", str(VALIDATOR), "--target-manifest", str(manifest_path), "--report-path", str(contract_report)]
            )
            self.assert_success(validate)
            self.assertTrue(json.loads(contract_report.read_text(encoding="utf-8"))["passed"])

            build = self.run_cmd(
                [
                    sys.executable,
                    "-B",
                    str(BUILDER),
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(plan_path),
                    "--report-path",
                    str(builder_report),
                    "--legacy-tl-output",
                    str(legacy_tl),
                ]
            )
            self.assert_success(build)
            self.assertTrue(plan_path.exists())
            self.assertTrue(legacy_tl.exists())
            self.assertTrue(builder_report.exists())

            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["schema_version"], "tallow.request_plan.v1")
            self.assertEqual(plan["request_count"], 2)
            self.assertTrue(plan["legacy_http_batch"]["compatible"])
            report = json.loads(builder_report.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertTrue(report["legacy_tl"]["emitted"])

            tl_text = legacy_tl.read_text(encoding="utf-8")
            self.assertIn("import tallow.http", tl_text)
            self.assertLess(tl_text.index("import tallow.http"), tl_text.index("@legal"))
            self.assertIn("http.batch(target_urls", tl_text)

            runner = self.run_cmd(
                [
                    sys.executable,
                    "-B",
                    str(RUNNER),
                    "--plan",
                    str(plan_path),
                    "--report-path",
                    str(runner_report),
                    "--output-dir",
                    str(runner_output),
                ]
            )
            self.assert_success(runner)
            runner_data = json.loads(runner_report.read_text(encoding="utf-8"))
            self.assertTrue(runner_data["passed"])
            self.assertEqual(runner_data["summary"]["executed"], 2)
            self.assertEqual(runner_data["summary"]["succeeded"], 2)
            self.assert_artifact_manifest_consistent(runner_output)

            check = self.run_cmd(self.tallow_cmd("check", legacy_tl), timeout=120.0)
            self.assert_success(check)
            self.assertIn("check passed", check.stdout)
            self.assertIn("0 warning(s)", check.stdout)

            run = self.run_cmd(self.tallow_cmd("run", legacy_tl), timeout=120.0)
            self.assert_success(run)
            self.assertIn("legacy transport request count=2", run.stdout)

            # `http.batch` is lowered natively now: the compiled path declares and calls
            # `tallow_http_batch`, and the interpreter-only refusal this step used to assert
            # was retired with the stub (see the compiler's own
            # `http_batch_lowers_to_runtime_ffi_not_the_stub` unit test). So `build` produces
            # a binary. It must not fetch — the counts below stay at two per path: one from
            # the runner's execution, one from the interpreter leg above.
            build = self.run_cmd(self.tallow_cmd("build", legacy_tl), timeout=120.0)
            self.assertEqual(build.returncode, 0, build.stderr + build.stdout)
            self.assertIn("built:", build.stdout)
            self.assertTrue(
                Path(str(legacy_tl)[: -len(".tl")]).exists(),
                "build must leave a binary beside the source",
            )

            seen = Counter(request["path"] for request in server.requests)
            self.assertEqual(seen["/alpha"], 2, server.requests)
            self.assertEqual(seen["/beta"], 2, server.requests)


if __name__ == "__main__":
    unittest.main()
