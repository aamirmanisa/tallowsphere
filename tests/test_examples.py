#!/usr/bin/env python3
"""Release-quality example smoke tests.

These tests are local/loopback only. They do not contact public internet, read
secrets, launch a browser, or perform live scraping.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_tallow_request_plan.py"
MOCK_SERVER = ROOT / "examples" / "fixtures" / "mock_server.py"

# ── tallow binary resolution (R4-1: no silent coverage holes) ────────────────
# Two cases, deliberately handled differently:
#   * TALLOW_BIN UNSET → fall back to target/debug/tallow. If that is absent the
#     binary-coverage test prints a WARNING naming the exact coverage gap and
#     then skips — the one defensible skip (a machine with no build, nobody asked
#     for one).
#   * TALLOW_BIN SET   → the operator explicitly named a binary, so a missing /
#     non-executable path is a hard FAILURE, never a skip: a mis-set TALLOW_BIN
#     used to silently pass by skipping the only test that exercises the real
#     binary in this module (audit a04 §4/§5; mirrored by ci-full.yml).
TALLOW_BIN_ENV = "TALLOW_BIN"
_TALLOW_BIN_ENV_VALUE = os.environ.get(TALLOW_BIN_ENV)
TALLOW_BIN_IS_EXPLICIT = bool(_TALLOW_BIN_ENV_VALUE)
TALLOW_BIN = Path(_TALLOW_BIN_ENV_VALUE) if TALLOW_BIN_IS_EXPLICIT else (ROOT / "target" / "debug" / "tallow")


class LoopbackFixture:
    def __enter__(self) -> "LoopbackFixture":
        self.proc = subprocess.Popen(
            [sys.executable, str(MOCK_SERVER), "--port", "0"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline().strip()
        match = re.search(r"http://127\.0\.0\.1:\d+", line)
        if not match:
            self.proc.terminate()
            stderr = self.proc.stderr.read() if self.proc.stderr else ""
            raise AssertionError(f"fixture did not report URL; stdout={line!r} stderr={stderr!r}")
        self.base_url = match.group(0)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        if self.proc.stdout is not None:
            self.proc.stdout.close()
        if self.proc.stderr is not None:
            self.proc.stderr.close()


class ReleaseExamplesTests(unittest.TestCase):
    def run_plan(self, example_dir: str, base_url: str, output_dir: Path, *, expect_code: int = 0) -> dict:
        report = output_dir / "execution_report.json"
        proc = subprocess.run(
            [
                sys.executable,
                "-B",
                str(RUNNER),
                "--plan",
                str(ROOT / "examples" / example_dir / "request-plan.v1.json"),
                "--report-path",
                str(report),
                "--output-dir",
                str(output_dir),
                "--mock-base-url",
                base_url,
                "--timeout-seconds",
                "5",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(proc.returncode, expect_code, proc.stdout + proc.stderr)
        self.assertTrue(report.exists(), proc.stdout + proc.stderr)
        return json.loads(report.read_text(encoding="utf-8"))

    def require_tallow_bin(self) -> Path:
        """Resolve the tallow binary for the binary-coverage test, LOUDLY (R4-1).

        - TALLOW_BIN unset and the default binary missing → print a WARNING that
          names the coverage that is being lost, then skip (the only defensible
          skip: no build on this machine and nobody pointed at one).
        - TALLOW_BIN set but the path is missing / not a file / not executable →
          FAIL the test. An explicitly configured binary that is wrong must never
          turn the only binary-coverage test in this module into a silent pass.
        """
        if not TALLOW_BIN_IS_EXPLICIT:
            if not TALLOW_BIN.exists():
                print(
                    "WARNING(R4-1): TALLOW_BIN is unset and the default tallow binary is missing: "
                    f"{TALLOW_BIN}\n"
                    "WARNING(R4-1): skipping "
                    "test_public_source_get_batch_typechecks_without_warnings — COVERAGE GAP: "
                    "nothing in this module then verifies that examples/public_source_get_batch.tl "
                    "type-checks without warnings.\n"
                    "WARNING(R4-1): close it with `cargo build --locked --bin tallow`, or export "
                    "TALLOW_BIN=/path/to/tallow (a set-but-wrong TALLOW_BIN fails loudly, never skips).",
                    file=sys.stderr,
                )
                self.skipTest(
                    f"TALLOW_BIN unset + default binary missing: {TALLOW_BIN} "
                    "(LOUD coverage-gap skip — see WARNING lines above)"
                )
            return TALLOW_BIN
        if not TALLOW_BIN.exists():
            self.fail(
                f"TALLOW_BIN is set to {TALLOW_BIN} but that path does not exist — refusing to "
                "pretend the binary is simply absent (R4-1). Fix TALLOW_BIN, or unset it to fall "
                "back to target/debug/tallow."
            )
        if not TALLOW_BIN.is_file() or not os.access(TALLOW_BIN, os.X_OK):
            self.fail(
                f"TALLOW_BIN={TALLOW_BIN} is not an executable regular file — refusing to pretend "
                "the binary is simply absent (R4-1). Fix TALLOW_BIN, or unset it to fall back to "
                "target/debug/tallow."
            )
        return TALLOW_BIN

    def test_public_source_get_batch_typechecks_without_warnings(self) -> None:
        tallow_bin = self.require_tallow_bin()
        proc = subprocess.run(
            [str(tallow_bin), "check", "examples/public_source_get_batch.tl"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("check passed", proc.stdout)
        self.assertIn("0 warning", proc.stdout)

    def test_request_plan_get_only_runs_against_loopback_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackFixture() as fixture:
            report = self.run_plan("request_plan_get_only", fixture.base_url, Path(td) / "get-only")
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["planned"], 2)
        self.assertEqual(report["summary"]["executed"], 2)
        self.assertEqual(report["summary"]["succeeded"], 2)
        self.assertFalse(report["non_claims"]["live_external_scraping"])
        self.assertFalse(report["non_claims"]["vault_secret_resolution"])

    def test_request_plan_post_graphql_preserves_post_body_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackFixture() as fixture:
            report = self.run_plan("request_plan_post_graphql", fixture.base_url, Path(td) / "post-graphql")
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["planned"], 1)
        self.assertEqual(report["summary"]["executed"], 1)
        self.assertEqual(report["summary"]["succeeded"], 1)
        request = report["requests"][0]
        self.assertEqual(request["method"], "POST")
        self.assertTrue(request["is_graphql"])
        self.assertEqual(request["graphql"]["operation_name"], "Products")

    def test_extraction_schema_html_writes_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackFixture() as fixture:
            output_dir = Path(td) / "extraction"
            report = self.run_plan("extraction_schema_html", fixture.base_url, output_dir)
            rows_path = output_dir / "extraction" / "rows.jsonl"
            rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines() if line]
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["extraction_rows"], 2)
        self.assertEqual(report["summary"]["extraction_quarantined"], 0)
        self.assertEqual([row["fields"]["name"]["value"] for row in rows], ["Local Mock Granola", "Fixture Coffee"])

    def test_browser_fallback_manual_gate_fails_closed_before_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as td, LoopbackFixture() as fixture:
            report = self.run_plan("browser_fallback_manual_gate", fixture.base_url, Path(td) / "browser-gate", expect_code=2)
        self.assertFalse(report.get("passed", False))
        self.assertEqual(report["summary"]["executed"], 0)
        self.assertEqual(report["summary"]["blocked"], 1)
        self.assertEqual(report["summary"]["unsupported"], 1)
        self.assertEqual(report["unsupported"][0]["code"], "live_browser_fallback_not_enabled")
        self.assertFalse(report["non_claims"]["browser_execution"])

    def test_each_example_readme_contains_command_expected_output_and_non_claims(self) -> None:
        readmes = [
            ROOT / "examples" / "public_source_get_batch.README.md",
            ROOT / "examples" / "request_plan_get_only" / "README.md",
            ROOT / "examples" / "request_plan_post_graphql" / "README.md",
            ROOT / "examples" / "extraction_schema_html" / "README.md",
            ROOT / "examples" / "browser_fallback_manual_gate" / "README.md",
        ]
        for readme in readmes:
            text = readme.read_text(encoding="utf-8")
            self.assertIn("## Command", text, str(readme))
            self.assertIn("## Expected output", text, str(readme))
            self.assertIn("## Non-claims", text, str(readme))

    def test_misset_tallow_bin_fails_loudly_instead_of_skipping(self) -> None:
        """R4-1 regression: a mis-set TALLOW_BIN must FAIL, never skip.

        Runs the binary-coverage test in a child interpreter with TALLOW_BIN
        pointed at a path that does not exist and asserts that the child *fails*
        (and does not report a skip) — pinning the "no silent skip path" rule.
        """
        target = (
            "tests.test_examples.ReleaseExamplesTests"
            ".test_public_source_get_batch_typechecks_without_warnings"
        )
        env = dict(os.environ, TALLOW_BIN=str(ROOT / "no" / "such" / "dir" / "tallow"))
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "unittest", target],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=60,
        )
        self.assertNotEqual(
            proc.returncode, 0, "a set-but-missing TALLOW_BIN must fail the binary test:\n" + proc.stdout
        )
        self.assertIn("TALLOW_BIN is set to", proc.stdout, proc.stdout)
        self.assertNotIn(
            "skipped", proc.stdout.lower(), "a set-but-missing TALLOW_BIN must not skip:\n" + proc.stdout
        )


if __name__ == "__main__":
    unittest.main()
