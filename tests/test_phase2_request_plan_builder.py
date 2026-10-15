#!/usr/bin/env python3
"""Tests for the Phase 2 target-manifest request plan builder."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_tallow_request_plan.py"


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class RequestPlanBuilderTests(unittest.TestCase):
    def run_builder(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def get_only_manifest(self) -> dict:
        return {
            "schema_version": "tallow.target_manifest.v2",
            "manifest_id": "qa-get-only",
            "defaults": {
                "headers": {
                    "Accept": "application/json",
                    "User-Agent": "TallowBot/phase2-test",
                },
                "browser_fallback": {"mode": "never"},
            },
            "targets": [
                {
                    "id": "example_a",
                    "url": "https://example.com/a",
                    "method": "GET",
                    "compliance": {
                        "source_authority": "public_web",
                        "purpose": "phase2_test",
                        "legal_basis": "legitimate_interest",
                        "pii_policy": "no_pii_expected",
                        "retention_days": 7,
                        "robots_mode": "strict",
                    },
                },
                {
                    "id": "example_b",
                    "url": "https://example.com/b",
                    "method": "GET",
                    "compliance": {
                        "source_authority": "public_web",
                        "purpose": "phase2_test",
                        "legal_basis": "legitimate_interest",
                        "pii_policy": "no_pii_expected",
                        "retention_days": 7,
                        "robots_mode": "strict",
                    },
                },
            ],
            "policy": {
                "allowlist": {"domains": ["example.com"]},
                "denylist": {},
                "robots": {"mode": "strict"},
                "rate_limits": {"per_domain": {"example.com": {"concurrent": 2}}, "per_ip_pool": {"default": {"concurrent": 2}}},
            },
        }

    def post_body_manifest(self) -> dict:
        manifest = self.get_only_manifest()
        manifest["manifest_id"] = "qa-post-body"
        manifest["targets"] = [
            {
                **manifest["targets"][0],
                "id": "example_graphql",
                "url": "https://example.com/graphql",
                "method": "POST",
                "body": {
                    "kind": "json",
                    "value": {"query": "query Example { products { name } }"},
                    "content_type": "application/json",
                    "redaction": "hash",
                },
                "graphql": {
                    "operation_type": "query",
                    "operation_name": "Example",
                },
            }
        ]
        return manifest

    def per_target_header_manifest(self) -> dict:
        manifest = self.get_only_manifest()
        manifest["manifest_id"] = "qa-per-target-header"
        manifest["targets"][0]["headers"] = {"X-Per-Target": "1"}
        return manifest

    def default_retry_manifest(self) -> dict:
        manifest = self.get_only_manifest()
        manifest["manifest_id"] = "qa-default-retry"
        manifest["defaults"]["retry"] = {
            "max_attempts": 3,
            "retry_on_error_kinds": ["timeout"],
            "backoff_ms": [100],
        }
        return manifest

    def test_get_only_manifest_writes_request_plan_and_legacy_tl(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            manifest = temp / "manifest.json"
            plan = temp / "request-plan.json"
            tl = temp / "legacy.tl"
            write_json(manifest, self.get_only_manifest())

            result = self.run_builder("--manifest", str(manifest), "--output", str(plan), "--legacy-tl-output", str(tl))

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            plan_data = json.loads(plan.read_text(encoding="utf-8"))
            self.assertEqual(plan_data["schema_version"], "tallow.request_plan.v1")
            self.assertEqual([r["target_id"] for r in plan_data["requests"]], ["example_a", "example_b"])
            self.assertEqual({r["method"] for r in plan_data["requests"]}, {"GET"})
            self.assertTrue(plan_data["legacy_http_batch"]["compatible"])
            tl_text = tl.read_text(encoding="utf-8")
            self.assertIn('"https://example.com/a"', tl_text)
            self.assertIn('"https://example.com/b"', tl_text)
            self.assertIn('"Accept": "application/json"', tl_text)
            self.assertIn("import tallow.http", tl_text)
            self.assertLess(tl_text.index("import tallow.http"), tl_text.index("@cra_class"))
            self.assertIn("http.batch(target_urls", tl_text)

    def test_post_body_manifest_writes_plan_but_refuses_legacy_tl(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            manifest = temp / "manifest.json"
            plan = temp / "request-plan.json"
            tl = temp / "legacy.tl"
            write_json(manifest, self.post_body_manifest())

            result = self.run_builder("--manifest", str(manifest), "--output", str(plan), "--legacy-tl-output", str(tl))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertTrue(plan.exists(), "request plan should still be written for inspection")
            self.assertFalse(tl.exists(), "legacy TL must not be emitted for lossy POST/body downgrade")
            plan_data = json.loads(plan.read_text(encoding="utf-8"))
            self.assertFalse(plan_data["legacy_http_batch"]["compatible"])
            reasons = "\n".join(plan_data["legacy_http_batch"]["blocked_reasons"])
            self.assertIn("method POST", reasons)
            self.assertIn("body", reasons)
            self.assertIn("graphql", reasons)
            self.assertIn("cannot be represented in legacy http.batch TL", result.stderr)

    def test_incompatible_manifest_removes_stale_legacy_tl_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            safe_manifest = temp / "safe-manifest.json"
            unsafe_manifest = temp / "unsafe-manifest.json"
            safe_plan = temp / "safe-request-plan.json"
            unsafe_plan = temp / "unsafe-request-plan.json"
            report = temp / "unsafe-request-plan-report.json"
            tl = temp / "legacy.tl"
            write_json(safe_manifest, self.get_only_manifest())
            safe_result = self.run_builder("--manifest", str(safe_manifest), "--output", str(safe_plan), "--legacy-tl-output", str(tl))
            self.assertEqual(safe_result.returncode, 0, safe_result.stderr + safe_result.stdout)
            self.assertTrue(tl.exists())
            stale_text = tl.read_text(encoding="utf-8")
            self.assertIn("http.batch(target_urls", stale_text)
            write_json(unsafe_manifest, self.post_body_manifest())

            result = self.run_builder(
                "--manifest",
                str(unsafe_manifest),
                "--output",
                str(unsafe_plan),
                "--report-path",
                str(report),
                "--legacy-tl-output",
                str(tl),
            )

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertTrue(unsafe_plan.exists())
            self.assertFalse(tl.exists(), "incompatible reruns must remove stale legacy TL at the requested output path")
            self.assertNotIn("legacy TL written", result.stdout)
            report_data = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(report_data["legacy_tl"]["compatible"])
            self.assertFalse(report_data["legacy_tl"]["emitted"])

    def test_per_target_headers_refuse_legacy_tl_without_losing_plan_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            manifest = temp / "manifest.json"
            plan = temp / "request-plan.json"
            tl = temp / "legacy.tl"
            write_json(manifest, self.per_target_header_manifest())

            result = self.run_builder("--manifest", str(manifest), "--output", str(plan), "--legacy-tl-output", str(tl))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertTrue(plan.exists())
            self.assertFalse(tl.exists())
            plan_data = json.loads(plan.read_text(encoding="utf-8"))
            self.assertEqual(plan_data["requests"][0]["headers"]["X-Per-Target"], "1")
            reasons = "\n".join(plan_data["legacy_http_batch"]["blocked_reasons"])
            self.assertIn("per-target headers", reasons)

    def test_default_retry_refuses_legacy_tl_without_losing_plan_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            manifest = temp / "manifest.json"
            plan = temp / "request-plan.json"
            tl = temp / "legacy.tl"
            write_json(manifest, self.default_retry_manifest())

            result = self.run_builder("--manifest", str(manifest), "--output", str(plan), "--legacy-tl-output", str(tl))

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertTrue(plan.exists())
            self.assertFalse(tl.exists())
            plan_data = json.loads(plan.read_text(encoding="utf-8"))
            self.assertEqual(plan_data["requests"][0]["retry"]["max_attempts"], 3)
            reasons = "\n".join(plan_data["legacy_http_batch"]["blocked_reasons"])
            self.assertIn("retry", reasons)


if __name__ == "__main__":
    unittest.main()
