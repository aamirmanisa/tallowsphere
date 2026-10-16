#!/usr/bin/env python3
"""Tests for Phase 2 stdlib surface manifest generation."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_stdlib_surface_manifest.py"


class StdlibSurfaceManifestTests(unittest.TestCase):
    def test_http_stdlib_declares_runtime_dispatched_functions(self) -> None:
        import re

        text = (ROOT / "stdlib" / "http.tl").read_text(encoding="utf-8")
        declared = set(re.findall(r"^(?:fn|function)\s+([A-Za-z_][A-Za-z0-9_]*)", text, re.MULTILINE))
        required = {"get", "post", "put", "delete", "batch", "listen", "server"}
        self.assertFalse(
            required - declared,
            f"stdlib/http.tl missing runtime-dispatched declarations: {sorted(required - declared)}",
        )

    def test_http_request_declares_runtime_headers_field(self) -> None:
        import re

        text = (ROOT / "stdlib" / "http.tl").read_text(encoding="utf-8")
        match = re.search(r"struct\s+HttpRequest\s*\{(?P<body>.*?)\n\}", text, re.DOTALL)
        self.assertIsNotNone(match, "stdlib/http.tl must declare HttpRequest")
        body = match.group("body") if match else ""
        self.assertRegex(
            body,
            r"\bheaders\s*:\s*Map\s*<\s*String\s*,\s*String\s*>",
            "HttpRequest must declare runtime-provided headers as Map<String, String>",
        )

    def test_generates_manifest_with_declared_runtime_doc_and_test_counts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "stdlib_surface_manifest.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--output", str(out)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            manifest = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], "tallow.stdlib_surface_manifest.v1")
            self.assertGreater(manifest["summary"]["declared_files"], 0)
            self.assertGreater(manifest["summary"]["rust_modules"], 0)
            self.assertGreater(manifest["summary"]["doc_pages"], 0)
            self.assertGreater(manifest["summary"]["test_files"], 0)
            modules = {module["name"]: module for module in manifest["modules"]}
            self.assertIn("http", modules)
            self.assertTrue(modules["http"]["declared"])
            self.assertIn("browser", modules)
            self.assertIn(modules["browser"]["status"], {"aligned", "runtime_or_doc_gap", "declared_only", "runtime_only", "doc_only"})

    def test_scraper_critical_scope_matches_p2_001_card(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "stdlib_surface_manifest.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--output", str(out)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            manifest = json.loads(out.read_text(encoding="utf-8"))
            required = {
                "http",
                "html",
                "json",
                "browser",
                "fs",
                "time",
                "log",
                "url",
                "process",
                "artifact",
                "report",
            }
            self.assertTrue(required.issubset(set(manifest["scraper_critical_modules"])))
            modules = {module["name"]: module for module in manifest["modules"]}
            self.assertEqual(modules["artifact"]["status"], "unknown")
            self.assertEqual(modules["report"]["status"], "unknown")
            self.assertEqual(manifest["summary"]["scraper_critical_unresolved_gaps"], 0)
            critical = {surface["module"]: surface for surface in manifest["critical_surfaces"]}
            self.assertEqual(critical["artifact"]["support_status"], "unsupported_non_production")
            self.assertTrue(critical["artifact"]["fail_closed"])
            self.assertIn("parse", critical["json"]["supported_declared_functions"])
            self.assertIn("parse_value", critical["json"]["explicitly_unsupported_functions"])
            self.assertIn("Response.text", critical["http"]["supported_declared_methods"])
            self.assertIn("Response.json", critical["http"]["supported_declared_methods"])
            self.assertNotIn("text", critical["http"]["explicitly_unsupported_functions"])
            self.assertNotIn("json", critical["http"]["explicitly_unsupported_functions"])
            self.assertIn("Document.select", critical["html"]["supported_declared_methods"])
            self.assertIn("Document.text", critical["html"]["supported_declared_methods"])
            self.assertIn("Element.attr", critical["html"]["supported_declared_methods"])
            self.assertNotIn("select", critical["html"]["explicitly_unsupported_functions"])
            self.assertNotIn("attr", critical["html"]["explicitly_unsupported_functions"])
            self.assertNotIn("text", critical["html"]["explicitly_unsupported_functions"])

    def test_fail_on_drift_reports_open_gaps_without_hiding_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "stdlib_surface_manifest.json"
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--output", str(out), "--fail-on-drift"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertIn(result.returncode, {0, 2})
            self.assertTrue(out.exists())
            manifest = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(result.returncode, 0 if manifest["summary"]["open_gaps"] == 0 else 2)
            self.assertIn("open_gaps", manifest["summary"])
    def test_contract_validator_accepts_generated_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "stdlib_surface_manifest.json"
            generate = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--output", str(out)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(generate.returncode, 0, generate.stderr + generate.stdout)
            validate = subprocess.run(
                [sys.executable, "-B", str(ROOT / "scripts" / "validate_tallow_contracts.py"), "--stdlib-surface-manifest", str(out)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(validate.returncode, 0, validate.stderr + validate.stdout)


if __name__ == "__main__":
    unittest.main()
