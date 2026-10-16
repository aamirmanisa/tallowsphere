#!/usr/bin/env python3
"""End-to-end tests for canonical source-backed research package initialization."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_research_package.py"


class ResearchPackageInitTests(unittest.TestCase):
    maxDiff = 2000

    def run_cmd(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )

    def test_research_package_init_writes_canonical_public_source_package(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            entities = temp / "entities.csv"
            queries = temp / "queries.md"
            output = temp / "package"
            entities.write_text("name,type\nExample Public LLC,business\nExample Owner,business_role\n", encoding="utf-8")
            queries.write_text(
                "# Queries\n\n"
                "- `Example Public LLC official registry`\n"
                "- `Example Public LLC permit record`\n",
                encoding="utf-8",
            )

            result = self.run_cmd(
                [
                    sys.executable,
                    "-B",
                    str(SCRIPT),
                    "--slug",
                    "example_public_research",
                    "--entities",
                    str(entities),
                    "--queries",
                    str(queries),
                    "--public-only",
                    "--output",
                    str(output),
                    "--mock-base-url",
                    "http://127.0.0.1:9",
                ]
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            expected_files = {
                "README.md",
                "EXAMPLE_PUBLIC_RESEARCH.md",
                "queries.md",
                "entities.csv",
                "sources_manifest.json",
                "example_public_research.request-plan.v1.json",
                "example_public_research.request-plan-report.json",
                "example_public_research.legacy-http-batch.tl",
                "tallow_contract_validation_report.json",
                "request_plan_dry_run_report.json",
                "run_notes.md",
                "tallow_run_report.md",
            }
            for rel in expected_files:
                self.assertTrue((output / rel).exists(), f"missing package file: {rel}")
            self.assertTrue((output / "request_plan_dry_run_artifacts" / "artifact_manifest.json").exists())

            manifest = json.loads((output / "sources_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], "tallow.target_manifest.v2")
            self.assertEqual(manifest["manifest_id"], "example_public_research_public_sources")
            self.assertEqual(manifest["policy"]["allowlist"]["domains"], ["www.bing.com"])
            self.assertEqual(len(manifest["targets"]), 2)
            self.assertTrue(all(target["method"] == "GET" for target in manifest["targets"]))
            self.assertTrue(all(target["compliance"]["legal_basis"] == "public_data" for target in manifest["targets"]))

            plan = json.loads((output / "example_public_research.request-plan.v1.json").read_text(encoding="utf-8"))
            self.assertEqual(plan["schema_version"], "tallow.request_plan.v1")
            self.assertEqual(plan["request_count"], 2)
            self.assertTrue(plan["legacy_http_batch"]["compatible"])
            manifest_artifact_path = output / "sources_manifest.json"
            try:
                expected_manifest_path = str(manifest_artifact_path.relative_to(ROOT))
            except ValueError:
                expected_manifest_path = str(manifest_artifact_path)
            self.assertEqual(plan["source_manifest"]["path"], expected_manifest_path)

            runner_report = json.loads((output / "request_plan_dry_run_report.json").read_text(encoding="utf-8"))
            self.assertTrue(runner_report["passed"])
            self.assertTrue(runner_report["dry_run"])
            self.assertEqual(runner_report["summary"]["planned"], 2)
            self.assertEqual(runner_report["summary"]["executed"], 0)

            readme = (output / "README.md").read_text(encoding="utf-8")
            self.assertIn("Canonical source-backed research package", readme)
            self.assertIn("No login-gated scraping", readme)
            self.assertIn("request_plan_dry_run_report.json", readme)


if __name__ == "__main__":
    unittest.main()
