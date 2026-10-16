#!/usr/bin/env python3
"""Tests for the P2-006 production CI gate matrix."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_SCRIPT = ROOT / "scripts" / "tallow_production_ci_gates.py"
WORKFLOW = ROOT / ".github" / "workflows" / "tallow-production-ci-gates.yml"

REQUIRED_GATE_IDS = {
    "p2-006-cargo-check",
    "p2-006-browser-contracts",
    "p2-006-request-plan-cli",
    "p2-006-request-plan-builder",
    "p2-006-request-plan-runner",
    "p2-006-extraction-rows",
    "p2-006-compliance-gate",
    "p2-006-phase1-smoke",
    "p2-006-contract-validation",
    "p2-005-benchmark-protocol",
    "p2-005-benchmark-help",
}
FORBIDDEN_FRAGMENTS = {
    "benchmark_all_sites",
    "run_baseline_benchmark_500",
    "run_scraping_benchmark_pack",
    "run_competitor_parity_benchmarks",
    "firecrawl-self-hosted",
    "--live",
    "--paid",
}


class TallowProductionCiGateTests(unittest.TestCase):
    maxDiff = 3000

    def run_script(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(CI_SCRIPT), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            env=env,
        )

    def test_gate_list_contains_required_offline_matrix_without_live_fragments(self) -> None:
        result = self.run_script("--list")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        gates = json.loads(result.stdout)
        ids = {gate["gate_id"] for gate in gates}
        self.assertEqual(ids, REQUIRED_GATE_IDS)
        for gate in gates:
            self.assertTrue(gate["live_safe"], gate)
            lowered = gate["command"].lower()
            for fragment in FORBIDDEN_FRAGMENTS:
                self.assertNotIn(fragment, lowered, gate)

    def test_workflow_self_check_passes_for_checked_in_workflow(self) -> None:
        result = self.run_script("--check-workflow", str(WORKFLOW))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("CI workflow gate check passed", result.stdout)
        self.assertIn(f"required_gate_count={len(REQUIRED_GATE_IDS)}", result.stdout)

    def test_workflow_self_check_fails_when_matrix_is_absent(self) -> None:
        tmp_root = ROOT / "tmp"
        tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=tmp_root) as td:
            workflow = Path(td) / "missing.yml"
            workflow.write_text("name: missing\njobs: {}\n", encoding="utf-8")
            result = self.run_script("--check-workflow", str(workflow))
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertIn("CI workflow is missing required gates", result.stderr)
        self.assertIn("p2-006-cargo-check", result.stderr)

    def test_live_or_paid_environment_fails_closed_before_running_matrix(self) -> None:
        env = os.environ.copy()
        env["TALLOW_RUN_BROWSER_LIVE_TESTS"] = "1"
        env["TALLOW_RUN_LIVE_BENCHMARKS"] = "true"
        env["FIRECRAWL_API_KEY"] = "present-for-fail-closed-test"
        result = self.run_script("--run", env=env)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertIn("TALLOW_RUN_BROWSER_LIVE_TESTS must be unset/false", result.stderr)
        self.assertIn("TALLOW_RUN_LIVE_BENCHMARKS must be unset/false", result.stderr)
        self.assertIn("FIRECRAWL_API_KEY must be unset/false", result.stderr)
        self.assertNotIn("::group::p2-006-cargo-check", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
