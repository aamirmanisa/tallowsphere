#!/usr/bin/env python3
"""Tests for Phase 10 local/offline benchmark protocol tooling."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_SCRIPT = ROOT / "scripts" / "benchmark_phase10_fixture.py"
COMPARE_SCRIPT = ROOT / "scripts" / "compare_tallow_firecrawl_offline.py"
CORPUS = ROOT / "docs" / "benchmarks" / "fixtures" / "phase10-local-corpus.json"

REQUIRED_ARTIFACTS = {
    "config.json",
    "summary.json",
    "kpi.csv",
    "errors.csv",
    "raw.jsonl",
    "system-metrics.json",
}

REQUIRED_RAW_FIELDS = {
    "run_id",
    "protocol_version",
    "manifest_version",
    "window_id",
    "timestamp_utc",
    "target_id",
    "url",
    "attempt",
    "status_code",
    "success",
    "duration_ms",
    "bytes_received",
    "error_class",
    "validation_passed",
    "worker_id",
    "concurrency_level",
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_path(item: dict[str, Any]) -> Path:
    path = Path(item["path"])
    return path if path.is_absolute() else ROOT / path


class Phase10BenchmarkProtocolTests(unittest.TestCase):
    def run_script(
        self,
        script: Path,
        *args: str,
        timeout: float = 10.0,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(script), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env=env,
        )

    def generate_run(self, temp: Path, provider: str, run_id: str) -> Path:
        output_dir = temp / provider
        result = self.run_script(
            BENCHMARK_SCRIPT,
            "--corpus",
            str(CORPUS),
            "--provider",
            provider,
            "--run-id",
            run_id,
            "--window-id",
            "A",
            "--concurrency-level",
            "1",
            "--output-dir",
            str(output_dir),
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return output_dir

    def assert_manifest_hashes(self, manifest: Path) -> None:
        payload = read_json(manifest)
        self.assertEqual(payload["schema_version"], "tallow.artifact_manifest.v1")
        for item in payload["files"]:
            path = manifest_path(item)
            self.assertTrue(path.exists(), item["path"])
            self.assertEqual(item["size_bytes"], path.stat().st_size, item["path"])
            self.assertEqual(item["sha256"], sha256_file(path), item["path"])

    def test_cli_help_exists_for_phase10_tools(self) -> None:
        for script in (BENCHMARK_SCRIPT, COMPARE_SCRIPT):
            result = self.run_script(script, "--help")
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("usage:", result.stdout)

    def test_fixture_generator_emits_required_protocol_artifacts(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase10" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            run_dir = self.generate_run(Path(td), "tallow-local", "phase10-test-tallow")
            emitted = {path.name for path in run_dir.iterdir() if path.is_file()}
            self.assertTrue(REQUIRED_ARTIFACTS.issubset(emitted), emitted)
            for filename in REQUIRED_ARTIFACTS:
                self.assertGreater((run_dir / filename).stat().st_size, 0, filename)
            summary = read_json(run_dir / "summary.json")
            self.assertEqual(summary["protocol_version"], "1.0-local-offline")
            self.assertEqual(summary["measurement_scope"], "local_fixture_only")
            self.assertEqual(summary["summary"]["targets_total"], 3)
            self.assertEqual(summary["summary"]["validation_failures"], 1)
            self.assertTrue(summary["non_claims"]["no_live_external_scraping"])
            self.assertTrue(summary["non_claims"]["no_performance_claim"])

    def test_raw_jsonl_rows_match_protocol_fields_and_quality_metrics(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase10" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            run_dir = self.generate_run(Path(td), "firecrawl-mock", "phase10-test-firecrawl")
            rows = [json.loads(line) for line in (run_dir / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 3)
            for row in rows:
                self.assertTrue(REQUIRED_RAW_FIELDS.issubset(row), row)
                self.assertEqual(row["protocol_version"], "1.0-local-offline")
                self.assertEqual(row["manifest_version"], "phase10-local-fixture-v1")
                self.assertEqual(row["window_id"], "A")
                self.assertEqual(row["concurrency_level"], 1)
                self.assertTrue(row["url"].startswith("fixture://"))
                self.assertLessEqual(row["attempt"], 3)
                self.assertIn(row["error_class"], {"none", "validation"})
                self.assertIn("fixture", row)
                self.assertIn("extracted_fields", row["fixture"])
                self.assertIn("expected_fields", row["fixture"])
            self.assertEqual(sum(1 for row in rows if row["validation_passed"]), 2)
            self.assertEqual(sum(1 for row in rows if row["error_class"] == "validation"), 1)

    def test_fixture_generator_refuses_non_fixture_urls(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase10" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            bad_corpus = temp / "bad-corpus.json"
            output_dir = temp / "bad-output"
            payload = read_json(CORPUS)
            payload["targets"][0]["url"] = "https://example.invalid/live"
            write_json(bad_corpus, payload)
            result = self.run_script(
                BENCHMARK_SCRIPT,
                "--corpus",
                str(bad_corpus),
                "--provider",
                "tallow-local",
                "--run-id",
                "bad-live-url",
                "--output-dir",
                str(output_dir),
            )
            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertIn("non-fixture URL refused", result.stderr + result.stdout)
            self.assertFalse((output_dir / "raw.jsonl").exists())

    def test_live_or_paid_benchmark_environment_fails_closed_before_artifacts(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase10" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            output_dir = Path(td) / "live-env-output"
            env = os.environ.copy()
            env["TALLOW_RUN_LIVE_BENCHMARKS"] = "1"
            env["FIRECRAWL_API_KEY"] = "present-for-fail-closed-test"
            result = self.run_script(
                BENCHMARK_SCRIPT,
                "--corpus",
                str(CORPUS),
                "--provider",
                "tallow-local",
                "--run-id",
                "blocked-live-env",
                "--output-dir",
                str(output_dir),
                env=env,
            )
            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            combined = result.stderr + result.stdout
            self.assertIn("TALLOW_RUN_LIVE_BENCHMARKS must be unset/false", combined)
            self.assertIn("FIRECRAWL_API_KEY must be unset/false", combined)
            self.assertFalse((output_dir / "raw.jsonl").exists())

    def test_offline_comparator_refuses_live_or_paid_environment(self) -> None:
        env = os.environ.copy()
        env["TALLOW_ENABLE_PAID_APIS"] = "true"
        result = self.run_script(COMPARE_SCRIPT, "--verify-manifest", "missing.json", env=env)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertIn("TALLOW_ENABLE_PAID_APIS must be unset/false", result.stderr + result.stdout)

    def test_offline_comparator_writes_non_claims_and_refuses_mismatched_corpus(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase10" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            tallow_dir = self.generate_run(temp, "tallow-local", "phase10-test-tallow")
            firecrawl_dir = self.generate_run(temp, "firecrawl-mock", "phase10-test-firecrawl")
            comparison_dir = temp / "comparison"
            result = self.run_script(
                COMPARE_SCRIPT,
                "--tallow-run-dir",
                str(tallow_dir),
                "--firecrawl-run-dir",
                str(firecrawl_dir),
                "--output-dir",
                str(comparison_dir),
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            comparison = read_json(comparison_dir / "comparison.json")
            self.assertEqual(comparison["schema_version"], "tallow.phase10_firecrawl_comparison.v1")
            self.assertEqual(comparison["comparison_mode"], "offline_fixture")
            self.assertEqual(comparison["firecrawl_mode"], "mock_fixture_projection")
            self.assertTrue(comparison["non_claims"]["no_live_firecrawl"])
            self.assertTrue(comparison["non_claims"]["no_paid_api"])
            self.assertTrue(comparison["non_claims"]["no_performance_claim"])
            self.assertEqual(comparison["speed_cost_claim"], "not_claimed")
            self.assertIn("Firecrawl service was not started", (comparison_dir / "comparison.md").read_text(encoding="utf-8"))

            mismatch_corpus = temp / "mismatch-corpus.json"
            payload = read_json(CORPUS)
            payload["corpus_id"] = "different-corpus"
            write_json(mismatch_corpus, payload)
            mismatch_firecrawl_dir = temp / "firecrawl-mock-mismatch"
            mismatch_generate = self.run_script(
                BENCHMARK_SCRIPT,
                "--corpus",
                str(mismatch_corpus),
                "--provider",
                "firecrawl-mock",
                "--run-id",
                "phase10-test-firecrawl-mismatch",
                "--window-id",
                "A",
                "--concurrency-level",
                "1",
                "--output-dir",
                str(mismatch_firecrawl_dir),
            )
            self.assertEqual(mismatch_generate.returncode, 0, mismatch_generate.stderr + mismatch_generate.stdout)
            mismatch = self.run_script(
                COMPARE_SCRIPT,
                "--tallow-run-dir",
                str(tallow_dir),
                "--firecrawl-run-dir",
                str(mismatch_firecrawl_dir),
                "--output-dir",
                str(temp / "mismatch-comparison"),
            )
            self.assertEqual(mismatch.returncode, 2, mismatch.stderr + mismatch.stdout)
            self.assertIn("corpus mismatch", mismatch.stderr + mismatch.stdout)

    def test_artifact_manifest_hashes_match_final_files(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase10" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            tallow_dir = self.generate_run(temp, "tallow-local", "phase10-test-tallow")
            firecrawl_dir = self.generate_run(temp, "firecrawl-mock", "phase10-test-firecrawl")
            comparison_dir = temp / "comparison"
            result = self.run_script(
                COMPARE_SCRIPT,
                "--tallow-run-dir",
                str(tallow_dir),
                "--firecrawl-run-dir",
                str(firecrawl_dir),
                "--output-dir",
                str(comparison_dir),
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assert_manifest_hashes(tallow_dir / "artifact_manifest.json")
            self.assert_manifest_hashes(firecrawl_dir / "artifact_manifest.json")
            self.assert_manifest_hashes(comparison_dir / "artifact_manifest.json")

            verify = self.run_script(COMPARE_SCRIPT, "--verify-manifest", str(comparison_dir / "artifact_manifest.json"))
            self.assertEqual(verify.returncode, 0, verify.stderr + verify.stdout)
            self.assertIn("artifact manifest verified", verify.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
