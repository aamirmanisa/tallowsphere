#!/usr/bin/env python3
"""P2-008 canonical error taxonomy/envelope regressions."""
from __future__ import annotations

import collections
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ERROR_FIELDS = [
    "kind",
    "message",
    "retryable",
    "policy_blocked",
    "source_target_id",
    "url",
    "phase",
]


def import_script(name: str) -> Any:
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ErrorTaxonomyTests(unittest.TestCase):
    def assert_error_object(
        self,
        error: dict[str, Any],
        *,
        kind: str | None = None,
        policy_blocked: bool | None = None,
        phase: str | None = None,
    ) -> None:
        self.assertEqual(set(error), set(REQUIRED_ERROR_FIELDS))
        self.assertIsInstance(error["kind"], str)
        self.assertIsInstance(error["message"], str)
        self.assertTrue(error["message"])
        self.assertIsInstance(error["retryable"], bool)
        self.assertIsInstance(error["policy_blocked"], bool)
        self.assertIn(type(error["source_target_id"]), {str, type(None)})
        self.assertIn(type(error["url"]), {str, type(None)})
        self.assertIsInstance(error["phase"], str)
        self.assertTrue(error["phase"])
        if kind is not None:
            self.assertEqual(error["kind"], kind)
        if policy_blocked is not None:
            self.assertEqual(error["policy_blocked"], policy_blocked)
        if phase is not None:
            self.assertEqual(error["phase"], phase)

    def test_taxonomy_declares_emitted_error_object_contract(self) -> None:
        taxonomy = json.loads((ROOT / "schemas/tallow/error-taxonomy.v1.json").read_text())
        schema = json.loads((ROOT / "schemas/tallow/error-taxonomy.schema.json").read_text())
        self.assertEqual(taxonomy["error_object"]["schema_version"], "tallow.error_object.v1")
        self.assertEqual(taxonomy["error_object"]["required_fields"], REQUIRED_ERROR_FIELDS)
        emitted = schema["$defs"]["emittedErrorObject"]
        self.assertEqual(emitted["required"], REQUIRED_ERROR_FIELDS)
        kinds = {entry["kind"] for entry in taxonomy["error_kinds"]}
        self.assertIn("auth", kinds)
        self.assertIn("robots_policy", kinds)
        self.assertIn("body_too_large", kinds)

    def test_python_runner_classifies_auth_and_emits_blocked_error_object(self) -> None:
        runner = import_script("run_tallow_request_plan")
        self.assertEqual(runner.classify_error(401, None), "auth")
        self.assertEqual(runner.classify_error(403, None), "auth")
        expected_mappings = {
            "inline_auth_ref": "auth",
            "unsupported_vault_provider": "auth",
            "unresolved_header_secret": "auth",
            "unsupported_header": "validation",
            "unsupported_body": "validation",
            "unsupported_graphql": "validation",
            "policy_compliance": "robots_policy",
            "live_execution_disabled": "robots_policy",
            "compliance_gate_legal_metadata_missing": "robots_policy",
            "extraction_schema_invalid": "validation",
            "multiple_extraction_schemas": "validation",
        }
        for legacy_code, canonical_kind in expected_mappings.items():
            with self.subTest(legacy_code=legacy_code):
                self.assertEqual(runner.canonical_error_kind(legacy_code), canonical_kind)
        tmp_root = ROOT / "tmp"
        tmp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=tmp_root) as td:
            tmp = Path(td)
            plan_path = tmp / "unsupported.request-plan.v1.json"
            report_path = tmp / "report.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "schema_version": "tallow.request_plan.v1",
                        "generated_at_utc": "2026-06-22T00:00:00Z",
                        "request_count": 1,
                        "requests": [
                            {
                                "target_id": "bad_method",
                                "method": "DELETE",
                                "url": "http://127.0.0.1:9/status",
                                "headers": {},
                                "compliance": {
                                    "source_authority": "owned_system",
                                    "purpose": "error taxonomy local test",
                                    "legal_basis": "legitimate_interest",
                                    "pii_policy": "no_pii_expected",
                                    "retention_days": 1,
                                    "robots_mode": "strict",
                                },
                            }
                        ],
                    }
                )
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/run_tallow_request_plan.py"),
                    "--plan",
                    str(plan_path),
                    "--report-path",
                    str(report_path),
                    "--dry-run",
                    "--network-scope",
                    "local",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 2, f"stdout={proc.stdout}\nstderr={proc.stderr}")
            report = json.loads(report_path.read_text())
            error = report["requests"][0]["error"]
            self.assert_error_object(error, kind="validation", policy_blocked=False, phase="request_policy")
            self.assertEqual(error["source_target_id"], "bad_method")
            self.assertEqual(error["url"], "http://127.0.0.1:9/status")

    def test_compliance_gate_violations_include_policy_error_object(self) -> None:
        compliance_gate = import_script("compliance_gate")
        violation = compliance_gate.violation("policy.denylist_match", "manifest.targets[0].url", "Target URL matches denylist")
        self.assert_error_object(violation["error"], kind="robots_policy", policy_blocked=True, phase="compliance_gate")

    def test_extraction_validator_violations_include_extraction_error_object(self) -> None:
        extractor = import_script("validate_extraction_rows")
        violations: list[dict[str, Any]] = []
        counts: collections.Counter[str] = collections.Counter()
        extractor.add(violations, counts, "field_value_type", "row-1", "field price value does not match number", hard=True, field="price")
        self.assertEqual(counts["field_value_type"], 1)
        self.assert_error_object(violations[0]["error"], kind="extraction", policy_blocked=False, phase="extraction_validation")
        self.assertEqual(violations[0]["error"]["source_target_id"], "row-1")


if __name__ == "__main__":
    unittest.main()
