#!/usr/bin/env python3
"""Phase 5 schema-defined extraction-row validator tests.

These tests are intentionally local/mock only. They do not fetch websites, launch a
browser, read secrets, or use production datasets.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/tallow/examples/product-listing.extraction.schema.json"
ROW_SCHEMA_PATH = ROOT / "schemas/tallow/extraction-row.schema.json"
REPORT_SCHEMA_PATH = ROOT / "schemas/tallow/extraction-row-validation-report.schema.json"
VALIDATOR = ROOT / "scripts/validate_extraction_rows.py"
CONTRACT_INDEX = ROOT / "schemas/tallow/contract-index.json"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def base_row(**overrides: object) -> dict:
    row = {
        "schema_version": "tallow.extraction_row.v1",
        "row_id": "phase5-local-mock-valid-0",
        "run_id": "phase5-local-mock-proof",
        "target_id": "local-mock-product",
        "source_url": "https://mock.local/products/granola",
        "extraction_schema_id": "example.product_listing.v1",
        "extraction_schema_version": "tallow.extraction_schema.v1",
        "entity": "product_listing",
        "row_index": 0,
        "extracted_at_utc": "2026-06-13T00:00:00Z",
        "mode": "local_mock",
        "status": "accepted",
        "row_confidence": 0.95,
        "fields": {
            "name": {
                "value": "Local Mock Granola",
                "type": "string",
                "required": True,
                "confidence": 0.95,
                "null_reason": None,
                "selector_kind": "ld_json",
                "selector": "schema.org/Product.name",
                "degraded": False,
                "source_evidence": "method:json_ld",
            },
            "price": {
                "value": {"amount": 4.99, "currency": "USD", "cents": 499},
                "type": "money",
                "required": False,
                "confidence": 0.95,
                "null_reason": None,
                "selector_kind": "ld_json",
                "selector": "schema.org/Product.offers.price",
                "degraded": False,
                "source_evidence": "method:json_ld",
            },
            "url": {
                "value": "https://mock.local/products/granola",
                "type": "url",
                "required": False,
                "confidence": 0.95,
                "null_reason": None,
                "selector_kind": "literal",
                "selector": "source_url",
                "degraded": False,
                "source_evidence": "source_url",
            },
        },
        "quality": {
            "required_null_count": 0,
            "selector_health": 1.0,
            "drift_detected": False,
            "quarantine_reasons": [],
        },
        "non_claims": {
            "live_scraping": False,
            "external_dataset": False,
            "production_ready": False,
        },
    }
    row.update(overrides)
    return row


class Phase5ExtractionRowsTests(unittest.TestCase):
    def test_row_contracts_are_indexed(self) -> None:
        for path in (ROW_SCHEMA_PATH, REPORT_SCHEMA_PATH):
            self.assertTrue(path.exists(), f"missing {path.relative_to(ROOT)}")
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["$schema"], "https://json-schema.org/draft/2020-12/schema")

        row_schema = json.loads(ROW_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(row_schema["properties"]["schema_version"]["const"], "tallow.extraction_row.v1")
        self.assertIn("fields", row_schema["required"])
        self.assertIn("quality", row_schema["required"])

        report_schema = json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(report_schema["properties"]["schema_version"]["const"], "tallow.extraction_row_validation_report.v1")

        index = json.loads(CONTRACT_INDEX.read_text(encoding="utf-8"))
        indexed = {entry["name"]: entry for entry in index["contracts"]}
        self.assertEqual(indexed["extraction_row"]["path"], "schemas/tallow/extraction-row.schema.json")
        self.assertEqual(indexed["extraction_row_validation_report"]["path"], "schemas/tallow/extraction-row-validation-report.schema.json")

    def test_valid_local_mock_rows_pass_and_write_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            rows = tmp_path / "rows.jsonl"
            quarantine = tmp_path / "quarantine.jsonl"
            report = tmp_path / "report.json"
            write_jsonl(rows, [base_row()])
            quarantine.write_text("", encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--schema",
                    str(SCHEMA_PATH),
                    "--row-schema",
                    str(ROW_SCHEMA_PATH),
                    "--rows",
                    str(rows),
                    "--quarantine-path",
                    str(quarantine),
                    "--report-path",
                    str(report),
                    "--fail-on-invalid",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(result["passed"])
            self.assertEqual(result["rows_total"], 1)
            self.assertEqual(result["rows_valid"], 1)
            self.assertEqual(result["rows_quarantined"], 0)
            self.assertEqual(result["non_claims"]["live_scraping"], False)

    def test_missing_required_field_is_quarantined_and_fails_when_requested(self) -> None:
        invalid = base_row(
            row_id="phase5-local-mock-invalid-0",
            status="quarantined",
            row_confidence=0.4,
            fields={
                **base_row()["fields"],
                "name": {
                    "value": None,
                    "type": "string",
                    "required": True,
                    "confidence": 0.0,
                    "null_reason": "missing",
                    "selector_kind": "ld_json",
                    "selector": "schema.org/Product.name",
                    "degraded": False,
                    "source_evidence": "method:json_ld",
                },
            },
            quality={
                "required_null_count": 1,
                "selector_health": 0.5,
                "drift_detected": True,
                "quarantine_reasons": ["required_field_null:name", "row_confidence_below_min"],
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            rows = tmp_path / "rows.jsonl"
            quarantine = tmp_path / "quarantine.jsonl"
            report = tmp_path / "report.json"
            write_jsonl(rows, [invalid])
            write_jsonl(quarantine, [invalid])
            proc = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--schema",
                    str(SCHEMA_PATH),
                    "--row-schema",
                    str(ROW_SCHEMA_PATH),
                    "--rows",
                    str(rows),
                    "--quarantine-path",
                    str(quarantine),
                    "--report-path",
                    str(report),
                    "--fail-on-invalid",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(result["passed"])
            self.assertEqual(result["rows_total"], 1)
            self.assertEqual(result["rows_quarantined"], 1)
            self.assertIn("required_field_null", result["error_counts"])

    def test_malformed_row_missing_confidence_fails_closed(self) -> None:
        malformed = base_row()
        del malformed["fields"]["name"]["confidence"]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            rows = tmp_path / "rows.jsonl"
            quarantine = tmp_path / "quarantine.jsonl"
            report = tmp_path / "report.json"
            write_jsonl(rows, [malformed])
            quarantine.write_text("", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--schema",
                    str(SCHEMA_PATH),
                    "--row-schema",
                    str(ROW_SCHEMA_PATH),
                    "--rows",
                    str(rows),
                    "--quarantine-path",
                    str(quarantine),
                    "--report-path",
                    str(report),
                    "--fail-on-invalid",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(result["passed"])
            self.assertIn("field_confidence_missing", result["error_counts"])


if __name__ == "__main__":
    unittest.main()
