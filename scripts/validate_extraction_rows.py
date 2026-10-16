#!/usr/bin/env python3
"""Validate Phase 5 schema-defined extraction rows.

This validator is intentionally stdlib-only and local/mock by default. It checks
row semantics against a Tallow extraction schema, writes a machine-readable
report, and refuses to turn Phase 5 artifacts into live/production claims.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NULL_REASONS = {"missing", "not_applicable", "blocked", "parse_failed", "policy_redacted", "unknown"}
SELECTOR_KINDS = {"css", "xpath", "json_path", "regex", "meta", "ld_json", "literal"}
FIELD_TYPES = {"string", "number", "integer", "boolean", "url", "email", "phone", "date", "datetime", "money", "array", "object"}


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except Exception as exc:  # noqa: BLE001
            rows.append({"__parse_error__": str(exc), "__line__": line_no})
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            rows.append({"__parse_error__": "JSONL entry must be an object", "__line__": line_no})
    return rows


def canonical_error_object(code: str, row_id: str, message: str) -> dict[str, Any]:
    kind = "extraction" if code.startswith(("field_", "quality_", "row_", "quarantine_", "jsonl_")) else "validation"
    return {
        "kind": kind,
        "message": message,
        "retryable": False,
        "policy_blocked": False,
        "source_target_id": row_id,
        "url": None,
        "phase": "extraction_validation",
    }


def add(violations: list[dict[str, Any]], counts: Counter[str], code: str, row_id: str, message: str, *, hard: bool = False, field: str | None = None) -> None:
    counts[code] += 1
    entry: dict[str, Any] = {"code": code, "row_id": row_id, "message": message, "hard": hard, "error": canonical_error_object(code, row_id, message)}
    if field is not None:
        entry["field"] = field
    violations.append(entry)


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def in_unit_interval(value: Any) -> bool:
    return is_number(value) and 0 <= float(value) <= 1


def type_matches(field_type: str, value: Any) -> bool:
    if value is None:
        return True
    if field_type in {"string", "email", "phone", "date", "datetime"}:
        return isinstance(value, str)
    if field_type == "url":
        return isinstance(value, str) and value.startswith(("http://", "https://"))
    if field_type == "number":
        return is_number(value)
    if field_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if field_type == "boolean":
        return isinstance(value, bool)
    if field_type == "array":
        return isinstance(value, list)
    if field_type == "object":
        return isinstance(value, dict)
    if field_type == "money":
        if is_number(value):
            return True
        if isinstance(value, str):
            try:
                float(value.replace("$", "").replace(",", ""))
                return True
            except ValueError:
                return False
        if isinstance(value, dict):
            return any(k in value for k in ("amount", "cents"))
    return False


def summarize(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"min": None, "max": None, "mean": None}
    return {"min": min(values), "max": max(values), "mean": sum(values) / len(values)}


def validate_row(
    row: dict[str, Any],
    row_no: int,
    schema: dict[str, Any],
    quarantine_ids: set[str],
    violations: list[dict[str, Any]],
    counts: Counter[str],
    null_counts: Counter[str],
    row_confidences: list[float],
    selector_health_values: list[float],
) -> tuple[bool, bool]:
    row_id = str(row.get("row_id", f"row[{row_no}]"))
    hard_before = sum(1 for v in violations if v.get("hard"))

    if "__parse_error__" in row:
        add(violations, counts, "jsonl_parse_error", row_id, str(row["__parse_error__"]), hard=True)
        return False, False

    required_top = {
        "schema_version",
        "row_id",
        "run_id",
        "target_id",
        "source_url",
        "extraction_schema_id",
        "extraction_schema_version",
        "entity",
        "row_index",
        "extracted_at_utc",
        "mode",
        "status",
        "row_confidence",
        "fields",
        "quality",
        "non_claims",
    }
    for key in sorted(required_top - set(row)):
        add(violations, counts, f"row_{key}_missing", row_id, f"missing required row key {key}", hard=True)

    if row.get("schema_version") != "tallow.extraction_row.v1":
        add(violations, counts, "row_schema_version", row_id, "schema_version must be tallow.extraction_row.v1", hard=True)
    if row.get("extraction_schema_id") != schema.get("schema_id"):
        add(violations, counts, "row_extraction_schema_id", row_id, "extraction_schema_id must match extraction schema", hard=True)
    if row.get("extraction_schema_version") != schema.get("schema_version"):
        add(violations, counts, "row_extraction_schema_version", row_id, "extraction_schema_version must match extraction schema", hard=True)
    if row.get("entity") != schema.get("entity"):
        add(violations, counts, "row_entity", row_id, "entity must match extraction schema", hard=True)
    if row.get("mode") != "local_mock":
        add(violations, counts, "row_mode_not_local_mock", row_id, "Phase 5 validator only accepts mode=local_mock", hard=True)
    if row.get("status") not in {"accepted", "quarantined"}:
        add(violations, counts, "row_status", row_id, "status must be accepted or quarantined", hard=True)
    if not in_unit_interval(row.get("row_confidence")):
        add(violations, counts, "row_confidence_invalid", row_id, "row_confidence must be a number in [0,1]", hard=True)
    else:
        row_confidences.append(float(row["row_confidence"]))

    non_claims = row.get("non_claims")
    if not isinstance(non_claims, dict):
        add(violations, counts, "row_non_claims_missing", row_id, "non_claims object is required", hard=True)
    else:
        for key in ("live_scraping", "external_dataset", "production_ready"):
            if non_claims.get(key) is not False:
                add(violations, counts, f"row_non_claim_{key}", row_id, f"non_claims.{key} must be false", hard=True)

    fields = row.get("fields")
    schema_fields = {field["name"]: field for field in schema.get("fields", []) if isinstance(field, dict) and "name" in field}
    if not isinstance(fields, dict):
        add(violations, counts, "row_fields_type", row_id, "fields must be an object", hard=True)
        fields = {}
    for name in sorted(set(fields) - set(schema_fields)):
        add(violations, counts, "field_unknown", row_id, f"field {name} is not declared in extraction schema", hard=True, field=name)

    required_null_count = 0
    field_hard_errors = 0
    for name, spec in schema_fields.items():
        cell = fields.get(name)
        base_required = {"value", "type", "required", "confidence", "null_reason", "selector_kind", "selector", "degraded", "source_evidence"}
        if not isinstance(cell, dict):
            add(violations, counts, "field_cell_missing", row_id, f"field {name} cell is missing", hard=True, field=name)
            field_hard_errors += 1
            if spec.get("required"):
                required_null_count += 1
            continue
        for key in sorted(base_required - set(cell)):
            code = f"field_{key}_missing"
            add(violations, counts, code, row_id, f"field {name} missing {key}", hard=True, field=name)
            field_hard_errors += 1

        if cell.get("type") != spec.get("type"):
            add(violations, counts, "field_type_mismatch", row_id, f"field {name} type must be {spec.get('type')}", hard=True, field=name)
            field_hard_errors += 1
        if cell.get("required") is not spec.get("required"):
            add(violations, counts, "field_required_mismatch", row_id, f"field {name} required flag mismatch", hard=True, field=name)
            field_hard_errors += 1

        value = cell.get("value")
        null_reason = cell.get("null_reason")
        confidence = cell.get("confidence")
        if not in_unit_interval(confidence):
            add(violations, counts, "field_confidence_missing" if "confidence" not in cell else "field_confidence_invalid", row_id, f"field {name} confidence must be a number in [0,1]", hard=True, field=name)
            field_hard_errors += 1
        if null_reason is not None and null_reason not in NULL_REASONS:
            add(violations, counts, "field_null_reason_invalid", row_id, f"field {name} null_reason is not allowed", hard=True, field=name)
            field_hard_errors += 1
        if value is None:
            if null_reason is None:
                add(violations, counts, "field_null_reason_missing", row_id, f"field {name} null value needs a null_reason", hard=True, field=name)
                field_hard_errors += 1
            else:
                null_counts[str(null_reason)] += 1
            if spec.get("required"):
                required_null_count += 1
                add(violations, counts, "required_field_null", row_id, f"required field {name} is null", field=name)
        else:
            if null_reason is not None:
                add(violations, counts, "field_null_reason_on_value", row_id, f"field {name} has value and null_reason", hard=True, field=name)
                field_hard_errors += 1
            if not type_matches(str(spec.get("type")), value):
                add(violations, counts, "field_value_type", row_id, f"field {name} value does not match {spec.get('type')}", hard=True, field=name)
                field_hard_errors += 1
            min_conf = spec.get("min_confidence")
            if is_number(min_conf) and in_unit_interval(confidence):
                confidence_value = float(confidence if confidence is not None else 0.0)
                min_conf_value = float(min_conf if min_conf is not None else 0.0)
                if confidence_value < min_conf_value:
                    add(violations, counts, "field_confidence_below_min", row_id, f"field {name} confidence below min_confidence", field=name)
        selector_kind = cell.get("selector_kind")
        if selector_kind is not None and selector_kind not in SELECTOR_KINDS:
            add(violations, counts, "field_selector_kind", row_id, f"field {name} selector_kind is invalid", hard=True, field=name)
            field_hard_errors += 1
        if not isinstance(cell.get("degraded"), bool):
            add(violations, counts, "field_degraded_type", row_id, f"field {name} degraded must be boolean", hard=True, field=name)
            field_hard_errors += 1

    raw_quality = row.get("quality")
    quality: dict[str, Any] = raw_quality if isinstance(raw_quality, dict) else {}
    if not isinstance(raw_quality, dict):
        add(violations, counts, "row_quality_missing", row_id, "quality object is required", hard=True)
    if quality.get("required_null_count") != required_null_count:
        add(violations, counts, "quality_required_null_count", row_id, "quality.required_null_count must match required null count", hard=True)
    selector_health = quality.get("selector_health")
    if not in_unit_interval(selector_health):
        add(violations, counts, "quality_selector_health", row_id, "quality.selector_health must be in [0,1]", hard=True)
    else:
        selector_health_values.append(float(selector_health if selector_health is not None else 0.0))
    if not isinstance(quality.get("drift_detected"), bool):
        add(violations, counts, "quality_drift_detected", row_id, "quality.drift_detected must be boolean", hard=True)
    reasons = quality.get("quarantine_reasons")
    if not isinstance(reasons, list):
        add(violations, counts, "quality_quarantine_reasons", row_id, "quality.quarantine_reasons must be an array", hard=True)
        reasons = []

    raw_schema_quality = schema.get("quality")
    schema_quality: dict[str, Any] = raw_schema_quality if isinstance(raw_schema_quality, dict) else {}
    min_row_confidence = float(schema_quality.get("min_row_confidence", 0))
    max_null_required_fields = int(schema_quality.get("max_null_required_fields", 0))
    row_confidence_value = row.get("row_confidence")
    row_confidence_below_min = in_unit_interval(row_confidence_value) and float(row_confidence_value if row_confidence_value is not None else 0.0) < min_row_confidence
    should_quarantine = required_null_count > max_null_required_fields or row_confidence_below_min
    if required_null_count > max_null_required_fields and not any(str(r).startswith("required_field_null") for r in reasons):
        add(violations, counts, "quality_missing_required_null_reason", row_id, "quarantined required-null row needs required_field_null reason", hard=True)
    if row_confidence_below_min:
        add(violations, counts, "row_confidence_below_min", row_id, "row confidence below schema minimum")
        if "row_confidence_below_min" not in reasons:
            add(violations, counts, "quality_missing_confidence_reason", row_id, "low-confidence row needs row_confidence_below_min reason", hard=True)
    if should_quarantine and row.get("status") != "quarantined":
        add(violations, counts, "row_status_should_quarantine", row_id, "row should be quarantined", hard=True)
    if not should_quarantine and row.get("status") != "accepted":
        add(violations, counts, "row_status_should_accept", row_id, "row should be accepted", hard=True)
    if row.get("status") == "quarantined" and row_id not in quarantine_ids:
        add(violations, counts, "quarantine_row_missing", row_id, "quarantined row missing from quarantine file", hard=True)
    if row.get("status") == "accepted" and row_id in quarantine_ids:
        add(violations, counts, "quarantine_accepted_row_present", row_id, "accepted row must not appear in quarantine file", hard=True)

    hard_after = sum(1 for v in violations if v.get("hard"))
    hard_row = hard_after > hard_before or field_hard_errors > 0
    return row.get("status") == "accepted" and not hard_row, row.get("status") == "quarantined" and not hard_row


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Phase 5 Tallow extraction rows")
    parser.add_argument("--schema", required=True, help="Extraction schema JSON, e.g. schemas/tallow/examples/product-listing.extraction.schema.json")
    parser.add_argument("--row-schema", default="schemas/tallow/extraction-row.schema.json", help="Extraction row schema JSON")
    parser.add_argument("--rows", required=True, help="Rows JSONL file")
    parser.add_argument("--quarantine-path", required=True, help="Quarantine JSONL file")
    parser.add_argument("--report-path", required=True, help="Validation report JSON path")
    parser.add_argument("--fail-on-invalid", action="store_true", help="Exit non-zero when any row is quarantined/invalid")
    args = parser.parse_args()

    schema_path = Path(args.schema)
    row_schema_path = Path(args.row_schema)
    rows_path = Path(args.rows)
    quarantine_path = Path(args.quarantine_path)
    report_path = Path(args.report_path)
    if not schema_path.is_absolute():
        schema_path = ROOT / schema_path
    if not row_schema_path.is_absolute():
        row_schema_path = ROOT / row_schema_path
    if not rows_path.is_absolute():
        rows_path = ROOT / rows_path
    if not quarantine_path.is_absolute():
        quarantine_path = ROOT / quarantine_path
    if not report_path.is_absolute():
        report_path = ROOT / report_path

    violations: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    null_counts: Counter[str] = Counter()
    row_confidences: list[float] = []
    selector_health_values: list[float] = []

    try:
        schema = load_json(schema_path)
        row_schema = load_json(row_schema_path)
    except Exception as exc:  # noqa: BLE001
        print(f"extraction row validation failed: cannot read schema: {exc}")
        return 2

    if row_schema.get("properties", {}).get("schema_version", {}).get("const") != "tallow.extraction_row.v1":
        add(violations, counts, "row_schema_contract_invalid", "__schema__", "row schema does not define tallow.extraction_row.v1", hard=True)

    rows = load_jsonl(rows_path)
    quarantine_rows = load_jsonl(quarantine_path)
    quarantine_ids = {str(row.get("row_id")) for row in quarantine_rows if isinstance(row, dict) and row.get("row_id")}

    valid = 0
    quarantined = 0
    for idx, row in enumerate(rows):
        is_valid, is_quarantined = validate_row(row, idx, schema, quarantine_ids, violations, counts, null_counts, row_confidences, selector_health_values)
        if is_valid:
            valid += 1
        if is_quarantined:
            quarantined += 1

    for qrow in quarantine_rows:
        if "__parse_error__" in qrow:
            add(violations, counts, "quarantine_jsonl_parse_error", f"quarantine[{qrow.get('__line__', '?')}]", str(qrow["__parse_error__"]), hard=True)
            continue
        if qrow.get("status") != "quarantined":
            add(violations, counts, "quarantine_status", str(qrow.get("row_id", "unknown")), "quarantine file may contain only quarantined rows", hard=True)

    hard_error_count = sum(1 for v in violations if v.get("hard"))
    fail_on_invalid_triggered = args.fail_on_invalid and (quarantined > 0 or counts.get("required_field_null", 0) > 0 or counts.get("row_confidence_below_min", 0) > 0)
    passed = hard_error_count == 0 and not fail_on_invalid_triggered

    report = {
        "schema_version": "tallow.extraction_row_validation_report.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "rows_total": len(rows),
        "rows_valid": valid,
        "rows_quarantined": quarantined,
        "hard_error_count": hard_error_count,
        "error_counts": dict(sorted(counts.items())),
        "null_reason_counts": dict(sorted(null_counts.items())),
        "confidence_summary": summarize(row_confidences),
        "selector_health_summary": summarize(selector_health_values),
        "drift_summary": {"rows_with_drift": sum(1 for row in rows if isinstance(row.get("quality"), dict) and row["quality"].get("drift_detected") is True)},
        "checked_paths": {
            "schema": rel(schema_path),
            "row_schema": rel(row_schema_path),
            "rows": rel(rows_path),
            "quarantine": rel(quarantine_path),
        },
        "non_claims": {
            "live_scraping": False,
            "external_dataset": False,
            "production_ready": False,
        },
        "violations": violations,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if passed:
        print(f"extraction row validation passed: rows={len(rows)} valid={valid} quarantined={quarantined}")
        return 0
    print(f"extraction row validation failed: rows={len(rows)} valid={valid} quarantined={quarantined} hard_errors={hard_error_count}")
    for code, count in sorted(counts.items())[:20]:
        print(f"- {code}: {count}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
