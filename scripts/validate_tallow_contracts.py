#!/usr/bin/env python3
"""Linux-native Phase 2 contract validator for Tallow/Nixe.

This is intentionally stdlib-only. It is not a full JSON Schema validator; it checks
Phase 2 contract spine invariants that must hold on Linux/CachyOS without PowerShell.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_JSON = [
    "schemas/tallow/error-taxonomy.schema.json",
    "schemas/tallow/error-taxonomy.v1.json",
    "schemas/tallow/extraction-schema.schema.json",
    "schemas/tallow/extraction-row.schema.json",
    "schemas/tallow/extraction-row-validation-report.schema.json",
    "schemas/tallow/target-manifest-v2.schema.json",
    "schemas/tallow/artifact-manifest.schema.json",
    "schemas/tallow/compliance-gate-report.schema.json",
    "schemas/tallow/contract-index.json",
    "configs/tallow/targets.v2.example.json",
    "schemas/tallow/examples/product-listing.extraction.schema.json",
]

REQUIRED_ERROR_KINDS = {
    "none", "transport", "dns", "tls", "timeout", "http_4xx", "auth",
    "rate_limited", "http_5xx", "robots_policy", "browser", "extraction",
    "validation", "body_too_large", "storage", "internal", "unknown",
}

TARGET_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
TARGET_ALLOWED_KEYS = {
    "id", "url", "method", "headers", "body", "graphql", "auth_ref",
    "extraction_schema_ref", "browser_fallback", "artifact_policy", "compliance",
    "retry", "tags",
}
COMPLIANCE_REQUIRED_KEYS = {
    "source_authority", "purpose", "legal_basis", "pii_policy", "retention_days", "robots_mode",
}
POLICY_REQUIRED_KEYS = {"allowlist", "denylist", "robots", "rate_limits"}


def load_json(rel: str, violations: list[dict[str, Any]]) -> Any | None:
    path = Path(rel)
    if not path.is_absolute():
        path = ROOT / rel
    if not path.exists():
        violations.append({"code": "file.missing", "path": rel, "message": "Required JSON file is missing"})
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report parse errors compactly
        violations.append({"code": "json.invalid", "path": rel, "message": str(exc)})
        return None


def require(condition: bool, violations: list[dict[str, Any]], code: str, path: str, message: str) -> None:
    if not condition:
        violations.append({"code": code, "path": path, "message": message})


def validate_contract_index(violations: list[dict[str, Any]]) -> None:
    index = load_json("schemas/tallow/contract-index.json", violations)
    if not isinstance(index, dict):
        return
    contracts = index.get("contracts")
    require(isinstance(contracts, list) and bool(contracts), violations, "contract_index.contracts", "schemas/tallow/contract-index.json", "contracts must be a non-empty array")
    if not isinstance(contracts, list):
        return
    names: set[str] = set()
    for i, entry in enumerate(contracts):
        base = f"schemas/tallow/contract-index.json:contracts[{i}]"
        require(isinstance(entry, dict), violations, "contract_index.entry_type", base, "contract entry must be an object")
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        rel = entry.get("path")
        require(isinstance(name, str) and bool(name), violations, "contract_index.name", base, "contract name is required")
        require(name not in names, violations, "contract_index.name_unique", base, "contract names must be unique")
        if isinstance(name, str):
            names.add(name)
        require(isinstance(rel, str) and bool(rel), violations, "contract_index.path", base, "contract path is required")
        if isinstance(rel, str):
            require((ROOT / rel).exists(), violations, "contract_index.path_exists", base, f"contract path does not exist: {rel}")
            load_json(rel, violations)


def validate_error_taxonomy(violations: list[dict[str, Any]]) -> None:
    taxonomy = load_json("schemas/tallow/error-taxonomy.v1.json", violations)
    if not isinstance(taxonomy, dict):
        return
    require(taxonomy.get("schema_version") == "tallow.error_taxonomy.v1", violations, "error_taxonomy.schema_version", "schemas/tallow/error-taxonomy.v1.json", "schema_version must be tallow.error_taxonomy.v1")
    kinds = taxonomy.get("error_kinds")
    require(isinstance(kinds, list) and bool(kinds), violations, "error_taxonomy.kinds", "schemas/tallow/error-taxonomy.v1.json", "error_kinds must be a non-empty array")
    if not isinstance(kinds, list):
        return
    seen: set[str] = set()
    for i, item in enumerate(kinds):
        base = f"schemas/tallow/error-taxonomy.v1.json:error_kinds[{i}]"
        require(isinstance(item, dict), violations, "error_taxonomy.entry_type", base, "entry must be object")
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        require(isinstance(kind, str) and bool(kind), violations, "error_taxonomy.kind", base, "kind is required")
        if isinstance(kind, str):
            require(kind not in seen, violations, "error_taxonomy.kind_unique", base, "kind values must be unique")
            seen.add(kind)
        for flag in ("retryable", "replayable", "policy_escalation"):
            require(isinstance(item.get(flag), bool), violations, "error_taxonomy.flag", f"{base}.{flag}", f"{flag} must be boolean")
    missing = sorted(REQUIRED_ERROR_KINDS - seen)
    require(not missing, violations, "error_taxonomy.required_kinds", "schemas/tallow/error-taxonomy.v1.json", f"missing required kinds: {', '.join(missing)}")
    error_object = taxonomy.get("error_object")
    require(isinstance(error_object, dict), violations, "error_taxonomy.error_object", "schemas/tallow/error-taxonomy.v1.json", "error_object contract is required")
    if isinstance(error_object, dict):
        require(error_object.get("schema_version") == "tallow.error_object.v1", violations, "error_taxonomy.error_object.schema_version", "schemas/tallow/error-taxonomy.v1.json:error_object", "error_object schema_version must be tallow.error_object.v1")
        required_fields = error_object.get("required_fields")
        expected_fields = ["kind", "message", "retryable", "policy_blocked", "source_target_id", "url", "phase"]
        require(required_fields == expected_fields, violations, "error_taxonomy.error_object.required_fields", "schemas/tallow/error-taxonomy.v1.json:error_object.required_fields", f"required_fields must be {expected_fields}")


def validate_target_manifest(manifest: Any, path: str, violations: list[dict[str, Any]]) -> None:
    if not isinstance(manifest, dict):
        require(False, violations, "target_manifest.type", path, "manifest must be an object")
        return
    require(manifest.get("schema_version") == "tallow.target_manifest.v2", violations, "target_manifest.schema_version", path, "schema_version must be tallow.target_manifest.v2")
    require(isinstance(manifest.get("manifest_id"), str) and bool(manifest.get("manifest_id")), violations, "target_manifest.manifest_id", path, "manifest_id is required")
    targets = manifest.get("targets")
    require(isinstance(targets, list) and bool(targets), violations, "target_manifest.targets", path, "targets must be a non-empty array")
    if isinstance(targets, list):
        ids: set[str] = set()
        for i, target in enumerate(targets):
            base = f"{path}:targets[{i}]"
            require(isinstance(target, dict), violations, "target_manifest.target_type", base, "target must be object")
            if not isinstance(target, dict):
                continue
            extra = sorted(set(target) - TARGET_ALLOWED_KEYS)
            require(not extra, violations, "target_manifest.target_keys", base, f"target has keys outside v2 contract: {', '.join(extra)}")
            tid = target.get("id")
            require(isinstance(tid, str) and bool(tid), violations, "target_manifest.target_id", base, "target id is required")
            if isinstance(tid, str):
                require(tid not in ids, violations, "target_manifest.target_id_unique", base, "target ids must be unique")
                ids.add(tid)
            url = target.get("url")
            require(isinstance(url, str) and url.startswith(("http://", "https://")), violations, "target_manifest.url", base, "target url must be HTTP(S)")
            require(target.get("method") in TARGET_METHODS, violations, "target_manifest.method", base, "target method is invalid")
            compliance = target.get("compliance")
            require(isinstance(compliance, dict), violations, "target_manifest.compliance", base, "target compliance object is required")
            if isinstance(compliance, dict):
                missing_compliance = sorted(COMPLIANCE_REQUIRED_KEYS - set(compliance))
                require(not missing_compliance, violations, "target_manifest.compliance_key", f"{base}.compliance", f"missing compliance keys: {', '.join(missing_compliance)}")
    policy = manifest.get("policy")
    require(isinstance(policy, dict), violations, "target_manifest.policy", path, "policy is required")
    if isinstance(policy, dict):
        missing_policy = sorted(POLICY_REQUIRED_KEYS - set(policy))
        require(not missing_policy, violations, "target_manifest.policy_key", f"{path}:policy", f"missing policy keys: {', '.join(missing_policy)}")


def validate_target_example(violations: list[dict[str, Any]]) -> None:
    manifest = load_json("configs/tallow/targets.v2.example.json", violations)
    validate_target_manifest(manifest, "configs/tallow/targets.v2.example.json", violations)


def validate_extraction_example(violations: list[dict[str, Any]]) -> None:
    schema = load_json("schemas/tallow/examples/product-listing.extraction.schema.json", violations)
    if not isinstance(schema, dict):
        return
    require(schema.get("schema_version") == "tallow.extraction_schema.v1", violations, "extraction.schema_version", "schemas/tallow/examples/product-listing.extraction.schema.json", "schema_version must be tallow.extraction_schema.v1")
    fields = schema.get("fields")
    require(isinstance(fields, list) and bool(fields), violations, "extraction.fields", "schemas/tallow/examples/product-listing.extraction.schema.json", "fields must be a non-empty array")
    if isinstance(fields, list):
        names: set[str] = set()
        for i, field in enumerate(fields):
            base = f"schemas/tallow/examples/product-listing.extraction.schema.json:fields[{i}]"
            require(isinstance(field, dict), violations, "extraction.field_type", base, "field must be object")
            if not isinstance(field, dict):
                continue
            name = field.get("name")
            require(isinstance(name, str) and bool(name), violations, "extraction.field_name", base, "field name is required")
            if isinstance(name, str):
                require(name not in names, violations, "extraction.field_name_unique", base, "field names must be unique")
                names.add(name)
            require(isinstance(field.get("type"), str) and bool(field.get("type")), violations, "extraction.field_type_value", base, "field type is required")
            require(isinstance(field.get("required"), bool), violations, "extraction.required", base, "field required must be boolean")
            selectors = field.get("selectors")
            require(isinstance(selectors, list) and bool(selectors), violations, "extraction.selectors", base, "field selectors must be non-empty")


def validate_extraction_row_contracts(violations: list[dict[str, Any]]) -> None:
    row_schema = load_json("schemas/tallow/extraction-row.schema.json", violations)
    if isinstance(row_schema, dict):
        require(
            row_schema.get("properties", {}).get("schema_version", {}).get("const") == "tallow.extraction_row.v1",
            violations,
            "extraction_row.schema_version",
            "schemas/tallow/extraction-row.schema.json",
            "row schema must define schema_version const tallow.extraction_row.v1",
        )
        required = set(row_schema.get("required", [])) if isinstance(row_schema.get("required"), list) else set()
        expected = {"schema_version", "row_id", "run_id", "target_id", "source_url", "extraction_schema_id", "fields", "quality", "non_claims"}
        missing = sorted(expected - required)
        require(
            not missing,
            violations,
            "extraction_row.required",
            "schemas/tallow/extraction-row.schema.json",
            f"missing required row keys: {', '.join(missing)}",
        )
        field_cell = row_schema.get("$defs", {}).get("field_cell", {})
        cell_required = set(field_cell.get("required", [])) if isinstance(field_cell.get("required"), list) else set()
        cell_expected = {"value", "type", "required", "confidence", "null_reason", "selector_kind", "selector", "degraded", "source_evidence"}
        missing_cell = sorted(cell_expected - cell_required)
        require(
            not missing_cell,
            violations,
            "extraction_row.field_cell_required",
            "schemas/tallow/extraction-row.schema.json:$defs.field_cell",
            f"missing required field-cell keys: {', '.join(missing_cell)}",
        )

    report_schema = load_json("schemas/tallow/extraction-row-validation-report.schema.json", violations)
    if isinstance(report_schema, dict):
        require(
            report_schema.get("properties", {}).get("schema_version", {}).get("const") == "tallow.extraction_row_validation_report.v1",
            violations,
            "extraction_row_report.schema_version",
            "schemas/tallow/extraction-row-validation-report.schema.json",
            "report schema must define schema_version const tallow.extraction_row_validation_report.v1",
        )
        required = set(report_schema.get("required", [])) if isinstance(report_schema.get("required"), list) else set()
        expected = {"schema_version", "passed", "rows_total", "rows_valid", "rows_quarantined", "error_counts", "checked_paths", "non_claims"}
        missing = sorted(expected - required)
        require(
            not missing,
            violations,
            "extraction_row_report.required",
            "schemas/tallow/extraction-row-validation-report.schema.json",
            f"missing required report keys: {', '.join(missing)}",
        )


def validate_artifact_manifest_schema(violations: list[dict[str, Any]]) -> None:
    schema = load_json("schemas/tallow/artifact-manifest.schema.json", violations)
    if not isinstance(schema, dict):
        return
    required = set(schema.get("required", [])) if isinstance(schema.get("required"), list) else set()
    expected = {"schema_version", "artifact_id", "launch_id", "run_id", "generated_at_utc", "files", "redaction", "retention", "replay"}
    missing = sorted(expected - required)
    require(not missing, violations, "artifact_manifest.required", "schemas/tallow/artifact-manifest.schema.json", f"missing required keys: {', '.join(missing)}")


def validate_compliance_gate_report_schema(violations: list[dict[str, Any]]) -> None:
    schema = load_json("schemas/tallow/compliance-gate-report.schema.json", violations)
    if not isinstance(schema, dict):
        return
    require(
        schema.get("properties", {}).get("schema_version", {}).get("const") == "tallow.compliance_gate_report.v1",
        violations,
        "compliance_gate_report.schema_version",
        "schemas/tallow/compliance-gate-report.schema.json",
        "compliance gate report schema must define schema_version const tallow.compliance_gate_report.v1",
    )
    required = set(schema.get("required", [])) if isinstance(schema.get("required"), list) else set()
    expected = {"schema_version", "generated_at_utc", "passed", "mode", "network_scope", "target_manifest", "summary", "production_gate", "legal", "gates", "violations", "warnings", "vault", "redaction", "retention", "non_claims"}
    missing = sorted(expected - required)
    require(not missing, violations, "compliance_gate_report.required", "schemas/tallow/compliance-gate-report.schema.json", f"missing required report keys: {', '.join(missing)}")


def validate_compliance_gate_report(path: str, violations: list[dict[str, Any]]) -> None:
    report = load_json(path, violations)
    if not isinstance(report, dict):
        require(False, violations, "compliance_gate_report.type", path, "compliance gate report must be an object")
        return
    require(report.get("schema_version") == "tallow.compliance_gate_report.v1", violations, "compliance_gate_report.schema_version", path, "schema_version must be tallow.compliance_gate_report.v1")
    require(report.get("mode") == "local_no_secret_proof", violations, "compliance_gate_report.mode", path, "mode must be local_no_secret_proof")
    require(report.get("network_scope") in {"local", "live"}, violations, "compliance_gate_report.network_scope", path, "network_scope must be local or live")
    summary = report.get("summary")
    require(isinstance(summary, dict), violations, "compliance_gate_report.summary", path, "summary is required")
    if isinstance(summary, dict):
        for key in ("targets_total", "targets_with_auth_ref", "violations_count", "warnings_count", "redaction_findings_total", "retention_plans_total"):
            require(isinstance(summary.get(key), int) and summary.get(key, -1) >= 0, violations, "compliance_gate_report.summary_count", f"{path}:summary.{key}", f"{key} must be a non-negative integer")
    production_gate = report.get("production_gate")
    require(isinstance(production_gate, dict), violations, "compliance_gate_report.production_gate", path, "production_gate section is required")
    if isinstance(production_gate, dict):
        require(isinstance(production_gate.get("approval_id"), str), violations, "compliance_gate_report.approval_id", f"{path}:production_gate.approval_id", "approval_id must be a string")
        require(production_gate.get("legal_metadata_status") in {"complete", "incomplete"}, violations, "compliance_gate_report.legal_metadata_status", f"{path}:production_gate.legal_metadata_status", "legal_metadata_status must be complete or incomplete")
        require(production_gate.get("redaction_status") in {"passed", "failed"}, violations, "compliance_gate_report.redaction_status", f"{path}:production_gate.redaction_status", "redaction_status must be passed or failed")
        require(production_gate.get("retention_status") in {"dry_run_only", "blocked_destructive"}, violations, "compliance_gate_report.retention_status", f"{path}:production_gate.retention_status", "retention_status must be dry_run_only or blocked_destructive")
        require(production_gate.get("network_io_performed") is False, violations, "compliance_gate_report.network_io", f"{path}:production_gate.network_io_performed", "compliance gate proof must not perform network I/O")
        require(production_gate.get("destructive_retention_performed") is False, violations, "compliance_gate_report.retention_destructive", f"{path}:production_gate.destructive_retention_performed", "compliance gate proof must not perform destructive retention")
    legal = report.get("legal")
    require(isinstance(legal, dict), violations, "compliance_gate_report.legal", path, "legal section is required")
    legal_targets = legal.get("targets") if isinstance(legal, dict) else None
    require(isinstance(legal_targets, list), violations, "compliance_gate_report.legal_targets", f"{path}:legal.targets", "legal.targets must be an array")
    if isinstance(legal_targets, list):
        for i, target in enumerate(legal_targets):
            base = f"{path}:legal.targets[{i}]"
            require(isinstance(target, dict), violations, "compliance_gate_report.legal_target", base, "legal target must be object")
            if isinstance(target, dict):
                for key in ("target_id", "source_authority", "purpose", "legal_basis", "pii_policy", "robots_mode"):
                    require(isinstance(target.get(key), str) and bool(target.get(key)), violations, "compliance_gate_report.legal_target_key", f"{base}.{key}", f"{key} must be a non-empty string")
                require(isinstance(target.get("retention_days"), int) and target.get("retention_days", 0) > 0, violations, "compliance_gate_report.legal_retention_days", f"{base}.retention_days", "retention_days must be a positive integer")
    vault = report.get("vault")
    require(isinstance(vault, dict), violations, "compliance_gate_report.vault", path, "vault section is required")
    if isinstance(vault, dict):
        require(vault.get("resolver") == "fake_local_reference_only", violations, "compliance_gate_report.vault_resolver", f"{path}:vault.resolver", "vault resolver must be fake_local_reference_only")
        require(vault.get("real_vault_contacted") is False, violations, "compliance_gate_report.real_vault", f"{path}:vault.real_vault_contacted", "real vault must not be contacted by Phase 9 local proof")
        require(vault.get("secret_material_serialized") is False, violations, "compliance_gate_report.vault_serialized", f"{path}:vault.secret_material_serialized", "secret material must not be serialized by Phase 9 local proof")
    retention = report.get("retention")
    require(isinstance(retention, dict), violations, "compliance_gate_report.retention", path, "retention section is required")
    if isinstance(retention, dict):
        require(retention.get("destructive_action_performed") is False, violations, "compliance_gate_report.retention_destructive", f"{path}:retention.destructive_action_performed", "destructive retention action must not be performed")
    non_claims = report.get("non_claims")
    require(isinstance(non_claims, dict), violations, "compliance_gate_report.non_claims", path, "non_claims section is required")
    if isinstance(non_claims, dict):
        for key in ("no_live_external_scraping", "no_real_secret_material", "no_real_vault_configuration", "no_destructive_retention_purge", "no_production_compliance_readiness"):
            require(non_claims.get(key) is True, violations, "compliance_gate_report.non_claim", f"{path}:non_claims.{key}", f"{key} must be true")


def validate_stdlib_surface_manifest(path: str, violations: list[dict[str, Any]]) -> None:
    manifest = load_json(path, violations)
    if not isinstance(manifest, dict):
        require(False, violations, "stdlib_surface.type", path, "stdlib surface manifest must be an object")
        return
    require(manifest.get("schema_version") == "tallow.stdlib_surface_manifest.v1", violations, "stdlib_surface.schema_version", path, "schema_version must be tallow.stdlib_surface_manifest.v1")
    summary = manifest.get("summary")
    require(isinstance(summary, dict), violations, "stdlib_surface.summary", path, "summary is required")
    modules = manifest.get("modules")
    require(isinstance(modules, list) and bool(modules), violations, "stdlib_surface.modules", path, "modules must be a non-empty array")
    if isinstance(summary, dict):
        for key in (
            "declared_files",
            "rust_modules",
            "doc_pages",
            "test_files",
            "modules",
            "aligned",
            "open_gaps",
            "module_open_gaps",
            "scraper_critical_modules",
            "scraper_critical_unresolved_gaps",
        ):
            require(isinstance(summary.get(key), int) and summary.get(key, -1) >= 0, violations, "stdlib_surface.summary_count", f"{path}:summary.{key}", f"{key} must be a non-negative integer")
    if isinstance(modules, list):
        names: set[str] = set()
        allowed = {"aligned", "runtime_or_doc_gap", "declared_only", "runtime_only", "doc_only", "unknown"}
        for i, module in enumerate(modules):
            base = f"{path}:modules[{i}]"
            require(isinstance(module, dict), violations, "stdlib_surface.module_type", base, "module must be an object")
            if not isinstance(module, dict):
                continue
            name = module.get("name")
            require(isinstance(name, str) and bool(name), violations, "stdlib_surface.module_name", base, "module name is required")
            if isinstance(name, str):
                require(name not in names, violations, "stdlib_surface.module_name_unique", base, "module names must be unique")
                names.add(name)
            require(module.get("status") in allowed, violations, "stdlib_surface.status", base, "module status is invalid")
            for key in ("declared", "rust_module", "doc_page", "scraper_critical"):
                require(isinstance(module.get(key), bool), violations, "stdlib_surface.module_flag", f"{base}.{key}", f"{key} must be boolean")
    critical_surfaces = manifest.get("critical_surfaces")
    require(isinstance(critical_surfaces, list) and bool(critical_surfaces), violations, "stdlib_surface.critical_surfaces", path, "critical_surfaces must be a non-empty array")
    if isinstance(critical_surfaces, list):
        seen_critical: set[str] = set()
        for i, surface in enumerate(critical_surfaces):
            base = f"{path}:critical_surfaces[{i}]"
            require(isinstance(surface, dict), violations, "stdlib_surface.critical_surface_type", base, "critical surface must be object")
            if not isinstance(surface, dict):
                continue
            module = surface.get("module")
            require(isinstance(module, str) and bool(module), violations, "stdlib_surface.critical_surface_module", base, "critical surface module is required")
            if isinstance(module, str):
                require(module not in seen_critical, violations, "stdlib_surface.critical_surface_unique", base, "critical surface modules must be unique")
                seen_critical.add(module)
            require(surface.get("support_status") in {"function_level_classified", "unsupported_non_production"}, violations, "stdlib_surface.critical_support_status", base, "critical support status is invalid")
            require(surface.get("fail_closed") is True, violations, "stdlib_surface.critical_fail_closed", base, "critical surface must be fail-closed")
            require(isinstance(surface.get("unresolved_gap_count"), int) and surface.get("unresolved_gap_count") == 0, violations, "stdlib_surface.critical_unresolved", base, "critical unresolved gaps must be zero")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Tallow Phase 2 contract spine")
    parser.add_argument("--report-path", default="", help="Optional JSON report path")
    parser.add_argument(
        "--target-manifest",
        action="append",
        default=[],
        help="Additional tallow.target_manifest.v2 file to validate, e.g. a generated v1->v2 normalization artifact",
    )
    parser.add_argument(
        "--stdlib-surface-manifest",
        action="append",
        default=[],
        help="Additional tallow.stdlib_surface_manifest.v1 file to validate",
    )
    parser.add_argument(
        "--compliance-gate-report",
        action="append",
        default=[],
        help="Additional tallow.compliance_gate_report.v1 file to validate",
    )
    args = parser.parse_args()

    violations: list[dict[str, Any]] = []
    for rel in REQUIRED_JSON:
        load_json(rel, violations)
    validate_contract_index(violations)
    validate_error_taxonomy(violations)
    validate_target_example(violations)
    validate_extraction_example(violations)
    validate_extraction_row_contracts(violations)
    validate_artifact_manifest_schema(violations)
    validate_compliance_gate_report_schema(violations)
    for rel in args.target_manifest:
        manifest = load_json(rel, violations)
        validate_target_manifest(manifest, rel, violations)
    for rel in args.stdlib_surface_manifest:
        validate_stdlib_surface_manifest(rel, violations)
    for rel in args.compliance_gate_report:
        validate_compliance_gate_report(rel, violations)

    report = {
        "schema_version": "tallow.contract_validation.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "passed": len(violations) == 0,
        "violations_count": len(violations),
        "violations": violations,
        "checked_files": REQUIRED_JSON,
        "checked_target_manifests": args.target_manifest,
        "checked_stdlib_surface_manifests": args.stdlib_surface_manifest,
        "checked_compliance_gate_reports": args.compliance_gate_report,
    }

    if args.report_path:
        report_path = ROOT / args.report_path
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if violations:
        print(f"contract validation failed: {len(violations)} violation(s)")
        for v in violations[:20]:
            print(f"- {v['code']} {v['path']}: {v['message']}")
        return 1

    print("contract validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
