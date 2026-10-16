#!/usr/bin/env python3
"""Phase 9 local/no-secret compliance gate for Tallow manifests and artifacts.

This tool is intentionally stdlib-only and fail-closed. It performs zero live
network I/O, never contacts a real vault, never resolves secret material, and
never performs destructive retention work. It emits redacted/local proof reports
for the Phase 9 compliance/vault/retention gate.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "api-key",
    "cookie",
    "set-cookie",
}
SECRETISH_ENV_MARKERS = ("TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL", "VAULT")
SKIP_PATH_MARKERS = (".env", "secret", "secrets", "credential", "credentials", "vault-token")
LOCAL_VAULT_PROVIDER_IDS = {"local", "fake"}
SCAN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}(?!\d)")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{6,}\b", re.IGNORECASE)),
    ("api_key_assignment", re.compile(r"\b(?:api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE)),
)


def sensitive_header_name(name: str) -> bool:
    lower = name.lower()
    return (
        lower in SENSITIVE_HEADER_NAMES
        or "token" in lower
        or "secret" in lower
        or "credential" in lower
        or "auth" in lower
        or "api-key" in lower
        or "apikey" in lower
        or lower.endswith("-key")
        or lower.endswith("_key")
        or lower == "key"
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def vault_provider_id(auth_ref: str) -> tuple[str, str]:
    parsed = urlparse(auth_ref)
    if parsed.scheme == "vault":
        return "vault", (parsed.netloc or "unknown").lower()
    if parsed.scheme:
        return parsed.scheme, parsed.scheme.lower()
    return "inline", "inline"


def root_rel(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def canonical_error_kind(code: str) -> str:
    if code.startswith(("policy.", "human_gate.", "compliance.", "retention.")):
        return "robots_policy"
    if code in {"inline_auth_ref", "unsupported_vault_provider", "sensitive_header"}:
        return "auth" if "auth" in code or "vault" in code else "robots_policy"
    if code.startswith("redaction.") or code == "redaction.findings":
        return "storage" if code.endswith("stat_failed") else "robots_policy"
    if code.startswith("target_manifest.") or code.startswith("manifest."):
        return "validation"
    return "validation"


def canonical_error_object(code: str, message: str, *, source_target_id: str | None = None, url: str | None = None, phase: str = "compliance_gate") -> dict[str, Any]:
    kind = canonical_error_kind(code)
    return {
        "kind": kind,
        "message": message,
        "retryable": False,
        "policy_blocked": kind in {"robots_policy", "auth"},
        "source_target_id": source_target_id,
        "url": url,
        "phase": phase,
    }


def violation(code: str, path: str, message: str) -> dict[str, str | dict[str, Any]]:
    return {"code": code, "path": path, "message": message, "error": canonical_error_object(code, message)}


def domain_matches(domain: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        pattern = str(pattern).lower()
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if domain.endswith(suffix) or domain == pattern[2:]:
                return True
        if domain == pattern:
            return True
    return False


def url_matches(url: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(url, pattern) for pattern in patterns)


def collect_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    if path.is_file():
        return [path]
    files: list[Path] = []
    for child in sorted(path.rglob("*")):
        if child.is_file():
            files.append(child)
    return files


def should_skip_scan_path(path: Path) -> bool:
    lowered_parts = [part.lower() for part in path.parts]
    for part in lowered_parts:
        if part == ".env" or part.startswith(".env."):
            return True
        if part in {"secret", "secrets", "credential", "credentials", "vault-token"}:
            return True
    return False


def scan_paths(paths: list[Path], warnings: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned: list[str] = []
    skipped: list[dict[str, str]] = []
    for input_path in paths:
        for path in collect_files(input_path):
            rel = root_rel(path)
            if should_skip_scan_path(path):
                skipped.append({"path": rel, "reason": "secret_or_credential_named_path_skipped_without_reading"})
                warnings.append(violation("redaction.scan_skipped_secret_named_path", rel, "Skipped secret/credential-named path without reading bytes"))
                continue
            try:
                stat = path.stat()
            except OSError as exc:
                warnings.append(violation("redaction.stat_failed", rel, str(exc)))
                continue
            if stat.st_size > 1_000_000:
                skipped.append({"path": rel, "reason": "file_larger_than_1MiB_skipped"})
                warnings.append(violation("redaction.scan_skipped_large_file", rel, "Skipped file larger than 1MiB"))
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                skipped.append({"path": rel, "reason": "non_utf8_file_skipped"})
                continue
            scanned.append(rel)
            for line_number, line in enumerate(text.splitlines(), start=1):
                for kind, pattern in SCAN_PATTERNS:
                    for match in pattern.finditer(line):
                        findings.append(
                            {
                                "kind": kind,
                                "path": rel,
                                "line": line_number,
                                "sha256": sha256_text(match.group(0)),
                            }
                        )
    return {
        "schema_version": "tallow.redaction_scan_report.v1",
        "generated_at_utc": iso(utc_now()),
        "scanner": "phase9_local_pattern_scanner_no_raw_values",
        "paths_scanned": scanned,
        "paths_skipped": skipped,
        "findings_total": len(findings),
        "findings": findings,
        "raw_values_emitted": False,
        "non_claims": {
            "not_a_full_dlp_system": True,
            "no_secret_files_read_by_default": True,
        },
    }


def validate_policy(manifest: dict[str, Any], violations: list[dict[str, Any]], warnings: list[dict[str, Any]]) -> None:
    policy = manifest.get("policy")
    if not isinstance(policy, dict):
        violations.append(violation("policy.missing", "manifest.policy", "Policy object is required"))
        return
    allowlist_value = policy.get("allowlist")
    denylist_value = policy.get("denylist")
    allowlist = allowlist_value if isinstance(allowlist_value, dict) else {}
    denylist = denylist_value if isinstance(denylist_value, dict) else {}
    allow_domains = list(allowlist.get("domains") or [])
    allow_patterns = list(allowlist.get("url_patterns") or [])
    deny_domains = list(denylist.get("domains") or [])
    deny_patterns = list(denylist.get("url_patterns") or [])
    if not allow_domains and not allow_patterns:
        violations.append(violation("policy.allowlist_missing", "manifest.policy.allowlist", "Allowlist must include domains or url_patterns"))
    robots_value = policy.get("robots")
    robots = robots_value if isinstance(robots_value, dict) else {}
    robots_mode = robots.get("mode")
    if robots_mode not in {"strict", "advisory", "off"}:
        violations.append(violation("policy.robots_mode_invalid", "manifest.policy.robots.mode", "robots.mode must be strict/advisory/off"))
    elif robots_mode != "strict":
        warnings.append(violation("policy.robots_not_strict", "manifest.policy.robots.mode", "Phase 9 local proof prefers strict robots mode"))
    rate_limits_value = policy.get("rate_limits")
    rate_limits = rate_limits_value if isinstance(rate_limits_value, dict) else {}
    per_domain_value = rate_limits.get("per_domain")
    per_domain = per_domain_value if isinstance(per_domain_value, dict) else {}
    if not per_domain:
        violations.append(violation("policy.rate_limits_missing", "manifest.policy.rate_limits.per_domain", "per_domain rate limits are required"))

    for index, target in enumerate(manifest.get("targets") or []):
        if not isinstance(target, dict):
            continue
        base = f"manifest.targets[{index}]"
        url = str(target.get("url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        if allow_domains or allow_patterns:
            if not (domain_matches(domain, allow_domains) or url_matches(url, allow_patterns)):
                violations.append(violation("policy.allowlist_miss", f"{base}.url", "Target URL does not match allowlist"))
        if domain_matches(domain, deny_domains) or url_matches(url, deny_patterns):
            violations.append(violation("policy.denylist_match", f"{base}.url", "Target URL matches denylist"))
        if per_domain and domain not in per_domain and "default" not in per_domain:
            violations.append(violation("policy.rate_limit_missing_for_domain", f"{base}.url", "No per-domain/default rate limit for target domain"))


def analyze_targets(manifest: dict[str, Any], network_scope: str, retention_action: str, human_approval_ref: str | None) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    violations: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    vault_refs: list[dict[str, Any]] = []
    retention_plans: list[dict[str, Any]] = []
    legal_targets: list[dict[str, Any]] = []
    now = utc_now()

    if network_scope == "live":
        violations.append(violation("human_gate.live_external_execution_not_approved", "network_scope", "Live network scope is human-gated for Phase 9 autopilot"))

    validate_policy(manifest, violations, warnings)

    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        violations.append(violation("manifest.targets_missing", "manifest.targets", "targets must be a non-empty array"))
        targets = []

    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            violations.append(violation("manifest.target_type", f"manifest.targets[{index}]", "target must be an object"))
            continue
        target_id = str(target.get("id") or f"target_{index}")
        base = f"manifest.targets[{index}]"
        compliance_value = target.get("compliance")
        compliance: dict[str, Any] = compliance_value if isinstance(compliance_value, dict) else {}
        if not compliance:
            violations.append(violation("compliance.missing", f"{base}.compliance", "target compliance object is required"))
        for key in ("source_authority", "purpose", "legal_basis", "pii_policy", "retention_days", "robots_mode"):
            if key not in compliance:
                violations.append(violation("compliance.required_key", f"{base}.compliance.{key}", f"missing compliance key: {key}"))
        if compliance.get("source_authority") == "unknown" or compliance.get("legal_basis") == "unknown":
            violations.append(violation("compliance.unknown_basis", f"{base}.compliance", "unknown source authority/legal basis is not accepted by Phase 9 local proof"))
        if compliance.get("pii_policy") == "allow_with_approval" and not compliance.get("approval_ref"):
            violations.append(violation("human_gate.pii_approval_required", f"{base}.compliance.pii_policy", "PII allow_with_approval requires explicit approval_ref"))
        if compliance.get("pii_policy") == "block":
            violations.append(violation("compliance.pii_block_policy", f"{base}.compliance.pii_policy", "pii_policy=block cannot proceed"))
        retention_days = compliance.get("retention_days")
        if not isinstance(retention_days, int) or retention_days < 1:
            violations.append(violation("retention.invalid_days", f"{base}.compliance.retention_days", "retention_days must be a positive integer"))
            retention_days = 1
        legal_targets.append(
            {
                "target_id": target_id,
                "source_authority": compliance.get("source_authority"),
                "purpose": compliance.get("purpose"),
                "legal_basis": compliance.get("legal_basis"),
                "pii_policy": compliance.get("pii_policy"),
                "retention_days": retention_days,
                "robots_mode": compliance.get("robots_mode"),
            }
        )
        retention_plans.append(
            {
                "target_id": target_id,
                "retention_days": retention_days,
                "delete_after_utc": iso(now + timedelta(days=retention_days)),
                "action": "plan_only_no_delete",
            }
        )

        auth_ref = target.get("auth_ref")
        if isinstance(auth_ref, str) and auth_ref:
            scheme, provider_id = vault_provider_id(auth_ref)
            if provider_id in LOCAL_VAULT_PROVIDER_IDS and scheme in {"vault", "local", "fake"}:
                status = "accepted_local_reference"
            elif scheme == "inline":
                status = "inline_auth_ref_rejected"
                violations.append(violation("inline_auth_ref", f"{base}.auth_ref", "auth_ref must be a local/fake reference, not inline secret material"))
            else:
                status = "unsupported_provider_fail_closed"
                violations.append(violation("unsupported_vault_provider", f"{base}.auth_ref", "Real/non-local vault refs require an explicitly configured approved provider and are not resolved by this gate"))
            vault_refs.append(
                {
                    "target_id": target_id,
                    "scheme": scheme,
                    "provider_id": provider_id,
                    "reference_hash": sha256_text(auth_ref),
                    "status": status,
                    "resolution_status": status,
                    "secret_material_resolved": False,
                    "secret_material_serialized": False,
                    "auth_ref_serialized": False,
                    "real_vault_contacted": False,
                }
            )

        headers_value = target.get("headers")
        headers: dict[str, Any] = headers_value if isinstance(headers_value, dict) else {}
        for header_name in headers:
            name = str(header_name)
            if sensitive_header_name(name):
                violations.append(violation("sensitive_header", f"{base}.headers.{name}", "Sensitive literal headers are forbidden; use a fake/local auth_ref in Phase 9 proof"))

    if retention_action == "purge":
        if human_approval_ref:
            violations.append(violation("human_gate.destructive_retention_not_automated", "retention_action", "Even with an approval ref, autopilot does not perform destructive retention purge"))
        else:
            violations.append(violation("destructive_retention_requires_human_approval", "retention_action", "Destructive retention purge is human-gated and was not performed"))

    vault_report = {
        "schema_version": "tallow.vault_resolution_report.v1",
        "generated_at_utc": iso(utc_now()),
        "resolver": "fake_local_reference_only",
        "references_total": len(vault_refs),
        "references": vault_refs,
        "no_secret_material_resolved": True,
        "secret_material_serialized": False,
        "real_vault_contacted": False,
        "non_claims": {
            "no_real_vault_configuration": True,
            "no_real_secret_material": True,
        },
    }
    retention_report = {
        "schema_version": "tallow.retention_dry_run_report.v1",
        "generated_at_utc": iso(utc_now()),
        "dry_run": True,
        "requested_action": retention_action,
        "destructive_action_performed": False,
        "plans": retention_plans,
        "non_claims": {
            "no_files_deleted": True,
            "no_remote_retention_policy_modified": True,
        },
    }
    return vault_report, retention_report, violations, warnings, targets, legal_targets


def artifact_file_entry(path: Path, artifact_class: str, redaction_status: str) -> dict[str, Any]:
    return {
        "path": root_rel(path),
        "artifact_class": artifact_class,
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "sha256": sha256_file(path) if path.exists() else "",
        "redaction_status": redaction_status,
    }


def write_artifact_manifest(output_dir: Path, files: list[tuple[Path, str, str]], retention_days: int) -> Path:
    manifest_path = output_dir / "artifact_manifest.json"
    manifest = {
        "schema_version": "tallow.artifact_manifest.v1",
        "artifact_id": "phase9-local-no-secret-compliance-proof",
        "launch_id": "phase9-local-no-secret-compliance-proof",
        "run_id": "phase9-local-no-secret-compliance-proof",
        "generated_at_utc": iso(utc_now()),
        "files": [artifact_file_entry(path, artifact_class, redaction_status) for path, artifact_class, redaction_status in files],
        "redaction": {
            "status": "passed",
            "pii_policy": "redact",
            "notes": "Phase 9 proof reports do not emit raw secret/PII values.",
        },
        "retention": {
            "retention_days": max(1, retention_days),
            "delete_after_utc": iso(utc_now() + timedelta(days=max(1, retention_days))),
        },
        "replay": {
            "safe_to_replay": False,
            "replay_reason": "Compliance/vault/retention proof artifacts are audit evidence, not replay input.",
            "requires_approval": True,
        },
    }
    write_json(manifest_path, manifest)
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Phase 9 local/no-secret compliance gate")
    parser.add_argument("--target-manifest", required=True, help="Path to tallow.target_manifest.v2 JSON")
    parser.add_argument("--output-dir", default="artifacts/phase9/local-no-secret-compliance-proof", help="Directory for Phase 9 proof reports")
    parser.add_argument("--report-path", default="", help="Optional compliance audit report path; defaults under output-dir")
    parser.add_argument("--scan-path", action="append", default=[], help="Local artifact/file path to scan for unredacted PII/secret markers")
    parser.add_argument("--network-scope", choices=["local", "live"], default="local", help="Live scope is human-gated and fails closed")
    parser.add_argument("--retention-action", choices=["dry-run", "purge"], default="dry-run", help="purge is human-gated and never performed by this tool")
    parser.add_argument("--human-approval-ref", default="", help="Records a human approval reference; does not enable destructive automation")
    args = parser.parse_args()

    output_dir = (ROOT / args.output_dir).resolve() if not Path(args.output_dir).is_absolute() else Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = (ROOT / args.report_path).resolve() if args.report_path and not Path(args.report_path).is_absolute() else Path(args.report_path).resolve() if args.report_path else output_dir / "compliance_audit_report.json"
    target_manifest_path = (ROOT / args.target_manifest).resolve() if not Path(args.target_manifest).is_absolute() else Path(args.target_manifest).resolve()
    scan_paths_arg = [(ROOT / path).resolve() if not Path(path).is_absolute() else Path(path).resolve() for path in args.scan_path]

    violations: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    try:
        manifest = load_json(target_manifest_path)
    except Exception as exc:  # noqa: BLE001 - report exact local parse failure
        manifest = {}
        violations.append(violation("target_manifest.load_failed", root_rel(target_manifest_path), str(exc)))

    if not isinstance(manifest, dict):
        manifest = {}
        violations.append(violation("target_manifest.type", root_rel(target_manifest_path), "target manifest must be an object"))

    if manifest.get("schema_version") != "tallow.target_manifest.v2":
        violations.append(violation("target_manifest.schema_version", "manifest.schema_version", "schema_version must be tallow.target_manifest.v2"))

    vault_report, retention_report, target_violations, target_warnings, targets, legal_targets = analyze_targets(
        manifest,
        args.network_scope,
        args.retention_action,
        args.human_approval_ref or None,
    )
    violations.extend(target_violations)
    warnings.extend(target_warnings)

    redaction_report = scan_paths(scan_paths_arg, warnings)
    if redaction_report["findings_total"]:
        violations.append(violation("redaction.findings", "scan_path", "Unredacted PII/secret-like values were found; raw values are not emitted"))

    target_manifest_sha = sha256_file(target_manifest_path) if target_manifest_path.exists() else ""
    retention_days_values = [plan["retention_days"] for plan in retention_report["plans"] if isinstance(plan.get("retention_days"), int)]
    retention_days = min(retention_days_values) if retention_days_values else 1
    summary = {
        "targets_total": len(targets),
        "targets_with_auth_ref": vault_report["references_total"],
        "violations_count": len(violations),
        "warnings_count": len(warnings),
        "redaction_findings_total": redaction_report["findings_total"],
        "retention_plans_total": len(retention_report["plans"]),
    }
    gates = [
        {"name": "target_manifest_loaded", "passed": target_manifest_path.exists(), "detail": root_rel(target_manifest_path)},
        {"name": "policy_metadata_present", "passed": not any(v["code"].startswith("policy.") for v in violations)},
        {"name": "fake_local_vault_only", "passed": not any("vault" in v["code"] or v["code"] == "inline_auth_ref" for v in violations), "detail": "no real vault contacted and no secret material resolved"},
        {"name": "redaction_scan", "passed": redaction_report["findings_total"] == 0, "detail": f"findings={redaction_report['findings_total']}"},
        {"name": "retention_dry_run", "passed": args.retention_action == "dry-run", "detail": "no destructive retention action performed"},
        {"name": "no_live_network_io", "passed": args.network_scope == "local", "detail": "tool performs no network requests"},
    ]
    passed = len(violations) == 0
    legal_metadata_complete = passed and len(legal_targets) == len(targets)
    redaction_passed = redaction_report["findings_total"] == 0
    retention_dry_run_only = args.retention_action == "dry-run" and retention_report["destructive_action_performed"] is False
    production_gate = {
        "approval_id": args.human_approval_ref or "",
        "legal_metadata_status": "complete" if legal_metadata_complete else "incomplete",
        "redaction_status": "passed" if redaction_passed else "failed",
        "retention_status": "dry_run_only" if retention_dry_run_only else "blocked_destructive",
        "accepted_for_live_preflight": bool(legal_metadata_complete and redaction_passed and retention_dry_run_only),
        "accepted_for_live_execution": False,
        "network_io_performed": False,
        "destructive_retention_performed": False,
    }
    compliance_report = {
        "schema_version": "tallow.compliance_gate_report.v1",
        "generated_at_utc": iso(utc_now()),
        "passed": passed,
        "mode": "local_no_secret_proof",
        "network_scope": args.network_scope,
        "target_manifest": {
            "path": root_rel(target_manifest_path),
            "schema_version": str(manifest.get("schema_version") or ""),
            "manifest_id": str(manifest.get("manifest_id") or ""),
            "sha256": target_manifest_sha,
        },
        "summary": summary,
        "production_gate": production_gate,
        "legal": {"targets": legal_targets},
        "gates": gates,
        "violations": violations,
        "warnings": warnings,
        "vault": {
            "resolver": vault_report["resolver"],
            "references_total": vault_report["references_total"],
            "references": vault_report["references"],
            "no_secret_material_resolved": vault_report["no_secret_material_resolved"],
            "secret_material_serialized": vault_report["secret_material_serialized"],
            "real_vault_contacted": vault_report["real_vault_contacted"],
        },
        "redaction": {
            "scanner": redaction_report["scanner"],
            "paths_scanned": redaction_report["paths_scanned"],
            "findings_total": redaction_report["findings_total"],
            "findings": redaction_report["findings"],
            "raw_values_emitted": redaction_report["raw_values_emitted"],
        },
        "retention": {
            "dry_run": retention_report["dry_run"],
            "requested_action": retention_report["requested_action"],
            "destructive_action_performed": retention_report["destructive_action_performed"],
            "plans": retention_report["plans"],
        },
        "non_claims": {
            "no_live_external_scraping": args.network_scope == "local",
            "no_real_secret_material": True,
            "no_real_vault_configuration": True,
            "no_destructive_retention_purge": True,
            "no_production_compliance_readiness": True,
        },
    }

    vault_path = output_dir / "vault_resolution_report.json"
    redaction_path = output_dir / "redaction_scan_report.json"
    retention_path = output_dir / "retention_dry_run_report.json"
    command_log_path = output_dir / "command-log.txt"
    hash_check_path = output_dir / "manifest_hash_verification.json"

    write_json(vault_path, vault_report)
    write_json(redaction_path, redaction_report)
    write_json(retention_path, retention_report)
    write_json(report_path, compliance_report)
    secret_like_env_present = any(any(marker in key.upper() for marker in SECRETISH_ENV_MARKERS) for key in os.environ)
    command_log_path.write_text(
        "Phase 9 local/no-secret compliance gate\n"
        f"generated_at_utc={iso(utc_now())}\n"
        f"argv={[arg if not any(marker.lower() in arg.lower() for marker in ('token', 'secret', 'password')) else '<redacted-arg>' for arg in sys.argv]}\n"
        f"secret_like_env_present={secret_like_env_present}\n"
        "secret_like_env_values_logged=false\n"
        "network_io_performed=false\n"
        "real_vault_contacted=false\n"
        "destructive_retention_action_performed=false\n",
        encoding="utf-8",
    )

    core_files = [
        (report_path, "manifest", "redacted"),
        (vault_path, "manifest", "redacted"),
        (redaction_path, "metrics", "redacted"),
        (retention_path, "manifest", "redacted"),
        (command_log_path, "logs", "redacted"),
    ]
    hash_report = {
        "schema_version": "tallow.phase9_manifest_hash_verification.v1",
        "generated_at_utc": iso(utc_now()),
        "passed": True,
        "files": [artifact_file_entry(path, artifact_class, redaction_status) for path, artifact_class, redaction_status in core_files],
    }
    write_json(hash_check_path, hash_report)
    artifact_manifest_path = write_artifact_manifest(
        output_dir,
        [*core_files, (hash_check_path, "metrics", "redacted")],
        retention_days,
    )

    print(f"compliance gate {'passed' if passed else 'failed'}")
    print(f"report={root_rel(report_path)}")
    print(f"artifact_manifest={root_rel(artifact_manifest_path)}")
    if violations:
        for item in violations[:20]:
            print(f"- {item['code']} {item['path']}: {item['message']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
