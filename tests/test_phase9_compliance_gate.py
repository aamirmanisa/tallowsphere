#!/usr/bin/env python3
"""Tests for Phase 9 local/no-secret compliance gate tooling."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compliance_gate.py"
VALIDATOR = ROOT / "scripts" / "validate_tallow_contracts.py"


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compliance(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "source_authority": "public_web",
        "purpose": "phase9_local_no_secret_proof",
        "legal_basis": "legitimate_interest",
        "pii_policy": "redact",
        "retention_days": 14,
        "robots_mode": "strict",
        "requires_approval": False,
    }
    base.update(overrides)
    return base


def target_manifest(*, auth_ref: str | None = "vault://local/phase9-demo-token", headers: dict[str, str] | None = None) -> dict[str, Any]:
    target: dict[str, Any] = {
        "id": "phase9_local_target",
        "url": "https://example.com/products",
        "method": "GET",
        "headers": headers or {"Accept": "application/json"},
        "compliance": compliance(),
        "artifact_policy": {"capture_body": "redacted", "screenshots": "never", "har": "never"},
    }
    if auth_ref is not None:
        target["auth_ref"] = auth_ref
    return {
        "schema_version": "tallow.target_manifest.v2",
        "manifest_id": "phase9-local-no-secret-test",
        "targets": [target],
        "policy": {
            "allowlist": {"domains": ["example.com"], "url_patterns": ["https://example.com/*"]},
            "denylist": {"domains": [], "url_patterns": ["https://example.com/admin/*"]},
            "robots": {"mode": "strict"},
            "rate_limits": {"per_domain": {"example.com": {"requests_per_minute": 60, "concurrent": 1}}, "per_ip_pool": {"default": {"requests_per_minute": 60, "concurrent": 1}}},
        },
    }


class Phase9ComplianceGateTests(unittest.TestCase):
    def run_script(self, *args: str, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )

    def run_validator(self, *args: str, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(VALIDATOR), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )

    def test_cli_help_exists(self) -> None:
        result = self.run_script("--help")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("usage:", result.stdout)

    def test_local_no_secret_gate_writes_hash_checked_reports(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase9" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            manifest_path = temp / "target-manifest.v2.json"
            output_dir = temp / "proof"
            scan_file = temp / "scan-input" / "redacted-response.txt"
            scan_file.parent.mkdir(parents=True)
            scan_file.write_text("customer=<redacted:sha256:abc123> status=ok\n", encoding="utf-8")
            write_json(manifest_path, target_manifest())

            result = self.run_script(
                "--target-manifest",
                str(manifest_path),
                "--output-dir",
                str(output_dir),
                "--scan-path",
                str(scan_file),
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            report = read_json(output_dir / "compliance_audit_report.json")
            self.assertEqual(report["schema_version"], "tallow.compliance_gate_report.v1")
            self.assertTrue(report["passed"])
            self.assertEqual(report["network_scope"], "local")
            self.assertTrue(report["vault"]["no_secret_material_resolved"])
            self.assertEqual(report["vault"]["references_total"], 1)
            self.assertEqual(report["redaction"]["findings_total"], 0)
            self.assertTrue(report["retention"]["dry_run"])
            self.assertFalse(report["retention"]["destructive_action_performed"])
            self.assertTrue(report["non_claims"]["no_live_external_scraping"])
            self.assertTrue(report["non_claims"]["no_real_secret_material"])

            for filename in (
                "vault_resolution_report.json",
                "redaction_scan_report.json",
                "retention_dry_run_report.json",
                "manifest_hash_verification.json",
                "command-log.txt",
                "artifact_manifest.json",
            ):
                self.assertTrue((output_dir / filename).exists(), filename)

            artifact_manifest = read_json(output_dir / "artifact_manifest.json")
            self.assertEqual(artifact_manifest["schema_version"], "tallow.artifact_manifest.v1")
            self.assertEqual(artifact_manifest["redaction"]["status"], "passed")
            self.assertFalse(artifact_manifest["replay"]["safe_to_replay"])
            for item in artifact_manifest["files"]:
                path = ROOT / item["path"]
                self.assertTrue(path.exists(), item["path"])
                self.assertEqual(item["size_bytes"], path.stat().st_size, item["path"])
                self.assertEqual(item["sha256"], sha256_file(path), item["path"])

            validation = self.run_validator(
                "--compliance-gate-report",
                str(output_dir / "compliance_audit_report.json"),
                "--report-path",
                str(temp / "contract-validation.json"),
            )
            self.assertEqual(validation.returncode, 0, validation.stderr + validation.stdout)

    def test_p1_010_report_contract_carries_live_gate_metadata_without_destructive_retention(self) -> None:
        """RED/P1-010: live/preflight consumers need legal + approval metadata in the gate report.

        This is a local-proof contract scaffold only. It must not contact a real vault,
        perform live scraping, or execute retention purge. The implementation should make
        compliance_gate.py emit a production_gate/legal section and make contract
        validation fail closed when those fields are missing.
        """
        phase_tmp_root = ROOT / "artifacts" / "phase9" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            manifest_path = temp / "target-manifest.v2.json"
            output_dir = temp / "proof"
            write_json(
                manifest_path,
                target_manifest(auth_ref="vault://local/p1-010-demo-token"),
            )

            result = self.run_script(
                "--target-manifest",
                str(manifest_path),
                "--output-dir",
                str(output_dir),
                "--human-approval-ref",
                "P1-010-LOCAL-PREFLIGHT-APPROVAL",
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            report = read_json(output_dir / "compliance_audit_report.json")
            self.assertTrue(report["passed"])
            self.assertEqual(report["production_gate"]["approval_id"], "P1-010-LOCAL-PREFLIGHT-APPROVAL")
            self.assertEqual(report["production_gate"]["legal_metadata_status"], "complete")
            self.assertEqual(report["production_gate"]["redaction_status"], "passed")
            self.assertEqual(report["production_gate"]["retention_status"], "dry_run_only")
            self.assertFalse(report["production_gate"]["network_io_performed"])
            self.assertFalse(report["production_gate"]["destructive_retention_performed"])
            legal_targets = report["legal"]["targets"]
            self.assertEqual(len(legal_targets), 1)
            legal = legal_targets[0]
            for key in ("target_id", "source_authority", "purpose", "legal_basis", "pii_policy", "retention_days", "robots_mode"):
                self.assertIn(key, legal)

            validation = self.run_validator(
                "--compliance-gate-report",
                str(output_dir / "compliance_audit_report.json"),
                "--report-path",
                str(temp / "contract-validation.json"),
            )
            self.assertEqual(validation.returncode, 0, validation.stderr + validation.stdout)

    def test_inline_secret_and_destructive_purge_fail_closed_without_leaking_secret(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase9" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            manifest_path = temp / "target-manifest.v2.json"
            output_dir = temp / "proof"
            secret_auth_ref = "Bearer phase9-secret-canary"
            api_key = "phase9-api-key-canary"
            write_json(
                manifest_path,
                target_manifest(auth_ref=secret_auth_ref, headers={"Accept": "application/json", "Authorization": secret_auth_ref, "X-Api-Key": api_key}),
            )

            result = self.run_script(
                "--target-manifest",
                str(manifest_path),
                "--output-dir",
                str(output_dir),
                "--retention-action",
                "purge",
            )

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            report_text = (output_dir / "compliance_audit_report.json").read_text(encoding="utf-8")
            self.assertIn("inline_auth_ref", report_text)
            self.assertIn("sensitive_header", report_text)
            self.assertIn("destructive_retention_requires_human_approval", report_text)
            self.assertNotIn(secret_auth_ref, report_text)
            self.assertNotIn(api_key, report_text)
            report = json.loads(report_text)
            self.assertFalse(report["passed"])
            self.assertFalse(report["retention"]["destructive_action_performed"])

    def test_token_secret_auth_like_header_names_fail_closed_without_raw_leak(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase9" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            manifest_path = temp / "target-manifest.v2.json"
            output_dir = temp / "proof"
            client_secret = "phase9-client-secret-canary"
            write_json(
                manifest_path,
                target_manifest(auth_ref=None, headers={"Accept": "application/json", "X-Client-Secret": client_secret}),
            )

            result = self.run_script(
                "--target-manifest",
                str(manifest_path),
                "--output-dir",
                str(output_dir),
            )

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            report_text = (output_dir / "compliance_audit_report.json").read_text(encoding="utf-8")
            self.assertIn("sensitive_header", report_text)
            self.assertNotIn(client_secret, report_text)
            report = json.loads(report_text)
            self.assertFalse(report["passed"])
            self.assertFalse(report["production_gate"]["accepted_for_live_preflight"])

    def test_unsupported_real_vault_ref_fails_closed_without_raw_auth_ref(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase9" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            manifest_path = temp / "target-manifest.v2.json"
            output_dir = temp / "proof"
            raw_auth_ref = "vault://aws-sm/prod/phase9-canary-token"
            write_json(manifest_path, target_manifest(auth_ref=raw_auth_ref))

            result = self.run_script(
                "--target-manifest",
                str(manifest_path),
                "--output-dir",
                str(output_dir),
            )

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            report_text = (output_dir / "compliance_audit_report.json").read_text(encoding="utf-8")
            vault_text = (output_dir / "vault_resolution_report.json").read_text(encoding="utf-8")
            self.assertIn("unsupported_vault_provider", report_text)
            self.assertNotIn(raw_auth_ref, report_text)
            self.assertNotIn(raw_auth_ref, vault_text)
            report = json.loads(report_text)
            self.assertFalse(report["passed"])
            self.assertFalse(report["vault"]["secret_material_serialized"])
            self.assertFalse(report["vault"]["real_vault_contacted"])
            reference = report["vault"]["references"][0]
            self.assertEqual(reference["provider_id"], "aws-sm")
            self.assertEqual(reference["resolution_status"], "unsupported_provider_fail_closed")
            self.assertEqual(reference["reference_hash"], hashlib.sha256(raw_auth_ref.encode("utf-8")).hexdigest())
            self.assertFalse(reference["secret_material_serialized"])
            self.assertFalse(reference["auth_ref_serialized"])
            self.assertFalse(reference["real_vault_contacted"])

    def test_redaction_scanner_reports_pii_without_raw_leak(self) -> None:
        phase_tmp_root = ROOT / "artifacts" / "phase9" / "tmp-tests"
        phase_tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=phase_tmp_root) as td:
            temp = Path(td)
            manifest_path = temp / "target-manifest.v2.json"
            output_dir = temp / "proof"
            scan_file = temp / "scan-input" / "response.txt"
            raw_email = "customer@example.com"
            raw_token = "Bearer phase9-token-canary"
            scan_file.parent.mkdir(parents=True)
            scan_file.write_text(f"email={raw_email}\nauth={raw_token}\n", encoding="utf-8")
            write_json(manifest_path, target_manifest(auth_ref=None))

            result = self.run_script(
                "--target-manifest",
                str(manifest_path),
                "--output-dir",
                str(output_dir),
                "--scan-path",
                str(scan_file),
            )

            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            report_text = (output_dir / "redaction_scan_report.json").read_text(encoding="utf-8")
            self.assertIn("email", report_text)
            self.assertIn("bearer_token", report_text)
            self.assertNotIn(raw_email, report_text)
            self.assertNotIn(raw_token, report_text)
            report = json.loads(report_text)
            self.assertEqual(report["findings_total"], 2)
            self.assertTrue(all("sha256" in finding for finding in report["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
