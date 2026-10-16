# Phase 9 Compliance Gate

> **Docs truth label:** Authoritative current local/no-secret compliance gate contract. This gate produces proof metadata for request-plan live-preflight/live gates, but it is not legal approval, real vault integration, real secret resolution, destructive retention, live scraping permission, deploy readiness, or Windows support.

Status: Linux/CachyOS local/no-secret proof gate with P1-010/P2-008 report contracts.

`scripts/compliance_gate.py` is the Phase 9 compliance/vault/redaction/retention proof runner. It is intentionally local and fail-closed by default.

## What this gate proves

- Target manifests carry required compliance metadata.
- Auth is represented only as fake/local vault references during autonomous Phase 9 proof.
- No real vault is contacted and no secret material is resolved.
- Sensitive literal headers fail closed.
- Local artifacts can be scanned for unredacted PII/secret-like markers without emitting raw matches.
- Retention behavior is dry-run planning only.
- Destructive purge attempts fail closed unless handled later by an explicit human-approved process; this script still does not delete anything.
- Hash-checked proof artifacts are emitted under `artifacts/phase9/local-no-secret-compliance-proof/`.
- The main compliance report carries a `production_gate` section and `legal.targets` metadata that request-plan `live-preflight` consumers require before any network path can pass.

## What this gate does not prove

- No live external scraping or crawling.
- No real credential vault configuration.
- No real secret retrieval or injection.
- No destructive retention purge/delete.
- No legal/compliance approval decision by itself.
- No production compliance readiness.
- No Windows support.

## Command

```bash
python3 scripts/compliance_gate.py \
  --target-manifest artifacts/phase9/local-no-secret-compliance-proof/phase9-local.target-manifest.v2.json \
  --output-dir artifacts/phase9/local-no-secret-compliance-proof \
  --scan-path artifacts/phase9/local-no-secret-compliance-proof/scan-input/redacted-response.txt
```

Expected local proof result:

```text
compliance gate passed
report=artifacts/phase9/local-no-secret-compliance-proof/compliance_audit_report.json
artifact_manifest=artifacts/phase9/local-no-secret-compliance-proof/artifact_manifest.json
```

## Reports

The runner writes:

- `compliance_audit_report.json` (`tallow.compliance_gate_report.v1`)
- `vault_resolution_report.json` (`tallow.vault_resolution_report.v1`)
- `redaction_scan_report.json` (`tallow.redaction_scan_report.v1`)
- `retention_dry_run_report.json` (`tallow.retention_dry_run_report.v1`)
- `manifest_hash_verification.json`
- `command-log.txt`
- `artifact_manifest.json` (`tallow.artifact_manifest.v1`)

The compliance report schema is indexed at `schemas/tallow/compliance-gate-report.schema.json` and validated by:

P2-008 adds canonical error objects to compliance findings. Every violation includes an `error` object with `kind`, `message`, `retryable`, `policy_blocked`, `source_target_id`, `url`, and `phase`; compliance-policy violations canonicalize to `robots_policy` instead of leaking ad hoc strings into downstream request-plan reports.

```bash
python3 scripts/validate_tallow_contracts.py \
  --target-manifest artifacts/phase9/local-no-secret-compliance-proof/phase9-local.target-manifest.v2.json \
  --compliance-gate-report artifacts/phase9/local-no-secret-compliance-proof/compliance_audit_report.json \
  --report-path artifacts/phase9/local-no-secret-compliance-proof/contract_validation_report.json
```

## Fail-closed behavior

The gate exits `2` and writes reports when it detects:

- inline `auth_ref` values instead of fake/local references;
- non-local/real vault references;
- sensitive literal headers such as `Authorization`, `Cookie`, or API-key headers;
- live network scope requests;
- unredacted PII/secret-like scan findings;
- destructive retention requests.

Raw secret/PII values are not written to the JSON reports. Findings include kind, path, line number, and SHA-256 only.

## Human gates

Stop and ask the operator before:

- using real secrets or configuring a real vault;
- running live external scraping/crawling;
- making legal/compliance policy choices;
- executing destructive retention purge/delete;
- claiming production/live compliance readiness.
