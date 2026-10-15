# Target Policy

> status: verified 2026-09-05 (C6 docs wave — Phase 9 local/no-secret compliance runner path current; legacy `.ps1` gate correctly labeled).

`scripts/policy_manifest_validate.ps1` is the legacy PowerShell pre-launch policy gate for governed Tallow scraper runs. It validates the manifest before any target list is injected into a `.tl` script or handed to the parallel launcher.

For the Linux/CachyOS 1000x phase gates, use the Phase 9 local/no-secret compliance runner first:

```bash
python3 scripts/compliance_gate.py \
  --target-manifest artifacts/phase9/local-no-secret-compliance-proof/phase9-local.target-manifest.v2.json \
  --output-dir artifacts/phase9/local-no-secret-compliance-proof \
  --scan-path artifacts/phase9/local-no-secret-compliance-proof/scan-input/redacted-response.txt
```

This Phase 9 runner is intentionally local and non-live: it validates policy/compliance metadata, fake/local vault references, redaction scan output, retention dry-run plans, and hash-checked audit artifacts. It does not contact a real vault, resolve secrets, crawl live targets, delete retained data, or claim production compliance readiness.

## Required Manifest Shape

Policy lives under the top-level `policy` key in a target manifest:

```json
{
  "targets": ["https://example.com/api"],
  "policy": {
    "allowlist": {
      "domains": ["example.com", "*.example.com"],
      "url_patterns": ["https://*.example.com/*"]
    },
    "denylist": {
      "url_patterns": ["https://*.example.com/private/*"]
    },
    "robots": {
      "mode": "strict"
    },
    "rate_limits": {
      "per_domain": {
        "example.com": {
          "requests_per_minute": 60,
          "burst": 10,
          "concurrent": 5,
          "cooldown_ms": 250
        }
      },
      "per_ip_pool": {
        "default": {
          "requests_per_minute": 500,
          "burst": 80,
          "concurrent": 50,
          "cooldown_ms": 100
        }
      }
    }
  }
}
```

## Validation Rules

`allowlist` is required and must include at least one `domains` or `url_patterns` selector. Every target must match the allowlist.

`denylist` is required. Denylist selectors override the allowlist, so any matching target fails validation.

`robots.mode` is required and must be one of:

- `strict`: intended mode for production governed runs.
- `advisory`: allowed, but reported as a warning because it does not block targets by itself.
- `off`: allowed, but reported as a warning.

`rate_limits.per_domain` is required. Each target host must match a configured domain key or `default`.

`rate_limits.per_ip_pool` is required. Use `default` when explicit pool routing is not configured.

Rate limit entries support:

- `requests_per_second`: positive number.
- `requests_per_minute`: positive number.
- `burst`: integer greater than or equal to `1`.
- `concurrent`: integer greater than or equal to `1`.
- `cooldown_ms`: integer greater than or equal to `0`.

Each rate limit entry must define at least one of `requests_per_second`, `requests_per_minute`, or `concurrent`.

## Command

Linux/CachyOS Phase 9 local proof:

```bash
python3 scripts/compliance_gate.py \
  --target-manifest artifacts/phase9/local-no-secret-compliance-proof/phase9-local.target-manifest.v2.json \
  --output-dir artifacts/phase9/local-no-secret-compliance-proof \
  --scan-path artifacts/phase9/local-no-secret-compliance-proof/scan-input/redacted-response.txt
```

Validate the Phase 9 contract/report bundle:

```bash
python3 scripts/validate_tallow_contracts.py \
  --target-manifest artifacts/phase9/local-no-secret-compliance-proof/phase9-local.target-manifest.v2.json \
  --compliance-gate-report artifacts/phase9/local-no-secret-compliance-proof/compliance_audit_report.json \
  --report-path artifacts/phase9/local-no-secret-compliance-proof/contract_validation_report.json
```

Legacy PowerShell policy validator:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\policy_manifest_validate.ps1 -ManifestPath configs\tallow\targets.example.json -ReportPath artifacts\policy_validation_report.json
```

The script writes the validation report to stdout and, when `-ReportPath` is supplied, to that path.

## Report Contract

The report schema is `tallow.policy.validation.v1`:

```json
{
  "schema_version": "tallow.policy.validation.v1",
  "generated_at_utc": "2026-04-28T00:00:00.000Z",
  "manifest_path": "~/Nixe\\configs\\tallow\\targets.example.json",
  "passed": true,
  "targets_total": 5,
  "domains_total": 3,
  "effective_policy": {
    "robots_mode": "advisory",
    "allowlist": {
      "domains": ["apollo.io", "*.apollo.io"],
      "url_patterns": ["https://*.apollo.io/*"]
    },
    "denylist": {
      "domains": [],
      "url_patterns": ["https://*.apollo.io/private/*"]
    },
    "rate_limits": {
      "per_domain_keys": ["app.apollo.io", "api.apollo.io"],
      "per_ip_pool_keys": ["default"]
    }
  },
  "violation_count": 0,
  "warning_count": 1,
  "violations": [],
  "warnings": []
}
```

The process exits with `1` when `violation_count` is greater than `0`; warnings do not fail the run.

## Phase 9 Human Gates

The Linux/CachyOS Phase 9 gate must stop before any of these actions unless the operator explicitly approves them in the current session:

- live external scraping or crawling;
- real secret material or real credential vault configuration;
- legal/compliance policy choices;
- destructive retention purge/delete/rewrite;
- production compliance-readiness claims;
- Windows support.
