# Request-plan operator workflow (2026-10-24)

The six verbs that turn a target manifest into an audited fetch, and the rules
each one enforces. All of them are local except `run-plan --network-scope live`.

```
validate-manifest  →  build-plan  →  run-plan  →  package-report
                                    (preflight / live)
```

`lint --profile scraper` and `fmt --check` guard generated scraper sources
before they enter that chain.

## Exit codes

| code | meaning |
|------|---------|
| 0 | passed / valid / formatted / clean |
| 1 | lint findings, or `fmt --check` found unformatted source |
| 2 | blocked or failed — the gate said no, or the fetch failed |
| 64 | usage error, unreadable file, unwritable output |

`2` is a *verdict*, not a crash: a blocked plan still prints a complete JSON
report on stdout. That separation is the whole point — automation must be able
to tell "the policy refused" from "the tool broke".

## `validate-manifest <MANIFEST> [--report-path FILE]`

Checks a `tallow.target_manifest.v2`:

* `schema_version` is exactly `tallow.target_manifest.v2`
* `manifest_id` is present
* every `targets[i].id` is **v2-safe**: letters, digits, `-`, `_`, `.`; no
  leading dot; at most 64 characters; unique within the manifest
* every `targets[i].url` is `http(s)`
* `method` is one the tree can express (`GET`, `HEAD`, `POST`)
* every target carries `compliance.source_authority`, `.purpose`,
  `.legal_basis`, `.pii_policy` and a numeric `.retention_days`

Report: `tallow.validate_manifest_report.v1`, written to stdout and to
`--report-path` byte-identically. `non_claims.no_network_io` is `true`.

## `build-plan <MANIFEST> --output <PLAN> [--report-path FILE]`

Produces a `tallow.request_plan.v1` plan:

* one request per target, with default headers merged under per-target headers
* `browser_fallback` inherited from `defaults` when the target does not set one
* `source_manifest` = `{path (canonical), sha256 (of the manifest bytes),
  schema_version}` — this is what `run-plan` later verifies, so a plan cannot
  drift from the manifest it was built from without being refused.

Refuses an invalid manifest (same checks as above) with exit `2`.

## `run-plan (--plan FILE | FILE) --output-dir DIR [...]`

Plan path may be positional or `--plan`. Scope is set by `--network-scope`:

| scope | behaviour |
|-------|-----------|
| `local` (default, alias `dry-run`) | evaluates policy, opens nothing, status `planned` |
| `live-preflight` | runs every live gate, opens nothing, status `policy_preflight_passed` |
| `live` | same gates, then one GET per request, status `succeeded` / `failed` |

`--dry-run` downgrades any scope to local evaluation.

### Gate order

Every gate runs before a socket exists, and every refusal lands in
`requests[i].blocked_reasons` with a stable `code`:

1. `invalid_browser_fallback` / `invalid_artifact_policy` — wrong JSON shape
   (`browser_fallback.mode` must be a string)
2. URL scheme — non-http(s) becomes a report-level `unsupported_reasons` entry
3. `live_method_not_enabled` — POST/DELETE have no native live path
4. `live_approval_required` — `live` without `--approve-live`
5. `compliance_gate_report_required` / `compliance_gate_report_invalid` — the
   report must exist, be `tallow.compliance_gate_report.v1`, and its
   `target_manifest.sha256` must equal the plan's attached manifest sha
6. `sensitive_header` — a literal secret in a header. Header *values* are never
   echoed into the report; only the names are named
7. `live_output_dir_not_isolated` — a live run needs an empty output directory
8. `source_manifest_missing` / `source_manifest_invalid` /
   `source_manifest_sha_mismatch`
9. `policy_denylist` / `policy_not_allowlisted` — from the manifest's policy
   block
10. `live_browser_fallback_not_enabled` / `browser_artifact_capture_not_enabled`
    — declared but not wired is refused, never simulated
11. `unsupported_vault_provider` — only `vault://local` resolves. The raw
    `auth_ref` is never serialised; the report carries
    `sha256(auth_ref)` and `auth_ref_serialized: false`

### Live execution

Loopback targets (`127.0.0.0/8`, `::1`, `localhost`) take a direct socket —
loopback never leaves the box and is not egress, so it is not routed through the
configured proxy plane. Everything else goes through
`request_plan::execute_get`, which fails closed on a configured-but-unusable
proxy.

### Artifacts (live only, on a clean run)

```
output-dir/
  artifact_manifest.json     tallow.artifact_manifest.v1 — size + sha256 per file
  request_plan.v1.json       redacted plan snapshot
  requests.jsonl             one line per request
  response_metadata.jsonl    status / length / body sha256 / duration
  source_index.csv           index,target_id,url,status
  run_metrics.json           counts for the run
  compliance_report.json     the gate report as supplied
  responses/
    response-NNN.body.txt    <redacted:sha256:…> (empty bodies included)
    response-NNN.json        per-request metadata
```

Bodies and plan bodies are stored as hash markers, never raw. A blocked run
writes nothing.

## `package-report <RUN_DIR> --output <REPORT>`

Recursive `size_bytes` + `sha256` manifest of a run directory
(`tallow.package_report.v1`), printed to stdout and written to `--output`
identically. The report excludes **its own output by file identity** —
canonicalised parent plus file name — so `run-dir/report.json` and
`/abs/path/run-dir/report.json` are recognised as the same file.

## `fmt <FILE> --check`

Verifies without rewriting. The comparison is against the formatted body, not
the raw file: a generated source carries a `// @generated_by(...)` header the
AST formatter does not reproduce, so the header is stripped from both sides.
Unformatted source exits non-zero and prints `not formatted`.

## `lint <FILE> --profile scraper --format json`

Scraper profile gates for generated source:

* `E-SCRAPER-IMPORT` — calls `http.*` without `import tallow.http`
* `E-SCRAPER-LEGAL` — performs HTTP work without a declared `@legal`

An import alone is not HTTP work, so an import-only file emits neither. Unknown
profiles are refused (`E-PROFILE-UNKNOWN`), never silently treated as clean.
