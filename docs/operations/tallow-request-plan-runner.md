# Tallow Request Plan Runner

> **Docs truth label:** Authoritative current operator/runtime contract for request-plan execution surfaces. This documents local/mock execution, zero-I/O preflight, approved native live GET gates, fail-closed unsupported semantics, and canonical reports; it is not approval for ungated live scraping, real vault secret resolution, browser execution, paid benchmarks, destructive retention, or Windows support.

Status: Current Linux/CachyOS request-plan runner contract after P2-008 canonical error taxonomy.

`scripts/run_tallow_request_plan.py` consumes `tallow.request_plan.v1` JSON directly. It is a stdlib-only Linux-native runner for local/mock verification of request-plan semantics. It does not use the legacy TL `http.batch` downgrade path.

This runner advances BLK-008 from producer-only request-plan generation toward runtime consumption, but it remains a bounded local/mock proof. It does not claim live external scraping, browser fallback execution, real vault-backed auth, benchmark readiness, or Windows/PowerShell support. Live-preflight gates now require a local/no-secret compliance gate report, but that report is proof metadata rather than a legal approval decision.

## Supported in this slice

- Request-plan schema gate: `schema_version == "tallow.request_plan.v1"`.
- Local/mock-only network execution by default.
- Optional `--mock-base-url` rewrite that preserves original request path/query while executing against loopback.
- `GET` requests.
- `POST` requests with `body.kind == "json"` and `application/json` content type.
- GraphQL query metadata when represented by an inline JSON POST body containing a `query` string.
- Per-request headers, with hop-by-hop and unresolved-secret-looking headers refused.
- Simple retry policy for retryable kinds such as `http_5xx`.
- Source-manifest request policy enforcement when a validated `source_manifest` is attached: allowlist, denylist, robots mode (`strict`/`advisory`, `off` fail-closed without explicit approval), per-domain rate-limit presence, and request compliance metadata.
- `--network-scope live-preflight` for zero-I/O validation of external/live targets against the attached source manifest and a passing `tallow.compliance_gate_report.v1` local proof.
- Native `tallow run-plan --network-scope live --approve-live` for approval-gated GET execution after source-manifest policy, local compliance report, live approval, isolated output directory, unresolved-secret gates, and browser-fallback fail-closed gates pass.
- Browser fallback boundary reporting: `browser_fallback.mode=reasoned` is recognized but fails closed until WebSocket CDP, budget, artifact capture, and challenge-classification proofs exist; reports include `browser_fallback` capability metadata and `non_claims.browser_execution=false`.
- Artifact policy for redacted response body capture when `capture_body` is `redacted` and `screenshots`/`har`/`dom` are `never`; sensitive JSON keys such as `query`, tokens, cookies, passwords, and secrets are hash-redacted in captured response snippets.
- Execution report: `tallow.request_plan_run_report.v1`.
- Artifact manifest: `tallow.artifact_manifest.v1`.
- Canonical error object: P2-008 report rows and artifact/package reports include `error` objects with `kind`, `message`, `retryable`, `policy_blocked`, `source_target_id`, `url`, and `phase`; legacy `error_kind`, `error_message`, and `blocked_reasons` remain compatibility fields only.

## Canonical error contract

Every blocked/failed row emitted by the Python compatibility runner or native CLI should expose the P2-008 canonical error object:

```json
{
  "kind": "robots_policy",
  "message": "blocked by policy",
  "retryable": false,
  "policy_blocked": true,
  "source_target_id": "target-id",
  "url": "https://example.invalid/path",
  "phase": "request_policy"
}
```

Known legacy/internal codes such as `policy_denylist`, `inline_auth_ref`, `compliance_gate_report_required`, `compliance_gate_legal_metadata_missing`, `live_browser_fallback_not_enabled`, `extraction_schema_invalid`, and `unsupported_body` are mapped into the canonical taxonomy instead of silently surfacing as `unknown`. `kind=unknown` is reserved for genuinely unmapped/unclassified failures and should trigger a new regression when a known emitted code is added.

## Fail-closed in this slice

The runner validates the whole plan before network I/O. If unsupported semantics exist, it writes a report, exits `2`, and makes no requests.

Unsupported now:

- Native live execution methods other than GET until POST/body artifact parity is implemented for the Rust CLI;
- non-loopback URLs without `--mock-base-url` in local scope;
- methods other than `GET`/`POST`;
- `POST` without `body.kind == "json"`;
- body kinds other than `none`/`json`;
- GraphQL mutation or `query_ref` resolver usage;
- `auth_ref`;
- `browser_fallback.mode=reasoned` is recognized but blocked until WebSocket CDP execution, browser budget enforcement, artifact capture, and challenge-classification proofs exist;
- screenshot, HAR, or DOM browser artifact capture;
- `artifact_policy.capture_body` values other than `none` or `redacted`;
- hop-by-hop headers or unresolved secret/template-looking header values;
- validated source-manifest request policy denials: denylist hits, allowlist misses, missing/non-positive per-domain rate limits, missing compliance metadata, approval-required targets, and `robots.mode=off` without a future explicit approval gate;
- missing, malformed, non-passing, SHA-mismatched, or legally incomplete `--compliance-gate-report` inputs for `live-preflight`/live-policy-preflight.

## CLI

### Native operator workflow

P2-007 makes the Rust CLI the primary supported operator surface. Python scripts remain implementation details for compatibility and build helpers.

```bash
tallow doctor
tallow doctor --stdlib-scraper
tallow check <file.tl>
tallow run <file.tl>
tallow validate-manifest <sources_manifest.json>
tallow build-plan <sources_manifest.json> --output <request-plan.v1.json>
tallow run-plan <request-plan.v1.json> --dry-run --network-scope local
tallow package-report <run-dir> --output <package-report.json>
```

`validate-manifest`, `build-plan`, and `package-report` are local/no-network commands. `run-plan` now accepts the positional request-plan path shown above while preserving the legacy `--plan <path>` form.

### Python compatibility runner

Dry run / classify only:

```bash
python3 scripts/run_tallow_request_plan.py \
  --plan artifacts/phase2/request-plans/local-get-post-graphql-runtime.request-plan.v1.json \
  --report-path /tmp/request-plan-dry-run.json \
  --output-dir /tmp/request-plan-dry-run-artifacts \
  --mock-base-url http://127.0.0.1:18080 \
  --dry-run
```

Local/mock execution:

```bash
python3 scripts/run_tallow_request_plan.py \
  --plan artifacts/phase2/request-plans/local-get-post-graphql-runtime.request-plan.v1.json \
  --report-path artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/execution_report.json \
  --output-dir artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof \
  --mock-base-url http://127.0.0.1:<mock-port> \
  --timeout-seconds 5 \
  --max-response-bytes 1048576
```

`--network-scope` supports `local`, `live-preflight`, and `live`. The Python compatibility runner still keeps actual live execution disabled; use `--network-scope live-preflight` (or legacy `--network-scope live --live-policy-preflight`) for zero-I/O policy validation. Live-preflight now requires `--compliance-gate-report path/to/compliance_audit_report.json`, produced by `scripts/compliance_gate.py` and carrying complete legal metadata, redaction pass, dry-run retention, and no-network/no-secret proof flags.

## Local/mock extraction rows

P1-005 wires `extraction_schema_ref` into the Python compatibility runner for local/mock execution. When a supported request succeeds, the runner loads the referenced `tallow.extraction_schema.v1` schema from the repository schema registry, dispatches selectors against the response body, and writes:

- `extraction/rows.jsonl` — `tallow.extraction_row.v1` rows;
- `extraction/quarantine.jsonl` — quarantined rows with machine-readable reason codes such as `required_field_null:<field>`;
- `extraction/validation_report.json` — output from `scripts/validate_extraction_rows.py`.

Supported parser dispatch in this slice is intentionally local/mock and stdlib-only: JSON path selectors (`$.products[*].name` style), lightweight CSS class selectors for fixture HTML, regex selectors, meta selectors, and literal `source_url` fallback. The runner still does not claim production/live extraction readiness; row artifacts set `non_claims.live_scraping`, `external_dataset`, and `production_ready` to `false`.

## Native CLI dry-run / preflight

P0-007 adds a first-class native CLI entry point for request-plan dry-runs and policy preflight reports:

```bash
./target/debug/tallow run-plan \
  --plan artifacts/phase2/request-plans/get-only-legacy-safe.request-plan.v1.json \
  --dry-run \
  --network-scope local
```

The native command prints `tallow.request_plan_run_report.v1` JSON to stdout and reports the same versioned execution core as the TL runtime bridge with role `native_cli_bridge`. Local dry-run performs no network I/O. `live-preflight` also performs no network I/O, but it requires a passing `--compliance-gate-report`, validates attached source-manifest request policy, and blocks denied URLs with machine-readable `blocked_reasons` before any fetch path.

Approval-gated live GET execution is available only with every live gate satisfied:

```bash
./target/debug/tallow run-plan \
  --plan path/to/request-plan.v1.json \
  --output-dir /tmp/isolated-tallow-live-run \
  --network-scope live \
  --approve-live \
  --compliance-gate-report path/to/compliance_audit_report.json
```

The live path requires a validated attached source manifest, local compliance report, policy/compliance pass, robots/rate-limit configuration, a nonexistent or empty isolated output directory, no unresolved `auth_ref`/vault-looking header references, browser fallback set to absent/`never`, no browser screenshot/HAR/DOM capture request, and currently GET-only native execution. Reports include `native_live_supported_methods: ["GET"]` so this narrower live capability is not confused with the shared execution contract's broader `GET`/`POST` method validation.

P1-008 browser fallback boundary: `reasoned` mode is parsed and reported but intentionally blocks with `live_browser_fallback_not_enabled` before network I/O in both `live-preflight` and approved `live`. Pipe transport is fail-closed; WebSocket CDP is listed as `not_implemented`; challenge pages must be classified-and-stopped, with no stealth/CAPTCHA bypass claim. Browser screenshot/HAR/DOM artifact requests block with `browser_artifact_capture_not_enabled` until the browser runtime has local proof artifacts.

Approved native live runs now write the P1 artifact set under `--output-dir`: `artifact_manifest.json`, redacted `request_plan.v1.json`, `requests.jsonl`, `responses/`, `response_metadata.jsonl`, `source_index.csv`, `run_metrics.json`, and `compliance_report.json`. Response body artifacts are hash-redacted (`<redacted:sha256:...>`) and every manifest-listed artifact records final size and SHA-256.

## Proof artifacts

Runtime fixture source:

- `artifacts/phase2/request-plans/local-get-post-graphql-runtime.target-manifest.v2.json`
- `artifacts/phase2/request-plans/local-get-post-graphql-runtime.request-plan.v1.json`
- `artifacts/phase2/request-plans/local-get-post-graphql-runtime.request-plan-report.json`

Local/mock runtime proof:

- `artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/execution_report.json`
- `artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/artifact_manifest.json`
- `artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/request_plan.v1.json`
- `artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/requests.jsonl`
- `artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/requests/`

The proof executes three original external-looking request-plan targets through a loopback mock rewrite:

- `GET /status?case=get` with per-target header propagation;
- `POST /graphql` with JSON GraphQL query body and GraphQL metadata in the report;
- `GET /retry` with first attempt HTTP 500, second attempt HTTP 200, and retry/artifact evidence.

Expected proof summary:

```text
runner_exit=0
runner_passed=True executed=3 succeeded=3 attempts=4
server_requests=4 methods=['GET', 'POST', 'GET', 'GET']
artifact_manifest_schema=tallow.artifact_manifest.v1 files=12
raw_graphql_query_in_execution_report=False
raw_graphql_query_in_response_body_artifact=False
report_hash_in_manifest_matches=True
```

## Verification

Targeted runner tests:

```bash
python3 -B -m unittest tests.test_phase2_request_plan_runner -v
```

Expected:

```text
Ran 20+ tests (exact count depends on active roadmap regressions)
OK
```

Full narrow Phase 2 runner loop:

```bash
python3 -B -m unittest tests.test_phase2_request_plan_builder tests.test_phase2_request_plan_runner -v
python3 -m py_compile scripts/build_tallow_request_plan.py scripts/run_tallow_request_plan.py tests/test_phase2_request_plan_runner.py
python3 scripts/validate_tallow_contracts.py \
  --target-manifest artifacts/phase2/normalized-targets/targets.example.36b7ab6a20ea.target-manifest.v2.json \
  --report-path artifacts/phase2/contract_validation_report.json
./target/debug/tallow check artifacts/phase2/request-plans/get-only-legacy-safe.legacy-http-batch.tl
python3 scripts/phase1_smoke_ladder.py --skip-build --skip-targeted-tests
```

## Status boundary

This slice is runtime-verified for local/mock HTTP request-plan semantics, zero-I/O live-preflight policy/compliance validation, and approved native live GET execution when all local source-manifest/compliance/isolation/fail-closed gates pass.

Still pending before production-live scraper readiness:

- approved external live fetch expansion beyond policy-gated native GET execution (POST/body parity and non-native/browser capture paths remain pending);
- real vault-backed `auth_ref` resolution and secret injection beyond the current fake/local fail-closed report interface;
- browser fallback execution and screenshot/HAR capture;
- human/legal approval workflow for production compliance decisions beyond the current local/no-secret compliance gate report;
- benchmark/performance readiness.
