# Tallow + `.tl` Full Fix List / Repair Roadmap

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make Tallow and `.tl` scripts reliable enough that generated public-source research/scraper packages can be checked, run, validated, audited, resumed, and packaged without Python-only escape hatches or runtime surprises.

**Architecture:** Treat Tallow as three connected layers that must agree: (1) `.tl` language/compiler/checker, (2) interpreter/runtime/stdlib dispatch, and (3) Nixe/Tallow scraper/request-plan/artifact/compliance pipeline. Fixes should move from local/mock proof to policy-gated live execution only with explicit safe gates.

**Tech Stack:** Rust root Tallow crate, `.tl` stdlib declarations under `stdlib/`, Python contract/request-plan helpers under `scripts/`, JSON schemas under `schemas/tallow/`, docs/phase artifacts under `docs/mega/`, Nixe personal database packages under `personal_database/`.

---

## 0. Ground truth from current repo state

### 0.1 Verified evidence used for this plan

- Current binary reports `tallow 0.4.0` on Linux/CachyOS.
- Root workspace is intentionally dirty; do not revert unrelated changes.
- Existing docs truth says current accepted scope is mostly Linux/CachyOS local/non-live/offline/fixture/no-secret proof through Phase 11.
- Existing blocker/capability docs show key remaining gaps:
  - stdlib/runtime/doc drift remains visible;
  - live external scraping remains deferred/human-gated;
  - request-plan runner is local/mock-only for network execution;
  - browser fallback is accepted only as local planner/status metadata, not live browser execution;
  - extraction rows are local/mock only;
  - compliance/vault/retention is local/no-secret only;
  - Firecrawl/live benchmark claims are not accepted.
- The latest generated public-source package under `personal_database/ashraf_ali_business_inquiry/` produced this concrete failure:

```text
./target/debug/tallow check ashraf_ali_business_inquiry.legacy-http-batch.tl
=> check passed: 1 items, 0 warning(s)

./target/debug/tallow run ashraf_ali_business_inquiry.legacy-http-batch.tl
=> runtime error: undefined function: http.batch
```

### 0.2 Main diagnosis

Tallow currently has a dangerous **truth gap**:

```text
Generated .tl script can pass checker/compiler validation,
but fail at runtime because stdlib/runtime dispatch does not implement the function.
```

The immediate example is `http.batch`, but the larger issue is broader: `.tl` declarations, generated scripts, the checker, native dispatch, interpreter runtime, Python request-plan bridge, and docs are not fully locked together by one conformance gate.

---

## 1. Definition of “fixed entirely”

Tallow should not be called “fixed” until all of these are true:

1. `cargo check --locked` passes.
2. `cargo test --locked` or the accepted narrow test matrix passes.
3. `./target/debug/tallow doctor` passes on the operator’s CachyOS system.
4. `./target/debug/tallow check` rejects `.tl` scripts that reference missing stdlib functions.
5. `./target/debug/tallow run` executes generated safe transport `.tl` scripts or fails at check-time with a clear unsupported-semantics message.
6. `stdlib/*.tl` declarations match Rust runtime dispatch and method dispatch.
7. The stdlib surface manifest has zero unexpected drift for scraper-critical modules.
8. Request-plan generation, TL generation, and runtime execution all share one contract.
9. Public-source scraper packages can go from:

```text
sources_manifest.json -> request-plan.v1.json -> .tl transport -> run report -> artifacts
```

without hand-editing.

10. Live external execution is impossible unless policy gates, robots/rate limits, retention, redaction, and approval gates pass.
11. Artifacts are reproducible: manifest, raw responses/metadata, normalized rows, validation reports, metrics, and source index.
12. Docs truth labels match actual runtime behavior.

---

## 2. P0 fixes — must fix before trusting generated `.tl` packages

## P0-001 — Make checker fail when runtime stdlib function is missing

**Problem:** `tallow check` accepts generated `.tl` containing `http.batch(...)`, but `tallow run` fails because `http.batch` is undefined.

**Observed evidence:**

- Generated file: `personal_database/ashraf_ali_business_inquiry/ashraf_ali_business_inquiry.legacy-http-batch.tl`
- Runtime result: `runtime error: undefined function: http.batch`
- Search evidence: `stdlib/http.tl` has no `batch`; `src/stdlib/http.rs` dispatches `get`, `post`, `put`, `delete`, `listen`, `server`, not `batch`.

**Files to inspect/modify:**

- `src/typeck.rs`
- `src/interp.rs`
- `src/stdlib/mod.rs`
- `src/stdlib/http.rs`
- `stdlib/http.tl`
- `scripts/generate_stdlib_surface_manifest.py`
- `tests/test_phase2_stdlib_surface_manifest.py`
- Add focused test: `tests/stdlib_http_batch.rs` or equivalent existing test area.

**Fix direction:**

1. Generate or load stdlib runtime surface during typecheck.
2. If a `.tl` function call uses a namespaced stdlib function missing from dispatch/declarations, fail during `check`.
3. Report a clear diagnostic:

```text
error[E-stdlib-missing]: function http.batch is declared/generated but not implemented in runtime dispatch
```

4. Add regression test using the current generated Ashraf package or a small fixture.

**Acceptance:**

```bash
cd /mnt/Personal/Nixe
./target/debug/tallow check tests/fixtures/stdlib_missing_http_batch.tl
# Expected before P0-002: FAIL at check-time, not runtime.
```

---

## P0-002 — Implement `http.batch` or stop generating it

**Problem:** `build_tallow_request_plan.py` emits legacy TL using `http.batch(target_urls, concurrency, headers)`, but runtime does not implement it.

**Files:**

- `scripts/build_tallow_request_plan.py`
- `src/stdlib/http.rs`
- `stdlib/http.tl`
- `tests/test_phase2_request_plan_builder.py`
- New `.tl` fixture: `tests/fixtures/http_batch_get_only.tl`

**Option A — implement `http.batch` in Rust runtime:**

Add dispatch arm:

```rust
"batch" => Some(http_batch(args)),
```

Minimum semantics:

- Input:
  - `urls: []String`
  - `concurrency: Int`
  - `headers: Map<String, String>` optional/default `{}`
- Output:
  - `[]Response` or `BatchResult` with per-request result metadata.
- Enforce:
  - max concurrency cap;
  - timeout per request;
  - safe body limit;
  - no secrets in headers;
  - structured error per URL instead of one crash killing the whole batch.

**Option B — stop generating `http.batch`:**

Make `build_tallow_request_plan.py` emit only runtime-supported `.tl`, such as a loop over `http.get`, if loops/maps are stable enough.

**Preferred:** Option A, because generated packages need a real batch transport and existing builder tests assert `http.batch(target_urls`.

**Acceptance:**

```bash
cd /mnt/Personal/Nixe
./target/debug/tallow check tests/fixtures/http_batch_get_only.tl
./target/debug/tallow run tests/fixtures/http_batch_get_only.tl
```

Expected:

```text
check passed
legacy transport request count=<N>
```

For local/mock tests, use a loopback HTTP server, not external web.

---

## P0-003 — Align `stdlib/http.tl` declarations with `src/stdlib/http.rs`

**Problem:** `stdlib/http.tl` is still labeled as a stub and lacks runtime-supported functions such as batch, timeout/header forms, and actual response methods. Some docs previously claimed drift in response shape.

**Files:**

- `stdlib/http.tl`
- `src/stdlib/http.rs`
- `scripts/generate_stdlib_surface_manifest.py`
- `artifacts/phase*/stdlib_surface_manifest.json`

**Fix list:**

1. Declare every runtime-dispatched function:
   - `http.get`
   - `http.post`
   - `http.put`
   - `http.delete`
   - `http.batch`
   - `http.listen` / `http.server` if still supported.
2. Declare response shape exactly:
   - `status`
   - `body`
   - `headers`
   - `url`
   - `time_ms`
3. Declare response methods exactly:
   - `.text()`
   - `.json()`
4. Remove “stub” language if it is now a real native module.
5. Regenerate stdlib surface manifest.

**Acceptance:**

```bash
cd /mnt/Personal/Nixe
python3 scripts/generate_stdlib_surface_manifest.py --output /tmp/stdlib_surface_manifest.json
python3 scripts/validate_tallow_contracts.py --stdlib-surface-manifest /tmp/stdlib_surface_manifest.json --report-path /tmp/stdlib_surface_validation.json
```

Expected:

```text
validation passed
http module aligned
```

---

## P0-004 — Make generated TL imports/namespaces unambiguous

**Problem:** Generated TL uses `http.batch(...)`. Depending on language rules, this may be treated differently from `tallow.http.batch` or an imported namespace. The runtime error says `undefined function: http.batch`, suggesting namespace dispatch exists but function does not.

**Files:**

- `src/parser.rs`
- `src/ast.rs`
- `src/interp.rs`
- `src/typeck.rs`
- `scripts/build_tallow_request_plan.py`
- `stdlib/http.tl`

**Fix list:**

1. Decide canonical namespace syntax:
   - `http.batch(...)`, or
   - `tallow.http.batch(...)`, or
   - `use tallow.http; http.batch(...)`.
2. Enforce one canonical style in generated scripts.
3. Add checker diagnostics for missing imports/unknown namespaces.
4. Add a formatter/linter rule to normalize old scripts.

**Acceptance:**

A generated `.tl` script must include deterministic namespace/import syntax and pass both `check` and `run` against loopback tests.

---

## P0-005 — Add a generated-package end-to-end test

**Problem:** The Ashraf Ali inquiry exposed a real integration gap only after generating a package. This should be a standard test.

**Files:**

- `tests/test_generated_public_source_package.py`
- `scripts/build_tallow_request_plan.py`
- `scripts/run_tallow_request_plan.py`
- `tests/fixtures/public_source_manifest_minimal.json`

**Test flow:**

1. Create minimal target manifest with 2 local/mock GET targets.
2. Validate manifest.
3. Build request plan.
4. Emit legacy `.tl`.
5. Run `tallow check`.
6. Run `tallow run` against loopback or dry-run transport.
7. Validate artifacts.

**Acceptance:**

```bash
python3 -B -m unittest tests.test_generated_public_source_package -v
```

Expected:

```text
Ran N tests
OK
```

---

## P0-006 — Make request-plan runner and TL runtime share one execution core

**Problem:** Python request-plan runner can validate/dry-run a plan, while generated TL transport follows another path. That creates divergence.

**Files:**

- `scripts/run_tallow_request_plan.py`
- `src/stdlib/http.rs`
- `src/interp.rs`
- future Rust request-plan module under `src/` or `crates/`

**Fix direction:**

1. Extract canonical request execution semantics into one Rust module or one formally versioned contract.
2. Make Python runner a compatibility bridge, not the source of truth.
3. Make `.tl` runtime call the same execution rules for:
   - headers;
   - retries;
   - redaction;
   - artifact capture;
   - body limits;
   - compliance gate status.

**Acceptance:**

Same manifest + same mock server should produce equivalent request counts/statuses/artifacts through:

```text
Python request-plan runner
Tallow .tl runtime transport
Future native `tallow run-plan` command
```

---

## P0-007 — Create a `tallow run-plan` CLI command

**Problem:** Today the main reliable path is Python scripts plus generated `.tl`, but the CLI does not expose a first-class request-plan execution command.

**Files:**

- `src/main.rs`
- `src/cli/`
- new module: `src/request_plan.rs` or `crates/tallow-runtime-request-plan/`
- schemas under `schemas/tallow/`

**Command design:**

```bash
tallow run-plan \
  --plan path/to/request-plan.v1.json \
  --output-dir path/to/artifacts \
  --network-scope local|live-preflight|live \
  --policy strict \
  --dry-run
```

**Rules:**

- `local`: loopback/mock only.
- `live-preflight`: validate policy, no network I/O.
- `live`: require explicit approval/config file and compliance gate pass.

**Acceptance:**

```bash
./target/debug/tallow run-plan --plan artifacts/...request-plan.v1.json --dry-run --network-scope local
```

Expected: JSON report with `passed=true`, no network I/O unless local/mock.

---

## P0-008 — Add fail-fast startup self-check for scraper-critical stdlib

**Problem:** Operators can start a Tallow scraper package that depends on missing stdlib functions.

**Files:**

- `src/main.rs`
- `src/stdlib/mod.rs`
- `src/stdlib/http.rs`
- `scripts/phase1_smoke_ladder.py`

**Fix:**

Add command:

```bash
tallow doctor --stdlib-scraper
```

Checks required functions:

- `http.get`
- `http.post`
- `http.batch`
- `Response.text`
- `Response.json`
- `json.parse`
- `html.parse/select/text/attr`
- `time.now`
- artifact/report helpers if implemented.

**Acceptance:**

Doctor report lists every required scraper-critical function and whether runtime dispatch + declaration + tests exist.

---

## 3. P1 fixes — make `.tl` usable for real source-backed packages

## P1-001 — Typed HTTP result model

**Problem:** Batch/live scraping needs structured per-request results, not only `Response` or runtime errors.

**Add types in `stdlib/http.tl`:**

```tl
struct HttpError {
    kind: String,
    message: String,
    retryable: bool,
    status: u16?,
    url: String,
}

struct BatchResponse {
    url: String,
    ok: bool,
    response: Response?,
    error: HttpError?,
    attempts: u16,
    elapsed_ms: u64,
}
```

**Runtime needs:**

- classify DNS/TLS/timeout/4xx/5xx/blocked/body-too-large;
- never panic on one failed URL;
- return stable fields for artifact/report writing.

---

## P1-002 — Request policy in runtime, not just manifest docs

**Problem:** Manifests contain robots/rate-limit/allowlist policy, but runtime execution path must enforce policy.

**Fix list:**

1. Add allowlist/denylist check before execution.
2. Add per-domain rate limits.
3. Add robots mode gate:
   - `strict`
   - `advisory`
   - `off` only with explicit approval.
4. Add reasoned block report when policy denies a request.

**Acceptance:**

A manifest with a denied URL must fail before network I/O and produce a machine-readable blocked reason.

---

## P1-003 — Implement live-preflight and live-safe execution modes

**Problem:** Current request-plan runner is documented as local/mock-only for external URLs. That is safe, but packages need a path to approved live public-source extraction.

**Fix list:**

1. Keep default `network_scope=local`.
2. Add `network_scope=live-preflight` that validates external targets without fetching.
3. Add `network_scope=live` only if:
   - manifest is validated;
   - compliance gate passes;
   - robots/rate limits are configured;
   - output directory is isolated;
   - command includes explicit approval flag/config;
   - no unresolved auth/vault refs unless vault gate passes.
4. Emit non-claims when not live.

---

## P1-004 — Artifact capture from `.tl` runtime

**Problem:** Generated `.tl` packages should produce audit artifacts like Python bridge packages do.

**Required output files:**

```text
artifact_manifest.json
request_plan.v1.json
requests.jsonl
responses/
response_metadata.jsonl
source_index.csv
run_metrics.json
compliance_report.json
```

**Fix list:**

- Add artifact writer stdlib or native runner support.
- Hash every artifact after write.
- Redact sensitive headers/body fields.
- Preserve source URL and access timestamp.

---

## P1-005 — Extraction schema execution in runtime

**Problem:** Extraction rows are validated locally/mock, but request-plan runner refuses `extraction_schema_ref` today.

**Fix list:**

1. Add schema registry loader.
2. Implement parser strategy dispatch:
   - HTML selectors;
   - JSON path;
   - GraphQL JSON envelope;
   - table extraction;
   - link discovery.
3. Produce `extraction-row.schema.json` compatible rows.
4. Quarantine invalid rows with reason codes.
5. Reuse `scripts/validate_extraction_rows.py` until Rust validator parity exists.

---

## P1-006 — Canonical source-backed research package command

**Problem:** The Ashraf package was generated with custom glue. This should become one first-class command or script.

**Command shape:**

```bash
tallow research-package init \
  --slug ashraf_ali_business_inquiry \
  --entities entities.csv \
  --queries queries.md \
  --public-only \
  --output personal_database/ashraf_ali_business_inquiry
```

**Outputs:**

- Markdown inquiry
- manifest
- request plan
- TL script
- dry-run report
- artifact folder
- README
- run report

---

## P1-007 — GraphQL/POST support from manifest into `.tl`

**Problem:** Phase 2 request plans support POST JSON/GraphQL metadata locally/mock, but legacy TL downgrade only supports safe GET/global headers.

**Fix options:**

1. Extend TL generator beyond legacy `http.batch` with structured `http.request_batch` supporting method/body.
2. Or stop emitting `.tl` for unsupported request-plan semantics and force native `run-plan`.

**Acceptance:**

Lossy downgrade must never silently happen. POST/GraphQL either works or fails before `.tl` emission.

---

## P1-008 — Browser fallback live execution, gated and honest

**Problem:** Browser fallback is currently accepted as local planner/status metadata, not live execution.

**Fix list:**

1. Keep default as `never`.
2. Add explicit `reasoned` mode that can launch Chromium only under live-approved runs.
3. Implement WebSocket CDP only first; leave pipe fail-closed unless implemented.
4. Capture screenshots/HAR/DOM only when artifact policy allows.
5. Write browser budget and reason codes to artifacts.
6. Never claim stealth/CAPTCHA bypass; classify challenge pages and stop.

---

## P1-009 — Credential/vault integration for authorized targets

**Problem:** Compliance phase proves fake/no-secret vault handling only. Real authorized targets need safe vault resolution.

**Fix list:**

1. Add real vault provider interface.
2. Resolve credentials only in approved live mode.
3. Never serialize secrets to request plan snapshots.
4. Redact in logs/reports.
5. Add tests that secret literals fail closed.

---

## P1-010 — Production compliance gate

**Problem:** Compliance gate is local/no-secret proof; production enforcement is deferred.

**Fix list:**

1. Make every live run require a compliance gate report.
2. Include:
   - legal basis;
   - public/authorized source classification;
   - robots mode;
   - retention days;
   - redaction policy;
   - source authority;
   - approval ID if live.
3. Fail closed for missing legal metadata.

---

## 4. P2 fixes — quality, performance, and operator readiness

## P2-001 — Stdlib parity closure across all scraper-critical modules

Close drift for:

- `http`
- `html`
- `json`
- `browser`
- `fs`
- `time`
- `log`
- `url`
- `process`
- artifact/report helpers

**Acceptance:** stdlib surface manifest has zero open scraper-critical gaps.

---

## P2-002 — Compiler/interpreter parity tests

For every meaningful `.tl` feature used by generated scripts, add tests for:

- parser;
- typechecker;
- interpreter;
- codegen if supported;
- formatter/linter if applicable.

Generated scripts rely on:

- arrays;
- maps;
- string concatenation;
- method calls;
- namespaced function calls;
- annotations;
- function declarations;
- integer literals;
- response length/method access.

---

## P2-003 — Replace giant ad-hoc `.tl` scripts with generated packages

The repo contains many historical/probe `.tl` files. Classify them:

```text
active example
fixture test
historical probe
unsafe/deprecated
superseded by manifest/request-plan
```

Add headers to old scripts so agents do not treat them as current best practice.

---

## P2-004 — Release-quality examples

Create clean examples:

```text
examples/public_source_get_batch.tl
examples/request_plan_get_only/
examples/request_plan_post_graphql/
examples/extraction_schema_html/
examples/browser_fallback_manual_gate/
```

Each example must have:

- README;
- exact command;
- expected output;
- fixture/mock server if network involved.

---

## P2-005 — Live benchmark matrix, only after live runner exists

Do not claim performance superiority until live runner exists.

Benchmark only with:

- approved public corpus;
- same target windows;
- fixed output schema;
- same retry budget;
- validation quality score;
- cost/resource metrics;
- Firecrawl comparison clearly labeled live or mock.

---

## P2-006 — CI gates

Minimum CI matrix:

```bash
cargo check --locked
cargo test --locked --test browser_contracts
python3 -B -m unittest tests.test_phase2_request_plan_builder -v
python3 -B -m unittest tests.test_phase2_request_plan_runner -v
python3 -B -m unittest tests.test_phase5_extraction_rows -v
python3 -B -m unittest tests.test_phase9_compliance_gate -v
python3 scripts/phase1_smoke_ladder.py
```

Add generated package e2e once P0-005 exists.

---

## P2-007 — Operator command set

Operators should have a short set of reliable commands:

```bash
tallow doctor
tallow doctor --stdlib-scraper
tallow check <file.tl>
tallow run <file.tl>
tallow validate-manifest <sources_manifest.json>
tallow build-plan <sources_manifest.json>
tallow run-plan <request-plan.v1.json> --dry-run
tallow package-report <run-dir>
```

Python scripts may remain implementation details, but the CLI should be the primary interface.

---

## P2-008 — Error taxonomy unification

Unify error kinds across:

- runtime HTTP errors;
- request-plan runner errors;
- extraction-row validation errors;
- compliance gate errors;
- browser fallback decision errors;
- artifact packaging errors.

Every error should have:

```text
kind
message
retryable
policy_blocked
source_target_id
url
phase
```

---

## P2-009 — Documentation truth maintenance

Every high-level doc must be labeled as one of:

```text
authoritative current contract
accepted local proof
roadmap / not proof
historical probe
superseded
```

Update:

- `docs/mega/tallow-1000x-blocker-register.md`
- `docs/mega/tallow-1000x-capability-matrix.md`
- `docs/tallow-scraper-full-task-list.md`
- `docs/operations/*`
- new plan docs under `docs/plans/`

---

## 5. P3 fixes — polish and long-term hardening

## P3-001 — Formatter/linter for generated `.tl`

Generated scripts should be deterministic:

```bash
tallow fmt generated.tl --check
tallow lint generated.tl --profile scraper
```

Lint rules:

- no unknown stdlib calls;
- no unsupported live network calls;
- no missing `@legal` annotation for network/storage;
- no hardcoded secrets;
- no huge inline target lists beyond threshold unless generated.

---

## P3-002 — `.tl` package metadata

Each generated package should include metadata:

```tl
@package(name: "ashraf_ali_business_inquiry", schema: "tallow.package.v1")
@legal(...)
@generated_by(tool: "build_tallow_request_plan.py", version: "...")
```

---

## P3-003 — Better developer diagnostics

Improve runtime errors from:

```text
runtime error: undefined function: http.batch
```

to:

```text
runtime error[E-stdlib-missing]: http.batch is not implemented in runtime dispatch.
Source: line 43 in ashraf_ali_business_inquiry.legacy-http-batch.tl
Suggested fixes:
  - upgrade Tallow runtime to a version with http.batch
  - regenerate script with --transport loop-http-get
  - run request-plan via tallow run-plan
```

---

## P3-004 — Generated package reproducibility

Every generated package should write:

```text
generation_manifest.json
input_hashes.json
tallow_version.txt
git_status_summary.txt
commands.sh
```

This prevents future confusion about which binary/script generated which files.

---

## P3-005 — Self-host compiler boundary

The self-host Tallow compiler should be labeled clearly:

- experiment;
- not production compiler;
- smoke tested or not;
- parity target or not.

Do not mix self-host claims with root Rust compiler acceptance until proven.

---

## 6. Suggested implementation order

### Sprint 1 — Stop runtime surprises

1. Add failing test for `http.batch` generated script.
2. Implement `http.batch` or stop emitting it.
3. Align `stdlib/http.tl` with runtime.
4. Add checker/runtime stdlib conformance gate.
5. Add `doctor --stdlib-scraper`.

### Sprint 2 — One execution contract

1. Add `tallow run-plan --dry-run`.
2. Share request execution semantics between Python runner and Rust runtime.
3. Add local/mock generated package e2e.
4. Add artifact manifest output from TL/runtime path.

### Sprint 3 — Public-source extraction path

1. Add live-preflight mode.
2. Add policy-gated live mode with explicit approval.
3. Implement extraction schema execution for HTML/JSON.
4. Produce normalized rows + validation report.

### Sprint 4 — Browser/compliance hardening

1. Implement approved live browser fallback.
2. Add screenshot/HAR/DOM capture gates.
3. Add real vault provider interface.
4. Add production compliance gate.

### Sprint 5 — Release readiness

1. Close stdlib drift.
2. Clean old `.tl` scripts.
3. Add CI generated-package e2e.
4. Run local/offline benchmark matrix.
5. Then, only with approval, run live benchmark matrix.

---

## 7. Immediate next task recommendation

Start with **P0-002: Implement `http.batch`**, because it directly blocks the generated inquiry/research packages from running in Tallow.

Minimal implementation target:

```text
http.batch(urls, concurrency, headers) -> []BatchResponse
```

Minimal acceptance package:

```bash
cd /mnt/Personal/Nixe
./target/debug/tallow check personal_database/ashraf_ali_business_inquiry/ashraf_ali_business_inquiry.legacy-http-batch.tl
./target/debug/tallow run personal_database/ashraf_ali_business_inquiry/ashraf_ali_business_inquiry.legacy-http-batch.tl
```

But for tests, use a loopback mock server first so CI does not hit public internet.

---

## 8. Non-goals / safety boundaries

Do **not** fix Tallow by adding unsafe scraping behavior.

Explicitly out of scope unless separately approved and legally reviewed:

- CAPTCHA bypass;
- login-gated scraping without authorization;
- paywall bypass;
- private API reverse engineering;
- fake identities;
- public internet exposure of services;
- unredacted secrets in artifacts;
- destructive retention purges without explicit approval.

Safe goal:

```text
public/authorized source-backed research with policy gates, evidence artifacts, redaction, rate limits, and honest non-claims.
```
