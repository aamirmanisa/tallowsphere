# Tallow Production Kanban Workflow

> **For Hermes:** Use `kanban-agent-workflows`, `test-driven-development`, and `requesting-code-review` for execution. Use `subagent-driven-development` when a card is large enough to warrant isolated implementation/review workers.

**Goal:** Move Tallow/Nixe from local-proof roadmap completion toward a production-safe release without overclaiming live scraping, browser fallback, vault, compliance, or benchmark readiness.

**Architecture:** The board is organized as a gated production workflow. Each implementation card follows RED → GREEN → VERIFY → REVIEW → DONE, with fail-closed security/compliance behavior preferred over permissive partial support.

**Tech Stack / Project Root:** `/mnt/Personal/Nixe`; Rust `tallow` CLI/runtime, Python stdlib-compatible scripts, JSON schemas/artifacts, Markdown operation docs.

---

## 1. Board columns

| Column | Meaning | Exit rule |
| --- | --- | --- |
| `Done` | Completed, verified, and independently reviewed | Final summary includes changed files, tests, review verdict, and no-open-blocker statement |
| `In Progress` | One active implementation card | Only one card should be here unless explicitly parallelized |
| `Ready` | Fully scoped and unblocked | Has acceptance criteria, likely files, verification commands, and dependencies satisfied |
| `Blocked / Human Gate` | Needs secrets, legal choice, live target approval, destructive action approval, or unavailable infra | Must name exact blocker and safe fallback |
| `Review` | Implementation finished; waiting on focused independent review | Review request must include scope-limited files and verification evidence |
| `Backlog` | Valid production task not ready to execute yet | Promote only when dependencies are done |

### WIP limits

- `In Progress`: 1 card.
- `Review`: max 2 cards.
- `Blocked / Human Gate`: unlimited, but every blocked card must include the precise unblock request.
- No live/secrets/destructive production step proceeds silently. If a card can be implemented with fake/local proofs, do that first and leave real production activation explicitly gated.

---

## 2. Definition of Ready

A card is ready only when it has:

- [ ] Exact scope and non-goals.
- [ ] Known dependencies.
- [ ] Expected files or discovery commands.
- [ ] RED regression target.
- [ ] GREEN implementation target.
- [ ] Verification commands.
- [ ] Docs/artifact updates if behavior changes.
- [ ] Review scope.
- [ ] Security/compliance implications called out.

---

## 3. Definition of Done

A card is done only when:

- [ ] RED regression was observed or an equivalent existing failing gap was documented.
- [ ] Implementation is minimal and fail-closed by default.
- [ ] Targeted tests pass.
- [ ] Related broader regression gates pass.
- [ ] `git diff --check` or equivalent whitespace check passes for scoped files.
- [ ] Secret/trailing scan passes for scoped files.
- [ ] Docs/capability labels are updated if behavior/claim boundaries changed.
- [ ] Focused independent review returns `APPROVED`.
- [ ] Any review blockers were fixed and re-reviewed.
- [ ] No commit is made unless explicitly requested.

---

## 4. Standard card execution loop

For every implementation card:

1. **Scope recovery**
   - Run `git status --short --branch`.
   - Read roadmap/doc sections for the card.
   - Search existing tests/code before writing new code.

2. **RED**
   - Add one focused regression test proving the production gap.
   - Run just that test and capture the expected failure.

3. **GREEN**
   - Implement the smallest fail-closed behavior that satisfies the test.
   - Prefer explicit unsupported/report metadata over permissive behavior.

4. **VERIFY**
   - Run targeted tests.
   - Run adjacent regression suites.
   - Run schema/docs validators where relevant.
   - Run scoped whitespace + secret/trailing scans.

5. **REVIEW**
   - Delegate focused independent review with exact files and evidence.
   - Fix blockers.
   - Re-review until approved.

6. **REPORT**
   - State what changed, what passed, what remains gated, and whether a commit was made.

---

## 5. Board state

### Done

| Card | Result |
| --- | --- |
| `P1-006` Canonical source-backed research package | Completed: package initializer, tests, docs |
| `P1-007` POST/GraphQL no-lossy-downgrade guard | Completed: fail-closed stale legacy TL cleanup, tests, docs |
| `P1-008` Safe browser fallback boundaries | Completed: browser fallback/artifact capture fail-closed in Rust/Python, docs, review-approved |

### In Progress

| Card | Status |
| --- | --- |
| `P1-009` Vault-provider interface and fail-closed secret handling | Active next card |

### Ready / Backlog

`P1-010`, `P2-001` through `P2-009`, and `P3-001` through `P3-005` are queued below.

---

## 6. Task cards

## P1-009 — Vault-provider interface and fail-closed secret handling

**Priority:** P0 for production readiness  
**Lane:** Security / Credentials  
**Status:** `In Progress`  
**Dependencies:** P1-008 complete; existing fake/local no-secret compliance proof exists.

**Objective:** Add a provider interface for credential references while keeping real secret resolution fail-closed unless explicitly approved and configured.

**Non-goals:**
- Do not store real secrets in repo, test fixtures, reports, logs, snapshots, or memory.
- Do not contact a real vault in default tests.
- Do not enable live credentialed scraping by default.

**Likely files:**
- `src/request_plan.rs`
- `tests/request_plan_cli.rs`
- `scripts/run_tallow_request_plan.py`
- `tests/test_phase2_request_plan_runner.py`
- `scripts/compliance_gate.py`
- `tests/test_phase9_compliance_gate.py`
- `docs/operations/tallow-request-plan-runner.md`
- `docs/operations/compliance-gate.md`
- possible new schema: `schemas/tallow/vault-resolution-report.schema.json`

**RED tests:**
- Native live/preflight rejects literal secret-looking `auth_ref` and inline header values before network I/O.
- Native approved live with `auth_ref=vault://...` remains fail-closed unless a configured provider exists.
- Python runner emits redacted vault-resolution metadata without raw secret material.
- Snapshot artifacts never contain the raw `auth_ref` value.

**GREEN target:**
- Define provider abstraction/report shape:
  - provider id
  - reference hash
  - resolution status
  - `secret_material_serialized=false`
  - `real_vault_contacted=false` for local proof
- Fail closed for unsupported providers.
- Accept only fake/local provider references in local tests.
- Add redaction guards for all vault/auth values.

**Verification:**
```bash
cargo test --test request_plan_cli auth vault -- --nocapture
python3 -B -m unittest tests.test_phase2_request_plan_runner tests.test_phase9_compliance_gate -v
python3 scripts/validate_tallow_contracts.py
```

**Acceptance:**
- Real secret resolution is still not claimed.
- Literal secrets fail closed.
- Local/fake vault references produce redacted reports only.
- No server/network request is made when auth policy blocks.
- Independent review approves.

---

## P1-010 — Production compliance gate contract/enforcement scaffold

**Priority:** P0 for production readiness  
**Lane:** Compliance / Release Gate  
**Status:** `Ready after P1-009`

**Objective:** Make every live run require a compliance gate report and fail closed when legal/source/retention/redaction metadata is missing.

**Dependencies:** P1-009 vault report shape.

**Likely files:**
- `schemas/tallow/compliance-gate-report.schema.json`
- `scripts/compliance_gate.py`
- `scripts/validate_tallow_contracts.py`
- `src/request_plan.rs`
- `tests/request_plan_cli.rs`
- `tests/test_phase9_compliance_gate.py`
- `docs/operations/compliance-gate.md`
- `docs/operations/tallow-request-plan-runner.md`

**RED tests:**
- Live run without compliance report path fails before network I/O.
- Live run with missing legal basis/source authority/retention days fails before network I/O.
- Compliance report with approval id passes preflight but still does not perform destructive retention.

**GREEN target:**
- Add compliance report contract validation to live/live-preflight surfaces.
- Report legal basis, source authority, robots mode, redaction policy, retention, approval id.
- Fail closed for missing metadata.

**Verification:**
```bash
python3 -B -m unittest tests.test_phase9_compliance_gate -v
cargo test --test request_plan_cli compliance live -- --nocapture
python3 scripts/validate_tallow_contracts.py
```

**Acceptance:**
- Live execution is impossible without a valid compliance report.
- Reports do not contain raw secrets/PII.
- Destructive purge remains blocked unless separately approved.
- Independent review approves.

---

## P2-001 — Close scraper-critical stdlib parity gaps

**Priority:** P1  
**Lane:** Runtime / Stdlib  
**Status:** `Ready after P1 gates`

**Objective:** Reduce stdlib declaration/runtime drift for scraper-critical modules to zero open critical gaps.

**Likely files:**
- `stdlib/*.tl`
- `src/stdlib/*.rs`
- `scripts/generate_stdlib_surface_manifest.py`
- `tests/test_phase2_stdlib_surface_manifest.py`
- `tests/stdlib_dispatch.rs`
- `artifacts/phase2/stdlib_surface_manifest.json`

**RED tests:**
- Manifest fail-on-drift test for scraper-critical modules.
- Dispatch/declaration mismatch regression for each critical module.

**GREEN target:**
- Align `http`, `html`, `json`, `browser`, `fs`, `time`, `log`, `url`, `process`, artifact/report helpers.
- Make unsupported functions explicitly fail closed instead of silently declared.

**Verification:**
```bash
python3 -B -m unittest tests.test_phase2_stdlib_surface_manifest -v
cargo test --test stdlib_dispatch -- --nocapture
cargo test stdlib::tests --lib -- --nocapture
```

**Acceptance:**
- Scraper-critical open gaps = 0 or explicitly documented as non-production unsupported.
- Manifest regenerated and validated.
- Independent review approves.

---

## P2-002 — Compiler/interpreter parity tests for generated-script features

**Priority:** P1  
**Lane:** Compiler / Runtime  
**Status:** `Ready after P2-001`

**Objective:** Prove generated TL features parse, typecheck, interpret, and where applicable codegen consistently.

**Generated-script features to cover:**
- arrays
- maps
- string concatenation
- method calls
- namespaced function calls
- annotations
- function declarations
- integer literals
- response length/method access

**Likely files:**
- `tests/*compiler*`
- `tests/*runtime*`
- `tests/stdlib_dispatch.rs`
- generated package fixtures under `tests/fixtures/`

**RED tests:**
- Add parity tests for one generated-script feature at a time.

**GREEN target:**
- Fix parser/typechecker/interpreter mismatches or make unsupported paths explicit.

**Verification:**
```bash
cargo test compiler interpreter generated -- --nocapture
./target/debug/tallow check <generated-fixture>.tl
./target/debug/tallow run <generated-fixture>.tl
```

**Acceptance:**
- Generated packages do not rely on untested language behavior.
- Failures produce actionable diagnostics.
- Independent review approves.

---

## P2-003 — Classify/deprecate historical ad-hoc TL scripts

**Priority:** P1  
**Lane:** Docs / Repo Hygiene  
**Status:** `Ready`

**Objective:** Prevent old probe scripts from being mistaken for current production examples.

**Likely files:**
- historical `.tl` files across repo
- new classification manifest, e.g. `artifacts/tl-script-inventory.json`
- docs update under `docs/operations/`

**Classifications:**
- active example
- fixture test
- historical probe
- unsafe/deprecated
- superseded by manifest/request-plan

**RED tests:**
- Inventory test finds `.tl` files without classification header or inventory entry.

**GREEN target:**
- Add headers or inventory entries to all historical scripts.
- Mark unsafe/deprecated scripts clearly.

**Verification:**
```bash
python3 -B -m unittest tests.test_tl_script_inventory -v
./target/debug/tallow check examples/*.tl
```

**Acceptance:**
- No unclassified `.tl` scripts remain.
- Current examples are obvious.
- Independent review approves.

---

## P2-004 — Release-quality examples with fixtures and commands

**Priority:** P1  
**Lane:** Developer Experience  
**Status:** `Ready after P2-001/P2-002`

**Objective:** Create clean, reproducible examples for the supported production-safe paths.

**Examples:**
- `examples/public_source_get_batch.tl`
- `examples/request_plan_get_only/`
- `examples/request_plan_post_graphql/`
- `examples/extraction_schema_html/`
- `examples/browser_fallback_manual_gate/`

**Each example must include:**
- README
- exact command
- expected output
- fixture/mock server if network involved
- non-claims if live/browser/vault is not implemented

**Verification:**
```bash
python3 -B -m unittest tests.test_examples -v
./target/debug/tallow check examples/public_source_get_batch.tl
```

**Acceptance:**
- Examples run locally without public internet or secrets.
- Browser/vault/live examples fail closed or preflight only.
- Independent review approves.

---

## P2-005 — Benchmark matrix scaffolding; live benchmarks gated

**Priority:** P2  
**Lane:** Benchmarks / Claims Control  
**Status:** `Ready after P2-004`

**Objective:** Provide official benchmark matrix scaffolding without making live or superiority claims.

**Likely files:**
- `docs/benchmarks/benchmark-protocol.md`
- `docs/benchmarks/fixtures/*`
- `scripts/benchmark_phase10_fixture.py`
- `scripts/compare_tallow_firecrawl_offline.py`
- `tests/test_phase10_benchmark_protocol.py`

**RED tests:**
- Live benchmark command without explicit approval fails closed.
- Fixture benchmark emits official artifact names and non-claims.

**GREEN target:**
- Local/offline matrix runner.
- Clear live approval gates and budget/secret/resource checks.

**Verification:**
```bash
python3 -B -m unittest tests.test_phase10_benchmark_protocol -v
python3 scripts/benchmark_phase10_fixture.py --help
```

**Acceptance:**
- No performance superiority claim.
- Live/paid/provider benchmarks remain blocked without explicit approval.
- Independent review approves.

---

## P2-006 — Minimal CI gates

**Priority:** P0 for release hygiene  
**Lane:** CI / Release  
**Status:** `Ready after P1-010`

**Objective:** Lock the repeatable production-readiness test matrix.

**Minimum commands:**
```bash
cargo check --locked
cargo test --locked --test browser_contracts
cargo test --locked --test request_plan_cli -- --nocapture
python3 -B -m unittest tests.test_phase2_request_plan_builder -v
python3 -B -m unittest tests.test_phase2_request_plan_runner -v
python3 -B -m unittest tests.test_phase5_extraction_rows -v
python3 -B -m unittest tests.test_phase9_compliance_gate -v
python3 scripts/phase1_smoke_ladder.py
python3 scripts/validate_tallow_contracts.py
```

**Likely files:**
- `.github/workflows/*` or project CI config if present
- `docs/operations/release-bootstrap-checklist.md`
- `docs/operations/tallow-runtime-bootstrap.md`

**RED tests:**
- CI dry-run/check script fails when a required command is absent from matrix.

**GREEN target:**
- Single CI checklist/script that can be run locally and in CI.

**Acceptance:**
- CI gate produces stable pass/fail output.
- No live/secrets tests run by default.
- Independent review approves.

---

## P2-007 — Consolidate operator CLI command set

**Priority:** P1  
**Lane:** Operator Experience  
**Status:** `Ready after P2-006`

**Objective:** Make the Rust CLI the primary operator surface while Python scripts remain implementation details.

**Target commands:**
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

**Likely files:**
- `src/main.rs`
- `src/request_plan.rs`
- `tests/request_plan_cli.rs`
- docs under `docs/operations/`

**RED tests:**
- CLI tests for missing commands/flags.
- Help text snapshot where useful.

**GREEN target:**
- Add missing wrappers or document scripts as non-canonical.

**Acceptance:**
- Operator can complete supported workflow from `tallow ...` commands.
- Unsupported production features are visible and fail closed.
- Independent review approves.

---

## P2-008 — Error taxonomy unification

**Priority:** P1  
**Lane:** Runtime / DX / Ops  
**Status:** `Ready after P2-007`

**Objective:** Emit stable error shape across runtime, request-plan runner, extraction validation, compliance gate, browser fallback, artifact packaging.

**Required fields:**
```text
kind
message
retryable
policy_blocked
source_target_id
url
phase
```

**Likely files:**
- `schemas/tallow/error-taxonomy.schema.json`
- `schemas/tallow/error-taxonomy.v1.json`
- `scripts/validate_tallow_contracts.py`
- `src/request_plan.rs`
- Python runner/compliance/extraction scripts
- tests for all above

**RED tests:**
- Each surface emits an error missing one required field.

**GREEN target:**
- Shared taxonomy entries and validators.
- Compatibility mapping for old codes.

**Verification:**
```bash
python3 scripts/validate_tallow_contracts.py
cargo test error taxonomy -- --nocapture
python3 -B -m unittest tests.test_error_taxonomy -v
```

**Acceptance:**
- Error reports are machine-actionable.
- Existing stable codes remain compatible or are explicitly mapped.
- Independent review approves.

---

## P2-009 — Documentation truth maintenance

**Priority:** P0 for claim safety  
**Lane:** Docs / Governance  
**Status:** `Ready after each behavior-changing card; final sweep after P2-008`

**Objective:** Keep docs aligned with current contracts and avoid production/live overclaims.

**Docs to update:**
- `docs/mega/tallow-1000x-blocker-register.md`
- `docs/mega/tallow-1000x-capability-matrix.md`
- `docs/tallow-scraper-full-task-list.md`
- `docs/operations/*`
- `docs/plans/*`

**Truth labels:**
- authoritative current contract
- accepted local proof
- roadmap / not proof
- historical probe
- superseded

**RED tests:**
- Truth-label probe fails for high-level docs without labels.

**GREEN target:**
- Update docs after P1/P2 changes.
- Explicitly preserve non-claims for live browser, real vault, paid benchmarks, Windows, destructive retention.

**Acceptance:**
- Capability matrix and blocker register match implemented state.
- No stale live/production claims.
- Independent review approves.

---

## P3-001 — Generated TL fmt/lint checks

**Priority:** P2/P3  
**Lane:** Developer Experience  
**Status:** `Backlog`

**Objective:** Make generated TL deterministic and lintable.

**Target commands:**
```bash
tallow fmt generated.tl --check
tallow lint generated.tl --profile scraper
```

**Lint rules:**
- no unknown stdlib calls
- no unsupported live network calls
- no missing `@legal` annotation for network/storage
- no hardcoded secrets
- no huge inline target lists beyond threshold unless generated

**Acceptance:**
- Generated scripts are reproducible and policy-checked.
- Independent review approves.

---

## P3-002 — TL package metadata

**Priority:** P3  
**Lane:** Packaging  
**Status:** `Backlog`

**Objective:** Add package metadata to generated packages.

**Example target:**
```tl
@package(name: "...", schema: "tallow.package.v1")
@legal(...)
@generated_by(tool: "...", version: "...")
```

**Acceptance:**
- Generated files carry source/tool/legal metadata.
- Metadata is checked by linter or package tests.
- Independent review approves.

---

## P3-003 — Better developer diagnostics

**Priority:** P3  
**Lane:** DX  
**Status:** `Backlog`

**Objective:** Replace vague runtime/checker errors with actionable diagnostics.

**Example:**
```text
runtime error[E-stdlib-missing]: http.batch is not implemented in runtime dispatch.
Source: line 43 in <file>
Suggested fixes:
  - upgrade Tallow runtime
  - regenerate script
  - run request-plan via tallow run-plan
```

**Acceptance:**
- Common missing stdlib/runtime/policy errors have codes and suggestions.
- Independent review approves.

---

## P3-004 — Generated package reproducibility artifacts

**Priority:** P3  
**Lane:** Reproducibility  
**Status:** `Backlog`

**Objective:** Every generated package should explain exactly how it was produced.

**Required artifacts:**
```text
generation_manifest.json
input_hashes.json
tallow_version.txt
git_status_summary.txt
commands.sh
```

**Acceptance:**
- Regeneration can be audited from package artifacts alone.
- No secrets are written to reproducibility files.
- Independent review approves.

---

## P3-005 — Self-host compiler boundary

**Priority:** P3  
**Lane:** Docs / Compiler Governance  
**Status:** `Backlog`

**Objective:** Clearly label the self-host Tallow compiler as experiment vs production compiler.

**Acceptance:**
- Docs and package metadata state whether self-host is smoke-tested, parity target, experiment, or unsupported.
- Root Rust compiler acceptance is not mixed with self-host claims.
- Independent review approves.

---

## 7. Dependency graph

```text
P1-009 vault provider
  -> P1-010 production compliance gate
      -> P2-006 CI gates
      -> P2-007 operator CLI consolidation

P2-001 stdlib parity
  -> P2-002 compiler/interpreter parity
  -> P2-004 release examples
  -> P3-001 fmt/lint
  -> P3-002 package metadata

P2-004 release examples
  -> P2-005 benchmark scaffolding
  -> P3-004 reproducibility artifacts

P2-007 operator CLI
  -> P2-008 error taxonomy unification

Every behavior-changing card
  -> P2-009 docs truth maintenance

P3-005 self-host boundary can run independently after docs truth baseline.
```

---

## 8. Production release gate checklist

Tallow can be called production-ready only when these are green:

- [ ] P1-009 vault/provider local proof complete; real secrets not serialized.
- [ ] P1-010 compliance gate required for live runs.
- [ ] P2-006 CI gates repeatably pass.
- [ ] Dirty worktree is split into reviewable commits or release artifacts.
- [ ] P2-001 scraper-critical stdlib drift closed or explicitly unsupported.
- [ ] P2-007 operator command path is stable.
- [ ] P2-008 errors are machine-actionable and stable.
- [ ] P2-009 docs truth labels updated.
- [ ] Public site/relay health check passes if the release includes SendTallow web surface.
- [ ] No live benchmark, browser fallback, real vault, Windows, destructive retention, or superiority claim is made without separate evidence.

---

## 9. Recommended immediate execution

Next card: **P1-009 — Vault-provider interface and fail-closed secret handling**.

Execution pattern:

1. Recover current code/test scope for `auth_ref`, vault, redaction, live gates.
2. Add RED tests for literal secret and unresolved real vault refs.
3. Add minimal provider/report interface with local/fake provider only.
4. Prove no raw secrets in reports/artifacts.
5. Run Rust/Python/compliance verification gates.
6. Run focused independent review.
7. Update docs truth labels if claims changed.
