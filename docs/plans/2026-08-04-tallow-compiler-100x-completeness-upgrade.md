---
date: 2026-08-04
scope: Tallow compiler/runtime 100x completeness — close the truth gap between declared capabilities and implemented behavior across the full compiler pipeline (stdlib dispatch, interpreter, codegen, async, spec/conformance)
status: draft
---

# Tallow Compiler 100x Completeness Upgrade

> **For Hermes:** Use `test-driven-development`, `requesting-code-review`, `systematic-debugging`, and `verification-before-completion` for execution. Use `dispatching-parallel-agents` when phases are independent enough to run side-by-side.

**Goal:** Close every meaningful gap between what the Tallow compiler claims (stdlib declarations, capability labels, async support, self-host parity, browser routing) and what it actually does at runtime — making the compiler/runtime a reliable foundation instead of an aspirational sketch.

**Architecture:** Six gated phases (C1–C6) progressing from surface-level truth (stdlib routing) through deep correctness (async, interpreter/codegen parity) to aspirational cleanup (feature flags, build hygiene) and finally to a living language specification with conformance tests. Each phase gates on the previous phases. Phases C1–C3 are the hard technical core; C4–C6 are correctness/credibility multipliers.

**Tech Stack / Project Root:** `/mnt/Personal/Nixe`; Rust `tallow` CLI/runtime (cargo workspace with crates under `crates/`), `stdlib/*.tl` declarations, `src/stdlib/*.rs` dispatch, `src/interp.rs`, `src/codegen.rs`, Python test harness, JSON schemas/artifacts, Markdown docs.

---

## Non-Claims (What This Plan Does NOT Assert)

This plan explicitly does **not** claim or require:

- **Live scraping readiness.** No live browser, network, or target-site test is required. All verification uses local mocks, fixtures, and unit tests.
- **Vault/secret resolution.** Secret handling and vault providers are owned by the P1 production kanban (P1-009/P1-010); this plan does not touch them.
- **Windows support.** All commands assume Linux. Windows CI is a separate concern.
- **Deployment/release packaging.** This plan covers compiler correctness; release packaging is the production kanban's domain.
- **Benchmark superiority.** No performance claims are made. Phase C4 addresses whether aspirational features exist at all, not whether they're fast.
- **Browser fallback for live scraping.** Browser routing correctness (C1) is about internal dispatch, not about connecting to real Chrome instances for production workloads.

---

## Architecture Overview

```text
C1 — Close the truth gap (stdlib dispatch)
 │
 ├─► C2 — Real async (await in interpreter + codegen)
 │
 ├─► C3 — Interpreter/codegen parity (differential harness)
 │
 ├─► C4 — Make aspirational real or re-scoped (feature flags, IPPool, self-host)
 │
 ├─► C5 — Clean-build baseline (stale assertions, clippy, fmt, fresh workspace)
 │
 └─► C6 — Language spec + conformance (canonical spec, test→spec mapping, truth table)
```

**Dependency note:** C2 and C3 are tightly coupled and should be executed sequentially. C4 can partially overlap with C5 (different subsystems). C6 depends on C1–C5 completing enough to produce a stable surface to spec against.

---

## Phase C1 — Close the Truth Gap: Stdlib Dispatch

**Priority:** P0 — foundation for all other phases
**Lane:** Runtime / Stdlib
**Status:** `Ready`

### Goal

Make every Tallow standard library function and method declared in `stdlib/*.tl` actually routable through the Rust dispatch layer in `src/stdlib/*.rs`. Today the browser module alone declares 43 functions and 159 methods, but `src/stdlib/browser.rs` only routes 4 metadata functions (`surface_manifest`, `pipe_transport_status`, `fallback_boundary`, `fallback_service_status`). Thirteen modules are declared but have zero dispatched functions. This phase makes `tallow doctor --stdlib-scraper` a hard CI gate that passes only when `open_gaps=0` for every module.

### Non-Goals

- Does not implement full browser automation (that's the production kanban's domain).
- Does not add new stdlib modules — only closes dispatch gaps for already-declared surfaces.
- Does not wire async internals (that's C2).
- Does not make every dispatched function produce correct results — only that it is routable and produces a defined response (even if that response is "not implemented, fail-closed").

### Current Gap Summary

| Module | Declared fns | Declared methods | Dispatched fns | Dispatched methods | Open gaps |
| --- | --- | --- | --- | --- | --- |
| `browser` | 43 | 159 | 4 | 0 | 198 |
| `agent` | 16 | 0 | 0 | 0 | 16 |
| `legal` | 19 | 0 | 0 | 0 | 19 |
| `db` | 3 | 14 | 0 | 0 | 17 |
| `config` | 6 | 0 | 0 | 0 | 6 |
| `cli` | 0 | 4 | 0 | 0 | 4 |
| `test` | 9 | 0 | 0 | 0 | 9 |
| `mime` | 5 | 0 | 0 | 0 | 5 |
| `cloud`, `iot`, `otel`, `pec`, `detection`, `safety` | 0 (type-only sentinels) | 0 | 0 | 0 | N/A (explicit sentinel) |
| **All 45 modules** | — | — | — | — | **target: 0** |

### Likely Files

| File | Role |
| --- | --- |
| `stdlib/browser.tl` | Declares 43 fns + 159 methods for browser surface |
| `src/stdlib/browser.rs` | Currently routes only 4 metadata fns; must expand to full dispatch table |
| `stdlib/*.tl` (all 45 modules) | Reference declarations for every module |
| `src/stdlib/*.rs` (all 13 gapped modules) | Rust dispatch impls — each must route its declared surface |
| `src/stdlib/mod.rs` | Module registry; may need updated routing |
| `src/interp.rs` | Stdlib call dispatch path (around line 2475 for ExprKind handling) |
| `scripts/generate_stdlib_surface_manifest.py` | Generates `open_gaps` manifest by comparing `stdlib/*.tl` declarations against `src/stdlib/*.rs` routing |
| `artifacts/phase2/stdlib_surface_manifest.json` | Output manifest consumed by `tallow doctor --stdlib-scraper` |
| `tests/stdlib_dispatch.rs` | Existing dispatch regression tests |
| `tests/test_phase2_stdlib_surface_manifest.py` | Python manifest validation tests |
| `src/main.rs` | CLI entry — `tallow doctor` subcommand |
| `Cargo.toml` | May need feature flag adjustments for newly-enabled modules |

### RED Targets (Failing Tests Before Work)

```bash
# 1. Manifest gap test — must fail because browser alone has 198 open gaps
python3 -B -m unittest tests.test_phase2_stdlib_surface_manifest -v
# Expected: FAIL — open_gaps > 0 for browser, agent, legal, db, config, cli, test, mime

# 2. Dispatch mismatch regression — each gapped module must have at least one test proving the gap
cargo test stdlib_dispatch::browser_missing_routes -- --nocapture
# Expected: FAIL — 198 browser routes untestable

cargo test stdlib_dispatch::agent_missing_routes -- --nocapture
# Expected: FAIL — 16 agent fns untestable

# 3. doctor gate — must fail before work
./target/debug/tallow doctor --stdlib-scraper
# Expected: FAIL — non-zero open_gaps, exit code != 0
```

### GREEN Targets (Implementation)

For each gapped module, add one of three dispatch strategies:

1. **Full implementation** (for clearly defined, low-risk functions): Route to existing Rust logic or implement minimally.
2. **Explicit fail-closed stub** (for aspirational/sentinel functions): Route to a stub that returns `Err(StdlibError::NotImplemented { module, fn_name })` with a stable error code.
3. **Sentinel downgrade** (for type-only modules like `cloud`, `iot`, `otel`): Mark them explicitly as sentinel-only in the manifest so `open_gaps` counts them as `0` instead of `N/A`.

**Priority dispatch order:**
- `browser` — largest gap (198), most user-visible
- `agent` — 16 fns, AI/agent surface
- `legal` — 19 fns, compliance surface
- `db` — 17 items, persistence surface
- `config` — 6 fns
- `cli` — 4 methods
- `test` — 9 fns
- `mime` — 5 fns

**GREEN verification commands:**

```bash
# 1. Manifest must show open_gaps=0 for all 45 modules
python3 -B -m unittest tests.test_phase2_stdlib_surface_manifest -v
# Expected: PASS

# 2. Every dispatched fn/method must have a dispatch test (even if stubbed)
cargo test stdlib_dispatch -- --nocapture
# Expected: PASS — all dispatch tests pass

# 3. doctor gate must pass
./target/debug/tallow doctor --stdlib-scraper
# Expected: PASS — exit code 0, open_gaps=0 for every module

# 4. 2 codegen-integration tests that were failing due to dispatch gaps must turn green
cargo test codegen_integration -- --nocapture
# Expected: PASS — 2 previously-failing tests now green

# 5. No check-accepts-run-fails regressions — every dispatched fn must either work or fail with a defined error
cargo test stdlib::check_accepts_run_fails -- --nocapture
# Expected: PASS — 0 check-accepts-run-fails
```

### Acceptance Criteria

- [ ] `tallow doctor --stdlib-scraper` exits 0 with `open_gaps=0` for all 45 modules.
- [ ] All 198 browser dispatch entries are routable.
- [ ] All 13 previously-undispatched modules have complete routing tables.
- [ ] Type-only sentinel modules are explicitly marked in the manifest.
- [ ] 2 codegen-integration tests pass.
- [ ] 0 check-accepts-run-fails regressions exist.
- [ ] Every dispatched but unimplemented function returns a stable, documented error code (not a panic or silent NOP).
- [ ] `scripts/generate_stdlib_surface_manifest.py` is regenerated and its output committed.
- [ ] Independent review approves.

### Gate: C1 → C2

C2 may begin only after: `tallow doctor --stdlib-scraper` passes, 2 codegen-integration tests pass, and review approves.

---

## Phase C2 — Real Async: `await` in Interpreter and Codegen

**Priority:** P0 — correctness prerequisite for any IO-bound Tallow program
**Lane:** Compiler / Runtime
**Status:** `Blocked on C1`

### Goal

Implement `await` in the Tallow interpreter and wire the codegen async path so that `ExprKind::Await` is no longer a TODO at `interp.rs:2475`. Replace the blunt `MAX_CALL_DEPTH=100` guard (C3). This enables Tallow programs to use async IO without interpreter panics or silent blocking.

### Non-Goals

- Does not implement a full async runtime or executor (Tokio is already integrated).
- Does not add new async stdlib functions — only makes existing async declarations work.
- Does not touch the VM trampoline (that's C3).

### Current State

```rust
// interp.rs:2475 — current state (conceptual)
ExprKind::Await(expr) => {
    // TODO: implement async/await in interpreter
    todo!("await not yet implemented in interpreter")
}
```

`MAX_CALL_DEPTH` is currently set to 100 as a blunt recursion guard, not a proper stack management strategy.

### Likely Files

| File | Role |
| --- | --- |
| `src/interp.rs` (~line 2475) | `ExprKind::Await` handler — must resolve futures and propagate results |
| `src/codegen.rs` | Async codegen path — must emit correct async blocks/state machines |
| `src/ast.rs` | AST node definitions for `Await` |
| `src/typeck.rs` | Type checking for async expressions |
| `tests/interp_async.rs` (new or existing) | Interpreter async tests |
| `tests/codegen_async.rs` (new or existing) | Codegen async tests |
| `tests/fixtures/async_*.tl` | Async test fixtures |

### RED Targets

```bash
# 1. Basic await in interpreter must fail before implementation
cargo test interp::await_simple -- --nocapture
# Expected: FAIL — "await not yet implemented" or panic

# 2. Await with return value propagation must fail
cargo test interp::await_returns_value -- --nocapture
# Expected: FAIL

# 3. Codegen async path must fail or produce incorrect output
cargo test codegen::async_block -- --nocapture
# Expected: FAIL or compile error

# 4. Nested await must fail
cargo test interp::await_nested -- --nocapture
# Expected: FAIL
```

### GREEN Targets

**Interpreter implementation (`interp.rs`):**

```rust
// After fix — conceptual shape
ExprKind::Await(expr) => {
    let future = self.eval_expr(expr)?;
    match future {
        Value::Future(fut) => {
            // Poll the future to completion within the interpreter loop
            // Yield to Tokio runtime if needed
            self.runtime.block_on(fut)
        }
        other => Err(RuntimeError::NotAFuture {
            expr: self.format_expr(expr),
            actual_type: other.type_name(),
        })
    }
}
```

**Codegen implementation (`codegen.rs`):**

```rust
// After fix — conceptual shape
ExprKind::Await(expr) => {
    let future_expr = self.codegen_expr(expr)?;
    // Emit .await point in generated code
    // Wire through Tokio-compatible future polling
    Ok(quote! { #future_expr.await })
}
```

**GREEN verification commands:**

```bash
# 1. Basic await passes in interpreter
cargo test interp::await_simple -- --nocapture
# Expected: PASS

# 2. Await returns values correctly
cargo test interp::await_returns_value -- --nocapture
# Expected: PASS

# 3. Nested await works
cargo test interp::await_nested -- --nocapture
# Expected: PASS

# 4. Codegen async path produces correct output
cargo test codegen::async_block -- --nocapture
# Expected: PASS

# 5. Full async test suite
cargo test async -- --nocapture
# Expected: PASS

# 6. No regression in existing interpreter/codegen tests
cargo test interp codegen -- --nocapture
# Expected: PASS (all previously-passing tests still pass)
```

### Acceptance Criteria

- [ ] `ExprKind::Await` is no longer a TODO.
- [ ] Interpreter can evaluate `await` expressions and propagate results.
- [ ] Codegen emits correct `.await` points.
- [ ] Error on attempting to await a non-Future value is clear and stable.
- [ ] Full async test suite passes.
- [ ] No regression in existing interpreter/codegen tests.
- [ ] Independent review approves.

### Gate: C2 → C3

C3 may begin only after: all async tests pass, codegen async path is wired, and review approves.

---

## Phase C3 — Interpreter/Codegen Parity

**Priority:** P0 — correctness prerequisite
**Lane:** Compiler / Runtime
**Status:** `Blocked on C2`

### Goal

Build a differential test harness that runs every Tallow example program through both the interpreter and codegen paths, compares results, and surfaces every divergence. Fix all divergences. Replace `MAX_CALL_DEPTH=100` with a proper VM trampoline that eliminates the artificial recursion limit.

### Non-Goals

- Does not add new language features.
- Does not optimize either path for performance — only correctness.
- Does not add a JIT or tiered compilation.

### Likely Files

| File | Role |
| --- | --- |
| `tests/differential_harness.rs` (new) | Differential test runner — runs each fixture through interpreter AND codegen, diffs output |
| `tests/fixtures/differential/*.tl` | Fixture programs for differential testing |
| `src/interp.rs` | Interpreter fixes for discovered gaps |
| `src/codegen.rs` | Codegen fixes for discovered gaps |
| `src/vm.rs` (new or extracted from interp.rs) | VM trampoline replacing MAX_CALL_DEPTH |
| `examples/*.tl` | Existing example programs as differential fixtures |
| `scripts/run_differential_harness.py` | Python runner that orchestrates `tallow check`, `tallow run`, and differential comparisons |

### RED Targets

```bash
# 1. Differential harness must reveal existing gaps (at least one divergence expected)
cargo test differential::example_hello_simple -- --nocapture
# Expected: MAY FAIL — divergence between interpreter and codegen output

# 2. MAX_CALL_DEPTH limit must be observable
cargo test interp::call_depth_limit -- --nocapture
# Expected: FAIL — hits MAX_CALL_DEPTH=100 on deep recursion
```

### GREEN Targets

**Differential harness design:**

```rust
// tests/differential_harness.rs — conceptual shape
#[test]
fn differential_all_fixtures() {
    for fixture in glob("tests/fixtures/differential/*.tl").unwrap() {
        let path = fixture.unwrap();
        let interp_output = run_interpreter(&path);
        let codegen_output = run_codegen(&path);
        assert_eq!(
            interp_output, codegen_output,
            "Divergence in {}: interpreter={:?}, codegen={:?}",
            path.display(), interp_output, codegen_output
        );
    }
}
```

**VM trampoline design (replacing MAX_CALL_DEPTH):**

```rust
// src/vm.rs — conceptual shape
pub struct Vm {
    stack: Vec<Frame>,
    // No artificial depth limit; bounded only by available memory
}
impl Vm {
    pub fn execute(&mut self, program: &Program) -> Result<Value> {
        loop {
            match self.current_instruction() {
                Instruction::Call { target, args } => {
                    self.stack.push(Frame::new(target, args));
                }
                Instruction::Return(value) => {
                    if self.stack.len() <= 1 {
                        return Ok(value);
                    }
                    self.stack.pop();
                    self.stack.top_mut().push_result(value);
                }
                // ... other instructions
            }
        }
    }
}
```

**GREEN verification commands:**

```bash
# 1. Differential harness passes for all fixtures
cargo test differential -- --nocapture
# Expected: PASS — all fixtures produce identical output in both paths

# 2. VM trampoline handles deep recursion (test at 10,000 calls)
cargo test vm::deep_recursion -- --nocapture
# Expected: PASS — no MAX_CALL_DEPTH panic

# 3. Full interpreter test suite
cargo test interp -- --nocapture
# Expected: PASS

# 4. Full codegen test suite
cargo test codegen -- --nocapture
# Expected: PASS

# 5. End-to-end: check + run for every example
for f in examples/*.tl; do
    ./target/debug/tallow check "$f" || echo "FAIL: check $f"
    ./target/debug/tallow run "$f" || echo "FAIL: run $f"
done
# Expected: all pass
```

### Acceptance Criteria

- [ ] Differential harness exists and covers all examples plus dedicated fixtures (minimum 20 programs).
- [ ] Every fixture produces identical output from interpreter and codegen paths.
- [ ] `MAX_CALL_DEPTH=100` is removed and replaced with VM trampoline.
- [ ] Deep recursion test (10,000+ calls) passes without artificial limit.
- [ ] All existing interpreter and codegen tests pass.
- [ ] `tallow check` + `tallow run` succeeds for every example file.
- [ ] Independent review approves.

### Gate: C3 → C4

C4 may begin after: differential harness passes, VM trampoline is in place, and review approves.

---

## Phase C4 — Make Aspirational Real or Re-Scoped

**Priority:** P1 — credibility multiplier
**Lane:** Compiler / Runtime / Feature Flags
**Status:** `Blocked on C3`

### Goal

Audit every feature flag, capability claim, and aspirational code path that does not actually work. For each: either make it work at a minimal level, or explicitly downgrade it to a documented sentinel with a stable error. Three specific targets:

1. **`real-ml` feature** — does not exist in `Cargo.toml`. Either add it with real functionality or remove all references.
2. **IPPool epoll backend** — currently a placeholder counter that always returns `127.0.0.1:0`. Either implement real epoll-backed pool behavior or make the placeholder explicitly documented.
3. **Self-host parity** — prove `hello_simple.tl` compiles end-to-end using the Tallow compiler compiled by itself (or document the exact gap).

### Non-Goals

- Does not implement a production IP pool or ML pipeline — only resolves the claim/reality gap.
- Does not make self-host the primary compiler — only establishes parity for one canonical example.
- Does not add new feature flags — only resolves existing ones.

### Likely Files

| File | Role |
| --- | --- |
| `Cargo.toml` | Feature flag definitions — `real-ml` must exist or all references removed |
| `src/ippool.rs` or `src/stdlib/ippool.rs` | IPPool epoll backend |
| `src/stdlib/net.rs` | Network stdlib that may reference IPPool |
| `src/*.rs` (grep for `real-ml`, `cfg(feature = "real-ml")`) | All references to the non-existent feature |
| `self-host/` directory (if exists) | Self-host toolchain |
| `examples/hello_simple.tl` | Canonical self-host target |
| `docs/mega/tallow-1000x-capability-matrix.md` | Capability claims that may reference these features |

### RED Targets

```bash
# 1. real-ml feature must not compile (doesn't exist)
cargo build --features real-ml 2>&1
# Expected: FAIL — "feature `real-ml` is not defined"

# 2. IPPool must return static placeholder
cargo test ippool::allocate -- --nocapture
# Expected: PASS but output is always 127.0.0.1:0 (confirming it's a placeholder)

# 3. Self-host must fail or not exist
# (If self-host directory exists)
cd self-host && cargo build 2>&1
# Expected: MAY FAIL — likely not buildable
```

### GREEN Targets

**For `real-ml`:**
- Option A: Add `real-ml = []` to `Cargo.toml` with a single `#[cfg(feature = "real-ml")]` gated function that returns a documented "not yet implemented" error.
- Option B: Remove all `cfg(feature = "real-ml")` references from source and docs.
- Decision gate: If `real-ml` is needed within 6 months, choose A. Otherwise, choose B.

**For IPPool:**
- Option A: Implement a real epoll-backed pool that allocates from a configurable range.
- Option B: Rename the placeholder to `StubPool` and document that real IP pooling is not yet implemented.
- Decision gate: If IP pooling is needed for production within 3 months, choose A. Otherwise, choose B.

**For self-host:**
- Prove `examples/hello_simple.tl` can be compiled by a Tallow binary that was itself compiled by Tallow.
- If not possible: document the exact bootstrap chain and the first function/feature that blocks self-hosting.

**GREEN verification commands:**

```bash
# 1. real-ml compiles (if added) or all references removed
cargo build 2>&1 | grep -i "real.ml" && echo "FAIL: orphan references" || echo "PASS"
# Expected: PASS — no orphan references

# 2. IPPool test reflects actual implementation
cargo test ippool -- --nocapture
# Expected: PASS — test matches implementation (real or documented stub)

# 3. Self-host parity test
# If self-host works:
cd self-host && cargo build && ./target/debug/tallow-compiler compile ../examples/hello_simple.tl
# Expected: compiles successfully

# 4. Capability matrix updated
python3 scripts/validate_tallow_contracts.py
# Expected: PASS — no capability claims reference non-existent features
```

### Acceptance Criteria

- [ ] `real-ml` either exists as a feature flag with a defined behavior, or all references are removed.
- [ ] IPPool is either real (epoll-backed) or explicitly documented as a stub with a stable error.
- [ ] Self-host parity is either proven for `hello_simple.tl` or the exact bootstrap gap is documented.
- [ ] Capability matrix (`docs/mega/tallow-1000x-capability-matrix.md`) is updated to reflect actual state.
- [ ] No feature flag references code that doesn't exist.
- [ ] Independent review approves.

### Gate: C4 → C5

C5 can begin in parallel with C4 (different subsystems, no shared files expected).

---

## Phase C5 — Clean-Build Baseline

**Priority:** P1 — release hygiene
**Lane:** CI / Build
**Status:** `Ready` (can run in parallel with C4)

### Goal

Achieve a clean `cargo test --workspace` from a fresh shell, plus `clippy` clean and `cargo fmt` clean. Fix the 5 known stale browser assertions that broke when Chrome upgraded from version 132 to 136.

### Non-Goals

- Does not add new CI infrastructure (that's P2-006 in the production kanban).
- Does not fix pre-existing warnings that are not clippy-denied.
- Does not reformat code beyond `cargo fmt`.

### Likely Files

| File | Role |
| --- | --- |
| `src/browser/*.rs` | Stale Chrome version assertions (132→136) |
| `tests/browser_contracts.rs` | Browser contract tests with stale assertions |
| `src/*.rs` (clippy warnings) | Files with clippy diagnostics |
| `src/*.rs` (fmt issues) | Files not conforming to `rustfmt` |
| `Cargo.toml` | May need version bumps for compatible Chrome CDP protocol |
| `rust-toolchain.toml` or `rust-toolchain` | Toolchain version pinning |

### RED Targets

```bash
# 1. Fresh workspace test must show failures
cargo test --workspace 2>&1 | tail -20
# Expected: MAY FAIL — stale browser assertions, maybe other failures

# 2. Clippy must show warnings
cargo clippy --workspace -- -D warnings 2>&1 | tail -20
# Expected: FAIL — clippy warnings present

# 3. Format check must show diffs
cargo fmt --check 2>&1
# Expected: FAIL — formatting violations
```

### GREEN Targets

**Stale browser assertion fix pattern:**

```rust
// Before (conceptual — Chrome 132 assertion)
assert_eq!(browser.version(), "132.0.0.0");

// After (conceptual — Chrome 136, or version-independent)
assert!(browser.version().starts_with("136."));
// Or better: assert that version is parseable, not a specific number
let version: semver::Version = browser.version().parse().unwrap();
assert!(version.major >= 136);
```

**GREEN verification commands:**

```bash
# 1. Full workspace test passes from clean state
cargo clean
cargo test --workspace 2>&1
# Expected: PASS — all tests pass, no failures

# 2. Clippy passes with deny-warnings
cargo clippy --workspace -- -D warnings 2>&1
# Expected: PASS — exit code 0, no warnings

# 3. Format check passes
cargo fmt --check 2>&1
# Expected: PASS — exit code 0, no diffs

# 4. Build succeeds with --locked
cargo build --locked 2>&1
# Expected: PASS
```

### Acceptance Criteria

- [ ] `cargo test --workspace` passes from a fresh `cargo clean`.
- [ ] All 5 stale browser assertions (Chrome 132→136) are fixed or made version-independent.
- [ ] `cargo clippy --workspace -- -D warnings` exits 0.
- [ ] `cargo fmt --check` exits 0.
- [ ] `cargo build --locked` exits 0.
- [ ] Independent review approves.

### Gate: C5 → C6

C6 may begin after C5 completes. C5 may run in parallel with C4.

---

## Phase C6 — Language Spec + Conformance

**Priority:** P1 — long-term credibility
**Lane:** Docs / Governance / Compiler
**Status:** `Blocked on C1–C5`

### Goal

Produce one canonical language specification document with conformance identifiers, a test→spec mapping, and a truth table for every `TALLOW-CAPABILITIES` claim. Every spec statement must be traceable to a passing test.

### Non-Goals

- Does not create a formal ISO-style specification — this is a living, test-backed spec.
- Does not add new language features — only documents what exists after C1–C5.
- Does not create a compliance certification program.

### Likely Files

| File | Role |
| --- | --- |
| `docs/spec/tallow-lang-spec.md` (new) | Canonical language specification |
| `docs/spec/conformance-ids.csv` (new) | Conformance identifier table |
| `docs/spec/test-to-spec-mapping.json` (new) | Maps each test to spec section |
| `docs/spec/capabilities-truth-table.md` (new) | Truth table for TALLOW-CAPABILITIES claims |
| `docs/mega/tallow-1000x-capability-matrix.md` | Existing capability matrix — must be reconciled |
| `docs/mega/tallow-1000x-blocker-register.md` | Existing blocker register — must be reconciled |
| `scripts/validate_spec_conformance.py` (new) | Validates spec→test→implementation traceability |
| `tests/spec_conformance.rs` (new) | Conformance test runner |

### Spec Structure

```markdown
# Tallow Language Specification v1.0-draft

## CONFORMANCE-001: Lexical Structure
- Tokens, identifiers, keywords, literals, comments
- Test: tests/lexer_spec.rs
- Status: PASS

## CONFORMANCE-002: Expression Grammar
- Binary/unary operators, precedence, grouping
- Test: tests/parser_expr_spec.rs
- Status: PASS

## CONFORMANCE-003: Await Expressions (C2)
- Async/await syntax, Future types, error handling
- Test: tests/interp_async.rs, tests/codegen_async.rs
- Status: PASS

... (one section per language feature)
```

### Truth Table Shape

```markdown
| Capability Claim | Spec Ref | Test | Implemented? | Status |
| --- | --- | --- | --- | --- |
| `async-await` | CONFORMANCE-003 | tests/interp_async.rs | Yes (C2) | PASS |
| `browser-goto` | CONFORMANCE-012 | tests/stdlib_dispatch.rs | Yes (C1, routed) | PASS |
| `browser-stealth` | CONFORMANCE-013 | tests/stdlib_dispatch.rs | No (stubbed, fail-closed) | SENTINEL |
| `real-ml` | CONFORMANCE-020 | — | Depends on C4 resolution | TBD |
| `self-host-compiler` | CONFORMANCE-030 | self-host tests | Depends on C4 resolution | TBD |
| `ippool-real` | CONFORMANCE-025 | tests/ippool.rs | Depends on C4 resolution | TBD |
```

### RED Targets

```bash
# 1. Spec conformance validator must report gaps
python3 scripts/validate_spec_conformance.py
# Expected: FAIL — spec doesn't exist yet

# 2. Spec conformance test runner must fail
cargo test spec_conformance -- --nocapture
# Expected: FAIL — no conformance tests written
```

### GREEN Targets

**GREEN verification commands:**

```bash
# 1. Spec conformance validator passes
python3 scripts/validate_spec_conformance.py
# Expected: PASS — all spec statements trace to tests, all tests map to spec

# 2. Conformance test runner passes
cargo test spec_conformance -- --nocapture
# Expected: PASS

# 3. Truth table has no UNKNOWN entries (everything is PASS, FAIL, or SENTINEL)
python3 scripts/validate_tallow_contracts.py
# Expected: PASS — all capability claims resolved
```

### Acceptance Criteria

- [ ] `docs/spec/tallow-lang-spec.md` exists with conformance identifiers for every language feature implemented in C1–C5.
- [ ] Every conformance identifier maps to at least one passing test.
- [ ] Truth table covers every claim in `docs/mega/tallow-1000x-capability-matrix.md`.
- [ ] No UNKNOWN or TBD entries remain in truth table (everything is PASS, FAIL, SENTINEL, or explicitly NOT-IMPLEMENTED).
- [ ] Spec does not claim any feature that C4 downgraded to sentinel.
- [ ] `validate_spec_conformance.py` passes.
- [ ] Independent review approves.

---

## Dependency Graph

```text
C1 — Stdlib dispatch (foundation)
 │
 ├─► C2 — Real async (depends on stable dispatch surface from C1)
 │     │
 │     └─► C3 — Interpreter/codegen parity (depends on async from C2)
 │           │
 │           ├─► C4 — Aspirational real or re-scoped (depends on stable runtime from C3)
 │           │
 │           └─► C5 — Clean-build baseline (can parallelize with C4)
 │                 │
 │                 └─► C6 — Language spec + conformance (depends on C1-C5 stable surface)
```

**Parallelism note:** C4 and C5 touch different subsystems (C4: feature flags, IPPool, self-host; C5: browser assertions, clippy, fmt). They may run concurrently.

---

## Completion Gate Checklist

The 100x completeness upgrade is done only when:

- [ ] **C1:** `tallow doctor --stdlib-scraper` exits 0 with `open_gaps=0` for all 45 modules.
- [ ] **C1:** 2 codegen-integration tests pass.
- [ ] **C1:** 0 check-accepts-run-fails regressions.
- [ ] **C2:** `ExprKind::Await` is implemented in interpreter and codegen.
- [ ] **C2:** Full async test suite passes.
- [ ] **C3:** Differential harness passes for all fixtures (interpreter ≡ codegen).
- [ ] **C3:** VM trampoline replaces `MAX_CALL_DEPTH=100`.
- [ ] **C3:** Deep recursion (10K+ calls) passes.
- [ ] **C4:** `real-ml` feature resolved (exists or all references removed).
- [ ] **C4:** IPPool resolved (real or documented stub).
- [ ] **C4:** Self-host parity proven or gap documented.
- [ ] **C5:** `cargo test --workspace` passes from clean state.
- [ ] **C5:** 5 stale Chrome assertions fixed.
- [ ] **C5:** Clippy and fmt clean.
- [ ] **C6:** Canonical spec with conformance IDs exists.
- [ ] **C6:** Test→spec mapping is complete.
- [ ] **C6:** Truth table has no unresolved entries.
- [ ] **Docs:** Capability matrix and blocker register updated to reflect post-C1–C5 reality.
- [ ] **Review:** Every phase has independent review approval.
- [ ] **No overclaims:** Live scraping, vault, Windows, benchmark superiority, and production deployment are not asserted.

---

## Recommended Execution Order

1. **Start C1 immediately.** It's unblocked, self-contained, and unlocks everything else.
2. **Dispatch C5 in parallel with C1** if worker availability permits — C5 is independent of C1–C4.
3. **C2 → C3 must be serial.** C3's differential harness depends on C2's async implementation.
4. **C4 can start after C3**, but the `real-ml` and IPPool audits can be scoped and researched while C2–C3 execute.
5. **C6 runs last**, synthesizing the stable surface from C1–C5.

**First action:** Run `cargo test --workspace 2>&1 | tail -30` to capture the current baseline failure count, then begin C1 with a manifest gap audit via `python3 scripts/generate_stdlib_surface_manifest.py`.
