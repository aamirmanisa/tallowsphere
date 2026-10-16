# Tallow behavioral-parity coverage matrix (tree-walk interpreter ↔ native codegen)

**Status:** REGISTERED — codified 2026-09-16 (campaign lane C1c, item **E2** of
`artifacts/TALLOW_FULL_TASKS_TODO.md`). This is the map, not the fix: it records what is
*proven equal* across the two execution paths today, what is only partially exercised, and
which surfaces are known gaps. Machine-readable mirror:
`artifacts/to-100-2026-09-16/C1c-evidence/parity-coverage-matrix.json`.

## What "parity" means here

- **Comparison unit:** same `.tl` source → tree-walk path (`tallow run <file> --target x86_64-linux`,
  the forced-interpreter form) vs native path (`tallow build <file>` then execute the produced
  binary). Verdict = **stdout byte-for-byte identical AND exit code identical**.
- **stderr is not compared** (warnings / `runtime error:` prefixes differ by design); it is
  captured for debugging only.
- **Reference oracle = the tree-walking interpreter** (`src/interp.rs`). A divergence is attributed
  to the native path unless the interpreter is provably wrong.
- **Determinism required:** every fixture is free of randomness, time, network, and filesystem
  imports, so any nondeterminism is a bug in a path, not in the fixture.
- Verdict vocabulary from the runner: `MATCH` / `DIVERGE` / `ERROR(build|timeout)`; only `DIVERGE`
  fails the runner (rc 1). `ERROR(build)` is a *capability gap*, reported loudly, never a pass.

## Status vocabulary

| Status | Meaning |
|---|---|
| **covered** | Evidence tier T1: a deterministic fixture runs through both paths in `tests/parity/run_parity.sh` and its last recorded verdict is `MATCH`. |
| **partial** | Some evidence exists (IR-pattern assert, codegen unit test, interpreter-only run, native-soundness probe, or a fail-loud boundary test), but there is **no** interp↔native byte-compare — or only part of the surface is exercised. |
| **gap** | No parity evidence: either known-unsupported (fail-loud or interpreter-only) or simply untested. |

Evidence tiers:

- **T1** byte-compare fixture (runner `MATCH`)
- **T2** IR-pattern assert (`emit_module()` output inspected; proves native can lower the construct, **not** that behavior matches)
- **T3** codegen unit test in `src/codegen.rs`
- **T4** interpreter-only run (`tallow check` + `tallow run` over `examples/`)
- **T5** native-soundness probe (build + direct binary exec, rc<128; **no output compare**)
- **T6** engine-honesty control (fallback markers / `--require-native` / clang-shim negative proof)

## Harness surfaces inventoried (2026-09-16)

| # | Surface | Path | Role |
|---|---|---|---|
| H1 | Parity runner | `tests/parity/run_parity.sh` (globs `tests/parity/parity_programs/*.tl`) | T1 driver: 8 fixtures, stdout+rc compare |
| H2 | Parity fixtures | `tests/parity/parity_programs/01..08*.tl` | deterministic probes (feature per fixture, below) |
| H3 | Parity README | `tests/parity/README.md` | verdict history (2026-09-09 + 2026-09-13: **7 MATCH / 0 DIVERGE / 1 ERROR(build)**) |
| H4 | Cargo differential target | `tests/interp_codegen_parity.rs` | examples corpus `check`+`run` (interpreter), skip lists; 21-example interpreter parity list |
| H5 | Cargo generated-fixture target | `tests/generated_tl_parity.rs` | generated-script features; asserts the `http.batch` compiled-mode boundary is explicit |
| H6 | IR parity fixture | `tests/fixtures/parity_test.tl` + `src/codegen.rs::codegen_parity_comprehensive` | T2: IR patterns for strings/arrays/results/maps/enums/loops/math/bools |
| H7 | Bench engine probes | `benches/tl/run_bench.sh` + `benches/tl/bench_{fib_iter,recursive,alloc,io}.tl` | T5: per-program engine label + independent native probe (NATIVE-OK / NATIVE-CRASH / BUILD-FAIL) |
| H8 | Release-gate engine proof | `scripts/release_gate.sh` S7c (smoke, engine=native) + S7d (clang-shim fallback marker + `--require-native` refusal) + S9 (`scripts/baseline_battery.py` engine goldens) | T6 |
| H9 | Fallback markers / flag | `src/main.rs` (~9909–9935: `native run crashed` / `native build unavailable`; `--require-native` refuses) | the only in-band engine signal |
| H10 | Latent CI jobs | `.github/workflows/ci.yml` `parity` job (~126–168); `ci-full.yml` deep-gates step (~194–213) | runs H1 in CI — **latent until first push (R0: no remote)** |

Fixture roster (H2): `01_control_flow`, `02_functions`, `03_loops_arrays`, `04_strings`, `05_maps`,
`06_map_mut` (map-mutation canary), `07_array_push` (array-growth canary), `08_closure_return`
(closure-return fail-loud document). Recorded verdicts: `01–07 MATCH`; `08 ERROR(build)` — expected,
native refuses loudly and `tallow run` falls back to the interpreter (correct `15`).

## Matrix — language surfaces

Statuses are as of the last recorded run set (see *Provenance*); this matrix is a snapshot, and a
matrix row is only "covered" while its fixture's recorded verdict is `MATCH`.

| ID | Feature | Status | Evidence | Gap / reason |
|---|---|---|---|---|
| A1 | Control flow: if / else-if / else, while + `break` / `continue`, nested loops | **covered** (T1) | `01_control_flow.tl`; `tests/parity/README.md` §matrix | — |
| A2 | Named functions, params, recursion, accumulation | **covered** (T1) | `02_functions.tl`; recursion cap fix `fd5b211` | — |
| A3a | Non-capturing closure value + call | **covered** (T1/T3) | `02_functions.tl`; `src/codegen.rs` ~25018 (non-capturing passes null env) | — |
| A3b | Closure capture-**read** (same fn scope) | **covered** (T1) | `02_functions.tl` (`closure(3)=11`, `closure(10)=25`) | — |
| A3c | Closure **returned** from a function | **gap** (fail-loud) | `08_closure_return.tl` → `ERROR(build)`; guard `src/codegen.rs` ~2933–2943 (`body_returns_closure`) | Native cannot lift a closure across a fn boundary; interpreter fallback correct. Multi-session feature, not a bounded fix. |
| A3d | Capturing closure passed **across a call** | **gap** (fail-loud) | guard `src/codegen.rs` ~5378–5400; register #77 (`docs/operations/stub-register.md:140`, fix `507e03a`); `examples/closure_capture.tl` | Native env-threading across the call boundary absent; guard makes `tallow run` build-fail → interpreter. |
| A3e | Closure capture-**mutation** (`{-> n=n+1}`) | **gap** (both paths) | `artifacts/TALLOW_FULL_TASKS_TODO.md:31` (B5 scope note) | Unimplemented in the tree-walker too — whole-language feature gap, not native-only. |
| A4 | Higher-order fns (`filter` / `map` / `each` over arrays) | **covered** (T1) | `02_functions.tl`, `03_loops_arrays.tl` | — |
| A5 | Arrays: literal, index, `.len()`, iterate, `for-in` | **covered** (T1) | `03_loops_arrays.tl` | — |
| A6 | Array `.push()` growth in a loop | **covered** (T1) | `07_array_push.tl`; fix `07980a1` (empty `[]` allocates a real buffer) | — |
| A7 | Array method surface: `first/last/sum/min/max/take/skip/contains` | **gap** (parity-level) | T2 only (`codegen_parity_comprehensive` via `tests/fixtures/parity_test.tl`); T4 in `tests/interp_codegen_parity.rs:113` list | No interp↔native byte-compare; IR assert proves lowering, not equal results. |
| A8 | Strings: interpolation, `+` concat, `.len()` | **covered** (T1) | `04_strings.tl` | — |
| A9 | String method surface: `trim/trim_start/trim_end/reverse/contains/starts_with/ends_with/lower/upper/replace/repeat` | **gap** (parity-level) | T2 only (`codegen_parity_comprehensive`); T4 example runs | Same as A7 — no behavioral compare. |
| A10 | Maps: literal, `[]` index, `.get()`, missing-key→nil, `.len()` | **covered** (T1) | `05_maps.tl`; tagged-dispatch fixes `ffd7369` (+`462b987`, `4062f95`) | — |
| A11 | Map `.set()` mutation in a loop | **covered** (T1) | `06_map_mut.tl`; fix `07980a1` (`emit_map_set` returns the real result map) | — |
| A12 | Map edge cases: nested map value, int-key map, array-in-map `.len()` | **partial** (T3/T5) | fixes `312fda0`, `ad30536`, `3c35969`; `TALLOW_FULL_TASKS_TODO.md:25–29` (edgemap program matches every line) | One-off edgemap evidence; **no standing fixture** — a regression would not trip the parity runner. |
| A13 | Map-value arithmetic (`m[k]+1`) and bool truthiness | **partial** (T3/T5) | `8907cdb`, `1b13df6`; `bench_alloc.tl` native-sound probe | No fixture byte-compare. |
| A14 | Enums + `match` | **partial** (T2/T4) | `codegen_parity_comprehensive` asserts `switch i64`; `enums.tl`/`match_test.tl` in the interp-only list | Native behavior not byte-compared. |
| A15 | Structs (decls, field access, arrays of structs) | **gap** (T4 only) | `structs.tl`, `struct_array.tl` run interpreter-only | No IR assert and no fixture at all in the parity harness. |
| A16 | `Result` (`Ok`/`Err`, `?`, `unwrap_or`, `is_ok`/`is_err`) | **partial** (T2/T4) | `codegen_parity_comprehensive` asserts `TallowResult`; `result_test.tl`/`question_mark_test.tl` interp-only | Native behavior not byte-compared. |
| A17 | `print` output surface used by the fixtures (int/bool/string/interp) | **covered** (T1, implicitly) | every `MATCH` fixture compares stdout bytes | Broader formatting surface (floats, nil, nested composites) has no fixture → B4 open (`TALLOW_FULL_TASKS_TODO.md:30`). |
| A18 | Exit-code propagation | **partial** (T1 partial) | `run_parity.sh:36` compares rc per fixture | All recorded rows are rc=0; **non-zero exit parity untested**. B4 open. |
| A19 | `main(args)` / CLI arguments | **gap** | no fixture exercises args | B4 open (lane C1a in flight this batch). |
| A20 | Native runtime errors: source line:col, bounds/div-zero checks | **gap** | E3 (`TALLOW_FULL_TASKS_TODO.md:55–63`): native has **no** bounds checks; `bail` is a Result-return, not a print; investigated + reverted cleanly | Divergence class by design; real feature, not a bounded win. |
| A21 | `async`/`await` + compiled `spawn` | **gap** (fail-loud / no-op) | F1 (`TALLOW_FULL_TASKS_TODO.md:67`, `await` is a no-op); `src/codegen.rs` ~2604–2686 spawn limits | Interpreter feature-completeness gap (F1) + compiled-mode limits; out of scope for parity proofs until features exist. |
| A22 | Stdlib namespaces in compiled mode (`http.batch`, `net`, `db`, `compress`, `regex`) | **partial** (fail-loud boundary) | `src/codegen.rs:16996` (`not available in compiled mode`), `17320/17391/17578/17766` warnings; boundary test `tests/generated_tl_parity.rs:134–151` | Interpreter-only by design; one boundary test; no per-namespace parity fixture. |
| A23 | `select` | **gap** (fail-loud) | `src/codegen.rs:4609` `select: not supported in compiled mode` | Source-verified refusal; no harness test found. |
| A24 | Compiled `panic`/`assert*` fail-loud contract | **covered** (T3, contract) | `src/codegen.rs` ~29938 / 30236 / 30354 (F3 tests) | Unit-level only; no fixture, but the contract *is* "fail loudly", which is what is tested. |

## Matrix — harness & honesty controls

| ID | Control | Status | Evidence | Gap / reason |
|---|---|---|---|---|
| B1 | Parity runner semantics (MATCH/DIVERGE/ERROR; rc 0/1/2) | **covered** | `tests/parity/run_parity.sh`; README §CI wiring | — |
| B2 | Cargo test wiring of the runner | **gap** | no cargo target invokes `run_parity.sh`; E1 item (`TALLOW_FULL_TASKS_TODO.md:53`) | Local `cargo test` runs cannot catch interp↔native divergence; lane C1b in flight for E1. |
| B3 | Bench engine-labeled probes (4 programs) | **covered** | `benches/tl/run_bench.sh:59–145`; `07980a1` (bench_alloc NATIVE-sound) | No output compare (T5) — by design a soundness probe. |
| B4 | Fallback detection + negative proof | **covered** | `release_gate.sh` S7c/S7d (~874/~878); `scripts/baseline_battery.py` engine goldens; markers `src/main.rs` ~9909–9935 | — |
| B5 | CI enforcement | **partial** (latent) | `ci.yml` `parity` job (~126–168), `ci-full.yml` (~194–213) | R0: no remote — Actions never execute; wiring is the deliverable until first push. |

## Top coverage gaps (ranked, one-line reasons)

1. **Closure forms native can't run** (A3c closure-return, A3d capture-through-call) — shipped contract
   is fail-loud refusal + interpreter fallback; native support is a multi-session feature.
2. **Method-surface parity absent** (A7 string/array methods, A15 structs, A14 enums, A16 Result) —
   only IR-pattern asserts + interpreter-only runs exist, so native output could drift silently.
3. **Map edge cases fixed but unpinned** (A12 nested / int-key / array-in-map `.len()`) — evidence is
   one-off; no standing fixture means no regression alarm.
4. **E1 wiring gap** (B2) — no cargo test drives `run_parity.sh`; the CI gate (B5) is latent until the
   repo gets a remote, so today parity is only checked by manually running the shell runner.
5. **Exit codes only proven for rc=0** (A18) and `main(args)` untested (A19) — B4 item open.
6. **Native runtime-error fidelity** (A20) — no bounds/div-zero checks natively, no line:col; E3
   recorded as not-a-bounded-win.
7. **Compiled-mode stdlib boundary** (A22/A23) — `http`/`net`/`db`/`compress`/`regex`/`select` are
   interpreter-only with one boundary test; per-namespace parity is undefined.
8. **Capture-mutation closures** (A3e) — missing in *both* paths, so parity trivially "holds" while the
   feature does not.

## Stale claim corrected

`artifacts/TALLOW_FULL_TASKS_TODO.md:54` (the E2 item text) still says *"maps via fallback"*. That was
the pre-2026-09-09 state: maps now MATCH natively (`05`, `06`; `ffd7369`/`07980a1`), and the native map
crash is fixed. This matrix supersedes that phrasing; the TODO line itself is left untouched (not owned
by this lane).

## Provenance / recorded runs

- Fixture verdicts recorded in `tests/parity/README.md:143–157`: 2026-09-09 run — 7 MATCH, 0 DIVERGE,
  1 ERROR(build); **2026-09-13 re-verify (M-08, aarch64 DEBUG): 7 MATCH, 0 DIVERGE, 1 ERROR(build), rc=0**.
- `07980a1` (2026-09-09) commit message records `run_parity.sh → 7 MATCH / 0 DIVERGE / 0 ERROR` at the
  7-fixture point and `codesgen 565/565`; `08_closure_return.tl` was added the same evening as the
  documented fail-loud case.
- This matrix is an **inventory snapshot (2026-09-16)** — no new runner execution was performed by this
  lane (map only; no feature work). Re-run `bash tests/parity/run_parity.sh` for fresh verdicts, under
  the campaign incident caps (`(ulimit -v 2000000; timeout 120 …)` for native runs).

## CI entry — PROPOSAL ONLY (not wired by this lane)

The runner already has latent CI jobs (B5). The missing coupling is *doc ↔ fixture drift*: a new
`parity_programs/*.tl` fixture can appear without a matrix row, and a matrix row can rot silently.

- **P1 (shell, lowest risk):** add a step to the existing `parity` job that fails when the fixture glob
  and the matrix JSON disagree. Snippet:

  ```yaml
  - name: Coverage-matrix drift gate
    run: |
      set -euo pipefail
      python3 - <<'PY'
      import glob, json, sys
      m = json.load(open("artifacts/to-100-2026-09-16/C1c-evidence/parity-coverage-matrix.json"))
      have = sorted(p.split("/")[-1] for p in glob.glob("tests/parity/parity_programs/*.tl"))
      want = sorted(f["name"] for f in m["fixtures"])
      print("fixtures on disk:", len(have), "in matrix:", len(want))
      sys.exit(0 if have == want else 1)
      PY
  ```

- **P2 (cargo, owned by the tests lane):** a `tests/parity_coverage_drift.rs` asserting the same
  invariant, so plain `cargo test` catches drift without CI.

Neither is wired by this lane; both are proposals for the parent/operator to place.

## Related documents

- `artifacts/TALLOW_PARITY_PLAN.md` — Phase 1.3 parity infra plan (two paths, vocabulary, sequencing).
- `artifacts/TALLOW_PARITY_VALIDATION.md` — Phase 4.1a fixture validation (5-fixture era).
- `tests/parity/README.md` — runner architecture + verified matrix + risk register.
- `references/...` in the `tallow-development` skill: `tallow-perf-levers.md`, `codegen-native-maps.md`.
