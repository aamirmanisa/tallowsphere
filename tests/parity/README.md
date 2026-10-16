# Tallow Behavioral-Parity Test — README

## Purpose

Prove that the **tree-walking interpreter** (`src/interp.rs`, the default path)
and the **CodeGen/native path** (`src/codegen_cranelift.rs`,
`src/codegen.rs`, `src/codegen_llvm.rs`, invoked from `src/main.rs`) execute the
**same `.tl` source to byte-identical output and the same exit code**.

This is the infra for **Phase 1.3** of `artifacts/TALLOW_PARITY_PLAN.md` / the
master task plan. The runner (`tests/parity/run_parity.sh`) is **implemented**
and **wired as a latent CI job** — `parity` in `.github/workflows/ci.yml`
(+ a deep-gates step in `.github/workflows/ci-full.yml`; M-08 / W-C5-10).
"Latent": the repo has no remote (R0), so GitHub Actions never execute; the
wiring is the deliverable until the first push. It is **not** a `cargo` test
target — the separate cargo target `tests/interp_codegen_parity.rs` covers the
broader `examples/` corpus (interpreter check+run, live-network files skipped)
and keeps its own known-fail lists.

## Current architecture (as of scaffold time)

- Default execution path: `tallow run <file.tl>` → tree-walking `Interpreter`
  (`src/interp.rs`). See `src/main.rs`, `Command::Run`.
- Native/compile path: `tallow build <file.tl>` → `CodeGen::compile_with_target...`
  emits LLVM IR then invokes `clang` to link a native executable
  (`src/codegen.rs`); `src/codegen_cranelift.rs` is a JIT variant that can run
  `main` in-process.

So today the two paths are entered through **different CLI subcommands** and
**different process launches**. The parity runner must bridge that.

## What the parity runner does (design)

For **each** `.tl` file in `parity_programs/`:

1. Run it through the **tree-walk** path (`tallow run <file>`), capture
   **stdout** and **exit code**.
2. Run it through the **native** path (`tallow build <file>` to produce a binary,
   then execute that binary), capture **stdout** and **exit code**.
3. Compare: same stdout (byte-for-byte), same exit code.
4. If they differ → **PASS = divergence reported** (this is a finding, not a
   crash). Emit a per-program verdict: `MATCH`, `DIVERGE`, or `ERROR(path X)`.

The runner must treat **timeout** and **build failure** as distinct outcomes
(`ERROR`) — they are not parity failures, they indicate the native path cannot
yet compile the program (an expected early condition per the sequencing below).

### Contract between the two paths

Both paths must agree on:

- **stdout** (all `print(...)` output, in order, byte-for-byte)
- **exit code** (interpreter: value returned from `main` / `Interpreter::run`;
  native: process exit code of the compiled binary)

Any difference in either is a parity failure. stderr is **not** compared (it
carries warnings/`runtime error:` prefixes that differ by path); it is captured
and shown for debugging only.

### Program naming / ordering

Files are prefixed `NN_` so they run in a stable order and the runner can
attribute a case to a feature area:

| File | Feature exercised |
|------|-------------------|
| `01_control_flow.tl` | if/else-if/else, while + break, while + continue, nested loops |
| `02_functions.tl` | named fns, recursion, closures, HOF (map/filter/each) |
| `03_loops_arrays.tl` | arrays (index/len/iterate), map/sum, for-in |
| `04_strings.tl` | interpolation, `+` concat, length |
| `05_maps.tl` | map literal, `[]` index, `.get()` — literal-read maps (now sound) |
| `06_map_mut.tl` | map `.set()` mutation in a loop — **silent native miscompile canary** |
| `07_array_push.tl` | array `.push()` growth + iterate — **native SIGSEGV canary** |

All programs are **deterministic**: no randomness, no time/clock reads, no
network, no filesystem imports. Their output is a fixed, reproducible byte
string, so any nondeterminism is a bug in a path, not the fixture.

## Known / expected risk areas (documented so the runner isn't surprised)

- **`.len()` vs `.len` property**: both forms are seen in the live codebase
  (`examples/map_test.tl` uses `high.len`; many stdlib/scratch files use
  `.len()`). The fixtures use `x.len()` **with parens**. If the native path
  honours only one form, that program will `DIVERGE` or `ERROR` — a finding.
- **Maps**: literal construction + `.get()` (`05_maps.tl`) now MATCH natively.
  **Mutation is the remaining gap** — `.set()` in a loop (`06_map_mut.tl`)
  silently returns the wrong value with exit 0. Keep 06 as a standing canary.
- **Array growth**: `.push()` in a loop (`07_array_push.tl`) SIGSEGVs natively
  (signal 139). Growth/mutation, not literal read, is the array gap.
- **Closures / HOF**: in-process native execution must cross the ABI between
  `Value` and native code; if closures aren't lowering, `02_functions.tl` /
  `03_loops_arrays.tl` will `DIVERGE`.
- **Exit-code mapping**: interpreter may return 0 vs the native process's
  `exit(0)`; ensure both report the same integer for the same success/failure.
- **`examples/closure_capture.tl` capture-through-call (recorded by M-08,
  2026-09-13; fixed by the capture-through-call fail-loud guard, register
  #77, 2026-09-15):** the native backend cannot thread a capturing closure's
  environment across a function-call boundary, so the compiled binary used to
  exit 1 silently or spin forever. The code generator now **refuses loudly**
  when a call passes a capturing closure (`codegen.rs::emit_call`), which
  makes `tallow run` build-fail and fall back to the interpreter — plain
  `tallow run examples/closure_capture.tl` prints the correct `10`/`21`,
  rc 0; `tallow build` fails with the guard message instead of producing a
  misbehaving binary. `examples/closure_advanced.tl` takes the same path.
  The forced-interpreter form (`tallow run … --target x86_64-linux`) keeps
  working, and non-capturing closures still compile and run natively.
  **Consequence:** the cargo target `tests/interp_codegen_parity.rs` no
  longer hangs on this example (no misbehaving native binary is produced).

## Layout

```
tests/parity/
  README.md                     <- this file
  parity_programs/
    01_control_flow.tl
    02_functions.tl
    03_loops_arrays.tl
    04_strings.tl
    05_maps.tl
    06_map_mut.tl
    07_array_push.tl
    08_closure_return.tl
```

The runner (`tests/parity/run_parity.sh`) is implemented and run (see `RESULT` below).

## CI wiring (M-08, 2026-09-13)

`run_parity.sh` runs as the latent `parity` job in `.github/workflows/ci.yml`
(SHA-pinned actions, `cargo build --locked --bin tallow`, clang guard, static
`bash -n` preflight; artifact `parity-report.txt`) and as a deep-gates step in
`ci-full.yml` (nightly, reusing the warm target dir). Exit semantics as above:
**rc 0 = no divergence** (MATCH + documented ERROR(build)); **rc 1 = at least
one DIVERGE** (gate fails); rc 2 = debug `tallow` binary missing. The job
mirrors `scripts/release_gate.sh` S7d's clang-shim fallback story: ERROR(build)
is a labeled outcome, never silently swallowed.

Run locally (same as CI): `bash tests/parity/run_parity.sh` after
`cargo build --bin tallow` (heavy jobs on this box go via
`bash scripts/ram_guard.sh`).

## Verified coverage matrix (run 2026-09-09, DEBUG, aarch64)

| Fixture | Feature | Verdict |
|---------|---------|---------|
| 01_control_flow.tl | if/else, while+break/continue, nested loops | **MATCH** (native byte-identical, rc=0) |
| 02_functions.tl | named fns, recursion, closures, HOF | **MATCH** (rc=0) |
| 03_loops_arrays.tl | arrays (index/len/iterate), map/sum, for-in | **MATCH** (rc=0) |
| 04_strings.tl | interpolation, `+` concat, length | **MATCH** (rc=0) |
| `05_maps.tl` | map literal, `[]` index, `.get()` | **MATCH** (rc=0) — literal-read maps are sound |
| `06_map_mut.tl` | map `.set()` mutation in a loop | **MATCH** (rc=0) — fixed: `.set()` now returns the real map (was silent `len=0`) |
| `07_array_push.tl` | array `.push()` growth + iterate | **MATCH** (rc=0) — fixed: empty `[]` now allocates a real buffer (was SIGSEGV) |
| `08_closure_return.tl` | closure returned from a fn | **ERROR(build)** — expected: native refuses (fail-loud) rather than silently miscompile; `tallow run` falls back to the interpreter (correct `15`). Interpreter reference = 15. |

**Notes:**
- **Re-verified 2026-09-13 (M-08, aarch64 DEBUG, `bash tests/parity/run_parity.sh`): `7 MATCH, 0 DIVERGE, 1 ERROR(build)`, rc=0** — same verdicts as the 2026-09-09 matrix (08_closure_return remains the documented fail-loud build refusal).
- All 7 fixtures MATCH — the native path is now byte-identical to the tree-walker
  for control-flow / functions / arrays / strings / maps-literal / map-mutation /
  array-push-growth.
- `05_maps.tl` was the historical canary (native used to segfault on string map
  values). **As of 2026-09-09 literal map construction is sound and 05 MATCHes.**
- `06_map_mut.tl` was the **map-mutation gap**: `.set()` in a loop silently
  returned `len=0` with exit 0 (a quiet miscompile — the worst kind, no signal to
  trigger the fallback). **Fixed**: `emit_map_set` now returns the real result map
  pointer instead of the constant `0`, so `m = m.set(...)` no longer clobbers `m`
  back to null.
- `07_array_push.tl` was the **array-growth gap**: `.push()` in a loop segfaulted
  natively (signal 139) because an empty `[]` literal emitted `null` and the first
  push loaded the length from a null base. **Fixed**: empty `[]`/`{}` literals now
  allocate a real `[count=0]` heap buffer.
- `03_loops_arrays.tl` only iterates a fixed literal, so it never exercised
  push-growth or map mutation — these two canaries (06/07) do.
- `08_closure_return.tl` documents the **closure-return fail-loud contract**: the
  native backend cannot lift a closure across a fn boundary, so `tallow build`
  rejects it (ERROR(build) is expected, not a regression) and `tallow run`
  correctly falls back to the interpreter. Full native closure-return threading
  (heap env + composite across the ABI) is a documented future item.
- **Run-path fallback note:** these defects were hidden by `tallow run`'s
  interpreter fallback (06 exits 0 with no signal; 07 is a signal-death the
  fallback re-runs). Use `tallow build` + direct binary execution (what this
  runner probes) to check native soundness. The bench harness
  (`benches/tl/run_bench.sh`) does this independent probe per program.
- 02_functions required a real fix: the debug recursion cap (8) blocked `fib(10)`;
  now 64MB stack + cap 100 lets the interpreter run it (MATCH).
- Exit codes agree for all MATCH cases (interpreter `main` return vs native `exit`).
