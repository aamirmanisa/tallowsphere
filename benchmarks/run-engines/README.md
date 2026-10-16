# `tallow run` engine benchmark — and why the native path is usually the slower one

Publishes the startup/turnaround numbers for **U-C14** (gate: *"Startup number published"*) and checks
that both engines compute the same answer. User-facing half: [`docs/RUN-ENGINES.md`](../../docs/RUN-ENGINES.md).

```sh
python3 run_engine_bench.py [--binary target/release/tallow] [--iters 6]
python3 run_engine_bench.py --json
```

## Result — median wall of the whole `tallow run` invocation

**Snapshot revised in wave 18**, which added a third engine. Binary `sha256 c38430cc7e1e424a0df24834…` — a
`--features jit` build, so its native/interpreter figures run a slightly larger binary than wave 17's
(`hello` native drifted 305.44 → 326.31 ms; that is the build, not a regression). Process floor
(`tallow --version`) **10.13 ms**; loadavg **2.69 / 4.35 / 3.66**; 5 iterations.

| Program | native | interpreter | cranelift | interpreter is |
|---|---|---|---|---|
| `hello` (trivial) | 326.31 ms | **12.81 ms** | REJECTED (builtin call) | **25.5× faster** |
| `loop 200k` (compute) | 335.06 ms | **139.81 ms** | REJECTED (builtin call) | **2.40× faster** |
| `06_map_mut.tl` (map mutation) | **5015.22 ms** | **12.60 ms** | REJECTED (array/map literals) | **398.0× faster** |
| `compute 3M` | **330.42 ms** | 2027.67 ms | REJECTED (`failed to define 'sum_to'`) | native wins |
| `compute 3M + print` | **340.58 ms** | 2038.30 ms | REJECTED (builtin call) | native wins |
| `jit_arith.tl` | 338.00 ms | 13.39 ms | **25.89 ms — ran, `main`=7 correct** | 25.2× faster |
| `jit_fncall.tl` | 326.59 ms | 15.29 ms | **ICE — crashed** | 21.4× faster |

**The interpreter wins on turnaround; native wins on work — and this corpus contains the crossover.** The
reason is not that the interpreter executes code quickly; it is that the native path pays a **static-link
cost on every single invocation**, and for small programs that cost dominates. Even a 200 000-iteration loop
loses, because ~300 ms of linking dwarfs the ~140 ms the loop takes to walk. But give the interpreter enough
work and the picture turns: **3 000 000 iterations cost it 2027.67 ms against native's 330.42 ms**, and the
48–82× throughput deficit becomes the deciding factor.

Neither engine is wrong. `run` is a dev-loop verb, so the common case is a short program where the link
dominates — which is why "native by default" on `run` makes that case slower, the gap U-C12/U-C13 target.
Native is right for build-once/run-many, where the link is amortised and the throughput advantage is what
you keep.

## The Cranelift tier — now reachable, and the measurement says it is not yet a tier

`--backend cranelift` (alias `--backend jit`) selects the in-process Cranelift JIT: no object file, no
`ld`. It has existed in-tree behind `#[cfg(feature = "jit")]`, **default OFF**, and until wave 18
**nothing on the CLI could reach it** — its own doc comment claimed a `--backend` flag that did not exist.
A binary built without the feature **refuses** the flag explicitly rather than quietly running a different
engine.

Built with `--features jit` (9m39s, offline from the local crate cache), **the tier runs 1 of the 7 cases
above**. On that one it is exactly what the tier was meant to be — **25.89 ms against native's 338.00 ms
(13×)** with no linker in the loop, computing the **correct** answer. But what it accepts is straight-line
arithmetic in `main` and nothing else:

| Refused | Reason (verbatim from the binary) |
|---|---|
| `hello`, `loop 200k`, `compute 3M + print` | `call to non-top-level function/builtin (e.g. print, closure, dynamic) …` |
| `06_map_mut.tl` | `array/map literals not yet implemented` |
| `compute 3M` | `failed to define function 'sum_to': Compilation error: Verifier errors` |
| `jit_fncall.tl` | **ICE** — `internal compiler error`, with a bug-report URL |

**A top-level call does not get refused; it crashes the compiler.** That is worse than an unsupported
feature and is why it is pinned as its own case: a crash must stay visible.

**Verdict: the tier is real but it is not a tier.** U-C12 asks for the JIT as *the scripting tier*; one
program in seven is not a scripting tier, and a tier that ICEs on a function call cannot be one. The
blocker is **not** performance — it is coverage, plus one crash.

## The backend's own test suite is RED, and CI has never seen it

I first inferred this suite was *vacuous* — its tests used to `eprintln!("skipping (compile)"); return;` on
failure, which would have made a green suite meaningless. **That inference was wrong, and the direct check
refuted it:**

```
$ cargo test --features jit --lib codegen_cranelift
test result: FAILED. 4 passed; 5 failed  (finished in 0.02s)
```

Five tests panic inside `cranelift-frontend` at `ssa.rs:381` — *"Attempting to seal block0 which is already
sealed"* — including `test_compile_simple_add`, `test_if_else`, `test_loop_while_compile_and_run`,
`test_loop_break_compile_and_run` and `test_for_range_compile_and_run`. The backend misuses Cranelift's SSA
builder, which is the same defect the CLI probes above run into from the outside (`if`/`while`/`for` all
fail to define the function).

**And nothing has ever run these tests**, because no CI job builds the feature: the only `--all-features` in
`.github/workflows/ci.yml` belongs to `cargo-deny` (an advisory check that compiles nothing), and every
`cargo test` job runs with default features. So a red suite has sat behind a default-OFF gate, invisible,
and the feature's own doc comment advertises a CLI flag that was never wired.

## Mechanism — the cost is the linker, and it scales with the program

Per-child timeline under `strace -f -tt -e trace=execve`, two programs on the same 495 MB runtime archive:

| Phase | `hello.tl` | `06_map_mut.tl` |
|---|---|---|
| `clang --version` probe | 11.3396 | 37.6841 |
| `clang <ir> -o <out>` | 11.4130 | 37.7310 |
| `clang -cc1` (LLVM frontend) | 11.5115 | 37.7692 |
| **`ld`** | 11.5987 | 37.8406 |
| native binary starts | 11.8828 | 22:10.3347 |
| **`ld` window** | **≈ 0.28 s** | **≈ 32.49 s** |
| program's own execution | — | **0.021 s** |

So codegen is ~0.07–0.10 s in both cases; the program executes in 21 ms; and **the entire difference —
a 114× spread — is GNU `ld` linking one object against `target/release/deps/libtallow-*.a`, a 495 MB static
archive.** `ld` receives the same 2 library/object arguments in both cases, so what differs is the symbol and
relocation surface the program drags in, not the command line.

`strace` inflates absolute times (~7× here), so take the **ratios** from the trace and the **absolutes** from
the harness table above.

Three fixes are implied and **none of them is measured here** — recording them as recommendations, not
results: cache the linked binary across runs of an unchanged source; use the **JIT/Cranelift tier** (U-C13),
which has no linker in the loop; and try a faster linker. On that last point: `ld.gold` **is installed**
(`/usr/bin/ld.gold`); `lld` and `mold` are not. **gold was not tested** and no number is claimed for it.

## Correctness gate — the engines must agree

A speed comparison between two engines is meaningless if they compute different things, so the harness runs
both and compares stdout + rc:

- `hello`, `loop 200k`, `06_map_mut.tl` — **all three agree** (rc=0, identical stdout).

`06_map_mut.tl` is included as a **regression pin**. Its own header comment still claims the native
`.set()` lowering is a silent miscompile that "succeeds" with `len=0`/nil; the shipped binary now prints
`len 10 / k3 3 / MAP_MUT_OK`, and `tests/parity/README.md:152` records it as fixed. Any divergence there
would be an **UNMARKED** divergence and the harness exits 1 — a silent miscompile that comes back is
exactly the failure that must not pass quietly.

## What this harness does not measure

- **Long-running programs.** Every case here finishes in well under a second of actual execution; the
  native engine's *throughput* advantage needs a workload that runs for seconds, which is a different
  harness (the cross-language one covers kernel throughput).
- **`tallow build` + run-many times**, which is the workflow native is optimised for.
- **gold / lld / mold**, and **binary caching** — the three implied fixes above.
