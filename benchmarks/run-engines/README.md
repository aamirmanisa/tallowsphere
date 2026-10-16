# `tallow run` engine benchmark — and why the native path is usually the slower one

Publishes the startup/turnaround numbers for **U-C14** (gate: *"Startup number published"*) and checks
that both engines compute the same answer. User-facing half: [`docs/RUN-ENGINES.md`](../../docs/RUN-ENGINES.md).

```sh
python3 run_engine_bench.py [--binary target/release/tallow] [--iters 6]
python3 run_engine_bench.py --json
```

## Result — median wall of the whole `tallow run` invocation

Binary `sha256 1ef1a897a1ab0312…`. Process floor (`tallow --version`) **10.13 ms**. Loadavg **2.33 / 4.64 / 3.65**
(companions were building during an earlier pass at load 10.01 — the ratios moved by <6%, so this is not a
contended artefact).

| Program | native | interpreter | interpreter is |
|---|---|---|---|
| `hello` (trivial) | **305.44 ms** | **13.25 ms** | **23.05× faster** |
| `loop 200k` (compute) | 309.34 ms | 139.73 ms | **2.21× faster** |
| `06_map_mut.tl` (map mutation) | **4729.71 ms** | 14.29 ms | **330.94× faster** |

**The interpreter is faster end-to-end on every program measured**, and the reason is not that it executes
code quickly — it is that the native path pays a **static-link cost on every single invocation**, and that
cost is what dominates. Even a 200 000-iteration loop loses to the interpreter, because ~300 ms of linking
dwarfs the ~140 ms the loop takes to walk.

This does not mean native is the wrong default: for a program run many times, `tallow build` once and
execute many times wins by orders of magnitude, and that is what native is for. What it does mean is that
**"native by default" applied to the `run` verb — a dev-loop verb — makes the common case slower**, which is
the gap U-C12/U-C13 target. The number here is the before.

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
