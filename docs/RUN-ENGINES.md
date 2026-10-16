# `tallow run` — the two engines, and which one you actually got

`tallow run` has two execution engines. **Native is the default.** The tree-walking interpreter
(`src/interp.rs`) is otherwise reachable only as a **fallback**, and the fallback fires on a *build
failure* or a *crash* — never on a **silent miscompile**, where the native binary exits 0 with wrong
output and nothing signals that anything happened. That class is the reason `--interpret` exists:

```sh
tallow run prog.tl                   # native (default)
tallow run --interpret prog.tl       # the interpreter, chosen on purpose
tallow run --require-native prog.tl  # fail instead of falling back
tallow run --backend cranelift prog.tl  # the in-process JIT (needs a --features jit build)
```

`--interpret` and `--require-native` **conflict** and clap rejects the pair. Asking for the interpreter
while also asking to refuse it is a contradiction, and accepting both silently ignores one of them —
which is how the pair behaved before the conflict was declared.

## How the interpreter was reached before this flag

Not by an engine selection — by a **side effect of cross-compilation**. `tallow run <file> --target
x86_64-linux` skips the native path because the native build is guarded by `if !is_cross`, so the run
falls through to the interpreter. `tests/parity/run_parity.sh:20` says so in as many words:

> `# A cross triple forces the interpreter path (is_cross guard skips native).`

That is an accidental mechanism standing in for a choice, and it also drags cross-compilation along with
it. `--interpret` replaces it. The guard for the cross case is **unchanged**, so the parity runner's
behaviour is unaffected.

## The engine marker is only half-implemented

`--require-native`'s help text promises: *"The one-line engine marker is printed to stderr **either
way** and is never suppressed by `-q` — see E-2-02 §5."*

Observed behaviour on the shipped binary:

| Path | stderr |
|---|---|
| native (default) | *(nothing from the marker)* |
| fallback | `* native build unavailable (...); running in the interpreter` |
| `--interpret` | `* running in the interpreter (--interpret)` |

So the marker exists on the two failure/explicit paths and **not on the native path**. A caller reading
stdout + rc cannot positively confirm a native run — it can only infer it from an **absence**, and an
absence is indistinguishable from an older binary, a suppressed diagnostic, or a run that never reached
that point. The documented contract is therefore not met, and this is **reported rather than fixed
here**: adding a line to every native run's stderr changes the output of every existing invocation and
needs a decision — and the E-2-02 document that supposedly specifies it is not in the tree (below).

**`E-2-02 §5` resolves to no document.** It is cited four times in `src/main.rs` as the normative
specification for this behaviour, and it exists in neither this repo nor `/home/aamir/tallow-redesign`.
A cited specification that cannot be read is not a specification.

## Related drift

`tests/parity/README.md` states: *"Default execution path: `tallow run <file.tl>` → tree-walking
`Interpreter`"*, with native entered through `tallow build`. That was true when the scaffold was
written — the file says *"as of scaffold time"* — and is **false now**: `tallow run` is native-first
(`src/main.rs`, *"Native-first: try compiling the program to a native binary and running it"*), and the
runner's own `is_cross` comment depends on the newer behaviour. The document contradicts itself and the
code.

Also distinct, and not to be confused with engine startup: `docs/benchmarks/cold-start-study-outline.md`
specifies a **product** cold-start study (install → first validated record) and is explicitly
`[target-only]` and unexecuted. It measures something else and publishes no numbers.

## Measured numbers

**The interpreter wins on turnaround; native wins on work — both are correct, and the crossover is in the
corpus.**

Median wall of the whole `tallow run` invocation (binary `sha256 c38430cc…`, a `--features jit` build;
process floor `tallow --version` **10.13 ms**, loadavg 2.69; snapshot revised in wave 18, which added the
third engine):

| Program | native | `--interpret` | `--backend cranelift` |
|---|---|---|---|
| `hello` — trivial | 326.31 ms | **12.81 ms** | REJECTED (builtin call) |
| `loop 200k` — compute | 335.06 ms | **139.81 ms** | REJECTED (builtin call) |
| `06_map_mut.tl` — map mutation | 5015.22 ms | **12.60 ms** | REJECTED (array/map literals) |
| `compute 3M` — same loop, 15× the work | **330.42 ms** | 2027.67 ms | REJECTED (verifier error) |
| `jit_arith.tl` | 338.00 ms | 13.39 ms | **25.89 ms — ran, correct** |
| `jit_fncall.tl` | 326.59 ms | 15.29 ms | **ICE — crashed** |

The interpreter's advantage is **turnaround**, not execution: 3 000 000 iterations cost it 2027.67 ms
against native's 330.42 ms, so the 48–82× throughput deficit decides as soon as there is enough work. `run`
is a dev-loop verb, so the short-program case is the common one, and there the ~300 ms static link
dominates — that is the gap U-C12/U-C13 target. Native remains right for build-once/run-many.

**The Cranelift tier is reachable as of wave 18 but is not yet a tier.** `--backend cranelift` is the
in-process JIT — no object file, no `ld` — and where it works it is exactly what the tier was meant to be
(**25.89 ms against native's 338.00 ms**, computing the right answer). But it accepts **straight-line
arithmetic in `main` and nothing else**: `if`/`while`/`for` fail to define the function, `print` and map
literals are refused, and a **top-level function call ICEs**. Its own test suite is **RED — 5 of 9 tests
panic inside `cranelift-frontend`** — and no CI job ever builds the feature, so a red suite has sat behind a
default-OFF gate. Full detail in `benchmarks/run-engines/README.md`.

The native path spends that time in **GNU `ld`**, linking one object against the **495 MB** static runtime
archive `target/release/deps/libtallow-*.a`: per-child timing shows the LLVM frontend finishing in
~0.07–0.10 s, the program executing in 21 ms, and the `ld` window running 0.28 s for `hello` versus 32.49 s
for the map program — a 114× spread on the same archive and the same command line.

**This does not make native the wrong default.** A program run many times should be built once and executed
many times, where native wins by orders of magnitude. What these numbers show is that *`run` is a dev-loop
verb*, and paying a static-link cost per invocation makes the common case slower — the gap U-C12/U-C13 exist
to close. Native remains the default; `--interpret` is the explicit scripting path.

Full method, the correctness gate (both engines produce identical stdout on all three programs), and the
untested recommendations (**cache the linked binary**, the **JIT tier**, and **`ld.gold`**, which is
installed but was not measured) are in `benchmarks/run-engines/README.md`.
