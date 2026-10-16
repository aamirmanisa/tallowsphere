# `tallow run` — the two engines, and which one you actually got

`tallow run` has two execution engines. **Native is the default.** The tree-walking interpreter
(`src/interp.rs`) is otherwise reachable only as a **fallback**, and the fallback fires on a *build
failure* or a *crash* — never on a **silent miscompile**, where the native binary exits 0 with wrong
output and nothing signals that anything happened. That class is the reason `--interpret` exists:

```sh
tallow run prog.tl              # native (default)
tallow run --interpret prog.tl  # the interpreter, chosen on purpose
tallow run --require-native prog.tl  # fail instead of falling back
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

**The interpreter is faster end-to-end than the native path on every program measured**, and the reason is
the linker, not the engines' execution speed.

Median wall of the whole `tallow run` invocation (binary `sha256 1ef1a897…`, process floor
`tallow --version` **10.13 ms**, loadavg 2.33):

| Program | native | `--interpret` |
|---|---|---|
| `hello` — trivial | 305.44 ms | **13.25 ms** |
| `loop 200k` — compute | 309.34 ms | **139.73 ms** |
| `06_map_mut.tl` — map mutation | 4729.71 ms | **14.29 ms** |

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
