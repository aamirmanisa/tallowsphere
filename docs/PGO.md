# PGO in the release pipeline (and why BOLT is not here)

Sheet item **U-C11** — *"PGO + BOLT in the release pipeline"*, gate *"Pipeline emits it; measured on
the real binary."*

**Half of this item is implementable on this box and half is not, so the halves are separated rather
than reported as one number:**

| | status |
|---|---|
| **PGO** | **implemented and measured** — `scripts/pgo_ab.sh`, below |
| **BOLT** | **NOT implemented: the tool is absent.** No `llvm-bolt` binary anywhere on the host, and no `perf` to collect the profile BOLT consumes. BOLT is a post-link optimizer that needs a hardware profile to reorder code; without either binary there is nothing to run. |

## The pipeline

```sh
scripts/pgo_ab.sh base                                # release build, no profile
scripts/pgo_ab.sh inst                                # release build with -Cprofile-generate
scripts/pgo_ab.sh workload <corpus-dir>               # run the instrumented binary over the corpus
scripts/pgo_ab.sh merge                               # llvm-profdata merge -> merged.profdata
scripts/pgo_ab.sh use                                 # release build with -Cprofile-use
# or the whole sequence:
scripts/pgo_ab.sh all <corpus-dir>
```

Each arm builds into its own `CARGO_TARGET_DIR` and logs to `benchmarks/out/pgo/<arm>.log`, so the
arms cannot contaminate each other and every number can be traced to a log.

## The trap this pipeline exists to encode

**The `.profraw` files must be merged by the `llvm-profdata` that ships with the toolchain — not the
system one.**

```
rustc 1.98.1        -> LLVM 22.1.8
/usr/bin/llvm-profdata-18 -> LLVM 18.1.3      # the wrong one
```

This is not a theoretical hazard. Handing the LLVM-22 profraws to the LLVM-18 merger:

```
warning: default_….profraw: raw profile version mismatch:
         Profile uses raw profile format version = 10; expected version = 9
PLEASE update this tool to version in the raw profile, or regenerate raw profile …
error: no profile can be merged
```

That reads as *corrupt profile data*, not as a version mismatch, and the natural next move — "the
profile is bad, rebuild and recollect it" — cannot fix it, because the profile generation is fine.
The correct merger is found dynamically in `scripts/pgo_ab.sh` (`$HOME/.rustup/toolchains/<tc>/
lib/rustlib/<host>/bin/llvm-profdata`, installed with the `llvm-tools` component) rather than
hardcoded, so a toolchain bump cannot silently select the system copy again.

## What PGO can and cannot move here

The workload is chosen deliberately: **`tallow copy`** and **`tallow check`**, both tallow's own
code. The native `tallow run` path is **clang + ld dominated** — the separately measured finding that
linking a program takes 32.49 s against 0.28 s for a trivial one (`docs/RUN-ENGINES.md`) — so PGO on
the tallow binary cannot move it, and including it in the workload would dilute the measurement into
a number that means nothing. Measuring the parts PGO can affect is the only way the result can
inform a decision.

## Measured on the real binaries

`base` 46,270,672 B (sha `d1738f26…`) vs the PGO binary **40,372,432 B** — **13% smaller**, from
profile-driven hot/cold splitting. Both are release `--locked` builds of the same source.

Work is tallow's own code: `copy` of 1 GiB (SHA-verified identical to the source afterwards) and
`check` on a generated 20,000-function file (25 s — ~2,600× the 9.8 ms process-start floor, so the
signal is real). Five interleaved iterations, medians:

| build | `copy` 1 GiB | `check` 20k fns |
|---|---|---|
| base | 1.2222 s | 25.6412 s |
| **PGO, representative profile** | 1.2184 s (**+0.31%**) | **24.0318 s (+6.28%)** |

**+6.28% on the front end, ~0% on `copy`** — which is the expected shape: `copy` is I/O- and
memcpy-bound (its 0.31% is noise), while the front end is pure tallow CPU work and is exactly what
PGO can reorder. The sheet's cited BOLT figure is *"5.4% avg / 8.0% max over PGO+LTO"*; PGO **alone**
landing at +6.28% on the front end is inside that band rather than contradicting it.

### The result worth keeping: an unrepresentative profile LOSES 27%

The first profile was collected on the tiny `benchmarks/run-engines/*.tl` files. Those do not
typecheck standalone — they fail in ~10 ms — so the profile taught the optimizer that the front end
*exits early*, and it laid the code out accordingly. Measured against the real 20k-function workload,
that binary was **26.99% SLOWER** (25.3448 s → 32.1848 s).

Re-profiled on the workload that is actually measured, and rebuilt from the same source with the
same flags, the same pipeline produced **+6.28%**.

So PGO here is not "sometimes helps" — it is **aggressively sensitive to the profile**, in both
directions, and a bad profile is worse than no PGO at all. The `workload` arm of the pipeline now
carries that lesson as a comment and profiles a large file that *passes* `check` plus real bytes
through `copy`, because the alternative is a 27% regression that looks like a result.

Two things that fell out of this and are worth knowing before re-running it:

* **A whole-tree `-Cprofile-generate` build deposits its own profiles.** The instrumented build
  wrote **92 profraw files / 56 MB** before any workload ran — proc macros and build scripts are
  compiled with the same `RUSTFLAGS` and dump profiles when they execute. Merging everything gave a
  64.2 MB profdata; profiling only the real workload gave 36.8 MB. Clear the profraw directory
  before the workload run, or the profile is mostly build machinery.
* **Measure the floor.** The first version of the harness checked `stdlib/*.tl`, which exits fast
  with 50 errors; that workload ran in 11 ms against a 9 ms spawn floor — no signal — and the
  meaningless −0.91% it produced was only recognisable as meaningless *because* the floor was
  measured alongside it.

## Scope

PGO is wired as a scriptable pipeline, not as a CI workflow: this repo's CI is intentionally not
executed by this work, and adding a 2×-full-build PGO job to it is a cost decision for the operator,
not a side effect. `-Cprofile-use` also makes builds brittle to unrelated code motion (the profile is
keyed to the exact source), which is a CI policy choice rather than a mechanism.
