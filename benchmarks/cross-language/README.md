# Cross-language baseline — C / Rust / Go / Python / Ruby

The in-repo, reproducible half of the multi-runtime baseline (sheet items **U-K01** and **U-C07(b)**).
Same kernels, same unit definitions, five languages, measured here by `run_bench.py`.

```sh
cd benchmarks/cross-language
python3 run_bench.py                  # full run -> results.json
python3 run_bench.py --quick          # 1 iteration, smoke
python3 run_bench.py --check-sources  # guard: every source implements every kernel
```

## What is NOT here, on purpose

**There is no Tallow row.** Tallow executes `.tl`; these are the C/Rust/Go/Python/Ruby implementations of the
kernels. Equipping Tallow with the same kernels is separate work, so Tallow is absent from the measured table
rather than present as a number that was not measured. A projected Tallow column belongs in prose with its
derivation shown and labelled `[projected]` — never as a row in a table of measurements.

## Method

| | |
|---|---|
| kernels | `mandelbrot`, `vec_sum`, `alloc_churn`, `str_build`, `startup` |
| unit | identical in kind across languages; budgets differ so each language runs a measurable interval, and **s per million units** normalises the difference away |
| timing | median wall ms over 3 runs, `perf_counter` around the child — GNU time's `%.2f` is 10 ms-quantized and useless below ~1 s |
| RSS | **separate** single run under `/usr/bin/time -f %M`, never the timed run |
| spawn floor | `/bin/true` median subtracted from the `startup` row, both numbers reported |
| identity | kernel, CPU, vCPU count, **load average**, tool versions and date are captured **at run time** into `results.json` — a hardcoded machine string rots silently |

Sources are dependency-free and were ported from the seed harness that produced the sheet's
`BENCHMARK-RESULTS.md` (provenance: `tallow-redesign/bench/src`, 2026-10-16).

## Read the load average before you read any number

**This run was taken at loadavg `8.00 5.00 3.75` on 8 vCPUs — oversubscribed.** Three other `cargo` builds
were running on the box at the time. Absolute figures here are therefore **inflated** and are not comparable
with a run on an idle machine; the same measurement against the seed harness differs by ~19% on the Ruby
Mandelbrot row for exactly that reason. That is why the load is captured per run instead of assumed.

**Caveat carried into every conclusion:** Go and Ruby are the versions apt supplies, not current releases
(Go 1.26 and Ruby 3.4+ exist). Their rows understate those languages; the Python and C rows are current.

**`startup` corrected to 0.000 ms for all five compiled languages.** Their startup (~1.7–2.1 ms) is at or below
the spawn floor (2.378 ms), so that subtraction floors at zero and the row is *uninformative for them* — it is
not a claim that they start instantly. The interpreted rows (Python 21.2 ms, Ruby 78.4 ms) are the informative
ones.

## Snapshot — 2026-10-16T17:37Z, 3 iterations, 40 measured cells

`s per million units`, lower is better; `startup` as corrected ms.

| Workload | C -O3 | C -mcpu=native | Rust opt3 | Rust fat LTO | Rust PGO+LTO | Go | Python | Ruby |
|---|---|---|---|---|---|---|---|---|
| mandelbrot | **0.0655** | 0.0722 | 0.0682 | 0.0720 | 0.0703 | 0.0684 | 1.4415 | 1.1984 |
| vec_sum | **0.0061** | 0.0062 | 0.0070 | 0.0076 | 0.0074 | 0.0078 | 0.1954 | 0.2143 |
| alloc_churn | 0.0158 | **0.0156** | 0.0188 | 0.0167 | 0.0164 | 0.0658 | 0.2329 | 0.3149 |
| str_build | 0.0755 | 0.0730 | 0.0377 | 0.0341 | **0.0260** | 0.1498 | 0.2376 | 0.3062 |
| startup (ms) | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.560 | 21.184 | 78.409 |

Peak RSS, largest cell per variant: C/Rust/Go ≈ **392 MB** (`vec_sum` allocates it), Python 91.8 MB, Ruby 30.6 MB.

**Two things in this table that need re-measuring before anyone quotes them:**
1. **`str_build` favours Rust over C by ~2×** (0.026–0.038 vs 0.073–0.076). That is a large, consistent gap for
   a string-building kernel, and on an oversubscribed box it is worth confirming on an idle one before being
   believed — it is a finding, not a conclusion.
2. **`-mcpu=native` is slower than plain `-O3`** on mandelbrot and vec_sum here. That may be CSE/allocation
   noise at this load, or a real codegen difference on this part (`0xd0c`, Neoverse-N1). Also needs a quiet box.

`results.json` is the machine-readable record; the table above is a snapshot of it at this commit.

## The guard that keeps the comparison valid

`--check-sources` asserts that **every** source implements **every** kernel. If one source drifts, the
comparison silently becomes apples-to-oranges and the failure looks like a benchmark result. The guard is
negative-controlled: renaming one kernel in `src/bench.rb` makes it exit 1 and name the file and the missing
kernel, and restoring the file makes it pass again.
