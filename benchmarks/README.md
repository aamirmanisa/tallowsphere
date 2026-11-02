# benchmarks/ — the compiler/parser measurement layer

This directory is the seed of the performance evidence the project did not have
(upgrade sheet §4-C). It measures `tallow check` over a `.tl` corpus and turns the
result into a gate that fails on a regression.

| File | What |
|---|---|
| `run_compiler_parser.py` | The harness (U-C02): warm-up + repeated iterations, records the six fields a publishable row needs (binary sha, corpus sha, kernel, CPU, load average, peak RSS) plus the build profile. |
| `corpus/` | **The pinned corpus** — the frozen programs the regression gate measures, plus `manifest.json` (per-file + aggregate sha256). Re-pin deliberately with `scripts/pin_perf_corpus.py`. |
| `targets/v1-targets.json` | **Targets as ranges with a rationale** (U-C03). Not a single value. |
| `baseline/` | Measured baselines, one per (arch, build profile). The gate selects the capture matching the machine it is running on. |
| `out/` | Transient run output (git-ignored). |

The gate itself lives at `scripts/no_regression_gate.py` (U-C01) and is wired into CI (U-C08).

## Run it

```bash
# measure the pinned corpus (needs a tallow binary; builds one or point --tallow at one)
python3 benchmarks/run_compiler_parser.py --tallow target/release/tallow \
    --corpus-manifest benchmarks/corpus/manifest.json --out benchmarks/out/current.json

# gate: regression vs the baseline matching this (arch, profile), and inside the ranges
python3 scripts/no_regression_gate.py --baseline benchmarks/baseline \
    --corpus-manifest benchmarks/corpus/manifest.json \
    --current benchmarks/out/current.json
python3 scripts/no_regression_gate.py --targets benchmarks/targets/v1-targets.json \
    --current benchmarks/out/current.json

# the gate's own gate: prove it fails on a seeded regression
python3 scripts/no_regression_gate.py --self-test
```

## Corpus — pinned, and why

The gate compares two measurements only when they were taken over the **same inputs**.
The harness originally globbed `examples/*.tl`, a directory that changes for reasons
unrelated to performance: example bugs get fixed, effect annotations get added, examples
move out. Two separate things moved, and only one of them was example churn:

* **The examples moved.** Replaying the harness's own `corpus_sha` over the top-level
  `examples/*.tl` tree at each commit gives `87c404f` (2026-10-20) `91f0df44..`, `6cb98a9`
  `7efda010..`, `8367b66`-onward `c9e0fe44..`. Four of the 57 files were edited between
  those states — `dealhunter.tl`, `msurface_one.tl`, `public_source_get_batch.tl`,
  `sitescan_demo.tl` (brace escapes, `with Net(...)` effect rows).
* **The baseline was never a committed state.** The v1.1 and v1 baselines both record
  `dc45d5af..`, which **no commit reproduces** — not under the non-recursive glob and not
  under a recursive one. It was captured (2026-10-20T20:10Z) against a working tree that
  no commit contains, so it could not be re-matched however stable `examples/` became.
  That is the root cause: an unpinned corpus makes the perf gate a tripwire on both
  example churn *and* on the capture-time working tree.

Either way the gate refused the comparison ("corpus sha mismatch — not the same
measurement"), and that refusal was correct. The fix is to pin: `benchmarks/corpus/` is
the frozen fixture and the harness measures exactly the files its manifest lists, refusing
to run if a pinned file's bytes changed.
Editing `examples/` no longer moves the measurement identity. Re-pinning is one
deliberate, reviewable commit:

```bash
python3 scripts/pin_perf_corpus.py        # re-copy examples/*.tl and rewrite the manifest
python3 scripts/pin_perf_corpus.py --check
```

Because the pin then no longer tracks `examples/`, CI measures the live tree as a
**separate** correctness step (same harness, `--targets` only) so a current example that
stops type-checking is still caught.

`stdlib/*.tl` is **not** a usable corpus for `tallow check`: only **11 of 85** stdlib files
pass standalone, because the stdlib declarations use constructs the standalone checker does
not parse — `await`, wildcard `_`, and `Type.method(...)` call syntax. That measured fact is
recorded here rather than hidden by corpus selection.

## Honesty rules

- The harness **never fabricates** a number: with no binary it exits `2` and prints the
  build command.
- Every run carries its revision: binary sha256 + corpus sha256 + kernel + CPU + load
  average + peak RSS.
- Targets are ranges with a written rationale (see `targets/v1-targets.json`).
