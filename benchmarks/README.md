# benchmarks/ — the compiler/parser measurement layer

This directory is the seed of the performance evidence the project did not have
(upgrade sheet §4-C). It measures `tallow check` over a `.tl` corpus and turns the
result into a gate that fails on a regression.

| File | What |
|---|---|
| `run_compiler_parser.py` | The harness (U-C02): warm-up + repeated iterations, records the six fields a publishable row needs (binary sha, corpus sha, kernel, CPU, load average, peak RSS). |
| `targets/v1-targets.json` | **Targets as ranges with a rationale** (U-C03). Not a single value. |
| `baseline/v1-baseline-aarch64.json` | A real measured baseline (this box, `/usr/local/bin/tallow` 1.1.1, aarch64). |
| `out/` | Transient run output (git-ignored). |

The gate itself lives at `scripts/no_regression_gate.py` (U-C01) and is wired into CI (U-C08).

## Run it

```bash
# measure (needs a tallow binary; builds one or point --tallow at one)
python3 benchmarks/run_compiler_parser.py --tallow /usr/local/bin/tallow --out benchmarks/out/current.json

# gate: regression vs the committed baseline, and inside the target ranges
python3 scripts/no_regression_gate.py --baseline benchmarks/baseline/v1-baseline-aarch64.json \
                                      --current benchmarks/out/current.json
python3 scripts/no_regression_gate.py --targets benchmarks/targets/v1-targets.json \
                                      --current benchmarks/out/current.json

# the gate's own gate: prove it fails on a seeded regression
python3 scripts/no_regression_gate.py --self-test
```

## Corpus — `examples/*.tl`, and why not `stdlib/*.tl`

`examples/*.tl` holds real programs the checker is meant to accept (51 of 58 type-check
clean; the 7 that do not are intentionally non-checking). `stdlib/*.tl` is **not** a usable
corpus for `tallow check`: only **11 of 85** stdlib files pass standalone, because the
stdlib declarations use constructs the standalone checker does not parse — `await`,
wildcard `_`, and `Type.method(...)` call syntax. That measured fact is recorded here rather
than hidden by corpus selection; it is a separate finding, not a benchmark defect.

## Honesty rules

- The harness **never fabricates** a number: with no binary it exits `2` and prints the
  build command.
- Every run carries its revision: binary sha256 + corpus sha256 + kernel + CPU + load
  average + peak RSS.
- Targets are ranges with a written rationale (see `targets/v1-targets.json`).
