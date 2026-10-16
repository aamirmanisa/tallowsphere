# Compiler/Parser Performance Harness

`tallowsphere/scripts/benchmark_compiler_parser.ps1` benchmarks parse and compile workloads with multiple iterations and aggregate metrics.

## What It Runs

- Parse workload: auto-detects and uses `parse` or `check` subcommand.
- Compile workload: auto-detects and uses `compile` or `build` subcommand.
- Each case runs `WarmupIterations + Iterations`.
- Warmups are recorded but excluded from measured aggregates.

By default, the harness uses fixture files in `tests\fixtures`:
- Parse defaults: `hello.tl`, `comprehensive.tl`
- Compile defaults: `compile_test.tl`, `parity_test.tl`

## Output

Each run writes a timestamped report directory under:
- `benchmark_reports\compiler_parser\<timestamp>\`

Artifacts:
- `benchmark_compiler_parser_report.json`: full per-iteration + aggregate data.
- `benchmark_compiler_parser_summary.txt`: compact text summary.

The JSON includes:
- Per-run records (`runs`) with duration, status, exit code, and output excerpt.
- Aggregate stats (`aggregates`) overall, by workload, and by case.

## Basic Usage

From repo root (`tallowsphere`):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark_compiler_parser.ps1
```

Custom iteration counts:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark_compiler_parser.ps1 `
  -Iterations 20 `
  -WarmupIterations 3
```

Use specific workload files:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark_compiler_parser.ps1 `
  -ParseFiles tests\fixtures\hello.tl,tests\fixtures\comprehensive.tl `
  -CompileFiles tests\fixtures\compile_test.tl,tests\fixtures\parity_test.tl
```

Compile in release mode:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark_compiler_parser.ps1 -ReleaseBuild
```

Run only one workload:

```powershell
# Parse only
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark_compiler_parser.ps1 -SkipCompile

# Compile only
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark_compiler_parser.ps1 -SkipParse
```

## Metric Interpretation

- `mean_ms`: average runtime across measured iterations.
- `median_ms`: typical runtime; generally best baseline signal.
- `p95_ms`: tail latency; most sensitive to regressions/noisy behavior.
- `stddev_ms`: run-to-run stability.
- `success`: pass percentage; any drop below `100%` indicates parser/compiler failures.

For regression checks, compare:
- `median_ms` for central tendency shifts.
- `p95_ms` for tail behavior.
- `success` and `fail_count` for correctness regressions.

## Repeatability Notes

- The harness can run with isolated source copies (`UseIsolatedCopies`, default `true`) so build artifacts are written inside the benchmark report directory, not source directories.
- For stable results, run on a quiet machine and keep the same iteration/warmup settings between comparisons.
