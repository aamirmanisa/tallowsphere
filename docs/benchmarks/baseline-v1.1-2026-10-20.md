# Perf baseline v1.1 — pinned 2026-10-20

`benchmarks/baseline/v1.1-baseline-aarch64.json` replaces `v1-baseline-aarch64.json`
as the reference for `scripts/no_regression_gate.py`.

## Why v1 was retired (not "beaten")

The v1 file cannot be reproduced, on two counts, and the gate is right to refuse it:

- **The measuring binary is gone.** v1 records `sha256 bfad86d4…` at
  `/usr/local/bin/tallow`; the file now at that path is `176f1d24…`. No copy of
  bfad86d4 exists on this host.
- **The corpus changed.** v1 records corpus `9218374662ea…`; `examples/*.tl` now
  hashes to a different value. `no_regression_gate.py` rejects the comparison with
  `corpus sha mismatch — not the same measurement`, which is the correct verdict.

An A/B against v1 is therefore unmeasurable, not merely inconvenient. Any claim that
"v1.1 is N% faster than v1" would be fabricated.

## What v1.1 measures

| field | value |
|---|---|
| engine tree | `3e876b3` (includes #124 function values) |
| binary | `target/release/tallow`, sha256 `946b25231c9ee5cf…` (built at `3e876b3`; it predates the `module`-header parser change `ce2004a`, so rebuild before packaging) |
| corpus | `examples/*.tl`, 57 files, sha256 `dc45d5af0884961b…` |
| host | aarch64, 8 cpus, kernel 6.8.0-146, loadavg 1.71 at capture |
| params | iters 7, warmup 2, parser mode `recover` |

| metric | value |
|---|---|
| files ok / total | **57 / 57** (success 1.0, 0 unresolved) |
| median check | 12.488 ms |
| p95 check | 16.359 ms |
| max check | 21.852 ms |
| throughput | 79.456 files/s |
| peak RSS | 21.2 MB |

A first capture of the same corpus on the pre-#124 binary (`c53b1869…`) read 12.343 ms
median / 14.963 ms p95 / 80.627 files/s / 22.8 MB. The delta is noise on this host, and
it is recorded rather than smoothed: one run cannot resolve a 1 % median shift.

The v1 file recorded 51/58 ok (0.8793) — three of those seven misses were genuinely
broken examples, fixed in this change:

- `agent_demo.tl` declared `can_spawn: true` on the default L3 level; spawning needs
  `level: .L4`. The example now typechecks.
- `agent_memory_demo.tl` declared `can_write: false` and then called `.store()`, which
  is a write. It now declares `can_write: true`.
- `financial_e2e_test.tl` was a different dialect (top-level statements, `|t| {}`
  closures, `export {}`, `|>` pipes, PascalCase namespaces over APIs the stdlib does
  not have). It moved to `docs/sketches/` — the corpus is 57 files, not 58.

## Gate status

`no_regression_gate.py --baseline …/v1.1-baseline-aarch64.json --current <repeat run>`
→ **PASS**. The two runs differ only by noise (median 12.343 vs 12.6 ms class), so this
certifies that the gate's comparison path works end to end with real measurements. It
is not a claim about performance over time; the next honest comparison is tallowsphere
after v1.1 against this file.
