# Profile A/B — `release` vs `max` (2026-10-16)

**Question (sheet U-C10):** should `[profile.max]` (fat LTO, `codegen-units=1`) be
the release default?

**Verdict:** ship with `--profile max`; keep `[profile.release]` for iteration.
Do **not** claim a runtime win — the measurement does not support one.

Raw record: [`benchmarks/baseline/profile-ab-2026-10-16.json`](../../benchmarks/baseline/profile-ab-2026-10-16.json).

## Method

- `cargo 1.98.1 (797e8a9bc 2026-08-05)`, aarch64, 8 vCPU, kernel 6.8.0-146-generic.
- Corpus: `examples/*.tl`, 58 files, `sha256` prefix `9218374662ea`; 51/58
  type-check clean under both binaries, so behaviour is identical by construction.
- Both builds ran under `CARGO_BUILD_JOBS=2` inside a `MemoryMax=8G` scope (the
  box's memory-safe recipe), not the repository's configured `jobs=8`.

**Caveat:** absolute build times are inflated by the 2-job cap and the
max/release build-time ratio may shift at 8 jobs. Size and functional behaviour
are unaffected.

## Results

| metric | release (thin LTO, cu=16, incremental) | max (fat LTO, cu=1) | delta |
|---|---|---|---|
| binary size | 46.0 MB (46,008,464 B) | 36.6 MB (36,636,688 B) | **−20.4%** |
| peak RSS | 22.6 MB | 20.7 MB | ~−8% |
| build wall | 1,707.6 s | 1,893.0 s | ~+11% |
| success rate | 0.8793 (51/58) | 0.8793 | 0 |
| unresolved | 7 | 7 | 0 |
| check median | 12.836 ms | 12.813 ms | within noise |
| check p95 | 24.099 ms | 22.211 ms | not claimed |

Only the size and RSS wins reproduce across the two binaries. The median shift
(0.023 ms on a 12.8 ms baseline) is inside run-to-run noise and is **not** a
speed claim; p95 moved in the other direction on a different run.
