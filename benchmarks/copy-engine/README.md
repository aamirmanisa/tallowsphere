# Copy-engine benchmark — replacing an internal number with a reproducible one

`docs/TALLOW-LANGUAGE-COMPARISON-2026-09-12.md` publishes a **2.6 GB/s** copy figure and flags it in the
same breath: *"the 2.6 GB/s copy/BLAKE3/zstd numbers are internal … before external use of these claims, run
an independent, reproducible benchmark pass and label target-vs-shipped."* This is that pass. It measures the
**shipped** binary on data whose sha256 is recorded.

```sh
python3 make_dataset.py --out /path/dataset --total-mb 1024 --files 4 --seed 20261016
python3 make_dataset.py --out /path/dataset --verify          # re-derive the sha from disk
python3 run_copy_bench.py --dataset /path/dataset [--binary /usr/local/bin/tallow]
```

## Gate

**Deterministic dataset sha recorded: `98c09ff41e1e7e583d43a7876010402343537259ea889ae42b4583afab2a9831`**
(1024 MB in 4 files, seed 20261016). This is the U-C04 gate, and it is *checkable*, not asserted: two
independent builds produce an identical sha, and `--verify` recomputes it by **hashing the files on disk**
rather than re-reading the manifest that wrote them. Corrupting a single byte makes it exit 1.

## Result — 3 independent runs, 3 iterations each, spread ≤ 4%

Device: ext4 on `/dev/sda1` (this box's single 150 GB volume). Kernel 6.8.0-146-generic, Neoverse-N1 (`0xd0c`),
8 vCPU. **Carried with the row, because it is part of the measurement: loadavg 2.7–4.6** — three other `cargo`
builds were running throughout. The cold figures are therefore a **floor under contention**, not a device
maximum; `cp` ran under identical conditions, so the *ratio* is the robust part.

| Variant | warm | cold | cold, spawn excluded | peak RSS |
|---|---|---|---|---|
| `tallow copy` (shipped) | 1.207 / 1.253 / 1.207 GB/s | **0.437 / 0.405 / 0.420** GB/s | 0.444 / 0.410 / 0.426 | 20.4 MB |
| coreutils `cp` | 1.234 / 1.291 / 1.290 GB/s | **0.597 / 0.562 / 0.559** GB/s | 0.601 / 0.564 / 0.563 | 2.0 MB |

Every copy was verified byte-identical (`sha256(dst) == sha256(src)`); **zero incorrect copies** in ~100 copies.

**The shipped single-file copy path measures ~0.42 GB/s cold and ~1.21 GB/s warm — roughly 6× and 2× below the
documented 2.6 GB/s**, on this box under this load.

**And coreutils `cp` is ~1.36× faster than `tallow copy` on identical bytes** (0.56–0.60 vs 0.41–0.44 GB/s).
That is the uncomfortable half of the finding: `tallow copy` is documented as *"Fast parallel file copy"*, and
on this workload the plain system tool wins.

## Mechanism — why, not just how fast

`strace` on both, same 256 MB file:

- **Both use `copy_file_range`**, and both hand the *entire* file to a single call (tallow requests 1 GiB; `cp`
  requests `SSIZE_MAX`). Both were served in one call. So the gap is **not** syscall choice.
- **Neither** sets `POSIX_FADV_SEQUENTIAL` and **neither** preallocates the destination — so read-ahead hints
  and `fallocate` are not the explanation either.
- `tallow copy` is **single-threaded** for a single file (one `clone` observed). It is not "parallel" on this
  path.

The residual ~1.36× is unresolved. It is recorded as unresolved rather than attributed — the two obvious
candidates (read-ahead, preallocation) were both checked and both came back empty.

**Scope limit, stated because the docs' word is "parallel":** this measures the **single-file `copy` verb**.
The `CopyPlan`/`CopyJob` engine (`src/stdlib/copy_engine.rs`, 287 lines) plans multi-action copies across
files, and a plan over many files may well behave differently. That path is **not measured here**.

## Three defects this harness had, and the numbers they produced

Kept because they are the reason to re-measure rather than trust:

1. **Warm-only measurement reported 16.5 GB/s.** The source was in page cache, so the harness was measuring
   memory bandwidth and calling it disk throughput. Fixed with surgical per-file eviction
   (`POSIX_FADV_DONTNEED` — deliberately *not* a global `drop_caches`, which would have stalled the three
   companion builds sharing the box).
2. **The variants ran in fixed order**, letting the first variant's dirty-page writeback interfere with the
   second's runs. Fixed by alternating order every iteration.
3. **A 4× overstatement.** The rate divided whole-dataset bytes by a **per-file** median. Fixed by accumulating
   one whole-dataset time per iteration; the comment in the source exists so it cannot come back.

A per-tool **spawn floor** is subtracted and reported both ways (`tallow` 9.08 ms vs `cp` 2.56 ms per process —
one process is launched per file, so an uncorrected comparison charges a 46 MB binary's startup to transfer
speed). Correcting for it does not change the conclusion.
