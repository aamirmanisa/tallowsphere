# CI and release build performance — 2026-10-22

Every number here comes from a workflow run on this repository. Run ids are given
so any figure can be re-read from the API. Nothing is extrapolated, and nothing
measured on one platform is reported for another.

## What was measured, and how

Two different clocks get conflated, so they are separated:

- **build step** — the `cargo build` step of one release job, as GitHub reports it
  in the job's step list. This is the part caching can change.
- **job total** — every step of that job, including checkout, prefetch, packaging,
  signing and the cache save. This is what the wall clock actually pays.

A "cold" run is one with no restore, and it also saves a cache. A "warm" run is one
that restores a cache saved by an earlier run of the same tree. A warm run of a
*changed* tree is the case that matters for daily work; a warm run of an *unchanged*
tree is the case that flatters any benchmark.

## Baselines

Release workflow, before any change (run `39701447979`, tag v1.1.5 tree, 543 crates
compiled per tag):

| target | build step |
|---|---|
| linux-x86_64 | 708 s |
| linux-aarch64 | 807 s |
| macos-x86_64 | 958 s |
| macos-aarch64 | not measured |
| windows-x86_64 | not measured |

CI workflow, before any change (run `39701448323`, `--test-threads=2`): Linux
9.6 min, macOS 10.5 min, Windows 11.4 min; run wall 13.1 min.

## What changed, in order, and what each change measured

1. **Compiler object cache, backed by a per-target `actions/cache` archive.**
   The first design used the GitHub Actions cache service directly from sccache,
   one entry per object. Measured on run `39704345890`: **716 of 992 writes failed**
   on linux-x86_64, 241 on Windows, 0% hit rate — the repository's 10 GB cache
   budget cannot hold per-object entries. Replaced with a local object store
   (`SCCACHE_DIR`) archived once per target.

   - cold, local store (`39710897602`): 554 / 867 / 935 / 1105 / **1459 s** (Windows)
   - warm, local store (`39715184870`): **215 / 329 / 439 / 419 s**, hit rate
     **99.80%** (990 hits, 2 misses, 1108 requests)

   That is −69.6% on linux-x86_64, −59.2% on linux-aarch64, −54.2% on
   macos-x86_64 against the baseline. The cold run being *faster* than the
   baseline (554 s vs 708 s) is not a caching effect: the first design's 700+
   doomed HTTP writes were themselves costing about 150 s.

2. **Windows Defender exclusions and removal of the registry restore.**
   The registry cache cost 103 s on Windows to restore what `cargo fetch` does in
   4–78 s, and it competed for the cache budget. Both removed; exclusions added for
   the workspace, `CARGO_HOME`, and rustc/link/lib.

   Windows job `39720235342`: **1215 s total**, of which the binary build was 885 s
   and packaging 190 s — against 1666 s for the equivalent job before.

3. **Timing instrumentation, which is what made the rest of this possible.**
   `cargo build --timings` plus a timed split of the binary and archive builds.
   `--timings=json` is not a flag the pinned toolchain accepts; the HTML report's
   embedded `UNIT_DATA` array is parsed instead.

   Windows unit breakdown from that run (698 units, 1665.4 s of unit time):

   | unit | mode | duration |
   |---|---|---|
   | tallow | compile+link | 321.9 s |
   | tallow | second unit | 307.7 s |
   | btls-sys | build-script | 207.0 s |
   | aws-lc-sys | build-script | 125.8 s |
   | zstd-sys | build-script | 45.9 s |
   | libsqlite3-sys | build-script | 39.1 s |
   | blst | build-script | 30.0 s |

   The build-script block is ~448 s that sccache cannot help with: it caches
   compilations, not script execution, and a fresh target directory has no
   fingerprint to reuse.

4. **Windows target-directory cache** (this is the change under measurement).
   Keyed by `Cargo.lock` and the toolchain pin, restored on non-PR runs. Populated
   by run `39723322749` (saved, 0.56 GB).

5. **`lld-link` — measured, and reverted.** `link.exe` under ThinLTO is the largest
   single unit in the Windows build, so the LLVM linker was tried. Run
   `39723322749`: binary build **1499 s**, against 885 s with `link.exe` on the same
   commit and runner label. **+614 s, a 69% regression.** The swap is reverted in
   `f44712d`; the experiment is recorded here because the expectation was the
   opposite and only the measurement settled it.

6. **CI: 4 threads** (`39704337104` against `39701448323`): Linux 9.6→7.8 min
   (−18.8%), macOS 10.5→8.2 min (−21.9%), Windows 11.4→10.8 min (−5.3%), wall
   13.1→12.7 min (−3.1%). Windows was and remains the wall.

7. **CI: Windows off the PR critical path.** `concurrency` cancels superseded PR
   runs; `Test (Windows)` runs the full suite on main and tags and
   `cargo check --workspace --all-targets` on pull requests. All `rust-cache` steps
   share one key, because ten per-job entries at ~0.7 GB were consuming 7 GB of the
   10 GB budget and evicting the release archives.

## The ceiling, stated rather than wished away

For a build whose source changed, two costs cannot be cached: the link, and
packaging the artifact.

- Windows link (inside the 321.9 s tallow unit): roughly 300 s
- Windows packaging (`7z` over a 46 MB exe and a 527 MB archive): 190–238 s

That floor is ~500 s against a 1459 s cold build, so **~65% is the honest maximum
for a changed tree**, and 90% is not reachable for one — it would require producing
the artifact without linking it. 90% *is* reachable for a rebuild of an unchanged
tree, where cargo does nothing and only packaging remains; that figure is reported
separately wherever it appears and is never presented as the daily-work number.

## What remains, in order of value

1. **Split `src/interp.rs` (56,406 lines).** It is a single compile unit recompiled
   in full on every edit, and it dominates the tallow crate's compile on every
   platform. This is the only remaining change that speeds up the local edit→build
   loop as well as CI.
2. **A larger Windows runner.** `windows-latest` is 4 cores; the build is
   compile-bound with ~1.9× parallelism observed (1665 s of unit time in 885 s
   wall). A 16-core runner is a paid decision, not a workflow change.
3. **`libtallow.a` at 527 MB** (issue #132). It is most of the packaging cost and a
   `cdylib` would remove it, but that is a runtime design change, not CI tuning.

## The local edit→build loop, measured (`cargo check --bin tallow`, this box)

| case | time |
|---|---|
| no-op, nothing changed, incremental off | 69.07 s |
| one-line edit, incremental off | 66.49 s |
| incremental warm-up build | 87.22 s |
| one-line edit, `CARGO_INCREMENTAL=1` | **15.79 s** |
| restore the line, `CARGO_INCREMENTAL=1` | **15.35 s** |

Two things follow. First, the edit itself is almost free: the no-op and the
edited check cost the same, so the loop is paying a fixed toll, not recompiling
the edit. Second, `CARGO_INCREMENTAL=1` removes most of that toll — 66.5 s down
to 15.8 s, a 4.2x cut — which is why `Cargo.toml` already documents that
invocation as the interactive loop, with the standing rule that a run reported as
evidence never uses it.

## Why moving `interp.rs` into modules would not have helped

`impl Interpreter` is 22,829 lines across 56 methods, and two of them are almost
all of it:

| method | lines |
|---|---|
| `call_function` | 8,632 |
| `call_method` | 8,291 |
| `eval_expr` | 1,610 |
| `call_browser_v2_sentinel` | 1,571 |

A Rust function is a single codegen unit. Splitting the impl across files leaves
those two functions whole, so the compile cost does not move; with incremental
compilation the unit that gets recompiled is still `call_function`. The change
that would actually shorten an edit is breaking those two functions into a
dispatch table of smaller helpers — a refactor of the interpreter's hot path,
guarded by the 9,150-test suite, not a file move.

---

# Second round — 2026-10-22, evening

Everything below is from runs after the first document was written. Two of its
claims are corrected here rather than rewritten above, so the record shows what
was believed and what the measurement said.

## Correction 1 — the Windows leg has no target-directory win

The first document left the Windows target-directory cache as "the change under
measurement". Measured now, on two runs:

| run | target cache | sccache | binary build | unit time | btls-sys | aws-lc-sys |
|---|---|---|---|---|---|---|
| `39720235342` | none | 93.24 % | **885 s** | 1665 s | 207 s | 126 s |
| `39723322749` | miss (0 s restore) + `lld-link` | **0.00 %** | 1499 s | 6053 s | — | — |
| `39799461308` | **hit, 563 MB in 11 s** | 93.05 % | **1148 s** | 2140 s | 315 s | 169 s |

The cache never delivered a win. On its first run the restore step finished in
0 s — a miss, which is what a 0.56 GB archive cannot do. On its second it
restored fully and the build was **263 s slower** than the same tree without it,
with sccache at the same 93 %. Unit time rose 1665 → 2140 s and the build-script
block it existed to skip grew instead. A restored `target/` hands cargo
fingerprints whose mtimes are new, so the scripts re-run; the 23 s of restore and
10 s of save are pure cost. **Removed from `release.yml`.**

## Correction 2 — sccache was not the only regression in the lld run

`39723322749` recorded 0 hits / 547 misses (0.00 %) on Windows while the same
archive had produced 93.24 % two runs earlier. The `CARGO_TARGET_*_LINKER`
env var is the only compile-relevant change in that commit, and `f44712d`
reverted it; the 93.05 % in `39799461308` is the confirmation. The 1499 s figure
was therefore an uncached dependency rebuild, not an lld link. The linker
conclusion in the first document (link.exe is faster here) still stands on the
same-commit comparison — it is just not a 69 % link cost.

## Packaging — measured, and fixed

`run 39720235342` spent 190 s and `39799461308` spent **233 s** in
`Package archive`, compressing 573 MB (46 MB exe + 527 MB runtime archive).
Local benchmark on the same payload shape (285 MB, 4 threads):

| tool / level | time | size |
|---|---|---|
| `7z -tzip -mx=9` | 161 s | 89 MB |
| `7z -tzip -mx=5 -mmt=4` | 21 s | 91 MB |
| `7z -tzip -mx=1` | 5 s | 95 MB |
| `zip -9` | 30 s | 93 MB |

Level 9 buys ~2 % size for ~8× the time. `package_release.sh` now uses
`-mx=5 -mmt=4` for the Windows zip, which is ~40 s against 233 s at the CI
payload size.

## Profile — `incremental` was on for release builds

`[profile.release]` carried `incremental = true`. Cargo warns against it for
release builds, and CI builds start from an empty target dir every time, so
nothing can be reused. It inflates the target directory (0.56 GB cached for a
tree whose rlib is 241 MB) and it is the wrong code path for a compiler cache.
Set to `false`. Interactive work keeps the documented `CARGO_INCREMENTAL=1
cargo check` loop (66.5 s → 15.8 s on this box).

Also recorded, not applied: `benchmarks/baseline/profile-ab-2026-10-16.json`
says *ship `--profile max`*, while every shipped target is built
`--profile release` and nothing invokes `max`. Fat LTO with `codegen-units = 1`
removes all codegen parallelism and would make the Windows leg (already the
wall) worse. Flagged for the operator instead of silently flipped.

## What is left on Windows, in order

1. **Runner size.** 4 cores, unit time 1665 s in an 885 s step — ~1.9× parallel.
   Every remaining item is compile- or link-bound; a 16-core runner is the only
   change that scales both. Paid decision.
2. **The 448 s build-script block** (btls-sys 207 s, aws-lc-sys 126 s,
   zstd-sys 46 s, libsqlite3-sys 39 s, blst 30 s). Neither sccache nor a target
   dir removes it; it is BoringSSL and friends being configured and archived on
   every run. The real fix is a prebuilt/vendored build or `btls` with system
   OpenSSL, which is a dependency decision, not CI tuning.
3. **`libtallow.a` at 527 MB** (issue #132) — a `cdylib` would remove the
   packaging payload; runtime design change.
4. **`Pre-fetch the dependency graph` 58–74 s** every run. A registry cache was
   already measured worse (103 s restore), so this stays.

## macOS and Linux — same warm run, different residual

From `39723322749` (sccache 99.80 % on both):

| target | build step | package | job | unit time | tallow crate | btls-sys |
|---|---|---|---|---|---|---|
| linux-x86_64 | 314 s | 18 s | 427 s | 514 s | 200.5 s | 93.9 s |
| linux-aarch64 | 372 s | 17 s | 477 s | 591 s | — | — |
| macos-aarch64 | 295 s | 13 s | 401 s | 597 s | 201.0 s | 65.0 s |
| macos-x86_64 | 356 s | 17 s | 473 s | 697 s | — | — |

Both are **compile-bound, not cache-bound**: the dependency graph is already
99.8 % cached, and ~40 % of the remaining unit time is the `tallow` crate itself
(201 s) plus the BoringSSL build script (65–94 s). Concretely:

- **Codegen parallelism is the free knob.** The tallow crate compiles as 16
  units on a 4-core runner; unit time 514 s against 314 s wall is 1.6×. Raising
  `codegen-units` for CI only is a measurable, reversible experiment; it costs
  runtime quality, so it must be A/B'd on the parity corpus before shipping.
- **The source is the real lever.** `Interpreter::call_function` (8,632 lines)
  and `call_method` (8,291) are single codegen units; every edit to either
  recompiles ~17k lines on every platform. Splitting them into a dispatch table
  is the only change that shortens CI *and* the local loop.
- **Cache-budget hygiene.** The repository holds 10.70 GB across 17 entries
  against a 10 GB cap — active churn. ~7 GB of it is ten per-job `rust-cache`
  entries (0.48–0.72 GB each); the five release `sccache` archives (0.58–1.72 GB)
  are what deliver the speedup and are the ones evicted when the budget pinches.
  Reducing CI caching to the jobs that need it protects the release caches.
- Packaging is already cheap on both (13–18 s) — no change warranted.

## Windows-only portability caught by the new compile plane

Two defects, both invisible on Linux, both found by
`cargo check --workspace --all-targets` for `x86_64-pc-windows-msvc`:

1. `crates/tallow-copy-engine/src/lib.rs` — two tests building symlinks and a
   `UnixListener` fixture (`E0433`, 4 sites). Gated `cfg(unix)`.
2. `crates/tallow-daemon/src/executor.rs:465` — `tokio::process::Command::pre_exec`
   (`E0599`). The landlock preflight already returns `Err` on non-Linux, so the
   arm is unreachable there, but it was still being instantiated. Gated
   `cfg(unix)`.

`Test (Windows)` is green at `0a67aca` (compile plane 488 s). The compile plane
is doing exactly the job it was added for: it costs ~8 minutes on a PR and
caught two release-blocking defects that the full Windows suite would only have
found after a tag.
