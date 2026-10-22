# How other projects release Rust binaries fast — measured, 2026-10-22

Method: read the release workflow of seven shipping Rust projects from
`raw.githubusercontent.com`, then pulled the job list and step durations for
their most recent release run from the Actions API. Every number below is a
`completed_at - started_at` on a real run, not a claim from a README.

## The measured field

| project | release run | jobs | longest leg | how it builds |
|---|---|---|---|---|
| BurntSushi/ripgrep | 15.2.0, 2026-07-15 | 16 | **183 s** (win-gnu, x86_64) | `cross` for 8 Linux targets, native Win/mac, `release-lto` profile, strip |
| casey/just | 1.59.0, 2026-10-15 | 14 | **241 s** (aarch64 Windows) | matrix of `os` × target, `Swatinem/rust-cache` |
| typst/typst | v0.15.x | 8 targets | not published | `cross build` for 4 Linux targets, `cargo build` on native mac/win |
| starship/starship | 2026-10-20 | 10 | <20 s build legs | `cross` and **`cargo zigbuild`** for riscv64, native elsewhere |
| helix-editor/helix | 2026-09-18 | 9 | **1103 s** (x86_64-windows) | **cargo-dist**; Windows is still the wall |
| astral-sh/uv | 2026-10-14 | 16 | **1038 s** (armv7 musl) | cargo-dist, **Depot runners** (`depot-ubuntu-latest-4`), `ACTIONS_CACHE_MODE: none` |
| biomejs/biome | 2026-10-20 | 13 | **1174 s** (win32-arm64) | Depot runners, per-target packaging |
| denoland/deno | current | many | — | native per-OS, **GitHub XL runners** (`windows-2022-xl`, `ubuntu-24.04-arm64-xl`) |

Two facts fall out immediately.

**1. Heavy binaries are not fast anywhere.** Helix's Windows dist job is 1103 s
and biome's win32 packaging is 1174 s. Tallow's 885 s (best measured, sccache
93 %) and 1148 s (with a pointless target cache) sit inside that band. The
project is not doing something uniquely wrong on Windows; it has heavy inputs.

**2. The fast ones are fast because their inputs are small.** ripgrep's slowest
release leg is 183 s and just's is 241 s. Neither ships a 527 MB static archive,
neither compiles BoringSSL, aws-lc, zstd, sqlite and blst on every tag, and
both have a crate small enough that ThinLTO is a rounding error.

## The six practices that actually separate them

### A. Paid, faster runners — the only lever that scales every remaining cost

Astral moved its release build to Depot (`depot-ubuntu-latest-4`) and Deno uses
GitHub's larger SKUs (`windows-2022-xl`, `ubuntu-24.04-arm64-xl`, `macos-14`).
A 4-core `windows-latest` that spends 1665 s of unit time in an 885 s step is
~1.9× parallel; a 16-core runner turns that same work into roughly a quarter of
the wall time, and it scales the link and the C++ build scripts too, which no
cache can touch. This is a purchase, not a workflow edit, and it is the single
highest-value change left for Tallow.

### B. Cross-compile everything that is not the host OS — but not MSVC

`cross` (Docker-based) and `cargo zigbuild` are used by ripgrep, typst and
starship for the Linux matrix: four to eight Linux targets from one x86_64
runner, each a few minutes. What none of them does is cross-compile
**x86_64-pc-windows-msvc from Linux** for the shipped artifact: every project in
this sample builds Windows on a Windows runner. cargo-dist can drive
`cargo-xwin`, but the sample shows the practice is to keep Windows native,
because the artifact links MSVC system libraries and the only proof that it runs
is running it.

For Tallow the transferable part is narrow: the aarch64 Linux leg already
cross-builds, and the Windows leg cannot leave a Windows runner without losing
its smoke test.

### C. cargo-dist as the orchestrator

Helix and uv both use cargo-dist to plan, build, archive, checksum, sign and
publish from one generated workflow. It buys correctness (consistent archive
layout, installer scripts, checksums) and removes a class of hand-written YAML
bugs — it does not make the compiler faster. Tallow already has the equivalent
by hand, including Sigstore signing, so the win here is maintenance, not speed.

### D. Release builds deliberately do not share caches

uv sets `ACTIONS_CACHE_MODE: none` for the release workflow, with the comment
"Release actions must not consume shared GitHub Actions caches". That is a
reproducibility decision: a release artifact should not depend on what happened
to be in a cache. It also means uv's 1038 s figure is an honest cold number, not
a warm-cache flattery. Tallow's release does the opposite — sccache archives are
restored per target — which is faster but makes the artifact depend on cache
contents. Worth knowing which one is being chosen.

### E. Strip and split debug info

Every sampled project strips or uses `strip = true` in the release profile;
ripgrep additionally strips per-target with the cross toolchain's `strip`.
Smaller artifacts cut link output, archive write time and packaging. Tallow
already sets `strip = true` and `panic = "abort"` — nothing left here.

### F. Cache the target directory the way Swatinem/rust-cache does, or not at all

Our own CI is the proof that target-directory caching *can* work: the Windows
compile plane took **488 s cold and 88 s warm** with `Swatinem/rust-cache`,
while the hand-rolled `actions/cache` archive of `target/<triple>` in the release
workflow restored 563 MB and then rebuilt everything (1148 s against 885 s).
The difference is not the archive, it is what the action does around it —
mtimes, `~/.cargo` registry layout and save conditions. If Tallow wants a warm
release target directory, it should adopt the action that demonstrably works in
its own CI rather than a bespoke cache key.

## What this means for Tallow, ranked by seconds saved

| # | change | expected effect | cost |
|---|---|---|---|
| 1 | 16-core Windows runner (or Depot/Namespace equivalent) | 885 s → ~300 s on the build step; scales link and build scripts | money |
| 2 | Prebuilt btls-sys / aws-lc-sys artifacts, or link system OpenSSL | removes ~330–450 s of build-script time per release leg | dependency decision |
| 3 | Ship a `cdylib` instead of a 527 MB `libtallow.a` (#132) | removes most of packaging (233 s → ~20 s) and shrinks the download | runtime design |
| 4 | Replace the hand-rolled target-dir cache with `Swatinem/rust-cache` | warm CI proved 488 → 88 s; release would need the same A/B | workflow edit |
| 5 | Split `call_function` / `call_method` (8.6k / 8.3k lines) | shortens the 200 s tallow unit on every platform and the local loop | refactor |
| 6 | Wider `codegen-units` for CI only | raises parallelism on 4 cores; must be A/B'd on the parity corpus | cheap, reversible |
| 7 | cargo-dist | maintenance only | migration |

## What does not transfer

- **Cross-compiling Windows from Linux.** Nobody in this sample ships MSVC that
  way, and it forfeits the only real proof the artifact runs.
- **A bigger cache.** Tallow already gets 93–99.8 % sccache hit rates; the
  remaining Windows time is build scripts, link and packaging — none of which a
  compiler cache can skip.
- **A cleverer linker.** `lld-link` was already measured on this tree: slower.
- **Removing ThinLTO for build speed.** It is the shipped profile's optimisation
  level, and the recorded A/B says heavier LTO buys no runtime; removing it is a
  product change, not a CI trick, and would need the parity corpus to justify.

## The honest comparison

Tallow's Windows release is in the same bracket as helix and biome, which are
the two other projects here that ship a large native binary — not in the bracket
of ripgrep and just, which ship small ones. The gap to "fast" is not a missing
trick in the workflow; it is 543 crates, a 527 MB static archive, five C/C++
build scripts, and a 4-core runner. The top three items on the list above are
each larger than every workflow adjustment combined.
