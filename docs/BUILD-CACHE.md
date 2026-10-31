# The shared compile cache: what it actually saves, and the one condition it needs

Sheet item **U-C16** ("Shared compile cache (sccache-style) for the 527 k-line build"), gate *"Measured
build-time reduction"*. Measured 2026-10-16 on the Hetzner ARM box, `--profile release --bin tallow`,
`--locked`, the repo's own `[build] jobs = 8`.

**First, the item's own figure is stale:** the build is **621,249 lines** of Rust (`src` + `stdlib` +
`crates`), not 527 k. Everything below is measured, not carried.

## Result

| Arm | Cache state | Target-dir path | Wall | Rust hits | Rust misses |
|---|---|---|---|---|---|
| **baseline** | empty | `/tmp/sccache-ab-baseline` | **764 s (12m 43s)** | 0 | 356 |
| **cached** | warm | `/tmp/sccache-ab-cached` (a *new* path) | **772 s (12m 51s)** | **0** | 538 |
| **repath** | warm | `/tmp/sccache-ab-baseline` (the path that **populated** the cache) | **350 s (5m 49s)** | **537** | 1 |

**The reduction is 764 s → 350 s: 414 s saved, −54.2%, 2.18× faster** — and the binary is byte-identical
across all three arms (46,074,000 bytes), so the cache changes speed and nothing else.

**And it is zero when the target-dir path changes** (arm `cached`: 772 s, i.e. +1.0% — noise). That single
row is the whole finding, and it is the row a plain A/B would have missed.

## The mechanism: the Rust cache key includes the target-dir path

sccache caches rustc invocations, but **the absolute paths in the invocation are part of the key** — every
rustc call carries `--out-dir <target>/release/deps`, `-L dependency=<target>/release/deps`, and
`--extern <name>=<target>/release/deps/lib….rlib`. Build the same source at a different `CARGO_TARGET_DIR`
and every one of those strings differs, so **every Rust lookup misses**. The cache is not broken and it is
not empty; it is being asked a different question.

**The C/C++ half is not path-sensitive.** Arms `cached` and `repath` both recorded **320 C/C++ hits**, and in
arm `baseline` (empty cache) 99 C/C++ hits appeared *within the same build* — identical C compilations
recurring inside one build. The C compilers are invoked with relative/`-o` style arguments that sccache
normalises, so they hit across paths. **This is why an sccache experiment that only looks at the total hit
count looks like it works** while the Rust half — the part that is 621 k lines — is missing entirely.

## What that means in practice

* **It pays where the target-dir path is stable.** CI is the natural case: a workflow's workspace path is
  fixed, so the cache is reusable across runs and across revisions for unchanged crates.
* **It pays for repeated rebuilds of one tree** — the `cargo clean` → rebuild cycle, and this repo's own
  build cost (`references/build-cost-model.md`: a bin-only edit is ~8 min of *one* crate compile plus the
  final link, which is **not** cached; see the 5m 49s floor below).
* **It does NOT deduplicate the box's several trees, and an earlier claim of mine that it would was wrong.**
  This host carries several checkouts of essentially the same source with their own target dirs (23 GB in
  total). Because those paths differ, a shared cache would return **0 Rust hits** between them — exactly arm
  `cached`. Sharing only works if the trees deliberately share one `CARGO_TARGET_DIR`.
* **The floor stays.** Even at a 537-hit cache the build takes **5m 49s**, because the final **link** (and
  the bin crate's LTO) is not a cacheable compilation. That matches the separately measured finding that
  `tallow run`'s native path is linker-dominated: the linker is the part neither tier removes.

## Reproduce

```sh
apt-get install -y sccache
scripts/sccache_ab.sh baseline   # populates the cache AND is the no-cache baseline
scripts/sccache_ab.sh cached     # same source, NEW target path  -> expect 0 Rust hits
scripts/sccache_ab.sh repath     # same source, SAME target path -> expect ~full hits
```

Each arm writes `<scratch>/sccache_ab_<arm>.{log,result}`. Two traps that make this measurement lie:

1. **sccache's stats are per-user and shared by every compile on the box.** Any other `cargo` build
   touching sccache — including a small "just checking it works" probe crate — lands in the same counters.
   Zero the stats immediately before the arm and touch nothing else until it finishes. (A probe I ran
   mid-measurement produced a confident, wrong "sccache never caches Rust" reading; it was the concurrent
   arm's numbers being read as the probe's.)
2. **`SCCACHE_DIR` does not redirect an already-running server.** The server is per-user and the *first*
   client's environment fixes the cache location, so `SCCACHE_DIR=/x sccache --show-stats` will report the
   default `/root/.cache/sccache` and look broken. Stop the server first (`sccache --stop-server`) if you
   actually intend to move the cache.
