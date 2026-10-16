# Crypto fast-path audit — the B7 cliff class

**Sheet item:** U-F12 · **Date:** 2026-10-16 · **Method:** measurement, not source reading
**Gate:** `python3 scripts/fastpath_audit.py --release-workflow <path> --binary <path>`

## What the cliff class is

A fast path chosen by a **compile-time** condition rather than by runtime CPU
detection. When the build flag is missing, the code silently runs a slow
fallback: no error, no runtime symptom, byte-identical output. The runtime check
keeps reporting that the hardware is present — which is exactly what makes it
silent.

## Measured, this box (aarch64, cargo 1.98.1)

Standalone probe against **the exact pinned version** `crates/tallow-crypto`
uses (`libcrux-aesgcm = "=0.0.8"`), 8 MiB × 32 iterations of AES-256-GCM:

| configuration | `cfg(target_feature="aes")` | AES-256-GCM |
|---|---|---|
| no flags | false | **98.7 MB/s** ← the silent fallback |
| `-C target-feature=+aes` | true | **909.3 MB/s** ← 9.2× |
| `LIBCRUX_DISABLE_SIMD128=1` | false | 14.9 MB/s (bitsliced, for scale) |
| `+aes` **and** disabled | true | 14.7 MB/s (`+aes` alone buys nothing) |

`libcrux_platform::aes_ni_support()` returned **true in all four** — it reads
`AT_HWCAP` at runtime and does not gate code generation.

**Mechanism.** libcrux's AES intrinsics are `#[target_feature(enable = "aes")]`.
Rust will not inline them into a caller compiled *without* that feature, so every
AES round becomes a real function call with register spills. That is the 9.2×.
The runtime check guards correctness, not speed.

## Findings

**F1 — the aarch64 fast path is live in the shipped artifact.** The installed
production compiler contains **8,587** ARMv8 AES instructions, 280 SHA-256,
60 SHA-1 and 1,022 PMULL. Confirmed by `objdump`, not by config reading.

**F2 — `+aes` is load-bearing and is correctly set for all three aarch64
targets** (`.cargo/config.toml`: gnu, musl, darwin).

**F3 — GAP: the three x86_64 release targets ship with no flags.**
`release.yml` builds six targets; `x86_64-unknown-linux-musl`,
`x86_64-apple-darwin` and `x86_64-pc-windows-msvc` have no
`[target.*] rustflags`. The x86_64 default feature set is
`sse,sse2,fxsr,crt-static` — **no `aes`**, so the inlining argument above applies
unchanged. **This is [inferred], not measured**: this box is aarch64 and the
x86_64 std target is not installed, so the cross-build could not be run.
Settling it needs one build on an x86_64 host:
`cargo build --release --target x86_64-unknown-linux-musl` then
`objdump -d target/x86_64-unknown-linux-musl/release/tallow | grep -c aesenc`.
**Fixing it is a compatibility call, not a config tweak** — `+aes` makes the
binary require AES-NI — so it is reported, not applied. `.cargo/config.toml`
already says not to add it without making that call.

**F4 — the RUSTFLAGS hazard is clear today.** An exported `RUSTFLAGS` makes cargo
ignore the `[target.*]` tables entirely, which would undo the whole thing
silently. No workflow in this tree sets it (and `ci.yml` says so explicitly).
The gate checks this so it stays true.

**F5 — a second hypothesis was tested and KILLED.** RustCrypto's `sha2` 0.10.9
gates its aarch64 hardware path behind the `asm` Cargo feature
(`#[cfg(all(feature="asm", target_arch="aarch64"))]`, default features `["std"]`),
while x86 gets runtime detection — which reads exactly like a second cliff. The
binary says otherwise: hardware SHA-256 instructions are present. **Source
reading of a feature gap does not tell you what the shipped binary contains.**
That is why this audit's gate is binary evidence and not a manifest check.

**F6 — my own first reading of F1's mechanism was wrong the same way.** Reading
`libcrux-aesgcm/build.rs` + `libcrux-platform` suggested the runtime dispatch made
`+aes` irrelevant. The 98.7/909.3 measurement is what settled it, and the source
reading is recorded here as superseded rather than quietly dropped.

**Primitives checked and clear:** `blake3` (runtime dispatch, `platform.rs`),
`ring` (`cpu/arm.rs`), `aws-lc-rs`, `chacha20` 0.9.1 (NEON path taken; NEON is a
baseline aarch64 feature).

## What the gate does

Four checks, each reporting `pass` / `GAP` / `could-not-evaluate` — an
unevaluable check returns 2, never a pass:

- **config-flags** — every `[target.<triple>]` override carries the flag its arch needs.
- **shipping-coverage** — every target in the release matrix is covered. Reads the
  matrix from `--release-workflow`; the release workflow lives in the parent tree,
  so this check reports `could-not-evaluate` rather than guessing when it is absent.
- **rustflags-hazard** — no workflow sets `RUSTFLAGS`.
- **binary-evidence** — the built binary contains AES, SHA-256 and PMULL
  instructions. Zero for any of them is a fail.

Exit: `0` clean · `1` gap found · `2` incompletely evaluated.

## Status

| path | status |
|---|---|
| aarch64 AES (bulk AEAD) | **closed** — flag set, present in the shipped binary |
| aarch64 SHA-256 / PMULL | **closed** — present in the shipped binary |
| x86_64 AES (3 shipped targets) | **OPEN — needs an operator go/no-go** |
| `RUSTFLAGS` bypass | clear, and gated |

The gate exits **1** today, on F3 alone. It will exit 0 the moment the x86_64
call is made one way or the other.
