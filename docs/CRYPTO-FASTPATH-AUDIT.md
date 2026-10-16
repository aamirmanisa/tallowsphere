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

**F3 — the three x86_64 release targets carried no flags. FIXED 2026-10-16 by
operator decision.**
`release.yml` builds six targets; `x86_64-unknown-linux-musl`,
`x86_64-apple-darwin` and `x86_64-pc-windows-msvc` had no `[target.*] rustflags`.
The x86_64 default feature set is `sse,sse2,fxsr,crt-static` — **no `aes`** — so the
inlining argument above applies unchanged. **The exposure was [inferred], not measured**:
this box is aarch64 and the x86_64 std target is not installed, so no cross-build was
possible; the confirmatory test on an x86_64 host is one command:

```
cargo build --release --target x86_64-unknown-linux-musl
objdump -d target/x86_64-unknown-linux-musl/release/tallow | grep -cE 'vaesenc|aesenc'   # expect > 0
```

**Applied:** `rustflags = ["-C", "target-feature=+aes,+avx2,+pclmulqdq"]` on all four
x86_64 triples — the three that ship, plus `x86_64-unknown-linux-gnu` so CI and local
x86 builds stop measuring a path ~9× slower than the one that ships. No `--cfg
aes_armv8`: that is RustCrypto's ARM opt-in and means nothing on x86, where RustCrypto
auto-detects AES-NI at runtime. **Compatibility consequence, accepted deliberately:**
the binaries now require AES-NI + AVX2 + PCLMULQDQ (Intel Haswell 2013+ / AMD Excavator
2015+); older x86_64 will fault. `+` adds to the default set, so `crt-static` and the
baseline SSE2 defaults are preserved. **Applied to both trees** — this repo *and*
`/home/aamir/Nixe/.cargo/config.toml`, because `release.yml` builds from the Nixe tree,
so editing only this one would have fixed nothing that ships.

**Not yet true until a release runs:** the already-published x86_64 artifacts are still
on the old path. This changes what the next release build produces.

**F3 confirmation — x86_64 codegen, added after the fact (2026-10-16).** The exposure was
[inferred] when the fix was applied, and an unverified fix is the thing this audit exists to
prevent — so it was checked statically afterwards. Cross-built the same probe for
`x86_64-unknown-linux-gnu` and disassembled `libcrux_aesgcm`'s object:

| build | out-of-line `core::arch` AES wrapper fns | inlined AES round instructions |
|---|---|---|
| default (no flags) | **30** | 4 (`aesenc`, `aesenclast`) |
| `+aes,+avx2,+pclmulqdq` | **0** | **276** (`vaesenc`, `vaesenclast`) + 60 `vpclmulqdq` |

Without the flags the intrinsics stay out-of-line — 30 separate `...core_arch3x86...aes...`
functions the hot loop has to **call**; with them they are inlined into the round loop. That is
the same inlining mechanism measured on aarch64, reproduced in x86_64 codegen, so the fix
addresses the same defect on the same reasoning. The VEX prefix in the flagged build is
expected: `+avx2` implies `+avx`, so LLVM emits the VEX form.

*Two traps worth recording.* (1) This box's native `objdump` is **aarch64-only** — on an x86-64
object it prints `can't disassemble for architecture UNKNOWN` and returns **nothing**, and the
first run of the analysis therefore reported "0 AES instructions" in *both* builds, which looked
like a finding. Use `llvm-objdump-18` (installed here) for any non-aarch64 target. (2)
`rustup target add x86_64-unknown-linux-gnu` works, but linking does not — there is no x86_64
cross-linker on this box, so the build stops at the link step with `cc: unrecognized ... '-m64'`.
That is fine: the object files are produced before linking, and codegen is the question here.

**Still not a throughput number** — that needs an x86_64 host. What this establishes is that the
mechanism and the fix are arch-independent, which is what the [inferred] label was standing in
for.

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
| x86_64 AES (3 shipped targets) | **closed** — flags applied 2026-10-16 to both trees; codegen confirmed on a cross-build (30 out-of-line intrinsic wrappers → 0, inlined); takes effect at the next release build |
| `RUSTFLAGS` bypass | clear, and gated |

The gate exits **0** on this tree. It exited 1 on F3 alone until the x86_64 call was
made; that is the gate doing its job, not a defect to be silenced.
