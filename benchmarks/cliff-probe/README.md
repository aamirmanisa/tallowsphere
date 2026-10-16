# cliff-probe

Measures whether a build actually selected libcrux-aesgcm's AES fast path — the
B7 cliff class. See [`docs/CRYPTO-FASTPATH-AUDIT.md`](../../docs/CRYPTO-FASTPATH-AUDIT.md)
for the findings and the mechanism.

**Run it from OUTSIDE the tallowsphere tree.** Inside the tree, the repository's
own `.cargo/config.toml` supplies `-C target-feature=+aes` for aarch64, so every
configuration looks fast and the cliff is invisible. (That is the config working
as intended — it just makes this probe useless in-place.)

Use **one target dir per configuration**: libcrux's build script enables its SIMD
module conditionally but does not declare `cargo:rerun-if-env-changed`, so a
shared target dir reuses stale output.

```bash
#                        expected on the aarch64 box, 8 MiB x 32:
cargo run --release -q                                              #  ~99 MB/s   fallback
RUSTFLAGS="-C target-feature=+aes" cargo run --release -q           # ~909 MB/s   fast path
LIBCRUX_DISABLE_SIMD128=1 cargo run --release -q                    #  ~15 MB/s   bitsliced
RUSTFLAGS="-C target-feature=+aes" LIBCRUX_DISABLE_SIMD128=1 \
    cargo run --release -q                                          #  ~15 MB/s   +aes buys nothing
```

The `compile-time:` line is the field that tracks the 9.2×; `platform:` reports
`aes_ni=true` in **all four** configurations, which is what makes the cliff silent.

To settle the open x86_64 question, run this on an x86_64 host with and without
`-C target-feature=+aes,+avx2`.
