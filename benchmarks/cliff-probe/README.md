# cliff-probe

Measures whether a build actually selected the AES-256-GCM hardware path — the
B7 cliff class. See [`docs/CRYPTO-FASTPATH-AUDIT.md`](../../docs/CRYPTO-FASTPATH-AUDIT.md)
for the findings and the mechanism.

Backend as of 2026-10-21: RustCrypto `aes-gcm` 0.10 (libcrux-aesgcm 0.0.8 was
removed for RUSTSEC-2026-0209 / -0211). The probe therefore measures `aes-gcm`.

Run it either way, but note the trap: this directory sits inside the tallowsphere
tree, so the repository's `.cargo/config.toml` supplies `-C target-feature=+aes`
for aarch64 whenever `RUSTFLAGS` is unset. Exporting `RUSTFLAGS` — **including as
an empty string** — disables that table, which is how the slow arm is produced.

Use **one target dir per configuration**, so neither arm can reuse the other's
artifacts.

```bash
# aarch64 box, 8 MiB x 16, measured 2026-10-21:
CARGO_TARGET_DIR=/tmp/cp-plain RUSTFLAGS="" \
    cargo run --release -q                                          #   65.6 MB/s  bitsliced
CARGO_TARGET_DIR=/tmp/cp-aes \
    RUSTFLAGS="-C target-feature=+aes --cfg aes_armv8" \
    cargo run --release -q                                          #  128.3 MB/s  fast path
```

For reference, the retired libcrux 0.0.8 backend on the same harness measured
99.3 MB/s bitsliced and 984.6 MB/s with `+aes` — the ~7.7× fast-path gap between
the two backends is the measured cost of the security fix, not a build-flag
regression.

The `compile-time:` line is the field that tracks the cliff. On x86_64 the
production flags add `+avx2,+pclmulqdq`; re-run there to confirm the same
selection logic.
