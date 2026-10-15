# Canonical-crate drift vs sendtallow — measured 2026-10-15

**Method:** compare every file pinned in `crates/CANONICAL-SYNC.sha256` against the vendored copy in the
sendtallow checkout (`<sendtallow>/crates/<path>`). This is the pinned set only — unlike `diff -rq` it
ignores build outputs and files the pin policy excludes.

```bash
cd crates && while read -r h p; do [ -f "<sendtallow>/crates/$p" ] \
  && [ "$(sha256sum "<sendtallow>/crates/$p" | cut -d" " -f1)" = "$h" ] \
  || echo "DRIFT $p"; done < <(grep -E "^[0-9a-f]{64}  " CANONICAL-SYNC.sha256)
```

**Result:** of 198 pinned files — **129 identical · 47 differing · 22 absent**.

The previous manifest documented **4** known divergences. **44 of the 47 differing files were never
documented**, which is the drift this manifest exists to surface and could not, because it had not
verified since 2026-09-21.

## Action — canonical → product, per policy #1

1. Sync the four crates from Tallowsphere into sendtallow (`--exclude target --exclude Cargo.lock`).
2. Re-run `sha256sum -c crates/CANONICAL-SYNC.sha256` in the product; expect 198 OK.
3. Copy `crates/CANONICAL-SYNC.sha256` and `crates/CANONICAL-SYNC.md` into the product's `crates/`.
4. Where the product legitimately leads (a port that has not gone back), port it into Tallowsphere first,
   then regenerate here — the policy is one-way: canonical first, product second.

This list is generated, not transcribed. No file in the sendtallow repository was read beyond
hashing, and none was modified.

## Differing (47)

```text
tallow-crypto/Cargo.toml
tallow-crypto/fuzz/Cargo.toml
tallow-crypto/src/hash/domain.rs
tallow-crypto/src/kdf/argon2.rs
tallow-crypto/src/kem/provider.rs
tallow-crypto/src/keys/identity.rs
tallow-crypto/src/keys/mod.rs
tallow-crypto/src/keys/storage.rs
tallow-crypto/src/lib.rs
tallow-crypto/src/pake/cpace.rs
tallow-crypto/src/pake/mod.rs
tallow-crypto/src/ratchet/triple.rs
tallow-crypto/src/symmetric/aes_gcm.rs
tallow-net/Cargo.toml
tallow-net/src/nat/candidates.rs
tallow-net/src/nat/detection.rs
tallow-net/src/nat/stun.rs
tallow-net/src/relay/client.rs
tallow-net/src/relay/resolve.rs
tallow-net/src/transport/connection.rs
tallow-net/src/transport/direct.rs
tallow-net/src/transport/fallback.rs
tallow-net/src/transport/mod.rs
tallow-net/src/transport/p2p.rs
tallow-net/src/transport/proxied.rs
tallow-net/src/transport/quic.rs
tallow-net/src/transport/tcp_tls.rs
tallow-net/src/transport/test_support.rs
tallow-net/src/transport/tls_cohort.rs
tallow-net/src/transport/tls_config.rs
tallow-net/tests/direct_transfer.rs
tallow-net/tests/proxy_integration.rs
tallow-net/tests/transport_fallback.rs
tallow-protocol/Cargo.toml
tallow-protocol/src/chat/encrypt.rs
tallow-protocol/src/kex.rs
tallow-protocol/src/lib.rs
tallow-protocol/src/room/code.rs
tallow-protocol/src/room/mod.rs
tallow-protocol/src/transfer/chunking.rs
tallow-protocol/src/transfer/manifest.rs
tallow-protocol/src/transfer/receive.rs
tallow-protocol/src/transfer/send.rs
tallow-protocol/src/wire/messages.rs
tallow-protocol/src/wire/mod.rs
tallow-protocol/src/wire/ordinals.rs
tallow-protocol/src/wire/version.rs
```

## Absent in sendtallow (22)

```text
tallow-crypto/fuzz/.gitignore
tallow-crypto/fuzz/fuzz_targets/fuzz_cpace_finish.rs
tallow-crypto/fuzz/fuzz_targets/fuzz_decode_msg.rs
tallow-crypto/fuzz/fuzz_targets/fuzz_handshake_signed.rs
tallow-crypto/fuzz/fuzz_targets/fuzz_mldsa_verify.rs
tallow-crypto/fuzz/fuzz_targets/fuzz_slhdsa_verify.rs
tallow-crypto/fuzz/fuzz_targets/fuzz_verify_signed_frame.rs
tallow-crypto/src/pake/adversarial.rs
tallow-crypto/src/pake/cpace_draft_vectors.rs
tallow-crypto/src/pake/tcs_pake_1_vectors.rs
tallow-crypto/src/pake/vectors.rs
tallow-crypto/src/rng.rs
tallow-crypto/tests/aes_gcm_differential.rs
tallow-crypto/tests/fips203_kat.rs
tallow-crypto/tests/fips204_kat.rs
tallow-net/examples/spki_pin_probe.rs
tallow-net/src/transport/spki_pin.rs
tallow-net/tests/live_relay_tls.rs
tallow-net/tests/spki_pin.rs
tallow-net/tests/spki_pin_live.rs
tallow-protocol/src/mode_auth.rs
tallow-protocol/src/pq_handshake.rs
```
