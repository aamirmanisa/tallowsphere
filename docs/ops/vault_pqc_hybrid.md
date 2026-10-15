# Vault PQC hybrid — composite-KEM (KEM+DEM) review (A6.1.3)

Status: **default ON for new vaults** (2026-09-11). Review of the v2 hybrid
container (`src/vault/pqc.rs`, `src/vault/db.rs`).

## Construction

v2 `.twv` payloads are **double-encrypted**; both layers are authenticated
(AEAD):

1. **DEM (inner, classical):** AES-256-GCM keyed by a password-derived key —
   `Argon2id(password, salt = BLAKE3(EK))` (64 MiB, t=3, p=4). Nonce:
   `classical_nonce`.
2. **KEM (outer, post-quantum):** ML-KEM-768 encapsulation against an
   **ephemeral** encapsulation key (fresh keypair per blob). The shared
   secret keys a second authenticated AES-256-GCM layer via a BLAKE3 keyed
   KDF. Nonce: `pqc_nonce`, encapsulated key: `pqc_ciphertext`.
3. **`dk` custody:** the ephemeral decapsulation key is stored wrapped under
   `Argon2id(password, BLAKE3(EK))` (`dk_nonce` + `wrapped_dk`).

Encrypt = inner then outer; decrypt peels outer then inner. Each layer
verifies its own authentication tag before releasing plaintext.

## Review findings

- **Why composite:** harvest-now-decrypt-later. If ML-KEM falls to a future
  adversary while AES-256-GCM holds (or vice versa), payloads stay protected;
  no single algorithm compromise defeats the container.
- **Both layers authenticated:** the previous outer layer was an
  **unauthenticated** BLAKE3-XOR stream (malleable: an attacker could corrupt
  the inner ciphertext undetected at the outer layer). It was replaced with
  AES-256-GCM keyed from the ML-KEM shared secret — the "KEM+DEM" upgrade
  this task called for.
- **Failure modes (all fail-closed):** tampered inner nonce/ciphertext → inner
  GCM rejects; tampered outer fields or KEM ciphertext → outer GCM /
  decapsulation mismatch rejects; wrong password → Argon2id-derived key
  mismatch → rejects; a v1 file opened through a v2 path (or vice versa) →
  version check in the container before any decryption.
- **Key handling:** `PQCKeyPair` carries no `Debug` (private material never
  reaches logs/panics) and wipes both keys on drop; `PQCEncryptedBlob` holds
  only ciphertext, public EK and nonces — no secrets — and also carries no
  `Debug`.
- **Nonce hygiene:** fresh random 96-bit nonces per layer per encryption.
  Volumes per vault are user-paced and far below birthday-bound concerns.
- **Accepted limits:** Argon2id is the only password-hardening step; the dk
  wrap shares its chain with the inner layer salt (password compromise alone
  suffices to unwrap `dk`, as expected for password-based containers); the
  format is versioned (`version: 2`) so future KEM swaps don't reinterpret
  existing bytes; `dk_hex` transits as a caller-owned `String` — callers
  should `Zeroizing` it after wrapping (db.rs does, via the wrap call shape).

## Default flip (A6.1.3)

- `VaultSettings::pqc_enabled` now defaults **true**: new vaults write v2.
- v1 files still open through the preserved legacy path; callers can opt down
  to v1 by setting `pqc_enabled = false` explicitly (pinned by
  `classic_vault_still_roundtrips_when_pqc_disabled`).
- Upgrading an existing vault: open → set `pqc_enabled = true` → save
  (pinned by `enabling_pqc_upgrades_vault_to_hybrid`).
