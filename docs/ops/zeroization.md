# Zeroization — module primitives + A6.1.1 repository sweep audit

Status: **sweep complete** (2026-09-11): primitives in `src/zeroize_util.rs`,
the HIGH-priority sweep, and the MEDIUM rows (`PQCKeyPair`, `SecretStore`,
`TokenData`) are DONE — per-type hand-written redacted `Debug` + drop wipe
(or a documented, compile-enforced reason none is needed), and consumer
field-moves fixed (`src/interp.rs` uses `Option::take()` instead of moving
fields out of `OAuthTokenResult`).
Remaining: none of the sweep rows — the LOW rows below are fingerprints /
identity metadata by design (see §4).

## 1. What `src/zeroize_util.rs` supplies

- `SecretBytes` / `SecretString` — owned secret wrappers:
  - no `Clone`, no `Serialize`; the accessor `expose()` is borrow-only
    (no copy-out — the wrapper always owns every buffer it wipes);
  - hand-written redacted `Debug`: `[redacted; N bytes]` (current `N` at print
    time) and `SecretString([redacted])`;
  - `zeroize_now()` wipes eagerly and empties the wrapper; the
    `#[derive(zeroize::ZeroizeOnDrop)]` wipe runs on drop.
- `zeroize_slice(&mut [u8])` — in-place wipe, length kept.
- `wipe(Vec<u8>)` — takes ownership; the backing buffer is zeroized before
  release (no return value the caller could read).
- `REDACTED = "[redacted]"` — redaction marker constant.

## 2. Rule set (apply during adoption)

1. Drop `Debug` — or hand-write a redacted `Debug` — on every type holding raw
   key material, tokens, passwords, or shares: derived `Debug` prints secrets
   into logs and panic messages.
2. No raw keys in returns or `Serialize` for secret-bearing types: wrap in
   `SecretBytes`/`SecretString` or hand out references only.
3. Zeroize on drop: `#[derive(zeroize::ZeroizeOnDrop)]` where fields are
   `Vec<u8>`/`String`, else manual `impl Drop` calling `Zeroize` (arrays,
   maps, hex-decoded buffers).
4. Keep pure-metadata types (ids, fingerprints, digests, lifecycle facts)
   serializable — they carry no secret bytes; do not wrap them.

## 3. Sweep inventory (`src/`, findings as of this task)

| Type | Location | `Debug`? | Zeroize today? | Priority |
|---|---|---|---|---|
| `ShredKeyring` (`keys: BTreeMap<String,[u8;KEY_LEN]>`) | src/shred.rs:145 | hand-written, redacts; no Clone/Serialize | manual: `destroy()` (l.176/280) + `impl Drop` | done — reference impl |
| `PQCKeyPair` (`decapsulation_key` hex `String`) | src/vault/pqc.rs:52 | none (good) | manual `impl Drop` wipes fields | done — swept 2026-09-11 (`Clone`/`Serialize`/`Deserialize` removed: no unwiped copies; sealed flows move the DK as wrapped hex, never through this type) |
| `SSHKeyData` (`private_key: String`) | src/vault/entry.rs:100 | hand-written, redacts | manual `impl Drop` wipes `private_key` | done — swept 2026-09-11 |
| `APIKeyData` (`key`, `secret: Option<String>`) | src/vault/entry.rs:109 | hand-written, redacts key+secret | manual `impl Drop` wipes key + secret | done — swept 2026-09-11 |
| `KeyShare` (`data`, hex share) | src/vault/share.rs:78 | hand-written, redacts share data | manual `impl Drop` wipes `data` | done — swept 2026-09-11 |
| `AgentKey` (`private_key: String`) | src/vault/ssh_agent.rs:49 | hand-written, redacts | manual `impl Drop` wipes `private_key` | done — swept 2026-09-11 |
| `OAuthTokenResult` (`access_token`/`refresh_token`) | src/browser/auth.rs:204 | hand-written, redacts tokens | manual `impl Drop` wipes tokens | done — swept 2026-09-11 |
| `TokenData` (private; oauth stdlib) | src/stdlib/oauth.rs:42 | hand-written, redacts tokens | manual `impl Drop` wipes token fields | done — swept 2026-09-11 |
| `SecretStore` (values XOR-obfuscated at rest) | src/stdlib/secrets.rs:44 | hand-written, redacts values | manual `impl Drop` wipes values (+ `save()` wipes its transient obfuscated copy) | done — swept 2026-09-11 (`Serialize`/`Deserialize` dropped: unused — the file (de)serializes a plain map by hand) |
| `KeyPinStore` (BLAKE3 fingerprint pins) | src/supply_chain.rs:35 | derived + Clone | none | LOW (fingerprints, not secrets) |
| `KeyMeta` / `KeyringMeta` (identity only) | src/keyring_store.rs:77/96 | derived (metadata) | n/a | LOW |
| `KeyRecord` / `ErasureEvent` (identity only) | src/shred.rs:82/96 | derived (metadata) | n/a | LOW |
| `KeyUse` (key id + context) | src/key_ledger.rs:69 | derived (metadata) | n/a | LOW |
| `StoreClient` / `StoreCoordinator` | src/agent_store.rs:37 | hand-written `Debug` (no secret fields found) | n/a (own Drop for coordinator) | none |

Priority = suggested adoption order. HIGH = derived `Debug` over private
material plus no wipe: highest leak risk through logs, error paths, panics.

## 4. Limits

- Wipes are **best-effort** (zeroize's volatile writes): no guarantee against
  copies taken before wrapping, allocator reuse, swap/hibernation images, or
  hardware remanence. `Vec::zeroize` cannot recall pre-`wipe` reallocations.
- Redacted `Debug` protects formatting paths only — not `Serialize`, not
  `unsafe` extraction, not memory inspection.
- The audit above is a read-based grep inventory; line numbers drift, re-grep
  before acting. HIGH- and MEDIUM-priority rows applied 2026-09-11 (see
  table); no sweep row remains open — LOW rows are fingerprint/identity
  metadata, not secret material, so no wrap or wipe is required.
