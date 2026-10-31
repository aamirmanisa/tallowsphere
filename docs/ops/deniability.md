# Deniable storage — semantics, usage, limits (B7.3.1–B7.3.3)

Module: `src/deniability.rs` (wiring line: `pub mod deniability;`). Scope: a
**byte-buffer model only** — no disk I/O; callers own persistence, naming,
and surrounding opsec.

## B7.3.1 Semantics

A deniable container carries **two unlock contexts over one byte buffer**:

- **Visible plane** — plain bytes, readable with no key via `open_visible`.
  This is the plausible content the file is "for".
- **Hidden region** (optional) — encrypted bytes readable only with the key
  via `open_hidden`. Without the key, an attempt is indistinguishable from
  noise: it simply fails (`BadKey`).

**Chaff vs hidden.** The container *body* starts as a deterministic
`chaff_stream(seed, body_len)` filler (splitmix64 byte stream). When a hidden
region is present, the encrypted payload (ciphertext ‖ 32-byte HMAC-SHA256
tag) is written into the body as isolated single-byte shards at salt-derived
**even** indices — shards are never contiguous (minimum gap 2: at least one
chaff byte between any two shards). Chaff is unauthenticated filler:
tampering with it is invisible by design. Ciphertext is
plaintext XOR `HMAC-SHA256(key, "tdlv1" ‖ counter_le64)` block keystream;
the tag is `HMAC-SHA256(key, plaintext)`, verified constant-time.

**Layout** (all LE): `MAGIC "TDLV0001" ‖ u32 visible_len ‖ visible bytes ‖
u32 hidden_field ‖ salt(8) ‖ body`. `hidden_field` is a presence-encoded
length: `0` = no hidden region, `n ≥ 1` = present with `n−1` bytes (a raw
length cannot distinguish "absent" from "present-empty"; §3 pins both).
`salt` = first 8 bytes of `SHA-256("tdlv1-salt" ‖ seed_le64 ‖
visible_len_le64 ‖ visible)`; `body_len = 2·(hidden_len + 32) + jitter`,
`jitter = 32 + (salt_le64 mod 64)`.

**Unlock-context separation.** Opening the visible plane never touches the
key and never fails because of hidden-region state; opening the hidden
region always requires the key. A visible-only container carries a chaff
body with the same outer length distribution as an empty-hidden one, so a
cursory size check does not separate them.

## B7.3.2 Build/usage notes for high-risk profiles

- Choose `visible` content that plausibly explains the file's existence,
  name, and length — it is what a coerced or cursory inspection sees.
- Use a high-entropy `key` (long passphrase or generated key); keys are raw
  bytes here — this module never stores, derives, or manages them.
- `seed` is a build-time chaff seed and is **not** stored in the container
  (open never needs it). It is not key material: leaking it reveals nothing;
  hiding it buys nothing.
- Builds are deterministic (same inputs → byte-identical container). Keep
  the key out of build logs and do not persist key and container together;
  prefer separate unlock contexts (device/session) for visible vs hidden.
- Do not hand-shrink containers: canonical body length is checked on open,
  and truncation/appending is rejected as `Corrupt`.
- Suggested pattern (high-risk profile): standard-looking visible file on
  disk; hidden material only inside the container; key memorised or held in
  a separate unlock context; on duress, open the visible plane.

## B7.3.3 Limits — read before relying on this

- **This is obfuscation-grade, NOT audited cryptography: no guarantees
  against forensic analysis beyond the stated XOR/keystream construction;
  size metadata still observable (container length, declared lengths, body
  presence).**
- The visible plane is unauthenticated by design: its bytes can be modified
  without detection. Only the hidden payload (ciphertext + tag) is
  authenticated.
- Chaff is unauthenticated filler and is ignored on open — chaff tampering
  is undetected. Payload/salt tampering fails the tag (`BadKey`) or the
  canonical length check (`Corrupt`).
- No protection against a malicious writer: such an actor can replace the
  container with a visible-only one or destroy it; integrity here is
  against a wrong *key*, not against write access.
- HMAC-SHA256-CTR keystream: safe only under unique keys per hidden region;
  reusing one key across containers is not analysed. No forward secrecy, no
  replay/rollback protection, no key management.
- Lengths are u32-bounded (visible ≤ 2^32−1, hidden ≤ 2^32−2 bytes);
  oversized build inputs are refused (`BadInput`). In-memory model only.
