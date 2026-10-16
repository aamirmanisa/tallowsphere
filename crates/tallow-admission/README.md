# tallow-admission

Mesh-door admission core for Tallow — the first production port of the
`veil v0` reference core (artifacts/tallow-veil-mesh-2026-09-27/tools/veil_core.js).

**What it is.** The riskiest mechanism of the mesh door, as a pure,
transport-agnostic library:

1. **Authenticated device admission** — X25519 ephemeral ECDH mixed against
   the pinned server static key, Ed25519 device identity, transcript-bound,
   timestamped, HKDF-derived directional AEAD keys (ChaCha20-Poly1305).
2. **Probe-indistinguishability** — every unauthenticated outcome (garbage,
   HTTP probes, silent lingerers, unknown/revoked devices, tampered or stale
   handshakes, replays) receives byte-identical cover bytes: the 260-byte
   "ordinary 404" (`sha256 f23589f6…158bfe`).

**Architecture.** The protocol lives in pure state machines —
`ServerSession` / `ClientSession` — that consume bytes and emit `Action`s
(`Write` / `Cover` / `Close`); no I/O inside. `io` is a thin blocking
loopback layer (thread-per-connection, `dial_call` / `dial_call_on` one-shot
client). The **loopback-first daemon binary `tallow-admissiond`** (`src/bin/`,
task-1.4 packaging) wraps the same core, binds loopback-only by default, and
loads registry/key files; production sits behind Caddy with real key material.
The **operator client `tallow-mesh`** (`src/bin/`, task-1.5 MVP) makes
one-shot admitted calls with **announced rungs** (`direct` / `ssh` forward /
`tor` via SOCKS5) and mints device keys (`keygen`, 0600) for the registry
ceremony.

## Port mapping (mechanical rename at first port)

| reference (veil v0) | this port |
|---|---|
| `V1S` / `V1A` / `V1C` | `T1S` / `T1A` / `T1C` |
| `veil-v0` transcript label | `tallow-v0` |
| `veil-v0/c2s`, `veil-v0/s2c` | `tallow-v0/c2s`, `tallow-v0/s2c` |
| DER SPKI (44 B) pubkeys on the wire | raw 32 B X25519 pubkeys |
| `veil-test/…` seeds | `tallow-test/…` seeds (`devkeys`) |

Cover bytes are unchanged (fidelity-anchored by test).

## Tests

- `cargo test` — battery-equivalent suite (`tests/battery.rs`, S0–S10):
  happy path + 50-frame echo integrity, transcript replay, tampered sig,
  stale ts, unknown/revoked device, forged server (client-side pin),
  cover-equality matrix 6/6, RBAC allow/deny + audit lines, key separation.
- `tests/loopback.rs` — real-socket happy path + cover scenarios.
- `tests/verify_v.rs` — VERITY V-series adversarial edges (length/timestamp
  boundaries incl. the 119 s in-window positive control; coalesced
  msg1+forged msg3; oversized-frame deadline; policy surface; the
  rx-counter-replay tripwire, now asserting rejection — flipped 2026-10-15
  when v1 hardening landed).
- `tests/daemon_smoke.rs` — drives the real `tallow-admissiond` binary:
  dev-registry minting, operator echo, RBAC deny, unknown-device cover,
  audit-file contents.
- `tests/mesh_client.rs` — end-to-end `tallow-mesh` MVP: the three rungs
  (direct · ssh guard+loopback · tor against a mock SOCKS5 proxy), rung
  unavailability stops announced (rc=1), unknown-device refusal (empty
  stdout), `keygen` 0600 + no-overwrite.

## Hardening status

**DONE (2026-10-15) — rx-counter monotonicity on `AeadChan::open`.** The
counter in a received frame must be strictly greater than the highest already
opened; anything else is refused with `AeadError::Replay` *before* decryption,
and a refused frame does not advance the high-water mark. Enforced in
`src/aead.rs`; the pre-fix behaviour is kept as an executable proof
(`proof_replay_is_processed_on_the_unfixed_code`) and the integration tripwire
`v6_v1_sealed_frame_replay_rejected` asserts the session now CLOSES on replay.

Policy: strictly increasing, no reordering window. This is a request/response
control plane over one reliable, ordered transport, so out-of-order delivery is
not expected; a window would add state and buy nothing here.

**DONE (2026-10-15) — total pre-auth deadline + pre-auth connection cap.**
`PRE_AUTH_TIMEOUT` is a per-*read* timeout, so a peer dribbling one byte per
interval reset it forever and held a connection — and its thread — open
indefinitely; `serve` also spawned an unbounded thread per accepted connection
with no accounting. Both are now bounded in `src/io.rs`:

- `PRE_AUTH_TOTAL` (= `CLIENT_DEADLINE`, 15 s) is fixed at accept time and
  clamps every pre-auth read via `next_read_timeout`. It applies to the
  **pre-auth phase only**: once `session.is_authenticated()` the connection
  reverts to `SESSION_IDLE_TIMEOUT` idle semantics, so long admitted sessions
  are never cut off.
- `MAX_PRE_AUTH_CONNECTIONS` (32) caps concurrent pre-auth connections. Over
  the cap the connection gets `cover()` and is closed, so a refusal is not
  distinguishable from ordinary traffic. Slots are held by an RAII guard
  (`PreAuthSlot`), so no exit path can leak one.

`next_read_timeout` is pure and clock-injected, so the deadline arithmetic is
unit-testable without sleeping. Pre-fix behaviour is kept as an executable
proof (`proof_drip_survives_the_total_budget_on_the_unfixed_arithmetic`).

## TODO (remaining v1 hardening — tracked for the deployed gate)

- Keepalive / idle policy inside authenticated sessions.
- Rate limiting per source (door-level, behind Caddy).
- Registry integration: back `DeviceRegistry` with the console device store
  (mint/revoke); production server keys from protected key files.
