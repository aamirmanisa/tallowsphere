<div align="center">

# tallow-admission

**A door that cannot be told apart from a wall.**

![cover](https://img.shields.io/badge/cover-260%20bytes%2C%20byte--identical-1f6feb?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-2ea44f?style=flat-square)

</div>

---

Every authenticated service leaks the same fact: something is there. A port that answers differently to a wrong key than to a wrong path tells an observer which is which, and that difference is enough to map a private network from the outside.

This crate is the admission handshake for the Tallow mesh door, built so that **every unauthenticated outcome looks like an ordinary web server answering a path that does not exist** — same bytes, same length, same timing shape.

## What it is

1. **Authenticated device admission.** X25519 ephemeral ECDH mixed against a pinned server static key; Ed25519 device identity; transcript binding; timestamp freshness; HKDF-derived directional AEAD keys (ChaCha20-Poly1305).
2. **Probe indistinguishability.** Garbage, HTTP probes, silent lingerers, unknown or revoked devices, tampered handshakes, stale timestamps, replays — all receive the same 260-byte cover response, byte-identical to an ordinary 404. Its digest is a constant in the crate: `cover::COVER_SHA256_HEX`.

The protocol is a pair of pure state machines. `ServerSession` and `ClientSession` consume bytes and emit `Action`s (`Write`, `Cover`, `Close`) — there is no I/O inside them, which is what makes the adversarial matrix testable without sockets.

## What it is not

- **Not a TLS replacement.** It runs *behind* a terminable proxy (Caddy in the reference deployment); TLS is terminated at the edge and admission decides who gets past it.
- **Not a general authentication framework.** One device identity, one role, one registry. There is no OAuth, no session store, no password reset.
- **Not invisibility.** It defeats probing and enumeration of the door. It does not hide that the host exists, nor does it claim to.

## Quick start

### As a library

```rust
use tallow_admission::server::{ServerCore, StaticRegistry};
use tallow_admission::{cover, COVER_LEN};

// The cover is a constant, not a computed response.
assert_eq!(cover().len(), COVER_LEN);
```

### The loopback daemon

```console
$ cargo run -p tallow-admission --bin tallow-admissiond -- \
    --registry dev-registry.json --listen 127.0.0.1:9410
```

```
--print-dev-registry   print the deterministic dev device registry (JSON), exit
--print-dev-server     print the deterministic dev server public keys (JSON), exit
--listen <addr>        bind address (default 127.0.0.1:9410)
--registry <path>      device registry JSON (required)
--server-key <path>    server key material {ed_seed_hex, x_seed_hex}
--audit <path|->       audit destination (default: - = stdout)
--allow-non-loopback   permit a non-loopback bind (default: refuse)
```

The daemon refuses a non-loopback bind unless you say otherwise. That default is deliberate: an admission surface on a public interface is a surface someone will probe, and the operator should have decided that explicitly.

### The operator client

```console
$ tallow-mesh keygen --out device.json          # 0600, refuses to overwrite
$ tallow-mesh call --act status --rung tor --host 127.0.0.1 --port 9410 --device-key device.json
```

Rungs are announced, never guessed: `direct`, `ssh` (forwarded on loopback), `tor` (via SOCKS5). If the requested rung is unavailable, the client stops and says so (`rc=1`) rather than silently falling back to a path the operator did not choose.

## Configuration

| Variable | Effect | Default |
|---|---|---|
| `TALLOW_ADMISSION_RATE_BURST` | Token-bucket burst per source | 20 |
| `TALLOW_ADMISSION_RATE_REFILL` | Tokens per second | 10 |

Constants that are deliberately not configurable:

| Constant | Value | Why |
|---|---|---|
| `PRE_AUTH_TOTAL` | 15 s | A per-read timeout is not a deadline; a peer dribbling one byte per interval would hold a thread forever |
| `MAX_PRE_AUTH_CONNECTIONS` | 32 | Over the cap the connection gets cover bytes and closes — indistinguishable from traffic |
| `SESSION_IDLE_TIMEOUT` | 30 s | An authenticated session that goes silent is closed; `{"act":"ping"}` keeps it open |
| Rate-limit map | 4,096 sources | Bounded, pruned only when buckets refill to full |

**Deployment note.** Behind a terminating proxy every peer looks like the proxy, so the per-source bucket degenerates into a global rate. Either size the budget for that or terminate admission at the edge.

## Deploying it

The reference shape is: TLS terminated by Caddy, `tallow-admissiond` bound to loopback, real key material loaded from protected files.

```ini
# /etc/systemd/system/tallow-admissiond.service
[Unit]
Description=Tallow mesh-door admission
After=network-online.target

[Service]
ExecStart=/usr/local/bin/tallow-admissiond \
  --listen 127.0.0.1:9410 \
  --registry /var/lib/tallow/registry.json \
  --server-key /etc/tallow/server-key.json \
  --audit /var/log/tallow/admission.jsonl
User=tallow
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Run it as an unprivileged user with a read-only filesystem apart from the registry and log paths. The daemon runs on deterministic **dev** keys, with a loud warning, when `--server-key` is absent — that is for rehearsal only; a production door must load real material or the pin means nothing.

## Design notes

**Why a constant cover rather than a generated 404.** A generated response varies with the request — headers, body length, timing. A constant is the only shape that is provably identical for every refusal, and a digest test locks it.

**Why the rx-counter rule is strict.** Frames must arrive strictly increasing; out-of-order delivery is refused *before* decryption and does not advance the high-water mark. The control plane runs over one reliable ordered transport, so a reordering window would add state and buy nothing.

**Why the total deadline, not an idle timeout.** The pre-auth phase has one fixed budget computed at accept time. Once authenticated, the connection switches to idle semantics so long sessions are never cut off mid-operation.

**Why pre-fix behaviour is kept as a test.** Two adversarial properties — drip-fed pre-auth connections and counter replay — are preserved as executable proofs of the *unfixed* code beside the tripwires that assert the fixed behaviour. A regression that reverts the fix fails the tripwire, not a comment.

## Verification

```console
$ cargo test -p tallow-admission
$ cargo test -p tallow-admission --test battery -- --nocapture
$ cargo test -p tallow-admission --test verify_v -- --nocapture
$ cargo test -p tallow-admission --test daemon_smoke -- --nocapture
```

26 test functions in the crate source [measured 2026-10-21], plus the integration batteries:

| Suite | Covers |
|---|---|
| `tests/battery.rs` | S0–S10: happy path, 50-frame echo integrity, transcript replay, tampered signature, stale timestamp, unknown/revoked device, forged server (client-side pin), cover-equality matrix 6/6, RBAC, key separation |
| `tests/loopback.rs` | Real sockets, happy path and cover scenarios |
| `tests/verify_v.rs` | Length and timestamp boundaries (including the 119 s in-window control), coalesced forged messages, oversized-frame deadline, replay tripwire |
| `tests/daemon_smoke.rs` | The real daemon binary: minting, echo, RBAC deny, unknown-device cover, audit contents |
| `tests/mesh_client.rs` | All three rungs, unavailable-rung refusal, `keygen` permissions |

## Limits

| Limit | Detail |
|---|---|
| Registry integration | `StaticRegistry` + file loading today; backing it with a live device store is the deployed-gate work |
| No key rotation | Server identity is a file; rotating it means redistributing the pin |
| One process per door | No clustering or shared session state |
| Cover is HTTP-404 shaped | A network that expects a different server personality needs its own cover, which is a wire change by design |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
