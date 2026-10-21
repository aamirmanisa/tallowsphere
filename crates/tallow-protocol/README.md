<div align="center">

# tallow-protocol

**Wire format, transfer pipeline and room semantics in one place — the part that must stay compatible when everything above it changes.**

![wire](https://img.shields.io/badge/wire-v9%20(min%20v4)-1f6feb?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-2ea44f?style=flat-square)

</div>

---

A transfer protocol fails in the boring places: a resumed download that starts two bytes off, a manifest that disagrees with the file it describes, a compression pipeline that picks the wrong codec for incompressible data. This crate is where those decisions are made once, with tests, instead of in every caller.

## What it is

| Module | Responsibility |
|---|---|
| `wire` | Message enum, codec, capability negotiation, version handshake (v9, minimum v4) |
| `transfer` | Manifest, chunking, send/receive state machine, resume, journal, queue, exclusion rules, watch, relay transfer |
| `compression` | zstd, lzma, brotli, lz4 behind an analysis step that can decline to compress |
| `room` | Room codes, roles, manager |
| `chat` | Message format, per-room encryption, session |
| `kex` | Key exchange available to both native and WASM builds |
| `pq_handshake` | Post-quantum handshake |
| `multi` | Per-peer key derivation and nonce tracking for multi-peer sessions |
| `metadata` | Filename sanitisation and metadata stripping |
| `mode_auth` | Mode authorisation |

Two feature sets shape what is compiled: `full` (default) pulls the native dependencies, `wasm` builds the browser-compatible subset — wire messages, key exchange, room codes — without tokio or compression.

## What it is not

- **Not an application protocol for the internet at large.** It assumes two Tallow peers that have already established keys; it does not define discovery or routing.
- **Not a filesystem.** `transfer` describes and verifies a transfer; writing bytes to disk belongs to the caller.
- **Not backwards-compatible forever.** The version handshake accepts v4 through v9 and refuses anything outside that. An old peer gets a clean refusal, not a corrupted transfer.

## Quick start

### Messages

```rust
use tallow_protocol::wire::{Message, TallowCodec};

let mut codec = TallowCodec::new();
let mut buf = bytes::BytesMut::new();
codec.encode_msg(&Message::VersionRequest { supported_versions: vec![9] }, &mut buf)?;
let decoded = codec.decode_msg(&mut buf)?;
```

### Compression that declines

```rust
use tallow_protocol::compression::analysis;

// Decide before spending CPU: already-compressed input is passed through.
if analysis::is_compressible(&payload) {
    // choose a codec and encode
}
```

### Version negotiation

```rust
use tallow_protocol::wire::version::PROTOCOL_VERSION;

assert_eq!(PROTOCOL_VERSION, 9);
```

A peer older than the minimum is refused during the handshake. There is no "best effort" path, because a partially-understood message is worse than no message.

## Configuration

The crate reads no environment variables. Behaviour is selected by feature flags and by explicit structs:

| Feature | Enables | Default |
|---|---|---|
| `full` | tokio, compression codecs, file watching, relay transfer | yes |
| `wasm` | Browser-compatible subset (wire, kex, room) | no |
| `dev-insecure` | Self-signed relay certificates for dev lanes | **never in release** |

## Deploying it

Embedded in the transfer stack:

```toml
[dependencies]
tallow-protocol = { path = "crates/tallow-protocol" }
```

Rules that come from how the protocol behaves rather than from taste:

- **Upgrade both ends together.** The version handshake prevents a broken transfer, but it cannot invent compatibility.
- **Keep the journal.** `transfer::journal` is what makes a resume safe after a crash; discarding it turns resume into a guess.
- **Do not disable the manifest hash.** It is the only thing that ties a received file to the file that was sent.

## Verification

```console
$ cargo test -p tallow-protocol
$ cargo test -p tallow-protocol transfer -- --nocapture
$ cargo test -p tallow-protocol wire -- --nocapture
$ cargo build -p tallow-protocol --no-default-features --features wasm
```

326 test functions in the crate source [measured 2026-10-21]. The WASM build is a separate gate: it must compile without tokio, and it does.

## Limits

| Limit | Detail |
|---|---|
| Resume granularity | Chunk-level, not byte-level; a chunk is re-sent whole |
| Compression heuristics | Analysis is sampling-based; it can pick a suboptimal codec on mixed data, never a lossy one |
| Room scale | Designed for small groups; there is no gossip or large-room fan-out |
| Wire compatibility | v4–v9 only |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
