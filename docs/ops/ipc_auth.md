# ipc_auth — authenticated IPC session handshake (B7.1.1–B7.1.3)

Model + gap check for mutual authentication between Tallow components that
exchange messages over a local transport (daemon, browser bridge, workers).
Source: `src/ipc_auth.rs` (pure model, no I/O).

## B7.1.1 — gap check: what IPC surfaces exist today (facts from the code read)

- **No authenticated handshake exists anywhere in `src/`.** The only literal
  `ipc` token in `src/` is the Chromium performance flag
  `--disable-ipc-flooding-protection` (`src/browser/process.rs:143`) — a
  browser flag, not an auth surface.
- **Browser bridge transports (unauthenticated):**
  - CDP over WebSocket: Chromium is launched with
    `--remote-debugging-port=<port>` (`src/browser/process.rs:304`); child
    stderr is parsed for the debug URL (`process.rs:426–427`). Access control
    is "loopback port", not authentication.
  - CDP over pipe: `--remote-debugging-pipe` (`process.rs:302`), with the two
    OS pipe ends handed to the child as fd 3/4 (`process.rs:447`, pipe
    creation `process.rs:597/662`). Authorization = fd inheritance only.
  - Firefox/Camoufox Juggler client rides the same pipe transport instead of
    WebSocket CDP (`src/browser/juggler.rs:477`). Same story.
- **Daemon surface (static bearer token):** `src/cli/daemon.rs`
  discovers `~/.tallow/daemon/port` + `~/.tallow/daemon/token` and talks
  HTTP to `http://127.0.0.1:<port>` (`src/cli/daemon.rs:7–25`). This gap
  check predates the wiring: the `ipc_auth` handshake now runs over this
  surface (see **Wire contract**), layered on top of the unchanged bearer
  flow.
- **Editor surface:** LSP is stdio JSON-RPC (`src/bin/tallow-lsp.rs:3`,
  `src/lsp.rs:13`) — trust comes from being the parent process.
- **In-process channels:** `src/agent_comm.rs` (SHA-256 CTR + MAC,
  `generate_channel_secret`, nonce‖ciphertext‖tag) is a message-auth
  primitive, but it is in-process (`Rc<RefCell<ChannelInner>>`), not a
  cross-process IPC handshake.
- **Not IPC:** `src/net/ip_pool.rs:100` `TcpListener` is outbound-egress
  tooling; `src/stdlib/ws.rs` handshake is an outbound WebSocket client.
- **Conclusion:** every inter-component path today is authenticated by
  transport locality or a static shared secret. Any new IPC path (daemon
  socket, bridge worker channel) needs exactly one added step — a mutual
  handshake — and that is what this module models.

## Wiring plan (where the handshake is called)

- **Accepting side** (daemon / bridge server), per connection, before any
  request is served: generate a nonce (`rand` 32 bytes → lowercase hex), send
  `Hello`; receive the peer's `Hello` back, compare transcripts. Own one
  `SeenNonces` for the listener's lifetime; call
  `Session::establish(psk, &hello, &initiator_proof, &responder_proof, now_ms,
  ttl_ms, &mut seen)` and keep the returned `Session` in per-connection state.
  Drop the connection on `Replayed`/`BadProof`; log `BadInput` as a
  programming error.
- **Initiating side** (worker/bridge client) after transport connect: build
  `hello()` with its own nonce, send `proof(psk, &h, Role::Initiator)`, verify
  the responder's proof with `verify(psk, &h, Role::Responder, ...)`.
- **Liveness**: before dispatching on an established connection, check
  `session.valid(now_ms)` (strict `<`); on expiry, tear down and re-handshake
  with a fresh nonce.
- **PSK source**: caller-owned (today: `~/.tallow/daemon/token`-style local
  file, root-readable). The module never reads it.
- **Wired (both halves) — B7.1.2 adoption:** the `daemon` client in
  `src/cli/daemon.rs` runs the initiator half once per invocation
  (`establish_audit_session`) and attaches `X-Tallow-Session: sess-<12 hex>` (or
  `none` when no session could be minted) to every authenticated request.
  The responder half runs in the daemon (`crates/tallow-daemon`,
  `POST /auth/handshake`): the client mints a session only when the daemon
  answers `200` with a `Hello` echoing the client's transcript and a
  responder proof that verifies against the same PSK — real mutual
  verification, nothing is completed locally. Exact headers and statuses:
  **Wire contract** below.

## Wire contract — `POST /auth/handshake` (frozen)

Client half: `src/cli/daemon.rs` (`establish_audit_session`). Responder half:
the daemon (`crates/tallow-daemon`). Both sides run the same pure model; only
the transport differs. Header values are lowercase hex.

Request (client → daemon):

- `POST {base_url}/auth/handshake` — `base_url` is
  `http://127.0.0.1:<port>` (from `~/.tallow/daemon/port`).
- `X-Tallow-Hello: <hex>` — hex of the UTF-8 JSON serialization of the
  initiator's `Hello` (serde wire form:
  `{"protocol":"tallow-ipc-auth-v1","initiator":"tallow-cli",
  "responder":"tallow-daemon","nonce":"<64 hex>"}`).
- `X-Tallow-Initiator: <hex>` — the initiator proof (64 lowercase hex
  characters) over the transcript, keyed by the daemon token as PSK.
- `Authorization: Bearer <token>` — the normal bearer credential rides
  along, so the route also passes the daemon's existing bearer middleware.

Response (daemon → client):

- `200 OK` — success, with headers:
  - `X-Tallow-Hello: <hex>` — the daemon's `Hello`, echoing the client's
    transcript (same initiator / responder / nonce).
  - `X-Tallow-Responder: <hex>` — the responder proof over that transcript.
- `401 Unauthorized` — replayed nonce or bad initiator proof.
- `400 Bad Request` — malformed input (non-hex or non-`Hello` header value).

Client fallback rules (honest downgrade — the request path never fails
because of the handshake):

- Empty token ⇒ no handshake is attempted; requests use
  `X-Tallow-Session: none`.
- Connection error, timeout (2 s), `404` (daemon predating the route), any
  non-`200` status, missing/malformed response headers, a daemon hello that
  does not echo the client's transcript, or a responder proof that does not
  verify ⇒ **no** session; requests still go out with
  `X-Tallow-Session: none`.
- Success ⇒ `Session::establish` re-verifies both proofs (constant time)
  and mints `sess-<12 hex>` (derived from the transcript + both proofs —
  the same value the daemon computes), attached as `X-Tallow-Session` on
  every authenticated request.
- **Daemon-side session validation:** the daemon registers each accepted
  session (id → expiry) and persists the registry to disk (tokens hashed at
  rest, file owner-only, `0600` in a `0700` dir); the registry is reloaded on
  restart, flushed at mint time, and swept periodically (expired records
  dropped). An authenticated request that
  presents an `X-Tallow-Session` value other than `none` must name a
  registered, unexpired session — otherwise `401`. `none`/absent stays
  allowed (pre-handshake compatibility; the bearer token still gates every
  route — the session header is the mutual handshake's audit artifact).

## Limits (read before relying on this)

- **Protocol MODEL, not an audited cryptographic implementation.** HMAC-SHA256
  over a transcript with a pre-shared key. Not Noise, not SPAKE2, not a
  reviewed protocol.
- **No forward secrecy, no key agreement**: the PSK is long-lived and static;
  compromise of the PSK retro-authenticates nothing but forges everything.
  PSK distribution/rotation is out of scope.
- **No channel binding**: the transcript does not bind the underlying socket
  /pipe/certificate, so a party that already relays the transport could relay
  a session (it cannot forge proofs without the PSK, but it can splice).
- **Replay guard is in-memory** (per `SeenNonces` owner) and not persisted
  across restarts; a restarted listener forgets consumed nonces. Nonce
  generation and clock (`now_ms`) are caller-supplied — the module never
  reads a clock and cannot detect a skewed one.
- **Wired (both halves)**: `pub mod ipc_auth` is in `src/lib.rs`; the client
  half (opening hello + initiator proof + session verification) lives in
  `src/cli/daemon.rs` and the responder half in the daemon
  (`crates/tallow-daemon`, `POST /auth/handshake`). The module itself stays
  pure — no I/O, no clock, no PSK handling; all of that lives with the
  callers.
