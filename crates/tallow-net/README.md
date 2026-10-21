<div align="center">

# tallow-net

**The transport ladder: QUIC first, TCP+TLS when that fails, a relay when neither can reach — each rung able to run through Tor or a SOCKS proxy.**

![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-2ea44f?style=flat-square)
![transport](https://img.shields.io/badge/transport-QUIC%20%C2%B7%20TCP%2BTLS%20%C2%B7%20relay-1f6feb?style=flat-square)

</div>

---

Two peers on the modern internet rarely have a clean path between them. One is behind CGNAT, one is on a network that blocks UDP, both want the traffic to look ordinary. `tallow-net` is the layer that keeps trying until something works, and says exactly which rung it used when it does.

## What it is

| Layer | What it provides |
|---|---|
| **Transport** | QUIC (primary), TCP+TLS (fallback), `FallbackTransport` that tries QUIC then falls back automatically |
| **Framing** | Length-prefixed messages — `[4-byte BE length][payload]` — identical across rungs |
| **NAT traversal** | STUN, TURN, UPnP, hole punching, candidate gathering and detection |
| **Discovery** | mDNS / DNS-SD on the local network |
| **Relay** | Relay client with password v2 hashing, mutual authentication, peer presence tracking |
| **Privacy** | SOCKS5 connector (including Tor's `IsolateSOCKSAuth`), Tor control port, DNS-over-HTTPS, traffic-analysis padding |
| **Proxied paths** | A TCP+TLS transport and tunnel that run through an HTTP/SOCKS proxy |
| **Identity** | SPKI pinning, TLS server-name validation, ECH support |

The public surface is a small trait plus concrete implementations:

```rust
pub trait Transport: Send + Sync {
    async fn connect(&mut self, addr: SocketAddr) -> Result<()>;
    async fn send(&mut self, data: &[u8]) -> Result<usize>;
    // recv / close …
}
```

`PeerChannel` is the narrower abstraction the transfer pipeline uses — `send_message` / `receive_message` / `close` — so a relay connection and a direct LAN connection are interchangeable above this line.

## What it is not

- **Not a VPN.** It moves Tallow's own frames; it does not tunnel arbitrary IP.
- **Not anonymity by itself.** This crate can *use* Tor and can pad traffic; whether a given path is anonymous is a property of the whole route, and the crate never claims more than the rung it reports.
- **Not a certificate authority.** TLS validation is CA-based by default; the `dangerous_skip_verify` feature exists for dev lanes and must never be enabled in a release build.

## Quick start

### A direct TCP+TLS connection

```rust
use tallow_net::transport::TcpTlsTransport;
use tallow_net::transport::Transport;

let mut t = TcpTlsTransport::new();
t.connect("203.0.113.10:4433".parse()?).await?;
t.send(b"hello").await?;
```

### Through Tor

```rust
use tallow_net::privacy::socks5::ProxyConfig;

let proxy = ProxyConfig::tor_default();          // socks5://127.0.0.1:9050
let connector = proxy.to_connector();
```

Tor's SOCKS port supports `IsolateSOCKSAuth`: distinct credentials produce distinct circuits. Use it when two connections must not share a circuit — a single shared credential means a single shared exit.

### Relay with a named server

```rust
use tallow_net::relay::client::RelayClient;

let mut relay = RelayClient::new_with_name(
    "relay.example.net:4433".parse()?,
    Some("relay.example.net".to_string()),
);
relay.connect().await?;
```

The server name matters: certificates are validated against the name actually dialed, not against a bare IP.

## Configuration

| Variable | Effect | Default |
|---|---|---|
| `TALLOW_RELAY_SPKI_PIN` | Pins the relay's TLS public key (SPKI) instead of trusting the CA chain for that host | unset |
| `HOME` / `LOCALAPPDATA` | Locates the Tor control cookie/auth file for `privacy::tor_control` | OS default |
| `HOSTNAME` / `COMPUTERNAME` | Instance name advertised over mDNS | OS hostname |

The two rules that are not configurable, on purpose:

- **No silent downgrade.** `FallbackTransport` reports which rung is active (`ActiveTransport`); a caller can refuse a fallback rather than accept one it did not expect.
- **No verification bypass.** `dangerous_skip_verify` is not in `default`; enabling it is an explicit, reviewable act.

## Deploying it

Library only — no daemon and no listening service. In production it is embedded in the transfer stack and in `tallow-daemon`:

```toml
[dependencies]
tallow-net = { path = "crates/tallow-net" }
```

Operational notes that matter in the field:

- **UDP must be permitted for QUIC.** A network that drops UDP silently gets the TCP+TLS rung, which is slower and more visible on the wire.
- **NAT traversal needs a STUN server you trust.** Point at your own; the public ones are rate-limited and log.
- **Pin the relay.** With a pinned SPKI, a compromised CA cannot redirect a relay connection.
- **Set a Tor circuit per task** when identity separation matters; sharing one `socks5://127.0.0.1:9050` across tasks gives every task the same exit.

## Verification

```console
$ cargo test -p tallow-net
$ cargo test -p tallow-net relay -- --nocapture
$ cargo test -p tallow-net privacy -- --nocapture
```

206 test functions in the crate source [measured 2026-10-21], including relay password-v2 vectors, SPKI pin behaviour, and fallback selection.

## Limits

| Limit | Detail |
|---|---|
| No IPv6-only networks | Address handling assumes a usable IPv4 path today |
| TURN support is client-side | It can use a TURN server; it does not implement one |
| No connection migration | A QUIC path change (Wi-Fi → cellular) requires reconnect |
| ECH depends on the peer | The client sends it; a server that ignores it falls back to plain SNI |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
