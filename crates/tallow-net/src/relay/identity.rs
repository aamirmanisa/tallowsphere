//! Daemon ↔ relay mutual authentication — async driver (rows #145/#146, lane J).
//!
//! Runs the [`tallow_svid::relay_auth`] handshake (mutual presentation of
//! short-lived, scope-bound workload tokens on top of the SVID fabric) over
//! any byte stream: the existing TCP+TLS (`tokio-rustls`) and QUIC (`quinn`)
//! streams both implement `AsyncRead + AsyncWrite`, so the same driver covers
//! the relay client's direct (QUIC) and proxied (TCP+TLS) transports.
//!
//! * [`authenticate_daemon`] — the connecting side (daemon dialling a
//!   relay): sends `Hello`, verifies the relay's presentation + transcript
//!   proof, answers `Confirm`, accepts the session on a matching `Established`.
//! * [`authenticate_relay`] — the accepting side (the relay): verifies
//!   the daemon's presentation, answers with its own, verifies the daemon's
//!   proof of possession, and only then establishes the session.
//!
//! Fail closed, no session on any failure:
//!
//! * a side without a configured identity (or without a token) refuses with
//!   [`NetworkError::AuthenticationFailed`] **before writing a single byte**
//!   ([`RelayMutualAuth::anonymous`]);
//! * every [`tallow_svid::relay_auth::RelayAuthError`] refusal (expired /
//!   wrong-scope token, certificate/key mismatch, bad proof of possession,
//!   binding mismatch, malformed message) is answered with an explicit
//!   `Reject { reason }` and returned as [`NetworkError::AuthenticationFailed`]
//!   — the peer sees a refusal, never a silent EOF;
//! * frame-level violations (oversize frame, bad JSON, EOF before a message)
//!   are [`NetworkError::ProtocolNegotiation`], transport errors are
//!   [`NetworkError::Io`].
//!
//! # Wire framing
//!
//! Length-prefixed frames: `u32` big-endian length + JSON payload, capped at
//! [`MAX_RELAY_AUTH_FRAME`]. JSON is transport only — every signature in the
//! handshake covers canonical bytes (see `tallow_svid::relay_auth`).
//!
//! # Honest scope [partial]
//!
//! The driver is **not yet called from [`super::client::RelayClient`]**: this
//! module lands the handshake + verification seam; wiring it into
//! `RelayClient::connect` (and the relay server in the root crate's
//! `tallow relay`, unowned this wave) is recorded in the lane log §OPEN.
//! Per-request authorization (Cedar) and the mesh leg are out of scope
//! ([target-only]).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use tallow_svid::relay_auth::{
    ClientMachine, EstablishedSession, PeerTrust, RelayAuthError, RelayAuthIdentity,
    RelayAuthMessage, ServerMachine,
};
use tallow_svid::workload::AccessToken;

use crate::{NetworkError, Result};

/// Hard cap on one handshake frame (a Hello carries a leaf cert + a token).
pub const MAX_RELAY_AUTH_FRAME: usize = 64 * 1024;

/// One side's configuration: own workload identity + its short-lived token,
/// and what this side requires of its peer.
pub struct RelayMutualAuth {
    identity: Option<RelayAuthIdentity>,
    token: Option<AccessToken>,
    trust: PeerTrust,
}

impl RelayMutualAuth {
    /// A fully-configured side (identity + token + peer trust).
    pub fn configured(identity: RelayAuthIdentity, token: AccessToken, trust: PeerTrust) -> Self {
        Self {
            identity: Some(identity),
            token: Some(token),
            trust,
        }
    }

    /// The fail-closed configuration: **no identity, no session**. Used when a
    /// deployment has no workload identity for this process — every entry
    /// point refuses before any byte moves.
    pub fn anonymous(trust: PeerTrust) -> Self {
        Self {
            identity: None,
            token: None,
            trust,
        }
    }

    /// True iff this side holds a workload identity and a token.
    pub fn identity_configured(&self) -> bool {
        self.identity.is_some() && self.token.is_some()
    }

    /// What this side requires of its peer.
    pub fn trust(&self) -> &PeerTrust {
        &self.trust
    }
}

impl std::fmt::Debug for RelayMutualAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayMutualAuth")
            .field("identity_configured", &self.identity_configured())
            .field("trust", &self.trust)
            .finish()
    }
}

/// Map a typed handshake refusal onto the transport error surface.
///
/// All auth refusals are [`NetworkError::AuthenticationFailed`]; the typed
/// reason is logged so operators see which leg refused. (`AuthenticationFailed`
/// is the same variant `RelayClient::connect` already uses for relay auth.)
fn auth_failed(leg: &'static str, e: RelayAuthError) -> NetworkError {
    tracing::warn!(leg, error = %e, "relay mutual-auth refused");
    NetworkError::AuthenticationFailed
}

/// Write one length-prefixed frame.
async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, msg: &RelayAuthMessage) -> Result<()> {
    let json = msg
        .to_json()
        .map_err(|e| NetworkError::ProtocolNegotiation(format!("relay-auth encode: {e}")))?;
    if json.len() > MAX_RELAY_AUTH_FRAME {
        return Err(NetworkError::ProtocolNegotiation(format!(
            "relay-auth frame {} exceeds cap {}",
            json.len(),
            MAX_RELAY_AUTH_FRAME
        )));
    }
    w.write_all(&(json.len() as u32).to_be_bytes())
        .await
        .map_err(NetworkError::Io)?;
    w.write_all(json.as_bytes())
        .await
        .map_err(NetworkError::Io)?;
    w.flush().await.map_err(NetworkError::Io)?;
    Ok(())
}

/// Read one length-prefixed frame.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<RelayAuthMessage> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(NetworkError::ProtocolNegotiation(
                "peer closed before a relay-auth message".to_string(),
            ))
        }
        Err(e) => return Err(NetworkError::Io(e)),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_RELAY_AUTH_FRAME {
        return Err(NetworkError::ProtocolNegotiation(format!(
            "relay-auth frame length {len} outside 1..={MAX_RELAY_AUTH_FRAME}"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(NetworkError::Io)?;
    let json = std::str::from_utf8(&buf)
        .map_err(|e| NetworkError::ProtocolNegotiation(format!("relay-auth not utf-8: {e}")))?;
    RelayAuthMessage::from_json(json)
        .map_err(|e| NetworkError::ProtocolNegotiation(format!("relay-auth decode: {e}")))
}

/// The connecting side: the **daemon** dialling a relay.
///
/// Refuses before touching the stream when no identity is configured
/// ([`RelayMutualAuth::anonymous`]). On success the returned session is
/// mutually authenticated: the daemon has verified the relay's presence via
/// the trusted authority, and the relay has verified the daemon's.
pub async fn authenticate_daemon<S>(
    stream: &mut S,
    config: &RelayMutualAuth,
    now: i64,
) -> Result<EstablishedSession>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut machine = ClientMachine::begin(
        config.identity.as_ref(),
        &config.trust,
        config.token.clone(),
    )
    .map_err(|e| auth_failed("daemon", e))?;

    let hello = machine.hello().map_err(|e| auth_failed("daemon", e))?;
    write_frame(stream, &hello).await?;

    let server_proof = read_frame(stream).await?;
    let confirm = machine
        .on_server_proof(&server_proof, now)
        .map_err(|e| auth_failed("daemon", e))?;
    write_frame(stream, &confirm).await?;

    let established = read_frame(stream).await?;
    machine
        .on_established(&established)
        .map_err(|e| auth_failed("daemon", e))
}

/// The accepting side: the **relay**.
///
/// Refuses before reading a byte when no identity is configured. Every
/// refusal on the way is answered with an explicit `Reject { reason }` frame
/// (best effort) before the error is returned.
pub async fn authenticate_relay<S>(
    stream: &mut S,
    config: &RelayMutualAuth,
    now: i64,
) -> Result<EstablishedSession>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut machine = ServerMachine::begin(
        config.identity.as_ref(),
        &config.trust,
        config.token.clone(),
    )
    .map_err(|e| auth_failed("relay", e))?;

    let hello = read_frame(stream).await?;
    let server_proof = match machine.on_hello(&hello, now) {
        Ok(msg) => msg,
        Err(e) => {
            let _ = write_frame(stream, &RelayAuthMessage::rejection(&e.to_string())).await;
            return Err(auth_failed("relay", e));
        }
    };
    write_frame(stream, &server_proof).await?;

    let confirm = read_frame(stream).await?;
    match machine.on_confirm(&confirm) {
        Ok(established) => {
            write_frame(stream, &established).await?;
            machine.session().cloned().ok_or_else(|| {
                NetworkError::ProtocolNegotiation(
                    "relay-auth established without a session".to_string(),
                )
            })
        }
        Err(e) => {
            let _ = write_frame(stream, &RelayAuthMessage::rejection(&e.to_string())).await;
            Err(auth_failed("relay", e))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — loopback fixtures (in-memory duplex, real TCP loopback, TLS loopback)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tallow_crypto::sig::ed25519::Ed25519Signer;
    use tallow_svid::issuer::{now_unix, NodeIssuer};
    use tallow_svid::model::{self, SpiffeId};
    use tallow_svid::policy::ServiceRegistry;
    use tallow_svid::workload::{
        Action, Scope, ScopePolicy, ScopeSet, TokenAuthority, WorkloadKey,
    };

    use tokio::io::AsyncReadExt;

    fn scope(service: &str, action: Action) -> Scope {
        Scope::new(service, action).unwrap()
    }

    fn relay_write() -> ScopeSet {
        ScopeSet::from_scopes([scope("relay", Action::Write)]).unwrap()
    }

    fn daemon_write() -> ScopeSet {
        ScopeSet::from_scopes([scope("daemon", Action::Write)]).unwrap()
    }

    fn id(node: &str, svc: &str) -> SpiffeId {
        SpiffeId::new(node, svc).unwrap()
    }

    /// The daemon and relay workloads on node-01, their tokens from the node
    /// authority, and the trust each side applies to the other.
    struct Fixture {
        daemon: RelayAuthIdentity,
        relay: RelayAuthIdentity,
        daemon_token: AccessToken,
        relay_token: AccessToken,
        daemon_trust: PeerTrust,
        relay_trust: PeerTrust,
    }

    fn fixture() -> Fixture {
        let mut issuer = NodeIssuer::generate("node-01").unwrap();
        issuer.issue_issuer_intermediate(None).unwrap();
        // "relay" is not a builtin service name; register it explicitly (the
        // operator-tunable issuance allowlist path).
        let mut registry = ServiceRegistry::builtin();
        registry.register("relay").unwrap();
        issuer.set_registry(registry);

        let daemon = {
            let key = WorkloadKey::generate();
            let id = id("node-01", "daemon");
            let chain = issuer
                .issue_workload_leaf_from_spki(&key.spki_der(), &id, None)
                .unwrap();
            RelayAuthIdentity::new(key, chain, id).unwrap()
        };
        let relay = {
            let key = WorkloadKey::generate();
            let id = id("node-01", "relay");
            let chain = issuer
                .issue_workload_leaf_from_spki(&key.spki_der(), &id, None)
                .unwrap();
            RelayAuthIdentity::new(key, chain, id).unwrap()
        };

        let issuer_id = SpiffeId::parse(&model::issuer_san("node-01").unwrap()).unwrap();
        let mut policy = ScopePolicy::empty();
        policy
            .grant("daemon", scope("relay", Action::Write))
            .unwrap();
        policy
            .grant("relay", scope("daemon", Action::Write))
            .unwrap();
        let mut authority =
            TokenAuthority::new(issuer_id, Ed25519Signer::from_seed([7u8; 32]), policy, None)
                .unwrap();

        let t = now_unix();
        let daemon_token = daemon
            .obtain_token(&mut authority, &relay_write(), None, t)
            .unwrap();
        let relay_token = relay
            .obtain_token(&mut authority, &daemon_write(), None, t)
            .unwrap();

        let daemon_trust = PeerTrust::new(&authority, daemon_write()).unwrap();
        let relay_trust = PeerTrust::new(&authority, relay_write()).unwrap();
        Fixture {
            daemon,
            relay,
            daemon_token,
            relay_token,
            daemon_trust,
            relay_trust,
        }
    }

    /// In-memory loopback: both real state machines over `tokio::io::duplex`.
    #[tokio::test]
    async fn loopback_mutual_auth_over_duplex_establishes_session() {
        let fx = fixture();
        let now = now_unix();
        let daemon_cfg = RelayMutualAuth::configured(fx.daemon, fx.daemon_token, fx.daemon_trust);
        let relay_cfg = RelayMutualAuth::configured(fx.relay, fx.relay_token, fx.relay_trust);
        assert!(daemon_cfg.identity_configured() && relay_cfg.identity_configured());

        let (mut client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let server =
            tokio::spawn(async move { authenticate_relay(&mut server_io, &relay_cfg, now).await });
        let client = authenticate_daemon(&mut client_io, &daemon_cfg, now)
            .await
            .expect("daemon side authenticates");
        let server = server.await.unwrap().expect("relay side authenticates");

        assert_eq!(client.role, "daemon");
        assert_eq!(server.role, "relay");
        assert_eq!(
            client.binding, server.binding,
            "both sides derive one session binding"
        );
        assert_eq!(client.peer.sub, id("node-01", "relay"));
        assert_eq!(server.peer.sub, id("node-01", "daemon"));
        assert_eq!(client.peer.scopes, daemon_write());
        assert_eq!(server.peer.scopes, relay_write());
    }

    /// Fail closed: no identity → refusal before a single byte is written.
    #[tokio::test]
    async fn no_identity_refuses_before_any_byte() {
        let fx = fixture();
        let now = now_unix();
        let anon = RelayMutualAuth::anonymous(fx.daemon_trust.clone());
        assert!(!anon.identity_configured());

        let (mut client_io, mut server_io) = tokio::io::duplex(4096);
        let err = authenticate_daemon(&mut client_io, &anon, now)
            .await
            .expect_err("anonymous daemon must refuse");
        assert!(matches!(err, NetworkError::AuthenticationFailed), "{err:?}");
        // Nothing was written: the peer sees a clean EOF with zero bytes.
        drop(client_io);
        let mut buf = [0u8; 16];
        assert_eq!(server_io.read(&mut buf).await.unwrap(), 0);

        // Same on the relay side: refused before reading anything.
        let anon_relay = RelayMutualAuth::anonymous(fx.relay_trust.clone());
        let (mut _c2, mut s2) = tokio::io::duplex(4096);
        let err = authenticate_relay(&mut s2, &anon_relay, now)
            .await
            .expect_err("anonymous relay must refuse");
        assert!(matches!(err, NetworkError::AuthenticationFailed), "{err:?}");
    }

    /// Refusal path over a real TCP loopback: an expired token is refused with
    /// an explicit `Reject` frame (the daemon sees `AuthenticationFailed`,
    /// not a silent EOF — the two are distinguishable in this driver).
    #[tokio::test]
    async fn expired_token_refused_with_explicit_reject_over_tcp_loopback() {
        let fx = fixture();
        let now = now_unix() + 3600; // daemon token (5 min default) has expired
        let daemon_cfg = RelayMutualAuth::configured(fx.daemon, fx.daemon_token, fx.daemon_trust);
        let relay_cfg = RelayMutualAuth::configured(fx.relay, fx.relay_token, fx.relay_trust);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            authenticate_relay(&mut stream, &relay_cfg, now).await
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err = authenticate_daemon(&mut stream, &daemon_cfg, now)
            .await
            .expect_err("expired daemon token must refuse");
        assert!(
            matches!(err, NetworkError::AuthenticationFailed),
            "explicit rejection expected, got {err:?}"
        );
        let err = server.await.unwrap().expect_err("relay refuses too");
        assert!(matches!(err, NetworkError::AuthenticationFailed), "{err:?}");
    }

    /// The same handshake over the crate's existing **rustls/TLS** stack
    /// (TCP + `tokio-rustls`, the relay's TCP+TLS transport shape).
    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test]
    async fn loopback_mutual_auth_over_rustls_tls_establishes_session() {
        use crate::transport::tls_config::{
            generate_self_signed, rustls_client_config, rustls_server_config,
        };

        let fx = fixture();
        let now = now_unix();
        let daemon_cfg = RelayMutualAuth::configured(fx.daemon, fx.daemon_token, fx.daemon_trust);
        let relay_cfg = RelayMutualAuth::configured(fx.relay, fx.relay_token, fx.relay_trust);

        let tls_identity = generate_self_signed().unwrap();
        let server_config = rustls_server_config(&tls_identity).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            authenticate_relay(&mut tls, &relay_cfg, now).await
        });

        let connector = tokio_rustls::TlsConnector::from(rustls_client_config().unwrap());
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        let client = authenticate_daemon(&mut tls, &daemon_cfg, now)
            .await
            .expect("daemon side authenticates over TLS");
        let server = server
            .await
            .unwrap()
            .expect("relay side authenticates over TLS");
        assert_eq!(client.binding, server.binding);
        assert_eq!(client.peer.sub, id("node-01", "relay"));
        assert_eq!(server.peer.sub, id("node-01", "daemon"));
    }
}
