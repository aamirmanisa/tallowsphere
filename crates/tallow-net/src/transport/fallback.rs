//! Fallback transport: QUIC-first with TCP+TLS fallback — **policy-aware**.
//!
//! Tries to connect via QUIC. If that fails (e.g., corporate firewall blocking
//! UDP), falls back to TCP+TLS automatically — but only when the egress route
//! permits it.
//!
//! R-08 batch-3 (rows #131/#132 / design P4-3): the previous implementation
//! fell back to a *direct* TCP+TLS connection unconditionally, which silently
//! bypasses a configured SOCKS5/Tor route. Now:
//!
//! * [`TransportRoute::Direct`] `{ allow_direct_udp: true }` — legacy behavior:
//!   QUIC first, direct TCP+TLS on failure (the direct-UDP opt-in is explicit;
//!   see `negotiation.rs`).
//! * [`TransportRoute::Direct`] `{ allow_direct_udp: false }` — TCP+TLS direct
//!   directly; QUIC is never attempted (no default direct-UDP preference).
//! * [`TransportRoute::Proxied`] — **refuses**: this transport only ever opens
//!   direct sockets, and connecting direct would bypass the proxy. Callers on a
//!   proxied route must use `ProxiedTcpTlsTransport` (the SOCKS5+TLS path).
//!   `NetworkError::PolicyDenied` — never a silent direct fallback.

use crate::transport::negotiation::TransportRoute;
use crate::{NetworkError, Result, Transport};
use std::net::SocketAddr;
use tracing::{info, warn};

/// Active transport type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTransport {
    /// Connected via QUIC
    Quic,
    /// Connected via TCP+TLS
    TcpTls,
    /// Not yet connected
    None,
}

/// Transport that tries QUIC first (when the route permits), falling back to
/// TCP+TLS — under the configured egress route.
pub struct FallbackTransport {
    #[cfg(feature = "quic")]
    quic: super::quic::QuicTransport,
    tcp_tls: super::tcp_tls::TcpTlsTransport,
    active: ActiveTransport,
    /// Egress route this transport must honor.
    route: TransportRoute,
}

impl std::fmt::Debug for FallbackTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackTransport")
            .field("active", &self.active)
            .field("route", &self.route.label())
            .finish()
    }
}

impl FallbackTransport {
    /// Create a new fallback transport with the legacy direct route
    /// (QUIC-first, direct TCP+TLS fallback).
    ///
    /// NOTE (P4-3 operator line): QUIC-first is only appropriate under an
    /// explicit direct-UDP opt-in; policy-resolved callers should construct
    /// with [`FallbackTransport::with_policy`] instead of relying on this.
    pub fn new() -> Self {
        Self::with_policy(TransportRoute::direct(true))
    }

    /// Create a fallback transport bound to an egress route.
    pub fn with_policy(route: TransportRoute) -> Self {
        Self {
            #[cfg(feature = "quic")]
            quic: super::quic::QuicTransport::new(),
            tcp_tls: super::tcp_tls::TcpTlsTransport::new(),
            active: ActiveTransport::None,
            route,
        }
    }

    /// The egress route this transport honors.
    pub fn route(&self) -> TransportRoute {
        self.route
    }

    /// Get the currently active transport type
    pub fn active_transport(&self) -> ActiveTransport {
        self.active
    }

    /// Connect to `addr` under the configured route.
    ///
    /// Refuses (fail-closed) on a proxied route: this transport cannot route
    /// through SOCKS5, and a direct connection would bypass the proxy.
    pub async fn connect_peer(&mut self, addr: SocketAddr) -> Result<ActiveTransport> {
        #[cfg(feature = "quic")]
        {
            let FallbackTransport {
                quic,
                tcp_tls,
                active,
                route,
            } = self;
            let attempt = quic.connect(addr);
            connect_inner(*route, addr, tcp_tls, active, attempt).await
        }
        #[cfg(not(feature = "quic"))]
        {
            let FallbackTransport {
                tcp_tls,
                active,
                route,
                ..
            } = self;
            connect_inner(
                *route,
                addr,
                tcp_tls,
                active,
                std::future::ready(Err(NetworkError::ConnectionFailed(
                    "QUIC feature disabled".to_string(),
                ))),
            )
            .await
        }
    }

    /// Connect with an injectable QUIC attempt (test seam + explicit callers).
    ///
    /// `quic_attempt` is only polled when the route permits QUIC
    /// ([`TransportRoute::allows_quic`]); on failure the TCP+TLS leg takes over.
    pub async fn connect_peer_with<F>(
        &mut self,
        addr: SocketAddr,
        quic_attempt: F,
    ) -> Result<ActiveTransport>
    where
        F: std::future::Future<Output = Result<()>>,
    {
        let FallbackTransport {
            tcp_tls,
            active,
            route,
            ..
        } = self;
        connect_inner(*route, addr, tcp_tls, active, quic_attempt).await
    }
}

/// Shared connect implementation (free function so the QUIC-attempt future can
/// borrow the QUIC field while TCP+TLS/active are borrowed separately).
async fn connect_inner<F>(
    route: TransportRoute,
    addr: SocketAddr,
    tcp_tls: &mut super::tcp_tls::TcpTlsTransport,
    active: &mut ActiveTransport,
    quic_attempt: F,
) -> Result<ActiveTransport>
where
    F: std::future::Future<Output = Result<()>>,
{
    if route.is_proxied() {
        return Err(NetworkError::PolicyDenied(format!(
            "route '{}' requires the SOCKS5 proxy; refusing to open a direct \
             QUIC/TCP connection (fail-closed). Use ProxiedTcpTlsTransport for \
             proxied routes.",
            route.label()
        )));
    }

    #[cfg(feature = "quic")]
    if route.allows_quic() {
        info!("attempting QUIC connection to {}", addr);
        match quic_attempt.await {
            Ok(()) => {
                info!("QUIC connection established");
                *active = ActiveTransport::Quic;
                return Ok(ActiveTransport::Quic);
            }
            Err(e) => {
                warn!("QUIC connection failed, falling back to TCP+TLS: {}", e);
            }
        }
    }
    #[cfg(not(feature = "quic"))]
    {
        let _ = quic_attempt;
    }

    // Fall back to TCP+TLS (direct route only — the proxied route returned
    // above; there is no silent direct fallback).
    info!("attempting TCP+TLS connection to {}", addr);
    tcp_tls.connect(addr).await?;
    info!("TCP+TLS connection established");
    *active = ActiveTransport::TcpTls;
    Ok(ActiveTransport::TcpTls)
}

impl Default for FallbackTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for FallbackTransport {
    async fn connect(&mut self, addr: SocketAddr) -> Result<()> {
        self.connect_peer(addr).await.map(|_| ())
    }

    async fn send(&mut self, data: &[u8]) -> Result<usize> {
        match self.active {
            #[cfg(feature = "quic")]
            ActiveTransport::Quic => self.quic.send(data).await,
            ActiveTransport::TcpTls => self.tcp_tls.send(data).await,
            _ => Err(NetworkError::ConnectionFailed("not connected".to_string())),
        }
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.active {
            #[cfg(feature = "quic")]
            ActiveTransport::Quic => self.quic.receive(buf).await,
            ActiveTransport::TcpTls => self.tcp_tls.receive(buf).await,
            _ => Err(NetworkError::ConnectionFailed("not connected".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_route_is_direct_with_udp_opt_in() {
        // `new()` keeps legacy behavior (QUIC-first) and is the *explicit*
        // direct-UDP opt-in; policy-resolved callers use with_policy.
        let t = FallbackTransport::new();
        assert_eq!(t.route(), TransportRoute::direct(true));
        assert!(t.route().allows_quic());
        assert_eq!(t.active_transport(), ActiveTransport::None);
    }

    #[test]
    fn test_with_policy_direct_tcp_only_has_no_quic() {
        let t = FallbackTransport::with_policy(TransportRoute::direct(false));
        assert!(!t.route().allows_quic());
        assert!(t.route().allows_direct());
    }

    #[tokio::test]
    async fn test_proxied_route_refuses_direct_connect_fail_closed() {
        let mut t = FallbackTransport::with_policy(TransportRoute::proxied(true));
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let err = t.connect_peer(addr).await.unwrap_err();
        match err {
            NetworkError::PolicyDenied(msg) => {
                assert!(msg.contains("fail-closed"), "message: {msg}");
                assert!(msg.contains("SOCKS5"), "message: {msg}");
            }
            other => panic!("expected PolicyDenied, got {other:?}"),
        }
        // The QUIC leg must not have been attempted either.
        assert_eq!(t.active_transport(), ActiveTransport::None);
    }

    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test]
    async fn test_quic_blocked_falls_back_to_tcp_tls_direct() {
        // A TLS listener proves the TCP+TLS leg really ran (self-signed certs
        // are accepted only under the `dangerous_skip_verify` opt-in lane).
        use tokio::net::TcpListener;

        let identity = super::super::tls_config::generate_self_signed().unwrap();
        let server_cfg = super::super::tls_config::rustls_server_config(&identity).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            use tokio::io::AsyncWriteExt;
            // Framed like every transport: [4-byte BE length][payload].
            tls.write_all(&[0, 0, 0, 2]).await.unwrap();
            tls.write_all(b"ok").await.unwrap();
            tls.flush().await.unwrap();
            tls.shutdown().await.ok();
        });

        let mut t = FallbackTransport::with_policy(TransportRoute::direct(true));
        let active = t
            .connect_peer_with(addr, async {
                Err(NetworkError::ConnectionFailed("UDP blocked (test)".into()))
            })
            .await
            .unwrap();
        assert_eq!(active, ActiveTransport::TcpTls);
        assert_eq!(t.active_transport(), ActiveTransport::TcpTls);

        let mut buf = [0u8; 2];
        let mut read = 0;
        while read < 2 {
            let n = t.receive(&mut buf[read..]).await.unwrap();
            assert!(n > 0);
            read += n;
        }
        assert_eq!(&buf, b"ok");
        server.await.unwrap();
    }

    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test]
    async fn test_tcp_only_route_skips_quic_attempt_entirely() {
        use tokio::net::TcpListener;

        let identity = super::super::tls_config::generate_self_signed().unwrap();
        let server_cfg = super::super::tls_config::rustls_server_config(&identity).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await.unwrap();
        });

        let mut t = FallbackTransport::with_policy(TransportRoute::direct(false));
        let active = t
            .connect_peer_with(addr, async {
                panic!("QUIC attempt must not be polled when direct-UDP is not opted in")
            })
            .await
            .unwrap();
        assert_eq!(active, ActiveTransport::TcpTls);
        server.await.unwrap();
    }
}
