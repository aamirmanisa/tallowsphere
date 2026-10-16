//! Transport protocol negotiation
//!
//! Two layers live here:
//!
//! 1. [`negotiate`] — the original peer-preference intersection (highest local
//!    preference the remote also supports).
//! 2. [`TransportRoute`] + [`negotiate_with_policy`] — the policy-aware layer
//!    (R-08 batch-3 · rows #131/#132 / design P4-3): the allowed *egress route*
//!    constrains which transports may even be considered, so a proxy/Tor route
//!    can never negotiate itself into a QUIC (or direct) connection. This is
//!    the "no silent direct fallback" rule at the negotiation layer.

use crate::{NetworkError, Result};

/// Transport protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// QUIC (UDP-based)
    Quic,
    /// TCP with TLS
    TcpTls,
    /// WebRTC data channels
    WebRtc,
}

/// Egress route a transport policy allows.
///
/// The route is a *policy* (what is permitted), not a preference order:
/// preference among permitted candidates is decided by [`TransportRoute::candidates`]
/// and, for the direct route, by the explicit direct-UDP opt-in only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportRoute {
    /// Direct sockets are permitted (clearnet peer/relay).
    ///
    /// `allow_direct_udp` gates UDP-based transports (QUIC). It exists because
    /// preferring direct UDP is an **explicit opt-in** (`TALLOW_ALLOW_DIRECT`-class,
    /// design P4-3 operator line) — never a default, and never available while a
    /// proxy route is configured.
    Direct {
        /// Explicit opt-in for UDP-based transports (QUIC) on the direct route.
        allow_direct_udp: bool,
    },
    /// All transport bytes must ride the configured SOCKS5 proxy (Tor or
    /// generic). Direct sockets are **denied** (fail-closed) and QUIC is
    /// ineligible: QUIC is UDP and cannot traverse SOCKS5 (tor-spec).
    Proxied {
        /// Tor mode (DNS resolved by the proxy; `.onion` targets reachable).
        tor_mode: bool,
    },
}

impl TransportRoute {
    /// Direct route with an explicit UDP opt-in decision.
    pub fn direct(allow_direct_udp: bool) -> Self {
        Self::Direct { allow_direct_udp }
    }

    /// SOCKS5 proxy route (`tor_mode` = Tor / `socks5h`).
    pub fn proxied(tor_mode: bool) -> Self {
        Self::Proxied { tor_mode }
    }

    /// True when the route requires the SOCKS5 proxy (direct is denied).
    pub fn is_proxied(&self) -> bool {
        matches!(self, Self::Proxied { .. })
    }

    /// True when a direct socket may be opened for this route.
    pub fn allows_direct(&self) -> bool {
        !self.is_proxied()
    }

    /// True when UDP-based transports (QUIC) are permitted by the route.
    ///
    /// Always `false` on the proxied route — no opt-in can enable direct UDP
    /// while a proxy is configured (P4-3 operator line).
    pub fn allows_quic(&self) -> bool {
        matches!(
            self,
            Self::Direct {
                allow_direct_udp: true
            }
        )
    }

    /// True when the route is Tor (hostname-based, `.onion`-capable) routing.
    pub fn is_tor(&self) -> bool {
        matches!(self, Self::Proxied { tor_mode: true })
    }

    /// Ordered transport candidates permitted by this route (highest priority
    /// first). Empty is impossible today (TCP+TLS is always permitted), but the
    /// signature keeps the door open for a route that permits nothing.
    pub fn candidates(&self) -> Vec<TransportProtocol> {
        match self {
            Self::Direct {
                allow_direct_udp: true,
            } => vec![TransportProtocol::Quic, TransportProtocol::TcpTls],
            // Direct without the UDP opt-in: TCP+TLS only — the direct-UDP
            // preference is never a default (P4-3 operator line).
            Self::Direct { .. } => vec![TransportProtocol::TcpTls],
            // QUIC cannot traverse SOCKS5; over a proxy the stream carries
            // tallow-protocol frames over TCP+TLS.
            Self::Proxied { .. } => vec![TransportProtocol::TcpTls],
        }
    }

    /// Human-readable route label for logs/errors (stable strings, no PII).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Direct {
                allow_direct_udp: true,
            } => "direct (udp authorized)",
            Self::Direct { .. } => "direct (tcp only)",
            Self::Proxied { tor_mode: true } => "tor (socks5h)",
            Self::Proxied { tor_mode: false } => "proxy (socks5)",
        }
    }
}

/// Negotiate transport protocol with peer.
///
/// Finds the highest-priority protocol supported by both sides.
/// Priority is determined by position in `local_prefs` (first = highest).
///
/// This is the *policy-free* negotiation; policy-constrained callers must use
/// [`negotiate_with_policy`].
pub async fn negotiate(
    local_prefs: &[TransportProtocol],
    remote_prefs: &[TransportProtocol],
) -> Result<TransportProtocol> {
    // Find the first local preference that the remote also supports
    for local in local_prefs {
        if remote_prefs.contains(local) {
            tracing::debug!("Negotiated transport protocol: {:?}", local);
            return Ok(*local);
        }
    }

    Err(NetworkError::ProtocolNegotiation(
        "No common transport protocol found".to_string(),
    ))
}

/// Policy-aware transport negotiation (R-08 batch-3 · #131/#132).
///
/// Intersects the transports permitted by `route` (in route priority order)
/// with the remote's preferences. The remote can **never widen** the route: a
/// peer that only offers QUIC is refused on a proxied route instead of being
/// silently connected over direct UDP/TCP (fail-closed).
pub async fn negotiate_with_policy(
    route: TransportRoute,
    remote_prefs: &[TransportProtocol],
) -> Result<TransportProtocol> {
    let candidates = route.candidates();
    for candidate in &candidates {
        if remote_prefs.contains(candidate) {
            tracing::debug!(
                "Negotiated transport protocol {:?} under route '{}'",
                candidate,
                route.label()
            );
            return Ok(*candidate);
        }
    }

    if route.is_proxied() && !remote_prefs.is_empty() {
        let offered: Vec<String> = remote_prefs.iter().map(|p| format!("{p:?}")).collect();
        return Err(NetworkError::PolicyDenied(format!(
            "peer offers only [{}] but route '{}' permits [{}] — QUIC cannot traverse \
             SOCKS5 and direct fallback is denied (fail-closed); refusing to negotiate \
             a connection that would bypass the proxy",
            offered.join(", "),
            route.label(),
            candidates
                .iter()
                .map(|p| format!("{p:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    Err(NetworkError::ProtocolNegotiation(format!(
        "No common transport protocol found under route '{}'",
        route.label()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_negotiate_common_protocol() {
        let local = [TransportProtocol::Quic, TransportProtocol::TcpTls];
        let remote = [TransportProtocol::TcpTls, TransportProtocol::Quic];
        let result = negotiate(&local, &remote).await.unwrap();
        assert_eq!(result, TransportProtocol::Quic);
    }

    #[tokio::test]
    async fn test_negotiate_no_common() {
        let local = [TransportProtocol::Quic];
        let remote = [TransportProtocol::TcpTls];
        assert!(negotiate(&local, &remote).await.is_err());
    }

    #[tokio::test]
    async fn test_negotiate_single_match() {
        let local = [TransportProtocol::TcpTls];
        let remote = [TransportProtocol::TcpTls];
        let result = negotiate(&local, &remote).await.unwrap();
        assert_eq!(result, TransportProtocol::TcpTls);
    }

    #[tokio::test]
    async fn test_negotiate_empty_prefs() {
        let local: [TransportProtocol; 0] = [];
        let remote = [TransportProtocol::Quic];
        assert!(negotiate(&local, &remote).await.is_err());
    }

    // ── Policy-aware negotiation (R-08 batch-3 · #131/#132) ──

    #[test]
    fn test_route_candidates() {
        assert_eq!(
            TransportRoute::direct(true).candidates(),
            vec![TransportProtocol::Quic, TransportProtocol::TcpTls]
        );
        assert_eq!(
            TransportRoute::direct(false).candidates(),
            vec![TransportProtocol::TcpTls]
        );
        assert_eq!(
            TransportRoute::proxied(true).candidates(),
            vec![TransportProtocol::TcpTls]
        );
    }

    #[test]
    fn test_route_quic_gate_is_opt_in_only_and_never_proxied() {
        assert!(!TransportRoute::direct(false).allows_quic());
        assert!(TransportRoute::direct(true).allows_quic());
        // No opt-in can enable direct UDP on the proxied route.
        assert!(!TransportRoute::proxied(false).allows_quic());
        assert!(!TransportRoute::proxied(true).allows_quic());
        assert!(!TransportRoute::proxied(true).allows_direct());
    }

    #[tokio::test]
    async fn test_tor_route_negotiates_tcp_tls_even_when_peer_prefers_quic() {
        let route = TransportRoute::proxied(true);
        let peer = [TransportProtocol::Quic, TransportProtocol::TcpTls];
        let picked = negotiate_with_policy(route, &peer).await.unwrap();
        assert_eq!(picked, TransportProtocol::TcpTls, "Tor mode ⇒ TCP+TLS only");
    }

    #[tokio::test]
    async fn test_tor_route_refuses_quic_only_peer_fail_closed() {
        let route = TransportRoute::proxied(true);
        let peer = [TransportProtocol::Quic];
        let err = negotiate_with_policy(route, &peer).await.unwrap_err();
        match err {
            NetworkError::PolicyDenied(msg) => {
                assert!(msg.contains("fail-closed"), "message: {msg}");
                assert!(msg.contains("tor"), "message: {msg}");
            }
            other => panic!("expected PolicyDenied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_direct_route_without_udp_opt_in_skips_quic() {
        let route = TransportRoute::direct(false);
        let peer = [TransportProtocol::Quic, TransportProtocol::TcpTls];
        let picked = negotiate_with_policy(route, &peer).await.unwrap();
        assert_eq!(
            picked,
            TransportProtocol::TcpTls,
            "direct-UDP is opt-in only"
        );
    }

    #[tokio::test]
    async fn test_direct_route_with_udp_opt_in_prefers_quic() {
        let route = TransportRoute::direct(true);
        let peer = [TransportProtocol::Quic, TransportProtocol::TcpTls];
        let picked = negotiate_with_policy(route, &peer).await.unwrap();
        assert_eq!(picked, TransportProtocol::Quic);
    }

    #[tokio::test]
    async fn test_policy_negotiation_empty_peer_prefs_is_negotiation_error() {
        let route = TransportRoute::proxied(true);
        let peer: [TransportProtocol; 0] = [];
        match negotiate_with_policy(route, &peer).await.unwrap_err() {
            NetworkError::ProtocolNegotiation(_) => {}
            other => panic!("expected ProtocolNegotiation, got {other:?}"),
        }
    }
}
