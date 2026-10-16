//! Transport layer implementations
//!
//! QUIC (primary), TCP+TLS (fallback), and the FallbackTransport that
//! tries QUIC first and falls back to TCP+TLS automatically.
//!
//! The `PeerChannel` trait provides a unified abstraction for both relay
//! and direct LAN connections, allowing the transfer pipeline to be
//! transport-agnostic.

pub mod bandwidth;
pub mod connection;
pub mod direct;
pub mod ech;
pub mod fallback;
pub mod negotiation;
pub mod p2p;
pub mod peer_channel;
pub mod proxied;
pub mod quic;
pub mod reconnect;
pub mod spki_pin;
pub mod tcp_tls;
pub mod test_support;
pub mod tls_cohort;
pub mod tls_config;

use crate::Result;
use std::net::SocketAddr;

#[cfg(feature = "quic")]
pub use connection::{
    establish_receiver_connection, establish_sender_connection, ConnectionResult,
};
#[cfg(feature = "quic")]
pub use direct::{connect_direct, DirectConnection, DirectListener};
pub use fallback::{ActiveTransport, FallbackTransport};
pub use negotiation::{negotiate, negotiate_with_policy, TransportProtocol, TransportRoute};
#[cfg(feature = "quic")]
pub use p2p::{negotiate_p2p, NegotiationResult};
pub use peer_channel::PeerChannel;
pub use proxied::{ProxiedTcpTlsTransport, ProxiedTunnel, TunnelReader, TunnelWriter};
#[cfg(feature = "quic")]
pub use quic::QuicTransport;
pub use reconnect::ReconnectConfig;
pub use tcp_tls::{
    connect_happy_eyeballs, connect_std, interleave_addresses, TcpTlsTransport,
    HAPPY_EYEBALLS_ATTEMPT_DELAY,
};

/// Transport layer abstraction
///
/// All transports use the same length-prefixed framing:
/// `[4-byte BE length][payload]`
#[allow(async_fn_in_trait)]
pub trait Transport: Send + Sync {
    /// Connect to a remote peer
    async fn connect(&mut self, addr: SocketAddr) -> Result<()>;

    /// Send data (framed with length prefix)
    async fn send(&mut self, data: &[u8]) -> Result<usize>;

    /// Receive data into buffer, returns number of bytes read
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize>;
}
