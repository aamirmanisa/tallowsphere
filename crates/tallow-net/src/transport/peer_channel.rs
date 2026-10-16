//! Unified peer channel trait for transport-agnostic communication
//!
//! Both relay connections and direct LAN connections implement this trait,
//! allowing the transfer pipeline to be transport-agnostic. The wire protocol
//! (`Message` enum, `TallowCodec`, postcard encoding) is identical regardless
//! of transport -- only the underlying connection differs.

use crate::Result;

/// Unified channel for communicating with a peer, regardless of transport.
///
/// Both relay connections and direct LAN connections implement this trait,
/// allowing the transfer pipeline to be transport-agnostic.
#[allow(async_fn_in_trait)]
pub trait PeerChannel: Send {
    /// Send a framed message to the peer.
    ///
    /// Uses the same 4-byte BE length-prefixed framing as `QuicTransport`.
    /// The caller is responsible for encoding `Message` to bytes via `TallowCodec`
    /// before calling this method.
    async fn send_message(&mut self, data: &[u8]) -> Result<()>;

    /// Receive a framed message from the peer.
    ///
    /// Returns the number of bytes read into `buf`.
    /// Uses the same 4-byte BE length-prefixed framing as `QuicTransport`.
    async fn receive_message(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Close the channel gracefully.
    async fn close(&mut self);

    /// Human-readable description of the transport for logging.
    ///
    /// Examples: `"relay (relay-us.example.com:4433)"`, `"direct LAN (192.168.1.42:52341)"`
    fn transport_description(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: DirectConnection implements PeerChannel
    #[cfg(feature = "quic")]
    #[test]
    fn test_direct_connection_is_peer_channel() {
        fn _assert_peer_channel<T: PeerChannel>() {}
        _assert_peer_channel::<crate::transport::direct::DirectConnection>();
    }

    /// Compile-time check: RelayClient implements PeerChannel
    #[test]
    fn test_relay_client_is_peer_channel() {
        fn _assert_peer_channel<T: PeerChannel>() {}
        _assert_peer_channel::<crate::relay::RelayClient>();
    }
}
