//! Relay client for connecting through relay servers
//!
//! Connects to a relay server via QUIC (default) or TCP+TLS through
//! a SOCKS5 proxy, joins a room by code hash, and forwards encrypted
//! data to/from the paired peer.

use super::identity::{authenticate_daemon_over, RelayMutualAuth};
use crate::privacy::ProxyConfig;
use crate::{NetworkError, Result};
use std::net::SocketAddr;
use tracing::info;

// ---------------------------------------------------------------------------
// Relay-password credential (v1 → v2 migration, 2026-10-10)
//
// The relay password is never sent in plaintext: the client presents a derived
// *tag* in the RoomJoin payload and the relay compares it in constant time
// (`tallow-relay`'s `auth::verify_relay_password_any`).
//
// v1 (legacy): bare 32-byte `BLAKE3(password)` — single-pass and unsalted.
//   Accepted server-side as a compatibility valve, but NO in-tree producer
//   emits it any more (R2-A retirement, operator directive 2026-10-10:
//   "upgrade everything to v2").
// v2 (current): 33 bytes = `0x02 || Argon2id(password, RELAY_PASS_V2_SALT,
//   Profile::Room)` — memory-hard, so a leaked bake is priced like the Room
//   profile rather than like a fast hash.
//
// This module is the single producer of the v2 tag for every in-tree client
// (the `tallow` CLI, and `tallow-relay`'s `hash-pass` bake tool, which
// re-exports it). The Argon2id cost parameters come from `tallow_crypto`'s
// `Profile::Room` — the workspace's single parameter source (§D7); they are
// not restated here.
// ---------------------------------------------------------------------------

/// Wire version byte for the v2 (Argon2id) relay-password tag.
pub const RELAY_PASS_V2_VERSION: u8 = 0x02;

/// Fixed domain salt for the v2 tag. Public by design — a domain separator,
/// not a per-relay secret (same rationale as `ROOM_ID_V2_SALT`).
pub const RELAY_PASS_V2_SALT: &[u8] = b"tallow-relay-pass-v2";

/// Derive the 32-byte Argon2id tag for a relay password.
///
/// Uses `tallow_crypto`'s [`Profile::Room`](tallow_crypto::kdf::argon2::Profile::Room)
/// (64 MiB, t=3, p=1): one derivation per distinct configured password, so the
/// ~0.3-1 s cost is paid once per join/process, and the parameters track the
/// named profile automatically.
pub fn hash_relay_password_v2(password: &str) -> [u8; 32] {
    let key = tallow_crypto::kdf::argon2::derive_key_with_profile(
        tallow_crypto::kdf::argon2::Profile::Room,
        password.as_bytes(),
        RELAY_PASS_V2_SALT,
        32,
    )
    .expect("static Argon2id params are valid");
    let mut out = [0u8; 32];
    out.copy_from_slice(&key);
    out
}

/// Full v2 wire value: `0x02 || hash_relay_password_v2(password)` (33 bytes).
pub fn relay_pass_v2_tag(password: &str) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = RELAY_PASS_V2_VERSION;
    out[1..].copy_from_slice(&hash_relay_password_v2(password));
    out
}

/// The relay-password credential a client presents on the wire: the 33-byte v2
/// tag, or `None` when no password is configured.
///
/// This is what every in-tree client calls; it exists so no call site can
/// accidentally fall back to the retired 32-byte v1 shape.
pub fn relay_password_tag(password: &str) -> Vec<u8> {
    relay_pass_v2_tag(password).to_vec()
}

/// Transport backing for the relay connection
///
/// Dispatches to QUIC (default, no proxy) or proxied TCP+TLS (when proxy active).
enum RelayTransport {
    /// QUIC transport (default, direct connection)
    #[cfg(feature = "quic")]
    Quic(crate::transport::QuicTransport),
    /// TCP+TLS routed through a SOCKS5 proxy
    Proxied(Box<crate::transport::ProxiedTcpTlsTransport>),
}

/// Relay client for connecting through relay servers
pub struct RelayClient {
    relay_addr: SocketAddr,
    transport: Option<RelayTransport>,
    /// Whether the peer was already in the room when we joined
    peer_present: bool,
    /// Optional proxy configuration for SOCKS5/Tor routing
    proxy_config: Option<ProxyConfig>,
    /// Relay hostname (for Tor DNS-via-proxy)
    relay_hostname: Option<String>,
    /// TLS server name for the direct QUIC path (SNI + certificate
    /// validation name in strict builds). `None` = default dev name.
    server_name: Option<String>,
    /// Opt-in relay mutual authentication. When set, the handshake runs on the
    /// live dial before the room-join payload is sent; a failed handshake
    /// aborts the connection.
    mutual_auth: Option<Box<RelayMutualAuth>>,
}

impl std::fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayClient")
            .field("relay_addr", &self.relay_addr)
            .field("peer_present", &self.peer_present)
            .field("has_proxy", &self.proxy_config.is_some())
            .finish()
    }
}

impl RelayClient {
    /// Create a new relay client targeting the given relay address (direct, no proxy)
    pub fn new(relay_addr: SocketAddr) -> Self {
        Self {
            relay_addr,
            transport: None,
            peer_present: false,
            proxy_config: None,
            relay_hostname: None,
            server_name: None,
            mutual_auth: None,
        }
    }

    /// Create a relay client with an explicit TLS server name for the direct
    /// (QUIC) path.
    ///
    /// Strict TLS builds (`dangerous_skip_verify` disabled) validate the
    /// relay certificate against this name — pass the DNS name the relay was
    /// dialed with (e.g. `relay.sendtallow.com`). Use [`Self::new`] for IP
    /// literals on dev/trusted networks.
    pub fn new_with_name(relay_addr: SocketAddr, server_name: Option<String>) -> Self {
        Self {
            relay_addr,
            transport: None,
            peer_present: false,
            proxy_config: None,
            relay_hostname: None,
            server_name,
            mutual_auth: None,
        }
    }

    /// Create a new relay client that routes through a SOCKS5 proxy
    ///
    /// For Tor mode, the hostname is sent to the proxy for DNS resolution
    /// inside the Tor network (no local DNS leak).
    pub fn new_with_proxy(relay_host: &str, relay_port: u16, proxy: ProxyConfig) -> Self {
        // In Tor/hostname mode we don't have an IP yet; use a placeholder
        // that will be overridden by connect_proxied() hostname mode.
        let relay_addr = SocketAddr::from(([0, 0, 0, 0], relay_port));
        Self {
            relay_addr,
            transport: None,
            peer_present: false,
            proxy_config: Some(proxy),
            relay_hostname: Some(relay_host.to_string()),
            server_name: None,
            mutual_auth: None,
        }
    }

    /// Set proxy configuration on an existing relay client
    ///
    /// Used when the relay is an IP literal but should still be routed
    /// through SOCKS5.
    pub fn set_proxy(&mut self, proxy: ProxyConfig) {
        self.proxy_config = Some(proxy);
    }

    /// Enable relay mutual authentication (workload identity + peer trust).
    ///
    /// The handshake runs on the live dial, *before* the room-join payload. A
    /// failed handshake aborts the connection rather than falling back to an
    /// unauthenticated join.
    pub fn with_mutual_auth(mut self, auth: RelayMutualAuth) -> Self {
        self.mutual_auth = Some(Box::new(auth));
        self
    }

    /// Run the mutual-auth handshake when one is configured.
    async fn handshake<T: crate::Transport>(&self, transport: &mut T) -> Result<()> {
        let Some(auth) = self.mutual_auth.as_deref() else {
            return Ok(());
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        let _session = authenticate_daemon_over(transport, auth, now).await?;
        info!("relay mutual authentication established");
        Ok(())
    }

    /// Connect to the relay server and join a room
    ///
    /// # Arguments
    ///
    /// * `room_id` - BLAKE3 hash of the code phrase (32 bytes)
    /// * `password_hash` - Optional relay-password credential: the 33-byte v2
    ///   tag [`relay_password_tag`] (or a 32-byte v1 BLAKE3 hash, accepted for
    ///   wire compatibility). `None` for an open relay.
    ///
    /// # Returns
    ///
    /// Whether the peer was already waiting in the room
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::AuthenticationFailed` if the relay rejects the password.
    pub async fn connect(
        &mut self,
        room_id: &[u8; 32],
        password_hash: Option<&[u8]>,
    ) -> Result<bool> {
        // Bound the dial here so *every* caller inherits it — `transport::connection`
        // wraps the main dial path in the same timeout, but direct users of this
        // client were unbounded (registered S5 residual: "unbounded for other dialers").
        match tokio::time::timeout(
            crate::transport::connection::RELAY_CONNECT_TIMEOUT,
            self.connect_inner(room_id, password_hash),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                tracing::warn!(
                    "relay connect to {} exceeded {:?} — giving up (relay unreachable)",
                    self.relay_addr,
                    crate::transport::connection::RELAY_CONNECT_TIMEOUT
                );
                Err(NetworkError::Timeout)
            }
        }
    }

    /// Inner dial for [`RelayClient::connect`] — the public wrapper applies
    /// [`crate::transport::connection::RELAY_CONNECT_TIMEOUT`].
    async fn connect_inner(
        &mut self,
        room_id: &[u8; 32],
        password_hash: Option<&[u8]>,
    ) -> Result<bool> {
        use crate::Transport;

        // Build the RoomJoin payload (shared between transport types)
        let join_payload = build_room_join_payload(room_id, password_hash);

        if let Some(ref proxy) = self.proxy_config {
            // Proxy path: TCP+TLS through SOCKS5
            let mut transport = crate::transport::ProxiedTcpTlsTransport::new(
                proxy,
                self.relay_hostname.clone(),
                self.relay_addr.port(),
            );
            transport.connect(self.relay_addr).await?;
            info!(
                "connected to relay via SOCKS5 proxy at {}",
                proxy.socks5_addr
            );

            self.handshake(&mut transport).await?;
            transport.send(&join_payload).await?;

            // Read response
            let mut buf = [0u8; 256];
            let n = transport.receive(&mut buf).await?;

            if n >= 1 && buf[0] == 0xFF {
                transport.close().await?;
                return Err(NetworkError::AuthenticationFailed);
            }

            if n >= 1 {
                self.peer_present = buf[0] == 1;
            }

            info!("joined room via proxy, peer_present={}", self.peer_present);
            self.transport = Some(RelayTransport::Proxied(Box::new(transport)));
            Ok(self.peer_present)
        } else {
            // Direct path: QUIC (original behavior)
            #[cfg(feature = "quic")]
            {
                let mut transport = crate::transport::QuicTransport::new();
                let server_name = self
                    .server_name
                    .as_deref()
                    .unwrap_or(crate::transport::quic::DEFAULT_QUIC_SERVER_NAME);
                transport
                    .connect_with_server_name(self.relay_addr, server_name)
                    .await?;
                info!("connected to relay at {}", self.relay_addr);

                self.handshake(&mut transport).await?;
                transport.send(&join_payload).await?;

                let mut buf = [0u8; 256];
                let n = transport.receive(&mut buf).await?;

                if n >= 1 && buf[0] == 0xFF {
                    transport.close().await;
                    return Err(NetworkError::AuthenticationFailed);
                }

                if n >= 1 {
                    self.peer_present = buf[0] == 1;
                }

                info!("joined room, peer_present={}", self.peer_present);
                self.transport = Some(RelayTransport::Quic(transport));
                Ok(self.peer_present)
            }

            #[cfg(not(feature = "quic"))]
            {
                Err(NetworkError::ConnectionFailed(
                    "no transport available: QUIC feature disabled and no proxy configured"
                        .to_string(),
                ))
            }
        }
    }

    /// Connect to the relay server with a raw join payload.
    ///
    /// Establishes the transport, sends the provided bytes (e.g. a
    /// postcard-serialized `RoomJoinMulti`), and returns the raw response.
    /// The caller is responsible for serializing the join message and
    /// interpreting the response.
    ///
    /// Returns `Err(AuthenticationFailed)` if the relay rejects authentication.
    pub async fn connect_raw(&mut self, join_payload: &[u8]) -> Result<Vec<u8>> {
        // Same bound as [`RelayClient::connect`] — the raw dialer is another entry
        // point of the registered S5 residual ("unbounded for other dialers").
        match tokio::time::timeout(
            crate::transport::connection::RELAY_CONNECT_TIMEOUT,
            self.connect_raw_inner(join_payload),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                tracing::warn!(
                    "relay connect_raw to {} exceeded {:?} — giving up (relay unreachable)",
                    self.relay_addr,
                    crate::transport::connection::RELAY_CONNECT_TIMEOUT
                );
                Err(NetworkError::Timeout)
            }
        }
    }

    /// Inner dial for [`RelayClient::connect_raw`] — bounded by the wrapper above.
    async fn connect_raw_inner(&mut self, join_payload: &[u8]) -> Result<Vec<u8>> {
        use crate::Transport;

        if let Some(ref proxy) = self.proxy_config {
            let mut transport = crate::transport::ProxiedTcpTlsTransport::new(
                proxy,
                self.relay_hostname.clone(),
                self.relay_addr.port(),
            );
            transport.connect(self.relay_addr).await?;
            info!(
                "connected to relay via SOCKS5 proxy at {}",
                proxy.socks5_addr
            );

            transport.send(join_payload).await?;

            let mut buf = vec![0u8; 16384];
            let n = transport.receive(&mut buf).await?;

            if n >= 1 && buf[0] == 0xFF {
                transport.close().await?;
                return Err(NetworkError::AuthenticationFailed);
            }

            buf.truncate(n);
            self.transport = Some(RelayTransport::Proxied(Box::new(transport)));
            Ok(buf)
        } else {
            #[cfg(feature = "quic")]
            {
                let mut transport = crate::transport::QuicTransport::new();
                let server_name = self
                    .server_name
                    .as_deref()
                    .unwrap_or(crate::transport::quic::DEFAULT_QUIC_SERVER_NAME);
                transport
                    .connect_with_server_name(self.relay_addr, server_name)
                    .await?;
                info!("connected to relay at {}", self.relay_addr);

                transport.send(join_payload).await?;

                let mut buf = vec![0u8; 16384];
                let n = transport.receive(&mut buf).await?;

                if n >= 1 && buf[0] == 0xFF {
                    transport.close().await;
                    return Err(NetworkError::AuthenticationFailed);
                }

                buf.truncate(n);
                self.transport = Some(RelayTransport::Quic(transport));
                Ok(buf)
            }

            #[cfg(not(feature = "quic"))]
            {
                Err(NetworkError::ConnectionFailed(
                    "no transport available: QUIC feature disabled and no proxy configured"
                        .to_string(),
                ))
            }
        }
    }

    /// Wait for the peer to arrive (blocks until PeerArrived notification)
    pub async fn wait_for_peer(&mut self) -> Result<()> {
        if self.peer_present {
            return Ok(());
        }

        use crate::Transport;
        let mut buf = [0u8; 256];

        let n = match self.transport.as_mut() {
            #[cfg(feature = "quic")]
            Some(RelayTransport::Quic(t)) => t.receive(&mut buf).await?,
            Some(RelayTransport::Proxied(t)) => t.receive(&mut buf).await?,
            None => {
                return Err(NetworkError::ConnectionFailed("not connected".to_string()));
            }
        };

        if n >= 1 && buf[0] == 2 {
            info!("peer arrived");
            self.peer_present = true;
        }

        Ok(())
    }

    /// Send data to the paired peer through the relay
    pub async fn forward(&mut self, data: &[u8]) -> Result<()> {
        use crate::Transport;

        match self.transport.as_mut() {
            #[cfg(feature = "quic")]
            Some(RelayTransport::Quic(t)) => {
                t.send(data).await?;
            }
            Some(RelayTransport::Proxied(t)) => {
                t.send(data).await?;
            }
            None => {
                return Err(NetworkError::ConnectionFailed("not connected".to_string()));
            }
        }
        Ok(())
    }

    /// Receive data from the paired peer through the relay
    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        use crate::Transport;

        match self.transport.as_mut() {
            #[cfg(feature = "quic")]
            Some(RelayTransport::Quic(t)) => t.receive(buf).await,
            Some(RelayTransport::Proxied(t)) => t.receive(buf).await,
            None => Err(NetworkError::ConnectionFailed("not connected".to_string())),
        }
    }

    /// Close the relay connection
    pub async fn close(&mut self) {
        match self.transport.take() {
            #[cfg(feature = "quic")]
            Some(RelayTransport::Quic(mut t)) => t.close().await,
            Some(RelayTransport::Proxied(mut t)) => {
                let _ = t.close().await;
            }
            None => {}
        }
    }

    /// Check if peer is present
    pub fn peer_present(&self) -> bool {
        self.peer_present
    }

    /// Get the relay address
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }
}

/// Build the RoomJoin payload for the relay protocol
///
/// Format: [discriminant(1)][varint_len(1)][room_id(32)][option_disc(1)][varint_len(1)][hash]
///
/// The credential's length prefix is written from the tag itself, so a 32-byte
/// v1 hash and a 33-byte v2 tag both encode correctly; the relay reads the
/// prefix generically (`tallow-relay`'s `parse_room_join_legacy`) and shape-
/// checks the value.
fn build_room_join_payload(room_id: &[u8; 32], password_hash: Option<&[u8]>) -> Vec<u8> {
    let capacity = 35 + password_hash.map_or(0, |h| 1 + h.len());
    let mut join_payload = Vec::with_capacity(capacity);
    join_payload.push(3); // RoomJoin discriminant (matches wire::Message enum position)
    join_payload.push(32); // varint length of room_id
    join_payload.extend_from_slice(room_id);

    match password_hash {
        None => {
            join_payload.push(0x00); // Option::None
        }
        Some(hash) => {
            debug_assert!(
                hash.len() <= u8::MAX as usize,
                "relay-password tag must fit the 1-byte length prefix"
            );
            join_payload.push(0x01); // Option::Some
            join_payload.push(hash.len() as u8); // varint length of tag (32 = v1, 33 = v2)
            join_payload.extend_from_slice(hash);
        }
    }

    join_payload
}

/// `PeerChannel` implementation for relay connections.
///
/// Delegates to `forward()` and `receive()` methods, allowing relay connections
/// to be used interchangeably with direct LAN connections via `Box<dyn PeerChannel>`.
impl crate::transport::PeerChannel for RelayClient {
    async fn send_message(&mut self, data: &[u8]) -> Result<()> {
        self.forward(data).await
    }

    async fn receive_message(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.receive(buf).await
    }

    async fn close(&mut self) {
        RelayClient::close(self).await;
    }

    fn transport_description(&self) -> String {
        if self.proxy_config.is_some() {
            format!("relay via proxy ({})", self.relay_addr)
        } else {
            format!("relay ({})", self.relay_addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_client_new_unchanged() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let client = RelayClient::new(addr);
        assert_eq!(client.relay_addr(), addr);
        assert!(!client.peer_present());
        assert!(client.proxy_config.is_none());
        assert!(client.server_name.is_none());
    }

    #[test]
    fn test_relay_client_new_with_name() {
        let addr: SocketAddr = "203.0.113.7:4433".parse().unwrap();
        let client = RelayClient::new_with_name(addr, Some("relay.example.com".to_string()));
        assert_eq!(client.relay_addr(), addr);
        assert_eq!(client.server_name.as_deref(), Some("relay.example.com"));
        assert!(client.proxy_config.is_none());
    }

    #[test]
    fn test_relay_client_new_with_proxy() {
        let proxy = ProxyConfig::tor_default();
        let client = RelayClient::new_with_proxy("relay.example.com", 4433, proxy);
        assert_eq!(client.relay_addr().port(), 4433);
        assert!(client.proxy_config.is_some());
        assert_eq!(client.relay_hostname.as_deref(), Some("relay.example.com"));
    }

    #[test]
    fn test_relay_client_set_proxy() {
        let addr: SocketAddr = "18.119.135.151:4433".parse().unwrap();
        let mut client = RelayClient::new(addr);
        assert!(client.proxy_config.is_none());

        client.set_proxy(ProxyConfig::tor_default());
        assert!(client.proxy_config.is_some());
    }

    #[test]
    fn test_build_room_join_payload_no_password() {
        let room_id = [0xAB; 32];
        let payload = build_room_join_payload(&room_id, None);
        assert_eq!(payload.len(), 35);
        assert_eq!(payload[0], 3); // discriminant
        assert_eq!(payload[1], 32); // varint len
        assert_eq!(&payload[2..34], &room_id);
        assert_eq!(payload[34], 0x00); // Option::None
    }

    #[test]
    fn test_build_room_join_payload_with_32_byte_v1_tag() {
        // The relay's legacy shape still encodes correctly (compat valve),
        // even though no in-tree client emits it any more.
        let room_id = [0xAB; 32];
        let pw_hash = [0xCD; 32];
        let payload = build_room_join_payload(&room_id, Some(&pw_hash));
        assert_eq!(payload.len(), 68);
        assert_eq!(payload[0], 3);
        assert_eq!(payload[34], 0x01); // Option::Some
        assert_eq!(payload[35], 32); // varint len
        assert_eq!(&payload[36..68], &pw_hash);
    }

    #[test]
    fn test_build_room_join_payload_with_33_byte_v2_tag() {
        // The R2-A credential: `0x02 || 32-byte Argon2id tag`.
        let room_id = [0xAB; 32];
        let tag = relay_pass_v2_tag("secretpass");
        let payload = build_room_join_payload(&room_id, Some(&tag));
        assert_eq!(payload.len(), 69);
        assert_eq!(payload[0], 3);
        assert_eq!(payload[34], 0x01); // Option::Some
        assert_eq!(payload[35], 33); // varint len
        assert_eq!(&payload[36..69], &tag[..]);
    }

    #[test]
    fn test_relay_password_tag_is_v2_not_v1() {
        // The client producer must never emit the retired 32-byte shape.
        let tag = relay_password_tag("secretpass");
        assert_eq!(
            tag.len(),
            33,
            "the client credential must be the 33-byte v2 tag"
        );
        assert_eq!(tag[0], RELAY_PASS_V2_VERSION);

        // ...and it must be the Argon2id derivation, not a re-tagged BLAKE3
        // hash (which would be the v1 value wearing the v2 prefix).
        let mut retagged_v1 = [0u8; 33];
        retagged_v1[0] = RELAY_PASS_V2_VERSION;
        retagged_v1[1..].copy_from_slice(&tallow_crypto::hash::blake3::hash(b"secretpass"));
        assert_ne!(
            tag[..],
            retagged_v1[..],
            "v2 must be Argon2id(Profile::Room), not BLAKE3 with a version prefix"
        );
    }

    #[test]
    fn test_v2_tag_deterministic_and_password_bound() {
        // Same password → same tag; different password → different tag.
        assert_eq!(relay_pass_v2_tag("alpha"), relay_pass_v2_tag("alpha"));
        assert_ne!(relay_pass_v2_tag("alpha"), relay_pass_v2_tag("beta"));
    }
}
