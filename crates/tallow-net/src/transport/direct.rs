//! Direct peer-to-peer QUIC transport for LAN transfers
//!
//! Provides `DirectConnection` (a QUIC stream pair), `DirectListener` (server-side
//! endpoint for senders), and `connect_direct()` (client-side for receivers).
//!
//! Uses the same 4-byte BE length-prefixed framing as relay connections.
//! The wire protocol is identical -- only the transport path differs.

#[cfg(feature = "quic")]
use crate::{NetworkError, Result};
#[cfg(feature = "quic")]
use std::net::SocketAddr;
#[cfg(feature = "quic")]
use std::sync::Arc;
#[cfg(feature = "quic")]
use std::time::Duration;

/// A direct peer-to-peer QUIC connection for LAN transfers.
///
/// Uses the same 4-byte BE length-prefixed framing as relay connections.
/// The wire protocol is identical -- only the transport path differs.
#[cfg(feature = "quic")]
pub struct DirectConnection {
    /// The QUIC endpoint (must stay alive for the IO driver)
    _endpoint: quinn::Endpoint,
    /// The underlying QUIC connection
    connection: quinn::Connection,
    /// Bidirectional send stream
    send: quinn::SendStream,
    /// Bidirectional receive stream
    recv: quinn::RecvStream,
    /// Remote peer address for logging
    remote_addr: SocketAddr,
}

#[cfg(feature = "quic")]
impl DirectConnection {
    /// Create a new DirectConnection from an established QUIC connection and streams.
    fn new(
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        remote_addr: SocketAddr,
    ) -> Self {
        Self {
            _endpoint: endpoint,
            connection,
            send,
            recv,
            remote_addr,
        }
    }

    /// Get the remote peer address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

#[cfg(feature = "quic")]
impl crate::transport::PeerChannel for DirectConnection {
    async fn send_message(&mut self, data: &[u8]) -> Result<()> {
        // Write 4-byte BE length prefix
        let len: u32 = data.len().try_into().map_err(|_| {
            NetworkError::ConnectionFailed(format!(
                "payload too large for length prefix: {} bytes",
                data.len()
            ))
        })?;
        self.send.write_all(&len.to_be_bytes()).await.map_err(|e| {
            NetworkError::ConnectionFailed(format!("direct write len failed: {}", e))
        })?;

        // Write payload
        self.send.write_all(data).await.map_err(|e| {
            NetworkError::ConnectionFailed(format!("direct write payload failed: {}", e))
        })?;

        Ok(())
    }

    async fn receive_message(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Read 4-byte BE length prefix
        let mut len_buf = [0u8; 4];
        self.recv.read_exact(&mut len_buf).await.map_err(|e| {
            NetworkError::ConnectionFailed(format!("direct read len failed: {}", e))
        })?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > buf.len() {
            return Err(NetworkError::ConnectionFailed(format!(
                "message too large: {} bytes (buffer is {})",
                len,
                buf.len()
            )));
        }

        // Read payload
        self.recv.read_exact(&mut buf[..len]).await.map_err(|e| {
            NetworkError::ConnectionFailed(format!("direct read payload failed: {}", e))
        })?;

        Ok(len)
    }

    async fn close(&mut self) {
        self.connection.close(0u32.into(), b"done");
    }

    fn transport_description(&self) -> String {
        format!("direct LAN ({})", self.remote_addr)
    }
}

/// Create a LAN-tuned QUIC transport configuration.
///
/// Optimized for LAN conditions: short idle timeout, low initial RTT estimate.
#[cfg(feature = "quic")]
fn lan_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("30s fits in IdleTimeout"),
    ));
    transport.initial_rtt(Duration::from_millis(1));
    transport
}

/// QUIC server for accepting a direct LAN connection from a peer.
///
/// The sender acts as the server: bind to `:0`, advertise the port via mDNS,
/// and wait for the receiver to connect.
#[cfg(feature = "quic")]
pub struct DirectListener {
    /// The QUIC endpoint accepting connections
    endpoint: quinn::Endpoint,
    /// The actual bound address (with OS-assigned port)
    local_addr: SocketAddr,
}

#[cfg(feature = "quic")]
impl DirectListener {
    /// Bind a QUIC listener on a random OS-assigned port (all interfaces).
    ///
    /// Generates a self-signed TLS certificate for the connection.
    /// The certificate is not verified by the peer -- E2E encryption
    /// handles confidentiality and authentication.
    pub fn bind() -> Result<Self> {
        Self::bind_to(
            "0.0.0.0:0"
                .parse()
                .map_err(|e| NetworkError::ConnectionFailed(format!("invalid bind addr: {}", e)))?,
        )
    }

    /// Bind a QUIC listener on a specific address and random OS-assigned port.
    ///
    /// Use `bind_to("127.0.0.1:0")` for loopback-only connections (e.g., tests
    /// on Windows where QUIC requires both endpoints on the same interface).
    pub fn bind_to(bind_addr: SocketAddr) -> Result<Self> {
        let identity = super::tls_config::generate_self_signed()?;

        let mut server_config = quinn::ServerConfig::with_single_cert(
            identity.chain(),
            identity.key_der.clone_key().into(),
        )
        .map_err(|e| {
            NetworkError::TlsError(format!("direct listener server config failed: {}", e))
        })?;

        server_config.transport_config(Arc::new(lan_transport_config()));

        let endpoint = quinn::Endpoint::server(server_config, bind_addr).map_err(|e| {
            NetworkError::ConnectionFailed(format!("direct listener bind failed: {}", e))
        })?;

        let local_addr = endpoint.local_addr().map_err(|e| {
            NetworkError::ConnectionFailed(format!("failed to get local addr: {}", e))
        })?;

        tracing::info!("Direct listener bound on {}", local_addr);

        Ok(Self {
            endpoint,
            local_addr,
        })
    }

    /// Return the bound port (used for mDNS advertisement).
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Return the full bound address.
    ///
    /// If the listener is bound to the unspecified address (0.0.0.0),
    /// returns 127.0.0.1:port instead, since 0.0.0.0 is not a valid
    /// connect target (especially on Windows where QUIC rejects it).
    pub fn local_addr(&self) -> SocketAddr {
        if self.local_addr.ip().is_unspecified() {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                self.local_addr.port(),
            )
        } else {
            self.local_addr
        }
    }

    /// Accept one incoming peer connection with a timeout.
    ///
    /// Waits for a single QUIC connection and opens a bidirectional stream.
    pub async fn accept_peer(&self, timeout: Duration) -> Result<DirectConnection> {
        let incoming = tokio::time::timeout(timeout, self.endpoint.accept())
            .await
            .map_err(|_| NetworkError::Timeout)?
            .ok_or_else(|| {
                NetworkError::ConnectionFailed("endpoint closed before accept".to_string())
            })?;

        let connection = incoming.await.map_err(|e| {
            NetworkError::ConnectionFailed(format!("direct accept connection failed: {}", e))
        })?;

        let remote_addr = connection.remote_address();
        tracing::info!("Direct connection accepted from {}", remote_addr);

        // Accept a bidirectional stream opened by the connecting peer
        let (send, recv) = connection.accept_bi().await.map_err(|e| {
            NetworkError::ConnectionFailed(format!("direct accept_bi failed: {}", e))
        })?;

        Ok(DirectConnection::new(
            self.endpoint.clone(),
            connection,
            send,
            recv,
            remote_addr,
        ))
    }

    /// Initiate an outbound QUIC connection to a peer using this listener's endpoint.
    ///
    /// This reuses the same UDP socket (and port) that the listener is bound to.
    /// Quinn natively supports both `accept()` and `connect()` on the same Endpoint.
    /// This is critical for hole punching: the outbound connection uses the same
    /// local port that STUN discovered, ensuring the NAT pinhole is reused.
    pub async fn connect_to(
        &mut self,
        peer_addr: SocketAddr,
        timeout_dur: Duration,
    ) -> Result<DirectConnection> {
        // Add client config to the endpoint so it can initiate connections.
        // The endpoint already has a server config from bind().
        let client_config = super::tls_config::quinn_client_config()?;
        let mut lan_client_config = client_config;
        lan_client_config.transport_config(Arc::new(lan_transport_config()));
        self.endpoint.set_default_client_config(lan_client_config);

        let connection = tokio::time::timeout(
            timeout_dur,
            self.endpoint.connect(peer_addr, "localhost").map_err(|e| {
                NetworkError::ConnectionFailed(format!("direct connect initiation failed: {}", e))
            })?,
        )
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(|e| {
            NetworkError::ConnectionFailed(format!("direct QUIC connection failed: {}", e))
        })?;

        let remote_addr = connection.remote_address();
        tracing::info!("Direct P2P connection established to {}", remote_addr);

        // Open a bidirectional stream (client role opens, server role accepts)
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("direct open_bi failed: {}", e)))?;

        Ok(DirectConnection::new(
            self.endpoint.clone(),
            connection,
            send,
            recv,
            remote_addr,
        ))
    }

    /// Close the listener endpoint.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

/// Connect directly to a LAN peer via QUIC.
///
/// The receiver calls this after discovering the sender via mDNS.
/// Uses the same skip-server-verification TLS config as relay connections,
/// justified by E2E encryption providing the actual security layer.
#[cfg(feature = "quic")]
pub async fn connect_direct(peer_addr: SocketAddr, timeout: Duration) -> Result<DirectConnection> {
    let client_config = super::tls_config::quinn_client_config()?;

    // Override with LAN-tuned transport config
    let mut lan_client_config = client_config;
    lan_client_config.transport_config(Arc::new(lan_transport_config()));

    // Bind client to the same interface as the target. On Windows, QUIC
    // requires both endpoints on the same interface for UDP routing to work.
    let bind_addr: SocketAddr = if peer_addr.ip().is_loopback() {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)
    } else {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    };

    let mut endpoint = quinn::Endpoint::client(bind_addr)
        .map_err(|e| NetworkError::ConnectionFailed(format!("direct client bind failed: {}", e)))?;

    endpoint.set_default_client_config(lan_client_config);

    let connection = tokio::time::timeout(
        timeout,
        endpoint.connect(peer_addr, "localhost").map_err(|e| {
            NetworkError::ConnectionFailed(format!("direct connect initiation failed: {}", e))
        })?,
    )
    .await
    .map_err(|_| NetworkError::Timeout)?
    .map_err(|e| NetworkError::ConnectionFailed(format!("direct QUIC connection failed: {}", e)))?;

    let remote_addr = connection.remote_address();
    tracing::info!("Direct connection established to {}", remote_addr);

    // Open a bidirectional stream
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| NetworkError::ConnectionFailed(format!("direct open_bi failed: {}", e)))?;

    Ok(DirectConnection::new(
        endpoint,
        connection,
        send,
        recv,
        remote_addr,
    ))
}

#[cfg(test)]
#[cfg(feature = "quic")]
mod tests {
    use super::*;
    use crate::transport::PeerChannel;

    /// Bind a loopback-only listener for tests.
    /// On Windows, QUIC requires both endpoints on the same interface.
    fn loopback_listener() -> DirectListener {
        DirectListener::bind_to("127.0.0.1:0".parse().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn test_direct_listener_bind() {
        let listener = loopback_listener();
        assert_ne!(listener.port(), 0);
        listener.close();
    }

    // NOTE: QUIC's open_bi() doesn't send a STREAM frame until data is written.
    // Tests must spawn both server and client as concurrent tasks where the
    // client writes data before the server handle is awaited, otherwise
    // accept_bi() and open_bi() deadlock.

    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_direct_roundtrip() {
        let listener = loopback_listener();
        let addr = listener.local_addr();

        let server_handle = tokio::spawn(async move {
            let mut server = listener.accept_peer(Duration::from_secs(5)).await.unwrap();

            // Receive from client
            let mut buf = vec![0u8; 1024];
            let n = server.receive_message(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello direct!");

            // Echo back
            server.send_message(b"hello back!").await.unwrap();
            server
        });

        let mut client = connect_direct(addr, Duration::from_secs(5)).await.unwrap();

        // Write data immediately — this triggers the QUIC STREAM frame
        // that unblocks the server's accept_bi()
        client.send_message(b"hello direct!").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.receive_message(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello back!");

        let mut server = server_handle.await.unwrap();
        client.close().await;
        server.close().await;
    }

    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_direct_large_message() {
        let listener = loopback_listener();
        let addr = listener.local_addr();

        let server_handle = tokio::spawn(async move {
            let mut server = listener.accept_peer(Duration::from_secs(10)).await.unwrap();

            let mut buf = vec![0u8; 1_100_000];
            let n = server.receive_message(&mut buf).await.unwrap();
            (server, n, buf)
        });

        let mut client = connect_direct(addr, Duration::from_secs(5)).await.unwrap();

        // Send a 1MB payload
        let payload: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        client.send_message(&payload).await.unwrap();

        let (mut server, n, buf) = server_handle.await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], &payload[..]);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn test_connect_timeout() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = connect_direct(addr, Duration::from_millis(500)).await;
        assert!(result.is_err());
    }

    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_empty_message() {
        let listener = loopback_listener();
        let addr = listener.local_addr();

        let server_handle = tokio::spawn(async move {
            let mut server = listener.accept_peer(Duration::from_secs(5)).await.unwrap();

            let mut buf = vec![0u8; 1024];
            let n = server.receive_message(&mut buf).await.unwrap();
            (server, n)
        });

        let mut client = connect_direct(addr, Duration::from_secs(5)).await.unwrap();

        // Send 0-byte payload — still triggers STREAM frame via length prefix
        client.send_message(&[]).await.unwrap();

        let (mut server, n) = server_handle.await.unwrap();
        assert_eq!(n, 0);

        client.close().await;
        server.close().await;
    }

    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_multiple_messages() {
        let listener = loopback_listener();
        let addr = listener.local_addr();

        let server_handle = tokio::spawn(async move {
            let mut server = listener.accept_peer(Duration::from_secs(5)).await.unwrap();

            let mut buf = vec![0u8; 1024];
            for i in 0u32..100 {
                let n = server.receive_message(&mut buf).await.unwrap();
                let expected = format!("message-{}", i);
                assert_eq!(&buf[..n], expected.as_bytes());
            }
            server
        });

        let mut client = connect_direct(addr, Duration::from_secs(5)).await.unwrap();

        // Send 100 messages in sequence
        for i in 0u32..100 {
            let msg = format!("message-{}", i);
            client.send_message(msg.as_bytes()).await.unwrap();
        }

        let mut server = server_handle.await.unwrap();
        client.close().await;
        server.close().await;
    }

    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_bidirectional_concurrent() {
        let listener = loopback_listener();
        let addr = listener.local_addr();

        let server_handle = tokio::spawn(async move {
            let mut server = listener.accept_peer(Duration::from_secs(5)).await.unwrap();

            // Server receives from client, then sends
            let mut buf = vec![0u8; 1024];
            let n = server.receive_message(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"from-client");

            server.send_message(b"from-server").await.unwrap();
            server
        });

        let mut client = connect_direct(addr, Duration::from_secs(5)).await.unwrap();

        // Client sends first (triggers stream), then receives
        client.send_message(b"from-client").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.receive_message(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from-server");

        let mut server = server_handle.await.unwrap();
        client.close().await;
        server.close().await;
    }
}
