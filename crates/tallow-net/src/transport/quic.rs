//! QUIC transport implementation using quinn
//!
//! Provides bidirectional stream communication over QUIC.
//! Uses length-prefixed framing matching the wire protocol codec.

#[cfg(feature = "quic")]
use crate::{NetworkError, Result};
#[cfg(feature = "quic")]
use std::net::SocketAddr;

/// QUIC transport (requires `quic` feature)
#[cfg(feature = "quic")]
pub struct QuicTransport {
    /// Local endpoint
    endpoint: Option<quinn::Endpoint>,
    /// Active connection
    connection: Option<quinn::Connection>,
    /// Send stream for the current bidirectional stream
    send_stream: Option<quinn::SendStream>,
    /// Receive stream for the current bidirectional stream
    recv_stream: Option<quinn::RecvStream>,
}

#[cfg(feature = "quic")]
impl std::fmt::Debug for QuicTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTransport")
            .field("has_endpoint", &self.endpoint.is_some())
            .field("has_connection", &self.connection.is_some())
            .field("has_streams", &self.send_stream.is_some())
            .finish()
    }
}

#[cfg(feature = "quic")]
impl QuicTransport {
    /// Create a new QUIC transport
    pub fn new() -> Self {
        Self {
            endpoint: None,
            connection: None,
            send_stream: None,
            recv_stream: None,
        }
    }

    /// Create a QUIC transport bound to a specific address (for servers)
    pub fn bind(addr: SocketAddr, server_config: quinn::ServerConfig) -> Result<Self> {
        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| NetworkError::ConnectionFailed(format!("QUIC bind failed: {}", e)))?;

        Ok(Self {
            endpoint: Some(endpoint),
            connection: None,
            send_stream: None,
            recv_stream: None,
        })
    }

    /// Accept an incoming connection (server-side)
    pub async fn accept(&mut self) -> Result<()> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| NetworkError::ConnectionFailed("no endpoint bound".to_string()))?;

        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| NetworkError::ConnectionFailed("endpoint closed".to_string()))?;

        let connection = incoming
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("QUIC accept failed: {}", e)))?;

        self.connection = Some(connection);
        Ok(())
    }

    /// Accept a bidirectional stream on the current connection
    pub async fn accept_bi_stream(&mut self) -> Result<()> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| NetworkError::ConnectionFailed("no connection".to_string()))?;

        let (send, recv) = conn
            .accept_bi()
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("accept_bi failed: {}", e)))?;

        self.send_stream = Some(send);
        self.recv_stream = Some(recv);
        Ok(())
    }

    /// Get a reference to the underlying connection
    pub fn connection(&self) -> Option<&quinn::Connection> {
        self.connection.as_ref()
    }

    /// Get the endpoint
    pub fn endpoint(&self) -> Option<&quinn::Endpoint> {
        self.endpoint.as_ref()
    }

    /// Close the transport gracefully
    ///
    /// Sends FIN on the outbound stream and gives the connection a bounded
    /// window to transmit whatever is still queued before tearing it down.
    /// quinn's `Connection::close()` discards unsent stream data, so closing
    /// immediately after a final `write_all` (e.g. the sender's
    /// `TransferComplete` frame) silently dropped that frame on the wire —
    /// receivers that require it (the browser) then stall forever while the
    /// sender reports success.
    pub async fn close(&mut self) {
        if let Some(mut send) = self.send_stream.take() {
            let _ = send.finish();
            if let Some(conn) = self.connection.as_ref() {
                // The relay tears the connection down once it sees our FIN
                // (its ingress read hits EOF); wait for that, bounded.
                let _ = tokio::time::timeout(std::time::Duration::from_millis(1500), conn.closed())
                    .await;
            }
        }
        if let Some(conn) = self.connection.take() {
            conn.close(0u32.into(), b"done");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0u32.into(), b"shutdown");
        }
        self.send_stream = None;
        self.recv_stream = None;
    }
}

#[cfg(feature = "quic")]
impl Default for QuicTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "quic")]
impl QuicTransport {
    /// Connect with an explicit TLS server name (SNI + certificate
    /// validation name in strict builds).
    ///
    /// Pass the DNS name the relay was dialed with (e.g.
    /// `relay.sendtallow.com`). Builds without `dangerous_skip_verify`
    /// require the name the peer certificate is issued for;
    /// [`DEFAULT_QUIC_SERVER_NAME`] is only usable for dev/self-signed
    /// relays.
    pub async fn connect_with_server_name(
        &mut self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<()> {
        let client_config = super::tls_config::quinn_client_config()?;

        // Bind to any available port
        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().map_err(|e| {
                NetworkError::ConnectionFailed(format!("invalid bind addr: {}", e))
            })?)
            .map_err(|e| {
                NetworkError::ConnectionFailed(format!("QUIC client bind failed: {}", e))
            })?;

        endpoint.set_default_client_config(client_config);

        let connection = endpoint
            .connect(addr, server_name)
            .map_err(|e| {
                NetworkError::ConnectionFailed(format!("QUIC connect initiation failed: {}", e))
            })?
            .await
            .map_err(|e| {
                NetworkError::ConnectionFailed(format!("QUIC connection failed: {}", e))
            })?;

        // Open a bidirectional stream
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("open_bi failed: {}", e)))?;

        self.endpoint = Some(endpoint);
        self.connection = Some(connection);
        self.send_stream = Some(send);
        self.recv_stream = Some(recv);

        Ok(())
    }
}

/// Default TLS server name for the relay QUIC path when the relay is
/// addressed by IP literal (no verifiable DNS name). Strict builds fail
/// closed on such relays; dev builds skip verification entirely.
#[cfg(feature = "quic")]
pub const DEFAULT_QUIC_SERVER_NAME: &str = "localhost";

#[cfg(feature = "quic")]
impl crate::Transport for QuicTransport {
    async fn connect(&mut self, addr: SocketAddr) -> Result<()> {
        // Default server name for the trait path: dev/self-signed flows.
        // Strict (CA-validating) callers must use
        // [`QuicTransport::connect_with_server_name`].
        self.connect_with_server_name(addr, DEFAULT_QUIC_SERVER_NAME)
            .await
    }

    async fn send(&mut self, data: &[u8]) -> Result<usize> {
        let stream = self
            .send_stream
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("no send stream".to_string()))?;

        // Write length prefix (4 bytes BE)
        let len: u32 = data.len().try_into().map_err(|_| {
            NetworkError::ConnectionFailed(format!(
                "payload too large for length prefix: {} bytes",
                data.len()
            ))
        })?;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("QUIC write len failed: {}", e)))?;

        // Write payload
        stream
            .write_all(data)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("QUIC write failed: {}", e)))?;

        Ok(data.len())
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        let stream = self
            .recv_stream
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("no recv stream".to_string()))?;

        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("QUIC read len failed: {}", e)))?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > buf.len() {
            return Err(NetworkError::ConnectionFailed(format!(
                "message too large: {} bytes (buffer is {})",
                len,
                buf.len()
            )));
        }

        // Read payload
        stream
            .read_exact(&mut buf[..len])
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("QUIC read failed: {}", e)))?;

        Ok(len)
    }
}
