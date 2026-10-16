//! Signaling client implementation
//!
//! Provides peer coordination (SDP offer/answer/ICE) via a signaling
//! server over a real TCP transport.
//!
//! # Wire protocol (v1 signaling transport)
//!
//! The transport is plain TCP (no TLS/WebSocket layer in v1). Each
//! direction carries a sequence of frames:
//!
//! ```text
//! frame := [u32 big-endian payload length][payload]
//! ```
//!
//! The payload is the JSON encoding of a `WireFrame` envelope:
//!
//! ```json
//! {"op": "ping"}
//! {"op": "pong"}
//! {"op": "message", "message": {"type": "Join", "room_code": "...", "peer_id": "..."}}
//! ```
//!
//! Connection establishment is a genuine liveness handshake: the client
//! connects its socket, sends `ping`, and only reports itself connected
//! after receiving `pong` from the server (bounded by a timeout). A
//! server may send `ping` frames at any time; the client answers them
//! with `pong`. `send`/`receive` transfer `SignalingMessage` payloads
//! over the same socket. Any socket error, EOF, protocol violation, or
//! handshake timeout is propagated as a `NetworkError` and the client
//! drops the connection — `is_connected()` is never true without a live,
//! handshake-verified socket.
//!
//! A signaling server is expected to speak the protocol above on its
//! listening port.

use super::protocol::SignalingMessage;
use crate::{NetworkError, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Timeout for the initial TCP connect.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for the ping/pong liveness handshake.
const PONG_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum accepted signaling frame payload (guards against length-prefix abuse).
const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Wire envelope exchanged with the signaling server.
///
/// Serialized as JSON, e.g. `{"op":"ping"}` or
/// `{"op":"message","message":{"type":"Join",...}}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum WireFrame {
    /// Liveness probe.
    Ping,
    /// Liveness response.
    Pong,
    /// A signaling message payload.
    Message {
        /// The signaling message
        message: SignalingMessage,
    },
}

/// Signaling client for coordinating with peers.
///
/// Backed by a real TCP socket: `connect()` opens the socket and
/// completes a ping/pong handshake before the client is considered
/// connected. `send`/`receive` read and write length-prefixed JSON
/// frames on that socket.
#[derive(Debug)]
pub struct SignalingClient {
    /// Server URL or address
    server_url: String,
    /// Live, handshake-verified socket to the signaling server
    ///
    /// `Some` only after a successful TCP connect + ping/pong handshake.
    /// `is_connected()` is derived from this field, so a client can never
    /// report itself connected without a live socket.
    stream: Option<TcpStream>,
}

impl SignalingClient {
    /// Create a new signaling client.
    ///
    /// `server_url` accepts `host:port`, an IP literal like
    /// `127.0.0.1:8080` or `[::1]:8080`, or an explicit `tcp://host:port`.
    /// WebSocket URLs (`ws://`/`wss://`) are rejected: the v1 transport is
    /// plain TCP and claiming otherwise would be dishonest.
    pub fn new(server_url: String) -> Self {
        Self {
            server_url,
            stream: None,
        }
    }

    /// Connect to the signaling server.
    ///
    /// Opens a real TCP socket to the server and completes a ping/pong
    /// liveness handshake. Returns `Ok` only after the socket is open and
    /// the server answered a `ping` with `pong`.
    ///
    /// # Errors
    ///
    /// * `NetworkError::ConnectionFailed` if the URL is unsupported or the
    ///   host cannot be resolved or the server fails the handshake.
    /// * `NetworkError::Io` if the TCP connect fails (e.g. connection
    ///   refused on an unreachable endpoint).
    /// * `NetworkError::Timeout` if connect or the handshake exceeds its
    ///   timeout.
    ///
    /// On any error the client is left disconnected.
    pub async fn connect(&mut self) -> Result<()> {
        // Already connected: re-verify liveness rather than trusting a
        // possibly-dead socket. If the peer is gone, fall through and
        // establish a fresh connection.
        if let Some(stream) = self.stream.as_mut() {
            if ping_pong(stream).await.is_ok() {
                return Ok(());
            }
        }
        self.stream = None;

        let endpoint = parse_server_url(&self.server_url)?;
        let addrs = resolve_endpoint(&endpoint).await?;

        let mut last_err: Option<NetworkError> = None;
        for addr in addrs {
            let connected = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await;
            match connected {
                Ok(Ok(mut stream)) => {
                    let _ = stream.set_nodelay(true);
                    match ping_pong(&mut stream).await {
                        Ok(()) => {
                            tracing::info!("Signaling client connected to {}", addr);
                            self.stream = Some(stream);
                            return Ok(());
                        }
                        Err(e) => {
                            // Handshake failed (EOF, garbage, timeout): this
                            // address does not speak the signaling protocol.
                            last_err = Some(e);
                        }
                    }
                }
                Ok(Err(e)) => last_err = Some(NetworkError::Io(e)),
                Err(_) => last_err = Some(NetworkError::Timeout),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            NetworkError::ConnectionFailed(format!(
                "could not connect to signaling server '{}'",
                self.server_url
            ))
        }))
    }

    /// Send a signaling message to the server.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::ConnectionFailed` if not connected. Socket
    /// errors are propagated and drop the connection.
    pub async fn send(&mut self, message: SignalingMessage) -> Result<()> {
        let mut stream = self.stream.take().ok_or_else(|| {
            NetworkError::ConnectionFailed("Signaling client not connected".to_string())
        })?;

        let result = write_frame(&mut stream, &WireFrame::Message { message }).await;

        match result {
            Ok(()) => {
                self.stream = Some(stream);
                Ok(())
            }
            Err(e) => {
                // Write failed: the socket is dead. Drop it so the client
                // does not keep claiming a broken connection.
                self.stream = None;
                Err(e)
            }
        }
    }

    /// Receive a signaling message from the server.
    ///
    /// Answers server-initiated `ping` frames with `pong` while waiting.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::ConnectionFailed` if not connected. EOF or
    /// socket errors are propagated and mark the client disconnected.
    pub async fn receive(&mut self) -> Result<SignalingMessage> {
        let mut stream = self.stream.take().ok_or_else(|| {
            NetworkError::ConnectionFailed("Signaling client not connected".to_string())
        })?;

        let result = loop {
            match read_frame(&mut stream).await {
                Ok(WireFrame::Message { message }) => break Ok(message),
                Ok(WireFrame::Ping) => {
                    if let Err(e) = write_frame(&mut stream, &WireFrame::Pong).await {
                        break Err(e);
                    }
                }
                // Unsolicited pong (no outstanding ping of ours): ignore.
                Ok(WireFrame::Pong) => {}
                Err(e) => break Err(e),
            }
        };

        match result {
            Ok(message) => {
                self.stream = Some(stream);
                Ok(message)
            }
            Err(e) => {
                self.stream = None;
                Err(e)
            }
        }
    }

    /// Close the connection to the signaling server.
    pub async fn close(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
        }
    }

    /// Check if the client is connected.
    ///
    /// True only while a live, handshake-verified socket is held.
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Get the server URL
    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}

/// Normalize a signaling server URL into a `host:port` endpoint.
///
/// Accepts `host:port`, `tcp://host:port`, and bracketed IPv6 literals.
/// Explicitly rejects `ws://`/`wss://` URLs: no WebSocket transport is
/// implemented, and silently treating one as a raw TCP endpoint would
/// misrepresent the connection.
fn parse_server_url(url: &str) -> Result<String> {
    let url = url.trim();
    if let Some(rest) = url.strip_prefix("tcp://") {
        return Ok(rest.to_string());
    }
    if url.starts_with("ws://") || url.starts_with("wss://") {
        return Err(NetworkError::ConnectionFailed(
            "websocket signaling transport not implemented; use tcp://host:port or host:port"
                .to_string(),
        ));
    }
    if url.contains("://") {
        return Err(NetworkError::ConnectionFailed(format!(
            "unsupported signaling server URL: {url}"
        )));
    }
    Ok(url.to_string())
}

/// Resolve a `host:port` endpoint to concrete socket addresses.
async fn resolve_endpoint(endpoint: &str) -> Result<Vec<SocketAddr>> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(endpoint).await?.collect();
    if addrs.is_empty() {
        return Err(NetworkError::ConnectionFailed(format!(
            "could not resolve signaling server: {endpoint}"
        )));
    }
    Ok(addrs)
}

/// Perform a ping/pong liveness round trip on an open socket.
///
/// Sends `ping` and waits for `pong`, replying to any server-initiated
/// `ping` frames while waiting. Bounded by `PONG_TIMEOUT`.
async fn ping_pong(stream: &mut TcpStream) -> Result<()> {
    write_frame(stream, &WireFrame::Ping).await?;

    tokio::time::timeout(PONG_TIMEOUT, async {
        loop {
            match read_frame(stream).await {
                Ok(WireFrame::Pong) => return Ok(()),
                Ok(WireFrame::Ping) => {
                    write_frame(stream, &WireFrame::Pong).await?;
                }
                Ok(WireFrame::Message { .. }) => {
                    return Err(NetworkError::ConnectionFailed(
                        "signaling server sent a message before completing the handshake"
                            .to_string(),
                    ));
                }
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .map_err(|_| NetworkError::Timeout)?
}

/// Write a single length-prefixed frame to the socket.
async fn write_frame(stream: &mut TcpStream, frame: &WireFrame) -> Result<()> {
    let payload = serde_json::to_vec(frame).map_err(|e| {
        NetworkError::ConnectionFailed(format!("failed to encode signaling frame: {e}"))
    })?;
    let len: u32 = payload.len().try_into().map_err(|_| {
        NetworkError::ConnectionFailed(format!(
            "signaling frame too large for length prefix: {} bytes",
            payload.len()
        ))
    })?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

/// Read a single length-prefixed frame from the socket.
async fn read_frame(stream: &mut TcpStream) -> Result<WireFrame> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(NetworkError::ConnectionFailed(format!(
            "signaling frame too large: {len} bytes (limit {MAX_FRAME_SIZE})"
        )));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;

    serde_json::from_slice(&payload).map_err(|e| {
        NetworkError::ConnectionFailed(format!("malformed signaling frame from server: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawn a minimal real signaling server on a loopback ephemeral port
    /// implementing the documented protocol: answers `ping` with `pong`
    /// and echoes `message` frames back. Serves a single connection.
    fn spawn_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking for tokio");
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        let addr = listener.local_addr().expect("listener address");

        let handle = tokio::spawn(async move {
            let Ok((mut socket, _peer)) = listener.accept().await else {
                return;
            };
            loop {
                match read_frame(&mut socket).await {
                    Ok(WireFrame::Ping) => {
                        if write_frame(&mut socket, &WireFrame::Pong).await.is_err() {
                            break;
                        }
                    }
                    Ok(WireFrame::Message { message }) => {
                        if write_frame(&mut socket, &WireFrame::Message { message })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(WireFrame::Pong) => {}
                    Err(_) => break,
                }
            }
        });

        (addr, handle)
    }

    fn join_msg() -> SignalingMessage {
        SignalingMessage::Join {
            room_code: "test".to_string(),
            peer_id: "peer1".to_string(),
        }
    }

    #[tokio::test]
    async fn test_connect_to_real_listener_succeeds() {
        let (addr, server) = spawn_echo_server();
        let mut client = SignalingClient::new(format!("tcp://{addr}"));
        assert!(!client.is_connected());

        client.connect().await.expect("real listener must accept");
        assert!(
            client.is_connected(),
            "is_connected must be true only after a live, handshake-verified socket"
        );
        client.close().await;
        assert!(!client.is_connected(), "close must drop the connection");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_double_connect_is_verified_noop() {
        let (addr, server) = spawn_echo_server();
        let mut client = SignalingClient::new(addr.to_string());
        client.connect().await.unwrap();
        // Second connect re-verifies liveness over the live socket.
        client.connect().await.unwrap();
        assert!(client.is_connected());
        client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_to_unreachable_endpoint_returns_err() {
        // Bind then drop: the port is guaranteed closed, so the connect is
        // refused rather than hanging.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind probe listener")
            .local_addr()
            .expect("probe address");

        let mut client = SignalingClient::new(addr.to_string());
        let err = client.connect().await;
        assert!(
            err.is_err(),
            "connecting to a closed port must fail honestly, got: {err:?}"
        );
        assert!(
            !client.is_connected(),
            "failed connect must not report connected"
        );

        // A failed client is not usable as if it were connected.
        assert!(client.send(join_msg()).await.is_err());
        assert!(client.receive().await.is_err());
    }

    #[tokio::test]
    async fn test_connect_rejects_non_signaling_peer() {
        // A TCP listener that accepts but does not speak the signaling
        // protocol (drops the connection immediately) must fail the
        // handshake, not report success.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let _ = listener.accept().await; // accept then drop => EOF on client read
        });

        let mut client = SignalingClient::new(addr.to_string());
        let err = client.connect().await;
        assert!(
            err.is_err(),
            "peer that never pongs must fail the handshake, got: {err:?}"
        );
        assert!(!client.is_connected());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_receive_roundtrip_over_real_socket() {
        let (addr, server) = spawn_echo_server();
        let mut client = SignalingClient::new(format!("tcp://{addr}"));
        client.connect().await.unwrap();

        let sent = SignalingMessage::Offer {
            to: "peer-b".to_string(),
            sdp: "v=0\r\no=- 123 456 IN IP4 127.0.0.1".to_string(),
        };
        client
            .send(sent.clone())
            .await
            .expect("send over live socket");

        let got = client.receive().await.expect("echoed over live socket");
        assert!(
            matches!(&got, SignalingMessage::Offer { to, sdp } if to == "peer-b" && sdp.starts_with("v=0"))
        );
        let _ = sent;

        client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_without_connect_errs() {
        let mut client = SignalingClient::new("127.0.0.1:9".to_string());
        assert!(!client.is_connected());
        assert!(client.send(join_msg()).await.is_err());
    }

    #[tokio::test]
    async fn test_receive_without_connect_errs() {
        let mut client = SignalingClient::new("127.0.0.1:9".to_string());
        assert!(client.receive().await.is_err());
    }

    #[tokio::test]
    async fn test_server_ping_answered_and_close_detected() {
        // Server: complete the handshake, send its own ping, then drop.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let Ok((mut socket, _peer)) = listener.accept().await else {
                return;
            };
            // Answer the client's handshake ping.
            if let Ok(WireFrame::Ping) = read_frame(&mut socket).await {
                let _ = write_frame(&mut socket, &WireFrame::Pong).await;
            }
            // Server-initiated ping, then hang up.
            let _ = write_frame(&mut socket, &WireFrame::Ping).await;
            drop(socket);
        });

        let mut client = SignalingClient::new(addr.to_string());
        client.connect().await.expect("handshake succeeds");

        // The server's ping is answered (or the write of the pong fails on
        // the closed socket); either way the subsequent EOF must surface as
        // an error and the client must stop reporting connected.
        let err = client.receive().await;
        assert!(err.is_err(), "EOF after server close must error: {err:?}");
        assert!(
            !client.is_connected(),
            "a dead socket must not report connected"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_unsupported_scheme_rejected() {
        // No WebSocket transport exists in v1; claiming a ws:// connection
        // would be channel fiction. It must fail loudly instead.
        let mut client = SignalingClient::new("ws://localhost:8080".to_string());
        let err = client.connect().await;
        assert!(err.is_err());
        assert!(!client.is_connected());

        let mut client = SignalingClient::new("http://localhost:8080".to_string());
        assert!(client.connect().await.is_err());
    }

    #[tokio::test]
    async fn test_invalid_endpoint_rejected() {
        let mut client = SignalingClient::new("not an endpoint".to_string());
        assert!(client.connect().await.is_err());
        assert!(!client.is_connected());
    }
}
