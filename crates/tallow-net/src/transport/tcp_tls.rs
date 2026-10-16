//! TCP+TLS transport implementation
//!
//! Fallback transport for networks where QUIC is blocked.
//! Uses tokio_rustls for TLS over TCP with the same framing as QUIC.
//!
//! R-08 batch-3 (#131/#132 · design P4-3): adds Happy Eyeballs v2 (RFC 8305)
//! dual-stack connect so the TCP+TLS fallback picks a working address family
//! quickly ([`connect_happy_eyeballs`], [`interleave_addresses`]) and a
//! blocking entry point ([`connect_std`]) for the synchronous relay client.

use crate::{NetworkError, Result, Transport};
use futures::StreamExt;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// Default RFC 8305 §5 "Connection Attempt Delay" (RECOMMENDED 250 ms).
pub const HAPPY_EYEBALLS_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// TCP with TLS transport
pub struct TcpTlsTransport {
    /// TLS-wrapped TCP stream
    stream: Option<TlsStream<TcpStream>>,
}

impl std::fmt::Debug for TcpTlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTlsTransport")
            .field("connected", &self.stream.is_some())
            .finish()
    }
}

impl TcpTlsTransport {
    /// Create a new TCP+TLS transport
    pub fn new() -> Self {
        Self { stream: None }
    }

    /// Close the transport gracefully
    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
        }
        Ok(())
    }

    /// Connect to `host:port` with Happy Eyeballs v2 (RFC 8305) before the TLS
    /// handshake. `server_name` is the TLS SNI/certificate name (defaults to
    /// `host`).
    ///
    /// This is the dual-stack entry point used when the peer is named (not an
    /// IP literal); [`TcpTlsTransport::connect`] keeps the single-address path.
    pub async fn connect_host(&mut self, host: &str, port: u16) -> Result<()> {
        let std_stream = connect_std(host, port).await?;
        // tokio sockets must be in nonblocking mode before adoption.
        std_stream
            .set_nonblocking(true)
            .map_err(|e| NetworkError::ConnectionFailed(format!("nonblocking mode failed: {e}")))?;
        let tcp_stream = TcpStream::from_std(std_stream).map_err(|e| {
            NetworkError::ConnectionFailed(format!("adopting TCP socket into tokio failed: {e}"))
        })?;

        let tls_config = super::tls_config::rustls_client_config()?;
        let connector = tokio_rustls::TlsConnector::from(tls_config);

        let server_name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|e| NetworkError::TlsError(format!("invalid server name '{}': {}", host, e)))?
            .to_owned();

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| NetworkError::TlsError(format!("TLS handshake failed: {}", e)))?;

        // PQ posture (P4-6): the cohort offers X25519MLKEM768 first, so a
        // completed handshake that dropped the hybrid group must be loud,
        // never silent.
        let group = super::tls_cohort::negotiated_kex_group(tls_stream.get_ref().1);
        super::tls_cohort::alarm_on_classical_kex(host, group);

        self.stream = Some(tls_stream);
        Ok(())
    }
}

impl Default for TcpTlsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for TcpTlsTransport {
    async fn connect(&mut self, addr: SocketAddr) -> Result<()> {
        let tcp_stream = TcpStream::connect(addr)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("TCP connect failed: {}", e)))?;

        let tls_config = super::tls_config::rustls_client_config()?;
        let connector = tokio_rustls::TlsConnector::from(tls_config);

        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .map_err(|e| NetworkError::TlsError(format!("invalid server name: {}", e)))?
            .to_owned();

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| NetworkError::TlsError(format!("TLS handshake failed: {}", e)))?;

        // PQ posture (P4-6): same fail-loud rule as `connect_host`.
        let group = super::tls_cohort::negotiated_kex_group(tls_stream.get_ref().1);
        super::tls_cohort::alarm_on_classical_kex(&addr.to_string(), group);

        self.stream = Some(tls_stream);
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<usize> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("not connected".to_string()))?;

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
            .map_err(|e| NetworkError::ConnectionFailed(format!("TCP write len failed: {}", e)))?;

        // Write payload
        stream
            .write_all(data)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("TCP write failed: {}", e)))?;

        Ok(data.len())
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("not connected".to_string()))?;

        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("TCP read len failed: {}", e)))?;

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
            .map_err(|e| NetworkError::ConnectionFailed(format!("TCP read failed: {}", e)))?;

        Ok(len)
    }
}

// ── Happy Eyeballs v2 (RFC 8305) ─────────────────────────────────────────────

/// Order a resolved address list per RFC 8305 §4.
///
/// The first address keeps its position (the resolver's preference — IPv6
/// first when the system returns it), then families alternate so a broken
/// family does not delay the connection by the whole list.
pub fn interleave_addresses(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addrs.iter().copied().partition(|a| a.is_ipv6());
    if v6.is_empty() || v4.is_empty() {
        return addrs.to_vec();
    }
    let mut out = Vec::with_capacity(addrs.len());
    let mut i = 0;
    while i < v6.len() || i < v4.len() {
        if i < v6.len() {
            out.push(v6[i]);
        }
        if i < v4.len() {
            out.push(v4[i]);
        }
        i += 1;
    }
    out
}

/// One in-flight connection attempt in the Happy Eyeballs race.
type ConnectAttempt = std::pin::Pin<
    Box<dyn std::future::Future<Output = (SocketAddr, std::io::Result<TcpStream>)> + Send>,
>;

/// Race TCP connection attempts per Happy Eyeballs v2 (RFC 8305): the first
/// address is attempted immediately, the next starts `attempt_delay` later (or
/// immediately after a failure), and the first successful connection wins.
pub async fn connect_happy_eyeballs(
    addrs: Vec<SocketAddr>,
    attempt_delay: Duration,
) -> Result<TcpStream> {
    if addrs.is_empty() {
        return Err(NetworkError::DnsResolution(
            "happy eyeballs: no addresses to try".to_string(),
        ));
    }

    let ordered = interleave_addresses(&addrs);
    let mut queue: VecDeque<SocketAddr> = ordered.into();
    let total = queue.len();
    let mut inflight: futures::stream::FuturesUnordered<ConnectAttempt> =
        futures::stream::FuturesUnordered::new();
    let mut last_err: Option<std::io::Error> = None;
    let mut launch_next = true;

    loop {
        if launch_next {
            if let Some(addr) = queue.pop_front() {
                inflight.push(Box::pin(
                    async move { (addr, TcpStream::connect(addr).await) },
                ));
                launch_next = false;
            }
        }

        if inflight.is_empty() {
            let detail = last_err
                .map(|e| format!("last error: {e}"))
                .unwrap_or_else(|| "no attempt completed".to_string());
            return Err(NetworkError::ConnectionFailed(format!(
                "happy eyeballs: all {total} address(es) failed ({detail})"
            )));
        }

        let timer = tokio::time::sleep(attempt_delay);
        tokio::select! {
            next = inflight.next() => {
                match next {
                    Some((_addr, Ok(stream))) => {
                        // First successful connection wins; other attempts drop.
                        return Ok(stream);
                    }
                    Some((_addr, Err(e))) => {
                        last_err = Some(e);
                        // RFC 8305 §5: on failure, start the next attempt
                        // immediately instead of waiting out the delay.
                        launch_next = !queue.is_empty();
                    }
                    None => {}
                }
            }
            _ = timer => {
                // Delay elapsed with an attempt still in flight: start the next
                // candidate in parallel (the actual HE behavior).
                launch_next = !queue.is_empty();
            }
        }
    }
}

/// Resolve `host:port` and return the connected socket without any TLS
/// (Happy Eyeballs v2), for synchronous callers.
///
/// The returned stream is a blocking `std::net::TcpStream` (converted from the
/// tokio socket), so socket timeouts and the std `Read`/`Write` traits behave
/// as usual.
pub async fn connect_std(host: &str, port: u16) -> Result<std::net::TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| NetworkError::DnsResolution(format!("resolve '{host}:{port}' failed: {e}")))?
        .collect();
    let stream = connect_happy_eyeballs(addrs, HAPPY_EYEBALLS_ATTEMPT_DELAY).await?;
    let std_stream = stream.into_std().map_err(|e| {
        NetworkError::ConnectionFailed(format!("converting to blocking socket failed: {e}"))
    })?;
    // Back to blocking mode: a synchronous caller (relay client) uses
    // SO_RCVTIMEO/SO_SNDTIMEO semantics, which only apply to blocking sockets.
    std_stream
        .set_nonblocking(false)
        .map_err(|e| NetworkError::ConnectionFailed(format!("blocking mode failed: {e}")))?;
    Ok(std_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }
    fn v6(port: u16) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port))
    }

    #[test]
    fn test_interleave_dual_stack_alternates() {
        let addrs = vec![v6(1), v6(2), v6(3), v4(1), v4(2)];
        let out = interleave_addresses(&addrs);
        assert_eq!(
            out,
            vec![v6(1), v4(1), v6(2), v4(2), v6(3)],
            "v6 first, then alternating families"
        );
    }

    #[test]
    fn test_interleave_single_family_unchanged() {
        let only4 = vec![v4(1), v4(2), v4(3)];
        assert_eq!(interleave_addresses(&only4), only4);
        let only6 = vec![v6(1), v6(2)];
        assert_eq!(interleave_addresses(&only6), only6);
    }

    #[test]
    fn test_interleave_v4_first_preserved_when_no_v6() {
        let addrs = vec![v4(9), v4(8), v4(7)];
        assert_eq!(interleave_addresses(&addrs), vec![v4(9), v4(8), v4(7)]);
    }

    #[tokio::test]
    async fn test_happy_eyeballs_picks_live_address_after_fast_failure() {
        // Race a refused port with a live listener: the refused attempt fails
        // immediately and must not delay the live one (no 250 ms wait needed
        // for correctness, only for the second launch).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        let dead = v4(1); // port 1: connection refused on loopback
        let stream = connect_happy_eyeballs(vec![dead, live], Duration::from_millis(250))
            .await
            .expect("live address must win the race");
        assert_eq!(stream.peer_addr().unwrap(), live);
    }

    #[tokio::test]
    async fn test_happy_eyeballs_all_fail_is_connection_error() {
        let err = connect_happy_eyeballs(vec![v4(1), v4(2)], Duration::from_millis(50))
            .await
            .unwrap_err();
        match err {
            NetworkError::ConnectionFailed(msg) => {
                assert!(msg.contains("all 2 address"), "message: {msg}");
            }
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_connect_std_loopback_hostname() {
        // `localhost` resolves to a dual-stack list on this box; the fixture
        // binds IPv4 only, so the ::1 attempt fails and IPv4 wins.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });
        let stream = connect_std("localhost", port).await.unwrap();
        assert!(stream.peer_addr().unwrap().is_ipv4());
        accept.await.unwrap();
    }

    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test]
    async fn test_tls_transport_connect_host_loopback() {
        // Full dual-stack TCP+TLS path against a local TLS fixture.
        let identity = super::super::tls_config::generate_self_signed().unwrap();
        let server_cfg = super::super::tls_config::rustls_server_config(&identity).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await.unwrap();
        });

        let mut t = TcpTlsTransport::new();
        t.connect_host("localhost", port)
            .await
            .expect("TLS over happy-eyeballs TCP");

        // P4-6: the completed handshake must expose its key-exchange group, and
        // between two Tallow configs (hybrid offered first on both ends) it
        // must land on the hybrid group — a classical result here would be a
        // real downgrade signal, not a test artifact.
        let group =
            super::super::tls_cohort::negotiated_kex_group(t.stream.as_ref().unwrap().get_ref().1);
        assert!(
            group.is_some(),
            "handshake key-exchange group must be readable"
        );
        super::super::tls_cohort::assert_pq_hybrid_kex_group("loopback", group)
            .unwrap_or_else(|alarm| panic!("{alarm} (negotiated group {group:?})"));
    }

    /// P4-6: a server that offers only a classical group must be classified as
    /// a silent PQ downgrade — the completed handshake exposes the classical
    /// group and the assert fails loudly (the alarm path fires end-to-end).
    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test]
    async fn test_pq_downgrade_detected_on_classical_only_handshake() {
        // Server provider limited to classical X25519; the client still offers
        // X25519MLKEM768 first, so the server must pick X25519.
        let identity = super::super::tls_config::generate_self_signed().unwrap();
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = provider
            .kx_groups
            .iter()
            .copied()
            .filter(|g| u16::from(g.name()) == 0x001d)
            .collect();
        assert_eq!(
            provider.kx_groups.len(),
            1,
            "test server must offer exactly classical X25519"
        );
        let server_cfg = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(identity.chain(), identity.key_der.clone_key().into())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await.unwrap();
        });

        let mut t = TcpTlsTransport::new();
        t.connect_host("localhost", port)
            .await
            .expect("TLS over happy-eyeballs TCP (classical-only server)");

        let group =
            super::super::tls_cohort::negotiated_kex_group(t.stream.as_ref().unwrap().get_ref().1);
        assert_eq!(
            group,
            Some(0x001d),
            "classical-only server must negotiate X25519"
        );
        let err = super::super::tls_cohort::assert_pq_hybrid_kex_group("loopback-classical", group)
            .expect_err("classical-only negotiation must fail the PQ assert");
        assert!(err.contains("PQ-DOWNGRADE ALARM"), "alarm text: {err}");
    }
}
