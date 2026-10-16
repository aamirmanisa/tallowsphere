//! Proxied TCP+TLS transport for SOCKS5/Tor connections
//!
//! Connects through a SOCKS5 proxy, then wraps the tunnel in TLS.
//! Used when `--proxy` or `--tor` flags are active. QUIC cannot
//! traverse SOCKS5, so this TCP+TLS transport is the only option
//! when a proxy is configured.
//!
//! R-08 batch-3 (#131/#132 · design P4-3): adds a raw-stream entry point
//! ([`ProxiedTcpTlsTransport::connect_proxied_host`] + `into_stream`) and a
//! **blocking byte pipe** ([`ProxiedTunnel`]) over the SOCKS5→TLS stream so the
//! synchronous relay-v1 client (`tallow-protocol` `send_file<R: Read, W: Write>`)
//! can carry file data fail-closed over Tor.

use crate::privacy::{ProxyConfig, Socks5Connector};
use crate::{NetworkError, Result, Transport};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::info;

/// SOCKS5 connect + TLS handshake budget (Tor circuits can be slow).
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// In-memory duplex buffer between the async TLS pump and the blocking relay
/// client (2 × 256 KiB relay frames fit without stalling the pump).
const TUNNEL_BUFFER_BYTES: usize = 1 << 20;

/// Blocking read/write poll granularity: bounds how long a blocking caller
/// waits before it can observe a SIGINT flag / deadline (the relay client's
/// `InterruptibleIo` retries `WouldBlock`).
const TUNNEL_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// TCP+TLS transport that routes through a SOCKS5 proxy
pub struct ProxiedTcpTlsTransport {
    /// SOCKS5 connector for tunneling
    connector: Socks5Connector,
    /// TLS-wrapped TCP stream (after connection)
    stream: Option<TlsStream<TcpStream>>,
    /// Relay hostname for Tor mode (send to proxy for DNS resolution)
    relay_host: Option<String>,
    /// Relay port
    relay_port: u16,
    /// Whether to send hostname to proxy instead of resolved IP (Tor mode)
    use_hostname: bool,
}

impl std::fmt::Debug for ProxiedTcpTlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxiedTcpTlsTransport")
            .field("connected", &self.stream.is_some())
            .field("relay_host", &self.relay_host)
            .field("relay_port", &self.relay_port)
            .field("use_hostname", &self.use_hostname)
            .finish()
    }
}

impl ProxiedTcpTlsTransport {
    /// Create a new proxied transport
    ///
    /// # Arguments
    ///
    /// * `proxy_config` - SOCKS5 proxy configuration
    /// * `relay_host` - Optional relay hostname (for Tor DNS-via-proxy)
    /// * `relay_port` - Relay port
    pub fn new(proxy_config: &ProxyConfig, relay_host: Option<String>, relay_port: u16) -> Self {
        Self {
            connector: proxy_config.to_connector(),
            stream: None,
            relay_host,
            relay_port,
            use_hostname: proxy_config.tor_mode,
        }
    }

    /// Connect to the relay through the SOCKS5 proxy
    ///
    /// For Tor mode: sends hostname to proxy (DNS resolved inside Tor network).
    /// For generic SOCKS5: connects via pre-resolved IP address.
    pub async fn connect_proxied(&mut self, addr: SocketAddr) -> Result<()> {
        // 10-second timeout — Tor connections can be slow
        let tcp_stream = tokio::time::timeout(PROXY_CONNECT_TIMEOUT, self.connect_socks5(addr))
            .await
            .map_err(|_| {
                NetworkError::ConnectionFailed(
                    "SOCKS5 connection timed out (10s) — is the proxy running?".to_string(),
                )
            })??;

        self.finish_tls(tcp_stream).await
    }

    /// Connect to a named relay through the SOCKS5 proxy (hostname-aware).
    ///
    /// Tor mode: the hostname goes to the proxy (DNS inside Tor; `.onion`
    /// targets work). Generic SOCKS5: the hostname is resolved locally first
    /// (the proxy connection then carries a local-DNS caveat; prefer `socks5h`).
    pub async fn connect_proxied_host(&mut self, host: &str, port: u16) -> Result<()> {
        let tcp_stream = tokio::time::timeout(PROXY_CONNECT_TIMEOUT, async {
            if self.use_hostname {
                self.connector.connect_hostname(host, port).await
            } else {
                let addr = tokio::net::lookup_host((host, port))
                    .await
                    .map_err(|e| {
                        NetworkError::DnsResolution(format!("resolve '{host}:{port}': {e}"))
                    })?
                    .next()
                    .ok_or_else(|| {
                        NetworkError::DnsResolution(format!("no addresses for '{host}:{port}'"))
                    })?;
                self.connector.connect(addr).await
            }
        })
        .await
        .map_err(|_| {
            NetworkError::ConnectionFailed(
                "SOCKS5 connection timed out (10s) — is the proxy running?".to_string(),
            )
        })??;

        self.finish_tls(tcp_stream).await
    }

    /// TLS-wrap the SOCKS5 tunnel (shared by both connect entry points).
    async fn finish_tls(&mut self, tcp_stream: TcpStream) -> Result<()> {
        // Wrap in TLS
        let tls_config = super::tls_config::rustls_client_config()?;
        let tls_connector = tokio_rustls::TlsConnector::from(tls_config);

        // SNI: use relay hostname when available, fall back to "localhost"
        let sni = self.relay_host.as_deref().unwrap_or("localhost");
        let server_name = rustls::pki_types::ServerName::try_from(sni)
            .map_err(|e| NetworkError::TlsError(format!("invalid server name '{}': {}", sni, e)))?
            .to_owned();

        // ECH (RFC 9849, U-105): for clearnet relay names the TLS ClientHello
        // SNI is on-path metadata (and proxy-visible for generic SOCKS5).
        // Warn when ECH is not active; .onion/local/IP names are skipped.
        super::ech::warn_if_ech_absent(sni, false);

        let tls_stream = tls_connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| {
                NetworkError::TlsError(format!("TLS handshake via proxy failed: {}", e))
            })?;

        // PQ posture (P4-6): same fail-loud rule as the direct TCP+TLS path —
        // a proxied relay connection that dropped the hybrid group must alarm.
        let group = super::tls_cohort::negotiated_kex_group(tls_stream.get_ref().1);
        super::tls_cohort::alarm_on_classical_kex(sni, group);

        info!(
            "connected to relay via SOCKS5 proxy (tor_mode={})",
            self.use_hostname
        );

        self.stream = Some(tls_stream);
        Ok(())
    }

    /// Take the raw TLS stream (byte pipe, no framing).
    ///
    /// Used by [`ProxiedTunnel`] to wrap the tunnel in the relay-v1 frame
    /// layer; returns `None` before a successful connect.
    pub fn into_stream(mut self) -> Option<TlsStream<TcpStream>> {
        self.stream.take()
    }

    /// Establish the SOCKS5→TLS tunnel and return a **blocking** byte pipe.
    ///
    /// The relay-v1 client is synchronous; the async stream is bridged through
    /// an in-memory duplex pump on a dedicated runtime thread. Each blocking
    /// read/write waits at most [`TUNNEL_POLL_INTERVAL`] before returning
    /// `WouldBlock`, so callers can stay interruptible.
    pub fn connect_blocking_tunnel(
        proxy: &ProxyConfig,
        relay_host: &str,
        relay_port: u16,
    ) -> Result<ProxiedTunnel> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tallow-proxied-tunnel")
            .build()
            .map_err(|e| NetworkError::ConnectionFailed(format!("tunnel runtime failed: {e}")))?;
        let handle = rt.handle().clone();

        let (client, server) = tokio::io::duplex(TUNNEL_BUFFER_BYTES);

        // Establish the tunnel *before* spawning the pump so connect errors
        // surface to the caller instead of turning into an opaque EOF.
        let mut transport =
            ProxiedTcpTlsTransport::new(proxy, Some(relay_host.to_string()), relay_port);
        rt.block_on(transport.connect_proxied_host(relay_host, relay_port))?;
        let mut tls = transport.into_stream().ok_or_else(|| {
            NetworkError::ConnectionFailed(
                "proxy tunnel reported success without a stream".to_string(),
            )
        })?;

        // The pump owns both the runtime and the TLS stream. It ends when the
        // blocking halves are dropped (duplex EOF), then the runtime shuts down
        // inside that thread — never blocking the caller.
        std::thread::Builder::new()
            .name("tallow-proxied-pump".to_string())
            .spawn(move || {
                rt.block_on(async move {
                    let mut server = server;
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut server).await;
                });
            })
            .map_err(|e| {
                NetworkError::ConnectionFailed(format!("tunnel pump thread failed: {e}"))
            })?;

        let (read_half, write_half) = tokio::io::split(client);
        Ok(ProxiedTunnel {
            reader: TunnelReader {
                handle: handle.clone(),
                inner: read_half,
                poll: TUNNEL_POLL_INTERVAL,
            },
            writer: TunnelWriter {
                handle,
                inner: write_half,
                poll: TUNNEL_POLL_INTERVAL,
            },
        })
    }

    /// Establish the SOCKS5 tunnel (hostname or IP mode)
    async fn connect_socks5(&self, addr: SocketAddr) -> Result<TcpStream> {
        if self.use_hostname {
            // Tor mode: send hostname to proxy for DNS resolution inside the network
            if let Some(ref host) = self.relay_host {
                self.connector.connect_hostname(host, self.relay_port).await
            } else {
                // Fallback: no hostname available, use IP directly
                self.connector.connect(addr).await
            }
        } else {
            // Generic SOCKS5: use pre-resolved IP address
            self.connector.connect(addr).await
        }
    }

    /// Close the transport gracefully
    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
        }
        Ok(())
    }
}

impl Transport for ProxiedTcpTlsTransport {
    async fn connect(&mut self, addr: SocketAddr) -> Result<()> {
        self.connect_proxied(addr).await
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

// ── Blocking byte pipe over the proxied TLS tunnel (relay-v1 client) ─────────

/// Blocking byte pipe over a SOCKS5→TLS tunnel, split into read/write halves.
///
/// Both halves are `std::io::{Read, Write}` and may be handed to
/// `tallow_protocol::transfer::relay::send_file`/`receive_file` directly.
pub struct ProxiedTunnel {
    /// Blocking read half (peer → us).
    pub reader: TunnelReader,
    /// Blocking write half (us → peer).
    pub writer: TunnelWriter,
}

/// Blocking read half of a [`ProxiedTunnel`].
pub struct TunnelReader {
    handle: tokio::runtime::Handle,
    inner: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    poll: Duration,
}

/// Blocking write half of a [`ProxiedTunnel`].
pub struct TunnelWriter {
    handle: tokio::runtime::Handle,
    inner: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    poll: Duration,
}

impl std::fmt::Debug for ProxiedTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxiedTunnel").finish_non_exhaustive()
    }
}

impl std::io::Read for TunnelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let TunnelReader {
            handle,
            inner,
            poll,
        } = self;
        let poll = *poll;
        // The timeout future is *constructed* inside `block_on` so it is built
        // with the runtime context (constructing a timer outside any runtime
        // context panics).
        handle.block_on(async move {
            match tokio::time::timeout(poll, tokio::io::AsyncReadExt::read(inner, buf)).await {
                Ok(result) => result,
                Err(_elapsed) => Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "proxied tunnel read poll timeout",
                )),
            }
        })
    }
}

impl std::io::Write for TunnelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let TunnelWriter {
            handle,
            inner,
            poll,
        } = self;
        let poll = *poll;
        handle.block_on(async move {
            match tokio::time::timeout(poll, tokio::io::AsyncWriteExt::write(inner, buf)).await {
                Ok(result) => result,
                Err(_elapsed) => Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "proxied tunnel write poll timeout",
                )),
            }
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let TunnelWriter {
            handle,
            inner,
            poll,
        } = self;
        let poll = *poll;
        handle.block_on(async move {
            match tokio::time::timeout(poll, tokio::io::AsyncWriteExt::flush(inner)).await {
                Ok(result) => result,
                Err(_elapsed) => Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "proxied tunnel flush poll timeout",
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxied_transport_new() {
        let config = ProxyConfig::tor_default();
        let transport =
            ProxiedTcpTlsTransport::new(&config, Some("relay.example.com".to_string()), 4433);
        assert!(transport.stream.is_none());
        assert_eq!(transport.relay_port, 4433);
        assert!(transport.use_hostname);
        assert_eq!(transport.relay_host.as_deref(), Some("relay.example.com"));
    }

    #[tokio::test]
    async fn test_proxied_transport_not_connected() {
        let config = ProxyConfig::tor_default();
        let mut transport = ProxiedTcpTlsTransport::new(&config, None, 4433);

        // send before connect should error
        let send_result = transport.send(b"hello").await;
        assert!(send_result.is_err());

        // receive before connect should error
        let mut buf = [0u8; 64];
        let recv_result = transport.receive(&mut buf).await;
        assert!(recv_result.is_err());
    }

    #[test]
    fn test_into_stream_before_connect_is_none() {
        let config = ProxyConfig::tor_default();
        let transport = ProxiedTcpTlsTransport::new(&config, None, 4433);
        assert!(transport.into_stream().is_none());
    }

    #[test]
    fn test_blocking_tunnel_connect_refused_when_proxy_down() {
        // No SOCKS5 listener on this port: the connect must fail (and must not
        // hang beyond the 10 s budget).
        let mut cfg = ProxyConfig::tor_default();
        cfg.socks5_addr = "127.0.0.1:1".parse().unwrap();
        cfg.tor_mode = false;
        let err =
            ProxiedTcpTlsTransport::connect_blocking_tunnel(&cfg, "127.0.0.1", 4433).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("SOCKS5") || msg.contains("Connection"),
            "message: {msg}"
        );
    }
}
