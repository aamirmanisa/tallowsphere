//! Loopback test fixtures for transport integration tests.
//!
//! **Not a production API.** This module exists so integration tests (including
//! the root crate's `tests/transfer_transport.rs`, which cannot depend on
//! `tokio-rustls` directly) can exercise the real SOCKS5 → TLS 1.3 route with
//! real fixtures instead of mocks:
//!
//! * [`Socks5Fixture`] — minimal SOCKS5 (no-auth, CONNECT) proxy that records
//!   the requested target and dials a fixed upstream. A **named** target only
//!   reaches it when the client used remote DNS (Tor-mode semantics).
//! * [`TlsEchoFixture`] — TLS 1.3 echo server (self-signed; accepted by
//!   clients built with the `dangerous_skip_verify` opt-in). Records the negotiated
//!   protocol version per connection.
//! * [`RelayFixture`] — relay-v1 pairing fixture (plaintext or TLS 1.3) that
//!   speaks the `TALLOW-SEND\n<code>\n\x01` / `TALLOW-RECV` preamble, pairs
//!   clients by code phrase and pipes bytes — the loopback stand-in for
//!   `tallow relay` with a TLS listener.
//!
//! Fixtures bind `127.0.0.1:0` (kernel-assigned port; nothing leaves the box)
//! and live until the test process exits.

use crate::{NetworkError, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// ── Shared async stream plumbing ────────────────────────────────────────────

trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> AsyncReadWrite for T {}

type DynStream = Box<dyn AsyncReadWrite + Unpin + Send>;

/// Connection wrapper that keeps bytes buffered past the relay-v1 preamble
/// (line reads) available to the piping phase.
struct BufferedConn {
    inner: tokio::io::BufReader<DynStream>,
}

impl BufferedConn {
    fn new(stream: DynStream) -> Self {
        Self {
            inner: tokio::io::BufReader::new(stream),
        }
    }
}

impl tokio::io::AsyncRead for BufferedConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for BufferedConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner.get_mut()).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner.get_mut()).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner.get_mut()).poll_shutdown(cx)
    }
}

/// Build a 2-worker runtime and run `fut` on a detached thread (fixtures run
/// for the lifetime of the test process).
fn spawn_runtime_thread<F>(name: &str, fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name(name.to_string())
        .build()
        .expect("fixture runtime");
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            rt.block_on(fut);
        })
        .expect("fixture thread");
}

fn tls_server_config() -> Arc<rustls::ServerConfig> {
    let identity = super::tls_config::generate_self_signed().expect("self-signed cert");
    super::tls_config::rustls_server_config(&identity).expect("rustls server config")
}

// ── SOCKS5 fixture ──────────────────────────────────────────────────────────

/// Minimal SOCKS5 proxy fixture (records CONNECT targets).
pub struct Socks5Fixture {
    /// Proxy listen address.
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<(String, u16)>>>,
    connects: Arc<AtomicUsize>,
}

impl Socks5Fixture {
    /// Start a SOCKS5 proxy that dials `upstream` for every CONNECT.
    pub fn start(upstream: SocketAddr) -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(NetworkError::Io)?;
        let addr = listener.local_addr().map_err(NetworkError::Io)?;
        listener.set_nonblocking(true).map_err(NetworkError::Io)?;
        let seen: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let connects = Arc::new(AtomicUsize::new(0));
        let seen_srv = seen.clone();
        let connects_srv = connects.clone();

        spawn_runtime_thread("tallow-socks5-fixture", async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => l,
                Err(_) => return,
            };
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let seen = seen_srv.clone();
                let connects = connects_srv.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut hdr = [0u8; 2];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; hdr[1] as usize];
                    if sock.read_exact(&mut methods).await.is_err() {
                        return;
                    }
                    if sock.write_all(&[0x05, 0x00]).await.is_err() {
                        return;
                    }
                    let mut req = [0u8; 4];
                    if sock.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let (host, port) = match req[3] {
                        0x01 => {
                            let mut a = [0u8; 4];
                            let mut p = [0u8; 2];
                            if sock.read_exact(&mut a).await.is_err()
                                || sock.read_exact(&mut p).await.is_err()
                            {
                                return;
                            }
                            (
                                std::net::Ipv4Addr::from(a).to_string(),
                                u16::from_be_bytes(p),
                            )
                        }
                        0x03 => {
                            let mut l = [0u8; 1];
                            if sock.read_exact(&mut l).await.is_err() {
                                return;
                            }
                            let mut name = vec![0u8; l[0] as usize];
                            let mut p = [0u8; 2];
                            if sock.read_exact(&mut name).await.is_err()
                                || sock.read_exact(&mut p).await.is_err()
                            {
                                return;
                            }
                            (
                                String::from_utf8_lossy(&name).to_string(),
                                u16::from_be_bytes(p),
                            )
                        }
                        0x04 => {
                            let mut a = [0u8; 16];
                            let mut p = [0u8; 2];
                            if sock.read_exact(&mut a).await.is_err()
                                || sock.read_exact(&mut p).await.is_err()
                            {
                                return;
                            }
                            (
                                std::net::Ipv6Addr::from(a).to_string(),
                                u16::from_be_bytes(p),
                            )
                        }
                        _ => return,
                    };
                    connects.fetch_add(1, Ordering::SeqCst);
                    seen.lock().unwrap().push((host, port));

                    let mut upstream = match tokio::net::TcpStream::connect(upstream).await {
                        Ok(s) => s,
                        Err(_) => {
                            let _ = sock
                                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                .await;
                            return;
                        }
                    };
                    if sock
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream).await;
                });
            }
        });

        Ok(Self {
            addr,
            seen,
            connects,
        })
    }

    /// CONNECT targets the proxy has observed, in order.
    pub fn targets(&self) -> Vec<(String, u16)> {
        self.seen.lock().unwrap().clone()
    }

    /// Number of completed SOCKS5 CONNECT requests.
    pub fn connects(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }
}

// ── TLS echo fixture ────────────────────────────────────────────────────────

/// TLS 1.3 echo server fixture (self-signed cert).
pub struct TlsEchoFixture {
    /// Listen port on 127.0.0.1.
    pub port: u16,
    versions: Arc<Mutex<Vec<String>>>,
}

impl TlsEchoFixture {
    /// Start the echo server and return its port.
    pub fn start() -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(NetworkError::Io)?;
        let port = listener.local_addr().map_err(NetworkError::Io)?.port();
        listener.set_nonblocking(true).map_err(NetworkError::Io)?;
        let versions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let versions_srv = versions.clone();
        let cfg = tls_server_config();

        spawn_runtime_thread("tallow-tls-echo-fixture", async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => l,
                Err(_) => return,
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let versions = versions_srv.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut tls = match acceptor.accept(stream).await {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    if let Some(v) = tls.get_ref().1.protocol_version() {
                        versions.lock().unwrap().push(format!("{v:?}"));
                    }
                    let mut buf = [0u8; 4096];
                    loop {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tls.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                                if tls.flush().await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        Ok(Self { port, versions })
    }

    /// Negotiated TLS versions observed (Debug strings, e.g. `TLSv1_3`).
    pub fn tls_versions(&self) -> Vec<String> {
        self.versions.lock().unwrap().clone()
    }
}

// ── Relay-v1 pairing fixture ────────────────────────────────────────────────

/// relay-v1 pairing fixture (plaintext or TLS 1.3), mirroring the shipped
/// relay's live-pairing semantics: clients announce `TALLOW-SEND`/`TALLOW-RECV`
/// with a code phrase, the fixture pairs the two roles and pipes bytes.
pub struct RelayFixture {
    /// Listen address.
    pub addr: SocketAddr,
    clients: Arc<Mutex<Vec<(String, String)>>>,
    versions: Arc<Mutex<Vec<String>>>,
}

impl RelayFixture {
    /// Start the fixture. `tls = true` terminates TLS 1.3 (self-signed cert).
    pub fn start(tls: bool) -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(NetworkError::Io)?;
        let addr = listener.local_addr().map_err(NetworkError::Io)?;
        listener.set_nonblocking(true).map_err(NetworkError::Io)?;
        let clients: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let versions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let clients_srv = clients.clone();
        let versions_srv = versions.clone();
        let cfg = if tls { Some(tls_server_config()) } else { None };

        spawn_runtime_thread("tallow-relay-fixture", async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => l,
                Err(_) => return,
            };
            let acceptor = cfg.map(tokio_rustls::TlsAcceptor::from);
            let waiting: Arc<Mutex<std::collections::HashMap<String, (char, BufferedConn)>>> =
                Arc::new(Mutex::new(std::collections::HashMap::new()));
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let clients = clients_srv.clone();
                let versions = versions_srv.clone();
                let waiting = waiting.clone();
                tokio::spawn(async move {
                    let conn: BufferedConn = match &acceptor {
                        Some(acc) => {
                            let tls = match acc.accept(stream).await {
                                Ok(t) => t,
                                Err(_) => return,
                            };
                            if let Some(v) = tls.get_ref().1.protocol_version() {
                                versions.lock().unwrap().push(format!("{v:?}"));
                            }
                            BufferedConn::new(Box::new(tls))
                        }
                        None => BufferedConn::new(Box::new(stream)),
                    };
                    handle_relay_client(conn, clients, waiting).await;
                });
            }
        });

        Ok(Self {
            addr,
            clients,
            versions,
        })
    }

    /// `(verb, code)` for every accepted client, in arrival order.
    pub fn clients(&self) -> Vec<(String, String)> {
        self.clients.lock().unwrap().clone()
    }

    /// Negotiated TLS versions observed (empty in plaintext mode).
    pub fn tls_versions(&self) -> Vec<String> {
        self.versions.lock().unwrap().clone()
    }
}

async fn handle_relay_client(
    mut conn: BufferedConn,
    clients: Arc<Mutex<Vec<(String, String)>>>,
    waiting: Arc<Mutex<std::collections::HashMap<String, (char, BufferedConn)>>>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let mut verb = String::new();
    let mut code = String::new();
    if conn.inner.read_line(&mut verb).await.is_err()
        || conn.inner.read_line(&mut code).await.is_err()
    {
        return;
    }
    let verb = verb.trim().to_string();
    let code = code.trim().to_string();
    let role = match verb.as_str() {
        "TALLOW-SEND" => 's',
        "TALLOW-RECV" => 'r',
        _ => return,
    };
    let mut ver = [0u8; 1];
    if conn.inner.read_exact(&mut ver).await.is_err() || ver[0] != 0x01 {
        return;
    }
    clients.lock().unwrap().push((verb, code.clone()));

    let partner = {
        let mut map = waiting.lock().unwrap();
        match map.get(&code).map(|(r, _)| *r) {
            Some(other) if other != role => map.remove(&code).map(|(_, c)| c),
            _ => None,
        }
    };
    match partner {
        Some(other) => {
            let (mut a, mut b) = if role == 's' {
                (conn, other)
            } else {
                (other, conn)
            };
            let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
        }
        None => {
            waiting.lock().unwrap().insert(code, (role, conn));
        }
    }
}
