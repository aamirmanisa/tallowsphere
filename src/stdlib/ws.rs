//! Standard library: `tallow.ws` — WebSocket client for real-time data feeds.
//!
//! Connects to WebSocket servers and receives streaming messages.
//! Supports text and binary frames, over `ws://` **and** `wss://` (TLS via
//! rustls with the webpki root store).
//!
//! # API
//! - `WS.connect(url)` — connect to a WebSocket server
//! - `ws.recv()` — receive next message (blocking with timeout)
//! - `ws.recv_all(limit)` — receive all available messages
//! - `ws.send(text)` — send a text message
//! - `ws.close()` — close the connection
//!
//! # Handle model (why there is a registry)
//!
//! The connection is NOT stored in the struct's fields. `dispatch_method`
//! receives the object by reference and returns a fresh `Value`, so it cannot
//! mutate the caller's binding: with the connection inline, `ws.send(x)` would
//! write to a throwaway copy while a later `ws.recv()` read a *different* one.
//! The handle therefore carries only an `id` and the live socket lives in the
//! registry below — the same pattern `stdlib/sync.rs` uses for atomics and
//! `stdlib/fs.rs` for watchers.
//!
//! Earlier this file reconnected from the URL inside every method ("recreate
//! from URL for now"), which meant `send` then `recv` talked to two different
//! connections and no call ever saw the previous one's state. That is gone.

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;

/// A WebSocket transport: plain TCP, or the same socket wrapped in TLS.
enum WsStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.read(buf),
            WsStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.write(buf),
            WsStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WsStream::Plain(s) => s.flush(),
            WsStream::Tls(s) => s.flush(),
        }
    }
}

/// Simple WebSocket frame parser (RFC 6455)
struct WebSocket {
    stream: WsStream,
    url: String,
    recv_buffer: VecDeque<Vec<u8>>,
}

// Live connections, keyed by the id carried in the handle. See the module doc:
// the value is passed by reference and replaced on return, so it cannot own the
// socket. The interpreter is single-threaded, so the lock is held across the
// blocking read/write inside a method call — atomic from a program's view.
static NEXT_WS_ID: AtomicU64 = AtomicU64::new(1);
static WS_CONNECTIONS: LazyLock<Mutex<HashMap<u64, WebSocket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn next_ws_id() -> u64 {
    NEXT_WS_ID.fetch_add(1, Ordering::Relaxed)
}

impl WebSocket {
    fn connect(url: &str) -> Result<Self, String> {
        // Parse ws:// or wss:// URL
        let (host, port, path, use_tls) = parse_ws_url(url)?;
        let addr = format!("{}:{}", host, port);

        let tcp = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("invalid address: {e}"))?,
            Duration::from_secs(10),
        )
        .map_err(|e| format!("connect: {e}"))?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("timeout: {e}"))?;

        // TLS before the handshake, so the HTTP upgrade also travels encrypted.
        let mut stream = if use_tls {
            upgrade_tls(tcp, &host)?
        } else {
            WsStream::Plain(tcp)
        };

        // Send WebSocket upgrade handshake
        let key = generate_ws_key();
        let handshake = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
            path, host, key
        );

        // No `try_clone`: the stream may be TLS (`StreamOwned` is not cloneable),
        // and we own it here, so the handshake can use it directly.
        stream
            .write_all(handshake.as_bytes())
            .map_err(|e| format!("handshake write: {e}"))?;

        // Read handshake response
        let mut response = String::new();
        let mut buf = [0u8; 1];
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            stream
                .read_exact(&mut buf)
                .map_err(|e| format!("handshake read: {e}"))?;
            response.push(buf[0] as char);
            if response.ends_with("\r\n\r\n") {
                break;
            }
        }

        if !response.contains("101") && !response.contains("Switching Protocols") {
            return Err(format!(
                "WebSocket handshake failed: {}",
                response.lines().next().unwrap_or("")
            ));
        }

        Ok(WebSocket {
            stream,
            url: url.to_string(),
            recv_buffer: VecDeque::new(),
        })
    }

    fn recv_timeout(&mut self, timeout_ms: u64) -> Result<Option<String>, String> {
        // Check buffer first
        if let Some(data) = self.recv_buffer.pop_front() {
            return Ok(Some(String::from_utf8_lossy(&data).to_string()));
        }

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        // A read timeout is a property of the underlying socket, which the
        // WsStream still owns; apply it through the raw handle when possible.
        if let WsStream::Plain(ref s) = self.stream {
            s.set_read_timeout(Some(Duration::from_millis(100)))
                .map_err(|e| format!("timeout: {e}"))?;
        } else if let WsStream::Tls(ref s) = self.stream {
            s.sock
                .set_read_timeout(Some(Duration::from_millis(100)))
                .map_err(|e| format!("timeout: {e}"))?;
        }

        loop {
            match self.read_frame() {
                Ok(Some(data)) => {
                    if !data.is_empty() {
                        return Ok(Some(String::from_utf8_lossy(&data).to_string()));
                    }
                }
                Ok(None) => return Ok(None),
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    // Timeout or partial frame — retry
                    if !e.contains("timeout") && !e.contains("WouldBlock") {
                        return Err(e);
                    }
                }
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    fn recv_all(&mut self, limit: usize) -> Result<Vec<String>, String> {
        let mut messages = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        while messages.len() < limit && Instant::now() < deadline {
            match self.recv_timeout(500) {
                Ok(Some(msg)) => messages.push(msg),
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(messages)
    }

    fn send_text(&mut self, text: &str) -> Result<(), String> {
        let mut frame = Vec::new();
        frame.push(0x81); // FIN + text opcode

        let len = text.len();
        if len < 126 {
            frame.push(len as u8);
        } else if len <= 65535 {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        frame.extend_from_slice(text.as_bytes());
        self.stream
            .write_all(&frame)
            .map_err(|e| format!("send: {e}"))
    }

    fn read_frame(&mut self) -> Result<Option<Vec<u8>>, String> {
        let mut header = [0u8; 2];
        match self.stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err("timeout".into());
            }
            Err(e) => return Err(format!("read header: {e}")),
        }

        let opcode = header[0] & 0x0F;
        match opcode {
            0x8 => return Ok(None),             // close frame
            0x9 => return Ok(Some(Vec::new())), // ping — ignore for now
            _ => {}
        }

        let mut len = (header[1] & 0x7F) as u64;

        if len == 126 {
            let mut ext = [0u8; 2];
            self.stream
                .read_exact(&mut ext)
                .map_err(|e| format!("ext len: {e}"))?;
            len = u16::from_be_bytes(ext) as u64;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            self.stream
                .read_exact(&mut ext)
                .map_err(|e| format!("ext len: {e}"))?;
            len = u64::from_be_bytes(ext);
        }

        let mut mask = [0u8; 4];
        self.stream
            .read_exact(&mut mask)
            .map_err(|e| format!("mask: {e}"))?;

        let mut data = vec![0u8; len as usize];
        self.stream
            .read_exact(&mut data)
            .map_err(|e| format!("payload: {e}"))?;

        // Unmask
        for i in 0..data.len() {
            data[i] ^= mask[i % 4];
        }

        Ok(Some(data))
    }
}

/// Wrap a connected socket in TLS for `wss://`, validating the chain against the
/// webpki root store.
///
/// Both `rustls` and `webpki-roots` are already crate dependencies, so `wss://`
/// needs no new dependency and no feature flag.
fn upgrade_tls(tcp: TcpStream, host: &str) -> Result<WsStream, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| format!("invalid TLS server name `{host}`: {e}"))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("TLS init: {e}"))?;

    Ok(WsStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp))))
}

fn parse_ws_url(url: &str) -> Result<(String, u16, String, bool), String> {
    let use_tls = url.starts_with("wss://");
    if !use_tls && !url.starts_with("ws://") {
        return Err(format!(
            "invalid WebSocket URL `{url}`: expected a ws:// or wss:// scheme"
        ));
    }
    let stripped = url.trim_start_matches("wss://").trim_start_matches("ws://");
    let (host_port, path) = stripped.split_once('/').unwrap_or((stripped, ""));
    let (host, port_str) = host_port.split_once(':').unwrap_or((host_port, ""));
    if host.is_empty() {
        return Err(format!("invalid WebSocket URL `{url}`: missing host"));
    }
    let port: u16 = port_str.parse().unwrap_or(if use_tls { 443 } else { 80 });
    Ok((host.to_string(), port, format!("/{}", path), use_tls))
}

fn generate_ws_key() -> String {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
        .ok();
    base64::engine::general_purpose::STANDARD.encode(&bytes)
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "connect" => Some(ws_connect(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "WebSocket") {
        return None;
    }
    match method {
        "recv" => Some(ws_recv(object, args)),
        "recv_all" => Some(ws_recv_all(object, args)),
        "send" => Some(ws_send(object, args)),
        "close" => Some(ws_close(object)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "connect")
}

/// The id carried in a `WebSocket` handle.
fn handle_id(fields: &[(String, Value)]) -> Result<u64, String> {
    fields
        .iter()
        .find(|(n, _)| n == "id")
        .and_then(|(_, v)| match v {
            Value::Int(i) => Some(*i as u64),
            _ => None,
        })
        .ok_or_else(|| "WebSocket handle is missing its id".to_string())
}

/// Run `f` against the live connection this handle refers to.
///
/// A handle whose connection is gone (already closed, or never registered) is an
/// error, never a silent reconnect — silently opening a new socket would make
/// `send` succeed against a connection the program never established.
fn with_connection<T, F>(value: &Value, f: F) -> Result<T, String>
where
    F: FnOnce(&mut WebSocket) -> Result<T, String>,
{
    let fields = match value {
        Value::Struct { name, fields } if name == "WebSocket" => fields,
        _ => return Err(format!("Expected WebSocket, got {}", type_name(value))),
    };
    let id = handle_id(fields)?;
    let mut registry = WS_CONNECTIONS
        .lock()
        .map_err(|_| "ws: connection registry poisoned".to_string())?;
    let ws = registry
        .get_mut(&id)
        .ok_or_else(|| format!("ws: unknown or closed WebSocket handle {id}"))?;
    f(ws)
}

fn ws_connect(args: Vec<Value>) -> StdlibResult {
    let url = expect_first_str(&args, "url")?;
    let ws = WebSocket::connect(url)?;
    let id = next_ws_id();
    match WS_CONNECTIONS.lock() {
        Ok(mut registry) => {
            registry.insert(id, ws);
        }
        Err(_) => return Err("ws.connect: connection registry poisoned".into()),
    }
    Ok(Value::Struct {
        name: "WebSocket".into(),
        fields: vec![
            ("id".into(), Value::Int(id as i128)),
            ("url".into(), Value::String(url.clone())),
        ],
    })
}

fn ws_recv(value: &Value, args: Vec<Value>) -> StdlibResult {
    let timeout = args
        .first()
        .and_then(|v| if let Value::Int(i) = v { Some(*i as u64) } else { None })
        .unwrap_or(7000);
    let msg = with_connection(value, |ws| ws.recv_timeout(timeout))?;
    Ok(match msg {
        Some(m) => Value::String(m),
        None => Value::Nil,
    })
}

fn ws_recv_all(value: &Value, args: Vec<Value>) -> StdlibResult {
    let limit = args
        .first()
        .and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None })
        .unwrap_or(100);
    let msgs = with_connection(value, |ws| ws.recv_all(limit))?;
    Ok(Value::Array(msgs.into_iter().map(Value::String).collect()))
}

fn ws_send(value: &Value, args: Vec<Value>) -> StdlibResult {
    let text = expect_first_str(&args, "text")?.clone();
    with_connection(value, |ws| ws.send_text(&text))?;
    Ok(Value::Nil)
}

fn ws_close(value: &Value) -> StdlibResult {
    let fields = match value {
        Value::Struct { name, fields } if name == "WebSocket" => fields,
        _ => return Err(format!("Expected WebSocket, got {}", type_name(value))),
    };
    let id = handle_id(fields)?;
    let mut registry = WS_CONNECTIONS
        .lock()
        .map_err(|_| "ws: connection registry poisoned".to_string())?;
    match registry.remove(&id) {
        // Closing an already-closed handle is a no-op, not an error: the caller's
        // intent (the socket is gone) already holds.
        None => Ok(Value::Nil),
        Some(mut ws) => {
            let _ = ws.stream.write_all(&[0x88, 0x00]);
            Ok(Value::Nil)
        }
    }
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ws_url_reads_scheme_port_and_path() {
        assert_eq!(
            parse_ws_url("ws://example.com/feed").unwrap(),
            ("example.com".to_string(), 80, "/feed".to_string(), false)
        );
        // wss:// defaults to 443, and the scheme decides it.
        assert_eq!(
            parse_ws_url("wss://example.com/feed").unwrap(),
            ("example.com".to_string(), 443, "/feed".to_string(), true)
        );
        assert_eq!(
            parse_ws_url("wss://example.com:8443").unwrap(),
            ("example.com".to_string(), 8443, "/".to_string(), true)
        );
    }

    #[test]
    fn parse_ws_url_refuses_a_non_websocket_scheme() {
        // Previously `https://…` silently parsed as a ws:// target on port 80.
        let err = parse_ws_url("https://example.com/feed").unwrap_err();
        assert!(err.contains("ws:// or wss://"), "{err}");
        assert!(parse_ws_url("ws://").is_err(), "empty host must be refused");
    }

    #[test]
    fn wss_is_supported_and_no_longer_refused_by_name() {
        // No network: port 1 on loopback refuses immediately. The point is that
        // the failure is a CONNECT failure, i.e. the TLS path was reached rather
        // than the old "not yet supported" short-circuit.
        // (No `unwrap_err()`: that would demand `WebSocket: Debug`.)
        let err = match WebSocket::connect("wss://127.0.0.1:1/feed") {
            Ok(_) => panic!("expected a connect failure against a closed port"),
            Err(e) => e,
        };
        assert!(
            !err.contains("not yet supported"),
            "wss:// must not be refused as unsupported any more: {err}"
        );
        assert!(err.starts_with("connect:"), "expected a connect error, got: {err}");
    }

    #[test]
    fn handles_carry_distinct_ids_and_survive_as_registry_keys() {
        let a = next_ws_id();
        let b = next_ws_id();
        assert_ne!(a, b);
        // A handle whose id was never registered is an error, never a silent
        // reconnect: this is the bug the registry replaced.
        let bogus = Value::Struct {
            name: "WebSocket".into(),
            fields: vec![("id".into(), Value::Int(999_999))],
        };
        let err = with_connection(&bogus, |ws| ws.send_text("x")).unwrap_err();
        assert!(err.contains("unknown or closed"), "{err}");
    }

    #[test]
    fn close_of_an_unknown_handle_is_a_noop() {
        let bogus = Value::Struct {
            name: "WebSocket".into(),
            fields: vec![("id".into(), Value::Int(424_242))],
        };
        assert!(ws_close(&bogus).is_ok());
    }
}
