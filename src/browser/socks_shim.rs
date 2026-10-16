//! Local SOCKS5 credential-injection relay ("socks-auth shim") for
//! Chromium launches — in-process edition.
//!
//! Chromium implements no SOCKS5 authentication (RFC 1929) and ignores
//! userinfo in `--proxy-server`; pointed at the fail-closed per-run identity
//! URL (`socks5(h)://<user>:<pass>@127.0.0.1:9050`) every page load fails
//! empty (verified 2026-10-02). This module restores per-run circuit
//! isolation for the Chromium engine: [`spawn_for_credentials`] binds a
//! loopback listener in this process and serves unauthenticated SOCKS5 that
//! re-originates each connection upstream (Tor) with the per-run credentials
//! injected. Design precedent: nixreader `socks-auth-shim.py`.
//!
//! **Why in-process and not a helper child:** `tallow run` executes
//! native-compiled script binaries (`/tmp/tallow_native_run_*`), so
//! `current_exe()` inside such a run is the generated script — it has no
//! tallow CLI surface. A helper child spawned that way re-ran the script
//! instead of the relay (verified 2026-10-02). The relay is therefore plain
//! blocking `std::net` threads owned by this process: no exec, no READY
//! handshake, no orphan risk. Threads die with the process; the guard's
//! Drop stops the accept loop on normal teardown.
//!
//! Scope: one relay per browser launch; loopback only — never a non-loopback
//! listen address.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Handshake-phase socket timeout (both directions).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Upstream (Tor SOCKS) connect timeout.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Accept-loop poll interval for the shutdown check.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Live in-process relay for one browser launch. Dropping the guard stops
/// the accept loop (in-flight connections finish on their own); the relay
/// thread cannot outlive the process.
pub struct SocksShimGuard {
    port: u16,
    shutdown: Arc<AtomicBool>,
}

impl SocksShimGuard {
    /// The loopback SOCKS5 URL to hand to Chromium
    /// (`socks5://127.0.0.1:<port>`). Chromium accepts this unauthenticated
    /// form; the relay adds the per-run credentials upstream.
    pub fn proxy_url(&self) -> String {
        format!("socks5://127.0.0.1:{}", self.port)
    }

    /// The loopback port the relay is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for SocksShimGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

/// True when the proxy URL carries SOCKS userinfo (per-run identity).
pub fn has_credentials(proxy_url: &str) -> bool {
    parse_credentialed_proxy(proxy_url).is_ok()
}

/// Parse `socks5://user:pass@host:port` (or `socks5h://`) into
/// `(upstream, user, pass)`. Errors on non-SOCKS schemes or missing
/// userinfo/port — callers use this to decide shim engagement and to fall
/// back to credential-stripping.
pub fn parse_credentialed_proxy(proxy_url: &str) -> Result<(String, String, String), String> {
    let rest = proxy_url
        .strip_prefix("socks5://")
        .or_else(|| proxy_url.strip_prefix("socks5h://"))
        .ok_or_else(|| format!("not a socks5 proxy url: {proxy_url}"))?;
    let (userinfo, hostport) = rest
        .rsplit_once('@')
        .ok_or_else(|| "no credentials in proxy url".to_string())?;
    let (user, pass) = userinfo
        .split_once(':')
        .ok_or_else(|| "malformed userinfo (expected user:pass)".to_string())?;
    if user.is_empty() || pass.is_empty() {
        return Err("empty credential component".to_string());
    }
    if !hostport.contains(':') {
        return Err(format!("missing port in upstream endpoint: {hostport}"));
    }
    Ok((hostport.to_string(), user.to_string(), pass.to_string()))
}

/// Start an in-process relay for a credentialed proxy URL.
///
/// Errors when the URL carries no credentials (callers gate on
/// [`has_credentials`]) and on any bind/resolve failure — callers fall back
/// to credential-stripped proxying, which stays on Tor.
pub fn spawn_for_credentials(proxy_url: &str) -> Result<SocksShimGuard, String> {
    let (upstream, user, pass) = parse_credentialed_proxy(proxy_url)?;
    let upstream_addr: SocketAddr = upstream
        .to_socket_addrs()
        .map_err(|e| format!("resolve upstream {upstream}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for upstream {upstream}"))?;
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind loopback relay: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("relay local_addr: {e}"))?
        .port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = Arc::clone(&shutdown);
    std::thread::spawn(move || {
        serve(listener, upstream_addr, (user, pass), thread_shutdown);
    });
    Ok(SocksShimGuard { port, shutdown })
}

/// Accept loop. Runs until the guard is dropped (or the process exits).
fn serve(
    listener: TcpListener,
    upstream: SocketAddr,
    creds: (String, String),
    shutdown: Arc<AtomicBool>,
) {
    let _ = listener.set_nonblocking(true);
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        match listener.accept() {
            Ok((client, _)) => {
                // The listener is non-blocking; accepted sockets are blocking
                // on Linux but reset explicitly for cross-platform safety.
                let _ = client.set_nonblocking(false);
                let creds = creds.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(client, upstream, creds);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// One client connection: no-auth handshake downstream, credentialed
/// handshake upstream, verbatim CONNECT relay, then bidirectional splice.
fn handle_conn(
    mut client: TcpStream,
    upstream: SocketAddr,
    creds: (String, String),
) -> std::io::Result<()> {
    let (user, pass) = creds;
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    client.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    // Client greeting: [ver, nmethods, methods...]. No-auth only.
    let mut head = [0u8; 2];
    client.read_exact(&mut head)?;
    if head[0] != 5 {
        return Ok(());
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods)?;
    client.write_all(&[5, 0])?;

    // CONNECT request: [5, cmd, rsv, atyp, addr..., port(2)].
    let mut req_head = [0u8; 4];
    client.read_exact(&mut req_head)?;
    if req_head[0] != 5 || req_head[1] != 1 {
        let _ = client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        return Ok(());
    }
    let addr_tail = read_atyp(&mut client, req_head[3])?;
    let mut req = Vec::with_capacity(6 + addr_tail.len());
    req.extend_from_slice(&[5, 1, 0, req_head[3]]);
    req.extend_from_slice(&addr_tail);

    // Upstream handshake.
    let mut up = match TcpStream::connect_timeout(&upstream, UPSTREAM_CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
            return Ok(());
        }
    };
    up.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    up.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    if user.len() > 255 || pass.len() > 255 {
        let _ = client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        return Ok(());
    }
    up.write_all(&[5, 1, 2])?; // offer username/password
    let mut rep = [0u8; 2];
    up.read_exact(&mut rep)?;
    if rep[1] == 2 {
        let mut auth = Vec::with_capacity(user.len() + pass.len() + 3);
        auth.push(1);
        auth.push(user.len() as u8);
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass.as_bytes());
        up.write_all(&auth)?;
        let mut st = [0u8; 2];
        up.read_exact(&mut st)?;
        if st[1] != 0 {
            let _ = client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
            return Ok(());
        }
    } else if rep[1] != 0 {
        // Upstream demanded a method we cannot honor.
        let _ = client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        return Ok(());
    }
    // rep[1] == 0: upstream accepts no-auth; relay anyway (shared circuit).

    // Relay the CONNECT verbatim and translate only the reply status.
    up.write_all(&req)?;
    let mut up_rep = [0u8; 4];
    up.read_exact(&mut up_rep)?;
    if up_rep[1] != 0 {
        let _ = client.write_all(&[5, up_rep[1], 0, 1, 0, 0, 0, 0, 0, 0]);
        return Ok(());
    }
    let _ = read_atyp(&mut up, up_rep[3])?; // consume bound addr + port
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;

    // Splice.
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    up.set_read_timeout(None)?;
    up.set_write_timeout(None)?;
    let mut c_read = client.try_clone()?;
    let mut u_write = up.try_clone()?;
    let up_task = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c_read, &mut u_write);
        let _ = u_write.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut up, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = up_task.join();
    Ok(())
}

/// Read an address+port block per ATYP (4 / 1+n / 16 address bytes plus the
/// 2-byte port). Returns the raw bytes for verbatim re-framing.
fn read_atyp(s: &mut TcpStream, atyp: u8) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    match atyp {
        1 => {
            let mut b = [0u8; 4 + 2];
            s.read_exact(&mut b)?;
            out.extend_from_slice(&b);
        }
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)?;
            let mut b = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut b)?;
            out.push(len[0]);
            out.extend_from_slice(&b);
        }
        4 => {
            let mut b = [0u8; 16 + 2];
            s.read_exact(&mut b)?;
            out.extend_from_slice(&b);
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad atyp",
            ))
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_and_rejects() {
        let (up, u, p) =
            parse_credentialed_proxy("socks5://alpha-1b2c:deadbeef@127.0.0.1:9050").unwrap();
        assert_eq!(up, "127.0.0.1:9050");
        assert_eq!(u, "alpha-1b2c");
        assert_eq!(p, "deadbeef");
        assert!(parse_credentialed_proxy("socks5h://u:p@127.0.0.1:9050").is_ok());
        assert!(parse_credentialed_proxy("socks5://127.0.0.1:9050").is_err());
        assert!(parse_credentialed_proxy("http://u:p@127.0.0.1:8080").is_err());
        assert!(!has_credentials("socks5://127.0.0.1:9050"));
        assert!(has_credentials("socks5://u:p@127.0.0.1:9050"));
    }

    #[test]
    fn spawn_requires_credentials() {
        // Must fail before binding anything (no creds in the URL).
        assert!(spawn_for_credentials("socks5://127.0.0.1:9050").is_err());
    }

    /// Fake upstream SOCKS5 server: one connection, captures the credential
    /// exchange, echoes one payload roundtrip.
    fn fake_upstream() -> (
        SocketAddr,
        std::thread::JoinHandle<(String, String, String)>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            // Greeting: expect method 2 (username/password) offered.
            let mut h = [0u8; 2];
            s.read_exact(&mut h).unwrap();
            assert_eq!(h[0], 5);
            let mut ms = vec![0u8; h[1] as usize];
            s.read_exact(&mut ms).unwrap();
            assert!(ms.contains(&2), "relay must offer username/password auth");
            s.write_all(&[5, 2]).unwrap();
            // RFC 1929 credential exchange.
            let mut ah = [0u8; 2];
            s.read_exact(&mut ah).unwrap();
            assert_eq!(ah[0], 1);
            let mut ub = vec![0u8; ah[1] as usize];
            s.read_exact(&mut ub).unwrap();
            let mut pl = [0u8; 1];
            s.read_exact(&mut pl).unwrap();
            let mut pb = vec![0u8; pl[0] as usize];
            s.read_exact(&mut pb).unwrap();
            let (u, p) = (
                String::from_utf8(ub).unwrap(),
                String::from_utf8(pb).unwrap(),
            );
            s.write_all(&[1, 0]).unwrap();
            // CONNECT request header [5,1,0,3], then the domain-length byte.
            let mut rh = [0u8; 4];
            s.read_exact(&mut rh).unwrap();
            assert_eq!(rh, [5, 1, 0, 3]);
            let mut domlen = [0u8; 1];
            s.read_exact(&mut domlen).unwrap();
            assert_eq!(domlen[0], 11);
            let mut dom = vec![0u8; 11];
            s.read_exact(&mut dom).unwrap();
            let mut portb = [0u8; 2];
            s.read_exact(&mut portb).unwrap();
            let target = format!(
                "{}:{}",
                String::from_utf8(dom).unwrap(),
                u16::from_be_bytes(portb)
            );
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            // Echo one roundtrip.
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&buf).unwrap();
            (u, p, target)
        });
        (addr, handle)
    }

    #[test]
    fn relay_injects_credentials_and_relays() {
        let (up_addr, up_handle) = fake_upstream();
        let guard = spawn_for_credentials(&format!("socks5://run1-abc:c0ffee@{up_addr}")).unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", guard.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        // No-auth offer.
        client.write_all(&[5, 1, 0]).unwrap();
        let mut rep = [0u8; 2];
        client.read_exact(&mut rep).unwrap();
        assert_eq!(rep, [5, 0]);
        // CONNECT example.com:443.
        let mut req = vec![5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).unwrap();
        let mut ok = [0u8; 10];
        client.read_exact(&mut ok).unwrap();
        assert_eq!(ok[1], 0, "relay must report success");
        // Echo roundtrip through the splice.
        client.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        client.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping");

        let (u, p, target) = up_handle.join().unwrap();
        assert_eq!(u, "run1-abc");
        assert_eq!(p, "c0ffee");
        assert_eq!(target, "example.com:443");
        drop(guard);
    }

    #[test]
    fn guard_drop_stops_listener() {
        let guard = spawn_for_credentials("socks5://u:p@127.0.0.1:9").unwrap();
        let port = guard.port();
        // Listener is up: a connect succeeds (then closes immediately).
        assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
        drop(guard);
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_err(),
            "listener should be closed after guard drop"
        );
    }
}
