//! `tallow.stealth_http` — browser-impersonated HTTP client (TLS/JA3/JA4/HTTP2).
//!
//! Compiled only behind the `stealth-http` cargo feature, which pulls in
//! [`wreq`] (BoringSSL-based, Chrome/Firefox/Safari/Edge TLS fingerprint
//! emulation). This is the P1-1 anti-bot win: the default `http.rs` client is
//! `ureq` (rustls), which leaks a rustls ClientHello that Akamai/Cloudflare
//! flag immediately. `wreq` produces Chrome-identical TLS so the raw HTTP
//! layer can hit Tier-2/3 targets without a browser.
//!
//! Since the 1000x-upgrade HTTP-first unification, the wreq client is also
//! proxy-aware: it honors `TALLOW_PROXY` / `TALLOW_TOR` (via `detect_proxy_url`
//! in `http.rs`) so browser-accurate TLS *and* SOCKS5 routing are finally
//! combined in a single client, instead of being split across ureq (proxy, no
//! fingerprint) and wreq (fingerprint, no proxy).
//!
//! NOTE: building this feature requires `cmake` (BoringSSL via `boring-sys2`).

use std::time::Duration;

/// Map a `tls_profile` name (see `stdlib/tls_profile.rs`) to a wreq emulation.
fn emulation_for(profile: &str) -> wreq_util::Profile {
    use wreq_util::Profile;
    match profile {
        "chrome_137" => Profile::Chrome137,
        "chrome_136" => Profile::Chrome136,
        "chrome_135" => Profile::Chrome135,
        "chrome_131" => Profile::Chrome131,
        "firefox_139" => Profile::Firefox139,
        "firefox_136" => Profile::Firefox136,
        "firefox_128" => Profile::Firefox128,
        "safari_18" => Profile::Safari18,
        "edge_134" => Profile::Edge134,
        "edge_131" => Profile::Edge131,
        _ => Profile::Chrome136,
    }
}

/// Build a browser-impersonated `wreq` client for the given TLS profile,
/// optionally routing every request through a SOCKS5/HTTP proxy (e.g.
/// `TALLOW_PROXY` or `TALLOW_TOR=1` → `socks5://127.0.0.1:9050`).
///
/// Timeout defaults to 30s; override per-request if needed.
pub fn client(profile: &str, proxy: Option<&str>) -> wreq::Client {
    let mut builder = wreq::Client::builder()
        .emulation(emulation_for(profile))
        // No implicit follow — docs/spec/EGRESS-REDIRECTS.md req. 1, and req. 7
        // for this plane specifically. A 3xx is a status to report, never a
        // request this client makes on its own: the register authorised the URL
        // the caller named, and nothing here re-consults it for a `Location`.
        //
        // Set explicitly even though `wreq` 6.0.0-rc.31 happens to initialise
        // its builder to `redirect::Policy::none()` (`src/client.rs:286`): that
        // is an upstream default this tree does not control, and the doc comment
        // on the very next `.redirect()` (`src/client.rs:960`) still promises
        // "follow redirects up to a maximum of 10". The policy this crate needs
        // is asserted here, not inherited. `Policy::none()` is the exact
        // expression of "zero hops"; measured by `stealth_redirects_*` below.
        .redirect(wreq::redirect::Policy::none())
        .timeout(Duration::from_secs(30));
    if let Some(p) = proxy {
        // wreq 6: explicit Proxy construction (intercepts http+https).
        builder = builder.proxy(wreq::Proxy::all(p).expect("invalid proxy URL"));
    }
    if let Some(store) = extra_ca_store_from_env() {
        // TALLOW_CA_BUNDLE: additive trust on top of the default paths.
        builder = builder.tls_cert_store(store);
    }
    builder
        .build()
        .expect("failed to build wreq stealth client")
}

/// Additive CA trust for mesh-internal endpoints (veil rung / dogfooding).
///
/// `TALLOW_CA_BUNDLE=<pem path>` loads PEM certificate(s) from the given file
/// ON TOP of the default trust paths (`SSL_CERT_FILE` / `SSL_CERT_DIR`-aware),
/// so public roots keep working while an internal CA — e.g. the Tallow mesh
/// CA (`console.wg`, `portal.wg`) — becomes trusted for this process.
/// Unset → previous behavior exactly; set-but-unreadable → warns and keeps
/// default trust (requests still fail closed at TLS; nothing ever silently
/// trusts MORE than intended).
fn extra_ca_store_from_env() -> Option<wreq::tls::trust::CertStore> {
    let path = std::env::var("TALLOW_CA_BUNDLE").ok()?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    let pem = match std::fs::read(path) {
        Ok(pem) => pem,
        Err(e) => {
            eprintln!(
                "stealth-http: TALLOW_CA_BUNDLE '{path}' unreadable ({e}); using default trust"
            );
            return None;
        }
    };
    let mut builder = match system_ca_bundle() {
        Some(sys) => wreq::tls::trust::CertStore::builder().add_stack_pem_certs(sys),
        // No readable system bundle: fall back to the compiled-in default
        // paths so public roots are still present alongside the extra PEM.
        None => wreq::tls::trust::CertStore::builder().set_default_paths(),
    };
    builder = builder.add_stack_pem_certs(&pem);
    match builder.build() {
        Ok(store) => Some(store),
        Err(e) => {
            eprintln!(
                "stealth-http: TALLOW_CA_BUNDLE '{path}' failed to build ({e}); using default trust"
            );
            None
        }
    }
}

/// The box's CA bundle: `SSL_CERT_FILE` when set, else the Debian/Ubuntu
/// default. Used as the base root set when `TALLOW_CA_BUNDLE` adds the mesh CA.
fn system_ca_bundle() -> Option<Vec<u8>> {
    let path = std::env::var("SSL_CERT_FILE")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| "/etc/ssl/certs/ca-certificates.crt".to_string());
    std::fs::read(&path).ok()
}

/// `GET` with browser-impersonated TLS. Returns `(status, body)`.
pub async fn get(
    profile: &str,
    url: &str,
    headers: &[(String, String)],
    proxy: Option<&str>,
) -> Result<(u16, String), String> {
    let c = client(profile, proxy);
    let mut req = c.get(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("stealth get: {}", err_chain(&e)))?;
    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("stealth body: {}", err_chain(&e)))?;
    Ok((status, body))
}

/// Flatten an error and its source chain into one line. Fail-closed paths
/// must say WHY they failed — a bare `client error (Connect)` hides the real
/// cause (TLS? DNS? proxy?) from operators and from the receipts.
fn err_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(" <- ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

/// `POST` with browser-impersonated TLS. Returns `(status, body)`.
pub async fn post(
    profile: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    proxy: Option<&str>,
) -> Result<(u16, String), String> {
    let c = client(profile, proxy);
    let mut req = c.post(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| format!("stealth post: {}", err_chain(&e)))?;
    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("stealth body: {}", err_chain(&e)))?;
    Ok((status, body))
}

/// Bridge the async wreq call into the synchronous `.tl` dispatcher.
///
/// Reuses the dedicated browser runtime (see `interp.rs::get_browser_runtime`)
/// so it never nests inside another tokio runtime.
pub fn get_blocking(
    profile: &str,
    url: &str,
    headers: &[(String, String)],
    proxy: Option<&str>,
) -> Result<(u16, String), String> {
    crate::interp::get_browser_runtime().block_on(get(profile, url, headers, proxy))
}

/// Blocking `POST` bridge (see [`get_blocking`]).
pub fn post_blocking(
    profile: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    proxy: Option<&str>,
) -> Result<(u16, String), String> {
    crate::interp::get_browser_runtime().block_on(post(profile, url, headers, body, proxy))
}

#[cfg(test)]
mod redirect_measurement {
    //! Loopback harness for `docs/spec/EGRESS-REDIRECTS.md` requirement 7:
    //! the stealth plane must not follow a hop the register never authorised.
    //!
    //! Server A (`127.0.0.1`, "listed") answers `302` to server B, a second
    //! origin the caller never named ("unlisted"); B records every request it
    //! receives. The passing condition is A receives the request, the caller
    //! receives the `302`, and B receives nothing.
    //!
    //! Both servers bind `127.0.0.1:0`. macOS configures only `127.0.0.1` on
    //! `lo0` — `127.0.0.2` is not a local address there, so binding it fails
    //! the fixture before the policy under test is reached. B is reached by the
    //! name `localhost` instead: a distinct, never-named origin that resolves
    //! to the same loopback socket on every platform.
    //!
    //! This drives [`super::get_blocking`] rather than `http.get` on purpose:
    //! `stdlib/http.rs::is_loopback_target` routes every loopback literal off
    //! the stealth plane, so a `http.get`-driven harness can never observe the
    //! `wreq` client at all.

    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const PROFILE: &str = "chrome_136";

    struct Server {
        addr: SocketAddr,
        hits: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Server {
        fn start<F>(bind: &str, handler: F) -> Server
        where
            F: Fn(&str) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + 'static,
        {
            let listener = TcpListener::bind(bind)
                .unwrap_or_else(|e| panic!("bind {bind}: {e}"));
            listener.set_nonblocking(true).expect("nonblocking accept");
            let addr = listener.local_addr().expect("local addr");
            let hits = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let hits_t = hits.clone();
            let stop_t = stop.clone();
            let handle = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(8);
                loop {
                    if stop_t.load(Ordering::Relaxed) || Instant::now() > deadline {
                        break;
                    }
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                            if let Ok((method, path)) = read_request(&mut stream) {
                                hits_t
                                    .lock()
                                    .expect("hits mutex")
                                    .push(format!("{method} {path}"));
                                let (status, headers, body) = handler(&path);
                                let _ = write_response(&mut stream, status, &headers, &body);
                            }
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::Interrupted =>
                        {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Server {
                addr,
                hits,
                stop,
                handle: Some(handle),
            }
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{}", self.addr, path)
        }

        /// Same socket, addressed by `host` instead of the bound literal —
        /// used to name the hop target by a host the plane was never given.
        fn url_as(&self, host: &str, path: &str) -> String {
            format!("http://{host}:{}{path}", self.addr.port())
        }

        fn hits(&self) -> Vec<String> {
            self.hits.lock().expect("hits mutex").clone()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn read_request(stream: &mut TcpStream) -> std::io::Result<(String, String)> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof before headers",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let mut parts = text
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();
        Ok((method, path))
    }

    fn write_response(
        stream: &mut TcpStream,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
    ) -> std::io::Result<()> {
        let reason = match status {
            200 => "OK",
            302 => "Found",
            _ => "OK",
        };
        let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
        for (k, v) in headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ));
        stream.write_all(out.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(())
    }

    /// A + B pair: A redirects to B, B records.
    struct Harness {
        listed: Server,
        unlisted: Server,
        start: String,
    }

    fn harness() -> Harness {
        let unlisted = Server::start("127.0.0.1:0", |_| {
            (200, Vec::new(), b"LEAKED".to_vec())
        });
        let leak = unlisted.url_as("localhost", "/leak");
        let listed = Server::start("127.0.0.1:0", move |_| {
            (
                302,
                vec![("Location".to_string(), leak.clone())],
                Vec::new(),
            )
        });
        let start = listed.url("/start");
        Harness {
            listed,
            unlisted,
            start,
        }
    }

    /// The pre-fix shape of the builder, kept here as evidence: the same
    /// `.emulation(...).timeout(...)` chain with no `.redirect(...)` call.
    fn unconfigured_builder_client() -> wreq::Client {
        wreq::Client::builder()
            .emulation(super::emulation_for(PROFILE))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build unconfigured wreq client")
    }

    #[test]
    fn stealth_redirects_unlisted_hop_is_not_followed() {
        let h = harness();
        let (status, body) = super::get_blocking(PROFILE, &h.start, &[], None)
            .expect("the stealth plane must return the 3xx, not fail the request");

        // A follow would have completed before `get_blocking` returned; the
        // sleep only covers the unlisted server's accept thread.
        std::thread::sleep(Duration::from_millis(150));
        let listed_hits = h.listed.hits();
        let unlisted_hits = h.unlisted.hits();

        assert_eq!(
            listed_hits,
            vec!["GET /start".to_string()],
            "the plane must really fetch the URL it was given (hits: {listed_hits:?})"
        );
        assert_eq!(status, 302, "a 3xx is a status to report, not a hop to take");
        assert_ne!(body, "LEAKED", "body must not come from the unlisted host");
        assert!(
            unlisted_hits.is_empty(),
            "unlisted origin localhost:{} received {unlisted_hits:?}",
            h.unlisted.addr.port()
        );
    }

    /// Evidence, not a gate: what the *unconfigured* builder does at this
    /// `wreq` version, so the spec's claim about the upstream default is
    /// re-measured on any dependency bump instead of re-read. Prints only —
    /// the policy this crate ships is `client()` above, and the test above
    /// pins it.
    #[test]
    fn stealth_redirects_upstream_default_is_recorded() {
        let h = harness();
        let client = unconfigured_builder_client();
        let observed = crate::interp::get_browser_runtime().block_on(async {
            match client.get(&h.start).send().await {
                Ok(r) => {
                    let status = r.status().as_u16();
                    let uri = r.uri().to_string();
                    let body = r.text().await.unwrap_or_default();
                    format!("status={status} uri={uri} body={body:?}")
                }
                Err(e) => format!("error={e}"),
            }
        });
        std::thread::sleep(Duration::from_millis(150));
        eprintln!(
            "wreq unconfigured builder: {observed} | listed_hits={:?} unlisted_hits={:?}",
            h.listed.hits(),
            h.unlisted.hits()
        );
    }
}
