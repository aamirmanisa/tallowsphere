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
