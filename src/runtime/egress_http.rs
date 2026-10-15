//! Shared egress HTTP client for the stdlib.
//!
//! One place that builds every outbound `ureq` request so the whole collection
//! surface honours the box's egress contract: **Tor is the default**,
//! `TALLOW_PROXY` overrides it, and `TALLOW_ALLOW_DIRECT=1` is the explicit
//! opt-out. A configured-but-unparseable `TALLOW_PROXY` is a hard refusal
//! (see [`egress_refusal`]): this module never silently degrades to a direct
//! connection. On top of that sits a baseline politeness delay.
//!
//! Before this module ~31 stdlib modules (`azure_phish`, `beehiiv`, `cxense`,
//! `cnam_dip`, `edgar`, `ghost`, `graphql`, `transfer`, `wordpress`, …) called
//! bare `ureq::get` / `ureq::post` — ~51 sites with **no proxy at all** — so
//! using them for collection egressed from the box IP while `fetch()`, `http.*`
//! and the browser rode Tor. Source-level guard tests below keep it that way:
//! no bare `ureq::get/post/…` (or default agents) may reappear under
//! `src/stdlib/**`, the runtime tree, `src/browser/**` or top-level `src/*.rs`.
//!
//! Rate limiting: `TALLOW_FETCH_DELAY_MS` (default 250 ms) is the minimum gap
//! between two requests to the **same host**; `0` disables it. The delay is per
//! host rather than global so a wide crawl is not serialised into one queue.
//! `Page.throttle_network()` remains the coarse per-page bandwidth knob.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Baseline per-host delay between collection requests, in milliseconds.
///
/// Defaults to 250 ms — slow enough to be polite, fast enough not to break a
/// normal scrape. `TALLOW_FETCH_DELAY_MS=0` disables the limiter entirely.
fn delay_ms() -> u64 {
    match std::env::var("TALLOW_FETCH_DELAY_MS") {
        Ok(v) => v.trim().parse().unwrap_or(250),
        Err(_) => 250,
    }
}

fn host_of(uri: &str) -> String {
    let rest = uri.split("://").nth(1).unwrap_or(uri);
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .rsplit('@')
        .next()
        .unwrap_or(rest);
    // strip :port
    match host.rfind(':') {
        Some(i) if !host[i + 1..].contains(']') && host[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
            host[..i].to_ascii_lowercase()
        }
        _ => host.to_ascii_lowercase(),
    }
}

static LAST_HIT: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Block until the per-host minimum interval has elapsed. Public so the
/// runtime's own `fetch()` and the interpreter's HTTP paths share one limiter
/// with the stdlib modules.
pub fn rate_limit_wait(uri: &str) {
    let delay = delay_ms();
    if delay == 0 {
        return;
    }
    let host = host_of(uri);
    let need = Duration::from_millis(delay);
    // Compute the wait under the lock, sleep outside it: holding the mutex
    // across a sleep would serialise unrelated hosts too.
    let wait = match LAST_HIT.lock() {
        Ok(g) => match g.get(&host) {
            Some(prev) => need.saturating_sub(prev.elapsed()),
            None => Duration::ZERO,
        },
        Err(_) => Duration::ZERO,
    };
    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
    if let Ok(mut g) = LAST_HIT.lock() {
        g.insert(host, Instant::now());
    }
}

// ── ECH (RFC 9849) on the direct egress path (rows #60/#156/#157) ────────────
//
// Tallow's HTTP client (ureq/wreq) does not expose ECH configuration, so an
// HTTPS request that leaves the box **directly** carries its destination in
// the TLS ClientHello (SNI) where every on-path observer can read it — the
// exact metadata leak rows #60/#156/#157 exist to close on clearnet paths.
// The rustls-based clients (tallow-net) warn from their own layer; this module
// cannot enable ECH for the HTTP client, but it can be honest about the leak:
// one warning per host, and only when the connection is genuinely direct
// (proxied/Tor egress hides the destination from this hop's observers).
//
// The name labels follow `tallow_net::transport::ech::sni_confidentiality_relevant`
// (RFC 9849 semantics): public multi-label DNS names only — never loopback,
// IP literals, `.local`, `.onion`, `.internal` or single-label names, whose
// SNI is not on-path metadata worth hiding.

/// `Some((host, message))` when `uri` is an `https://` request to a
/// confidentiality-relevant name and the egress path is **direct**.
/// Pure over its two inputs (no env, no global state) so the decision is
/// testable in isolation.
fn direct_ech_leak(uri: &str, direct: bool) -> Option<(String, String)> {
    if !direct {
        return None;
    }
    let trimmed = uri.trim();
    if !trimmed.to_ascii_lowercase().starts_with("https://") {
        return None;
    }
    let host = host_of(trimmed);
    if !tallow_net::transport::ech::sni_confidentiality_relevant(&host) {
        return None;
    }
    let message = format!(
        "ECH unavailable for '{host}': this direct HTTPS request's TLS SNI/destination is \
         visible to on-path observers (RFC 9849 metadata leak). Tallow's HTTP client does not \
         yet offer ECH — ride the proxy (Tor by default) or accept the leak deliberately."
    );
    Some((host, message))
}

/// Hosts already warned about — once per host, so a wide crawl logs the
/// metadata-leak posture without flooding the log (and without hiding it:
/// every *new* clearnet host still gets its line).
static ECH_NOTED_HOSTS: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Record `host` in the warned-set; `true` on the first sighting.
fn first_ech_note_for(host: &str) -> bool {
    ECH_NOTED_HOSTS
        .lock()
        .map(|mut g| g.insert(host.to_string()))
        .unwrap_or(false)
}

/// Surface the no-ECH metadata-leak warning when this request will ride a
/// direct connection (rows #60/#156/#157; report §P4-10). Called from the
/// outbound request builders; emits at most one `tracing::warn!` per host.
///
/// The egress path comes from the shared contract
/// ([`crate::runtime::fetch::egress_proxy_url`]): a proxy (Tor by default)
/// means the destination is not in a directly-observable ClientHello and this
/// stays silent — it is specifically *direct mode* the rows ask about.
pub fn note_missing_ech_on_direct_egress(uri: &str) {
    let direct = crate::runtime::fetch::egress_proxy_url().is_none();
    if let Some((host, message)) = direct_ech_leak(uri, direct) {
        if first_ech_note_for(&host) {
            tracing::warn!("{}", message);
        }
    }
}

/// The configured proxy for ureq, if any (`socks5h://` form).
pub fn proxy_url() -> Option<String> {
    crate::runtime::fetch::egress_proxy_url_ureq()
}

/// Agents are cached per proxy URL, so a changed env (tests!) is honoured
/// instead of silently reusing a stale direct agent.
static AGENTS: LazyLock<Mutex<HashMap<String, ureq::Agent>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Refusal message for a proxy URL `ureq::Proxy::new` rejects.
///
/// The word "refusing" here is load-bearing (invariant N3): it is only ever
/// produced on a path that attempts **no** request. Paths that warn and then
/// proceed must not reuse it.
fn refusal_hint(url: &str, e: impl std::fmt::Display) -> String {
    format!(
        "[egress] refusing to run unproxied — invalid proxy URL from \
         TALLOW_PROXY/TALLOW_TOR ({url:?}): {e}"
    )
}

/// `Some(reason)` when `url` cannot be parsed into a `ureq::Proxy` — the
/// condition on which this module hard-refuses instead of degrading to a
/// direct connection (N3). Pure over its input: no env, no side effects.
fn refusal_reason(url: &str) -> Option<String> {
    ureq::Proxy::new(url).err().map(|e| refusal_hint(url, e))
}

/// `Some(reason)` when a proxy URL is configured (non-blank `TALLOW_PROXY`, or
/// the fail-closed Tor default) but unusable. When this is `Some`, every
/// builder in this module refuses — `proxy()`/`agent()` panic and **no request
/// is attempted**; `None` means the resolved egress config is usable as-is.
pub fn egress_refusal() -> Option<String> {
    proxy_url().and_then(|url| refusal_reason(&url))
}

/// Parse a proxy URL, refusing hard (panic) when it is unparseable.
///
/// # Panics
/// A configured-but-unusable proxy URL is a hard refusal, not a degradation:
/// continuing would build a *direct* agent, the leak this module exists to
/// prevent (N3). Panicking attempts no request, which is what makes the
/// refusal real. All callers are env-driven — a user-typo case that should be
/// loud, not silent.
fn parse_proxy(url: &str) -> ureq::Proxy {
    match ureq::Proxy::new(url) {
        Ok(p) => p,
        Err(e) => {
            let _ = crate::observability::emit_to_default_journal(
                &crate::observability::SecurityEvent {
                    class: crate::observability::EventClass::EgressRefusal,
                    actor: "runtime.egress_http".to_string(),
                    target: Some(url.to_string()),
                    size: url.len(),
                    at_ms: crate::observability::now_ms(),
                },
            );
            panic!("{}", refusal_hint(url, e))
        }
    }
}

/// The configured proxy as a `ureq::Proxy`, for modules that need their own
/// agent tuning but must still ride the egress contract.
///
/// # Panics
/// See [`parse_proxy`]: a configured-but-unparseable proxy URL refuses hard
/// rather than returning `None` (which callers would treat as "no proxy",
/// i.e. a direct connection).
pub fn proxy() -> Option<ureq::Proxy> {
    proxy_url().map(|url| parse_proxy(&url))
}

fn build_agent(global: Option<Duration>, per_call: Option<Duration>) -> ureq::Agent {
    let mut b = ureq::Agent::config_builder()
        .timeout_global(global)
        .timeout_per_call(per_call)
        .https_only(false);
    if let Some(url) = proxy_url() {
        // Hard refusal, not a warning: a malformed TALLOW_PROXY must not
        // silently fall back to a direct connection (N3).
        b = b.proxy(Some(parse_proxy(&url)));
    }
    if let Some(rc) = ca_bundle_root_certs() {
        // Same env var, same additive semantics as the stealth (wreq) path.
        b = b.tls_config(ureq::tls::TlsConfig::builder().root_certs(rc).build());
    }
    b.build().new_agent()
}

/// Additive CA trust for mesh-internal endpoints on the ureq path.
///
/// Mirror of `stdlib::stealth_http`'s wreq hook: same env var, same semantics.
/// `TALLOW_CA_BUNDLE=<pem>` trusts **system bundle + every certificate in the
/// given PEM**, so public HTTPS keeps working while the internal mesh CA
/// (`console.wg` / `portal.wg`) becomes trusted. Unset → ureq's compiled
/// WebPki default exactly as before; set-but-unreadable → warn + `None`
/// (requests still fail closed at TLS; nothing silently trusts more than asked).
pub(crate) fn ca_bundle_root_certs() -> Option<ureq::tls::RootCerts> {
    let path = std::env::var("TALLOW_CA_BUNDLE").ok()?;
    let path = path.trim().to_string();
    if path.is_empty() {
        return None;
    }
    let extra = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "egress-http: TALLOW_CA_BUNDLE '{path}' unreadable ({e}); using default trust"
            );
            return None;
        }
    };
    let mut certs: Vec<ureq::tls::Certificate<'static>> = Vec::new();
    match system_ca_bundle() {
        Some(sys) => certs.extend(pem_certificates(&sys)),
        None => eprintln!(
            "egress-http: TALLOW_CA_BUNDLE set but no system CA bundle readable; trusting only the bundle file"
        ),
    }
    let from_extra = pem_certificates(&extra);
    if from_extra.is_empty() {
        eprintln!(
            "egress-http: TALLOW_CA_BUNDLE '{path}' contained no parseable certificates; using default trust"
        );
        return None;
    }
    certs.extend(from_extra);
    Some(ureq::tls::RootCerts::new_with_certs(&certs))
}

/// Parse every certificate in a PEM bundle (multi-cert safe).
fn pem_certificates(pem: &[u8]) -> Vec<ureq::tls::Certificate<'static>> {
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        if let Some(end) = block.find("-----END CERTIFICATE-----") {
            let single = format!(
                "-----BEGIN CERTIFICATE-----{}-----END CERTIFICATE-----\n",
                &block[..end]
            );
            if let Ok(c) = ureq::tls::Certificate::from_pem(single.as_bytes()) {
                out.push(c);
            }
        }
    }
    out
}

/// The box's CA bundle (see the stealth twin in `stdlib::stealth_http`).
fn system_ca_bundle() -> Option<Vec<u8>> {
    let path = std::env::var("SSL_CERT_FILE")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| "/etc/ssl/certs/ca-certificates.crt".to_string());
    std::fs::read(&path).ok()
}

/// Shared agent honouring the egress contract (used by the shims below and by
/// any module that needs an `&Agent`).
pub fn agent() -> ureq::Agent {
    let mut key = proxy_url().unwrap_or_else(|| "direct".to_string());
    if std::env::var("TALLOW_CA_BUNDLE")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        key.push_str("|ca-bundle");
    }
    if let Ok(g) = AGENTS.lock() {
        if let Some(a) = g.get(&key) {
            return a.clone();
        }
    }
    let a = build_agent(None, None);
    if let Ok(mut g) = AGENTS.lock() {
        g.insert(key, a.clone());
    }
    a
}

/// Agent with explicit timeouts, still honouring the egress proxy. This is the
/// replacement for the hand-built `ureq::Agent::config_builder()` statics that
/// several modules carried (they never set a proxy).
pub fn agent_with_timeouts(global: Option<Duration>, per_call: Option<Duration>) -> ureq::Agent {
    build_agent(global, per_call)
}

// ── Request shims ───────────────────────────────────────────────────────────
// Same shapes as `ureq::get`/`post`/… so call sites keep their chaining
// (`.header(..).send(..)`), but they run through the proxied shared agent and
// the politeness limiter.

macro_rules! shim {
    ($name:ident, $agent_method:ident, $state:ident) => {
        /// Proxy-aware, rate-limited drop-in for `ureq::$name`.
        pub fn $name(uri: &str) -> ureq::RequestBuilder<ureq::typestate::$state> {
            rate_limit_wait(uri);
            note_missing_ech_on_direct_egress(uri);
            agent().$agent_method(uri)
        }
    };
}

shim!(get, get, WithoutBody);
shim!(delete, delete, WithoutBody);
shim!(head, head, WithoutBody);
shim!(options, options, WithoutBody);
shim!(post, post, WithBody);
shim!(put, put, WithBody);
shim!(patch, patch, WithBody);

/// T-128: the single process-global test-only env lock. Process env is
/// global and `cargo test` runs test threads in parallel, so EVERY test
/// that mutates `TALLOW_*` / proxy env must take this one lock — otherwise
/// an env reader (e.g. the zone egress predicate) can observe a sibling
/// test's in-flight mutation (`None` vs `Some(DirectOptIn)` flake).
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquire [`ENV_LOCK`]; poison-tolerant so one failing test cannot wedge
/// every later env-mutating test.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_strips_scheme_port_and_userinfo() {
        assert_eq!(host_of("https://example.com/a/b?c"), "example.com");
        assert_eq!(host_of("http://example.com:8080/x"), "example.com");
        assert_eq!(host_of("socks5h://user:pw@127.0.0.1:9050"), "127.0.0.1");
        assert_eq!(host_of("example.com/x"), "example.com");
    }

    /// Rows #60/#156/#157: the direct-mode ECH warning fires **only** for
    /// direct HTTPS requests to public clearnet names — the RFC 9849 label
    /// semantics shared with `tallow_net::transport::ech`.
    #[test]
    fn direct_ech_leak_fires_on_direct_https_public_names_only() {
        // Direct + public HTTPS name → one warning naming the host.
        let (host, msg) = direct_ech_leak("https://relay.example.com/jobs", true)
            .expect("direct https to a public name must warn");
        assert_eq!(host, "relay.example.com");
        assert!(msg.contains("ECH unavailable"), "message: {msg}");
        assert!(msg.contains("RFC 9849"), "message must cite RFC 9849: {msg}");

        // Proxied (Tor) egress never warns — the row is about *direct* mode.
        assert!(direct_ech_leak("https://relay.example.com/jobs", false).is_none());

        // Plaintext HTTP is not a TLS-SNI statement.
        assert!(direct_ech_leak("http://relay.example.com/", true).is_none());

        // Local/onion/IP/single-label names carry no on-path SNI metadata.
        for uri in [
            "https://localhost/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://peer.local/x",
            "https://abcdef234.onion/x",
            "https://relay/x",
            "not a url",
        ] {
            assert!(
                direct_ech_leak(uri, true).is_none(),
                "must not warn for {uri}"
            );
        }
    }

    /// One warning per host: the first sighting is the one that notes.
    #[test]
    fn direct_ech_note_is_once_per_host() {
        let host = "once-per-host-1.example.com";
        assert!(first_ech_note_for(host), "first sighting must note");
        assert!(!first_ech_note_for(host), "second sighting must stay silent");
        assert!(
            first_ech_note_for("once-per-host-2.example.com"),
            "a different host is its own first sighting"
        );
    }

    #[test]
    fn rate_limit_is_per_host_and_env_driven() {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = env_lock();
        // 0 disables → two immediate calls must not block.
        unsafe { std::env::set_var("TALLOW_FETCH_DELAY_MS", "0") };
        let t0 = Instant::now();
        rate_limit_wait("https://a.example.com/1");
        rate_limit_wait("https://a.example.com/2");
        assert!(t0.elapsed() < Duration::from_millis(50), "0 must disable the limiter");

        // 120 ms between two hits on the SAME host must be enforced …
        unsafe { std::env::set_var("TALLOW_FETCH_DELAY_MS", "120") };
        LAST_HIT.lock().unwrap().clear();
        rate_limit_wait("https://b.example.com/1");
        let t1 = Instant::now();
        rate_limit_wait("https://b.example.com/2");
        assert!(t1.elapsed() >= Duration::from_millis(110), "same-host gap not enforced");

        // … while a different host is not delayed.
        let t2 = Instant::now();
        rate_limit_wait("https://c.example.com/1");
        assert!(t2.elapsed() < Duration::from_millis(60), "different host must not wait");

        unsafe { std::env::remove_var("TALLOW_FETCH_DELAY_MS") };
    }

    /// No stdlib module may build its own unproxied client again.
    ///
    /// Scope: `src/stdlib/**` recursively — the top-level modules plus nested
    /// trees (e.g. `platform/**`). `http.rs` owns the interpreter's HTTP
    /// client and applies the egress proxy itself; everything else must go
    /// through this module. Banned shapes are [`BANNED_PATTERNS`] (bare
    /// shims, `ureq::agent()` / `ureq::Agent::new_with_defaults()` default
    /// agents) plus a hand-built `config_builder` agent without `.proxy(…)`.
    /// Tolerated sites are the tracked debt in [`STDLIB_ALLOWED`].
    #[test]
    fn no_bare_ureq_calls_outside_the_egress_client() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        collect_runtime_rs(&root.join("src/stdlib"), &mut files);

        let mut offenders = Vec::new();
        for path in files {
            let rel = rel_path(root, &path);
            // http.rs owns the interpreter's HTTP client and applies the egress
            // proxy itself; everything else must go through this module.
            if rel == "src/stdlib/http.rs" {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read stdlib file");
            let code = uncommented(&src);
            for pat in BANNED_PATTERNS {
                if code.contains(pat) && !stdlib_allowlisted(&rel, pat) {
                    offenders.push(format!("{rel}: {pat}"));
                }
            }
            // A hand-built agent is fine only if it actually sets a proxy.
            if code.contains("ureq::Agent::config_builder()")
                && !code.contains(".proxy(")
                && !stdlib_allowlisted(&rel, CONFIG_BUILDER_DEBT)
            {
                offenders.push(format!("{rel}: {CONFIG_BUILDER_DEBT}"));
            }
        }
        assert!(
            offenders.is_empty(),
            "unproxied stdlib HTTP calls found — route them through \
             crate::runtime::egress_http (they would egress from the box IP): {offenders:?}"
        );
    }

    /// No runtime, interpreter, browser or top-level module may build its own
    /// unproxied `ureq` client either.
    ///
    /// Companion to [`no_bare_ureq_calls_outside_the_egress_client`] (which
    /// covers `src/stdlib/**`). Everything else that can egress from the box
    /// IP is in scope: `src/runtime/*.rs`, every top-level `src/*.rs` (the
    /// interpreter included), `src/browser/**` and every crate src tree. All
    /// must ride *this* module's Tor-default egress contract. A bare
    /// `ureq::get(…)` egresses from the box IP; a default agent
    /// (`ureq::agent()` / `ureq::Agent::new_with_defaults()`) can never carry
    /// a proxy; a hand-built agent without `.proxy(…)` silently ignores
    /// `TALLOW_PROXY`. Whole-line comments are skipped (docs legitimately
    /// *name* the banned patterns, e.g. `fetch.rs`'s history note); string
    /// literals and trailing comments still count. Tolerated sites are the
    /// tracked debt in [`RUNTIME_ALLOWED`] — everything else fails the guard.
    #[test]
    fn no_bare_ureq_calls_in_the_runtime_tree() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(root.join("src/runtime"))
            .expect("read src/runtime")
            .map(|entry| entry.expect("dir entry").path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("rs"))
            .collect();
        // Every top-level `src/*.rs`: the interpreter plus the other
        // single-file modules (request plan, …).
        files.extend(
            std::fs::read_dir(root.join("src"))
                .expect("read src")
                .map(|entry| entry.expect("dir entry").path())
                .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("rs")),
        );
        // The browser tree is a second egress surface (robots.txt, browser
        // downloads, captcha solvers, sitemaps, …): recursive.
        collect_runtime_rs(&root.join("src/browser"), &mut files);
        // Every crate src tree is in scope too (recursive); a missing
        // `crates/` or `src/` just contributes no files.
        if let Ok(crates) = std::fs::read_dir(root.join("crates")) {
            for c in crates.filter_map(|e| e.ok()) {
                collect_runtime_rs(&c.path().join("src"), &mut files);
            }
        }

        let mut offenders = Vec::new();
        for path in files {
            let rel = rel_path(root, &path);
            // The egress client itself is the sanctioned `ureq` surface — the
            // analogue of `http.rs` in the stdlib guard above; every other
            // module must go through it.
            if rel == "src/runtime/egress_http.rs" {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read runtime file");
            let code = uncommented(&src);
            for pat in BANNED_PATTERNS {
                if code.contains(pat) && !runtime_allowlisted(&rel, pat) {
                    offenders.push(format!("{rel}: {pat}"));
                }
            }
            // A hand-built agent is fine only if it actually sets a proxy.
            if code.contains("ureq::Agent::config_builder()")
                && !code.contains(".proxy(")
                && !runtime_allowlisted(&rel, CONFIG_BUILDER_DEBT)
            {
                offenders.push(format!("{rel}: {CONFIG_BUILDER_DEBT}"));
            }
        }
        assert!(
            offenders.is_empty(),
            "unproxied runtime/interpreter HTTP calls found — route them through \
             crate::runtime::egress_http (they would egress from the box IP): {offenders:?}"
        );
    }

    /// R-6.13 (lite): no hard egress refusal without a telemetry emission.
    ///
    /// Third source guard, after the two `no_bare_ureq_…` tests. Every module
    /// that owns a hard egress-refusal constructor must emit one redacted
    /// security event at the observability choke point (`crate::observability`,
    /// R-6.1 slice 1) on the refusal path — the wiring T-115/T-115b landed for
    /// `runtime.egress_http`, `interp.rs` fetch, `stdlib.http`,
    /// `stdlib.cnam_dip` and `stdlib.lrn_dip`.
    ///
    /// Mechanism: a per-`(file, marker)` string-containment check —
    /// [`REFUSAL_SITES`] names each refusal site by a marker substring (the
    /// message spine `"refusing to run unproxied"`, or the shared
    /// `refusal_hint` helper); the file must contain that marker **and** an
    /// `emit_to_default_journal(` call within 4000 bytes of it. The test tail
    /// (`#[cfg(test)]` onward) is excluded via [`non_test_code`], so the guard
    /// can never be satisfied by its own test text — or by anyone else's. The
    /// failure mode (emit removed ⇒ flagged) is exercised on fixture files
    /// below.
    ///
    /// A refusal that legitimately cannot emit must be listed in
    /// [`REFUSAL_EMIT_ALLOWED`] — DEBT, keep minimal: each entry is a site the
    /// guard no longer protects, so it states exactly where it is and why it
    /// is tolerated (same convention as [`STDLIB_ALLOWED`] /
    /// [`RUNTIME_ALLOWED`]).
    #[test]
    fn every_hard_egress_refusal_emits_a_security_event() {
        // `(manifest-relative file, refusal marker)`.
        const REFUSAL_SITES: &[(&str, &str)] = &[
            // Runtime fetch/agent builders: `parse_proxy` emits next to the
            // refusal it panics with (T-115).
            ("src/runtime/egress_http.rs", "refusal_hint"),
            // Interpreter fetch refusal (same T-115 wiring, `interp.rs`).
            ("src/interp.rs", "refusing to run unproxied"),
            // Standard-library client builders: `http.rs` `proxy_for_url`
            // (T-115), `cnam_dip.rs` / `lrn_dip.rs` `proxy_for_url` (T-115b).
            ("src/stdlib/http.rs", "refusing to run unproxied"),
            ("src/stdlib/cnam_dip.rs", "refusing to run unproxied"),
            ("src/stdlib/lrn_dip.rs", "refusing to run unproxied"),
        ];
        // DEBT — keep empty/minimal: every entry is a refusal site the guard
        // no longer protects; state the site and why it cannot emit.
        const REFUSAL_EMIT_ALLOWED: &[(&str, &str)] = &[];

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let offenders = refusal_emit_offenders(root, REFUSAL_SITES, REFUSAL_EMIT_ALLOWED);
        assert!(
            offenders.is_empty(),
            "hard egress refusals must emit a security event (R-6.13) — wire \
             crate::observability::emit_to_default_journal next to the refusal \
             or allowlist the site: {offenders:?}"
        );

        // Failure mode on fixtures (emit removed ⇒ the checker flags the
        // site): proves the guard fails if emit calls are removed, without
        // mutating the real tree.
        let fixture = std::env::temp_dir()
            .join(format!("t115b-refusal-emit-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(&fixture).expect("create fixture dir");
        std::fs::write(
            fixture.join("unwired.rs"),
            "fn refusal() -> String {\n    \"refusing to run unproxied\".to_string()\n}\n",
        )
        .expect("write unwired fixture");
        std::fs::write(
            fixture.join("wired.rs"),
            "fn refusal() -> String {\n    let _ = crate::observability::emit_to_default_journal(&ev);\n    \"refusing to run unproxied\".to_string()\n}\n",
        )
        .expect("write wired fixture");
        const FIXTURE_SITES: &[(&str, &str)] = &[
            ("wired.rs", "refusing to run unproxied"),
            ("unwired.rs", "refusing to run unproxied"),
        ];
        let flagged = refusal_emit_offenders(&fixture, FIXTURE_SITES, &[]);
        let _ = std::fs::remove_dir_all(&fixture);
        assert_eq!(
            flagged.len(),
            1,
            "exactly the emit-less fixture must be flagged: {flagged:?}"
        );
        assert!(
            flagged[0].starts_with("unwired.rs:"),
            "the emit-less fixture must be the one flagged: {flagged:?}"
        );
    }

    /// Core of [`every_hard_egress_refusal_emits_a_security_event`], taking an
    /// explicit root + site list so fixtures can exercise it. The emit must
    /// sit within 4000 bytes of the marker in the file's non-test code —
    /// generous, but tight enough that an unrelated emit elsewhere in a large
    /// module (e.g. `interp.rs`) would not save the site.
    fn refusal_emit_offenders(
        root: &std::path::Path,
        sites: &[(&str, &str)],
        allowed: &[(&str, &str)],
    ) -> Vec<String> {
        const EMIT_MARKER: &str = "emit_to_default_journal";
        const EMIT_WINDOW: usize = 4_000;
        let mut offenders = Vec::new();
        for (rel, marker) in sites {
            if allowed.iter().any(|(f, m)| f == rel && m == marker) {
                continue;
            }
            let src = std::fs::read_to_string(root.join(rel))
                .unwrap_or_else(|e| panic!("read refusal site {rel}: {e}"));
            let code = uncommented(&non_test_code(&src));
            let Some(m_pos) = code.find(marker) else {
                offenders.push(format!(
                    "{rel}: refusal marker {marker:?} not found — REFUSAL_SITES is stale"
                ));
                continue;
            };
            let mut nearest = usize::MAX;
            let mut from = 0;
            while let Some(p) = code[from..].find(EMIT_MARKER) {
                let at = from + p;
                nearest = nearest.min(at.abs_diff(m_pos));
                from = at + EMIT_MARKER.len();
            }
            if nearest > EMIT_WINDOW {
                offenders.push(format!(
                    "{rel}: refusal ({marker:?}) without a nearby {EMIT_MARKER}(…) call (nearest: {})",
                    if nearest == usize::MAX {
                        "none".to_string()
                    } else {
                        format!("{nearest} bytes")
                    }
                ));
            }
        }
        offenders
    }

    /// The source with its test tail removed: everything from the first
    /// `#[cfg(test)]` line on is dropped. Source guards must judge the
    /// non-test code, so their own (or any test's) text can never satisfy a
    /// check; all currently guarded modules keep their test code after a
    /// single `#[cfg(test)]` tail, which makes the first-match cut exact. If
    /// a file ever gains an earlier `#[cfg(test)]` block, its marker check
    /// fails loudly (stale `REFUSAL_SITES`) rather than passing silently.
    fn non_test_code(src: &str) -> String {
        let mut out = String::new();
        for line in src.lines() {
            if line.trim_start().starts_with("#[cfg(test)]") {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Banned substrings — bare `ureq` constructors and request shims that
    /// bypass this module's egress contract.
    ///
    /// The request shims (`ureq::get(…)` …) go out unproxied; `ureq::agent()`
    /// and `ureq::Agent::new_with_defaults()` hand out a default agent that
    /// can never carry a proxy (the same leak); `ureq::Agent::config_builder()`
    /// is additionally banned without `.proxy(…)` (see [`CONFIG_BUILDER_DEBT`]).
    const BANNED_PATTERNS: &[&str] = &[
        "ureq::get(",
        "ureq::post(",
        "ureq::put(",
        "ureq::delete(",
        "ureq::head(",
        "ureq::patch(",
        "ureq::agent(",
        "ureq::Agent::new_with_defaults(",
    ];

    /// Canonical debt key for a hand-built agent that never sets `.proxy(…)`.
    /// Doubles as the allowlist pattern for that check, so the proxied shape
    /// of the same call stays fine.
    const CONFIG_BUILDER_DEBT: &str = "ureq::Agent::config_builder() without .proxy(…)";

    /// `(manifest-relative file, banned pattern)` pairs the stdlib guard
    /// tolerates.
    ///
    /// DEBT — keep minimal: every entry is a site the guard no longer
    /// protects, so each states exactly where it is and why it is tolerated.
    /// The former `("src/stdlib/transfer.rs", "ureq::agent(")` entry was
    /// **deleted**: R1-1 landed and the four S3 helpers (`s3_req_no_body`,
    /// `s3_req_with_body`, `s3_get_bytes`, `cloud_s3_head`) now ride the
    /// shared proxy-aware agent built from `egress_http::agent_with_timeouts`
    /// (60 s global / 30 s per call) — no bare `ureq` site remains in
    /// `src/stdlib/**`, so the debt list is empty (zero tolerance, same
    /// end-state convention as `RUNTIME_ALLOWED` / `REFUSAL_EMIT_ALLOWED`).
    const STDLIB_ALLOWED: &[(&str, &str)] = &[];

    fn stdlib_allowlisted(file: &str, pat: &str) -> bool {
        STDLIB_ALLOWED.iter().any(|(f, p)| *f == file && *p == pat)
    }

    /// `(manifest-relative file, banned pattern)` pairs the runtime guard
    /// tolerates.
    ///
    /// DEBT — keep minimal: every entry is a site the guard no longer
    /// protects, so each states exactly where it is and why it is tolerated.
    /// The former `("src/interp.rs", "ureq::get(")` entry was **deleted**:
    /// T-103a landed and that site now runs through
    /// `crate::runtime::egress_http::get` (+ `egress_refusal`). The T-108
    /// browser entries (robots, download, captcha, proxy_intelligence,
    /// sitemap, adaptive_crawler) were **deleted** by T-115c: T-207 landed,
    /// every browser path now rides the `browser::zone` predicate /
    /// `egress_http` contract, and none of those patterns remains in the
    /// named files. The last entry, `("src/request_plan.rs", "ureq::get(")`,
    /// was **deleted** by T-104b: `execute_get` now refuses on a configured-
    /// but-unusable proxy (`egress_refusal`) and otherwise rides
    /// `crate::runtime::egress_http::get` — no bare `ureq` site remains in
    /// the runtime tree, so the debt list is empty (zero tolerance, same
    /// end-state convention as `REFUSAL_EMIT_ALLOWED`).
    const RUNTIME_ALLOWED: &[(&str, &str)] = &[];

    fn runtime_allowlisted(file: &str, pat: &str) -> bool {
        RUNTIME_ALLOWED.iter().any(|(f, p)| *f == file && *p == pat)
    }

    /// The file's code with whole-line comments dropped.
    ///
    /// Docs legitimately *name* the banned patterns, so whole-line comments
    /// are skipped; string literals and trailing comments still count.
    fn uncommented(src: &str) -> String {
        src.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Manifest-relative, `/`-separated path — the allowlist key and the
    /// offender label share this form.
    fn rel_path(root: &std::path::Path, path: &std::path::Path) -> String {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }

    /// Recursively collect `*.rs` files under `dir` (missing dir = no-op).
    fn collect_runtime_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                collect_runtime_rs(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn tor_is_the_default_and_direct_needs_an_explicit_opt_in() {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = env_lock();
        unsafe { std::env::remove_var("TALLOW_PROXY") };
        unsafe { std::env::remove_var("TALLOW_TOR") };
        unsafe { std::env::remove_var("TALLOW_TOR_ISOLATE") };
        unsafe { std::env::remove_var("TALLOW_ALLOW_DIRECT") };
        // Fail-closed: with nothing set at all, traffic goes to Tor — with the
        // per-run circuit identity bound in the URL (P1 W1-E1). A compiled
        // binary or an interpreter run that forgets to export anything cannot
        // leak the box IP by omission.
        let tor_default = proxy_url().expect("no env at all must still route to Tor");
        assert!(
            tor_default.starts_with("socks5h://") && tor_default.ends_with("@127.0.0.1:9050"),
            "no env at all must still route to Tor with per-run credentials: {tor_default}"
        );
        // A typo or a false-y value must NOT open a leak (and must not
        // downgrade the resolved default either).
        for junk in ["nope", "0", "false", "", "no"] {
            unsafe { std::env::set_var("TALLOW_ALLOW_DIRECT", junk) };
            assert_eq!(
                proxy_url().as_deref(),
                Some(tor_default.as_str()),
                "TALLOW_ALLOW_DIRECT={junk:?} must not enable direct egress"
            );
        }
        // The explicit opt-out is the only route to a direct connection.
        unsafe { std::env::set_var("TALLOW_ALLOW_DIRECT", "1") };
        assert_eq!(proxy_url(), None);
        // An explicit proxy outranks the opt-out (and keeps the socks5h upgrade).
        unsafe { std::env::set_var("TALLOW_PROXY", "socks5://127.0.0.1:9051") };
        assert_eq!(proxy_url().as_deref(), Some("socks5h://127.0.0.1:9051"));
        // A blank TALLOW_PROXY falls through to the opt-out rather than to Tor.
        unsafe { std::env::set_var("TALLOW_PROXY", "  ") };
        assert_eq!(proxy_url(), None);
        unsafe { std::env::remove_var("TALLOW_PROXY") };
        unsafe { std::env::remove_var("TALLOW_ALLOW_DIRECT") };
    }

    #[test]
    fn agent_is_proxy_aware_when_env_set() {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = env_lock();
        unsafe { std::env::remove_var("TALLOW_PROXY") };
        unsafe { std::env::set_var("TALLOW_TOR", "1") };
        let resolved = proxy_url().expect("TALLOW_TOR=1 must resolve the Tor default");
        assert!(
            resolved.starts_with("socks5h://") && resolved.ends_with("@127.0.0.1:9050"),
            "the Tor default carries the per-run circuit identity: {resolved}"
        );
        let _ = agent();
        assert!(
            AGENTS.lock().unwrap().contains_key(&resolved),
            "agent() must key its cache on the resolved proxy URL"
        );
        let _ = agent(); // must build without panicking
        unsafe { std::env::remove_var("TALLOW_TOR") };
    }

    /// N3: an unparseable proxy URL must refuse, never degrade to direct.
    /// Pure over its input — deliberately no env mutation, so it cannot race
    /// the env-based tests above (which mutate `TALLOW_PROXY`).
    #[test]
    fn unparseable_proxy_url_reports_a_hard_refusal() {
        let reason = refusal_reason("::::nope").expect("malformed proxy URL must refuse");
        assert!(
            reason.contains("refusing to run unproxied"),
            "the message must say it is refusing: {reason:?}"
        );
        // The fail-closed Tor default and a valid explicit proxy stay usable.
        assert!(refusal_reason(crate::runtime::fetch::TOR_SOCKS_URL).is_none());
        assert!(refusal_reason("socks5h://127.0.0.1:9051").is_none());
    }

    /// N3 mechanism: the build path panics instead of falling back to a
    /// proxyless (i.e. direct) agent. Pure over its input — no env, no race.
    #[test]
    #[should_panic(expected = "refusing to run unproxied")]
    fn the_build_path_refuses_instead_of_degrading_to_direct() {
        let _ = parse_proxy("::::nope");
    }
}
