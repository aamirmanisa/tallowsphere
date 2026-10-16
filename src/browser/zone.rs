//! Browser-zone egress lockdown (P4-15 slice, task T-207).
//!
//! The browser zone is a network-privileged surface: page loads, the cookie
//! bridge, antibot/captcha solvers, downloads, sitemaps and the CDP control
//! channel all emanate from it. P4-15 promises that browser-zone egress
//! reaches **only** the box's egress contract (Tor SOCKS by default) plus the
//! in-zone CDP relay. This module is the single authoritative predicate
//! behind that promise: every browser-originated network path asks it
//! whether egress is allowed and, if so, over which proxy — no per-call
//! ad-hoc decisions, no silent direct fallbacks.
//!
//! The contract itself lives in [`crate::runtime::egress_http`]:
//!
//! - **Tor is the default** — with no env at all the zone egresses via
//!   `socks5h://127.0.0.1:9050` ([`crate::runtime::fetch::TOR_SOCKS_URL`]).
//! - **`TALLOW_PROXY` overrides** the default for every zone path.
//! - **`TALLOW_ALLOW_DIRECT=1`** is the explicit, logged opt-out
//!   ([`ZoneEgress::DirectOptIn`]) — a leak by design, never the default,
//!   and audited: the first zone path that resolves to it emits one
//!   [`crate::observability::EventClass::DirectEgress`] record (T-207-fu).
//! - A configured-but-unusable proxy URL is a **hard refusal**
//!   ([`browser_zone_egress`] returns `Err`): the zone must never degrade to
//!   a direct connection (invariant N3).
//!
//! Consumers:
//! - `process.rs` launch args: [`browser_zone_chrome_proxy`] decides
//!   `--proxy-server` for the browser process (page loads).
//! - `juggler.rs` launch (Camoufox/Firefox): [`browser_zone_firefox_proxy`]
//!   + [`firefox_user_js_proxy_prefs`] put the contract into the profile's
//!   `user.js` (Firefox has no `--proxy-server`); an inexpressible contract
//!   proxy refuses the launch (T-207-fu residual closure).
//! - `page.rs` cookie bridge: [`browser_zone_egress`] gate before the
//!   contract agent serves authenticated fetches.
//! - `cdp.rs` connect: [`is_in_zone_target`] keeps the CDP target loopback /
//!   pipe only (an unauthenticated network CDP port is CHAIN-5-4).
//! - reqwest-based browser clients (`dual_mode`, `free_proxies`,
//!   `perf_engine`, `autonomous`, `dpi_bypass`): [`browser_zone_reqwest_proxy`].
//!
//! The source guard at the bottom of this file (mirroring the
//! `src/runtime/egress_http.rs` guards) keeps the zone honest: bare `ureq`
//! constructors and direct client construction may not reappear outside this
//! module, and a hand-built reqwest/ureq client is only tolerated when the
//! file actually attaches the contract proxy.

/// Decision for one browser-zone network path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneEgress {
    /// WAN egress rides the runtime egress contract, over this proxy.
    Contract { proxy: String },
    /// Destination is in-zone (loopback CDP relay / local service): the
    /// bytes never leave the zone, so no WAN route applies.
    InZone,
    /// Explicit operator opt-out (`TALLOW_ALLOW_DIRECT=1`): the zone egresses
    /// directly. Leak-by-design — surfaced to the operator, never silent.
    DirectOptIn,
}

/// T-128: one process-global test-only env lock. Every test that mutates
/// process env (`TALLOW_*` / proxy vars) serializes on
/// [`crate::runtime::egress_http::env_lock`]; `ZONE_ENV_LOCK` is kept as a
/// re-export of the same mutex for pre-existing call sites (juggler tests).
#[cfg(test)]
pub(crate) use crate::runtime::egress_http::ENV_LOCK as ZONE_ENV_LOCK;

/// Emit one redacted refusal event (R-6.13 pattern: hard egress refusals are
/// telemetry-bearing). `target` names the site or URL that was refused.
pub(crate) fn emit_zone_refusal(target: &str) {
    let _ = crate::observability::emit_to_default_journal(&crate::observability::SecurityEvent {
        class: crate::observability::EventClass::EgressRefusal,
        actor: "browser.zone".to_string(),
        target: Some(target.to_string()),
        size: target.len(),
        at_ms: crate::observability::now_ms(),
    });
}

/// Emit the direct-egress opt-in as an audit record (same R-6.13 pattern as
/// [`emit_zone_refusal`], mirrored from the `egress_http` emission sites).
///
/// `TALLOW_ALLOW_DIRECT=1` makes zone traffic leave from the box IP; that is
/// leak-by-design but must never be **silent** — the record carries
/// [`crate::observability::EventClass::DirectEgress`] (audit plane, actor
/// `browser.zone`), one per bypass decision.
pub(crate) fn emit_zone_direct_bypass(reason: &str) {
    let _ = crate::observability::emit_to_default_journal(&crate::observability::SecurityEvent {
        class: crate::observability::EventClass::DirectEgress,
        actor: "browser.zone".to_string(),
        target: Some(reason.to_string()),
        size: reason.len(),
        at_ms: crate::observability::now_ms(),
    });
}

/// The opt-in bypass is a per-process posture, not a per-request event: emit
/// it exactly once (the first zone path that resolves to
/// [`ZoneEgress::DirectOptIn`]), so the journal stays signal instead of one
/// record per fetch. Refusals ([`emit_zone_refusal`]) stay per-occurrence.
fn emit_zone_direct_bypass_once() {
    static EMITTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !EMITTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        emit_zone_direct_bypass(
            "TALLOW_ALLOW_DIRECT=1 — browser-zone egress is direct (leak-by-design opt-in)",
        );
    }
}

/// The single authoritative browser-zone egress predicate.
///
/// Every browser-originated WAN path must pass through this decision —
/// request builders, launch args (`--proxy-server` / Firefox `user.js`
/// prefs), and the tests that guard them. `Ok` carries the contract verdict;
/// `Err(reason)` is the N3 hard refusal (the zone must not degrade to a
/// direct connection).
pub fn browser_zone_egress() -> Result<ZoneEgress, String> {
    if let Some(reason) = crate::runtime::egress_http::egress_refusal() {
        emit_zone_refusal(&reason);
        return Err(reason);
    }
    match crate::runtime::egress_http::proxy_url() {
        Some(proxy) => Ok(ZoneEgress::Contract { proxy }),
        None => {
            // DirectOptIn is the operator's explicit opt-out — audit it.
            emit_zone_direct_bypass_once();
            Ok(ZoneEgress::DirectOptIn)
        }
    }
}

/// Predicate for a concrete destination: in-zone targets never count as WAN
/// egress; everything else must resolve to [`ZoneEgress::Contract`] (or the
/// explicit operator opt-in).
pub fn browser_zone_egress_for(target: &str) -> Result<ZoneEgress, String> {
    if is_in_zone_target(target) {
        return Ok(ZoneEgress::InZone);
    }
    browser_zone_egress()
}

/// True for the in-zone destinations the browser zone legitimately talks to
/// without the WAN contract: the loopback CDP relay (`ws://127.0.0.1:<port>`),
/// `localhost`, bracketed IPv6 loopback, any loopback address, and
/// unix-socket / pipe targets. Everything else (WAN *and* LAN) is a
/// contract egress.
///
/// Note this is intentionally strict about host parsing: `127.evil.com` and
/// other lookalike names are **not** loopback.
pub fn is_in_zone_target(target: &str) -> bool {
    let t = target.trim();
    if t.starts_with("unix:") || t.starts_with("pipe:") {
        return true;
    }
    // Strip scheme, then path/query/fragment, then userinfo, then port.
    let after_scheme = match t.split_once("://") {
        Some((_, rest)) => rest,
        None => t,
    };
    let hostport = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host = hostport.rsplit('@').next().unwrap_or(hostport);
    let host = match host.strip_prefix('[') {
        // Bracketed IPv6: `[::1]:9222` → `::1`.
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => match host.rfind(':') {
            Some(i)
                if !host[i + 1..].contains(']')
                    && host[i + 1..].chars().all(|c| c.is_ascii_digit()) =>
            {
                &host[..i]
            }
            _ => host,
        },
    };
    let host = host.trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback();
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return ip.is_loopback();
    }
    host.eq_ignore_ascii_case("localhost")
}

/// `--proxy-server` value for a browser launch, decided by the zone
/// predicate.
///
/// - `Ok(Some(url))` — route the browser process over the contract
///   (`process.rs` normalizes the scheme for Chrome before passing it).
/// - `Ok(None)` — explicit `TALLOW_ALLOW_DIRECT=1` opt-in: launch direct
///   (leak-by-design; never chosen by default).
/// - `Err(reason)` — the configured proxy is unusable: refuse to launch
///   rather than spawn a browser that can egress from the box IP.
///
/// Firefox-family launches (Camoufox/Firefox backends) take the same
/// decision through [`browser_zone_firefox_proxy`].
pub fn browser_zone_chrome_proxy() -> Result<Option<String>, String> {
    match browser_zone_egress()? {
        ZoneEgress::Contract { proxy } => Ok(Some(proxy)),
        ZoneEgress::DirectOptIn => Ok(None),
        ZoneEgress::InZone => Ok(None),
    }
}

/// Firefox-family (`BrowserBackend::Camoufox` / `Firefox`) launch decision.
///
/// The launcher differs — Firefox has no `--proxy-server`, so the contract is
/// applied through [`firefox_user_js_proxy_prefs`] in the profile's `user.js`
/// — the predicate does not: same contract as [`browser_zone_chrome_proxy`],
/// same explicit-opt-in `Ok(None)`, same N3 refusal on a malformed configured
/// proxy. T-207's residual (the Camoufox/Firefox early-return spawning
/// unproxied) is closed by `juggler.rs` consuming this decision.
pub fn browser_zone_firefox_proxy() -> Result<Option<String>, String> {
    browser_zone_chrome_proxy()
}

/// `user.js` pref lines that route a Firefox-family profile over the zone
/// contract proxy.
///
/// Firefox prefs (manual proxy mode) are the only launch-time knob — there is
/// no `--proxy-server` — and this is the same mechanism Playwright/Camoufox
/// use for their `proxy` launch option. `Err` is the N3 refusal: a contract
/// proxy this cannot express (no scheme, no host, no usable port, or an
/// `https://` endpoint, which Firefox prefs cannot encode) must refuse the
/// launch rather than spawn a Firefox that egresses from the box IP.
///
/// `socks5h://` (the box's remote-DNS Tor spelling) maps to
/// `network.proxy.socks_remote_dns=true`; a plain `socks5://` must not leak
/// remote-DNS semantics, so it maps to `false`.
pub(crate) fn firefox_user_js_proxy_prefs(proxy_url: &str) -> Result<Vec<String>, String> {
    let url = proxy_url.trim();
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        format!(
            "[zone] refusing to launch Firefox with unrecognized contract proxy {url:?} \
             (no scheme — prefs need an explicit socks5h://socks5://socks4://http:// endpoint)"
        )
    })?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "socks5h" | "socks5" | "socks" | "socks4" | "http") {
        return Err(format!(
            "[zone] refusing to launch Firefox: contract proxy scheme {scheme:?} is not \
             expressible as Firefox profile prefs (socks5h/socks5/socks4/http are; an \
             https:// proxy endpoint cannot be encoded)"
        ));
    }
    // Strip path/query/fragment, then split userinfo, then host:port —
    // bracketed IPv6 handled explicitly.
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (userinfo, hostport) = match hostport.rsplit_once('@') {
        Some((u, hp)) => (Some(u), hp),
        None => (None, hostport),
    };
    let (host, port_str) = match hostport.strip_prefix('[') {
        Some(rest6) => match rest6.split_once(']') {
            Some((h6, tail)) => (h6.to_string(), tail.strip_prefix(':')),
            None => (String::new(), None),
        },
        None => match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (hostport.to_string(), None),
        },
    };
    if host.is_empty() {
        return Err(format!(
            "[zone] refusing to launch Firefox: contract proxy {url:?} has no host"
        ));
    }
    let port: u16 = match port_str.and_then(|p| p.parse::<u16>().ok()) {
        Some(p) if p != 0 => p,
        _ => {
            return Err(format!(
                "[zone] refusing to launch Firefox: contract proxy {url:?} has no usable \
                 port (a missing/typo'd port must not silently become a default)"
            ))
        }
    };

    let mut prefs = Vec::new();
    // Manual proxy mode (1) + keep in-zone destinations (loopback CDP relay,
    // local services) out of the tunnel.
    prefs.push("user_pref(\"network.proxy.type\", 1);".to_string());
    prefs.push(
        "user_pref(\"network.proxy.no_proxies_on\", \"localhost, 127.0.0.1, [::1]\");".to_string(),
    );
    if scheme.starts_with("socks") {
        prefs.push(format!("user_pref(\"network.proxy.socks\", {host:?});"));
        prefs.push(format!("user_pref(\"network.proxy.socks_port\", {port});"));
        prefs.push(format!(
            "user_pref(\"network.proxy.socks_version\", {});",
            if scheme == "socks4" { 4 } else { 5 }
        ));
        prefs.push(format!(
            "user_pref(\"network.proxy.socks_remote_dns\", {});",
            scheme == "socks5h"
        ));
        if let Some(u) = userinfo {
            let (user, pass) = match u.split_once(':') {
                Some((user, pass)) => (user, pass),
                None => (u, ""),
            };
            prefs.push(format!(
                "user_pref(\"network.proxy.socks_username\", {user:?});"
            ));
            prefs.push(format!(
                "user_pref(\"network.proxy.socks_password\", {pass:?});"
            ));
        }
    } else {
        // Plain HTTP CONNECT proxy endpoint for all protocols.
        prefs.push(format!("user_pref(\"network.proxy.http\", {host:?});"));
        prefs.push(format!("user_pref(\"network.proxy.http_port\", {port});"));
        prefs.push("user_pref(\"network.proxy.share_proxy_settings\", true);".to_string());
    }
    Ok(prefs)
}

/// Contract-bound `reqwest` proxy for in-process browser clients.
///
/// `Ok(Some(p))` = attach to the client; `Ok(None)` = explicit direct
/// opt-in; `Err(reason)` = the contract proxy is unusable and the caller
/// must refuse to build a direct client (N3).
pub fn browser_zone_reqwest_proxy() -> Result<Option<reqwest::Proxy>, String> {
    match browser_zone_egress()? {
        ZoneEgress::Contract { proxy } => match reqwest::Proxy::all(&proxy) {
            Ok(p) => Ok(Some(p)),
            Err(e) => {
                let reason = format!(
                    "[zone] refusing to build a direct browser-zone client — \
                     contract proxy {proxy:?} unusable for reqwest: {e}"
                );
                emit_zone_refusal(&reason);
                Err(reason)
            }
        },
        ZoneEgress::DirectOptIn | ZoneEgress::InZone => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure classifier: only true loopback / pipe destinations are in-zone.
    #[test]
    fn in_zone_targets_are_loopback_only() {
        for t in [
            "ws://127.0.0.1:9222/devtools/browser/abc",
            "http://127.0.0.1:9222/json/version",
            "ws://localhost:9222",
            "http://localhost/x",
            "ws://[::1]:9222/devtools/browser/x",
            "127.0.0.1:9222",
            "unix:/tmp/cdp.sock",
            "pipe:3",
        ] {
            assert!(is_in_zone_target(t), "{t} must be classified in-zone");
        }
        for t in [
            "https://example.com",
            "https://127.evil.com/",
            "http://169.254.169.254/latest/meta-data",
            "https://10.0.0.1/",
            "ws://192.168.1.2:9222",
            "socks5h://127.0.0.1:9050.onion.example.com",
        ] {
            assert!(
                !is_in_zone_target(t),
                "{t} must NOT be classified in-zone (WAN/LAN path)"
            );
        }
    }

    /// Env wiring: the predicate must reproduce the contract's verdict and
    /// the chrome-proxy decision it feeds `process.rs`.
    #[test]
    fn zone_predicate_rides_the_contract_and_refuses_malformed_proxies() {
        let _guard = crate::runtime::egress_http::env_lock();
        unsafe { std::env::remove_var("TALLOW_ALLOW_DIRECT") };
        unsafe { std::env::remove_var("TALLOW_PROXY") };
        unsafe { std::env::remove_var("TALLOW_TOR") };
        unsafe { std::env::remove_var("TALLOW_TOR_ISOLATE") };
        // Fail-closed default: no env at all → Tor contract, not direct, with
        // the per-run circuit identity bound in the URL (P1 W1-E1).
        match browser_zone_egress().expect("default env must not refuse") {
            ZoneEgress::Contract { proxy } => assert!(
                proxy.starts_with("socks5h://") && proxy.ends_with("@127.0.0.1:9050"),
                "no env must route the zone to Tor with per-run credentials: {proxy}"
            ),
            other => panic!("no env must route the zone to Tor, got {other:?}"),
        }
        assert!(
            browser_zone_chrome_proxy()
                .ok()
                .flatten()
                .as_deref()
                .is_some_and(|p| p.starts_with("socks5h://") && p.ends_with("@127.0.0.1:9050")),
            "launch must get a --proxy-server value by default"
        );
        assert!(
            browser_zone_reqwest_proxy().expect("default").is_some(),
            "reqwest clients must get a contract proxy by default"
        );
        // The explicit isolation opt-out restores the bare URL (debug mode).
        unsafe { std::env::set_var("TALLOW_TOR_ISOLATE", "0") };
        assert_eq!(
            browser_zone_chrome_proxy().ok().flatten().as_deref(),
            Some(crate::runtime::fetch::TOR_SOCKS_URL),
            "TALLOW_TOR_ISOLATE=0 must resolve the bare Tor URL"
        );
        unsafe { std::env::remove_var("TALLOW_TOR_ISOLATE") };
        // Explicit opt-out → DirectOptIn (leak-by-design, operator-chosen).
        unsafe { std::env::set_var("TALLOW_ALLOW_DIRECT", "1") };
        assert_eq!(browser_zone_egress().ok(), Some(ZoneEgress::DirectOptIn));
        assert_eq!(browser_zone_chrome_proxy().ok().flatten(), None);
        // Malformed proxy → hard refusal (N3), never a direct fallback.
        unsafe { std::env::set_var("TALLOW_PROXY", "::::nope") };
        let err = browser_zone_egress().expect_err("malformed proxy must refuse");
        assert!(err.contains("refusing"), "refusal must say so: {err:?}");
        assert!(
            browser_zone_chrome_proxy().is_err(),
            "launch must refuse, not spawn a direct browser"
        );
        assert!(
            browser_zone_reqwest_proxy().is_err(),
            "clients must refuse, not degrade to direct"
        );
        // Restore.
        unsafe { std::env::remove_var("TALLOW_PROXY") };
        unsafe { std::env::remove_var("TALLOW_ALLOW_DIRECT") };
    }

    /// T-207-fu: the Firefox/Camoufox launcher has no `--proxy-server`, so the
    /// zone contract must be expressible as profile `user.js` prefs — or the
    /// launch refuses (N3). Never a direct Firefox.
    #[test]
    fn firefox_launch_gets_contract_proxy_prefs_or_refuses() {
        let socks = firefox_user_js_proxy_prefs("socks5h://127.0.0.1:9050")
            .expect("the box's Tor spelling must be expressible")
            .join("\n");
        assert!(socks.contains("user_pref(\"network.proxy.type\", 1);"));
        assert!(socks.contains("user_pref(\"network.proxy.socks\", \"127.0.0.1\");"));
        assert!(socks.contains("user_pref(\"network.proxy.socks_port\", 9050);"));
        assert!(
            socks.contains("user_pref(\"network.proxy.socks_remote_dns\", true);"),
            "socks5h must enable remote DNS: {socks}"
        );
        // Scheme semantics stay honest: plain socks5 is local-DNS.
        let local = firefox_user_js_proxy_prefs("socks5://127.0.0.1:9050")
            .expect("socks5 must be expressible")
            .join("\n");
        assert!(local.contains("user_pref(\"network.proxy.socks_remote_dns\", false);"));
        // An HTTP proxy endpoint rides one shared CONNECT setting.
        let http = firefox_user_js_proxy_prefs("http://10.0.0.5:3128")
            .expect("http proxy must be expressible")
            .join("\n");
        assert!(http.contains("user_pref(\"network.proxy.http\", \"10.0.0.5\");"));
        assert!(http.contains("user_pref(\"network.proxy.http_port\", 3128);"));
        assert!(http.contains("user_pref(\"network.proxy.share_proxy_settings\", true);"));
        // SOCKS userinfo must survive into prefs, not be silently dropped.
        let auth = firefox_user_js_proxy_prefs("socks5h://user:pa55@127.0.0.1:9050")
            .expect("userinfo must be expressible")
            .join("\n");
        assert!(auth.contains("user_pref(\"network.proxy.socks_username\", \"user\");"));
        assert!(auth.contains("user_pref(\"network.proxy.socks_password\", \"pa55\");"));
        // Inexpressible contract proxies refuse — never launch unproxied.
        for bad in [
            "::::nope",
            "127.0.0.1:9050",
            "socks5h://127.0.0.1",
            "socks5h://:9050",
            "https://10.0.0.5:3128",
        ] {
            let err = firefox_user_js_proxy_prefs(bad)
                .expect_err(&format!("{bad} must refuse"));
            assert!(
                err.contains("refusing"),
                "{bad}: refusal must say so: {err:?}"
            );
        }
    }

    /// T-207-fu: the `TALLOW_ALLOW_DIRECT` bypass records the dedicated
    /// `DirectEgress` class — a leak-by-design must never be silent.
    #[test]
    fn direct_bypass_is_recorded_as_a_dedicated_audit_class() {
        // Wire contract of the dedicated class.
        assert_eq!(
            crate::observability::EventClass::DirectEgress.as_str(),
            "direct_egress"
        );
        assert_eq!(
            crate::observability::EventClass::DirectEgress.plane(),
            crate::observability::Plane::Audit
        );

        let _guard = crate::runtime::egress_http::env_lock();
        let dir = std::env::temp_dir().join(format!(
            "t207fu-direct-bypass-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create journal dir");
        let journal = dir.join("security-events.jsonl");
        let prior = std::env::var("TALLOW_SECURITY_EVENTS").ok();
        unsafe { std::env::set_var("TALLOW_SECURITY_EVENTS", &journal) };
        emit_zone_direct_bypass("TALLOW_ALLOW_DIRECT=1 — test bypass record");
        match prior {
            Some(v) => unsafe { std::env::set_var("TALLOW_SECURITY_EVENTS", v) },
            None => unsafe { std::env::remove_var("TALLOW_SECURITY_EVENTS") },
        }
        let body = std::fs::read_to_string(&journal).expect("bypass must have been journaled");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            body.contains("\"class\":\"direct_egress\""),
            "record must carry the dedicated class: {body}"
        );
        assert!(
            body.contains("\"plane\":\"audit\""),
            "the posture change must land on the audit plane: {body}"
        );
        assert!(
            body.contains("\"actor_hash\""),
            "the actor must be hashed, never raw: {body}"
        );
    }

    /// T-207 source guard (mirrors the `src/runtime/egress_http.rs` runtime
    /// guard): within the browser zone, client construction is the predicate
    /// module's job.
    ///
    /// Scope: `src/browser/**` recursively. Banned everywhere except this
    /// module: bare `ureq` constructors / request shims and a default
    /// `reqwest::Client`; a hand-built ureq/reqwest client is tolerated only
    /// when the file actually sets a proxy (`.proxy(…)`). Tolerated sites are
    /// the tracked debt in [`ZONE_ALLOWED`] — everything else fails.
    #[test]
    fn every_browser_path_client_rides_the_zone_or_is_tracked_debt() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let offenders = zone_guard_offenders(root, ZONE_ALLOWED);
        assert!(
            offenders.is_empty(),
            "browser-zone client construction found outside src/browser/zone.rs — \
             route it through the zone predicate / crate::runtime::egress_http, \
             or allowlist it as tracked debt: {offenders:?}"
        );
    }

    /// Failure mode on fixtures: the guard must flag a contract-bypassing
    /// client and tolerate a proxied one. Proves the guard fails when a bare
    /// constructor reappears, without mutating the real tree.
    #[test]
    fn zone_guard_flags_client_construction_on_fixtures() {
        let fixture = std::env::temp_dir().join(format!(
            "t207-zone-guard-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(fixture.join("src/browser")).expect("create fixture dir");
        // Built via parts so this test's own text cannot satisfy the guard.
        let violator = [
            "fn f() { let _ = ureq::",
            "get(\"https://example.com\"); }\n",
        ]
        .concat();
        std::fs::write(fixture.join("src/browser/violator.rs"), violator)
            .expect("write violator fixture");
        std::fs::write(
            fixture.join("src/browser/proxied.rs"),
            "fn f() { let _ = reqwest::Client::builder().proxy(p).build(); }\n",
        )
        .expect("write proxied fixture");
        let flagged = zone_guard_offenders(&fixture, &[]);
        let _ = std::fs::remove_dir_all(&fixture);
        assert_eq!(
            flagged.len(),
            1,
            "exactly the contract-bypassing fixture must be flagged: {flagged:?}"
        );
        assert!(
            flagged[0].contains("violator.rs"),
            "the bare-constructor fixture must be the one flagged: {flagged:?}"
        );
    }

    /// Coverage contract (S1/S3 tie-in): the zone guard must actually read
    /// the browser modules whose network/injection surface it exists to
    /// protect — a guard that stops scanning `download.rs` is silently off.
    #[test]
    fn zone_guard_scans_the_download_and_bridge_modules() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        collect_rs(&root.join("src/browser"), &mut files);
        let rels: Vec<String> = files.iter().map(|p| rel_path(root, p)).collect();
        for required in [
            "src/browser/download.rs",
            "src/browser/cft_pins.rs",
            "src/browser/page.rs",
            "src/browser/stealth.rs",
            "src/browser/zone.rs",
        ] {
            assert!(
                rels.iter().any(|r| r == required),
                "zone guard must scan {required}; scanned: {rels:?}"
            );
        }
    }

    /// `(manifest-relative file, banned pattern)` pairs the zone guard
    /// tolerates.
    ///
    /// DEBT — keep minimal: every entry is a site the guard no longer
    /// protects, so each states exactly where it is and why it is tolerated.
    const ZONE_ALLOWED: &[(&str, &str)] = &[
        // `src/browser/typesense.rs` `TypesenseClient::new` (~L166): client
        // for a local Typesense search service (loopback default; base_url
        // caller-set). Tracked debt: the P4-15 netns slice pins local
        // services to an explicit local-only allowlist.
        ("src/browser/typesense.rs", concat!("reqwest::Client::", "new()")),
    ];

    /// Banned substrings — bare `ureq` constructors and default `reqwest`
    /// clients that bypass the zone predicate / egress contract. Built from
    /// parts so this file's own source never contains a live banned pattern
    /// (the `src/runtime/egress_http.rs` tree guard scans this file too).
    fn zone_banned_patterns() -> Vec<&'static str> {
        vec![
            concat!("ureq::", "get("),
            concat!("ureq::", "post("),
            concat!("ureq::", "put("),
            concat!("ureq::", "delete("),
            concat!("ureq::", "head("),
            concat!("ureq::", "patch("),
            concat!("ureq::", "agent("),
            concat!("ureq::Agent::", "new_with_defaults("),
            concat!("reqwest::Client::", "new()"),
        ]
    }

    /// A hand-built ureq agent without `.proxy(…)` silently ignores the
    /// contract; a hand-built reqwest client without `.proxy(…)` leaf
    /// similarly.
    const UREQ_CONFIG_BUILDER: &str = concat!("ureq::Agent::", "config_builder()");
    const REQWEST_BUILDER: &str = concat!("reqwest::Client::", "builder()");

    /// Core of [`every_browser_path_client_rides_the_zone_or_is_tracked_debt`],
    /// taking an explicit root + allowlist so fixtures can exercise it. This
    /// module (`src/browser/zone.rs`) is the sanctioned construction surface
    /// and is the one file skipped.
    fn zone_guard_offenders(
        root: &std::path::Path,
        allowed: &[(&str, &str)],
    ) -> Vec<String> {
        let mut files = Vec::new();
        collect_rs(&root.join("src/browser"), &mut files);

        let mut offenders = Vec::new();
        for path in files {
            let rel = rel_path(root, &path);
            // The predicate module itself is where construction is allowed.
            if rel == "src/browser/zone.rs" {
                continue;
            }
            let src = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let code = uncommented(&src);
            for pat in zone_banned_patterns() {
                if code.contains(pat) && !allowed.iter().any(|(f, p)| *f == rel && *p == pat) {
                    offenders.push(format!("{rel}: {pat}"));
                }
            }
            // A hand-built client is fine only if it actually sets a proxy.
            for pat in [UREQ_CONFIG_BUILDER, REQWEST_BUILDER] {
                if code.contains(pat)
                    && !code.contains(".proxy(")
                    && !allowed.iter().any(|(f, p)| *f == rel && *p == pat)
                {
                    offenders.push(format!("{rel}: {pat} without .proxy(…)"));
                }
            }
        }
        offenders
    }

    /// The file's code with whole-line comments dropped (docs legitimately
    /// *name* the banned patterns; trailing comments/strings still count).
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
    fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
}
