//! T-122 — egress census + resolver source guard + plain-DNS fail-closed guard.
//!
//! All groups run offline: the census/guard tests read `src/` and need no
//! network; the plain-DNS guard tests compile the real
//! `src/runtime/dns_guard.rs` via `#[path]` against a stub `observability`
//! module (`emit_to_default_journal` + `now_ms` are all the guard uses).
//!
//! * `egress_census_*`  — row #28: every egress-capable call site under `src/`
//!   (`ureq::` / `reqwest` / `hickory_resolver` / `TcpStream::connect` /
//!   `UdpSocket::{bind,connect}`) is contract-routed (a routing marker is
//!   present in the file) or allowlisted with a written reason. Bidirectional
//!   pin: a new unclassified file fails the test; a stale inventory entry
//!   fails it too.
//! * `resolver_calls_*` — row #61: DNS-resolver usage must be DoH-configured
//!   (`hickory_resolver` next to `CLOUDFLARE`) or allowlisted with a reason.
//!   Runtime leg `src/runtime/dns_guard.rs` is adopted at every registered
//!   raw-resolution site (T-122b); each such row pins the `dns_guard::`
//!   structural needle, so a regression that drops the guard fails the test.
//! * `plain_dns_*`      — fail-closed `:53` guard semantics (refusal emits an
//!   `EgressRefusal` event; the explicit opt-in emits `DirectEgress`; junk
//!   values stay fail-closed).
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

// ── Stub observability — compile-time stand-in for the guard's journal. ─────
// `src/runtime/dns_guard.rs` references `crate::observability::…`; in this
// test crate those paths resolve here (module of the same name at the crate
// root). Field names/types mirror the real `src/observability.rs`.
mod observability {
    use std::sync::Mutex;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EventClass {
        EgressRefusal,
        DirectEgress,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SecurityEvent {
        pub class: EventClass,
        pub actor: String,
        pub target: Option<String>,
        pub size: usize,
        pub at_ms: i64,
    }

    pub static EMITTED: Mutex<Vec<SecurityEvent>> = Mutex::new(Vec::new());

    pub fn now_ms() -> i64 {
        1_700_000_000_000
    }

    pub fn emit_to_default_journal(ev: &SecurityEvent) -> Result<(), String> {
        EMITTED.lock().expect("emitted lock").push(ev.clone());
        Ok(())
    }
}

/// The real guard, compiled straight from its production path.
#[path = "../src/runtime/dns_guard.rs"]
mod dns_guard;

use Class::{Allowlist, Contract, Sanctioned};

// ── Egress census inventory (seeded from the T-122 `rg` census of `src/`) ───

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A routing marker (egress_http / browser zone / DoH) must be present.
    Contract,
    /// The sanctioned egress client itself — asserted structurally.
    Sanctioned,
    /// Pre-existing or non-egress usage, kept with a written reason.
    Allowlist,
}

const EGRESS_PRIMITIVES: &[&str] = &[
    "ureq::",
    "reqwest",
    "hickory_resolver",
    "TcpStream::connect",
    "UdpSocket::bind",
    "UdpSocket::connect",
];

const CONTRACT_MARKERS: &[&str] = &[
    "egress_http::",
    "egress_proxy_url_ureq",
    "browser_zone_reqwest_proxy",
    "CLOUDFLARE",
    "dns_guard::",
];

const CENSUS: &[(&str, Class, &str)] = &[
    // ── contract-keyed: a routing marker must be present (machine-checked) ──
    ("src/interp.rs", Contract, "request paths via egress_http:: shims (L8215+, L22633); agent config L3497 validates via ureq::Proxy"),
    ("src/main.rs", Contract, "egress_http::/egress_refusal wiring present; relay/SIG sockets are local plumbing"),
    ("src/browser/adaptive_crawler.rs", Contract, "crawler HTTP rides in-file egress/zone markers (checked)"),
    ("src/browser/autonomous.rs", Contract, "autonomous browser HTTP rides egress/zone markers (checked)"),
    ("src/browser/dpi_bypass.rs", Contract, "HTTPS/DNS RR lookups via hickory DoH (CLOUDFLARE) — routed"),
    ("src/browser/dual_mode.rs", Contract, "dual-mode browser HTTP rides egress/zone markers (checked)"),
    ("src/browser/free_proxies.rs", Contract, "proxy-list fetch rides egress/zone markers (checked)"),
    ("src/browser/llm_extract.rs", Contract, "reqwest client built with browser_zone_reqwest_proxy (L227)"),
    ("src/browser/page.rs", Contract, "page HTTP rides egress/zone markers (checked)"),
    ("src/browser/perf_engine.rs", Contract, "perf probes ride egress/zone markers (checked)"),
    ("src/browser/sitemap.rs", Contract, "sitemap fetch rides egress/zone markers (checked)"),
    ("src/browser/zone.rs", Contract, "the browser-zone egress contract itself (browser_zone_* proxies)"),
    ("src/runtime/fetch.rs", Contract, "compiled-side egress contract (defines egress_proxy_url_ureq)"),
    ("src/stdlib/azure_sql.rs", Contract, "stdlib HTTP module; in-file egress routing marker present"),
    ("src/stdlib/beehiiv.rs", Contract, "stdlib HTTP module; in-file egress routing marker present"),
    ("src/stdlib/cnam_dip.rs", Contract, "reqwest client via egress_proxy_url_ureq, fail-closed (N3)"),
    ("src/stdlib/cxense.rs", Contract, "ureq agent via egress_http::agent_with_timeouts (L35)"),
    ("src/stdlib/email.rs", Contract, "IMAP/SMTP over raw TCP; egress markers present (residual raw transport)"),
    ("src/stdlib/ghost.rs", Contract, "stdlib HTTP module; in-file egress routing marker present"),
    ("src/stdlib/http.rs", Contract, "proxy_for_url(egress_proxy_url_ureq), fail-closed (N3)"),
    ("src/stdlib/lrn_dip.rs", Contract, "reqwest client via egress_proxy_url_ureq, fail-closed (N3)"),
    ("src/stdlib/medium.rs", Contract, "stdlib HTTP module; in-file egress routing marker present"),
    ("src/stdlib/modisoft.rs", Contract, "stdlib HTTP module; in-file egress routing marker present"),
    ("src/stdlib/modisoft_insights.rs", Contract, "stdlib HTTP module; in-file egress routing marker present"),
    ("src/stdlib/modisoft_recon.rs", Contract, "stdlib HTTP module; in-file egress routing marker present"),
    ("src/stdlib/net.rs", Contract, "DoH resolve_doh (CLOUDFLARE); raw sites L349/L866/L950 gated by dns_guard (T-122b)"),
    ("src/stdlib/osint.rs", Contract, "stdlib HTTP module; to_socket_addrs sites L459/L1173 gated by dns_guard (T-122b)"),
    ("src/stdlib/sitescan.rs", Contract, "stdlib HTTP module; scan agents via ureq::Agent::config_builder + egress_http::proxy()"),
    ("src/stdlib/substack.rs", Contract, "ureq agent via egress_http::agent_with_timeouts (L35)"),
    ("src/stdlib/transfer.rs", Contract, "S3 helpers via egress_http::agent_with_timeouts (R1-1); UDP binds + to_socket_addrs (host:0, L935) gated by dns_guard (T-122b)"),
    ("src/stdlib/wordpress.rs", Contract, "stdlib HTTP module; in-file egress routing marker present"),
    // ── the sanctioned egress client itself ────────────────────────────────
    ("src/runtime/egress_http.rs", Sanctioned, "shared proxy-aware agent + egress_refusal + request shims"),
    // ── allowlisted: written reason required, no marker expected ───────────
    ("src/browser/advanced_stealth.rs", Allowlist, "consumes a caller-built reqwest::Client (warm(.., &reqwest::Client)); no client built here"),
    ("src/browser/crawl_pipeline.rs", Allowlist, "ureq::http::HeaderValue type references only; requests ride browser-zone/egress layers"),
    ("src/browser/ipv6_pool.rs", Allowlist, "raw tokio TcpStream health probe to pool addrs (comment: avoids reqwest); probe-only residual"),
    ("src/browser/network_stealth.rs", Allowlist, "stealth TCP probes; tokio lookup_host (L223/L290) gated by dns_guard::plain_dns_refusal (T-122b)"),
    ("src/browser/observability.rs", Allowlist, "loopback test client (127.0.0.1) inside #[cfg(test)]"),
    ("src/browser/process.rs", Allowlist, "local browser-process/daemon port probe (connect_timeout)"),
    ("src/browser/proxy.rs", Allowlist, "proxy reachability probe (tokio TcpStream::connect to the proxy addr)"),
    ("src/browser/typesense.rs", Allowlist, "carries a reqwest::Client (field/impls); builder supplied by the caller"),
    ("src/cli/fingerprint_audit_cmd.rs", Allowlist, "loopback SOCKS-endpoint reachability probe (--tor-check, connect_timeout, no data); egress proxy reported via egress_http::proxy_url; no fetches"),
    ("src/cli/daemon.rs", Allowlist, "daemon health-check reqwest::get — pre-existing direct call; convert to egress_http (residual #61)"),
    ("src/runtime/net_ffi.rs", Allowlist, "raw net FFI primitives (TcpStream::connect/bind) for compiled programs; direct by design"),
    ("src/signing.rs", Allowlist, "signing HTTP client (reqwest::blocking) — residual; convert to egress_http"),
    ("src/stdlib/mesh.rs", Allowlist, "inbound UDP listener (UdpSocket::bind 0.0.0.0) — no outbound connect"),
    ("src/stdlib/sync.rs", Allowlist, "sync client (reqwest::blocking::Client::new x2) — pre-existing direct; residual"),
    ("src/stdlib/transfer_net.rs", Allowlist, "relay TCP plumbing (tokio connect to relay_addr) + measurement connect_timeout"),
    ("src/stdlib/ws.rs", Allowlist, "websocket raw TCP connect (connect_timeout) — residual; convert to egress or document"),
];

/// Resolver-primitive census (row #61). `doh == true` entries must contain
/// `CLOUDFLARE`; `extra` pins per-file structural evidence.
const RESOLVER_CENSUS: &[(&str, bool, &[&str], &str)] = &[
    ("src/browser/dpi_bypass.rs", true, &[], "HTTPS RR lookups via hickory DoH (CLOUDFLARE) — routed"),
    ("src/stdlib/net.rs", true, &["resolve_doh", "dns_guard::"], "DoH resolver present (resolve_doh); raw sites L349/L866/L950 adopt dns_guard (T-122b)"),
    ("src/browser/network_stealth.rs", false, &["dns_guard::"], "stealth TCP probes resolve via tokio lookup_host (L223/L290) gated by dns_guard::plain_dns_refusal (T-122b)"),
    ("src/stdlib/osint.rs", false, &["dns_guard::"], "probe helpers use ToSocketAddrs (L459/L1173) gated by dns_guard::check (T-122b)"),
    ("src/stdlib/transfer.rs", false, &["dns_guard::"], "interface enumeration via to_socket_addrs (host:0, L935) gated by dns_guard (T-122b)"),
];

const RESOLVER_PRIMITIVES: &[&str] = &[
    "hickory_resolver",
    "lookup_host(",
    "to_socket_addrs(",
    "ResolverConfig",
    "TokioResolver",
];

// ── Helpers ─────────────────────────────────────────────────────────────────

fn has_any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

/// Every `.rs` file under `src/`, keyed by manifest-relative path.
fn src_files() -> BTreeMap<String, String> {
    fn walk(dir: &Path, out: &mut BTreeMap<String, String>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                let Ok(body) = std::fs::read_to_string(&path) else { continue };
                let rel = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .expect("file under CARGO_MANIFEST_DIR")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, body);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

fn flagged(files: &BTreeMap<String, String>, primitives: &[&str]) -> BTreeSet<String> {
    files
        .iter()
        .filter(|(_, body)| has_any(body, primitives))
        .map(|(p, _)| p.clone())
        .collect()
}

fn diff_report(a: &BTreeSet<String>, b: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    (
        a.difference(b).cloned().collect(),
        b.difference(a).cloned().collect(),
    )
}

// ── Tests: egress census (row #28) ──────────────────────────────────────────

#[test]
fn egress_census_every_site_is_contract_routed_or_allowlisted() {
    let files = src_files();
    let flagged = flagged(&files, EGRESS_PRIMITIVES);
    let known: BTreeSet<String> = CENSUS.iter().map(|(p, _, _)| p.to_string()).collect();

    let (unknown, stale) = diff_report(&flagged, &known);
    assert!(
        unknown.is_empty(),
        "new egress-capable file(s) not classified — route through crate::runtime::egress_http / \
         the browser zone (or add an allowlist entry with a reason) and extend CENSUS in \
         tests/egress_census.rs:\n{}",
        unknown.join("\n")
    );
    assert!(
        stale.is_empty(),
        "CENSUS entries that no longer match any egress primitive — drop or reclassify them:\n{}",
        stale.join("\n")
    );

    for (path, class, reason) in CENSUS {
        let body = files
            .get(*path)
            .unwrap_or_else(|| panic!("CENSUS path missing under src/: {path}"));
        assert!(!reason.is_empty(), "{path}: every entry needs a written reason");
        match class {
            Contract => {
                assert!(
                    has_any(body, CONTRACT_MARKERS),
                    "{path} classified Contract but carries none of {CONTRACT_MARKERS:?} — \
                     fix the routing or move it to Allowlist with a reason"
                );
            }
            Sanctioned => {
                assert!(
                    body.contains("pub fn agent("),
                    "{path} (sanctioned) must expose the shared proxy-aware agent"
                );
                assert!(
                    body.contains("pub fn egress_refusal("),
                    "{path} (sanctioned) must expose egress_refusal"
                );
            }
            Allowlist => {}
        }
    }

    println!(
        "egress census: {} flagged files, all classified ({} contract/sanctioned, {} allowlisted)",
        flagged.len(),
        CENSUS.iter().filter(|(_, c, _)| *c != Allowlist).count(),
        CENSUS.iter().filter(|(_, c, _)| *c == Allowlist).count(),
    );
}

// ── Tests: per-run Tor circuit binding (P1 W1-E1) ───────────────────────────

#[test]
fn default_tor_egress_binds_per_run_credentials() {
    let files = src_files();
    let fetch = files
        .get("src/runtime/fetch.rs")
        .expect("src/runtime/fetch.rs present");
    // The fail-closed default must mint a per-run identity, not share the
    // bare URL: a literal `Some(TOR_SOCKS_URL.to_string())` default would
    // re-introduce fleet-wide circuit pooling (every run on one circuit).
    assert!(
        fetch.contains("fn default_tor_proxy_url"),
        "src/runtime/fetch.rs must expose the per-run default URL builder"
    );
    assert!(
        fetch.contains("TALLOW_TOR_STREAM_ID"),
        "the per-run binding must document the runner stream-id override"
    );
    assert!(
        fetch.contains("IsolateSOCKSAuth"),
        "the mechanism (Tor IsolateSOCKSAuth) must be named where the binding lives"
    );
    assert!(
        !fetch.contains("Some(TOR_SOCKS_URL.to_string())"),
        "the fail-closed default must not resolve to the bare shared URL"
    );
    // Browser attach + pool hand-out bind per-launch credentials too.
    let pool = files
        .get("src/tor/pool.rs")
        .expect("src/tor/pool.rs present");
    assert!(
        pool.contains("fn isolation_credentials"),
        "src/tor/pool.rs must expose the per-launch credential mint"
    );
    assert!(
        pool.contains("socks5h://{}:{}@127.0.0.1:{}"),
        "attach_browser must embed the per-launch credentials in the proxy URL"
    );
}

// ── Tests: resolver source guard (row #61) ──────────────────────────────────

#[test]
fn resolver_calls_use_dns_over_https_or_are_allowlisted() {
    let files = src_files();
    let flagged = flagged(&files, RESOLVER_PRIMITIVES);
    let known: BTreeSet<String> = RESOLVER_CENSUS.iter().map(|(p, _, _, _)| p.to_string()).collect();

    let (unknown, stale) = diff_report(&flagged, &known);
    assert!(
        unknown.is_empty(),
        "new DNS-resolver usage not classified — resolve via DoH (hickory + CLOUDFLARE, \
         see src/stdlib/net.rs::resolve_doh), gate raw sites with crate::runtime::dns_guard::check, \
         or add an allowlist entry with a reason in tests/egress_census.rs:\n{}",
        unknown.join("\n")
    );
    assert!(
        stale.is_empty(),
        "RESOLVER_CENSUS entries that no longer match any resolver primitive — drop or reclassify:\n{}",
        stale.join("\n")
    );

    for (path, doh, extra, reason) in RESOLVER_CENSUS {
        let body = files
            .get(*path)
            .unwrap_or_else(|| panic!("RESOLVER_CENSUS path missing under src/: {path}"));
        assert!(!reason.is_empty(), "{path}: every entry needs a written reason");
        if *doh {
            assert!(
                body.contains("CLOUDFLARE"),
                "{path} claims DoH routing but does not pin CLOUDFLARE as the resolver"
            );
        }
        for needle in *extra {
            assert!(
                body.contains(needle),
                "{path} structural pin {needle:?} not found — update the inventory"
            );
        }
    }

    // Global invariant: any hickory-resolver use in the tree must be a
    // DoH-configured resolver application (CLOUDFLARE DoH endpoint), never a
    // plain-DNS resolver configuration.
    for (path, body) in &files {
        if body.contains("hickory_resolver") {
            assert!(
                body.contains("CLOUDFLARE"),
                "{path} uses hickory_resolver without CLOUDFLARE — plain-DNS resolver \
                 usage must not appear (route via DoH or dns_guard)"
            );
        }
    }

    println!(
        "resolver guard: {} flagged files, all classified (DoH or allowlisted+reason)",
        flagged.len()
    );
}

// ── Tests: plain-DNS fail-closed guard (runtime leg) ────────────────────────

static DNS_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn plain_dns_refusal_is_fail_closed_and_emits_a_refusal_event() {
    let _g = DNS_ENV_LOCK.lock().expect("dns env lock");
    unsafe { std::env::remove_var("TALLOW_ALLOW_DIRECT") };
    observability::EMITTED.lock().expect("emitted").clear();

    let refusal = dns_guard::check(53, false).expect_err("plain :53 without opt-in must refuse");
    assert!(refusal.contains("refusing"), "refusal must say so: {refusal:?}");
    assert!(refusal.contains(":53"), "refusal must name the port: {refusal:?}");

    let emitted = observability::EMITTED.lock().expect("emitted");
    assert_eq!(emitted.len(), 1, "exactly one refusal event");
    assert_eq!(emitted[0].class, observability::EventClass::EgressRefusal);
    assert_eq!(emitted[0].actor, "runtime.dns_guard");
    drop(emitted);

    // Junk / falsy values must not open the guard (mirrors fetch::allow_direct).
    for junk in ["junk", "0", "false", ""] {
        unsafe { std::env::set_var("TALLOW_ALLOW_DIRECT", junk) };
        assert!(
            !dns_guard::allow_direct(),
            "TALLOW_ALLOW_DIRECT={junk:?} must not enable direct DNS"
        );
        assert!(dns_guard::plain_dns_refusal(53, false).is_some());
    }
    unsafe { std::env::remove_var("TALLOW_ALLOW_DIRECT") };
}

#[test]
fn plain_dns_guard_allows_egress_non_53_and_explicit_optin() {
    let _g = DNS_ENV_LOCK.lock().expect("dns env lock");

    // The egress path (socks5h remote DNS / DoH) is never guarded.
    assert!(dns_guard::plain_dns_refusal(53, true).is_none());
    // Non-:53 ports are not plain-DNS lookups.
    assert!(dns_guard::plain_dns_refusal(443, false).is_none());
    assert!(dns_guard::check(0, false).is_ok());

    // Explicit operator opt-in — allowed, but journaled as a direct-egress
    // bypass (trim + case-insensitive, same parse as fetch::allow_direct).
    unsafe { std::env::set_var("TALLOW_ALLOW_DIRECT", "TRUE") };
    assert!(dns_guard::allow_direct(), "TRUE must opt in after trim+lowercase");
    observability::EMITTED.lock().expect("emitted").clear();
    assert!(dns_guard::plain_dns_refusal(53, false).is_none());
    let emitted = observability::EMITTED.lock().expect("emitted");
    assert_eq!(emitted.len(), 1, "bypass must be journaled (never silent)");
    assert_eq!(emitted[0].class, observability::EventClass::DirectEgress);
    drop(emitted);
    unsafe { std::env::remove_var("TALLOW_ALLOW_DIRECT") };
}
