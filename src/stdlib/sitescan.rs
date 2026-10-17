//! Standard library: `tallow.sitescan` — comprehensive website + infrastructure
//! scanning module (read-only · public-data · GET-only · Tor-first).
//!
//! # What this module does
//!
//! `tallow.sitescan` answers one question with one call: *"what is this website
//! and everything underneath it?"* — pages, assets, endpoints, DNS, subdomains,
//! certificates, registrar, netblocks, and (opt-in, authorized-only) open ports.
//! It composes Tallow's existing resource spectrum instead of reinventing it:
//!
//! | Layer            | Reused Tallow resource                                   |
//! |------------------|----------------------------------------------------------|
//! | HTTP transport   | `runtime::egress_http` (fail-closed Tor egress contract) |
//! | Pacing/backoff   | `stdlib::http::{RateGovernor, governed_get}`             |
//! | Tech fingerprint | `stdlib::osint::match_signatures` (Wappalyzer-style)     |
//! | Port scanning    | `stdlib::osint` `ScanScope.authorize` + `Scanner.scan`   |
//! | Web archive      | `stdlib::osint` `WebArchive.snapshots` (opt-in)          |
//!
//! New in this module: bounded same-site crawling, asset inventory, JS/CSS
//! endpoint mining, DoH-based DNS enumeration, CT-log subdomain + certificate
//! aggregation, RDAP registrar/netblock lookup, and the aggregated report.
//!
//! # Depth ladder (how far the scan penetrates)
//!
//! | Level | Label     | Penetration                                              |
//! |-------|-----------|----------------------------------------------------------|
//! | 1     | `surface` | reachability, headers, security headers, cookies, robots, sitemap, homepage structure, tech stack, third-party hosts |
//! | 2     | `pages`   | + bounded same-site link crawl (page inventory)          |
//! | 3     | `assets`  | + full asset inventory, CSS refs, JS endpoint mining     |
//! | 4     | `infra`   | + DNS records (8 types via DoH), CT subdomains, cert summary, RDAP registrar/netblocks, optional DNS brute + Wayback |
//! | 5     | `network` | + TCP connect port scan — **requires** `opts.authorized_cidr`; IPs outside the authorized CIDR are refused |
//!
//! Levels 1–4 stop at the public web/registration plane. Level 5 is the only
//! stage that opens sockets to the target itself and is double-gated:
//! an explicit `authorized_cidr` in opts AND per-IP containment validation
//! before any connect (enforced, not advisory). It never runs by default.
//!
//! # Functions
//!
//! - `sitescan.scan(target, depth?, opts_json?) -> String`
//!     JSON envelope (see the `stages` object for per-stage findings).
//!     `depth` is an Int 1–5 or a label (`"surface".."network"`, `"full"`=5).
//!     `opts_json` is an optional JSON object: `max_pages`, `link_depth`,
//!     `max_js`, `max_css`, `include_subdomains`, `brute`, `wayback`,
//!     `only` (["stage", ...]), `ports` ([int]), `authorized_cidr`,
//!     `port_timeout_ms`. Caps are hard-clamped; see `limits` in the envelope.
//! - `sitescan.report(scan_json) -> String`
//!     Renders a scan envelope into a human-readable Markdown report.
//! - `sitescan.depth_info() -> String`
//!     The depth ladder as JSON (programmatic introspection).
//! - `sitescan.probe_egress() -> String`
//!     Tor egress proof: `{ip, is_tor, checked_at, source}` via
//!     check.torproject.org (rides the same governed client).
//! - `sitescan.version() -> String`
//!
//! # 🔴 POLICY (non-negotiable — do not bypass)
//!
//! - **GET-only, read-only.** No POST/PUT/DELETE, no credential submission,
//!   no form submission, no writes to any target. The scanner never logs in.
//! - **Public data only.** robots.txt is parsed and (best-effort) respected;
//!   no directory brute-forcing beyond sitemap/robots enumeration; the only
//!   "list" probing is JS-derived endpoint *discovery* from public bundles.
//! - **Tor-first.** All HTTP rides `runtime::egress_http` (fail-closed:
//!   `socks5h://127.0.0.1:9050` by default; `TALLOW_PROXY` overrides;
//!   `TALLOW_ALLOW_DIRECT=1` is the only opt-out; malformed proxy refuses).
//!   DNS rides DoH over the same client — no plain :53 lookups. The single
//!   exception is the opt-in `network` stage's TCP connect scan, which is a
//!   direct authorized-scope probe (like a local `nmap`) and therefore
//!   requires the explicit `authorized_cidr` gate.
//! - **Paced.** One process-wide governor (`TALLOW_SITESCAN_RPS`, default 2)
//!   paces every request. Per-stage caps bound total traffic.
//!
//! # Error contract (stable prefixes for `.tl` matching)
//!
//! - `sitescan:param:<detail>` — caller-side argument problem (also for
//!   authorized-CIDR containment refusals of the network stage).
//! - `sitescan:net:<cause>`   — persistent transport-level failure.
//! - `sitescan:http:<status>` — unexpected HTTP status after retries.
//! - `sitescan:shape:<detail>`— upstream body did not match the expected shape.
//!
//! `scan()` returns `Ok(envelope)` even when individual stages fail — failures
//! are recorded in `envelope.errors` and the scan continues where possible.
//! Hard `Err` is reserved for malformed arguments. `envelope.ok` is false
//! only when the primary document fetch (depth ≥ 1) did not succeed.
//!
//! # Test seam
//!
//! `FETCH_OVERRIDE` (module-private; a no-op outside `#[cfg(test)]`) replaces
//! the transport for every fetch path (fingerprint GETs and governed JSON
//! GETs), so unit tests run offline and instantly against inline fixtures.
//! Tests that install it serialize on `TEST_LOCK`.

use super::http::RateGovernor;
use super::StdlibResult;
use crate::interp::Value;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Map as JMap, Value as J};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::io::Read as _;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use ureq::ResponseExt;

// =====================================================================
// Constants
// =====================================================================

const VERSION: &str = "0.1.0";

/// Pinned desktop UA — matches the Chrome-136-class UA used by the sibling
/// recon modules. One UA for the whole scan keeps the HTTP fingerprint
/// internally coherent (see the fingerprint-coherence program).
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

/// Retry ceiling for `governed_get`-backed JSON calls (crt.sh / RDAP / DoH).
const MAX_RETRIES: u32 = 3;

/// Redirect ceiling for fingerprint GETs that must land on the final URL.
const FOLLOW_REDIRECTS: u32 = 8;

// ── Caps (hard ceilings; opts are clamped into these, never above) ────
const DEFAULT_MAX_PAGES: usize = 25;
const HARD_MAX_PAGES: usize = 200;
const DEFAULT_LINK_DEPTH: u32 = 3;
const HARD_LINK_DEPTH: u32 = 6;
const DEFAULT_MAX_JS: usize = 10;
const HARD_MAX_JS: usize = 50;
const DEFAULT_MAX_CSS: usize = 5;
const HARD_MAX_CSS: usize = 20;
const HARD_MAX_PORTS: usize = 64;
const DEFAULT_PORT_TIMEOUT_MS: u64 = 1500;
const DEFAULT_INCLUDE_SUBDOMAINS: bool = false;

/// Per-response body character caps (post-read, pre-parse).
const BODY_CAP_PAGE: usize = 20_000_000;
const BODY_CAP_SMALL: usize = 5_000_000;
const BODY_CAP_JS: usize = 2_000_000;
const BODY_CAP_CSS: usize = 1_000_000;

/// Inline `<script>` text kept per page for endpoint mining. Single-file
/// bundles can be megabytes; this bounds memory while still covering apps.
const INLINE_JS_CAP: usize = 4_000_000;

/// Total bytes of page bodies retained across a crawl for the assets stage.
const CRAWL_BODY_BUDGET: usize = 64 * 1024 * 1024;

/// List caps (kept in the envelope; overflow is counted, not silently lost).
const MAX_LINKS_KEPT: usize = 400;
const MAX_ENDPOINTS_KEPT: usize = 400;
const MAX_SUBDOMAINS_KEPT: usize = 500;
const MAX_PAGES_LISTED: usize = 200;

/// Endpoints in the surface plane.
const DOH_ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";
const TOR_CHECK_ENDPOINT: &str = "https://check.torproject.org/api/ip";
const CRTSH_ENDPOINT: &str = "https://crt.sh/";
const RDAP_ENDPOINT: &str = "https://rdap.org";

const DNS_TYPES: [&str; 8] = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"];

/// Curated default port set for the network stage (common web/infra ports;
/// a reconnaissance *starting set*, not a full sweep — opts.ports overrides).
const DEFAULT_PORTS: &[i128] = &[
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 2082, 2083, 3000, 3306, 5432,
    6379, 8000, 8080, 8443, 8888, 9000, 10000, 27017,
];

/// Security headers whose presence/absence is reported explicitly.
const SECURITY_HEADERS: [&str; 8] = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
];

/// Document extensions surfaced as link components during crawling.
const DOCUMENT_EXTS: [&str; 12] = [
    "pdf", "csv", "xlsx", "xls", "docx", "doc", "pptx", "zip", "txt", "json", "xml", "ics",
];

/// Compact DNS brute wordlist used only when `opts.brute` is set (rides DoH).
const DNS_BRUTE_WORDS: [&str; 40] = [
    "www", "mail", "api", "app", "dev", "staging", "admin", "portal", "shop", "blog", "cdn",
    "static", "assets", "img", "images", "media", "docs", "support", "help", "status", "test",
    "demo", "beta", "old", "new", "vpn", "git", "ci", "jenkins", "grafana", "monitor", "db",
    "sql", "ns1", "ns2", "ftp", "smtp", "webmail", "cpanel", "m",
];

/// URL noise filtered out of JS-mined absolute URLs (namespaces, specs).
const URL_NOISE: [&str; 6] = [
    "w3.org", "ns.adobe.com", "purl.org", "xmlsoap.org", "schema.org", "localhost",
];

// =====================================================================
// Rate governor + HTTP plumbing (mirrors the governed stdlib HTTP pattern)
// =====================================================================

/// Effective rps for the sitescan governor: `TALLOW_SITESCAN_RPS` if set to a
/// sane positive value, else 2.0. Read once at first use.
fn gov_rps() -> f64 {
    std::env::var("TALLOW_SITESCAN_RPS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|r| r.is_finite() && *r > 0.0 && *r <= 20.0)
        .unwrap_or(2.0)
}

/// Process-wide token bucket pacing every `tallow.sitescan` network call.
static GOV_SITESCAN: LazyLock<Mutex<RateGovernor>> =
    LazyLock::new(|| Mutex::new(RateGovernor::new(gov_rps())));

/// Build a ureq agent with the same phase timeouts as the sibling recon
/// modules, `http_status_as_error(false)` (4xx/5xx arrive as ordinary
/// responses — status codes are findings here, not errors), and the
/// fail-closed egress proxy from the single source of truth.
fn scan_agent(max_redirects: u32) -> ureq::Agent {
    let builder = ureq::Agent::config_builder()
        .timeout_global(None)
        .timeout_per_call(Some(Duration::from_secs(30)))
        .timeout_resolve(Some(Duration::from_secs(10)))
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_send_request(Some(Duration::from_secs(10)))
        .timeout_send_body(Some(Duration::from_secs(30)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .timeout_recv_body(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .max_redirects(max_redirects)
        .https_only(false)
        .proxy(crate::runtime::egress_http::proxy());
    builder.build().new_agent()
}

/// Agent that follows redirects (page fetches land on the final URL).
static AGENT_FOLLOW: LazyLock<ureq::Agent> = LazyLock::new(|| scan_agent(FOLLOW_REDIRECTS));

/// Agent with redirects disabled (fingerprint GETs that must observe 3xx).
static AGENT_NOFOLLOW: LazyLock<ureq::Agent> = LazyLock::new(|| scan_agent(0));

/// One full HTTP response captured for scanning.
#[derive(Debug, Clone)]
struct HttpResp {
    status: u16,
    /// Body truncated to the per-call cap (lossy UTF-8).
    body: String,
    /// Full byte length as received (before truncation).
    len: usize,
    /// Headers, names lower-cased.
    headers: Vec<(String, String)>,
    /// Final URL after redirects (request URL when none).
    final_url: String,
}

impl HttpResp {
    /// First value for `name` (lower-cased, last-wins on duplicates).
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Copy response headers into `(lowercased_name, value)` pairs.
fn collect_headers(resp: &ureq::http::Response<ureq::Body>) -> Vec<(String, String)> {
    resp.headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Capture a response into [`HttpResp`], reading at most `cap` body bytes.
///
/// `Body::read_to_vec()` must NOT be used here: it has a hard 10 MB default
/// limit and returns an error beyond it — silently swallowed, a 16 MB
/// homepage once scanned as 0 bytes. `take(cap)` reads exactly what we want,
/// yields EOF at the cap, and a mid-transfer error keeps the partial body.
fn capture(resp: ureq::http::Response<ureq::Body>, cap: usize) -> HttpResp {
    let status = resp.status().as_u16();
    let headers = collect_headers(&resp);
    let final_url = resp.get_uri().to_string();
    let mut buf: Vec<u8> = Vec::with_capacity(256 * 1024);
    let _ = resp
        .into_body()
        .into_reader()
        .take(cap as u64)
        .read_to_end(&mut buf);
    let len = buf.len();
    HttpResp {
        status,
        body: String::from_utf8_lossy(&buf).into_owned(),
        len,
        headers,
        final_url,
    }
}

/// Test seam: when set, every fetch (fingerprint GET and governed JSON GET)
/// is served by this function instead of the network. No-op outside tests.
type FetchFn = fn(&str, &[(String, String)]) -> Result<HttpResp, String>;
static FETCH_OVERRIDE: Mutex<Option<FetchFn>> = Mutex::new(None);

/// Standard headers for fingerprinting: browser UA + any-accept.
fn fp_headers() -> Vec<(String, String)> {
    vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "*/*".to_string()),
    ]
}

/// One paced, single-attempt fingerprint GET (statuses in-band; only
/// transport failures are errors). Bodies are captured up to the page cap.
fn fp_get(url: &str, headers: &[(String, String)], follow: bool) -> Result<HttpResp, String> {
    fp_get_capped(url, headers, follow, BODY_CAP_PAGE)
}

/// Same as [`fp_get`] but captures the body only up to `cap` bytes
/// (CSS/JS/small documents don't need the full page budget).
fn fp_get_capped(
    url: &str,
    headers: &[(String, String)],
    follow: bool,
    cap: usize,
) -> Result<HttpResp, String> {
    if let Some(fetch) = *FETCH_OVERRIDE.lock().unwrap() {
        return fetch(url, headers);
    }
    GOV_SITESCAN.lock().unwrap().wait();
    let agent = if follow {
        AGENT_FOLLOW.clone()
    } else {
        AGENT_NOFOLLOW.clone()
    };
    let mut req = agent.get(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    match req.call() {
        Ok(resp) => Ok(capture(resp, cap)),
        Err(ureq::Error::StatusCode(code)) => Ok(HttpResp {
            status: code,
            body: String::new(),
            len: 0,
            headers: Vec::new(),
            final_url: url.to_string(),
        }),
        Err(e) => Err(format!("sitescan:net: {url}: {e}")),
    }
}

/// Governed, retried GET for JSON APIs (crt.sh / DoH / RDAP / tor check).
/// Routes through `http::governed_get` (backoff + jitter + retry on 429/5xx).
fn gov_json_get(url: &str, accept: &str) -> Result<String, String> {
    if let Some(fetch) = *FETCH_OVERRIDE.lock().unwrap() {
        let headers = vec![
            ("User-Agent".to_string(), USER_AGENT.to_string()),
            ("Accept".to_string(), accept.to_string()),
        ];
        let resp = fetch(url, &headers)?;
        if resp.status != 200 {
            return Err(format!("sitescan:http: {} fetching {url}", resp.status));
        }
        return Ok(resp.body);
    }
    let headers: Vec<(String, String)> = vec![
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), accept.to_string()),
    ];
    let (status, body, _retries, rate_limited) =
        super::http::governed_get(url, &headers, &GOV_SITESCAN, MAX_RETRIES)
            .map_err(|e| format!("sitescan:net: {e}"))?;
    if rate_limited {
        return Err(format!("sitescan:http: 429 fetching {url}"));
    }
    if status != 200 {
        return Err(format!("sitescan:http: {status} fetching {url}"));
    }
    Ok(body)
}

// =====================================================================
// URL helpers
// =====================================================================

/// Normalize a user-supplied target into an absolute http(s) URL.
fn normalize_target(input: &str) -> Result<url::Url, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("sitescan:param: empty target".to_string());
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = url::Url::parse(&with_scheme)
        .map_err(|e| format!("sitescan:param: invalid target '{trimmed}': {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "sitescan:param: unsupported scheme '{other}' (http/https only)"
            ))
        }
    }
    if parsed.host_str().is_none() {
        return Err(format!("sitescan:param: target '{trimmed}' has no host"));
    }
    Ok(parsed)
}

/// Apex-ish host: strip a single leading `www.` (deliberately conservative —
/// no public-suffix-list machinery here).
fn apex_host(host: &str) -> String {
    host.strip_prefix("www.").unwrap_or(host).to_lowercase()
}

/// Dedupe key for a URL: fragment dropped, host lower-cased.
fn key_of(u: &url::Url) -> String {
    let mut c = u.clone();
    c.set_fragment(None);
    if let Some(h) = c.host_str().map(|h| h.to_lowercase()) {
        let _ = c.set_host(Some(&h));
    }
    c.to_string()
}

/// Resolve an `href`/`src` against a base; http(s) only; None for
/// mailto/tel/js/data/blob/fragment-only.
fn abs_url(base: &url::Url, href: &str) -> Option<url::Url> {
    let h = href.trim();
    if h.is_empty() || h.starts_with('#') {
        return None;
    }
    let lower = h.to_ascii_lowercase();
    for skip in ["mailto:", "tel:", "javascript:", "data:", "blob:", "sms:", "about:"] {
        if lower.starts_with(skip) {
            return None;
        }
    }
    let joined = base.join(h).ok()?;
    match joined.scheme() {
        "http" | "https" => Some(joined),
        _ => None,
    }
}

/// Whether `host` belongs to the scanned site (`base_host`).
fn same_site(host: &str, base_host: &str, include_subdomains: bool) -> bool {
    let h = host.to_lowercase();
    let b = base_host.to_lowercase();
    if h == b {
        return true;
    }
    let h_apex = apex_host(&h);
    let b_apex = apex_host(&b);
    if h_apex == b_apex {
        return true;
    }
    include_subdomains && (h.ends_with(&format!(".{b}")) || h.ends_with(&format!(".{b_apex}")))
}

/// Case-insensitive substring-free percent-encode for query values.
fn encode_query_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// =====================================================================
// robots.txt / sitemap.xml
// =====================================================================

#[derive(Debug, Clone, Default)]
struct Robots {
    disallow: Vec<String>,
    allow: Vec<String>,
    sitemaps: Vec<String>,
    crawl_delay_s: Option<f64>,
}

/// Parse robots.txt, aggregating rules across all user-agent groups
/// (conservative: we take the union of Disallow prefixes).
fn parse_robots(text: &str) -> Robots {
    let mut r = Robots::default();
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "disallow" => {
                if !value.is_empty() {
                    r.disallow.push(value.to_string());
                }
            }
            "allow" => {
                if !value.is_empty() {
                    r.allow.push(value.to_string());
                }
            }
            "sitemap" => {
                if !value.is_empty() {
                    r.sitemaps.push(value.to_string());
                }
            }
            "crawl-delay" => {
                if let Ok(v) = value.parse::<f64>() {
                    r.crawl_delay_s = Some(v);
                }
            }
            _ => {}
        }
    }
    r.disallow.truncate(200);
    r.allow.truncate(200);
    r.sitemaps.truncate(20);
    r
}

/// Best-effort robots check for a path (longest-match Allow/Disallow).
fn robots_allows(robots: &Robots, path: &str) -> bool {
    let path = if path.is_empty() { "/" } else { path };
    let longest = |rules: &[String]| -> Option<usize> {
        rules
            .iter()
            .filter(|p| path.starts_with(p.as_str()))
            .map(|p| p.len())
            .max()
    };
    let d = longest(&robots.disallow);
    let a = longest(&robots.allow);
    match (d, a) {
        (None, _) => true,
        (Some(dl), Some(al)) => al >= dl,
        (Some(_), None) => false,
    }
}

#[derive(Debug, Clone, Default)]
struct SitemapInfo {
    is_index: bool,
    /// Page URLs (urlset) — for an index this is empty.
    urls: Vec<String>,
    /// Child sitemap URLs (sitemapindex).
    children: Vec<String>,
    /// Total <loc> entries seen before capping.
    total_locs: usize,
}

/// Extract <loc> entries; distinguishes a sitemap index from a urlset.
fn parse_sitemap(xml: &str) -> SitemapInfo {
    let is_index = xml
        .get(..4096.min(xml.len()))
        .map(|head| head.to_ascii_lowercase().contains("<sitemapindex"))
        .unwrap_or(false);
    let mut locs: Vec<String> = Vec::new();
    let mut total = 0usize;
    let mut rest = xml;
    while let Some(start) = rest.find("<loc>") {
        let after = &rest[start + 5..];
        let Some(end) = after.find("</loc>") else {
            break;
        };
        let value = after[..end].trim();
        if !value.is_empty() {
            total += 1;
            if locs.len() < 3000 {
                locs.push(value.to_string());
            }
        }
        rest = &after[end..];
    }
    if is_index {
        locs.truncate(200);
        SitemapInfo {
            is_index,
            urls: vec![],
            children: locs,
            total_locs: total,
        }
    } else {
        SitemapInfo {
            is_index,
            urls: locs,
            children: vec![],
            total_locs: total,
        }
    }
}

// =====================================================================
// HTML page facts (scraper-based)
// =====================================================================

#[derive(Debug, Clone, Default)]
struct AssetRef {
    url: String,
    kind: String,
}

#[derive(Debug, Clone, Default)]
struct FormFacts {
    action: String,
    method: String,
    /// (name, input-kind) pairs.
    inputs: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
struct PageFacts {
    title: String,
    meta_description: String,
    meta_generator: String,
    lang: String,
    /// Absolute http(s) link URLs (a[href]).
    links: Vec<String>,
    /// mailto:/tel: target counts (PII kept out — counts only).
    mailto_count: usize,
    tel_count: usize,
    assets: Vec<AssetRef>,
    forms: Vec<FormFacts>,
    /// Script srcs (absolute).
    script_srcs: Vec<String>,
    /// Stylesheet hrefs (absolute).
    stylesheets: Vec<String>,
    /// Concatenated inline <script> text (capped).
    inline_js: String,
    /// iframe srcs (absolute).
    iframes: Vec<String>,
    /// Scripts/src-resolved srcset URLs (absolute) — kept as assets too.
    srcset_urls: Vec<String>,
}

/// Parse a page's HTML into structured facts. Never panics on junk input.
fn parse_page_facts(html: &str, base: &url::Url) -> PageFacts {
    let doc = scraper::Html::parse_document(html);
    let mut f = PageFacts::default();

    let sel = |s: &str| scraper::Selector::parse(s).unwrap();

    if let Some(el) = doc.select(&sel("title")).next() {
        f.title = el
            .text()
            .collect::<Vec<_>>()
            .join("")
            .trim()
            .chars()
            .take(300)
            .collect();
    }
    if let Some(el) = doc.select(&sel("meta[name=description]")).next() {
        f.meta_description = el
            .value()
            .attr("content")
            .unwrap_or("")
            .trim()
            .chars()
            .take(500)
            .collect();
    }
    if let Some(el) = doc.select(&sel("meta[name=generator]")).next() {
        f.meta_generator = el.value().attr("content").unwrap_or("").trim().to_string();
    }
    if let Some(el) = doc.select(&sel("html")).next() {
        f.lang = el.value().attr("lang").unwrap_or("").trim().to_string();
    }

    // Links + contact schemes.
    for el in doc.select(&sel("a[href]")) {
        let href = el.value().attr("href").unwrap_or("").trim();
        let lower = href.to_ascii_lowercase();
        if lower.starts_with("mailto:") {
            f.mailto_count += 1;
            continue;
        }
        if lower.starts_with("tel:") {
            f.tel_count += 1;
            continue;
        }
        if let Some(u) = abs_url(base, href) {
            if f.links.len() < MAX_LINKS_KEPT {
                f.links.push(u.to_string());
            }
        }
    }

    // Assets.
    for el in doc.select(&sel("script")) {
        if let Some(src) = el.value().attr("src") {
            if let Some(u) = abs_url(base, src) {
                let s = u.to_string();
                f.script_srcs.push(s.clone());
                f.assets.push(AssetRef {
                    url: s,
                    kind: "script".to_string(),
                });
            }
        } else {
            let text = el.text().collect::<Vec<_>>().join("");
            if f.inline_js.len() + text.len() <= INLINE_JS_CAP {
                f.inline_js.push_str(&text);
                f.inline_js.push('\n');
            }
        }
    }
    for el in doc.select(&sel("link[href]")) {
        let rel = el.value().attr("rel").unwrap_or("").to_ascii_lowercase();
        let Some(u) = el.value().attr("href").and_then(|h| abs_url(base, h)) else {
            continue;
        };
        let s = u.to_string();
        let kind = if rel.contains("stylesheet") {
            f.stylesheets.push(s.clone());
            "stylesheet"
        } else if rel.contains("icon") {
            "icon"
        } else if rel.contains("manifest") {
            "manifest"
        } else if rel.contains("preload") || rel.contains("prefetch") {
            "preload"
        } else {
            "link"
        };
        f.assets.push(AssetRef {
            url: s,
            kind: kind.to_string(),
        });
    }
    for el in doc.select(&sel("img")) {
        if let Some(src) = el.value().attr("src") {
            if let Some(u) = abs_url(base, src) {
                f.assets.push(AssetRef {
                    url: u.to_string(),
                    kind: "image".to_string(),
                });
            }
        }
        if let Some(srcset) = el.value().attr("srcset") {
            for part in srcset.split(',') {
                if let Some(candidate) = part.trim().split_whitespace().next() {
                    if let Some(u) = abs_url(base, candidate) {
                        let s = u.to_string();
                        f.srcset_urls.push(s.clone());
                        f.assets.push(AssetRef {
                            url: s,
                            kind: "image".to_string(),
                        });
                    }
                }
            }
        }
    }
    for el in doc.select(&sel("source")) {
        if let Some(src) = el.value().attr("src") {
            if let Some(u) = abs_url(base, src) {
                f.assets.push(AssetRef {
                    url: u.to_string(),
                    kind: "media".to_string(),
                });
            }
        }
        if let Some(srcset) = el.value().attr("srcset") {
            for part in srcset.split(',') {
                if let Some(candidate) = part.trim().split_whitespace().next() {
                    if let Some(u) = abs_url(base, candidate) {
                        f.assets.push(AssetRef {
                            url: u.to_string(),
                            kind: "media".to_string(),
                        });
                    }
                }
            }
        }
    }
    for el in doc.select(&sel("video[src], audio[src]")) {
        if let Some(src) = el.value().attr("src") {
            if let Some(u) = abs_url(base, src) {
                f.assets.push(AssetRef {
                    url: u.to_string(),
                    kind: "media".to_string(),
                });
            }
        }
    }
    for el in doc.select(&sel("iframe[src]")) {
        if let Some(src) = el.value().attr("src") {
            if let Some(u) = abs_url(base, src) {
                let s = u.to_string();
                f.iframes.push(s.clone());
                f.assets.push(AssetRef {
                    url: s,
                    kind: "iframe".to_string(),
                });
            }
        }
    }

    // Forms (structure only — the scanner never submits).
    for form in doc.select(&sel("form")) {
        if f.forms.len() >= 20 {
            break;
        }
        let action = form
            .value()
            .attr("action")
            .and_then(|a| abs_url(base, a))
            .map(|u| u.to_string())
            .unwrap_or_else(|| base.to_string());
        let method = form
            .value()
            .attr("method")
            .unwrap_or("get")
            .to_ascii_lowercase();
        let mut inputs = Vec::new();
        for input in form.select(&sel("input, select, textarea")) {
            if inputs.len() >= 50 {
                break;
            }
            let kind = input
                .value()
                .attr("type")
                .map(|t| t.to_string())
                .unwrap_or_else(|| input.value().name().to_string());
            let name = input.value().attr("name").unwrap_or("").to_string();
            inputs.push((name, kind));
        }
        f.forms.push(FormFacts {
            action,
            method,
            inputs,
        });
    }

    f.assets.truncate(MAX_LINKS_KEPT);
    f.script_srcs.truncate(100);
    f.stylesheets.truncate(100);
    f.iframes.truncate(50);
    f
}

// =====================================================================
// JS / CSS endpoint mining
// =====================================================================

static RE_ABS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,300}"#).unwrap()
});
static RE_CALL: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?:fetch|axios\.(?:get|post|put|delete|patch|request)|XMLHttpRequest|\.open)\s*\(\s*[`'"]([^`'"]{1,300})[`'"]"#,
    )
    .unwrap()
});
static RE_APIPATH: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"[`'"](/(?:api|v\d+|graphql|gql|rest|admin|auth|oauth|account|user|users|internal|private|upload|download|search|data|webhook|socket|ws)[A-Za-z0-9\-._~/{}$:]{0,200})[`'"]"#,
    )
    .unwrap()
});
static RE_WS: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"wss?://[^\s`'"<>]{4,300}"#).unwrap());
static RE_SOURCEMAP: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"sourceMappingURL=([^\s*'"]+)"#).unwrap());
static RE_CSS_URL: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"url\(\s*['"]?([^)'"\s]{1,300})['"]?\s*\)"#).unwrap()
});
static RE_CSS_IMPORT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"@import\s+(?:url\()?\s*['"]([^'"]{1,300})['"]"#).unwrap()
});

/// Strip delimiter junk that regex URL captures pick up from surrounding
/// source text (`https://x.test';` → `https://x.test`).
fn trim_url_junk(s: &str) -> String {
    s.trim_end_matches(|c: char| matches!(c, '\'' | '"' | ';' | ')' | ',' | '.' | '+'))
        .to_string()
}

/// Mine a JS body for endpoints/URLs. Returns (kind, value) pairs where kind
/// is one of `url` | `call` | `api_path` | `ws` | `sourcemap`.
fn mine_js_endpoints(js: &str) -> Vec<(String, String)> {
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    for m in RE_ABS.find_iter(js) {
        let url = trim_url_junk(m.as_str());
        let lower = url.to_ascii_lowercase();
        if URL_NOISE.iter().any(|n| lower.contains(n)) {
            continue;
        }
        if found.len() < MAX_ENDPOINTS_KEPT {
            found.insert(("url".to_string(), url));
        }
    }
    for caps in RE_CALL.captures_iter(js) {
        if let Some(c) = caps.get(1) {
            if found.len() < MAX_ENDPOINTS_KEPT {
                found.insert(("call".to_string(), c.as_str().to_string()));
            }
        }
    }
    for caps in RE_APIPATH.captures_iter(js) {
        if let Some(c) = caps.get(1) {
            if found.len() < MAX_ENDPOINTS_KEPT {
                found.insert(("api_path".to_string(), c.as_str().to_string()));
            }
        }
    }
    for m in RE_WS.find_iter(js) {
        if found.len() < MAX_ENDPOINTS_KEPT {
            found.insert(("ws".to_string(), trim_url_junk(m.as_str())));
        }
    }
    for caps in RE_SOURCEMAP.captures_iter(js) {
        if let Some(c) = caps.get(1) {
            found.insert(("sourcemap".to_string(), c.as_str().to_string()));
        }
    }
    found.into_iter().collect()
}

/// Extract url(...) references and @imports from a CSS body.
fn mine_css_refs(css: &str) -> (Vec<String>, Vec<String>) {
    let mut urls: Vec<String> = Vec::new();
    let mut imports: Vec<String> = Vec::new();
    for caps in RE_CSS_URL.captures_iter(css) {
        if let Some(c) = caps.get(1) {
            let v = c.as_str().to_string();
            if !v.starts_with("data:") && urls.len() < 200 {
                urls.push(v);
            }
        }
    }
    for caps in RE_CSS_IMPORT.captures_iter(css) {
        if let Some(c) = caps.get(1) {
            if imports.len() < 50 {
                imports.push(c.as_str().to_string());
            }
        }
    }
    (urls, imports)
}

// =====================================================================
// DoH DNS / crt.sh / RDAP
// =====================================================================

/// DNS-over-HTTPS query via Cloudflare (JSON). Returns (owner, data) rows.
fn doh_query(name: &str, rrtype: &str) -> Result<Vec<(String, String)>, String> {
    let url = format!(
        "{DOH_ENDPOINT}?name={}&type={}",
        encode_query_value(name),
        rrtype
    );
    let body = gov_json_get(&url, "application/dns-json")?;
    let parsed: J =
        serde_json::from_str(&body).map_err(|e| format!("sitescan:shape: DoH JSON: {e}"))?;
    let status = parsed.get("Status").and_then(|s| s.as_i64()).unwrap_or(-1);
    let mut rows = Vec::new();
    if let Some(answers) = parsed.get("Answer").and_then(|a| a.as_array()) {
        for a in answers {
            let owner = a.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let data = match a.get("data") {
                Some(J::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => continue,
            };
            rows.push((owner, data));
        }
    }
    // NOERROR(0) and NXDOMAIN(3) are both valid outcomes; other rcodes are
    // recorded as an error for the caller but not fatal.
    if status != 0 && status != 3 {
        return Err(format!("sitescan:shape: DoH rcode {status} for {name}/{rrtype}"));
    }
    Ok(rows)
}

/// Resolve A + AAAA for a host via DoH. Transport failures are swallowed
/// into an empty list (callers note the gap via the stage error channel).
fn resolve_ips(host: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (rtype, keep_v4) in [("A", true), ("AAAA", false)] {
        if let Ok(rows) = doh_query(host, rtype) {
            for (_owner, data) in rows {
                let is_v4 = data.parse::<std::net::Ipv4Addr>().is_ok();
                let is_v6 = data.parse::<std::net::Ipv6Addr>().is_ok();
                if (keep_v4 && is_v4) || (!keep_v4 && is_v6) {
                    if !out.contains(&data) {
                        out.push(data);
                    }
                }
            }
        }
    }
    out
}

/// Tolerant timestamp parsing for CT/RDAP strings.
fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        if let Some(ndt) = d.and_hms_opt(0, 0, 0) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
struct CtInfo {
    /// Which CT source produced the rows ("crt.sh" | "certspotter").
    source: String,
    subdomains: Vec<String>,
    wildcard_count: usize,
    cert_count: usize,
    issuers: BTreeMap<String, usize>,
    earliest_not_before: Option<String>,
    latest_not_after: Option<String>,
    latest_not_after_days: Option<i64>,
    expiring_within_45d: usize,
    sample_sans: Vec<String>,
}

/// Query crt.sh for CT-log rows and derive subdomains + certificate summary.
fn ct_lookup_crtsh(apex: &str) -> Result<CtInfo, String> {
    let url = format!("{CRTSH_ENDPOINT}?q=%25.{}&output=json", encode_query_value(apex));
    let body = gov_json_get(&url, "application/json")?;
    let parsed: J =
        serde_json::from_str(&body).map_err(|e| format!("sitescan:shape: crt.sh JSON: {e}"))?;
    let rows = parsed
        .as_array()
        .ok_or_else(|| "sitescan:shape: crt.sh returned non-array".to_string())?;
    let now = Utc::now();
    let mut info = CtInfo::default();
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut earliest_nb: Option<DateTime<Utc>> = None;
    let mut latest_na: Option<DateTime<Utc>> = None;
    for row in rows.iter().take(5000) {
        info.cert_count += 1;
        if let Some(issuer) = row.get("issuer_name").and_then(|v| v.as_str()) {
            let key = issuer
                .rsplit("CN=")
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| issuer.to_string());
            *info.issuers.entry(key).or_insert(0) += 1;
        }
        if let Some(nb) = row.get("not_before").and_then(|v| v.as_str()).and_then(parse_time) {
            if earliest_nb.map(|e| nb < e).unwrap_or(true) {
                earliest_nb = Some(nb);
            }
        }
        if let Some(na) = row.get("not_after").and_then(|v| v.as_str()).and_then(parse_time) {
            if latest_na.map(|e| na > e).unwrap_or(true) {
                latest_na = Some(na);
            }
            if na > now && (na - now).num_days() <= 45 {
                info.expiring_within_45d += 1;
            }
        }
        if let Some(nv) = row.get("name_value").and_then(|v| v.as_str()) {
            for line in nv.lines() {
                let name = line.trim().to_ascii_lowercase();
                if name.is_empty() {
                    continue;
                }
                if let Some(stripped) = name.strip_prefix("*.") {
                    if stripped.ends_with(apex) {
                        info.wildcard_count += 1;
                    }
                    continue;
                }
                if name.ends_with(apex) {
                    names.insert(name);
                }
            }
        }
    }
    info.subdomains = names.iter().take(MAX_SUBDOMAINS_KEPT).cloned().collect();
    info.sample_sans = names.iter().take(12).cloned().collect();
    info.earliest_not_before = earliest_nb.map(|d| d.to_rfc3339());
    if let Some(na) = latest_na {
        info.latest_not_after = Some(na.to_rfc3339());
        info.latest_not_after_days = Some((na - now).num_days());
    }
    Ok(info)
}

/// CT-log lookup with a keyless fallback: crt.sh first, Cert Spotter second
/// (crt.sh is famously flaky; both are public GET-only sources).
fn ct_lookup(apex: &str) -> Result<CtInfo, String> {
    let mut first_err: Option<String> = None;
    match ct_lookup_crtsh(apex) {
        Ok(mut info) => {
            info.source = "crt.sh".to_string();
            return Ok(info);
        }
        Err(e) => first_err = Some(e),
    }
    match ct_lookup_certspotter(apex) {
        Ok(mut info) => {
            info.source = "certspotter".to_string();
            Ok(info)
        }
        Err(e2) => Err(format!(
            "sitescan:http: CT lookup failed: crt.sh: {} | certspotter: {}",
            first_err.unwrap_or_default(),
            e2
        )),
    }
}

/// Cert Spotter fallback (keyless): issuances for apex + subdomains.
fn ct_lookup_certspotter(apex: &str) -> Result<CtInfo, String> {
    let url = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        encode_query_value(apex)
    );
    let body = gov_json_get(&url, "application/json")?;
    let parsed: J = serde_json::from_str(&body)
        .map_err(|e| format!("sitescan:shape: certspotter JSON: {e}"))?;
    let rows = parsed
        .as_array()
        .ok_or_else(|| "sitescan:shape: certspotter returned non-array".to_string())?;
    let now = Utc::now();
    let mut info = CtInfo::default();
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut earliest_nb: Option<DateTime<Utc>> = None;
    let mut latest_na: Option<DateTime<Utc>> = None;
    for row in rows.iter().take(5000) {
        info.cert_count += 1;
        if let Some(nb) = row
            .get("not_before")
            .and_then(|v| v.as_str())
            .and_then(parse_time)
        {
            if earliest_nb.map(|e| nb < e).unwrap_or(true) {
                earliest_nb = Some(nb);
            }
        }
        if let Some(na) = row
            .get("not_after")
            .and_then(|v| v.as_str())
            .and_then(parse_time)
        {
            if latest_na.map(|e| na > e).unwrap_or(true) {
                latest_na = Some(na);
            }
            if na > now && (na - now).num_days() <= 45 {
                info.expiring_within_45d += 1;
            }
        }
        if let Some(dns) = row.get("dns_names").and_then(|v| v.as_array()) {
            for n in dns {
                let Some(name) = n.as_str() else { continue };
                let name = name.trim().to_ascii_lowercase();
                if name.is_empty() {
                    continue;
                }
                if let Some(stripped) = name.strip_prefix("*.") {
                    if stripped.ends_with(apex) {
                        info.wildcard_count += 1;
                    }
                    continue;
                }
                if name.ends_with(apex) {
                    names.insert(name);
                }
            }
        }
    }
    info.subdomains = names.iter().take(MAX_SUBDOMAINS_KEPT).cloned().collect();
    info.sample_sans = names.iter().take(12).cloned().collect();
    info.earliest_not_before = earliest_nb.map(|d| d.to_rfc3339());
    if let Some(na) = latest_na {
        info.latest_not_after = Some(na.to_rfc3339());
        info.latest_not_after_days = Some((na - now).num_days());
    }
    Ok(info)
}

/// Extract the registrar display name from an RDAP entity's jCard.
fn vcard_fn(entity: &J) -> Option<String> {
    let arr = entity.get("vcardArray")?.as_array()?;
    let props = arr.get(1)?.as_array()?;
    for prop in props {
        let prop = prop.as_array()?;
        if prop.first().and_then(|v| v.as_str()) == Some("fn") {
            // jCard value may be a bare string or an array of values
            // (["fn", {}, "text", "Porkbun LLC"] vs ["fn", {}, "text", ["X"]]).
            if let Some(v) = prop.get(3) {
                if let Some(name) = v.as_str() {
                    return Some(name.to_string());
                }
                if let Some(name) = v.as_array().and_then(|vals| vals.first()).and_then(|v| v.as_str()) {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// RDAP domain lookup (registrar plane). Returns a compacted JSON object.
fn rdap_domain(apex: &str) -> Result<J, String> {
    let url = format!("{RDAP_ENDPOINT}/domain/{}", encode_query_value(apex));
    let body = gov_json_get(&url, "application/rdap+json")?;
    let parsed: J =
        serde_json::from_str(&body).map_err(|e| format!("sitescan:shape: RDAP JSON: {e}"))?;
    let mut out = JMap::new();
    if let Some(v) = parsed.get("ldhName").or_else(|| parsed.get("handle")) {
        out.insert("name".into(), v.clone());
    }
    if let Some(status) = parsed.get("status").and_then(|v| v.as_array()) {
        out.insert(
            "status".into(),
            J::Array(status.iter().map(|s| s.clone()).take(12).collect()),
        );
    }
    if let Some(events) = parsed.get("events").and_then(|v| v.as_array()) {
        let mut ev = JMap::new();
        for e in events.iter().take(12) {
            let action = e.get("eventAction").and_then(|v| v.as_str()).unwrap_or("");
            let date = e.get("eventDate").and_then(|v| v.as_str()).unwrap_or("");
            if !action.is_empty() && !date.is_empty() {
                ev.insert(action.to_string(), J::String(date.to_string()));
            }
        }
        out.insert("events".into(), J::Object(ev));
    }
    if let Some(ns) = parsed.get("nameservers").and_then(|v| v.as_array()) {
        let list: Vec<J> = ns
            .iter()
            .filter_map(|n| n.get("ldhName").and_then(|v| v.as_str()))
            .map(|s| J::String(s.to_ascii_lowercase()))
            .take(12)
            .collect();
        out.insert("nameservers".into(), J::Array(list));
    }
    if let Some(entities) = parsed.get("entities").and_then(|v| v.as_array()) {
        for ent in entities {
            let is_registrar = ent
                .get("roles")
                .and_then(|r| r.as_array())
                .map(|roles| roles.iter().any(|r| r.as_str() == Some("registrar")))
                .unwrap_or(false);
            if is_registrar {
                if let Some(name) = vcard_fn(ent) {
                    out.insert("registrar".into(), J::String(name));
                    break;
                }
            }
        }
    }
    Ok(J::Object(out))
}

/// RDAP IP lookup (netblock plane). Returns a compacted JSON object.
fn rdap_ip(ip: &str) -> Result<J, String> {
    let url = format!("{RDAP_ENDPOINT}/ip/{}", encode_query_value(ip));
    let body = gov_json_get(&url, "application/rdap+json")?;
    let parsed: J =
        serde_json::from_str(&body).map_err(|e| format!("sitescan:shape: RDAP JSON: {e}"))?;
    let mut out = JMap::new();
    for (src, dst) in [
        ("handle", "handle"),
        ("name", "name"),
        ("country", "country"),
        ("type", "type"),
    ] {
        if let Some(v) = parsed.get(src).and_then(|v| v.as_str()) {
            out.insert(dst.to_string(), J::String(v.to_string()));
        }
    }
    let start = parsed.get("startAddress").and_then(|v| v.as_str());
    let end = parsed.get("endAddress").and_then(|v| v.as_str());
    if let (Some(s), Some(e)) = (start, end) {
        out.insert("range".into(), J::String(format!("{s} - {e}")));
    }
    if out.is_empty() {
        return Err("sitescan:shape: RDAP IP response had no recognizable fields".into());
    }
    Ok(J::Object(out))
}

// =====================================================================
// Value -> JSON conversion (for composed osint results)
// =====================================================================

/// Convert an interpreter `Value` into `serde_json::Value`. Privacy-wrapped
/// values are redacted, never serialized.
fn value_to_json(v: &Value) -> J {
    match v {
        Value::Nil => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Int(n) => match i64::try_from(*n) {
            Ok(x) => json!(x),
            Err(_) => J::String(n.to_string()),
        },
        Value::Float(f) => json!(*f),
        Value::String(s) => J::String(s.clone()),
        Value::Array(a) => J::Array(a.iter().map(value_to_json).collect()),
        Value::Map(m) => {
            let mut obj = JMap::new();
            for (k, val) in m {
                obj.insert(k.as_string(), value_to_json(val));
            }
            J::Object(obj)
        }
        Value::Ok(inner) => value_to_json(inner),
        Value::Err(inner) => json!({ "_error": inner.as_string() }),
        Value::Private(_) => J::String("«private»".to_string()),
        Value::Secret(_) => J::String("«secret»".to_string()),
        Value::Struct { name, fields } => {
            let mut obj = JMap::new();
            obj.insert("_type".to_string(), J::String(name.clone()));
            for (k, val) in fields {
                obj.insert(k.clone(), value_to_json(val));
            }
            J::Object(obj)
        }
        Value::Enum {
            enum_name,
            variant,
            fields,
        } => {
            let mut obj = JMap::new();
            obj.insert("_enum".to_string(), J::String(enum_name.clone()));
            obj.insert("variant".to_string(), J::String(variant.clone()));
            for (k, val) in fields {
                obj.insert(k.clone(), value_to_json(val));
            }
            J::Object(obj)
        }
        Value::Range { start, end, step } => {
            json!({"start": start.to_string(), "end": end.to_string(), "step": step.to_string()})
        }
        other => J::String(other.as_string()),
    }
}

// =====================================================================
// Network stage (composed from osint ScanScope + Scanner)
// =====================================================================

/// Parse dotted-quad IPv4 into u32.
fn parse_ipv4(s: &str) -> Option<u32> {
    let addr: std::net::Ipv4Addr = s.parse().ok()?;
    Some(u32::from(addr))
}

/// Containment test: is `ip` inside `base/mask`? (`mask` = prefix bits)
fn ipv4_in_cidr(ip: u32, base: u32, mask: u32) -> bool {
    if mask == 0 {
        return true;
    }
    if mask >= 32 {
        return ip == base;
    }
    let m = u32::MAX << (32 - mask);
    (ip & m) == (base & m)
}

/// Extract (base_ip, mask) from a `ScanScope` struct value produced by
/// `osint::dispatch("ScanScope.authorize", ...)`.
fn extract_scan_scope(scope: &Value) -> Result<(u32, u32), String> {
    if let Value::Struct { name, fields } = scope {
        if name == "ScanScope" {
            let base = fields
                .iter()
                .find(|(k, _)| k == "base_ip")
                .and_then(|(_, v)| match v {
                    Value::Int(n) => Some(*n as u32),
                    _ => None,
                })
                .ok_or_else(|| "ScanScope missing base_ip".to_string())?;
            let mask = fields
                .iter()
                .find(|(k, _)| k == "mask")
                .and_then(|(_, v)| match v {
                    Value::Int(n) => Some(*n as u32),
                    _ => None,
                })
                .ok_or_else(|| "ScanScope missing mask".to_string())?;
            return Ok((base, mask));
        }
    }
    Err("expected ScanScope struct".to_string())
}

/// Run the port scan through the osint Scanner resource. Every target IP is
/// validated inside `authorized_cidr` first; anything outside is refused.
fn run_port_scan(
    ips: &[String],
    ports: &[i128],
    authorized_cidr: &str,
    timeout_ms: u64,
) -> Result<(Vec<J>, Vec<String>, usize), String> {
    let scope = match super::osint::dispatch(
        "ScanScope.authorize",
        vec![Value::String(authorized_cidr.to_string())],
    ) {
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            return Err(format!(
                "sitescan:param: invalid authorized_cidr '{authorized_cidr}': {e}"
            ))
        }
        None => return Err("sitescan:param: ScanScope router unavailable".to_string()),
    };
    let (base, mask) = extract_scan_scope(&scope).map_err(|e| format!("sitescan:param: {e}"))?;

    let mut results: Vec<J> = Vec::new();
    let mut refused: Vec<String> = Vec::new();
    let mut scanned_hosts = 0usize;
    for ip in ips {
        let Some(ip_u32) = parse_ipv4(ip) else {
            refused.push(format!("{ip}: not an IPv4 address — skipped"));
            continue;
        };
        if !ipv4_in_cidr(ip_u32, base, mask) {
            refused.push(format!(
                "{ip}: outside authorized_cidr '{authorized_cidr}' — refused (containment gate)"
            ));
            continue;
        }
        let per_host = format!("{ip}/32");
        let host_scope = match super::osint::dispatch(
            "ScanScope.authorize",
            vec![Value::String(per_host)],
        ) {
            Some(Ok(v)) => v,
            Some(Err(e)) => {
                refused.push(format!("{ip}: scope error: {e}"));
                continue;
            }
            None => {
                refused.push(format!("{ip}: scope router unavailable"));
                continue;
            }
        };
        let call = super::osint::dispatch(
            "Scanner.scan",
            vec![
                host_scope,
                Value::Array(ports.iter().map(|p| Value::Int(*p)).collect()),
                Value::Int(timeout_ms as i128),
            ],
        );
        match call {
            Some(Ok(Value::Array(rows))) => {
                scanned_hosts += 1;
                for row in rows {
                    results.push(value_to_json(&row));
                }
            }
            Some(Ok(other)) => refused.push(format!("{ip}: unexpected scan result {}", other.as_string())),
            Some(Err(e)) => refused.push(format!("{ip}: scan error: {e}")),
            None => refused.push(format!("{ip}: Scanner router unavailable")),
        }
    }
    Ok((results, refused, scanned_hosts))
}

// =====================================================================
// Options + depth
// =====================================================================

#[derive(Debug, Clone)]
struct ScanOpts {
    max_pages: usize,
    link_depth: u32,
    max_js: usize,
    max_css: usize,
    include_subdomains: bool,
    brute: bool,
    wayback: bool,
    only: Vec<String>,
    ports: Vec<i128>,
    authorized_cidr: Option<String>,
    port_timeout_ms: u64,
}

impl Default for ScanOpts {
    fn default() -> Self {
        Self {
            max_pages: DEFAULT_MAX_PAGES,
            link_depth: DEFAULT_LINK_DEPTH,
            max_js: DEFAULT_MAX_JS,
            max_css: DEFAULT_MAX_CSS,
            include_subdomains: DEFAULT_INCLUDE_SUBDOMAINS,
            brute: false,
            wayback: false,
            only: Vec::new(),
            ports: DEFAULT_PORTS.to_vec(),
            authorized_cidr: None,
            port_timeout_ms: DEFAULT_PORT_TIMEOUT_MS,
        }
    }
}

fn opt_usize(opts: &J, key: &str) -> Option<usize> {
    opts.get(key).and_then(|v| v.as_u64()).map(|v| v as usize)
}

fn opt_bool(opts: &J, key: &str) -> Option<bool> {
    opts.get(key).and_then(|v| v.as_bool())
}

fn parse_opts(raw: Option<&Value>) -> Result<ScanOpts, String> {
    let mut o = ScanOpts::default();
    let Some(v) = raw else { return Ok(o) };
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Nil => return Ok(o),
        other => {
            return Err(format!(
                "sitescan:param: opts must be a JSON string, got {}",
                other.as_string()
            ))
        }
    };
    if s.trim().is_empty() {
        return Ok(o);
    }
    let parsed: J =
        serde_json::from_str(&s).map_err(|e| format!("sitescan:param: opts JSON: {e}"))?;
    if !parsed.is_object() {
        return Err("sitescan:param: opts JSON must be an object".to_string());
    }
    if let Some(v) = opt_usize(&parsed, "max_pages") {
        o.max_pages = v.clamp(1, HARD_MAX_PAGES);
    }
    if let Some(v) = opt_usize(&parsed, "link_depth") {
        o.link_depth = (v as u32).clamp(1, HARD_LINK_DEPTH);
    }
    if let Some(v) = opt_usize(&parsed, "max_js") {
        o.max_js = v.clamp(0, HARD_MAX_JS);
    }
    if let Some(v) = opt_usize(&parsed, "max_css") {
        o.max_css = v.clamp(0, HARD_MAX_CSS);
    }
    if let Some(v) = opt_bool(&parsed, "include_subdomains") {
        o.include_subdomains = v;
    }
    if let Some(v) = opt_bool(&parsed, "brute") {
        o.brute = v;
    }
    if let Some(v) = opt_bool(&parsed, "wayback") {
        o.wayback = v;
    }
    if let Some(v) = parsed.get("ports").and_then(|v| v.as_array()) {
        let mut ports: Vec<i128> = Vec::new();
        for p in v {
            if let Some(n) = p.as_i64() {
                if (1..=65535).contains(&n) && !ports.contains(&(n as i128)) {
                    ports.push(n as i128);
                }
            }
        }
        ports.truncate(HARD_MAX_PORTS);
        if !ports.is_empty() {
            o.ports = ports;
        }
    }
    if let Some(v) = parsed.get("authorized_cidr").and_then(|v| v.as_str()) {
        o.authorized_cidr = Some(v.to_string());
    }
    if let Some(v) = opt_usize(&parsed, "port_timeout_ms") {
        o.port_timeout_ms = (v as u64).clamp(200, 10_000);
    }
    if let Some(only) = parsed.get("only").and_then(|v| v.as_array()) {
        let valid = ["surface", "pages", "assets", "infra", "network"];
        for s in only {
            if let Some(name) = s.as_str() {
                let name = name.to_ascii_lowercase();
                if valid.contains(&name.as_str()) {
                    o.only.push(name);
                } else {
                    return Err(format!("sitescan:param: unknown stage '{name}' in only[]"));
                }
            }
        }
    }
    Ok(o)
}

/// Parse the depth argument: Int 1–5, or a label / `"full"`.
fn depth_of(arg: Option<&Value>) -> Result<(u8, &'static str), String> {
    const LABELS: [(u8, &str); 5] = [
        (1, "surface"),
        (2, "pages"),
        (3, "assets"),
        (4, "infra"),
        (5, "network"),
    ];
    let label_for = |level: u8| -> &'static str {
        LABELS
            .iter()
            .find(|(l, _)| *l == level)
            .map(|(_, s)| *s)
            .unwrap_or("surface")
    };
    let Some(v) = arg else { return Ok((1, "surface")) };
    match v {
        Value::Int(n) => {
            let level = *n as i64;
            if (1..=5).contains(&level) {
                Ok((level as u8, label_for(level as u8)))
            } else {
                Err(format!(
                    "sitescan:param: depth must be 1-5 (or a label), got {level}"
                ))
            }
        }
        Value::String(s) => {
            let l = s.trim().to_ascii_lowercase();
            if let Ok(level) = l.parse::<u8>() {
                if (1..=5).contains(&level) {
                    return Ok((level, label_for(level)));
                }
            }
            match l.as_str() {
                "surface" => Ok((1, "surface")),
                "pages" => Ok((2, "pages")),
                "assets" => Ok((3, "assets")),
                "infra" => Ok((4, "infra")),
                "network" => Ok((5, "network")),
                "full" | "max" => Ok((5, "network")),
                other => Err(format!(
                    "sitescan:param: unknown depth '{other}' (1-5, surface..network, full)"
                )),
            }
        }
        other => Err(format!(
            "sitescan:param: depth must be Int or String, got {}",
            other.as_string()
        )),
    }
}

/// Which stages run for a given depth (+ `only` override).
fn select_stages(level: u8, only: &[String]) -> Vec<&'static str> {
    const ALL: [&str; 5] = ["surface", "pages", "assets", "infra", "network"];
    if only.is_empty() {
        ALL.iter()
            .take(usize::from(level).min(5))
            .cloned()
            .collect()
    } else {
        ALL.iter()
            .filter(|s| only.iter().any(|o| o == *s))
            .cloned()
            .collect()
    }
}

// =====================================================================
// Shared stage plumbing
// =====================================================================

#[derive(Debug, Clone)]
struct HomePage {
    url: String,
    final_url: String,
    resp: HttpResp,
    facts: PageFacts,
}

#[derive(Debug, Clone)]
struct CrawledPage {
    url: String,
    final_url: String,
    status: u16,
    content_type: String,
    bytes: usize,
    depth: u32,
    title: String,
    links_internal: usize,
    links_external: usize,
    assets: usize,
    forms: usize,
    body_kept: bool,
    body: String,
}

/// Present response headers as a JSON object (duplicates joined).
fn headers_to_json(resp: &HttpResp) -> J {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in &resp.headers {
        grouped.entry(k.clone()).or_default().push(v.clone());
    }
    let mut obj = JMap::new();
    for (k, vs) in grouped {
        obj.insert(k, J::String(vs.join(", ")));
    }
    J::Object(obj)
}

/// Security-header presence report.
fn security_headers_to_json(resp: &HttpResp) -> J {
    let mut obj = JMap::new();
    for name in SECURITY_HEADERS {
        let value = resp.header(name);
        obj.insert(
            name.to_string(),
            json!({"present": value.is_some(), "value": value}),
        );
    }
    J::Object(obj)
}

/// Set-Cookie summary (names + flags; values are never parsed or kept).
fn cookies_to_json(resp: &HttpResp) -> J {
    let mut out: Vec<J> = Vec::new();
    for (k, v) in &resp.headers {
        if k != "set-cookie" {
            continue;
        }
        let name = v.split('=').next().unwrap_or("").trim().to_string();
        let lower = v.to_ascii_lowercase();
        let samesite = lower
            .find("samesite=")
            .map(|i| {
                lower[i + 9..]
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
            .unwrap_or_default();
        out.push(json!({
            "name": name,
            "secure": lower.contains("; secure"),
            "httponly": lower.contains("httponly"),
            "samesite": samesite,
        }));
    }
    J::Array(out)
}

/// Is a fetch response HTML-ish?
fn looks_html(resp: &HttpResp) -> bool {
    if let Some(ct) = resp.header("content-type") {
        return ct.to_ascii_lowercase().contains("html");
    }
    let head = resp.body.get(..1024).unwrap_or("").to_ascii_lowercase();
    head.contains("<!doctype html") || head.contains("<html")
}

/// Run the surface stage. Returns (JSON, homepage-for-reuse, parsed robots).
fn stage_surface(
    target: &url::Url,
    root_url: &str,
    errors: &mut Vec<String>,
) -> (J, Option<HomePage>, Option<Robots>) {
    let started = Instant::now();
    let mut out = JMap::new();

    // robots.txt
    let robots_url = format!("{}://{}/robots.txt", target.scheme(), target.host_str().unwrap_or(""));
    let robots = match fp_get_capped(&robots_url, &fp_headers(), true, BODY_CAP_SMALL) {
        Ok(resp) if resp.status == 200 => {
            // SPA hosts serve index.html for every path; a "robots.txt" that
            // is HTML is a fallback shell — record it, but do not treat it as
            // rules or apply fake crawl filtering.
            let html_fallback = looks_html(&resp);
            let parsed = parse_robots(&resp.body);
            out.insert(
                "robots".into(),
                json!({
                    "present": !html_fallback,
                    "html_fallback": html_fallback,
                    "disallow_count": parsed.disallow.len(),
                    "disallow": parsed.disallow.clone(),
                    "allow": parsed.allow.clone(),
                    "sitemaps": parsed.sitemaps.clone(),
                    "crawl_delay_s": parsed.crawl_delay_s,
                }),
            );
            if html_fallback {
                None
            } else {
                Some(parsed)
            }
        }
        Ok(resp) => {
            out.insert(
                "robots".into(),
                json!({"present": false, "status": resp.status}),
            );
            None
        }
        Err(e) => {
            errors.push(format!("surface/robots: {e}"));
            out.insert("robots".into(), json!({"present": false, "error": e}));
            None
        }
    };

    // sitemap.xml (root) — child sitemaps followed one level (cap 3).
    let sitemap_url = format!(
        "{}://{}/sitemap.xml",
        target.scheme(),
        target.host_str().unwrap_or("")
    );
    let mut sm = JMap::new();
    match fp_get_capped(&sitemap_url, &fp_headers(), true, BODY_CAP_SMALL) {
        Ok(resp) if resp.status == 200 => {
            // Same SPA-fallback defence as robots: a "sitemap" that is not
            // XML is not a sitemap — record the fallback shape only.
            if !(resp.body.contains("<urlset") || resp.body.contains("<sitemapindex")) {
                sm.insert("present".into(), J::Bool(false));
                sm.insert("html_fallback".into(), J::Bool(looks_html(&resp)));
                sm.insert("status".into(), json!(resp.status));
            } else {
            let info = parse_sitemap(&resp.body);
            sm.insert("present".into(), J::Bool(true));
            sm.insert("is_index".into(), J::Bool(info.is_index));
            sm.insert("url_count".into(), json!(info.total_locs));
            if info.is_index {
                let mut child_urls: Vec<String> = Vec::new();
                for child in info.children.iter().take(3) {
                    if let Ok(cresp) = fp_get_capped(child, &fp_headers(), true, BODY_CAP_SMALL) {
                        if cresp.status == 200 {
                            let cinfo = parse_sitemap(&cresp.body);
                            child_urls.extend(cinfo.urls.into_iter().take(20));
                        }
                    }
                }
                sm.insert("children".into(), json!(info.children));
                sm.insert(
                    "sample".into(),
                    json!(child_urls.into_iter().take(20).collect::<Vec<_>>()),
                );
            } else {
                sm.insert(
                    "sample".into(),
                    json!(info.urls.iter().take(20).cloned().collect::<Vec<_>>()),
                );
            }
            }
        }
        Ok(resp) => {
            sm.insert("present".into(), J::Bool(false));
            sm.insert("status".into(), json!(resp.status));
        }
        Err(e) => {
            errors.push(format!("surface/sitemap: {e}"));
            sm.insert("present".into(), J::Bool(false));
            sm.insert("error".into(), J::String(e));
        }
    }
    out.insert("sitemap".into(), J::Object(sm));

    // Homepage.
    let resp = match fp_get(root_url, &fp_headers(), true) {
        Ok(r) => r,
        Err(e) => {
            errors.push(format!("sitescan:fatal: surface fetch failed: {e}"));
            out.insert("homepage".into(), json!({"error": e}));
            out.insert("duration_ms".into(), json!(started.elapsed().as_millis()));
            return (J::Object(out), None, robots);
        }
    };
    let facts = parse_page_facts(&resp.body, target);
    let base_host = target.host_str().unwrap_or("").to_string();
    let mut internal = 0usize;
    let mut external = 0usize;
    let mut third_party: BTreeSet<String> = BTreeSet::new();
    for link in &facts.links {
        if let Ok(u) = url::Url::parse(link) {
            let host = u.host_str().unwrap_or("").to_string();
            if same_site(&host, &base_host, true) {
                internal += 1;
            } else {
                external += 1;
                third_party.insert(host);
            }
        }
    }
    for asset in &facts.assets {
        if let Ok(u) = url::Url::parse(&asset.url) {
            let host = u.host_str().unwrap_or("").to_string();
            if !same_site(&host, &base_host, true) {
                third_party.insert(host);
            }
        }
    }

    out.insert(
        "http".into(),
        json!({
            "status": resp.status,
            "final_url": resp.final_url,
            "content_type": resp.header("content-type"),
            "bytes": resp.len,
            "redirected": resp.final_url != root_url,
        }),
    );
    out.insert("headers".into(), headers_to_json(&resp));
    out.insert(
        "security_headers".into(),
        security_headers_to_json(&resp),
    );
    out.insert("cookies".into(), cookies_to_json(&resp));
    out.insert(
        "homepage".into(),
        json!({
            "title": facts.title,
            "meta_description": facts.meta_description,
            "meta_generator": facts.meta_generator,
            "lang": facts.lang,
            "links_internal": internal,
            "links_external": external,
            "mailto_links": facts.mailto_count,
            "tel_links": facts.tel_count,
            "assets": facts.assets.len(),
            "scripts": facts.script_srcs.len(),
            "stylesheets": facts.stylesheets.len(),
            "iframes": facts.iframes.len(),
            "forms": facts.forms.iter().map(|f| json!({
                "action": f.action,
                "method": f.method,
                "inputs": f.inputs.iter().map(|(n, k)| json!({"name": n, "kind": k})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }),
    );
    out.insert(
        "third_party_hosts".into(),
        json!(third_party.iter().cloned().collect::<Vec<_>>()),
    );

    // Tech fingerprint — reuse the osint signature table on the page we
    // already fetched (no second request).
    let tech = super::osint::match_signatures(&resp.headers, &resp.body);
    out.insert(
        "tech".into(),
        json!(tech
            .into_iter()
            .map(|(name, category, confidence)| {
                json!({"name": name, "category": category, "confidence": confidence})
            })
            .collect::<Vec<_>>()),
    );

    out.insert("duration_ms".into(), json!(started.elapsed().as_millis()));
    (
        J::Object(out),
        Some(HomePage {
            url: root_url.to_string(),
            final_url: resp.final_url.clone(),
            resp,
            facts,
        }),
        robots,
    )
}

/// Bounded same-site crawl (breadth-first over a[href] links).
fn crawl(
    seed: &url::Url,
    home: Option<&HomePage>,
    robots: Option<&Robots>,
    opts: &ScanOpts,
    errors: &mut Vec<String>,
) -> (Vec<CrawledPage>, bool) {
    let base_host = seed.host_str().unwrap_or("").to_string();
    let mut pages: Vec<CrawledPage> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<(url::Url, u32)> = VecDeque::new();
    let mut capped = false;
    let mut body_budget = CRAWL_BODY_BUDGET;

    if let Some(h) = home {
        let final_u = url::Url::parse(&h.final_url).unwrap_or_else(|_| seed.clone());
        seen.insert(key_of(&final_u));
        let (li, le) = count_links(&h.facts, &base_host, opts.include_subdomains);
        pages.push(CrawledPage {
            url: h.url.clone(),
            final_url: h.final_url.clone(),
            status: h.resp.status,
            content_type: h
                .resp
                .header("content-type")
                .unwrap_or("")
                .to_string(),
            bytes: h.resp.len,
            depth: 0,
            title: h.facts.title.clone(),
            links_internal: li,
            links_external: le,
            assets: h.facts.assets.len(),
            forms: h.facts.forms.len(),
            body_kept: true,
            body: h.resp.body.clone(),
        });
        body_budget = body_budget.saturating_sub(h.resp.body.len());
        enqueue_links(&h.facts, seed, &base_host, 1, robots, &seen, &mut queue, opts);
    } else {
        queue.push_back((seed.clone(), 0));
    }

    while let Some((u, depth)) = queue.pop_front() {
        if pages.len() >= opts.max_pages {
            capped = true;
            break;
        }
        let k = key_of(&u);
        if !seen.insert(k) {
            continue;
        }
        if let Some(rb) = robots {
            if !robots_allows(rb, u.path()) {
                continue;
            }
        }
        match fp_get(u.as_str(), &fp_headers(), true) {
            Ok(resp) => {
                let facts = if looks_html(&resp) {
                    parse_page_facts(&resp.body, &u)
                } else {
                    PageFacts::default()
                };
                let (li, le) = count_links(&facts, &base_host, opts.include_subdomains);
                let keep_body = body_budget > 0;
                let body = if keep_body {
                    body_budget = body_budget.saturating_sub(resp.body.len());
                    resp.body.clone()
                } else {
                    String::new()
                };
                pages.push(CrawledPage {
                    url: u.to_string(),
                    final_url: resp.final_url.clone(),
                    status: resp.status,
                    content_type: resp.header("content-type").unwrap_or("").to_string(),
                    bytes: resp.len,
                    depth,
                    title: facts.title.clone(),
                    links_internal: li,
                    links_external: le,
                    assets: facts.assets.len(),
                    forms: facts.forms.len(),
                    body_kept: keep_body,
                    body,
                });
                if depth < opts.link_depth {
                    let final_u = url::Url::parse(&resp.final_url).unwrap_or_else(|_| u.clone());
                    enqueue_links(&facts, &final_u, &base_host, depth + 1, robots, &seen, &mut queue, opts);
                }
            }
            Err(e) => {
                errors.push(format!("pages/{u}: {e}"));
            }
        }
    }
    (pages, capped)
}

fn count_links(facts: &PageFacts, base_host: &str, include_sub: bool) -> (usize, usize) {
    let mut internal = 0usize;
    let mut external = 0usize;
    for link in &facts.links {
        if let Ok(u) = url::Url::parse(link) {
            let host = u.host_str().unwrap_or("").to_string();
            if same_site(&host, base_host, include_sub) {
                internal += 1;
            } else {
                external += 1;
            }
        }
    }
    (internal, external)
}

#[allow(clippy::too_many_arguments)]
fn enqueue_links(
    facts: &PageFacts,
    _base: &url::Url,
    base_host: &str,
    next_depth: u32,
    robots: Option<&Robots>,
    seen: &BTreeSet<String>,
    queue: &mut VecDeque<(url::Url, u32)>,
    opts: &ScanOpts,
) {
    for link in &facts.links {
        let Ok(u) = url::Url::parse(link) else { continue };
        let host = u.host_str().unwrap_or("").to_string();
        if !same_site(&host, base_host, opts.include_subdomains) {
            continue;
        }
        if let Some(rb) = robots {
            if !robots_allows(rb, u.path()) {
                continue;
            }
        }
        let k = key_of(&u);
        if seen.contains(&k) {
            continue;
        }
        if queue.len() >= 2000 {
            return;
        }
        queue.push_back((u, next_depth));
    }
}

/// Assets stage: roll up assets from crawled pages, fetch JS/CSS samples,
/// mine endpoints/refs. Returns the stage JSON.
fn stage_assets(
    seed: &url::Url,
    pages: &[CrawledPage],
    home: Option<&HomePage>,
    opts: &ScanOpts,
    errors: &mut Vec<String>,
) -> J {
    let started = Instant::now();
    let base_host = seed.host_str().unwrap_or("").to_string();
    let mut out = JMap::new();

    // Build the fact set to mine: prefer crawled page bodies; if none are
    // available (only=["assets"]), fetch the seed once.
    let mut facts_list: Vec<PageFacts> = Vec::new();
    let mut inline_sources: Vec<(String, String)> = Vec::new();
    if pages.is_empty() && home.is_none() {
        match fp_get(seed.as_str(), &fp_headers(), true) {
            Ok(resp) => {
                let facts = parse_page_facts(&resp.body, seed);
                if !facts.inline_js.is_empty() {
                    inline_sources.push((resp.final_url.clone(), facts.inline_js.clone()));
                }
                facts_list.push(facts);
            }
            Err(e) => {
                errors.push(format!("assets/seed: {e}"));
                out.insert("error".into(), J::String(e));
                out.insert("duration_ms".into(), json!(started.elapsed().as_millis()));
                return J::Object(out);
            }
        }
    } else {
        // Re-parse facts from stored page bodies.
        for p in pages {
            if !p.body.is_empty() {
                if let Ok(u) = url::Url::parse(&p.final_url) {
                    let facts = parse_page_facts(&p.body, &u);
                    if !facts.inline_js.is_empty() {
                        inline_sources.push((p.final_url.clone(), facts.inline_js.clone()));
                    }
                    facts_list.push(facts);
                }
            }
        }
        if let Some(h) = home {
            if !h.facts.inline_js.is_empty()
                && !inline_sources.iter().any(|(u, _)| u == &h.final_url)
            {
                inline_sources.push((h.final_url.clone(), h.facts.inline_js.clone()));
            }
            // Ensure the homepage's own facts participate when the crawl
            // didn't already re-parse its body.
            let home_included = pages
                .iter()
                .any(|p| p.final_url == h.final_url && !p.body.is_empty());
            if !home_included {
                facts_list.push(h.facts.clone());
            }
        }
    }
    let asset_source_pages = &facts_list;

    // Asset inventory.
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_host: BTreeMap<String, usize> = BTreeMap::new();
    let mut external_hosts: BTreeSet<String> = BTreeSet::new();
    let mut unique_assets: BTreeSet<(String, String)> = BTreeSet::new(); // (url, kind)
    let mut documents: BTreeSet<String> = BTreeSet::new();
    for facts in asset_source_pages.iter() {
        for a in &facts.assets {
            let key = (a.url.clone(), a.kind.clone());
            if unique_assets.contains(&key) {
                continue;
            }
            unique_assets.insert(key);
            *by_kind.entry(a.kind.clone()).or_insert(0) += 1;
            if let Ok(u) = url::Url::parse(&a.url) {
                let host = u.host_str().unwrap_or("").to_string();
                *by_host.entry(host.clone()).or_insert(0) += 1;
                if !same_site(&host, &base_host, true) {
                    external_hosts.insert(host);
                }
            }
        }
        for link in &facts.links {
            if let Ok(u) = url::Url::parse(link) {
                let ext = u
                    .path()
                    .rsplit('.')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if DOCUMENT_EXTS.contains(&ext.as_str()) {
                    documents.insert(link.clone());
                }
            }
        }
    }

    // Fetch CSS samples and mine refs.
    let mut css_refs: Vec<J> = Vec::new();
    let mut css_fetched = 0usize;
    let mut seen_css: BTreeSet<String> = BTreeSet::new();
    'css: for facts in asset_source_pages.iter() {
        for sheet in &facts.stylesheets {
            if seen_css.contains(sheet) {
                continue;
            }
            if css_fetched >= opts.max_css {
                break 'css;
            }
            seen_css.insert(sheet.clone());
            match fp_get_capped(sheet, &fp_headers(), true, BODY_CAP_CSS) {
                Ok(resp) if resp.status == 200 => {
                    css_fetched += 1;
                    let (urls, imports) = mine_css_refs(&resp.body);
                    let mut refs: Vec<J> = Vec::new();
                    for r in urls.iter().take(100) {
                        if let Some(u) = abs_url(&resp_or_base(&resp.final_url, seed), r) {
                            let kind = if is_font_url(u.path()) { "font" } else { "image" };
                            refs.push(json!({"url": u.to_string(), "kind": kind}));
                        } else {
                            refs.push(json!({"url": r, "kind": "ref"}));
                        }
                    }
                    for imp in imports.iter().take(20) {
                        if let Some(u) = abs_url(&url::Url::parse(&resp.final_url).unwrap_or_else(|_| seed.clone()), imp) {
                            refs.push(json!({"url": u.to_string(), "kind": "import"}));
                        }
                    }
                    css_refs.push(json!({
                        "sheet": sheet,
                        "refs": refs,
                    }));
                }
                Ok(resp) => {
                    errors.push(format!("sitescan:http: CSS {sheet} -> {}", resp.status));
                }
                Err(e) => errors.push(format!("assets/css {sheet}: {e}")),
            }
        }
    }

    // Fetch JS samples and mine endpoints.
    let mut js_sources: Vec<J> = Vec::new();
    let mut js_fetched = 0usize;
    let mut endpoint_map: BTreeMap<(String, String), String> = BTreeMap::new(); // (kind,value)->source
    let mut sourcemaps: BTreeSet<String> = BTreeSet::new();
    let mut seen_js: BTreeSet<String> = BTreeSet::new();
    // Same-site scripts first (own code reveals own endpoints).
    let mut script_candidates: Vec<(bool, String)> = Vec::new();
    for facts in asset_source_pages.iter() {
        for s in &facts.script_srcs {
            let is_same = url::Url::parse(s)
                .ok()
                .and_then(|u| u.host_str().map(|h| same_site(h, &base_host, true)))
                .unwrap_or(false);
            if !seen_js.contains(s) {
                seen_js.insert(s.clone());
                script_candidates.push((is_same, s.clone()));
            }
        }
    }
    script_candidates.sort_by_key(|(same, _)| !*same);
    'js: for (_same, script) in &script_candidates {
        if js_fetched >= opts.max_js {
            break 'js;
        }
        match fp_get_capped(script, &fp_headers(), true, BODY_CAP_JS) {
            Ok(resp) if resp.status == 200 => {
                js_fetched += 1;
                let body = if resp.body.len() > BODY_CAP_JS {
                    &resp.body[..BODY_CAP_JS]
                } else {
                    &resp.body
                };
                let found = mine_js_endpoints(body);
                let mut count = 0usize;
                for (kind, value) in found {
                    if kind == "sourcemap" {
                        sourcemaps.insert(value.clone());
                    }
                    endpoint_map
                        .entry((kind, value))
                        .or_insert_with(|| script.clone());
                    count += 1;
                }
                js_sources.push(json!({
                    "url": script,
                    "bytes": resp.len,
                    "endpoints_found": count,
                }));
            }
            Ok(resp) => errors.push(format!("sitescan:http: JS {script} -> {}", resp.status)),
            Err(e) => errors.push(format!("assets/js {script}: {e}")),
        }
    }
    // Inline scripts.
    for (page_url, inline) in &inline_sources {
        let found = mine_js_endpoints(inline);
        for (kind, value) in found {
            if kind == "sourcemap" {
                sourcemaps.insert(value.clone());
            }
            endpoint_map
                .entry((kind, value))
                .or_insert_with(|| format!("{page_url} (inline)"));
        }
    }

    out.insert(
        "inventory".into(),
        json!({
            "unique": unique_assets.len(),
            "by_kind": by_kind,
            "by_host": by_host,
            "external_hosts": external_hosts.iter().cloned().collect::<Vec<_>>(),
            "documents": documents.iter().take(100).cloned().collect::<Vec<_>>(),
        }),
    );
    out.insert(
        "css".into(),
        json!({"fetched": css_fetched, "sheets": css_refs}),
    );
    out.insert(
        "js".into(),
        json!({"fetched": js_fetched, "sources": js_sources, "inline_blocks": inline_sources.len()}),
    );
    out.insert(
        "endpoints".into(),
        json!(endpoint_map
            .iter()
            .take(MAX_ENDPOINTS_KEPT)
            .map(|((kind, value), source)| {
                json!({"kind": kind, "value": value, "source": source})
            })
            .collect::<Vec<_>>()),
    );
    out.insert(
        "sourcemaps".into(),
        json!(sourcemaps.iter().take(50).cloned().collect::<Vec<_>>()),
    );
    out.insert("duration_ms".into(), json!(started.elapsed().as_millis()));
    J::Object(out)
}

/// Base for resolving CSS-relative refs: prefer the sheet's final URL,
/// falling back to the scan seed.
fn resp_or_base<'a>(final_url: &str, seed: &'a url::Url) -> url::Url {
    url::Url::parse(final_url).unwrap_or_else(|_| seed.clone())
}

fn is_font_url(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    matches!(ext.as_str(), "woff" | "woff2" | "ttf" | "otf" | "eot")
}

/// Infra stage: DNS records, CT subdomains + certs, RDAP, optional brute +
/// Wayback. Returns (JSON, resolved IPs for the network stage).
fn stage_infra(
    target: &url::Url,
    opts: &ScanOpts,
    errors: &mut Vec<String>,
) -> (J, Vec<String>) {
    let started = Instant::now();
    let mut out = JMap::new();
    let host = target.host_str().unwrap_or("").to_string();
    let apex = apex_host(&host);

    // ── DNS via DoH ──
    let mut dns = JMap::new();
    let mut dns_errors = JMap::new();
    let mut ips: Vec<String> = Vec::new();
    for rtype in DNS_TYPES {
        let qname = if rtype == "A" || rtype == "AAAA" { &host } else { &apex };
        match doh_query(qname, rtype) {
            Ok(rows) => {
                let values: Vec<J> = rows
                    .iter()
                    .map(|(owner, data)| json!({"name": owner, "data": data}))
                    .collect();
                if rtype == "A" || rtype == "AAAA" {
                    for (_o, data) in &rows {
                        if !ips.contains(data) && data.parse::<std::net::IpAddr>().is_ok() {
                            ips.push(data.clone());
                        }
                    }
                }
                dns.insert(rtype.to_string(), J::Array(values));
            }
            Err(e) => {
                dns.insert(rtype.to_string(), J::Array(vec![]));
                dns_errors.insert(rtype.to_string(), J::String(e.clone()));
                errors.push(format!("infra/dns.{rtype}: {e}"));
            }
        }
    }
    // Also resolve the apex when the host carries a www prefix.
    if apex != host {
        if let Ok(rows) = doh_query(&apex, "A") {
            let mut extra: Vec<J> = Vec::new();
            for (_o, data) in &rows {
                if !ips.contains(data) && data.parse::<std::net::Ipv4Addr>().is_ok() {
                    ips.push(data.clone());
                }
                extra.push(json!({"name": apex, "data": data}));
            }
            dns.insert("A_apex".to_string(), J::Array(extra));
        }
    }
    out.insert("dns".into(), J::Object(dns));
    if !dns_errors.is_empty() {
        out.insert("dns_errors".into(), J::Object(dns_errors));
    }
    out.insert("ips".into(), json!(ips));

    // ── CT logs: subdomains + certificate summary ──
    match ct_lookup(&apex) {
        Ok(ct) => {
            let mut cj = JMap::new();
            cj.insert("count".into(), json!(ct.subdomains.len()));
            cj.insert("items".into(), json!(ct.subdomains));
            cj.insert("wildcard_count".into(), json!(ct.wildcard_count));
            cj.insert("source".into(), J::String(ct.source.clone()));
            out.insert("subdomains".into(), J::Object(cj));
            out.insert(
                "certs".into(),
                json!({
                    "cert_rows": ct.cert_count,
                    "issuers": ct.issuers,
                    "earliest_not_before": ct.earliest_not_before,
                    "latest_not_after": ct.latest_not_after,
                    "latest_not_after_days": ct.latest_not_after_days,
                    "expiring_within_45d_rows": ct.expiring_within_45d,
                    "sample_sans": ct.sample_sans,
                }),
            );
        }
        Err(e) => {
            errors.push(format!("infra/ct: {e}"));
            out.insert("subdomains".into(), json!({"error": e}));
        }
    }

    // ── Optional DNS brute (rides DoH; opt-in) ──
    if opts.brute {
        let mut found_names: Vec<String> = Vec::new();
        for word in DNS_BRUTE_WORDS {
            let candidate = format!("{word}.{apex}");
            if let Ok(rows) = doh_query(&candidate, "A") {
                if !rows.is_empty() {
                    found_names.push(candidate);
                }
            }
        }
        out.insert("dns_brute".into(), json!({"wordlist": DNS_BRUTE_WORDS.len(), "found": found_names}));
    }

    // ── RDAP: domain (registrar plane) + netblocks ──
    match rdap_domain(&apex) {
        Ok(v) => {
            out.insert("rdap_domain".into(), v);
        }
        Err(e) => {
            errors.push(format!("infra/rdap-domain: {e}"));
            out.insert("rdap_domain".into(), json!({"error": e}));
        }
    }
    let mut nets: Vec<J> = Vec::new();
    for ip in ips.iter().take(4) {
        match rdap_ip(ip) {
            Ok(v) => nets.push(v),
            Err(e) => errors.push(format!("infra/rdap-ip {ip}: {e}")),
        }
    }
    out.insert("netblocks".into(), J::Array(nets));

    // ── Optional Wayback history (composed from osint WebArchive) ──
    if opts.wayback {
        let root = format!("{}://{}", target.scheme(), host);
        match super::osint::dispatch(
            "WebArchive.snapshots",
            vec![Value::String(root), Value::Int(10)],
        ) {
            Some(Ok(Value::Array(rows))) => {
                let snaps: Vec<J> = rows.iter().take(20).map(value_to_json).collect();
                out.insert("wayback".into(), json!({"count": snaps.len(), "snapshots": snaps}));
            }
            Some(Ok(other)) => {
                out.insert("wayback".into(), json!({"note": other.as_string()}));
            }
            Some(Err(e)) => errors.push(format!("infra/wayback: {e}")),
            None => errors.push("infra/wayback: WebArchive router unavailable".to_string()),
        }
    }

    out.insert("duration_ms".into(), json!(started.elapsed().as_millis()));
    (J::Object(out), ips)
}

/// Network stage: TCP connect port scan under an explicit authorization gate.
fn stage_network(
    target: &url::Url,
    opts: &ScanOpts,
    known_ips: &[String],
    errors: &mut Vec<String>,
) -> J {
    let started = Instant::now();
    let mut out = JMap::new();
    let ips = if known_ips.is_empty() {
        resolve_ips(target.host_str().unwrap_or(""))
    } else {
        known_ips.to_vec()
    };
    out.insert("resolved_ips".into(), json!(ips));
    let Some(cidr) = opts.authorized_cidr.clone() else {
        errors.push(
            "sitescan:param: network stage requires opts.authorized_cidr (ScanScope gate) — skipped"
                .to_string(),
        );
        out.insert("skipped".into(), J::Bool(true));
        out.insert(
            "reason".into(),
            J::String("authorized_cidr not provided".to_string()),
        );
        out.insert("duration_ms".into(), json!(started.elapsed().as_millis()));
        return J::Object(out);
    };
    match run_port_scan(&ips, &opts.ports, &cidr, opts.port_timeout_ms) {
        Ok((results, refused, scanned_hosts)) => {
            let open: Vec<J> = results
                .iter()
                .filter(|r| r.get("open").and_then(|v| v.as_bool()) == Some(true))
                .cloned()
                .collect();
            out.insert("authorized_cidr".into(), J::String(cidr));
            out.insert("targets_scanned".into(), json!(scanned_hosts));
            out.insert(
                "ports_requested".into(),
                json!(opts.ports.iter().map(|p| *p as i64).collect::<Vec<_>>()),
            );
            out.insert("results".into(), J::Array(results));
            out.insert("open".into(), J::Array(open));
            out.insert("refused".into(), json!(refused));
        }
        Err(e) => {
            errors.push(e.clone());
            out.insert("error".into(), J::String(e));
        }
    }
    out.insert("duration_ms".into(), json!(started.elapsed().as_millis()));
    J::Object(out)
}

// =====================================================================
// Public functions
// =====================================================================

/// `sitescan.scan(target, depth?, opts?) -> String` (JSON envelope).
fn scan(args: Vec<Value>) -> StdlibResult {
    let target_raw = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("sitescan:param: scan() requires a target URL string".to_string()),
    };
    let target = normalize_target(&target_raw)?;
    let (level, label) = depth_of(args.get(1))?;
    let opts = parse_opts(args.get(2))?;
    let stages = select_stages(level, &opts.only);

    let started_at = Utc::now();
    let started = Instant::now();
    let mut errors: Vec<String> = Vec::new();
    let host = target.host_str().unwrap_or("").to_string();
    let root_url = target.to_string();

    let mut envelope = JMap::new();
    envelope.insert("module".into(), J::String("sitescan".into()));
    envelope.insert("version".into(), J::String(VERSION.into()));
    envelope.insert("target".into(), J::String(root_url.clone()));
    envelope.insert("host".into(), J::String(host.clone()));
    envelope.insert("apex".into(), J::String(apex_host(&host)));
    envelope.insert(
        "depth".into(),
        json!({"level": level, "label": label, "requested": args.get(1).map(|v| v.as_string())}),
    );
    envelope.insert("stage_order".into(), json!(stages));
    envelope.insert("started_at".into(), J::String(started_at.to_rfc3339()));

    let mut stages_obj = JMap::new();
    let mut home: Option<HomePage> = None;
    let mut pages_data: Vec<CrawledPage> = Vec::new();
    let mut infra_ips: Vec<String> = Vec::new();
    let mut robots: Option<Robots> = None;

    for stage in &stages {
        match *stage {
            "surface" => {
                let (sjson, h, rb) = stage_surface(&target, &root_url, &mut errors);
                home = h;
                robots = rb;
                stages_obj.insert("surface".into(), sjson);
            }
            "pages" => {
                let (pjson, _capped, crawled) =
                    run_pages_stage(&target, home.as_ref(), robots.as_ref(), &opts, &mut errors);
                pages_data = crawled;
                stages_obj.insert("pages".into(), pjson);
            }
            "assets" => {
                let ajson = stage_assets(&target, &pages_data, home.as_ref(), &opts, &mut errors);
                stages_obj.insert("assets".into(), ajson);
            }
            "infra" => {
                let (ijson, ips) = stage_infra(&target, &opts, &mut errors);
                infra_ips = ips;
                stages_obj.insert("infra".into(), ijson);
            }
            "network" => {
                let njson = stage_network(&target, &opts, &infra_ips, &mut errors);
                stages_obj.insert("network".into(), njson);
            }
            _ => {}
        }
    }

    let surface_ok = if stages.contains(&"surface") {
        home.is_some()
    } else {
        true
    };

    envelope.insert("ok".into(), J::Bool(surface_ok));
    envelope.insert("stages".into(), J::Object(stages_obj));
    envelope.insert("errors".into(), json!(errors));
    envelope.insert(
        "limits".into(),
        json!({
            "max_pages": opts.max_pages,
            "link_depth": opts.link_depth,
            "max_js": opts.max_js,
            "max_css": opts.max_css,
            "include_subdomains": opts.include_subdomains,
            "ports": opts.ports.iter().map(|p| *p as i64).collect::<Vec<_>>(),
            "port_timeout_ms": opts.port_timeout_ms,
            "pacing_rps": gov_rps(),
            "notes": [
                "read-only GET-only; public data; robotted crawl",
                "HTTP via fail-closed egress contract (Tor by default)",
                "DNS via Cloudflare DoH (no plain :53)",
                "network stage is direct TCP connect, gated by authorized_cidr"
            ],
        }),
    );
    envelope.insert(
        "finished_at".into(),
        J::String(Utc::now().to_rfc3339()),
    );
    envelope.insert("duration_ms".into(), json!(started.elapsed().as_millis()));

    Ok(Value::String(J::Object(envelope).to_string()))
}

/// Pages stage wrapper (kept separate for clarity).
fn run_pages_stage(
    target: &url::Url,
    home: Option<&HomePage>,
    robots: Option<&Robots>,
    opts: &ScanOpts,
    errors: &mut Vec<String>,
) -> (J, bool, Vec<CrawledPage>) {
    let started = Instant::now();
    let (pages, capped) = crawl(target, home, robots, opts, errors);
    let mut out = JMap::new();
    out.insert("count".into(), json!(pages.len()));
    out.insert("capped".into(), J::Bool(capped));
    out.insert(
        "pages".into(),
        J::Array(
            pages
                .iter()
                .take(MAX_PAGES_LISTED)
                .map(|p| {
                    json!({
                        "url": p.url,
                        "final_url": p.final_url,
                        "status": p.status,
                        "content_type": p.content_type,
                        "bytes": p.bytes,
                        "depth": p.depth,
                        "title": p.title,
                        "links_internal": p.links_internal,
                        "links_external": p.links_external,
                        "assets": p.assets,
                        "forms": p.forms,
                        "body_kept": p.body_kept,
                    })
                })
                .collect::<Vec<_>>(),
        ),
    );
    out.insert("duration_ms".into(), json!(started.elapsed().as_millis()));
    (J::Object(out), capped, pages)
}

/// `sitescan.report(scan_json) -> String` — Markdown aggregation.
fn report(args: Vec<Value>) -> StdlibResult {
    let raw = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("sitescan:param: report() requires the scan JSON string".to_string()),
    };
    let env: J = serde_json::from_str(&raw)
        .map_err(|e| format!("sitescan:param: report input is not valid scan JSON: {e}"))?;
    Ok(Value::String(render_report(&env)))
}

/// Render a scan envelope as Markdown. Pure function (unit-testable).
fn render_report(env: &J) -> String {
    let mut s = String::new();
    let g = |path: &[&str]| -> Option<&J> {
        let mut cur = env;
        for p in path {
            cur = cur.get(*p)?;
        }
        Some(cur)
    };
    let gs = |path: &[&str]| -> String {
        match g(path) {
            Some(J::String(v)) => v.clone(),
            Some(v) if !v.is_null() => v.to_string(),
            _ => String::new(),
        }
    };
    let gn = |path: &[&str]| -> i64 { g(path).and_then(|v| v.as_i64()).unwrap_or(0) };

    let target = gs(&["target"]);
    let host = gs(&["host"]);
    let depth_label = gs(&["depth", "label"]);
    let depth_level = gn(&["depth", "level"]);
    let ok = g(&["ok"]).and_then(|v| v.as_bool()).unwrap_or(false);

    let _ = writeln!(s, "# Site scan report — {target}");
    s.push('\n');
    let _ = writeln!(
        s,
        "**Host:** `{host}` · **Depth:** {depth_level} (`{depth_label}`) · **Status:** {} · **Duration:** {} ms · **Module:** sitescan {}",
        if ok { "ok" } else { "PARTIAL" },
        gn(&["duration_ms"]),
        gs(&["version"]),
    );
    let _ = writeln!(
        s,
        "**Started:** {}  ·  **Finished:** {}",
        gs(&["started_at"]),
        gs(&["finished_at"])
    );
    s.push('\n');

    // Surface
    if let Some(surface) = g(&["stages", "surface"]) {
        s.push_str("## 1. Surface\n\n");
        let status = surface.get("http").and_then(|h| h.get("status")).and_then(|v| v.as_u64());
        let final_url = surface
            .get("http")
            .and_then(|h| h.get("final_url"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let bytes = surface.get("http").and_then(|h| h.get("bytes")).and_then(|v| v.as_u64());
        let _ = writeln!(
            s,
            "- Primary document: HTTP {} · {} bytes · landed on `{}`",
            status.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
            bytes.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
            final_url
        );
        if let Some(home) = surface.get("homepage") {
            let _ = writeln!(
                s,
                "- Title: {}",
                home.get("title").and_then(|v| v.as_str()).filter(|t| !t.is_empty()).unwrap_or("(none)")
            );
            let _ = writeln!(
                s,
                "- Links: {} internal / {} external · assets {} · forms {}",
                home.get("links_internal").and_then(|v| v.as_i64()).unwrap_or(0),
                home.get("links_external").and_then(|v| v.as_i64()).unwrap_or(0),
                home.get("assets").and_then(|v| v.as_i64()).unwrap_or(0),
                home.get("forms").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
            );
        }
        if let Some(rb) = surface.get("robots") {
            let present = rb.get("present").and_then(|v| v.as_bool()).unwrap_or(false);
            if present {
                let sitemaps = rb
                    .get("sitemaps")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "[]".to_string());
                let _ = writeln!(
                    s,
                    "- robots.txt: present · {} disallow rules · sitemaps: {}",
                    rb.get("disallow_count").and_then(|v| v.as_i64()).unwrap_or(0),
                    sitemaps
                );
            } else if rb.get("html_fallback").and_then(|v| v.as_bool()) == Some(true) {
                let _ = writeln!(s, "- robots.txt: none (SPA fallback served HTML, not rules)");
            } else {
                let _ = writeln!(s, "- robots.txt: absent");
            }
        }
        if let Some(sm) = surface.get("sitemap") {
            let _ = writeln!(
                s,
                "- sitemap.xml: present={} · urls={}",
                sm.get("present").and_then(|v| v.as_bool()).unwrap_or(false),
                sm.get("url_count").and_then(|v| v.as_i64()).unwrap_or(0)
            );
        }
        if let Some(sec) = surface.get("security_headers").and_then(|v| v.as_object()) {
            s.push_str("\n### Security headers\n\n");
            for (name, info) in sec {
                let present = info.get("present").and_then(|v| v.as_bool()).unwrap_or(false);
                let value = info
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let mark = if present { "✅" } else { "❌" };
                if value.is_empty() {
                    let _ = writeln!(s, "- {mark} `{name}`");
                } else {
                    let _ = writeln!(s, "- {mark} `{name}`: `{value}`");
                }
            }
        }
        if let Some(tech) = surface.get("tech").and_then(|v| v.as_array()) {
            if !tech.is_empty() {
                s.push_str("\n### Technology fingerprint\n\n");
                for t in tech {
                    let _ = writeln!(
                        s,
                        "- {} ({}, {})",
                        t.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                        t.get("category").and_then(|v| v.as_str()).unwrap_or(""),
                        t.get("confidence").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
        if let Some(tp) = surface.get("third_party_hosts").and_then(|v| v.as_array()) {
            if !tp.is_empty() {
                let list: Vec<String> = tp.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                let _ = writeln!(s, "\n- Third-party hosts ({}): {}", list.len(), list.join(", "));
            }
        }
        s.push('\n');
    }

    // Pages
    if let Some(pages) = g(&["stages", "pages"]) {
        s.push_str("## 2. Pages (crawled)\n\n");
        let _ = writeln!(
            s,
            "{} pages · capped={}",
            pages.get("count").and_then(|v| v.as_i64()).unwrap_or(0),
            pages.get("capped").and_then(|v| v.as_bool()).unwrap_or(false)
        );
        s.push('\n');
        if let Some(list) = pages.get("pages").and_then(|v| v.as_array()) {
            let _ = writeln!(s, "| # | status | bytes | depth | title | url |");
            let _ = writeln!(s, "|---|--------|-------|-------|-------|-----|");
            for (i, p) in list.iter().enumerate() {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | {} | `{}` |",
                    i + 1,
                    p.get("status").and_then(|v| v.as_u64()).unwrap_or(0),
                    p.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                    p.get("depth").and_then(|v| v.as_u64()).unwrap_or(0),
                    p.get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .replace('|', "\\|")
                        .chars()
                        .take(60)
                        .collect::<String>(),
                    p.get("url").and_then(|v| v.as_str()).unwrap_or("")
                );
            }
        }
        s.push('\n');
    }

    // Assets
    if let Some(assets) = g(&["stages", "assets"]) {
        s.push_str("## 3. Assets & endpoints\n\n");
        if let Some(inv) = assets.get("inventory") {
            let _ = writeln!(
                s,
                "- Unique assets: {}",
                inv.get("unique").and_then(|v| v.as_i64()).unwrap_or(0)
            );
            if let Some(kinds) = inv.get("by_kind").and_then(|v| v.as_object()) {
                for (k, v) in kinds {
                    let _ = writeln!(s, "  - {}: {}", k, v);
                }
            }
            if let Some(hosts) = inv.get("external_hosts").and_then(|v| v.as_array()) {
                if !hosts.is_empty() {
                    let list: Vec<String> = hosts.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    let _ = writeln!(s, "- External asset hosts: {}", list.join(", "));
                }
            }
            if let Some(docs) = inv.get("documents").and_then(|v| v.as_array()) {
                if !docs.is_empty() {
                    let list: Vec<String> = docs.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    let _ = writeln!(s, "- Document links: {}", list.join(", "));
                }
            }
        }
        let jsf = assets.get("js").and_then(|v| v.get("fetched")).and_then(|v| v.as_i64()).unwrap_or(0);
        let cssf = assets.get("css").and_then(|v| v.get("fetched")).and_then(|v| v.as_i64()).unwrap_or(0);
        let _ = writeln!(s, "- JS sources mined: {jsf} · CSS sheets mined: {cssf}");
        if let Some(eps) = assets.get("endpoints").and_then(|v| v.as_array()) {
            if !eps.is_empty() {
                s.push_str("\n### Discovered endpoints\n\n");
                let _ = writeln!(s, "| kind | value | source |");
                let _ = writeln!(s, "|------|-------|--------|");
                for e in eps.iter().take(80) {
                    let _ = writeln!(
                        s,
                        "| {} | `{}` | `{}` |",
                        e.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
                        e.get("value").and_then(|v| v.as_str()).unwrap_or("").replace('|', "\\|"),
                        e.get("source").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
        if let Some(sm) = assets.get("sourcemaps").and_then(|v| v.as_array()) {
            if !sm.is_empty() {
                let list: Vec<String> = sm.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                let _ = writeln!(s, "\n- Sourcemaps referenced: {}", list.join(", "));
            }
        }
        s.push('\n');
    }

    // Infra
    if let Some(infra) = g(&["stages", "infra"]) {
        s.push_str("## 4. Infrastructure\n\n");
        if let Some(dns) = infra.get("dns").and_then(|v| v.as_object()) {
            s.push_str("### DNS records\n\n");
            for (rtype, rows) in dns {
                if let Some(arr) = rows.as_array() {
                    if arr.is_empty() {
                        let _ = writeln!(s, "- **{}**: (none)", rtype);
                    }
                    for row in arr.iter().take(12) {
                        let _ = writeln!(
                            s,
                            "- **{}**: `{}`",
                            rtype,
                            row.get("data").and_then(|v| v.as_str()).unwrap_or("")
                        );
                    }
                }
            }
        }
        if let Some(subs) = infra.get("subdomains") {
            if let Some(err) = subs.get("error").and_then(|v| v.as_str()) {
                let _ = writeln!(s, "\n### Subdomains (CT logs)\n\n- unavailable — {err}");
            } else {
            let count = subs.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            let wildcard = subs.get("wildcard_count").and_then(|v| v.as_i64()).unwrap_or(0);
            let source = subs
                .get("source")
                .and_then(|v| v.as_str())
                .map(|v| format!(" · source: {v}"))
                .unwrap_or_default();
            let _ = writeln!(s, "\n### Subdomains (CT logs)\n\n- {} discovered · {} wildcard entries{}", count, wildcard, source);
            if let Some(items) = subs.get("items").and_then(|v| v.as_array()) {
                for it in items.iter().take(60) {
                    if let Some(name) = it.as_str() {
                        let _ = writeln!(s, "  - `{name}`");
                    }
                }
            }
            }
        }
        if let Some(certs) = infra.get("certs") {
            s.push_str("\n### Certificates (CT summary)\n\n");
            let _ = writeln!(s, "- Cert rows observed: {}", certs.get("cert_rows").and_then(|v| v.as_i64()).unwrap_or(0));
            let _ = writeln!(s, "- Earliest notBefore: {}", certs.get("earliest_not_before").cloned().unwrap_or(J::Null));
            let _ = writeln!(s, "- Latest notAfter: {} ({} days)", certs.get("latest_not_after").cloned().unwrap_or(J::Null), certs.get("latest_not_after_days").cloned().unwrap_or(J::Null));
            if let Some(issuers) = certs.get("issuers").and_then(|v| v.as_object()) {
                for (iss, n) in issuers {
                    let _ = writeln!(s, "  - issuer `{iss}`: {n}");
                }
            }
        }
        if let Some(rdap) = infra.get("rdap_domain") {
            s.push_str("\n### Registration (RDAP)\n\n");
            let _ = writeln!(s, "- Registrar: {}", rdap.get("registrar").cloned().unwrap_or(J::Null));
            if let Some(ev) = rdap.get("events").and_then(|v| v.as_object()) {
                for (k, v) in ev {
                    let _ = writeln!(s, "- {}: {}", k, v);
                }
            }
            if let Some(ns) = rdap.get("nameservers").and_then(|v| v.as_array()) {
                let list: Vec<String> = ns.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                let _ = writeln!(s, "- Nameservers: {}", list.join(", "));
            }
        }
        if let Some(nets) = infra.get("netblocks").and_then(|v| v.as_array()) {
            if !nets.is_empty() {
                s.push_str("\n### Netblocks (RDAP)\n\n");
                for n in nets {
                    let _ = writeln!(
                        s,
                        "- `{}` — {} ({})",
                        n.get("handle").and_then(|v| v.as_str()).unwrap_or("?"),
                        n.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                        n.get("range").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
        }
        s.push('\n');
    }

    // Network
    if let Some(net) = g(&["stages", "network"]) {
        s.push_str("## 5. Network (authorized-scope port scan)\n\n");
        let skipped = net.get("skipped").and_then(|v| v.as_bool()).unwrap_or(false);
        if skipped {
            let _ = writeln!(
                s,
                "⚠️ Skipped: {}",
                net.get("reason").and_then(|v| v.as_str()).unwrap_or("authorized_cidr missing")
            );
        } else {
            let _ = writeln!(
                s,
                "- Authorized scope: `{}` · targets scanned: {}",
                net.get("authorized_cidr").and_then(|v| v.as_str()).unwrap_or(""),
                net.get("targets_scanned").and_then(|v| v.as_i64()).unwrap_or(0)
            );
            if let Some(open) = net.get("open").and_then(|v| v.as_array()) {
                let _ = writeln!(s, "\n### Open ports\n");
                if open.is_empty() {
                    let _ = writeln!(s, "(none open)");
                }
                let _ = writeln!(s, "| ip | port | service |");
                let _ = writeln!(s, "|----|------|---------|");
                for row in open {
                    let _ = writeln!(
                        s,
                        "| `{}` | {} | {} |",
                        row.get("ip").and_then(|v| v.as_str()).unwrap_or(""),
                        row.get("port").and_then(|v| v.as_i64()).unwrap_or(0),
                        row.get("service").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
            if let Some(refused) = net.get("refused").and_then(|v| v.as_array()) {
                if !refused.is_empty() {
                    let list: Vec<String> = refused.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    let _ = writeln!(s, "\n- Refused/skipped targets: {}", list.join("; "));
                }
            }
        }
        s.push('\n');
    }

    // Errors + limits
    if let Some(errors) = g(&["errors"]).and_then(|v| v.as_array()) {
        if !errors.is_empty() {
            s.push_str("## Errors & notes\n\n");
            for e in errors {
                let _ = writeln!(s, "- {}", e.as_str().unwrap_or(""));
            }
            s.push('\n');
        }
    }
    if let Some(limits) = g(&["limits"]) {
        s.push_str("## Scope, depth & limits (as run)\n\n");
        for (k, v) in limits.as_object().into_iter().flatten() {
            if k == "notes" {
                continue;
            }
            let _ = writeln!(s, "- {}: {}", k, v);
        }
        if let Some(notes) = limits.get("notes").and_then(|v| v.as_array()) {
            for n in notes {
                let _ = writeln!(s, "- note: {}", n.as_str().unwrap_or(""));
            }
        }
        s.push('\n');
    }

    let _ = writeln!(
        s,
        "---\n*Generated by `tallow.sitescan` {} · read-only · public-data · Tor-first (see module docs for the depth ladder).*",
        &env.get("version").and_then(|v| v.as_str()).unwrap_or(VERSION)
    );
    s
}

/// `sitescan.depth_info() -> String` (JSON).
fn depth_info() -> StdlibResult {
    Ok(Value::String(
        json!({
            "module": "sitescan",
            "version": VERSION,
            "levels": [
                {"level": 1, "label": "surface", "includes": ["reachability", "headers", "security headers", "cookies", "robots.txt", "sitemap.xml", "homepage structure", "tech fingerprint", "third-party hosts"]},
                {"level": 2, "label": "pages", "includes": ["bounded same-site crawl", "page inventory with status/title/size/depth"]},
                {"level": 3, "label": "assets", "includes": ["asset inventory", "CSS refs and @imports", "JS fetch + endpoint mining", "sourcemap references", "document links"]},
                {"level": 4, "label": "infra", "includes": ["DNS 8 record types via DoH", "CT-log subdomains", "certificate summary", "RDAP registrar + netblocks", "optional DNS brute (opts.brute)", "optional Wayback (opts.wayback)"]},
                {"level": 5, "label": "network", "includes": ["TCP connect port scan", "REQUIRES opts.authorized_cidr", "per-IP containment gate before any connect"]}
            ],
            "opts": ["max_pages", "link_depth", "max_js", "max_css", "include_subdomains", "brute", "wayback", "only", "ports", "authorized_cidr", "port_timeout_ms"],
            "caps": {"max_pages": HARD_MAX_PAGES, "link_depth": HARD_LINK_DEPTH, "max_js": HARD_MAX_JS, "max_css": HARD_MAX_CSS, "ports": HARD_MAX_PORTS}
        })
        .to_string(),
    ))
}

/// `sitescan.probe_egress() -> String` — Tor egress proof.
fn probe_egress() -> StdlibResult {
    let body = gov_json_get(TOR_CHECK_ENDPOINT, "application/json")?;
    let parsed: J =
        serde_json::from_str(&body).map_err(|e| format!("sitescan:shape: tor check JSON: {e}"))?;
    let ip = parsed
        .get("IP")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let is_tor = parsed
        .get("IsTor")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(Value::String(
        json!({
            "ip": ip,
            "is_tor": is_tor,
            "checked_at": Utc::now().to_rfc3339(),
            "source": TOR_CHECK_ENDPOINT,
            "pacing_rps": gov_rps(),
        })
        .to_string(),
    ))
}

/// Dispatch entry point for the `sitescan` namespace.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "scan" => Some(scan(args)),
        "report" => Some(report(args)),
        "depth_info" => Some(depth_info()),
        "probe_egress" => Some(probe_egress()),
        "version" => Some(Ok(Value::String(VERSION.to_string()))),
        _ => None,
    }
}

// =====================================================================
// Tests (offline; FETCH_OVERRIDE seam)
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that install/remove FETCH_OVERRIDE.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn ok_resp(status: u16, body: &str, ct: &str, url: &str) -> HttpResp {
        HttpResp {
            status,
            body: body.to_string(),
            len: body.len(),
            headers: vec![("content-type".to_string(), ct.to_string())],
            final_url: url.to_string(),
        }
    }

    fn fixture_fetch(url: &str, _headers: &[(String, String)]) -> Result<HttpResp, String> {
        let base = "https://x.test";
        if url == format!("{base}/robots.txt") {
            return Ok(ok_resp(
                200,
                "User-agent: *\nDisallow: /private\nSitemap: https://x.test/sitemap.xml\n",
                "text/plain",
                url,
            ));
        }
        if url == format!("{base}/sitemap.xml") {
            return Ok(ok_resp(
                200,
                r#"<?xml version="1.0"?><urlset><url><loc>https://x.test/</loc></url><url><loc>https://x.test/about</loc></url></urlset>"#,
                "application/xml",
                url,
            ));
        }
        if url == format!("{base}/") {
            return Ok(ok_resp(
                200,
                r#"<!doctype html><html lang="en"><head><title>X Test Site</title>
                <meta name="description" content="fixture">
                <link rel="stylesheet" href="/s.css">
                <script src="/app.js"></script>
                <script>var API="/api/v2/things";</script></head>
                <body><a href="/about">About</a><a href="https://ext.example/">Ext</a>
                <a href="mailto:hi@x.test">mail</a>
                <form action="/search" method="post"><input name="q" type="text"></form>
                <img src="/img/logo.png">
                </body></html>"#,
                "text/html",
                &format!("{base}/"),
            ));
        }
        if url == format!("{base}/about") {
            return Ok(ok_resp(
                200,
                "<html><head><title>About</title></head><body><a href=\"/\">Home</a></body></html>",
                "text/html",
                url,
            ));
        }
        if url == format!("{base}/app.js") {
            return Ok(ok_resp(
                200,
                r#"const u="https://api.x.test/v1/items";fetch("/api/v2/orders");new WebSocket("wss://x.test/ws");var s="sourceMappingURL=app.js.map";"#,
                "application/javascript",
                url,
            ));
        }
        if url == format!("{base}/s.css") {
            return Ok(ok_resp(
                200,
                "body{background:url('/img/bg.png')} @font-face{src:url('/fonts/a.woff2')}",
                "text/css",
                url,
            ));
        }
        Ok(ok_resp(404, "not found", "text/plain", url))
    }

    #[test]
    fn depth_parsing() {
        assert_eq!(depth_of(None).unwrap(), (1, "surface"));
        assert_eq!(depth_of(Some(&Value::Int(4))).unwrap(), (4, "infra"));
        assert_eq!(
            depth_of(Some(&Value::String("full".into()))).unwrap(),
            (5, "network")
        );
        assert_eq!(
            depth_of(Some(&Value::String("assets".into()))).unwrap(),
            (3, "assets")
        );
        assert!(depth_of(Some(&Value::Int(9))).is_err());
        assert!(depth_of(Some(&Value::String("nope".into()))).is_err());
    }

    #[test]
    fn url_normalize_and_helpers() {
        let u = normalize_target("x.test").unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), Some("x.test"));
        let u2 = normalize_target("http://x.test/a/b?q=1#frag").unwrap();
        let k = key_of(&u2);
        assert!(!k.contains("#frag"));
        assert!(normalize_target("ftp://x.test").is_err());
        assert!(normalize_target("").is_err());

        let base = url::Url::parse("https://x.test/dir/page").unwrap();
        assert_eq!(
            abs_url(&base, "/a").unwrap().as_str(),
            "https://x.test/a"
        );
        assert_eq!(
            abs_url(&base, "b").unwrap().as_str(),
            "https://x.test/dir/b"
        );
        assert!(abs_url(&base, "mailto:x@y.z").is_none());
        assert!(abs_url(&base, "#frag").is_none());

        assert!(same_site("x.test", "x.test", false));
        assert!(same_site("www.x.test", "x.test", false));
        assert!(!same_site("api.x.test", "x.test", false));
        assert!(same_site("api.x.test", "x.test", true));
        assert!(!same_site("other.test", "x.test", true));
    }

    #[test]
    fn robots_parsing() {
        let r = parse_robots(
            "# comment\nUser-agent: *\nDisallow: /a\nDisallow: /b\nAllow: /a/ok\nSitemap: https://x.test/sitemap.xml\nCrawl-delay: 1.5\n",
        );
        assert_eq!(r.disallow.len(), 2);
        assert_eq!(r.allow.len(), 1);
        assert_eq!(r.sitemaps.len(), 1);
        assert_eq!(r.crawl_delay_s, Some(1.5));
        assert!(robots_allows(&r, "/other"));
        assert!(!robots_allows(&r, "/a/secret"));
        assert!(robots_allows(&r, "/a/ok/page")); // longer Allow wins
    }

    #[test]
    fn sitemap_parsing() {
        let urlset = parse_sitemap(
            r#"<urlset><url><loc>https://x.test/a</loc></url><url><loc>https://x.test/b</loc></url></urlset>"#,
        );
        assert!(!urlset.is_index);
        assert_eq!(urlset.urls.len(), 2);
        let index = parse_sitemap(
            r#"<sitemapindex><sitemap><loc>https://x.test/s1.xml</loc></sitemap></sitemapindex>"#,
        );
        assert!(index.is_index);
        assert_eq!(index.children.len(), 1);
    }

    #[test]
    fn page_facts_extraction() {
        let html = r#"<!doctype html><html lang="en"><head><title>T</title>
            <meta name="description" content="D"><meta name="generator" content="G">
            <link rel="stylesheet" href="/s.css"><script src="/a.js"></script>
            <script>var x=1;</script></head>
            <body><a href="/in">i</a><a href="https://out.example/">o</a><a href="mailto:a@b.c">m</a>
            <form action="/f" method="post"><input name="q" type="text"><select name="s"></select></form>
            <img src="/img.png"><iframe src="https://frame.example/"></iframe></body></html>"#;
        let base = url::Url::parse("https://x.test/").unwrap();
        let f = parse_page_facts(html, &base);
        assert_eq!(f.title, "T");
        assert_eq!(f.meta_description, "D");
        assert_eq!(f.meta_generator, "G");
        assert_eq!(f.lang, "en");
        assert_eq!(f.links.len(), 2);
        assert_eq!(f.mailto_count, 1);
        assert_eq!(f.forms.len(), 1);
        assert_eq!(f.forms[0].method, "post");
        assert_eq!(f.forms[0].inputs.len(), 2);
        assert!(f.script_srcs.contains(&"https://x.test/a.js".to_string()));
        assert!(f.stylesheets.contains(&"https://x.test/s.css".to_string()));
        assert!(!f.inline_js.is_empty());
        assert!(f.iframes.contains(&"https://frame.example/".to_string()));
        assert!(f.assets.iter().any(|a| a.kind == "image"));
    }

    #[test]
    fn js_and_css_mining() {
        let js = r#"fetch("/api/v2/x"); axios.get("https://api.y.test/z"); new WebSocket("wss://x.test/ws");
            var k="https://cdn.example/lib.js"; //# sourceMappingURL=app.map"#;
        let found = mine_js_endpoints(js);
        assert!(found.iter().any(|(k, v)| k == "call" && v == "/api/v2/x"));
        assert!(found.iter().any(|(k, v)| k == "url" && v.contains("api.y.test")));
        assert!(found.iter().any(|(k, _)| k == "ws"));
        assert!(found.iter().any(|(k, v)| k == "sourcemap" && v == "app.map"));

        let (urls, imports) = mine_css_refs(
            "a{background:url('/img/x.png')} @import \"other.css\"; @font-face{src:url(c.woff2)}",
        );
        assert!(urls.contains(&"/img/x.png".to_string()));
        assert!(urls.contains(&"c.woff2".to_string()));
        assert!(imports.contains(&"other.css".to_string()));
    }

    #[test]
    fn cidr_math() {
        let ip = parse_ipv4("203.0.113.1").unwrap();
        let base = parse_ipv4("203.0.113.1").unwrap();
        assert!(ipv4_in_cidr(ip, base, 32));
        // This read `204.168.219.0`, which made the assertion ARITHMETICALLY FALSE — a
        // different /24 can never contain 203.0.113.1 — so the suite could only ever be red.
        // The implementation was right and the fixture was wrong (203.0.113.0/24 is
        // TEST-NET-3, the documentation range: clearly the intent). Corrected to the network
        // that actually covers the address, and the boundary below is what makes the test
        // discriminate instead of merely agreeing.
        let net = parse_ipv4("203.0.113.0").unwrap();
        assert!(ipv4_in_cidr(ip, net, 24));
        assert!(!ipv4_in_cidr(ip, parse_ipv4("203.0.114.0").unwrap(), 24));
        assert!(!ipv4_in_cidr(ip, parse_ipv4("10.0.0.0").unwrap(), 8));
        assert!(ipv4_in_cidr(ip, 0, 0));
    }

    #[test]
    fn value_json_conversion() {
        let v = Value::Struct {
            name: "T".to_string(),
            fields: vec![
                ("a".to_string(), Value::Int(5)),
                ("b".to_string(), Value::Array(vec![Value::Bool(true)])),
                ("c".to_string(), Value::Private(Box::new(Value::String("x".into())))),
            ],
        };
        let j = value_to_json(&v);
        assert_eq!(j["_type"], "T");
        assert_eq!(j["a"], 5);
        assert_eq!(j["b"][0], true);
        assert_eq!(j["c"], "«private»");
    }

    #[test]
    fn scan_pipeline_offline() {
        let _guard = TEST_LOCK.lock().unwrap();
        *FETCH_OVERRIDE.lock().unwrap() = Some(fixture_fetch);
        let opts = r#"{"max_pages": 10, "max_js": 5, "max_css": 5}"#;
        let out = scan(vec![
            Value::String("https://x.test/".to_string()),
            Value::Int(3),
            Value::String(opts.to_string()),
        ])
        .expect("scan should return an envelope");
        let env: J = match out {
            Value::String(s) => serde_json::from_str(&s).unwrap(),
            other => panic!("unexpected value {other:?}"),
        };
        *FETCH_OVERRIDE.lock().unwrap() = None;

        assert_eq!(env["ok"], true);
        assert_eq!(env["depth"]["level"], 3);
        assert_eq!(env["stages"]["pages"]["count"], 2);
        assert_eq!(
            env["stages"]["surface"]["robots"]["present"], true,
            "robots parsed"
        );
        assert_eq!(env["stages"]["surface"]["sitemap"]["url_count"], 2);
        let endpoints = env["stages"]["assets"]["endpoints"].as_array().unwrap();
        assert!(
            endpoints.iter().any(|e| e["value"] == "/api/v2/orders"),
            "fetch endpoint mined: {endpoints:?}"
        );
        assert!(
            endpoints.iter().any(|e| e["kind"] == "ws"),
            "ws endpoint mined"
        );
        // Report renders.
        let md = render_report(&env);
        assert!(md.contains("## 1. Surface"));
        assert!(md.contains("## 3. Assets & endpoints"));
        assert!(md.contains("X Test Site"));
    }
}
