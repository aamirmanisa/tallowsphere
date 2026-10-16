//! Standard library: `tallow.http` -- HTTP client/server.

use super::StdlibResult;
use crate::interp::Value;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Global storage for active TcpListeners keyed by port.
static HTTP_LISTENERS: LazyLock<Mutex<HashMap<u16, TcpListener>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Global storage for active TcpStreams keyed by stream_id.
static HTTP_STREAMS: LazyLock<Mutex<HashMap<u64, std::net::TcpStream>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Counter for stream IDs.
static STREAM_ID_COUNTER: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

/// Dispatch a `tallow.http.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "get" => Some(http_get(args)),
        "post" => Some(http_post(args)),
        "put" => Some(http_request("PUT", args)),
        "delete" => Some(http_request("DELETE", args)),
        "batch" => Some(http_batch(args)),
        "listen" => Some(http_listen(args)),
        // Client/Server constructors still fall through to interp.rs inline
        "Client" | "Server" => None,
        "server" => Some(http_listen(args)),
        _ => None,
    }
}

/// Dispatch a method call on an HTTP object.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, .. } = object {
        match name.as_str() {
            "HttpListener" => Some(listener_method(object, method, args)),
            "Response" => Some(response_method(object, method, args)),
            _ => None,
        }
    } else {
        None
    }
}

// â”€â”€ HTTP Client â”€â”€

/// TLS fingerprint profile for the `stealth-http` (wreq/BoringSSL) path.
/// Overridable via `TALLOW_TLS_PROFILE`; defaults to Chrome 136.
#[cfg(feature = "stealth-http")]
fn stealth_profile() -> String {
    std::env::var("TALLOW_TLS_PROFILE").unwrap_or_else(|_| "chrome_136".to_string())
}

/// Resolve the egress proxy URL, returned as a raw URL string so it can feed
/// *any* HTTP client (ureq's `Proxy::new`, wreq's `.proxy(...)`, etc.) rather
/// than coupling proxy detection to one backend.
///
/// Delegates to [`crate::runtime::fetch::egress_proxy_url`] so the interpreter
/// and the compiled runtime cannot drift: **Tor by default**, `TALLOW_PROXY`
/// overrides, and `TALLOW_ALLOW_DIRECT=1` is the explicit opt-out. This used to
/// be a second, independent copy of the logic that defaulted to a direct
/// connection — i.e. an interpreter program that forgot to export `TALLOW_TOR`
/// leaked the box IP while the compiled path did not.
/// The host component of a URL, lowercased, with any port and userinfo removed.
fn url_host(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    host.to_ascii_lowercase()
}

/// True only when the host is a **literal** loopback IP (`127.0.0.0/8`, `::1`).
///
/// Deliberately narrowed to literals, because this is the predicate that also bypasses the
/// egress proxy (see `build_agent_with`): a literal cannot resolve anywhere else, whereas a
/// *name* — including `localhost` — is resolved through `/etc/hosts` or DNS, so treating one as
/// "necessarily this machine" would make the bypass a leak waiting on a poisoned resolver. An
/// IP literal is the only spelling that is loopback by construction.
fn is_loopback_literal(url: &str) -> bool {
    url_host(url)
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// True for a literal loopback IP or a loopback *name* (`localhost`, `*.localhost`).
///
/// Used to skip the browser-impersonation plane, where a name is safe to trust: the request
/// still goes through the egress proxy in that path, so a misresolved name cannot leak. There
/// is nothing to impersonate about talking to your own machine anyway, and the stealth path
/// simply fails on loopback — the SOCKS hop answers `General SOCKS server failure`.
fn is_loopback_target(url: &str) -> bool {
    let host = url_host(url);
    is_loopback_literal(url) || host == "localhost" || host.ends_with(".localhost")
}

pub fn detect_proxy_url() -> Option<String> {
    crate::runtime::fetch::egress_proxy_url()
}

/// Refusal message for a proxy URL `ureq::Proxy::new` rejects.
///
/// The word "refusing" is load-bearing (invariant N3): it is only ever
/// produced on a path that attempts **no** request. Mirrors
/// `src/runtime/egress_http.rs::refusal_hint` so the interpreter and the
/// native runtime speak the same refusal.
fn refusal_hint(url: &str, e: impl std::fmt::Display) -> String {
    format!(
        "[egress] refusing to run unproxied — invalid proxy URL from \
         TALLOW_PROXY/TALLOW_TOR ({url:?}): {e}"
    )
}

/// Pure: map the resolved egress URL to the `ureq` proxy for it.
///
/// `None` — the explicit `TALLOW_ALLOW_DIRECT=1` opt-out — stays a direct
/// connection. A `Some(url)` is a configured proxy: the URL arrives already
/// normalized to the `socks5h://` remote-DNS spelling by
/// [`crate::runtime::fetch::egress_proxy_url_ureq`] (ureq ABORTS the process
/// on `socks5://` — a hard core dump, not a catchable error — because that
/// spelling means "resolve locally"), and it must parse. An unparseable value
/// hard-refuses via panic — never a silent degrade to a DIRECT agent, which
/// is the leak this function exists to prevent (N3; same contract as
/// `src/runtime/egress_http.rs::parse_proxy`). Pure over its input: no env
/// reads, so tests need no env mutation. On refusal one redacted security
/// event is emitted (best-effort) to the telemetry choke point
/// (`crate::observability`, R-6.1 slice 1) immediately before the panic.
fn proxy_for_url(url: Option<String>) -> Option<ureq::Proxy> {
    let url = url?;
    match ureq::Proxy::new(&url) {
        Ok(proxy) => Some(proxy),
        Err(e) => {
            let _ = crate::observability::emit_to_default_journal(
                &crate::observability::SecurityEvent {
                    class: crate::observability::EventClass::EgressRefusal,
                    actor: "stdlib.http".to_string(),
                    target: Some(url.clone()),
                    size: url.len(),
                    at_ms: crate::observability::now_ms(),
                },
            );
            panic!("{}", refusal_hint(&url, e))
        }
    }
}

/// Detect proxy from TALLOW_PROXY or TALLOW_TOR env vars (ureq backend).
///
/// # Panics
/// See [`proxy_for_url`]: a configured-but-unparseable proxy URL is a hard
/// refusal, not a silent fall-through to a direct connection.
fn detect_proxy() -> Option<ureq::Proxy> {
    proxy_for_url(crate::runtime::fetch::egress_proxy_url_ureq())
}

/// Build an agent with standard per-phase timeouts, with or without the egress proxy.
///
/// `with_proxy` exists for exactly one caller shape: a target that is loopback *by construction*
/// — an IP literal, see [`is_loopback_literal`]. Every other target keeps the proxy, because
/// silently degrading to a direct connection is the leak the egress policy exists to prevent
/// (invariant N3). A literal loopback target cannot leak: the packet never leaves the host, and
/// no name resolution stands between the URL and the socket.
fn build_agent_with(timeout: Option<Duration>, with_proxy: bool) -> ureq::Agent {
    let t = timeout.unwrap_or(Duration::from_secs(30));
    let mut builder = ureq::Agent::config_builder()
        .timeout_global(None)
        .timeout_per_call(Some(t))
        .timeout_resolve(Some(Duration::from_secs(10)))
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_send_request(Some(Duration::from_secs(10)))
        .timeout_send_body(Some(t))
        .timeout_recv_response(Some(t))
        .timeout_recv_body(Some(t))
        .https_only(false);

    if with_proxy {
        if let Some(proxy) = detect_proxy() {
            builder = builder.proxy(Some(proxy));
        }
    }
    builder.build().new_agent()
}

/// Build an agent with standard per-phase timeouts and the egress proxy.
fn build_agent(timeout: Option<Duration>) -> ureq::Agent {
    build_agent_with(timeout, true)
}

/// Shared agent for connection pooling and TLS session reuse.
static SHARED_AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| build_agent(None));

/// The same agent without a proxy, for loopback literals only.
///
/// Proxied loopback cannot work at all here: the allowlist chokepoint answers SOCKS5 reply `0x02`
/// — "connection not allowed by ruleset" — for `127.0.0.1`, which is what `http.get` against a
/// loopback fixture was reporting. It also needs no anonymity plane, because there is nothing to
/// anonymise about a request that never leaves the host.
static DIRECT_AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| build_agent_with(None, false));

fn extract_headers(args: &[Value]) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for arg in args {
        if let Value::Map(entries) = arg {
            for (k, v) in entries {
                headers.insert(k.as_string(), v.as_string());
            }
        }
    }
    headers
}

fn extract_timeout(args: &[Value]) -> Option<Duration> {
    for arg in args {
        if let Value::Int(ms) = arg {
            if *ms > 0 {
                return Some(Duration::from_millis(*ms as u64));
            }
        }
    }
    None
}

/// Build an agent with per-call timeout, reusing the shared agent when
/// no custom timeout is specified.
fn get_agent(timeout: Option<Duration>) -> ureq::Agent {
    match timeout {
        Some(t) => build_agent(Some(t)),
        None => SHARED_AGENT.clone(),
    }
}

/// Build the agent for a specific URL: a loopback literal gets the proxy-free agent, everything
/// else keeps the egress proxy.
///
/// The literal test is load-bearing. A name — `localhost` included — resolves through `/etc/hosts`
/// or DNS, so letting one bypass the proxy would be a leak waiting on a poisoned resolver. An IP
/// literal is loopback by construction and cannot resolve elsewhere, so only that spelling may take
/// the proxy-free path.
fn get_agent_for(url: &str, timeout: Option<Duration>) -> ureq::Agent {
    if is_loopback_literal(url) {
        return match timeout {
            Some(t) => build_agent_with(Some(t), false),
            None => DIRECT_AGENT.clone(),
        };
    }
    get_agent(timeout)
}

// ── Governed fetch (rate-limit / backoff / retry) ────────────────────────────

/// A minimal token-bucket governor that paces outbound calls to a fixed
/// requests-per-second budget. Shared across a process so many call sites
/// (crt.sh, Wayback, Common Crawl, HIBP, Shodan, ...) collectively honor a
/// per-provider budget. Mirrors the semantics of `tallow.rate_limit`'s token
/// bucket so the data-access layer actually enforces one.
pub struct RateGovernor {
    rate: f64,
    tokens: f64,
    max_tokens: f64,
    last_refill: Instant,
}

impl RateGovernor {
    pub fn new(calls_per_sec: f64) -> Self {
        let rate = calls_per_sec.max(0.01);
        RateGovernor {
            rate,
            tokens: rate,
            max_tokens: rate,
            last_refill: Instant::now(),
        }
    }
    /// Block until a token is available, then consume one.
    pub fn wait(&mut self) {
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.rate).min(self.max_tokens);
            self.last_refill = now;
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Default budget for keyless/free sources (2 rps) — conservative.
pub static GOV_DEFAULT: LazyLock<Mutex<RateGovernor>> =
    LazyLock::new(|| Mutex::new(RateGovernor::new(2.0)));
/// HIBP Pwned Passwords range API — free, keyless; ~1 req/5s keeps it polite.
pub static GOV_HIBP: LazyLock<Mutex<RateGovernor>> =
    LazyLock::new(|| Mutex::new(RateGovernor::new(0.2)));
/// Shodan free tier is ~1 rps / 10k credits per month.
pub static GOV_SHODAN: LazyLock<Mutex<RateGovernor>> =
    LazyLock::new(|| Mutex::new(RateGovernor::new(1.0)));

/// Exponential backoff in ms with ±25% jitter. attempt 0 → 1000ms.
fn governed_backoff_ms(attempt: u32) -> u64 {
    let base = 1000u64;
    let max = 60_000u64;
    let delay = (base * (1u64 << attempt.min(5))).min(max);
    let quarter = delay / 4;
    if quarter == 0 {
        return delay;
    }
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    delay - quarter + (seed % (quarter * 2))
}

/// A governed GET with rate limiting, exponential backoff + jitter on 429/5xx,
/// and retry of transient transport errors.
///
/// Returns `Ok((status, body, retries, rate_limited))`:
/// - `status` distinguishes 200/429/5xx distinctly (never collapsed),
/// - `rate_limited` is true only for 429 (already retried up to `max_retries`),
/// - `retries` is the number of backoff+retry cycles actually performed.
/// A persistent transport-level error past `max_retries` returns `Err`.
pub fn governed_get(
    url: &str,
    headers: &[(String, String)],
    limiter: &Mutex<RateGovernor>,
    max_retries: u32,
) -> Result<(u16, String, u32, bool), String> {
    limiter.lock().unwrap().wait();
    let mut retries = 0u32;
    loop {
        let agent = SHARED_AGENT.clone();
        let mut req = agent.get(url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        match req.call() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.into_body().read_to_string().unwrap_or_default();
                if retries < max_retries && (status == 429 || (500..=599).contains(&status)) {
                    std::thread::sleep(Duration::from_millis(governed_backoff_ms(retries)));
                    retries += 1;
                    limiter.lock().unwrap().wait();
                    continue;
                }
                return Ok((status, body, retries, status == 429));
            }
            Err(ureq::Error::StatusCode(code)) => {
                let status = code;
                if retries < max_retries && (status == 429 || (500..=599).contains(&status)) {
                    std::thread::sleep(Duration::from_millis(governed_backoff_ms(retries)));
                    retries += 1;
                    limiter.lock().unwrap().wait();
                    continue;
                }
                return Ok((status, String::new(), retries, status == 429));
            }
            Err(e) => {
                if retries < max_retries {
                    std::thread::sleep(Duration::from_millis(governed_backoff_ms(retries)));
                    retries += 1;
                    limiter.lock().unwrap().wait();
                    continue;
                }
                return Err(format!("governed_get({url}): {e}"));
            }
        }
    }
}

/// Block briefly on a governor without issuing a request (e.g. pacing a
/// non-HTTP data-source call such as port-43 WHOIS).
pub fn paced(limiter: &Mutex<RateGovernor>) {
    limiter.lock().unwrap().wait();
}

// ── HIBP Pwned Passwords k-anonymity range (cache + padding) ─────────────────

/// Local HIBP range cache: SHA-1 prefix -> {suffix -> count}. Populated on first
/// fetch for a prefix and reused across calls to cut repeat range queries.
static HIBP_RANGE_CACHE: LazyLock<Mutex<HashMap<String, HashMap<String, u64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Add decoy suffix entries to the cache so an observer of the local cache
/// cannot infer which specific hash we probed (cache side-channel hardening).
const HIBP_PADDING: bool = true;
const HIBP_PADDING_DECOYS: usize = 8;

/// Check a full uppercase SHA-1 hex hash against HIBP using the k-anonymity
/// range API. Never sends more than the first 5 hex chars. Serves from the
/// local prefix->suffix cache when the prefix is already known.
pub fn hibp_range_check(full_hash_hex: &str) -> Result<u64, String> {
    let upper = full_hash_hex.to_uppercase();
    let prefix = &upper[..5];
    let suffix = &upper[5..];

    if let Some(map) = HIBP_RANGE_CACHE.lock().unwrap().get(prefix).cloned() {
        return Ok(map.get(suffix).copied().unwrap_or(0));
    }

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let (status, body, _retries, rate_limited) =
        governed_get(&url, &[], &GOV_HIBP, 3)?;
    if rate_limited {
        return Err(format!("HIBP rate limited (429) for prefix {prefix}"));
    }
    if status != 200 {
        return Err(format!("HIBP HTTP {status} for prefix {prefix}"));
    }

    // Parse "SUFFIX:COUNT" lines into the local cache.
    let mut map: HashMap<String, u64> = HashMap::new();
    for line in body.lines() {
        let Some((s, c)) = line.split_once(':') else {
            continue;
        };
        let s = s.trim();
        if s.len() != 35 {
            continue;
        }
        if let Ok(count) = c.trim().parse::<u64>() {
            map.insert(s.to_string(), count);
        }
    }
    // Optional padding: inject decoy (suffix,count) entries so the cache's
    // contents cannot be correlated with the exact hash that was checked.
    if HIBP_PADDING {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        for i in 0..HIBP_PADDING_DECOYS {
            let decoy = format!(
                "{:035X}",
                seed.wrapping_add((i as u64).wrapping_mul(2_654_435_761))
            );
            map.entry(decoy)
                .or_insert((seed as u64 % 5000) + 1);
        }
    }
    HIBP_RANGE_CACHE
        .lock()
        .unwrap()
        .insert(prefix.to_string(), map.clone());
    Ok(map.get(suffix).copied().unwrap_or(0))
}

fn build_response_value(
    status: u16,
    body: Vec<u8>,
    url: &str,
    resp_headers: Vec<(String, String)>,
    time_ms: u64,
) -> Value {
    let header_map: Vec<(Value, Value)> = resp_headers
        .into_iter()
        .map(|(k, v)| (Value::String(k), Value::String(v)))
        .collect();
    Value::Struct {
        name: "Response".to_string(),
        fields: vec![
            ("status".to_string(), Value::Int(status as i128)),
            ("body".to_string(), Value::Bytes(body)),
            ("url".to_string(), Value::String(url.to_string())),
            ("time_ms".to_string(), Value::Int(time_ms as i128)),
            ("headers".to_string(), Value::Map(header_map)),
        ],
    }
}

fn response_body_bytes(object: &Value) -> Result<Vec<u8>, String> {
    if let Value::Struct { fields, .. } = object {
        let body = fields
            .iter()
            .find(|(name, _)| name == "body")
            .map(|(_, value)| value)
            .ok_or_else(|| "Response.text: missing body field".to_string())?;
        match body {
            Value::Bytes(bytes) => Ok(bytes.clone()),
            Value::String(text) => Ok(text.as_bytes().to_vec()),
            other => Err(format!("Response.body must be Bytes, got {other:?}")),
        }
    } else {
        Err("Response method called on non-struct".to_string())
    }
}

fn response_method(object: &Value, method: &str, _args: Vec<Value>) -> StdlibResult {
    match method {
        "text" => {
            let bytes = response_body_bytes(object)?;
            Ok(Value::String(String::from_utf8_lossy(&bytes).to_string()))
        }
        "json" => {
            let bytes = response_body_bytes(object)?;
            Ok(Value::Ok(Box::new(Value::String(
                String::from_utf8_lossy(&bytes).to_string(),
            ))))
        }
        _ => Err(format!("Response has no method '{method}'")),
    }
}

fn elapsed_ms_since(started: Instant) -> u64 {
    let elapsed_ms = started.elapsed().as_millis();
    elapsed_ms.min(u128::from(u64::MAX)) as u64
}

fn collect_response_headers(resp: &ureq::http::Response<ureq::Body>) -> Vec<(String, String)> {
    resp.headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Unified HTTP GET used by the `fetch()` builtin and the HTTP-first fast path.
///
/// Combines the two previously-split capabilities — browser-impersonated TLS
/// (wreq/BoringSSL) *and* SOCKS5 routing — into one client that honors
/// `TALLOW_PROXY`/`TALLOW_TOR`. When the `stealth-http` feature is off, it
/// falls back to the proxy-aware ureq shared agent. Returns `(status, body)`.
pub fn unified_get(
    url: &str,
    headers: &[(String, String)],
    _timeout: Option<Duration>,
) -> Result<(u16, Vec<u8>), String> {
    // Same loopback rule as `http.get`: a local fixture has nothing to impersonate and the SOCKS
    // hop refuses it outright, so it takes the direct path even when the stealth plane is on.
    #[cfg(feature = "stealth-http")]
    {
        if !is_loopback_target(url) {
            let proxy = detect_proxy_url();
            let (status, body) = super::stealth_http::get_blocking(
                &stealth_profile(),
                url,
                headers,
                proxy.as_deref(),
            )?;
            return Ok((status, body.into_bytes()));
        }
    }

    // Direct path: loopback literals under `stealth-http`, and every target when the feature is
    // off. `get_agent_for` keeps the egress proxy for anything that is not a loopback literal.
    let agent = get_agent_for(url, _timeout);
    let mut req = agent.get(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.call().map_err(|e| format!("http.get: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.into_body().read_to_vec().unwrap_or_default();
    Ok((status, body))
}

fn http_get(args: Vec<Value>) -> StdlibResult {
    let url = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "http.get requires a URL argument".to_string())?;

    let headers = extract_headers(&args[1..]);
    let timeout = extract_timeout(&args[1..]);

    #[cfg(feature = "stealth-http")]
    {
        // Loopback is excluded: see `is_loopback_target`. A fixture on 127.0.0.1 has no anonymity
        // plane to ride, and the SOCKS hop refuses it outright.
        if !is_loopback_target(&url) {
            // Browser-impersonated TLS (wreq/BoringSSL) — P1-1 anti-bot path.
            let hdrs: Vec<(String, String)> =
                headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            let started = Instant::now();
            let proxy = detect_proxy_url();
            match super::stealth_http::get_blocking(
                &stealth_profile(),
                &url,
                &hdrs,
                proxy.as_deref(),
            ) {
                Ok((status, body)) => {
                    return Ok(build_response_value(
                        status,
                        body.into_bytes(),
                        &url,
                        vec![],
                        elapsed_ms_since(started),
                    ));
                }
                Err(e) => {
                    return Ok(Value::Err(Box::new(Value::String(format!("http.get: {e}")))));
                }
            }
        }
    }

    let agent = get_agent_for(&url, timeout);

    let mut req = agent.get(&url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }

    let started = Instant::now();
    match req.call() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let resp_headers = collect_response_headers(&resp);
            let body = resp.into_body().read_to_vec().unwrap_or_default();
            Ok(build_response_value(
                status,
                body,
                &url,
                resp_headers,
                elapsed_ms_since(started),
            ))
        }
        Err(e) => Ok(Value::Err(Box::new(Value::String(format!(
            "http.get: {e}"
        ))))),
    }
}

/// http.batch(urls: [String], concurrency?: Int) -> [Response]
///
/// Fetch many URLs concurrently with a bounded worker pool. Each entry is
/// Ok(Response) or Err(message) — per-URL failures never abort the batch.
/// Closes the documented "truth gap" where .tl scripts could check-pass
/// against a declared http.batch but die at runtime.
fn http_batch(args: Vec<Value>) -> StdlibResult {
    let urls = match args.first() {
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_string())
            .collect::<Vec<String>>(),
        _ => return Err("http.batch requires a [String] URLs argument".to_string()),
    };
    let concurrency = args
        .get(1)
        .and_then(|v| if let Value::Int(n) = v { Some(*n) } else { None })
        .map(|n| n.max(1) as usize)
        .unwrap_or(8)
        .min(64);

    let fetch_one = |url: String| -> Value {
        match http_get(vec![Value::String(url.clone())]) {
            Ok(resp) => resp,
            Err(e) => Value::Err(Box::new(Value::String(format!("http.batch[{url}]: {e}")))),
        }
    };

    let results: Vec<Value> = if urls.len() <= concurrency || concurrency <= 1 {
        urls.into_iter().map(fetch_one).collect()
    } else {
        // Sequential even for large batches: http_get closes over
        // thread-local non-Send state (Rc<RefCell<_>> caches), so scoped
        // threads cannot capture it. Per-URL failures stay isolated.
        eprintln!(
            "http.batch: concurrency capped to sequential in this build (non-Send fetch state)"
        );
        urls.into_iter().map(fetch_one).collect()
    };

    Ok(Value::Array(results))
}

fn http_post(args: Vec<Value>) -> StdlibResult {
    let url = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "http.post requires a URL argument".to_string())?;

    let body = args.get(1).map(|v| v.as_string()).unwrap_or_default();
    let headers = extract_headers(&args[2..]);
    let timeout = extract_timeout(&args[2..]);

    #[cfg(feature = "stealth-http")]
    {
        // Loopback is excluded: see `is_loopback_target`.
        if !is_loopback_target(&url) {
            // Browser-impersonated TLS (wreq/BoringSSL) — P1-1 anti-bot path.
            let hdrs: Vec<(String, String)> =
                headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            let started = Instant::now();
            let proxy = detect_proxy_url();
            match super::stealth_http::post_blocking(
                &stealth_profile(),
                &url,
                &hdrs,
                body.as_bytes(),
                proxy.as_deref(),
            ) {
                Ok((status, resp_body)) => {
                    return Ok(build_response_value(
                        status,
                        resp_body.into_bytes(),
                        &url,
                        vec![],
                        elapsed_ms_since(started),
                    ));
                }
                Err(e) => {
                    return Ok(Value::Err(Box::new(Value::String(format!("http.post: {e}")))));
                }
            }
        }
    }

    let agent = get_agent_for(&url, timeout);

    let mut req = agent.post(&url);
    let mut has_ct = false;
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
        if k.eq_ignore_ascii_case("content-type") {
            has_ct = true;
        }
    }
    if !has_ct {
        req = req.header("Content-Type", "text/plain");
    }

    let started = Instant::now();
    match req.send(body.as_bytes()) {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let resp_headers = collect_response_headers(&resp);
            let resp_body = resp.into_body().read_to_vec().unwrap_or_default();
            Ok(build_response_value(
                status,
                resp_body,
                &url,
                resp_headers,
                elapsed_ms_since(started),
            ))
        }
        Err(e) => Ok(Value::Err(Box::new(Value::String(format!(
            "http.post: {e}"
        ))))),
    }
}

fn http_request(method: &str, args: Vec<Value>) -> StdlibResult {
    let url = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| format!("http.{} requires a URL argument", method.to_lowercase()))?;

    let body = args.get(1).map(|v| v.as_string()).unwrap_or_default();
    let headers = extract_headers(&args[2..]);
    let timeout = extract_timeout(&args[2..]);
    let agent = get_agent_for(&url, timeout);

    let method_lower = method.to_lowercase();
    let started = Instant::now();

    // ureq 3.x has typed builders: WithBody vs WithoutBody.
    // PUT has body, DELETE doesn't. Handle separately.
    let result: Result<ureq::http::Response<ureq::Body>, ureq::Error> = match method {
        "PUT" => {
            let mut req = agent.put(&url);
            for (k, v) in &headers {
                req = req.header(k.as_str(), v.as_str());
            }
            if body.is_empty() {
                req.send(&[] as &[u8])
            } else {
                req.send(body.as_bytes())
            }
        }
        _ => {
            // DELETE and others are WithoutBody
            let mut req = agent.delete(&url);
            for (k, v) in &headers {
                req = req.header(k.as_str(), v.as_str());
            }
            req.call()
        }
    };

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let resp_headers = collect_response_headers(&resp);
            let resp_body = resp.into_body().read_to_vec().unwrap_or_default();
            Ok(build_response_value(
                status,
                resp_body,
                &url,
                resp_headers,
                elapsed_ms_since(started),
            ))
        }
        Err(e) => Ok(Value::Err(Box::new(Value::String(format!(
            "http.{method_lower}: {e}"
        ))))),
    }
}

// â”€â”€ HTTP Server â”€â”€

fn http_listen(args: Vec<Value>) -> StdlibResult {
    let port = args
        .first()
        .and_then(|v| match v {
            Value::Int(n) => Some(*n as u16),
            _ => None,
        })
        .unwrap_or(8080);

    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).map_err(|e| format!("http.listen: {e}"))?;

    let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let actual_addr = format!("127.0.0.1:{actual_port}");

    let mut listeners = HTTP_LISTENERS.lock().unwrap();
    listeners.insert(actual_port, listener);

    Ok(Value::Struct {
        name: "HttpListener".to_string(),
        fields: vec![
            ("port".to_string(), Value::Int(actual_port as i128)),
            ("address".to_string(), Value::String(actual_addr)),
        ],
    })
}

fn listener_method(object: &Value, method: &str, args: Vec<Value>) -> StdlibResult {
    let port = if let Value::Struct { fields, .. } = object {
        fields
            .iter()
            .find(|(n, _)| n == "port")
            .and_then(|(_, v)| match v {
                Value::Int(n) => Some(*n as u16),
                _ => None,
            })
            .ok_or_else(|| "HttpListener: missing port field".to_string())?
    } else {
        return Err("HttpListener method called on non-struct".to_string());
    };

    match method {
        "accept" => listener_accept(port),
        "close" => listener_close(port),
        "respond" => {
            let request = args.first().ok_or("respond requires a request argument")?;
            let status = args
                .get(1)
                .and_then(|v| match v {
                    Value::Int(n) => Some(*n as u16),
                    _ => None,
                })
                .unwrap_or(200);
            let body = args.get(2).map(|v| v.as_string()).unwrap_or_default();

            let stream_id = if let Value::Struct { fields, .. } = request {
                fields
                    .iter()
                    .find(|(n, _)| n == "_stream_id")
                    .and_then(|(_, v)| match v {
                        Value::Int(n) => Some(*n as u64),
                        _ => None,
                    })
                    .ok_or_else(|| "respond: request missing _stream_id".to_string())?
            } else {
                return Err("respond: first argument must be an HttpRequest".to_string());
            };

            stream_respond(stream_id, status, &body)
        }
        _ => Err(format!("HttpListener has no method '{method}'")),
    }
}

fn listener_accept(port: u16) -> StdlibResult {
    let listeners = HTTP_LISTENERS.lock().unwrap();
    let listener = listeners
        .get(&port)
        .ok_or_else(|| format!("HttpListener on port {port} not found"))?;

    let (stream, _addr) = listener.accept().map_err(|e| format!("http accept: {e}"))?;

    // Clone stream for reading -- the original will be stored for responding
    let read_stream = stream
        .try_clone()
        .map_err(|e| format!("http stream clone: {e}"))?;

    let mut reader = BufReader::new(read_stream);
    let mut first_line = String::new();
    reader
        .read_line(&mut first_line)
        .map_err(|e| format!("http read: {e}"))?;

    let parts: Vec<&str> = first_line.trim().splitn(3, ' ').collect();
    let method = parts.first().unwrap_or(&"GET").to_string();
    let path = parts.get(1).unwrap_or(&"/").to_string();

    // Read headers
    let mut headers = Vec::new();
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("http read headers: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((Value::String(key), Value::String(value)));
        }
    }

    // Read body if content-length > 0
    let body = if content_length > 0 {
        let mut body_buf = vec![0u8; content_length];
        reader
            .read_exact(&mut body_buf)
            .map_err(|e| format!("http read body: {e}"))?;
        String::from_utf8_lossy(&body_buf).to_string()
    } else {
        String::new()
    };

    // Store the stream for later respond()
    let stream_id = {
        let mut counter = STREAM_ID_COUNTER.lock().unwrap();
        *counter += 1;
        *counter
    };

    {
        let mut streams = HTTP_STREAMS.lock().unwrap();
        streams.insert(stream_id, stream);
    }

    Ok(Value::Struct {
        name: "HttpRequest".to_string(),
        fields: vec![
            ("method".to_string(), Value::String(method)),
            ("path".to_string(), Value::String(path)),
            ("headers".to_string(), Value::Map(headers)),
            ("body".to_string(), Value::String(body)),
            ("_stream_id".to_string(), Value::Int(stream_id as i128)),
        ],
    })
}

fn stream_respond(stream_id: u64, status: u16, body: &str) -> StdlibResult {
    let mut streams = HTTP_STREAMS.lock().unwrap();
    let stream = streams
        .remove(&stream_id)
        .ok_or_else(|| format!("respond: stream {stream_id} not found (already responded?)"))?;

    let status_text = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };

    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    let mut writer = stream;
    writer
        .write_all(response.as_bytes())
        .map_err(|e| format!("respond write: {e}"))?;
    writer.flush().map_err(|e| format!("respond flush: {e}"))?;

    Ok(Value::Nil)
}

fn listener_close(port: u16) -> StdlibResult {
    let mut listeners = HTTP_LISTENERS.lock().unwrap();
    listeners.remove(&port);
    Ok(Value::Nil)
}

/// POST a JSON body to `url` and return the response body, or an error string.
///
/// Used by `OtelExporter.export()` (OTLP format) to send spans/metrics to a
/// configured collector endpoint.  Deliberately separate from the interpreter's
/// main fetch path so it can be called from `call_otel_sentinel` without
/// needing access to the `Interpreter` instance.
pub fn post_json_blocking(url: &str, body: &str) -> Result<String, String> {
    let agent = SHARED_AGENT.clone();
    match agent
        .post(url)
        .header("Content-Type", "application/json")
        .send(body.as_bytes())
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.into_body().read_to_string().unwrap_or_default();
            if (200..300).contains(&status) {
                Ok(text)
            } else {
                Err(format!("HTTP {}: {}", status, text))
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_value_includes_declared_time_ms_field() {
        let response = build_response_value(
            200,
            b"ok".to_vec(),
            "https://example.test",
            vec![("content-type".to_string(), "text/plain".to_string())],
            7,
        );

        match response {
            Value::Struct { name, fields } => {
                assert_eq!(name, "Response");
                let time_ms = fields
                    .iter()
                    .find(|(field, _)| field == "time_ms")
                    .map(|(_, value)| value);
                assert!(
                    time_ms.is_some(),
                    "Response must include declared time_ms field"
                );
                assert!(
                    matches!(time_ms.unwrap(), Value::Int(ms) if *ms == 7),
                    "time_ms should preserve elapsed milliseconds as an integer"
                );
            }
            other => panic!("expected Response struct, got {other:?}"),
        }
    }

    #[test]
    fn response_value_uses_declared_bytes_body_and_text_methods() {
        let response = build_response_value(
            200,
            b"{\"ok\":true}".to_vec(),
            "https://example.test/data",
            vec![],
            3,
        );

        match &response {
            Value::Struct { name, fields } => {
                assert_eq!(name, "Response");
                let body = fields
                    .iter()
                    .find(|(field, _)| field == "body")
                    .map(|(_, value)| value)
                    .expect("Response must include body");
                assert!(
                    matches!(body, Value::Bytes(bytes) if bytes == b"{\"ok\":true}"),
                    "Response.body must match stdlib/http.tl Bytes declaration"
                );
            }
            other => panic!("expected Response struct, got {other:?}"),
        }

        let text = crate::stdlib::dispatch_method(&response, "text", vec![])
            .expect("Response.text should dispatch through top-level stdlib router")
            .expect("Response.text should decode UTF-8 bytes");
        assert!(matches!(text, Value::String(ref s) if s == "{\"ok\":true}"));

        let json = crate::stdlib::dispatch_method(&response, "json", vec![])
            .expect("Response.json should dispatch through top-level stdlib router")
            .expect("Response.json should return a Result-like value");
        assert!(
            matches!(json, Value::Ok(inner) if matches!(*inner, Value::String(ref s) if s == "{\"ok\":true}"))
        );
    }

    // ── audit-07 F-2: malformed proxy hard-refuses, never silent DIRECT ────
    // `proxy_for_url` is pure (no env reads), so these need no ENV-lock and
    // no env mutation — robust against parallel-test env races.

    /// `None` means the explicit `TALLOW_ALLOW_DIRECT=1` opt-out: a direct
    /// connection with no refusal — behavior unchanged.
    #[test]
    fn proxy_for_url_none_stays_direct() {
        assert!(proxy_for_url(None).is_none());
    }

    /// A valid configured proxy still resolves to a usable `ureq::Proxy`.
    #[test]
    fn proxy_for_url_accepts_valid_proxy() {
        assert!(proxy_for_url(Some("socks5h://127.0.0.1:9050".to_string())).is_some());
        assert!(proxy_for_url(Some("http://127.0.0.1:8080".to_string())).is_some());
    }

    /// A configured-but-unparseable proxy URL must refuse (panic) instead of
    /// returning `None` — which `build_agent` would treat as "no proxy" and
    /// go DIRECT: the leak this path exists to prevent (N3). Uses the same
    /// malformed value as the runtime contract's sibling test
    /// (`src/runtime/egress_http.rs`), which ureq rejects in `Uri` parsing
    /// (bare hosts are legal for `ureq::Proxy` — it defaults them to `http` —
    /// so the sample must be genuinely unparseable, not just scheme-less).
    #[test]
    #[should_panic(expected = "refusing to run unproxied")]
    fn proxy_for_url_refuses_hard_on_malformed_proxy() {
        let _ = proxy_for_url(Some("::::nope".to_string()));
    }
}
