//! HTTP fetch runtime wrapper.
//!
//! Provides `extern "C"` functions for performing synchronous HTTP requests
//! via ureq. This is the compiled-binary equivalent of the interpreter's
//! built-in `fetch()` function.

use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use super::{cstr_to_str, set_last_error, string_to_cstr};

// ── Egress (proxy / Tor) ────────────────────────────────────────────────────

/// Resolve the egress proxy URL.
///
/// **Fail-closed by default: Tor.** With nothing set, Tallow rides the box's
/// anonymous stack ([`default_tor_proxy_url`] — Tor with a **per-run circuit
/// identity** bound into the URL; [`TOR_SOCKS_URL`] is the bare opt-out form).
/// A compiled binary or an interpreter run that forgets to export anything
/// therefore cannot leak the box IP by omission (the box IP is
/// `203.0.113.1`; every Tor exit differs).
///
/// Precedence:
/// 1. `TALLOW_PROXY=<url>` — explicit proxy, wins over everything.
/// 2. `TALLOW_ALLOW_DIRECT=1|true|yes` — deliberate opt-out → `None` (direct).
/// 3. otherwise → Tor. `TALLOW_TOR=1` is still accepted but is now redundant:
///    it used to be what *enabled* Tor, and survives only to document intent.
///
/// There is no silent fallback: if Tor is not reachable the request fails
/// loudly rather than quietly going direct.
///
/// This is the egress contract the whole box uses, documented in the
/// `tor-anonymous-stack` skill. It lives here (rather than next to the
/// interpreter's own resolver) so the native runtime has no dependency on the
/// interpreter stdlib, and so a compiled binary and the interpreter cannot
/// disagree about where traffic goes.
pub fn egress_proxy_url() -> Option<String> {
    if let Ok(url) = std::env::var("TALLOW_PROXY") {
        let url = url.trim();
        if !url.is_empty() {
            return Some(url.to_string());
        }
    }
    if allow_direct() {
        return None;
    }
    // `socks5h` (remote DNS), NOT `socks5`: ureq ABORTS the process — a hard
    // SIGABRT/core dump, not a catchable error — on `socks5://`, whose
    // local-DNS SOCKS path is broken (verified: a compiled Tallow binary
    // `timeout: the monitored command dumped core`). Remote DNS is also the
    // privacy-correct choice: no query leaves the box.
    Some(default_tor_proxy_url())
}

/// The box's Tor SOCKS endpoint, remote-DNS spelling (see [`egress_proxy_url`]).
///
/// This is the **bare legacy** URL (no per-run credentials): every consumer
/// shares Tor's default circuit. It remains valid — the opt-out target of
/// `TALLOW_TOR_ISOLATE=0` and the parse-stable fixture in tests — but the
/// fail-closed default is [`default_tor_proxy_url`], which binds a per-run
/// identity so each run gets its own circuit.
/// Default port used when nothing overrides it (see [`tor_socks_port`]).
pub const TOR_SOCKS_PORT: u16 = 9050;

/// The bare legacy Tor URL at the **default** port.
///
/// Retained because tests and docs assert on this exact string. Callers that
/// actually make requests must use [`tor_socks_url`], which honours
/// [`TOR_SOCKS_PORT_ENV`] — using this constant directly reintroduces the
/// hardcoded-port bug it was named for.
pub const TOR_SOCKS_URL: &str = "socks5h://127.0.0.1:9050";

/// The bare legacy Tor URL, honouring [`TOR_SOCKS_PORT_ENV`].
pub fn tor_socks_url() -> String {
    format!("socks5h://127.0.0.1:{}", tor_socks_port())
}

/// Per-run Tor circuit binding (P1 W1-E1, egress diversity).
///
/// Tor's `IsolateSOCKSAuth` assigns a distinct circuit per distinct SOCKS5
/// (RFC 1929) username/password pair. The fail-closed default therefore embeds
/// a **per-run identity**, minted once per process ([`tor_run_identity`]): runs
/// that assign no id never share a circuit, and within one run traffic stays on
/// one circuit. An explicit id is the runner's stickiness lever: the same
/// `TALLOW_TOR_STREAM_ID` is deterministic, so that id keeps its circuit (and
/// exit) across runs — one task = one exit (exit-hopping mid-task is itself a
/// signal, and a shared circuit across *unrelated* runs links them at the
/// exit).
///
/// - `TALLOW_TOR_STREAM_ID=<id>` — the runner assigns the identity explicitly
///   (sanitized to `[A-Za-z0-9_-]{1,64}`); set a fresh id per target/task to
///   request a fresh circuit between tasks (exit-set hygiene, W1-E4).
/// - `TALLOW_TOR_ISOLATE=0|false|no` — explicit opt-out: the bare
///   [`TOR_SOCKS_URL`] (one shared circuit per box; debugging / back-compat
///   only). Junk values keep the binding — a typo must never silently
///   downgrade isolation.
pub const TOR_ISOLATE_ENV: &str = "TALLOW_TOR_ISOLATE";

/// Env var carrying the runner-assigned stream identity (see [`TOR_ISOLATE_ENV`]).
pub const TOR_STREAM_ID_ENV: &str = "TALLOW_TOR_STREAM_ID";

/// Env var overriding the Tor SOCKS **port** (`TALLOW_TOR_SOCKS_PORT`).
///
/// The port was hardcoded to 9050, which silently made Tallow unusable on any box
/// whose Tor is not on the system default — notably Tor Browser and the per-user
/// `tor` unit, which listen on 9150. There was no error explaining it: the proxy
/// resolved to an empty port, every request failed with `Connection refused`
/// (os error 111), and the fail-closed default made it look like a policy block.
/// Measured on the Atlas box: nothing listens on 9050, Tor is on 9150, and the
/// same run succeeded 9/10 the moment the port was correct.
///
/// Junk or out-of-range values fall back to 9050 rather than disabling Tor: a typo
/// must never silently push traffic out of the anonymous path (same rule as
/// [`tor_isolation_disabled`], in the other direction).
pub const TOR_SOCKS_PORT_ENV: &str = "TALLOW_TOR_SOCKS_PORT";

/// Default Tor SOCKS port (the system daemon's).
pub const TOR_SOCKS_PORT_DEFAULT: u16 = 9050;

/// Resolve the Tor SOCKS port, honouring [`TOR_SOCKS_PORT_ENV`].
pub fn tor_socks_port() -> u16 {
    match std::env::var(TOR_SOCKS_PORT_ENV) {
        Ok(v) => v.trim().parse::<u16>().unwrap_or(TOR_SOCKS_PORT_DEFAULT),
        Err(_) => TOR_SOCKS_PORT_DEFAULT,
    }
}

/// `TALLOW_TOR_ISOLATE=0|false|no` disables the per-run circuit binding.
/// Unset, junk, or any other value keep it (fail-closed toward isolation,
/// mirroring [`allow_direct`]'s strict parse in the other direction).
pub fn tor_isolation_disabled() -> bool {
    match std::env::var(TOR_ISOLATE_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "0" || v == "false" || v == "no"
        }
        Err(_) => false,
    }
}

/// Sanitize a runner-supplied stream id for the SOCKS username field.
/// Keeps `[A-Za-z0-9_-]`, truncates to 64 bytes; `None` when nothing usable
/// remains (the caller then falls back to the auto-minted identity).
fn sanitize_stream_id(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Mint a `(username, password)` SOCKS5 identity for one run.
///
/// `stream_id` — the runner-assigned identity (`TALLOW_TOR_STREAM_ID`), or
/// `None` for the auto-minted `tallow-<pid>-<random>` form.
///
/// **Explicit ids are deterministic**: the same id yields the same credentials
/// in every process, so Tor's `IsolateSOCKSAuth` keeps that id on one circuit
/// across runs — the sticky leg of W1-E4 ("one task = one exit"; a fresh id is
/// how a runner requests a fresh circuit). Auto-minted identities stay random
/// per process, so runs that assign no id never share a circuit. Isolation
/// keys need uniqueness and stability, not secrecy (mirrors
/// `src/tor/pool.rs`).
fn mint_run_identity(stream_id: Option<&str>) -> (String, String) {
    use rand::Rng as _;
    if let Some(id) = stream_id.and_then(sanitize_stream_id) {
        return (id.clone(), stable_hex16(&id));
    }
    let mut rng = rand::rng();
    let user = format!("tallow-{}-{:08x}", std::process::id(), rng.random::<u32>());
    let pass: String = (0..16)
        .map(|_| char::from_digit(rng.random_range(0..16_u32), 16).expect("0..16 is a hex digit"))
        .collect();
    (user, pass)
}

/// Stable 64-bit FNV-1a as 16 hex chars — deterministic across builds and
/// runs (unlike `DefaultHasher`, whose output is not contractual). Isolation
/// key material only: uniqueness and stability are the properties, not
/// secrecy.
fn stable_hex16(input: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in input.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Format the per-run default Tor proxy URL from a minted identity.
fn tor_proxy_url_for(identity: &(String, String)) -> String {
    format!(
        "socks5h://{}:{}@127.0.0.1:{}",
        identity.0,
        identity.1,
        tor_socks_port()
    )
}

/// The per-run identity, minted once per process (per run).
fn tor_run_identity() -> &'static (String, String) {
    static IDENTITY: std::sync::LazyLock<(String, String)> = std::sync::LazyLock::new(|| {
        let stream = std::env::var(TOR_STREAM_ID_ENV).ok();
        mint_run_identity(stream.as_deref())
    });
    &IDENTITY
}

/// The fail-closed default proxy: Tor with a per-run circuit identity bound
/// in the URL (see [`TOR_ISOLATE_ENV`] for the opt-out and the stream-id
/// override). Stable within a process — one run mints one identity.
pub fn default_tor_proxy_url() -> String {
    if tor_isolation_disabled() {
        return tor_socks_url();
    }
    tor_proxy_url_for(tor_run_identity())
}

/// `TALLOW_ALLOW_DIRECT=1|true|yes` is the only way to get a direct connection.
/// Unset, `0`, `false` or junk all keep the fail-closed Tor default, so a typo
/// cannot open a leak.
pub fn allow_direct() -> bool {
    match std::env::var("TALLOW_ALLOW_DIRECT") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        }
        Err(_) => false,
    }
}

/// Upgrade a `socks5://` proxy URL to the `socks5h://` (remote-DNS) spelling
/// ureq needs — see [`egress_proxy_url_ureq`]. Pure over its input: only the
/// exact `socks5://` prefix is rewritten; `socks5h://` and every other scheme
/// pass through unchanged (so the upgrade can never be applied twice).
fn upgrade_socks5_to_socks5h(url: &str) -> String {
    match url.strip_prefix("socks5://") {
        Some(rest) => format!("socks5h://{rest}"),
        None => url.to_string(),
    }
}

/// Same as [`egress_proxy_url`], but guaranteed to be a scheme ureq can use: a
/// caller-supplied `TALLOW_PROXY=socks5://…` is upgraded to `socks5h://…` for
/// the same reason (ureq's `socks5://` path aborts the process).
pub fn egress_proxy_url_ureq() -> Option<String> {
    egress_proxy_url().map(|url| upgrade_socks5_to_socks5h(&url))
}

/// Build the HTTP agent for `fetch()`, honouring the egress env above. Without
/// this the FFI called bare `ureq::get(url)`, so a compiled binary egressed from
/// the box IP even with `TALLOW_TOR=1` set (verified: box `203.0.113.1` vs
/// Tor exit `192.42.116.104`) — a silent anonymity leak in a tool built for
/// anonymous collection.
///
/// Timeouts are loosened *only* when a proxy is configured: Tor circuits are
/// slow (cold ones slower), and ureq's defaults are tuned for direct
/// connections.
///
/// A configured-but-unparseable proxy URL is a **hard refusal**: this returns
/// `Err` and the FFI entry points surface it via `set_last_error`, with no
/// request attempted. Warn-then-proceed was a silent fallback to the box IP —
/// the leak class invariant N3 exists to prevent. The message mirrors the
/// interpreter's refusal (`src/interp.rs`).
fn fetch_agent(url: &str) -> Result<ureq::Agent, String> {
    build_agent(crate::stdlib::http::is_loopback_literal(url))
}

/// Build the native fetch agent. `loopback_direct` bypasses the egress proxy —
/// only ever true for a literal loopback address (see [`fetch_agent`]).
fn build_agent(loopback_direct: bool) -> Result<ureq::Agent, String> {
    let mut builder = ureq::Agent::config_builder()
        // HTTP statuses are DATA, not transport failures: 4xx/5xx arrive as
        // ordinary responses (parity with the stdlib client — `governed_get`
        // "distinguishes 200/429/5xx distinctly (never collapsed)" — and the
        // sitescan agents, all of which set this). Without it,
        // ureq maps every non-2xx to `Err(StatusCode)` and both native FFI
        // entry points return a null handle: compiled `http.get` consumers
        // lose status+body, and the R-01 leg cannot classify 429/5xx/403
        // [measured 2026-09-13: loopback probe returned status=-1 on all].
        .http_status_as_error(false)
        // EGRESS-REDIRECTS.md requirement 1: no implicit follow on either
        // plane. `egress_http::follow` is the only way a 3xx becomes another
        // request, and it consults the register per hop.
        .max_redirects(0);
    // A LITERAL loopback address cannot resolve anywhere but this machine, so
    // it is not an anonymity plane and must not be sent through the proxy: the
    // SOCKS allowlist denies 127.0.0.0/8 by design, which turned a registered
    // loopback GET into `connection not allowed by ruleset` instead of reaching
    // the socket. The interpreter plane has always taken this branch
    // (`stdlib::http::get_agent_for` → DIRECT_AGENT), so this restores parity
    // and makes "registered host is reachable" measurable on the compiled
    // plane. Names — including `localhost` — are NOT bypassed: they resolve.
    if !loopback_direct {
        if let Some(url) = egress_proxy_url_ureq() {
            // Refuse, never degrade: the request must not fall back to an
            // unproxied connection just because the proxy URL is junk. The
            // refusal message is computed in exactly one place (tested pure).
            refusal_for_proxy_url(&url)?;
            // Validated on the line above; `ureq::Proxy::new` is pure and
            // deterministic over this exact input, so this cannot fail.
            let proxy = ureq::Proxy::new(&url).expect("proxy URL validated one line above");
            builder = builder
                .proxy(Some(proxy))
                .timeout_connect(Some(Duration::from_secs(30)))
                .timeout_recv_response(Some(Duration::from_secs(60)))
                .timeout_recv_body(Some(Duration::from_secs(60)));
        }
    }
    if let Some(rc) = crate::runtime::egress_http::ca_bundle_root_certs() {
        // Mesh/internal-CA trust (`TALLOW_CA_BUNDLE`): same env var and
        // additive semantics as the stealth (wreq) path and the egress
        // agent — see the docs on `egress_http::ca_bundle_root_certs`.
        builder = builder.tls_config(ureq::tls::TlsConfig::builder().root_certs(rc).build());
    }
    Ok(builder.build().new_agent())
}

/// Pure refusal computation for the native fetch path (invariant N3).
///
/// `Ok(())` — `url` parses into a usable `ureq::Proxy`, so the request may go
/// through it. `Err(reason)` — the configured proxy URL is unusable, so the
/// fetch path refuses and attempts **no** request (warn-then-proceed was a
/// silent fallback to the box IP — the leak class N3 retires). Extracted from
/// [`fetch_agent`] so the refusal is testable without mutating process env
/// (env mutation would race the env-based `egress_http` tests).
///
/// The return value is pure over `url`; on the refuse branch one redacted
/// security event is additionally emitted, best-effort, to the telemetry
/// choke point (`crate::observability`, R-6.1 slice 1) — the refusal itself
/// never depends on the journal being writable.
fn refusal_for_proxy_url(url: &str) -> Result<(), String> {
    match ureq::Proxy::new(url) {
        Ok(_) => Ok(()),
        Err(e) => {
            let _ = crate::observability::emit_to_default_journal(
                &crate::observability::SecurityEvent {
                    class: crate::observability::EventClass::EgressRefusal,
                    actor: "runtime.fetch".to_string(),
                    target: Some(url.to_string()),
                    size: url.len(),
                    at_ms: crate::observability::now_ms(),
                },
            );
            Err(format!(
                "fetch: refusing to run unproxied — invalid proxy URL from \
                 TALLOW_PROXY/TALLOW_TOR ({url}): {e}"
            ))
        }
    }
}


// ── Response Handle ─────────────────────────────────────────────────────────

/// Opaque response type passed across FFI boundary as *mut c_void.
struct FetchResponse {
    status: u16,
    body: String,
    url: String,
}

// ── FFI Functions ───────────────────────────────────────────────────────────

/// Perform an HTTP GET request. Returns an opaque response handle, or null on error.
///
/// The caller must free the handle with tallow_response_free().
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fetch(url: *const c_char) -> *mut c_void {
    let url_str = match unsafe { cstr_to_str(url) } {
        Some(s) => s,
        None => {
            set_last_error("fetch: null or invalid URL".to_string());
            return std::ptr::null_mut();
        }
    };

    // Refuse before waiting or sending anything when the configured proxy is
    // unusable (N3: fail closed, never egress unproxied by accident).
    let agent = match fetch_agent(url_str) {
        Ok(agent) => agent,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };
    // Scope gate first: deny-by-default, and a refusal costs nothing because it
    // happens before the delay and before the request is built.
    if let Err(r) = crate::scope::require(url_str, "GET") {
        set_last_error(format!("{} — {}", r.code(), r.explain()));
        return std::ptr::null_mut();
    }
    // Baseline politeness delay (`TALLOW_FETCH_DELAY_MS`, default 250 ms per
    // host) shared with the stdlib egress client — applied per hop inside
    // `follow`.
    match crate::runtime::egress_http::follow(&agent, url_str, "GET", None, &[]) {
        Ok(followed) => response_to_handle(followed.response, &followed.final_url),
        Err(refusal) => {
            set_last_error(format!("fetch: {refusal}"));
            std::ptr::null_mut()
        }
    }
}

/// Perform an HTTP request with an explicit method and body.
/// Returns an opaque response handle, or null on error.
///
/// - `url`: null-terminated URL string.
/// - `method`: null-terminated method name (case-insensitive; a leading `.`
///   such as `.POST` from Tallow's DotIdent literals is tolerated).
/// - `body`: request body bytes, or null for an empty body.
/// - `body_len`: number of valid bytes in `body` (ignored when body is null).
///
/// The caller must free the handle with tallow_response_free().
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fetch_method(
    url: *const c_char,
    method: *const c_char,
    body: *const c_char,
    body_len: i64,
) -> *mut c_void {
    let url_str = match unsafe { cstr_to_str(url) } {
        Some(s) => s,
        None => {
            set_last_error("fetch_method: null or invalid URL".to_string());
            return std::ptr::null_mut();
        }
    };
    // Normalize the method: tolerate ".POST" (Tallow DotIdent) and lowercase.
    let method_str = unsafe { cstr_to_str(method) }
        .unwrap_or("GET")
        .trim_start_matches('.')
        .to_uppercase();
    let body_bytes: Vec<u8> = if body.is_null() || body_len <= 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(body as *const u8, body_len as usize) }.to_vec()
    };

    // Refuse before waiting or sending anything when the configured proxy is
    // unusable (N3: fail closed, never egress unproxied by accident).
    let agent = match fetch_agent(url_str) {
        Ok(agent) => agent,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };
    // Scope gate: the method decides which grant applies, so it is consulted
    // with the real method rather than defaulted to GET.
    if let Err(r) = crate::scope::require(url_str, &method_str) {
        set_last_error(format!("{} — {}", r.code(), r.explain()));
        return std::ptr::null_mut();
    }
    // Baseline politeness delay, same limiter as `fetch(url)` and the stdlib
    // egress client — applied per hop inside `follow`.
    let result = crate::runtime::egress_http::follow(
        &agent,
        url_str,
        &method_str,
        if body_bytes.is_empty() {
            None
        } else {
            Some(body_bytes.as_slice())
        },
        &[],
    );

    match result {
        Ok(followed) => response_to_handle(followed.response, &followed.final_url),
        Err(refusal) => {
            set_last_error(format!("fetch_method({method_str}): {refusal}"));
            std::ptr::null_mut()
        }
    }
}

/// Shared response-handle construction for both fetch entry points.
fn response_to_handle(response: ureq::http::Response<ureq::Body>, url: &str) -> *mut c_void {
    match response_to_handle_result(response, url) {
        Ok(handle) => handle,
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

/// `Err` carries the same text [`response_to_handle`] stores via
/// `set_last_error`, so the batch path can name the reason per URL instead of
/// reading a thread-local back.
fn response_to_handle_result(
    response: ureq::http::Response<ureq::Body>,
    url: &str,
) -> Result<*mut c_void, String> {
    let status = response.status().as_u16();
    let body = match response.into_body().read_to_string() {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("fetch: failed to read body: {e}"));
        }
    };
    let resp = Box::new(FetchResponse {
        status,
        body,
        url: url.to_string(),
    });
    Ok(Box::into_raw(resp) as *mut c_void)
}

/// Get the HTTP status code from a response handle.
/// Returns -1 if the handle is null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_response_status(handle: *mut c_void) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let resp = unsafe { &*(handle as *const FetchResponse) };
    resp.status as i32
}

/// Get the response body as a C string. Caller must free with tallow_free_string().
/// Returns null if the handle is null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_response_body(handle: *mut c_void) -> *mut c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let resp = unsafe { &*(handle as *const FetchResponse) };
    string_to_cstr(&resp.body)
}

/// Get the final URL (after redirects) as a C string. Caller must free with tallow_free_string().
/// Returns null if the handle is null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_response_url(handle: *mut c_void) -> *mut c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let resp = unsafe { &*(handle as *const FetchResponse) };
    string_to_cstr(&resp.url)
}

/// Free a response handle previously returned by tallow_fetch().
/// Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_response_free(handle: *mut c_void) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle as *mut FetchResponse));
        }
    }
}

// ── Batch fetch (http.batch) ────────────────────────────────────────────────

/// The `%struct.TallowResult` ABI as emitted by codegen
/// (`codegen.rs`: `%struct.TallowResult = type { i64, i64, i64 }`):
/// tag 0 = Ok, 1 = Err; `value` is the payload (pointer bitcast to i64);
/// `value_type` 2 = string payload, 3 = response-handle payload.
#[repr(C)]
struct BatchResultBox {
    tag: i64,
    value: i64,
    value_type: i64,
}

/// `value_type` for a string payload (the interpreter's `as_string`/`display`).
const VTYPE_STRING: i64 = 2;
/// `value_type` for a `FetchResponse` handle payload. Codegen prints such an
/// entry as `Response { status: N, url: "…" }` instead of reading the handle's
/// bytes as a C string (which printed garbage), and `if let Ok(h) = r[i]`
/// binds it as an i64 handle value.
const VTYPE_HANDLE: i64 = 3;

// ── http.batch: the TYPED entry ABI (`tallow_http_batch_entries`) ──────────
//
// `tallow_http_batch` above renders each slot as a `%struct.TallowResult`
// box. That shape is shared with `pool.map` (`codegen.rs`), documented, and
// must not drift — so the `http.batch` verb gets its OWN entry point that
// renders the declared `[]BatchResponse` model (`stdlib/http.tl`):
//
//   %struct.HttpError     = type { i8*, i8*, i64, i1, i8* }
//                           ; kind, url, status?, retryable, message
//   %struct.BatchResponse = type { i8*, i1, i64, i64, i8*, i8* }
//                           ; url, ok, attempts, elapsed_ms, response, error
//
// The Rust mirrors below must stay `#[repr(C)]` and field-for-field identical:
// a wrong order or a missing bool pad is a silently wrong READ at run time,
// not a build error. `response` is the opaque `FetchResponse` handle (usable
// with `tallow_response_*`), NOT a materialised `Response` — the compiled
// plane has no in-record representation for `body: Bytes` /
// `headers: Map<..>`. `error` is a pointer that is NULL on a successful entry;
// codegen guards the null rather than dereferencing it.

/// `%struct.HttpError` (`{ i8*, i8*, i64, i1, i8* }`).
#[repr(C)]
struct HttpErrorRecord {
    kind: *const c_char,
    url: *const c_char,
    status: i64,
    retryable: bool,
    message: *const c_char,
}

/// `%struct.BatchResponse` (`{ i8*, i1, i64, i64, i8*, i8* }`).
#[repr(C)]
struct BatchResponseRecord {
    url: *const c_char,
    ok: bool,
    attempts: i64,
    elapsed_ms: i64,
    response: *mut c_void,
    error: *mut HttpErrorRecord,
}

/// One per-URL failure, in the declared `HttpError` model (`stdlib/http.tl`):
/// `kind` is `egress_refused` (the register / jurisdiction / ledger refused it)
/// or `transport`; `status` is present only for an HTTP status.
struct EntryError {
    kind: &'static str,
    status: Option<i64>,
    retryable: bool,
    message: String,
}

/// The outcome of one batch slot, independent of which entry ABI renders it.
///
/// Both `tallow_http_batch` (Result boxes, shared with `pool.map`) and
/// `tallow_http_batch_entries` (BatchResponse records, `http.batch` only) are
/// built from this, so the two ABIs cannot drift on gating or on wording.
struct EntryOutcome {
    url: String,
    /// A response handle came back — the `Ok`/`Err` split of the shared
    /// `Result` ABI. Deliberately NOT the same thing as `BatchResponse.ok`: a
    /// fetched 4xx is `Ok(handle)` there and `ok=false` here, because the
    /// interpreter's typed model reports a 4xx as a result carrying both the
    /// body and an `HttpError`.
    fetched: bool,
    status: Option<i64>,
    elapsed_ms: i64,
    response: *mut c_void,
    error: Option<EntryError>,
}

impl EntryOutcome {
    /// A failed slot: nothing was fetched, one `HttpError` names the ground.
    fn refused(
        url: &str,
        kind: &'static str,
        status: Option<i64>,
        retryable: bool,
        message: String,
    ) -> Self {
        Self {
            url: url.to_string(),
            fetched: false,
            status,
            elapsed_ms: 0,
            response: std::ptr::null_mut(),
            error: Some(EntryError {
                kind,
                status,
                retryable,
                message,
            }),
        }
    }

    /// The shared-ABI rendering (`%struct.TallowResult`), byte-identical to
    /// what `fetch_entry` produced before the typed ABI existed.
    fn result_box(&self) -> i64 {
        if self.fetched {
            result_box(0, self.response, VTYPE_HANDLE)
        } else {
            let message = self
                .error
                .as_ref()
                .map(|e| e.message.clone())
                .unwrap_or_default();
            result_box(1, string_to_cstr(&message) as *mut c_void, VTYPE_STRING)
        }
    }

    /// The typed-ABI rendering (`*mut BatchResponseRecord`, as an i64 slot).
    fn record(&self) -> i64 {
        // A fetched 4xx/5xx is a *result* in the declared model, not a
        // transport failure: `ok=false` with the handle still attached, so the
        // body stays readable — the same split the interpreter's `classify`
        // makes (`stdlib/http.rs`).
        let derived_error: Option<(String, Option<i64>, bool, String)> =
            match (&self.error, self.fetched, self.status) {
                (None, true, Some(status)) if status >= 400 => {
                    let kind = if status < 500 { "http_4xx" } else { "http_5xx" };
                    Some((
                        kind.to_string(),
                        Some(status),
                        false,
                        format!("HTTP {status} for {}", self.url),
                    ))
                }
                (None, _, _) => None,
                (Some(e), _, _) => Some((
                    e.kind.to_string(),
                    e.status,
                    e.retryable,
                    e.message.clone(),
                )),
            };
        let ok = derived_error.is_none() && self.fetched;
        let error = match derived_error {
            Some((kind, status, retryable, message)) => Box::into_raw(Box::new(HttpErrorRecord {
                kind: string_to_cstr(&kind),
                url: string_to_cstr(&self.url),
                // The declaration is `status: Int?`; 0 on the wire is the
                // "absent" sentinel codegen documents for the optional.
                status: status.unwrap_or(0),
                retryable,
                message: string_to_cstr(&message),
            })),
            None => std::ptr::null_mut(),
        };
        Box::into_raw(Box::new(BatchResponseRecord {
            url: string_to_cstr(&self.url),
            ok,
            // The batch path makes exactly one attempt per URL (the
            // interpreter's model reports the same constant).
            attempts: 1,
            elapsed_ms: self.elapsed_ms,
            response: if self.fetched {
                self.response
            } else {
                std::ptr::null_mut()
            },
            error,
        })) as i64
    }
}

fn result_box(tag: i64, payload: *mut c_void, value_type: i64) -> i64 {
    Box::into_raw(Box::new(BatchResultBox {
        tag,
        value: payload as i64,
        value_type,
    })) as i64
}

/// `http.batch(urls, concurrency)` → one result per URL, in input order.
///
/// Mirrors the interpreter's `http_batch` (`src/stdlib/http.rs`) on semantics —
/// a per-URL failure becomes an `Err` entry instead of aborting the batch, and
/// `concurrency` is clamped to `1..=64` (`-1` = argument absent ⇒ the
/// interpreter's default 8) — but unlike the interpreter's current build
/// (sequential, `non-Send fetch state`) the compiled path runs a **real
/// bounded worker pool**: `min(concurrency, urls)` scoped threads, each pulling
/// the next index off a shared counter. Entries keep INPUT order regardless of
/// completion order (each worker writes only its own slot). The politeness
/// limiter is still per host, so same-host requests stay spaced.
///
/// `urls` is a NATIVE array (`[count: i64][slot: i64 …]`, see
/// `runtime::browser::native_array`) whose slots hold `*const c_char` bitcast
/// to i64. Returns a NATIVE array of `%struct.TallowResult` boxes:
/// `Ok(handle)` for a fetched response (usable with `tallow_response_*`),
/// `Err(message)` otherwise. A null `urls` (the interpreter's `nil`) yields an
/// empty array plus `set_last_error`; codegen refuses that case loudly before
/// calling in.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_http_batch(urls: *mut c_void, concurrency: i64) -> *mut c_void {
    let Some(slots) = batch_slots(urls) else {
        set_last_error("http.batch requires a [String] URLs argument".to_string());
        return crate::runtime::browser::native_array(Vec::new());
    };

    let concurrency = batch_concurrency(concurrency);

    // One agent for the whole batch. A configured-but-unusable proxy refuses
    // *every* URL with the same reason and no request attempted (N3) instead
    // of degrading to a direct connection — that path stays sequential (there
    // is nothing to parallelise when no request is allowed).
    let agent = batch_agent(&slots);

    let count = slots.len();
    let entries: Vec<i64> = match &agent {
        Err(e) => slots.iter().map(|slot| err_entry(*slot, e)).collect(),
        Ok(agent) => run_bounded_pool(count, concurrency, |i| fetch_entry(agent, slots[i])),
    };

    crate::runtime::browser::native_array(entries)
}

/// `http.batch(urls, concurrency)` with the **typed** entry ABI: one
/// `*mut BatchResponseRecord` per URL, in input order, as a native array of
/// i64 slots (codegen `inttoptr`s each slot before the field GEP).
///
/// Same gates, same worker pool and same sentences as `tallow_http_batch` —
/// both are built from [`EntryOutcome`] — but the element is the declared
/// `BatchResponse` record rather than a `%struct.TallowResult` box. That is
/// why this is a second entry point and not a change to the first:
/// `pool.map` shares `tallow_http_batch` and its documented `Result` element
/// shape must not drift with `http.batch`.
///
/// Per-URL failures still never abort the batch. `error` is NULL on a
/// successful entry; codegen guards the null instead of dereferencing it.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_http_batch_entries(urls: *mut c_void, concurrency: i64) -> *mut c_void {
    let Some(slots) = batch_slots(urls) else {
        set_last_error("http.batch requires a [String] URLs argument".to_string());
        return crate::runtime::browser::native_array(Vec::new());
    };

    let concurrency = batch_concurrency(concurrency);
    let agent = batch_agent(&slots);

    let count = slots.len();
    let entries: Vec<i64> = match &agent {
        Err(e) => slots
            .iter()
            .map(|slot| err_entry_record(*slot, e))
            .collect(),
        Ok(agent) => run_bounded_pool(count, concurrency, |i| {
            fetch_entry_record(agent, slots[i])
        }),
    };

    crate::runtime::browser::native_array(entries)
}

/// Read the native `[String]` array argument (`[count: i64][slot: i64 …]`,
/// slots holding `*const c_char` bitcast to i64) into owned i64 slots.
/// `None` for a null array — the interpreter's `nil`, a hard argument error.
/// Shared by both batch entry points so they cannot drift on the contract.
fn batch_slots(urls: *mut c_void) -> Option<Vec<i64>> {
    if urls.is_null() {
        return None;
    }
    let count = unsafe { *(urls as *const i64) }.max(0) as usize;
    let slots: &[i64] = unsafe { std::slice::from_raw_parts((urls as *const i64).add(1), count) };
    Some(slots.to_vec())
}

/// The one agent for a whole batch.
///
/// The batch keeps one agent for the whole run (proxy policy is per run, not
/// per URL); a literal-loopback batch is not proxied and is the case the
/// register's loopback GET grant is exercised by. The agent is shared, so the
/// bypass is all-or-nothing: a batch of literal loopback URLs is direct, a
/// batch containing any other host keeps the proxy (a mixed batch is not
/// silently split into two policies).
fn batch_agent(slots: &[i64]) -> Result<ureq::Agent, String> {
    let loopback_batch = slots.iter().all(|slot| {
        let url = unsafe { cstr_to_str(*slot as *const c_char) }.unwrap_or("");
        crate::stdlib::http::is_loopback_literal(url)
    });
    build_agent(loopback_batch)
}

/// Fetch one slot and box the outcome: `Ok(handle)` for a fetched response,
/// `Err(\"http.batch[<url>]: <reason>\")` otherwise. Never fails the batch.
fn fetch_entry(agent: &ureq::Agent, slot: i64) -> i64 {
    fetch_outcome(agent, slot).result_box()
}

/// Fetch one slot and render the outcome as a `BatchResponse` record.
fn fetch_entry_record(agent: &ureq::Agent, slot: i64) -> i64 {
    fetch_outcome(agent, slot).record()
}

/// Milliseconds since `started`, saturating rather than wrapping.
fn elapsed_ms_since(started: std::time::Instant) -> i64 {
    started.elapsed().as_millis().min(i64::MAX as u128) as i64
}

/// Fetch one slot and describe the outcome in ABIs-independent terms.
///
/// The gates are unchanged and are the ones this file already carried, in the
/// same order: the **register** first (verb `GET` — the verb the batch
/// actually sends), then jurisdiction, then the egress ledger, then the
/// request itself (whose redirect hops are re-gated by `egress_http::follow`).
/// The decision to *return* a per-URL refusal rather than abort is the batch
/// contract: `http.batch` never fails whole, and both entry ABIs render the
/// returned entry (see `reports/ledger-batch-stage2.md` §per-site table).
fn fetch_outcome(agent: &ureq::Agent, slot: i64) -> EntryOutcome {
    let started = std::time::Instant::now();
    let url = match unsafe { cstr_to_str(slot as *const c_char) } {
        Some(u) => u.to_string(),
        None => {
            return EntryOutcome::refused(
                "<invalid url>",
                "transport",
                None,
                false,
                "http.batch[<invalid url>]: null or non-UTF-8 URL".to_string(),
            );
        }
    };

    // Scope gate for the batch path (deny-by-default, same register).
    if let Err(r) = crate::scope::require(&url, "GET") {
        return EntryOutcome::refused(
            &url,
            "egress_refused",
            None,
            false,
            format!("http.batch[{url}]: {} — {}", r.code(), r.explain()),
        );
    }
    // Jurisdiction is checked before the budget: a host we may not touch at all
    // should not consume a request slot or a ledger line.
    let host = crate::net::egress::host_of(&url);
    if let Err(reason) = crate::scope_jurisdiction::check(&host) {
        return EntryOutcome::refused(
            &url,
            "egress_refused",
            None,
            false,
            format!("http.batch[{url}]: {reason}"),
        );
    }
    // The egress ledger applies to the native batch path too, or the control
    // would depend on which engine ran the program.
    if let Some(ledger) = crate::net::egress::ledger() {
        if let Err(reason) = ledger.permit(&host) {
            ledger.record_refusal(&host, &url, "GET", &reason);
            return EntryOutcome::refused(
                &url,
                "egress_refused",
                None,
                false,
                format!("http.batch[{url}]: {reason}"),
            );
        }
    }
    // Baseline politeness delay, same limiter as `tallow_fetch` (per host) —
    // applied per hop inside `follow`, which also re-gates every hop.
    match crate::runtime::egress_http::follow(agent, &url, "GET", None, &[]) {
        Ok(followed) => {
            // Read the status before the response is consumed into a handle:
            // a 403 must reach the ledger as a 403, not as "allowed".
            let status = followed.response.status().as_u16();
            match response_to_handle_result(followed.response, &followed.final_url) {
                Ok(handle) => {
                    if let Some(ledger) = crate::net::egress::ledger() {
                        ledger.record(&host, &url, "GET", status);
                    }
                    EntryOutcome {
                        url,
                        fetched: true,
                        status: Some(i64::from(status)),
                        elapsed_ms: elapsed_ms_since(started),
                        response: handle,
                        error: None,
                    }
                }
                Err(e) => EntryOutcome::refused(
                    &url,
                    "transport",
                    Some(i64::from(status)),
                    true,
                    format!("http.batch[{url}]: {e}"),
                ),
            }
        }
        Err(refusal) => {
            if let Some(ledger) = crate::net::egress::ledger() {
                ledger.record(&host, &url, "GET", 0);
            }
            EntryOutcome::refused(
                &url,
                "transport",
                None,
                true,
                format!("http.batch[{url}]: fetch: {refusal}"),
            )
        }
    }
}

/// Per-URL `Err` entry used when the batch refuses to send anything at all
/// (unusable configured proxy): the URL is still named, the reason is shared.
fn err_entry(slot: i64, reason: &str) -> i64 {
    let url = unsafe { cstr_to_str(slot as *const c_char) }.unwrap_or("<invalid url>");
    result_box(
        1,
        string_to_cstr(&format!("http.batch[{url}]: {reason}")) as *mut c_void,
        VTYPE_STRING,
    )
}

/// Typed-ABI twin of [`err_entry`]: the whole batch refused to send anything
/// (unusable configured proxy), so every URL gets the same reason as its own
/// `BatchResponse` record. Still one entry per URL, never a failed batch.
fn err_entry_record(slot: i64, reason: &str) -> i64 {
    let url = unsafe { cstr_to_str(slot as *const c_char) }.unwrap_or("<invalid url>");
    EntryOutcome::refused(
        url,
        "transport",
        None,
        true,
        format!("http.batch[{url}]: {reason}"),
    )
    .record()
}

/// Run `task(i)` for every `i in 0..count` with at most `workers` threads and
/// return the results in INPUT ORDER regardless of completion order.
///
/// Each worker claims the next index from a shared atomic counter and writes
/// only its own slot (an `AtomicI64`, relaxed — the scope join orders the reads
/// after the writes). Pure over `task`, so the pool's ordering and parallelism
/// are unit-testable without any network.
fn run_bounded_pool<F>(count: usize, workers: usize, task: F) -> Vec<i64>
where
    F: Fn(usize) -> i64 + Sync,
{
    let out: Vec<AtomicI64> = (0..count).map(|_| AtomicI64::new(0)).collect();
    if count == 0 {
        return Vec::new();
    }
    let workers = workers.max(1).min(count);
    if workers <= 1 {
        for (i, slot) in out.iter().enumerate() {
            slot.store(task(i), Ordering::Relaxed);
        }
    } else {
        let next = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= count {
                        break;
                    }
                    out[i].store(task(i), Ordering::Relaxed);
                });
            }
        });
    }
    out.into_iter().map(|a| AtomicI64::into_inner(a)).collect()
}

/// Concurrency for `tallow_http_batch`, mirroring the interpreter's
/// `http_batch` (`src/stdlib/http.rs:563-568`): the argument is clamped to
/// `1..=64`, and an absent argument (`-1`, the codegen sentinel) is the
/// interpreter's default of 8. Pure so the clamp is testable.
fn batch_concurrency(requested: i64) -> usize {
    if requested < 0 {
        8
    } else {
        requested.clamp(1, 64) as usize
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tor SOCKS port (TALLOW_TOR_SOCKS_PORT) ─────────────────────────────
    //
    // These lock the fix for the hardcoded-9050 bug. Env access is process-wide,
    // so each test takes the serialisation lock and restores the variable, or a
    // parallel test would observe another's value.

    fn with_port_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        // `set_var`/`remove_var` are unsafe in edition 2024: mutating the
        // process environment is racy against any other thread reading it.
        // The mutex serialises the whole read-modify-restore window so no two
        // of these tests overlap; the crate's other env tests (browser.rs) do
        // the same. Restores the previous value on the way out so a later test
        // never inherits this one's setting.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var(TOR_SOCKS_PORT_ENV).ok();
        unsafe {
            match value {
                Some(v) => std::env::set_var(TOR_SOCKS_PORT_ENV, v),
                None => std::env::remove_var(TOR_SOCKS_PORT_ENV),
            }
        }
        let out = f();
        unsafe {
            match previous {
                Some(v) => std::env::set_var(TOR_SOCKS_PORT_ENV, v),
                None => std::env::remove_var(TOR_SOCKS_PORT_ENV),
            }
        }
        out
    }

    #[test]
    fn tor_port_defaults_to_9050_when_unset() {
        let port = with_port_env(None, tor_socks_port);
        assert_eq!(port, TOR_SOCKS_PORT_DEFAULT);
    }

    #[test]
    fn tor_port_honours_9150() {
        // The Atlas box: nothing on 9050, Tor on 9150. This is the configuration
        // that used to fail every request with `Connection refused`.
        let port = with_port_env(Some("9150"), tor_socks_port);
        assert_eq!(port, 9150);
    }

    #[test]
    fn junk_port_falls_back_to_default_rather_than_disabling_tor() {
        // A typo must not push traffic out of the anonymous path.
        for junk in ["", "abc", "99999", "-1", "9050.5"] {
            let port = with_port_env(Some(junk), tor_socks_port);
            assert_eq!(port, TOR_SOCKS_PORT_DEFAULT, "junk {junk:?} must not win");
        }
    }

    #[test]
    fn bare_tor_url_uses_the_configured_port() {
        let url = with_port_env(Some("9150"), tor_socks_url);
        assert_eq!(url, "socks5h://127.0.0.1:9150");
        // socks5h, not socks5: ureq aborts the process on local-DNS SOCKS.
        assert!(url.starts_with("socks5h://"));
    }

    #[test]
    fn per_run_identity_url_uses_the_configured_port() {
        let identity = ("user".to_string(), "pass".to_string());
        let url = with_port_env(Some("9150"), || tor_proxy_url_for(&identity));
        assert_eq!(url, "socks5h://user:pass@127.0.0.1:9150");
    }

    // ── http.batch: pure helpers + argument edges (no network) ─────────────

    #[test]
    fn batch_concurrency_matches_the_interpreter_clamp() {
        assert_eq!(
            batch_concurrency(-1),
            8,
            "absent argument (-1 sentinel) ⇒ the interpreter's default"
        );
        assert_eq!(batch_concurrency(0), 1, "0 clamps up to 1 (interp: max(1))");
        assert_eq!(batch_concurrency(-7), 8, "any negative value is 'absent'");
        assert_eq!(batch_concurrency(4), 4);
        assert_eq!(batch_concurrency(64), 64);
        assert_eq!(
            batch_concurrency(999),
            64,
            "cap matches the interpreter's min(64)"
        );
    }

    #[test]
    fn bounded_pool_preserves_input_order_and_covers_every_index() {
        // Task cost inverted vs index: later indices finish FIRST, so a pool
        // that appended results on completion would come back reversed.
        let results = run_bounded_pool(6, 3, |i| {
            let cost = (6 - i) as u64 * 10;
            std::thread::sleep(Duration::from_millis(cost));
            (i * 10) as i64
        });
        assert_eq!(results, vec![0, 10, 20, 30, 40, 50]);
    }

    #[test]
    fn bounded_pool_actually_overlaps_work() {
        // Witness for real parallelism: with 4 workers and 4 sleeping tasks,
        // more than one task must be in flight simultaneously.
        let in_flight = AtomicUsize::new(0);
        let max_seen = AtomicUsize::new(0);
        let _ = run_bounded_pool(4, 4, |_| {
            let now = in_flight.fetch_add(1, Ordering::Relaxed) + 1;
            max_seen.fetch_max(now, Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(50));
            in_flight.fetch_sub(1, Ordering::Relaxed);
            0
        });
        assert!(
            max_seen.load(Ordering::Relaxed) >= 2,
            "pool must run tasks concurrently (max in-flight {})",
            max_seen.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn bounded_pool_degrades_to_sequential_and_handles_empty() {
        assert_eq!(run_bounded_pool(3, 1, |i| i as i64), vec![0, 1, 2]);
        assert!(run_bounded_pool(0, 8, |_| 0).is_empty());
    }

    #[test]
    fn batch_null_urls_is_an_empty_array_plus_reported_error() {
        let arr = tallow_http_batch(std::ptr::null_mut(), -1);
        assert!(
            !arr.is_null(),
            "a null URLs argument must still yield a usable (empty) array"
        );
        assert_eq!(
            unsafe { *(arr as *const i64) },
            0,
            "null urls ⇒ zero entries"
        );
        let err = crate::runtime::tallow_last_error();
        assert!(!err.is_null(), "the reason must be retrievable");
        let text = unsafe { std::ffi::CStr::from_ptr(err) }.to_string_lossy();
        assert!(
            text.contains("[String] URLs argument"),
            "message must name the argument error: {text}"
        );
    }

    #[test]
    fn batch_empty_urls_array_is_zero_entries_without_network() {
        let arr = crate::runtime::browser::native_array(Vec::new());
        let out = tallow_http_batch(arr, -1);
        assert!(!out.is_null());
        assert_eq!(unsafe { *(out as *const i64) }, 0);
    }

    // ── P1: malformed proxy URL → hard refusal, no request attempted ────────
    //
    // Pure over their inputs: no process-env mutation, so these cannot race
    // the env-based `egress_http` tests (which set/remove `TALLOW_PROXY` and
    // `TALLOW_ALLOW_DIRECT`). The malformed inputs are ones `ureq::Proxy::new`
    // (ureq 3.2.0) rejects: unparseable URI or missing authority.

    #[test]
    fn malformed_proxy_url_is_a_hard_refusal() {
        let refusal = refusal_for_proxy_url("::::nope")
            .expect_err("an unparseable proxy URL must refuse, never degrade");
        assert!(
            refusal.contains("refusing to run unproxied"),
            "the message must say it is refusing (invariant N3): {refusal:?}"
        );
        assert!(
            refusal.contains("::::nope"),
            "the refusal must name the offending URL: {refusal:?}"
        );
    }

    #[test]
    fn every_malformed_shape_refuses() {
        for url in ["socks5://", "not a url", ""] {
            assert!(
                refusal_for_proxy_url(url).is_err(),
                "{url:?} must refuse rather than fall back to a direct fetch"
            );
        }
    }

    #[test]
    fn usable_proxy_urls_do_not_refuse() {
        // The fail-closed Tor default and explicit proxies must stay usable.
        for url in [
            TOR_SOCKS_URL,
            "socks5h://127.0.0.1:9051",
            "socks5://127.0.0.1:9050", // upgraded to socks5h before `Proxy::new`
            "http://127.0.0.1:8080",
        ] {
            assert!(
                refusal_for_proxy_url(url).is_ok(),
                "{url:?} is usable and must not refuse"
            );
        }
    }

    // ── P5: `socks5://` → `socks5h://` upgrade (pure) ───────────────────────

    #[test]
    fn socks5_scheme_is_upgraded_to_remote_dns() {
        assert_eq!(
            upgrade_socks5_to_socks5h("socks5://127.0.0.1:9050"),
            "socks5h://127.0.0.1:9050"
        );
        // Credentials and non-default ports survive the rewrite verbatim.
        assert_eq!(
            upgrade_socks5_to_socks5h("socks5://user:pass@proxy.example:1080"),
            "socks5h://user:pass@proxy.example:1080"
        );
    }

    #[test]
    fn other_schemes_pass_through_unchanged() {
        for url in [
            TOR_SOCKS_URL, // socks5h: already remote-DNS — never double-upgraded
            "http://127.0.0.1:8080",
            "https://127.0.0.1:8443",
            "socks4a://127.0.0.1:1080",
        ] {
            assert_eq!(upgrade_socks5_to_socks5h(url), url);
        }
        // Prefix-scoped: a URL that merely contains the token is untouched.
        assert_eq!(
            upgrade_socks5_to_socks5h("http://example.com/socks5://x"),
            "http://example.com/socks5://x"
        );
    }

    // ── Native status surfacing: 4xx/5xx arrive as responses (R-01 leg) ─────
    //
    // Root cause these pin: ureq maps non-2xx to `Err(StatusCode)` by default,
    // so the FFI returned null (status -1) for every 429/5xx/403. The leg
    // contract (M-04 §5 Q2-A) and compiled-`http.get` parity both require the
    // response to survive. Env mutation serialized on the shared lock (T-128).

    #[test]
    fn fetch_agent_surfaces_http_statuses_as_responses() {
        let _guard = crate::runtime::egress_http::env_lock();
        let prev_proxy = std::env::var("TALLOW_PROXY").ok();
        let prev_direct = std::env::var("TALLOW_ALLOW_DIRECT").ok();
        unsafe {
            std::env::remove_var("TALLOW_PROXY");
            std::env::set_var("TALLOW_ALLOW_DIRECT", "1");
        }
        let agent = build_agent(false).expect("direct-mode agent must build");
        assert!(
            !agent.config().http_status_as_error(),
            "native fetch must surface 4xx/5xx as responses, never collapse to Err/null"
        );
        match prev_proxy {
            Some(v) => unsafe { std::env::set_var("TALLOW_PROXY", v) },
            None => unsafe { std::env::remove_var("TALLOW_PROXY") },
        }
        match prev_direct {
            Some(v) => unsafe { std::env::set_var("TALLOW_ALLOW_DIRECT", v) },
            None => unsafe { std::env::remove_var("TALLOW_ALLOW_DIRECT") },
        }
    }

    #[test]
    fn native_fetch_returns_response_handle_for_non_2xx_over_loopback() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            listener.set_nonblocking(true).expect("nonblocking accept");
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0_u8; 1024];
                        let _ = stream.read(&mut buf);
                        let body = "too many requests";
                        let resp = format!(
                            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        return;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() > deadline {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return,
                }
            }
        });

        let _guard = crate::runtime::egress_http::env_lock();
        let prev_proxy = std::env::var("TALLOW_PROXY").ok();
        let prev_direct = std::env::var("TALLOW_ALLOW_DIRECT").ok();
        let prev_delay = std::env::var("TALLOW_FETCH_DELAY_MS").ok();
        unsafe {
            std::env::remove_var("TALLOW_PROXY");
            std::env::set_var("TALLOW_ALLOW_DIRECT", "1");
            std::env::set_var("TALLOW_FETCH_DELAY_MS", "0");
        }

        let url = format!("http://{addr}/f429");
        let handle = tallow_fetch(crate::runtime::string_to_cstr(&url));

        // Restore ambient env immediately after the request.
        for (key, prev) in [
            ("TALLOW_PROXY", prev_proxy),
            ("TALLOW_ALLOW_DIRECT", prev_direct),
            ("TALLOW_FETCH_DELAY_MS", prev_delay),
        ] {
            match prev {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
        }

        let status = unsafe { tallow_response_status(handle) };
        let body_ptr = unsafe { tallow_response_body(handle) };
        let body = if body_ptr.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(body_ptr) }
                .to_string_lossy()
                .into_owned()
        };
        unsafe {
            if !body_ptr.is_null() {
                crate::runtime::tallow_free_string(body_ptr);
            }
            tallow_response_free(handle);
        }
        server.join().expect("server thread");

        assert!(
            !handle.is_null(),
            "a 429 must yield a response handle (got null — status collapsed to Err)"
        );
        assert_eq!(status, 429, "status must survive as data, not -1");
        assert!(
            body.contains("too many requests"),
            "the 429 body must be readable: {body:?}"
        );
    }

    // ── Per-run Tor circuit binding (P1 W1-E1) ──────────────────────────────

    #[test]
    fn per_run_identity_minting_is_distinct_and_sanitized() {
        // Distinct runs mint distinct identities (the isolation key).
        let a = mint_run_identity(Some("run-a"));
        let b = mint_run_identity(Some("run-b"));
        assert_ne!(a, b, "distinct runs must mint distinct identities");
        assert_ne!(a.1, b.1, "passwords must be unique per identity");
        // An explicit id is deterministic (sticky): the same id pins the same
        // circuit across processes — "one task = one exit" (W1-E4); the
        // sticky control in tests/egress/check_egress.sh depends on this.
        assert_eq!(
            a,
            mint_run_identity(Some("run-a")),
            "explicit stream ids must be deterministic across runs"
        );
        // Auto-minted identities carry no stickiness promise.
        assert_ne!(
            mint_run_identity(None),
            mint_run_identity(None),
            "auto-minted identities must be distinct per call site"
        );
        // The stream id is the SOCKS username; the URL carries both parts.
        let url = tor_proxy_url_for(&a);
        assert!(
            url.starts_with("socks5h://run-a:") && url.ends_with("@127.0.0.1:9050"),
            "stream id must be the SOCKS username with remote-DNS scheme: {url}"
        );
        // Runner ids are sanitized; nothing usable falls back to the mint.
        assert_eq!(sanitize_stream_id("  "), None);
        assert_eq!(sanitize_stream_id("a b/c=d.e").as_deref(), Some("abcde"));
        assert!(mint_run_identity(Some("!!")).0.starts_with("tallow-"));
        assert!(mint_run_identity(None).0.starts_with("tallow-"));
    }

    #[test]
    fn default_tor_proxy_url_binds_and_respects_the_opt_out() {
        let _guard = crate::runtime::egress_http::env_lock();
        let prev = std::env::var(TOR_ISOLATE_ENV).ok();

        // Default (unset): the per-run binding is on — the URL carries creds.
        unsafe { std::env::remove_var(TOR_ISOLATE_ENV) };
        let url = default_tor_proxy_url();
        assert!(
            url.starts_with("socks5h://") && url.contains('@') && url.ends_with("127.0.0.1:9050"),
            "the fail-closed default must bind per-run credentials: {url}"
        );
        // Stable within the process: one run = one identity = one circuit.
        assert_eq!(
            url,
            default_tor_proxy_url(),
            "the per-run identity must be minted once per process"
        );

        // Explicit opt-out restores the bare URL; junk must NOT downgrade.
        for (value, expect_bare) in [
            ("0", true),
            ("false", true),
            ("no", true),
            ("junk", false),
            ("", false),
        ] {
            unsafe { std::env::set_var(TOR_ISOLATE_ENV, value) };
            let got = default_tor_proxy_url();
            assert_eq!(
                got == TOR_SOCKS_URL,
                expect_bare,
                "TALLOW_TOR_ISOLATE={value:?} must {} the bare URL (got {got})",
                if expect_bare { "select" } else { "reject" }
            );
        }

        match prev {
            Some(v) => unsafe { std::env::set_var(TOR_ISOLATE_ENV, v) },
            None => unsafe { std::env::remove_var(TOR_ISOLATE_ENV) },
        }
    }
}
