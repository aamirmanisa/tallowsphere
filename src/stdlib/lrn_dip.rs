//! `tallow.stdlib.lrn_dip` — Tier-C LRN / NPAC current-carrier dip for a phone number.
//!
//! The P0 offline NANP allocation (see `phone_osint`) only knows the *assigned*
//! carrier from public NPA-NXX data. After a number is **ported**, the assigned
//! carrier is wrong. The authoritative answer requires a Tier-C LRN (Local
//! Routing Number) dip against an NPAC/porting database — a **licensed**,
//! key-gated provider API (e.g. iconectiv PortData / Alcazar / TNS).
//!
//! This module implements the *real* dip rather than a stub:
//!   - configurable provider base URL (`TALLOW_LRN_BASE_URL`) + API key
//!     (`TALLOW_LRN_API_KEY`), matching the gate in `phone_osint`;
//!   - fail-closed egress: the proxy is resolved by the shared box contract
//!     (`crate::runtime::fetch::egress_proxy_url_ureq`: `TALLOW_PROXY` wins,
//!     `TALLOW_ALLOW_DIRECT` is the only opt-out, default = Tor
//!     `socks5h://127.0.0.1:9050`), and a configured-but-unusable proxy URL
//!     is a **hard refusal** (invariant N3) — never a silent degrade to direct;
//!   - request **building** and response **parsing** are pure functions with
//!     no network, so they are unit-testable offline.
//!
//! ## Honesty invariant
//! A ported/carrier value is **never guessed**. If the provider returns no
//! ported/carrier/OCN data, the result is surfaced as a clear `no-data` error —
//! the caller must report `unknown`, never a fabricated carrier name.

use std::time::Duration;

/// One current-carrier dip result.
///
/// `ported` is only `true` when the provider asserts the number has been
/// ported from its as-allocated carrier. `current_carrier` and `ocn` are empty
/// strings (never a guessed value) when the provider gave no data.
#[derive(Debug, Clone, PartialEq)]
pub struct LrnDipResult {
    /// Whether the number has been ported away from its assigned carrier.
    pub ported: bool,
    /// The carrier presently routing this number (empty = unknown / no data).
    pub current_carrier: String,
    /// Operating Company Number (4-char) of the current carrier (empty = unknown).
    pub ocn: String,
    /// The provider that served the dip (e.g. "iconectiv", "alcazar", "tns").
    pub provider: String,
    /// The entitlement gate that authorized this dip ("authorized" | "not-configured").
    pub provider_gate: String,
}

impl LrnDipResult {
    /// An honest "no data" result: nothing is guessed, `current_carrier`/`ocn`
    /// are empty and `ported` is `false` (we do not know).
    pub fn no_data(provider: &str) -> Self {
        LrnDipResult {
            ported: false,
            current_carrier: String::new(),
            ocn: String::new(),
            provider: provider.to_string(),
            provider_gate: "not-configured".to_string(),
        }
    }
}

/// Standard error message prefix for a provider that gave no usable data.
pub const NO_DATA: &str = "no-data";

/// Resolve the entitlement gate for the LRN dip, mirroring the `LicensedDip`
/// gate in `phone_osint`. Returns `true` when `TALLOW_LRN_API_KEY` is present.
pub fn provider_available() -> bool {
    match std::env::var("TALLOW_LRN_API_KEY") {
        Ok(k) if !k.is_empty() => true,
        _ => false,
    }
}

/// Build a `reqwest` blocking `Request` for a single-number LRN dip.
///
/// Pure: constructing a request against a **client** performs no network I/O,
/// so this is unit-testable entirely offline. The dip uses a `GET` with the
/// phone number as the `number` query parameter and the API key as an
/// `Authorization: Bearer <key>` header (the idiomatic key-gated shape for
/// NPAC/porting provider APIs). Provider is set via the `user-agent` header.
///
/// `tn` is sent exactly as given (caller normalizes to E.164 first).
pub fn build_lrn_request(
    client: &reqwest::blocking::Client,
    base_url: &str,
    key: &str,
    tn: &str,
) -> Result<reqwest::blocking::Request, String> {
    if base_url.is_empty() {
        return Err("build_lrn_request: base_url is empty".to_string());
    }
    if key.is_empty() {
        return Err("build_lrn_request: API key is empty".to_string());
    }
    if tn.is_empty() {
        return Err("build_lrn_request: phone number is empty".to_string());
    }

    // Append the tn as a query param via reqwest's `.query()`, which
    // percent-encodes the value (a raw `+` in `+151...1815` would otherwise be
    // decoded as a space by form-urlencoded semantics, corrupting the number).
    let url = format!("{}{}", base_url, if base_url.contains('?') { "" } else { "?" });
    client
        .get(&url)
        .query(&[("number", tn)])
        .header("Authorization", format!("Bearer {key}"))
        .header("Accept", "application/json")
        .header("User-Agent", "tallow-lrn-dip/1.0")
        .build()
        .map_err(|e| format!("build_lrn_request: failed to build request: {e}"))
}

/// Build a blocking `reqwest` client with fail-closed egress (invariant N3).
///
/// The proxy is resolved by the shared egress contract
/// (`crate::runtime::fetch::egress_proxy_url_ureq`, the same resolver
/// `src/runtime/egress_http.rs` uses): `TALLOW_PROXY` wins,
/// `TALLOW_ALLOW_DIRECT=1|true|yes` is the only opt-out, and the fail-closed
/// default is Tor (`socks5h://127.0.0.1:9050`, remote DNS). The `tor` flag is
/// retained for call-site compatibility only — the contract default is
/// already Tor, so it no longer changes where traffic goes.
///
/// A configured-but-unusable proxy URL is a **hard refusal**: this returns
/// `Err` and no request is attempted. The previous `if let Ok(proxy)` behavior
/// was a silent degrade to direct — the leak class invariant N3 retires. The
/// message mirrors `src/runtime/egress_http.rs`.
pub fn make_client(tor: bool) -> Result<reqwest::blocking::Client, String> {
    // Egress contract is authoritative (see doc above); `tor` is redundant.
    let _ = tor;

    let mut builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(15));

    if let Some(url) = crate::runtime::fetch::egress_proxy_url_ureq() {
        // Refuse, never degrade: a junk proxy URL must not silently build an
        // unproxied client (N3). reqwest with the `socks` feature accepts
        // http/https/socks4/socks4a/socks5/socks5h; anything else is junk.
        builder = builder.proxy(proxy_for_url(&url)?);
    }

    builder
        .build()
        .map_err(|e| format!("make_client: failed to build client: {e}"))
}

/// Refusal computation for the dip clients (invariant N3): `Ok(proxy)` when
/// `url` parses into a usable `reqwest::Proxy` (request may be proxied),
/// `Err(reason)` when the configured proxy URL is unusable — callers attempt
/// **no** request. Extracted from [`make_client`] so the refusal is testable
/// without mutating process env (env mutation would race the env-based
/// egress tests). On refusal one redacted security event is emitted
/// (best-effort, see [`emit_refusal`]) immediately before the `Err` is
/// returned — the refusal's outcome never depends on telemetry (T-115b,
/// R-6.13).
fn proxy_for_url(url: &str) -> Result<reqwest::Proxy, String> {
    match proxy_for_url_inner(url) {
        Ok(proxy) => Ok(proxy),
        Err(reason) => {
            emit_refusal(url);
            Err(reason)
        }
    }
}

/// Best-effort refusal telemetry (R-6.1 slice 1 wiring, T-115b): one
/// redacted security event at the observability choke point immediately
/// before a dip refusal is returned. Emit errors are ignored — only the
/// `Err` return makes the refusal real.
fn emit_refusal(url: &str) {
    let _ = crate::observability::emit_to_default_journal(
        &crate::observability::SecurityEvent {
            class: crate::observability::EventClass::EgressRefusal,
            actor: "stdlib.lrn_dip".to_string(),
            target: Some(url.to_string()),
            size: url.len(),
            at_ms: crate::observability::now_ms(),
        },
    );
}

/// Body of [`proxy_for_url`]: `Ok` when `url` is a usable proxy, `Err(reason)`
/// on every unusable form. Kept emission-free so [`proxy_for_url`] emits once
/// for the whole refusal surface.
fn proxy_for_url_inner(url: &str) -> Result<reqwest::Proxy, String> {
    // Explicit scheme allow-list (invariant N3): `reqwest::Proxy::all` accepts
    // unknown schemes WITHOUT error (verified empirically), and a proxy with an
    // unrecognized scheme is not applied to requests — a silent direct-egress
    // path. Only schemes reqwest can actually use pass (the `socks` feature is
    // enabled in the root manifest).
    let parsed = reqwest::Url::parse(url).map_err(|e| {
        format!(
            "lrn_dip: refusing to run unproxied — invalid proxy URL from \
             TALLOW_PROXY/TALLOW_TOR ({url}): {e}"
        )
    })?;
    match parsed.scheme() {
        "http" | "https" | "socks4" | "socks4a" | "socks5" | "socks5h" => {}
        other => {
            return Err(format!(
                "lrn_dip: refusing to run unproxied — unsupported proxy scheme \
                 '{other}' in TALLOW_PROXY/TALLOW_TOR ({url}); allowed: http, https, \
                 socks4, socks4a, socks5, socks5h"
            ));
        }
    }
    reqwest::Proxy::all(url).map_err(|e| {
        format!(
            "lrn_dip: refusing to run unproxied — invalid proxy URL from \
             TALLOW_PROXY/TALLOW_TOR ({url}): {e}"
        )
    })
}

/// Resolve the effective provider base URL + API key from env.
///
/// Returns `Err` (with a clear hint) when not configured, so a dip can never
/// silently hit a wrong/placeholder endpoint.
pub fn config_from_env() -> Result<(String, String), String> {
    let base_url = std::env::var("TALLOW_LRN_BASE_URL").unwrap_or_default();
    let key = std::env::var("TALLOW_LRN_API_KEY").unwrap_or_default();
    if base_url.is_empty() || key.is_empty() {
        return Err(
            "LRN dip not configured: set TALLOW_LRN_BASE_URL (provider endpoint) and \
             TALLOW_LRN_API_KEY (licensed NPAC/LRN key); unset, current carrier stays \
             unknown (never guessed)"
                .to_string(),
        );
    }
    Ok((base_url, key))
}

/// Perform a single-number LRN dip against the configured provider.
///
/// `tn` should be a normalized E.164 string (e.g. "+15128501815"). Returns
/// [`LrnDipResult`] on a successfully parsed response, or `Err(NO_DATA …)`
/// when the provider returned no ported/carrier/OCN facts (never a guess).
pub fn dip_lrn(tn: &str) -> Result<LrnDipResult, String> {
    let tor = std::env::var("TALLOW_TOR")
        .map(|v| v == "1")
        .unwrap_or(false);
    let client = make_client(tor)?;
    let (base_url, key) = config_from_env()?;
    let request = build_lrn_request(&client, &base_url, &key, tn)?;

    let provider = provider_name(&base_url);
    let response = client
        .execute(request)
        .map_err(|e| format!("dip_lrn: request failed: {e}"))?;

    let status = response.status();
    let body = response
        .text()
        .map_err(|e| format!("dip_lrn: failed to read response body: {e}"))?;

    if !status.is_success() {
        return Err(format!(
            "dip_lrn: provider returned HTTP {}: {}",
            status.as_u16(),
            truncate(&body, 160)
        ));
    }

    let mut result = parse_lrn_response(&body)?;
    result.provider = provider;
    result.provider_gate = "authorized".to_string();
    Ok(result)
}

/// Derive a short provider label from a base URL (purely a label, not data).
fn provider_name(base_url: &str) -> String {
    if base_url.is_empty() {
        return "unknown".to_string();
    }
    let clean = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = clean.split('/').next().unwrap_or("unknown");
    let host = host.split('.').next().unwrap_or(host);
    if host.is_empty() {
        "unknown".to_string()
    } else {
        host.to_string()
    }
}

/// Truncate a string for error messages.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push_str("…");
        out
    }
}

/// Parse a provider LRN-dip JSON response into a [`LrnDipResult`].
///
/// Pure (no network), so unit-testable offline. Tolerant of a top-level
/// `data` wrapper and of common field spellings:
///   - ported: `ported`, `is_ported`, `number_ported`, ported-as-string
///   - carrier: `current_carrier`, `carrier`, `carrier_name`, `spid`
///   - ocn: `ocn`, `lrn`
///
/// Returns `Err(NO_DATA …)` when the body contains no ported/carrier/OCN facts.
pub fn parse_lrn_response(body: &str) -> Result<LrnDipResult, String> {
    if body.trim().is_empty() {
        return Err(format!("{NO_DATA}: empty provider response body"));
    }

    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| format!("parse_lrn_response: invalid JSON: {e}"))?;

    // Unwrap a top-level `data`/`result` wrapper if present.
    let root = if value.get("data").is_some() {
        &value["data"]
    } else if value.get("result").is_some() {
        &value["result"]
    } else {
        &value
    };

    let get_str = |obj: &serde_json::Value, keys: &[&str]| -> String {
        for k in keys {
            if let Some(v) = obj.get(*k) {
                if let Some(s) = v.as_str() {
                    if !s.trim().is_empty() {
                        return s.trim().to_string();
                    }
                }
            }
        }
        String::new()
    };

    let carrier = get_str(root, &["current_carrier", "carrier", "carrier_name", "spid"]);
    let ocn = get_str(root, &["ocn", "lrn"]);

    // ported flag: accept a bool or a "ported"/"not_ported"/"true"/"false" string.
    fn as_bool(v: Option<&serde_json::Value>) -> Option<bool> {
        match v {
            Some(serde_json::Value::Bool(b)) => Some(*b),
            Some(serde_json::Value::String(s)) => match s.to_lowercase().as_str() {
                "1" | "true" | "yes" | "ported" | "y" => Some(true),
                "0" | "false" | "no" | "not_ported" | "not-ported" | "n" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }
    let ported = as_bool(root.get("ported"))
        .or_else(|| as_bool(root.get("is_ported")))
        .or_else(|| as_bool(root.get("number_ported")))
        .unwrap_or(false);

    // Honesty: if we have neither a carrier nor an OCN, there is no usable
    // carrier fact — surface a clear no-data result, never a guess.
    if carrier.is_empty() && ocn.is_empty() && !ported {
        return Err(format!(
            "{NO_DATA}: provider response contained no ported/carrier/ocn facts: {body}"
        ));
    }

    Ok(LrnDipResult {
        ported,
        current_carrier: carrier,
        ocn,
        provider: String::new(), // filled by dip_lrn
        provider_gate: "authorized".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1. Request building: key lands in the Authorization header, TN in the
    ///    query param, URL is well-formed. Client construction is offline.
    #[test]
    fn build_lrn_request_sets_bearer_and_tn() {
        let client = reqwest::blocking::Client::new();
        let req = build_lrn_request(
            &client,
            "https://api.porting.example.org/lrn",
            "secret-key-123",
            "+15128501815",
        )
        .expect("request should build");

        assert_eq!(req.method(), reqwest::Method::GET);
        let url = req.url();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("api.porting.example.org"));
        // TN present in the query.
        assert_eq!(
            url.query_pairs().find(|(k, _)| k == "number").map(|(_, v)| v.to_string()),
            Some("+15128501815".to_string())
        );
        // Bearer key in the auth header.
        let auth = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .expect("auth header present");
        assert_eq!(auth, "Bearer secret-key-123");
    }

    /// Request building rejects empty key / tn / base_url.
    #[test]
    fn build_lrn_request_rejects_empty_inputs() {
        let client = reqwest::blocking::Client::new();
        assert!(build_lrn_request(&client, "", "k", "123").is_err());
        assert!(build_lrn_request(&client, "http://x", "", "123").is_err());
        assert!(build_lrn_request(&client, "http://x", "k", "").is_err());
    }

    /// 2. Malformed / non-JSON body -> Err (never a guessed carrier).
    #[test]
    fn parse_malformed_body_is_err() {
        assert!(parse_lrn_response("").is_err());
        assert!(parse_lrn_response("not json at all").is_err());
        assert!(parse_lrn_response(r#"{"carrier": "[""#).is_err());
    }

    /// 3. Happy-path JSON (top-level and `data`-wrapped) -> parsed result.
    #[test]
    fn parse_happy_path() {
        let r = parse_lrn_response(
            r#"{"ported": true, "current_carrier": "AT&T Mobility", "ocn": "0202"}"#,
        )
        .expect("should parse");
        assert!(r.ported);
        assert_eq!(r.current_carrier, "AT&T Mobility");
        assert_eq!(r.ocn, "0202");

        // data-wrapped + alternate field spellings.
        let r2 = parse_lrn_response(
            r#"{"data": {"is_ported": "ported", "carrier_name": "Verizon", "lrn": "0115"}}"#,
        )
        .expect("data wrapper should parse");
        assert!(r2.ported);
        assert_eq!(r2.current_carrier, "Verizon");
        assert_eq!(r2.ocn, "0115");
    }

    /// 4. Documented no-data case: a recognizable-but-empty body produces
    ///    `Err(NO_DATA)` rather than a fabricated carrier.
    #[test]
    fn parse_empty_data_returns_no_data() {
        let err = parse_lrn_response(r#"{"ported": false}"#).unwrap_err();
        assert!(err.starts_with(NO_DATA), "got: {err}");

        // Body with unrelated fields only is also no-data.
        let err2 = parse_lrn_response(r#"{"status": "ok", "message": "lookup complete"}"#)
            .unwrap_err();
        assert!(err2.starts_with(NO_DATA), "got: {err2}");
    }

    /// no_data() is honest: empty carrier/ocn, ported=false.
    #[test]
    fn no_data_result_is_honest() {
        let d = LrnDipResult::no_data("alcazar");
        assert_eq!(d.current_carrier, "");
        assert_eq!(d.ocn, "");
        assert!(!d.ported);
    }
    /// 5. Egress fail-closed (invariant N3): a configured-but-unusable proxy
    ///    URL refuses via `Err` — never a silent degrade to a direct client.
    ///    Pure over its input (no env reads), so it cannot race env-based tests.
    #[test]
    fn unusable_proxy_url_refuses_instead_of_going_direct() {
        // Unknown scheme -> explicit allow-list refuses -> no direct fallback.
        let err = proxy_for_url("bogus://127.0.0.1:1").unwrap_err();
        assert!(err.contains("refusing to run unproxied"), "got: {err}");

        // Malformed URL -> refusal too.
        let err2 = proxy_for_url("not a url").unwrap_err();
        assert!(err2.contains("refusing"), "got: {err2}");

        // The fail-closed default (socks5h = remote DNS) is usable, as is the
        // socks scheme set reqwest-with-`socks` accepts.
        assert!(proxy_for_url("socks5h://127.0.0.1:9050").is_ok());
        assert!(proxy_for_url("socks5://127.0.0.1:9050").is_ok());
    }
}
