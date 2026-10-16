//! `tallow.stdlib.cnam_dip` — Tier-D CNAM / LIDB displayed-name dip for a phone number.
//!
//! The P0 offline NANP allocation (see `phone_osint`) only knows the *assigned*
//! carrier from public NPA-NXX data. The caller-ID display label shown on a
//! receiving phone — the CNAM (Caller NAME / display name) — is stored in the
//! LIDB (Line Information Database) and is **not public data**. Retrieving it is
//! a **licensed**, key-gated provider API (e.g. iconectiv / TNS / Broadforward).
//!
//! This module implements the *real* dip rather than a stub:
//!   - configurable provider base URL (`TALLOW_CNAM_BASE_URL`) + API key
//!     (`TALLOW_CNAM_API_KEY`), matching the gate in `phone_osint`;
//!   - fail-closed egress: the proxy is resolved by the shared box contract
//!     (`crate::runtime::fetch::egress_proxy_url_ureq`: `TALLOW_PROXY` wins,
//!     `TALLOW_ALLOW_DIRECT` is the only opt-out, default = Tor
//!     `socks5h://127.0.0.1:9050`), and a configured-but-unusable proxy URL
//!     is a **hard refusal** (invariant N3) — never a silent degrade to direct;
//!   - request **building** and response **parsing** are pure functions with
//!     no network, so they are unit-testable offline.
//!
//! ## Honesty invariant (important)
//! CNAM is **known-unreliable** in the United States. A returned label is a
//! **best-effort, carrier-reported label** — frequently the *subscriber's billing
//! or account* label, not the person making the call, and often stale or absent
//! (wireless CNAM is spotty). The dip therefore carries a `carrier_reported_label`
//! flag and must **never** be presented as verified owner identity. If the
//! provider returns no name, the result surfaces `displayed_name: None` — never a
//! fabricated or guessed name.

use std::time::Duration;

/// One CNAM / LIDB displayed-name dip result.
///
/// `displayed_name` is `None` (never a guessed label) when the provider gave no
/// name. `carrier_reported_label` is **always `true`** when a name is present
/// (and `false` otherwise): it is the honest marker that this is the carrier's
/// subscription/account label, **not** verified owner identity.
#[derive(Debug, Clone, PartialEq)]
pub struct CnamDipResult {
    /// The carrier-reported customer/display label, if any (None = unknown).
    pub displayed_name: Option<String>,
    /// Honest caveat: the label is a carrier-reported subscription/account label,
    /// NOT verified owner identity. Always `true` when a name is present.
    pub carrier_reported_label: bool,
    /// The provider that served the dip (e.g. "iconectiv", "tns", "broadforward").
    pub provider: String,
    /// The entitlement gate that authorized this dip ("authorized" | "not-configured").
    pub provider_gate: String,
}

impl CnamDipResult {
    /// An honest "no label" result: no name, `carrier_reported_label` is `false`
    /// (there is no label to caveat), nothing is guessed.
    pub fn no_data(provider: &str) -> Self {
        CnamDipResult {
            displayed_name: None,
            carrier_reported_label: false,
            provider: provider.to_string(),
            provider_gate: "not-configured".to_string(),
        }
    }
}

/// Standard error message prefix for a provider that gave no usable label.
pub const NO_DATA: &str = "no-data";

/// Resolve the entitlement gate for the CNAM dip, mirroring the `LicensedDip`
/// gate in `phone_osint`. Returns `true` when `TALLOW_CNAM_API_KEY` is present.
pub fn provider_available() -> bool {
    match std::env::var("TALLOW_CNAM_API_KEY") {
        Ok(k) if !k.is_empty() => true,
        _ => false,
    }
}

/// Build a `reqwest` blocking `Request` for a single-number CNAM dip.
///
/// Pure: constructing a request against a **client** performs no network I/O,
/// so this is unit-testable entirely offline. The dip uses a `GET` with the
/// phone number as the `number` query parameter and the API key as an
/// `Authorization: Bearer *** header (the idiomatic key-gated shape for
/// CNAM/LIDB provider APIs). Provider is set via the `user-agent` header.
///
/// `tn` is sent exactly as given (caller normalizes to E.164 first).
pub fn build_cnam_request(
    client: &reqwest::blocking::Client,
    base_url: &str,
    key: &str,
    tn: &str,
) -> Result<reqwest::blocking::Request, String> {
    if base_url.is_empty() {
        return Err("build_cnam_request: base_url is empty".to_string());
    }
    if key.is_empty() {
        return Err("build_cnam_request: API key is empty".to_string());
    }
    if tn.is_empty() {
        return Err("build_cnam_request: phone number is empty".to_string());
    }

    let url = format!("{}{}", base_url, if base_url.contains('?') { "" } else { "?" });
    client
        .get(&url)
        .query(&[("number", tn)])
        .header("Authorization", format!("Bearer {key}"))
        .header("Accept", "application/json")
        .header("User-Agent", "tallow-cnam-dip/1.0")
        .build()
        .map_err(|e| format!("build_cnam_request: failed to build request: {e}"))
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
            actor: "stdlib.cnam_dip".to_string(),
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
            "cnam_dip: refusing to run unproxied — invalid proxy URL from \
             TALLOW_PROXY/TALLOW_TOR ({url}): {e}"
        )
    })?;
    match parsed.scheme() {
        "http" | "https" | "socks4" | "socks4a" | "socks5" | "socks5h" => {}
        other => {
            return Err(format!(
                "cnam_dip: refusing to run unproxied — unsupported proxy scheme \
                 '{other}' in TALLOW_PROXY/TALLOW_TOR ({url}); allowed: http, https, \
                 socks4, socks4a, socks5, socks5h"
            ));
        }
    }
    reqwest::Proxy::all(url).map_err(|e| {
        format!(
            "cnam_dip: refusing to run unproxied — invalid proxy URL from \
             TALLOW_PROXY/TALLOW_TOR ({url}): {e}"
        )
    })
}

/// Resolve the effective provider base URL + API key from env.
///
/// Returns `Err` (with a clear hint) when not configured, so a dip can never
/// silently hit a wrong/placeholder endpoint.
pub fn config_from_env() -> Result<(String, String), String> {
    let base_url = std::env::var("TALLOW_CNAM_BASE_URL").unwrap_or_default();
    let key = std::env::var("TALLOW_CNAM_API_KEY").unwrap_or_default();
    if base_url.is_empty() || key.is_empty() {
        return Err(
            "CNAM dip not configured: set TALLOW_CNAM_BASE_URL (provider endpoint) and \
             TALLOW_CNAM_API_KEY (licensed CNAM/LIDB key); unset, displayed name stays \
             unknown (never guessed)"
                .to_string(),
        );
    }
    Ok((base_url, key))
}

/// Perform a single-number CNAM dip against the configured provider.
///
/// `tn` should be a normalized E.164 string. Returns [`CnamDipResult`] on a
/// successfully parsed response, or `Err(NO_DATA …)` when the provider returned
/// no displayed label (never a guess).
pub fn dip_cnam(tn: &str) -> Result<CnamDipResult, String> {
    let tor = std::env::var("TALLOW_TOR")
        .map(|v| v == "1")
        .unwrap_or(false);
    let client = make_client(tor)?;
    let (base_url, key) = config_from_env()?;
    let request = build_cnam_request(&client, &base_url, &key, tn)?;

    let provider = provider_name(&base_url);
    let response = client
        .execute(request)
        .map_err(|e| format!("dip_cnam: request failed: {e}"))?;

    let status = response.status();
    let body = response
        .text()
        .map_err(|e| format!("dip_cnam: failed to read response body: {e}"))?;

    if !status.is_success() {
        return Err(format!(
            "dip_cnam: provider returned HTTP {}: {}",
            status.as_u16(),
            truncate(&body, 160)
        ));
    }

    let mut result = parse_cnam_response(&body)?;
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

/// Parse a provider CNAM/LIDB response JSON into a [`CnamDipResult`].
///
/// Pure (no network), so unit-testable offline. Tolerant of a top-level
/// `data` wrapper and of common field spellings for the display label:
///   - `displayed_name`, `cnam`, `caller_name`, `name`, `label`, `display_name`
///
/// Returns `Err(NO_DATA …)` when the body contains no usable label. When a
/// label is present, `carrier_reported_label` is set to `true` — the honest
/// caveat that this is a carrier-reported subscription/account label, NOT
/// verified owner identity.
pub fn parse_cnam_response(body: &str) -> Result<CnamDipResult, String> {
    if body.trim().is_empty() {
        return Err(format!("{NO_DATA}: empty provider response body"));
    }

    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| format!("parse_cnam_response: invalid JSON: {e}"))?;

    // Unwrap a top-level `data`/`result` wrapper if present.
    let root = if value.get("data").is_some() {
        &value["data"]
    } else if value.get("result").is_some() {
        &value["result"]
    } else {
        &value
    };

    let mut displayed_name: Option<String> = None;
    for k in ["displayed_name", "display_name", "cnam", "caller_name", "name", "label"] {
        if let Some(v) = root.get(k) {
            if let Some(s) = v.as_str() {
                let s = s.trim();
                if !s.is_empty() {
                    displayed_name = Some(s.to_string());
                    break;
                }
            }
        }
    }

    // Honesty: if no label, there is no usable fact — surface a clear no-data
    // result, never a guess, and never invent an identity.
    let name = match displayed_name {
        Some(n) => n,
        None => {
            return Err(format!(
                "{NO_DATA}: provider response contained no displayed-name label: {body}"
            ))
        }
    };

    // A name from CNAM/LIDB is ALWAYS a carrier-reported subscription/account
    // label; flag it honestly. It must never be treated as verified identity.
    Ok(CnamDipResult {
        displayed_name: Some(name),
        carrier_reported_label: true,
        provider: String::new(), // filled by dip_cnam
        provider_gate: "authorized".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1. Request building: key lands in the Authorization header, TN in the
    ///    query param, URL is well-formed. Client construction is offline.
    #[test]
    fn build_cnam_request_sets_bearer_and_tn() {
        let client = reqwest::blocking::Client::new();
        let req = build_cnam_request(
            &client,
            "https://api.cnam.example.org/lookup",
            "secret-key-123",
            "+151****1815",
        )
        .expect("request should build");

        assert_eq!(req.method(), reqwest::Method::GET);
        let url = req.url();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("api.cnam.example.org"));
        assert_eq!(
            url.query_pairs().find(|(k, _)| k == "number").map(|(_, v)| v.to_string()),
            Some("+151****1815".to_string())
        );
        let auth = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .expect("auth header present");
        assert_eq!(auth, "Bearer secret-key-123");
    }

    /// 2. Request building rejects empty key / tn / base_url.
    #[test]
    fn build_cnam_request_rejects_empty_inputs() {
        let client = reqwest::blocking::Client::new();
        assert!(build_cnam_request(&client, "", "k", "123").is_err());
        assert!(build_cnam_request(&client, "http://x", "", "123").is_err());
        assert!(build_cnam_request(&client, "http://x", "k", "").is_err());
    }

    /// 3. Happy-path JSON (top-level and `data`-wrapped) -> parsed result with
    ///    the honest `carrier_reported_label` caveat always `true`.
    #[test]
    fn parse_happy_path() {
        let r = parse_cnam_response(r#"{"displayed_name": "JOHN DOE"}"#)
            .expect("should parse");
        assert_eq!(r.displayed_name.as_deref(), Some("JOHN DOE"));
        assert!(r.carrier_reported_label, "label must be flagged carrier-reported");

        // data-wrapped + alternate field spelling (`caller_name`).
        let r2 = parse_cnam_response(
            r#"{"data": {"caller_name": "A. SMITH"}}"#,
        )
        .expect("data wrapper should parse");
        assert_eq!(r2.displayed_name.as_deref(), Some("A. SMITH"));
        assert!(r2.carrier_reported_label);
    }

    /// 4. Honesty: a recognizable empty/no-label body -> `Err(NO_DATA)`, never a
    ///    fabricated or guessed name.
    #[test]
    fn parse_empty_data_returns_no_data() {
        let err = parse_cnam_response(r#"{"displayed_name": ""}"#).unwrap_err();
        assert!(err.starts_with(NO_DATA), "got: {err}");

        let err2 = parse_cnam_response(r#"{"status": "ok", "message": "lookup complete"}"#)
            .unwrap_err();
        assert!(err2.starts_with(NO_DATA), "got: {err2}");

        // Malformed / non-JSON is also an error.
        assert!(parse_cnam_response("not json at all").is_err());
    }

    /// no_data() is honest: no displayed name, caveat flag `false` (no label to
    /// caveat), gate reports not-configured.
    #[test]
    fn no_data_result_is_honest() {
        let d = CnamDipResult::no_data("iconectiv");
        assert_eq!(d.displayed_name, None);
        assert!(!d.carrier_reported_label);
        assert_eq!(d.provider_gate, "not-configured");
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
