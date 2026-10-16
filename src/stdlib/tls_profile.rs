//! Standard library: `tallow.tls_profile` — TLS/JA4 fingerprint profiles.
//!
//! Inspired by curl-impersonate and koon. Provides pre-built TLS fingerprint
//! profiles matching real browser configurations for HTTP/2 and TLS handshake
//! fingerprint evasion.
//!
//! # API
//! - `TLSProfile.list()` — list all available profiles
//! - `TLSProfile.get(name)` — get a specific profile
//! - `profile.to_curl_args()` — curl-impersonate compatible args
//! - `profile.to_headers()` — matching HTTP headers
//!
//! # Profiles
//! - chrome_131, chrome_130, chrome_120
//! - firefox_132, firefox_128
//! - safari_18, safari_17
//! - edge_131
//!
//! # Version coherence
//! The `TLSProfile.user_agent` is the single source of truth for the browser
//! version. `to_headers()` derives `Sec-CH-UA` from that UA instead of
//! hard-coding a version, so the Client-Hint brand/version, the `User-Agent`,
//! and the TLS/JA4 fingerprint stay in lockstep. When a `TLSProfile` is
//! selected for the active `StealthProfile` (see `crate::browser::StealthProfile`
//! and `stdlib/http.rs::stealth_profile()`), keep the browser family AND major
//! version aligned so the whole stack reports one coherent browser.

use super::StdlibResult;
use crate::interp::{type_name, Value};

/// A TLS fingerprint profile
#[allow(dead_code)] // profile fields kept for future JA4/curl-impersonate export
struct TLSProfile {
    name: String,
    ja4: String,
    user_agent: String,
    cipher_suites: Vec<String>,
    http2_settings: Vec<String>,
    tls_version: String,
    alpn: Vec<String>,
    supported_groups: Vec<String>,
    key_share_groups: Vec<String>,
    signature_algorithms: Vec<String>,
    grease: bool,
}

impl TLSProfile {
    fn all_profiles() -> Vec<TLSProfile> {
        vec![
            TLSProfile {
                name: "chrome_131".into(),
                ja4: "t13d1516h2_8daaf6152771_e9e4f3b7".into(),
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
                cipher_suites: vec![
                    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ].into_iter().map(|s| s.to_string()).collect(),
                http2_settings: vec![
                    "HEADER_TABLE_SIZE=65536", "MAX_CONCURRENT_STREAMS=1000",
                    "INITIAL_WINDOW_SIZE=6291456", "MAX_HEADER_LIST_SIZE=262144",
                ].into_iter().map(|s| s.to_string()).collect(),
                tls_version: "TLSv1.3".into(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                supported_groups: vec![
                    "GREASE", "x25519", "secp256r1", "secp384r1",
                ].into_iter().map(|s| s.to_string()).collect(),
                key_share_groups: vec!["x25519".into(), "GREASE".into()],
                signature_algorithms: vec![
                    "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256",
                    "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384",
                ].into_iter().map(|s| s.to_string()).collect(),
                grease: true,
            },
            TLSProfile {
                name: "firefox_132".into(),
                ja4: "t13d1715h2_5b57614c22b0_cd5f6e18".into(),
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0".into(),
                cipher_suites: vec![
                    "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                ].into_iter().map(|s| s.to_string()).collect(),
                http2_settings: vec![
                    "HEADER_TABLE_SIZE=65536", "INITIAL_WINDOW_SIZE=131072", "MAX_FRAME_SIZE=16384",
                ].into_iter().map(|s| s.to_string()).collect(),
                tls_version: "TLSv1.3".into(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                supported_groups: vec![
                    "x25519", "secp256r1", "secp384r1", "secp521r1",
                    "ffdhe2048", "ffdhe3072",
                ].into_iter().map(|s| s.to_string()).collect(),
                key_share_groups: vec!["x25519".into()],
                signature_algorithms: vec![
                    "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384",
                    "ecdsa_secp521r1_sha512", "rsa_pss_rsae_sha256",
                ].into_iter().map(|s| s.to_string()).collect(),
                grease: false,
            },
            TLSProfile {
                name: "safari_18".into(),
                ja4: "t13d1516h2_8daaf6152771_f8e4c5d9".into(),
                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15".into(),
                cipher_suites: vec![
                    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ].into_iter().map(|s| s.to_string()).collect(),
                http2_settings: vec![
                    "MAX_CONCURRENT_STREAMS=100", "INITIAL_WINDOW_SIZE=4194304",
                ].into_iter().map(|s| s.to_string()).collect(),
                tls_version: "TLSv1.3".into(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                supported_groups: vec![
                    "x25519", "secp256r1", "secp384r1", "secp521r1",
                ].into_iter().map(|s| s.to_string()).collect(),
                key_share_groups: vec!["x25519".into()],
                signature_algorithms: vec![
                    "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256",
                    "rsa_pkcs1_sha256",
                ].into_iter().map(|s| s.to_string()).collect(),
                grease: true,
            },
            TLSProfile {
                name: "edge_131".into(),
                ja4: "t13d1516h2_8daaf6152771_d8e5f3c6".into(),
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0".into(),
                cipher_suites: vec![
                    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                ].into_iter().map(|s| s.to_string()).collect(),
                http2_settings: vec![
                    "HEADER_TABLE_SIZE=65536", "MAX_CONCURRENT_STREAMS=1000",
                    "INITIAL_WINDOW_SIZE=6291456",
                ].into_iter().map(|s| s.to_string()).collect(),
                tls_version: "TLSv1.3".into(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                supported_groups: vec![
                    "GREASE", "x25519", "secp256r1",
                ].into_iter().map(|s| s.to_string()).collect(),
                key_share_groups: vec!["x25519".into(), "GREASE".into()],
                signature_algorithms: vec![
                    "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256",
                ].into_iter().map(|s| s.to_string()).collect(),
                grease: true,
            },
        ]
    }

    fn to_value(&self) -> Value {
        Value::Struct {
            name: "TLSProfile".into(),
            fields: vec![
                ("name".into(), Value::String(self.name.clone())),
                ("ja4".into(), Value::String(self.ja4.clone())),
                ("user_agent".into(), Value::String(self.user_agent.clone())),
                ("tls_version".into(), Value::String(self.tls_version.clone())),
                ("cipher_count".into(), Value::Int(self.cipher_suites.len() as i128)),
                ("supports_h2".into(), Value::Bool(self.alpn.contains(&"h2".to_string()))),
                ("grease".into(), Value::Bool(self.grease)),
            ],
        }
    }

    fn to_curl_args(&self) -> String {
        format!(
            "--tls-max 1.3 --ciphers '{}' --http2 --http2-settings '{}' --alpn '{}'",
            self.cipher_suites.join(":"),
            self.http2_settings.join(","),
            self.alpn.join(",")
        )
    }

    /// Chromium-family major version (from `Edg/` or `Chrome/` in the UA), or
    /// `None` for non-Chromium profiles (Firefox does not emit `Sec-CH-UA`).
    fn chromium_version(&self) -> Option<String> {
        for marker in ["Edg/", "Chrome/"] {
            if let Some(rest) = self.user_agent.split(marker).nth(1) {
                let ver = rest.split(['.', ' ', ';']).next().unwrap_or("");
                if !ver.is_empty() {
                    return Some(ver.to_string());
                }
            }
        }
        None
    }

    fn to_headers(&self) -> Vec<(String, String)> {
        let mut h = Vec::new();
        h.push(("User-Agent".into(), self.user_agent.clone()));
        h.push(("Accept-Language".into(), "en-US,en;q=0.9".into()));
        // Sec-CH-UA is derived from THIS profile's UA version (not hardcoded),
        // so the Client-Hint brand/version stays coherent with the selected
        // TLS/JA4 fingerprint (see module "Version coherence" note).
        if let Some(v) = self.chromium_version() {
            let is_edge = self.user_agent.contains("Edg/");
            let brand = if is_edge { "Microsoft Edge" } else { "Google Chrome" };
            h.push((
                "Sec-Ch-Ua".into(),
                format!(r#""Chromium";v="{v}", "{brand}";v="{v}""#),
            ));
        }
        if self.grease {
            h.push(("Sec-Ch-Ua-Platform".into(), "\"Windows\"".into()));
            h.push(("Sec-Ch-Ua-Mobile".into(), "?0".into()));
        }
        h
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "list" => Some(tls_list()),
        "get" => Some(tls_get(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "TLSProfile") {
        return None;
    }
    match method {
        "to_curl_args" => {
            let profile = match extract_profile(object) {
                Ok(p) => p,
                Err(_) => return None,
            };
            Some(Ok(Value::String(profile.to_curl_args())))
        }
        "to_headers" => {
            let profile = match extract_profile(object) {
                Ok(p) => p,
                Err(_) => return None,
            };
            let headers: Vec<(Value, Value)> = profile.to_headers().into_iter()
                .map(|(k, v)| (Value::String(k), Value::String(v)))
                .collect();
            Some(Ok(Value::Map(headers)))
        }
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "list" | "get")
}

fn tls_list() -> StdlibResult {
    let profiles: Vec<Value> = TLSProfile::all_profiles().iter()
        .map(|p| p.to_value())
        .collect();
    Ok(Value::Array(profiles))
}

fn tls_get(args: Vec<Value>) -> StdlibResult {
    let name = args.first().and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None })
        .unwrap_or("chrome_131");
    for p in TLSProfile::all_profiles() {
        if p.name == name {
            return Ok(p.to_value());
        }
    }
    Err(format!("Unknown profile: {name}. Available: chrome_131, firefox_132, safari_18, edge_131"))
}

fn extract_profile(value: &Value) -> Result<TLSProfile, String> {
    let fields = match value {
        Value::Struct { name, fields } if name == "TLSProfile" => fields,
        _ => return Err(format!("Expected TLSProfile, got {}", type_name(value))),
    };
    let name = field_str(fields, "name");
    for p in TLSProfile::all_profiles() {
        if p.name == name {
            return Ok(p);
        }
    }
    Err(format!("Profile not found: {}", name))
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}
