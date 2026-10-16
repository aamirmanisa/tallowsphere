//! Anti-bot vendor detection engine.
//!
//! Identifies which anti-bot system a site uses from multiple signal types:
//! response headers, cookies, HTML content, script URLs, status codes, and
//! challenge page patterns. Returns confidence-scored detections with
//! recommended bypass strategies per vendor.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Vendor enum
// ─────────────────────────────────────────────────────────────────────────────

/// Known anti-bot / WAF vendors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiBotVendor {
    Cloudflare,
    CloudflareTurnstile,
    Akamai,
    PerimeterX,
    DataDome,
    Kasada,
    /// F5 Shape Security.
    ShapeSecurity,
    /// Imperva / Incapsula.
    Imperva,
    AwsWaf,
    GoogleRecaptcha,
    HCaptcha,
    /// FunCaptcha.
    ArkoseLabs,
    GeeTest,
    /// Now part of Imperva.
    Distil,
    Reblaze,
    /// Radware Bot Manager.
    Radware,
    Barracuda,
    Unknown(String),
}

impl AntiBotVendor {
    /// Human-readable display name.
    pub fn name(&self) -> &str {
        match self {
            Self::Cloudflare => "Cloudflare",
            Self::CloudflareTurnstile => "Cloudflare Turnstile",
            Self::Akamai => "Akamai Bot Manager",
            Self::PerimeterX => "PerimeterX / HUMAN",
            Self::DataDome => "DataDome",
            Self::Kasada => "Kasada",
            Self::ShapeSecurity => "Shape Security (F5)",
            Self::Imperva => "Imperva / Incapsula",
            Self::AwsWaf => "AWS WAF",
            Self::GoogleRecaptcha => "Google reCAPTCHA",
            Self::HCaptcha => "hCaptcha",
            Self::ArkoseLabs => "Arkose Labs (FunCaptcha)",
            Self::GeeTest => "GeeTest",
            Self::Distil => "Distil Networks (Imperva)",
            Self::Reblaze => "Reblaze",
            Self::Radware => "Radware Bot Manager",
            Self::Barracuda => "Barracuda WAF",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal types
// ─────────────────────────────────────────────────────────────────────────────

/// How a signal was observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalType {
    ResponseHeader,
    Cookie,
    HtmlContent,
    ScriptUrl,
    StatusCode,
    ServerHeader,
    ChallengeType,
}

/// A single piece of evidence contributing to a vendor detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub signal_type: SignalType,
    /// The raw value that matched (e.g. header value, cookie name, HTML snippet).
    pub value: String,
    /// How much this signal contributes to detection (0.0 – 1.0).
    pub weight: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection result
// ─────────────────────────────────────────────────────────────────────────────

/// A single vendor detection with confidence and supporting evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorDetection {
    pub vendor: AntiBotVendor,
    /// Aggregated confidence score (0.0 – 1.0).
    pub confidence: f64,
    /// Individual signals that contributed to this detection.
    pub signals: Vec<DetectionSignal>,
    /// Recommended strategy for bypassing this vendor.
    pub recommended_strategy: VendorStrategy,
}

// ─────────────────────────────────────────────────────────────────────────────
// Vendor strategy
// ─────────────────────────────────────────────────────────────────────────────

/// Recommended configuration for bypassing a particular anti-bot vendor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorStrategy {
    /// Minimum proxy quality tier: "residential", "mobile", "datacenter", "isp".
    pub min_proxy_tier: String,
    /// Whether a real browser (Chrome via CDP) is required.
    pub requires_browser: bool,
    /// Whether cookie farming is needed before HTTP-only requests work.
    pub requires_cookie_farm: bool,
    /// Effective cookie lifetime in seconds.
    pub cookie_ttl_seconds: u64,
    /// Maximum safe request rate.
    pub max_requests_per_second: f64,
    /// Whether a warm-up navigation sequence is needed first.
    pub warmup_required: bool,
    /// TLS client-hello profile to use.
    pub tls_profile: String,
    /// HTTP/2 fingerprint profile to use.
    pub h2_profile: String,
    /// Whether mouse/scroll/timing simulation is needed.
    pub behavioral_simulation: bool,
    /// Whether the same IP must be reused for the entire session.
    pub sticky_session: bool,
    /// Human-readable notes and tips.
    pub notes: String,
}

impl VendorStrategy {
    /// Built-in strategy for a known vendor.
    pub fn for_vendor(vendor: &AntiBotVendor) -> Self {
        match vendor {
            AntiBotVendor::Cloudflare | AntiBotVendor::CloudflareTurnstile => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: false,
                requires_cookie_farm: true,
                cookie_ttl_seconds: 1800,
                max_requests_per_second: 1.0,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: false,
                sticky_session: false,
                notes: "Cookie farm cf_clearance + __cf_bm. 30-min TTL. \
                        Turnstile may require real browser interaction."
                    .into(),
            },
            AntiBotVendor::Akamai => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: false,
                requires_cookie_farm: true,
                cookie_ttl_seconds: 300,
                max_requests_per_second: 0.5,
                warmup_required: true,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: true,
                sticky_session: true,
                notes: "Cookie farm _abck + sensor data. 5-min effective TTL. \
                        Must reuse same IP + UA that generated cookies. \
                        Sensor requires scroll + mouse events."
                    .into(),
            },
            AntiBotVendor::PerimeterX => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: true,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 900,
                max_requests_per_second: 0.33,
                warmup_required: true,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: true,
                sticky_session: true,
                notes: "Full browser required. Single Chrome instance per session. \
                        _px3 cookie tied to browser fingerprint. \
                        Behavioral signals are heavily weighted."
                    .into(),
            },
            AntiBotVendor::DataDome => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: true,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 600,
                max_requests_per_second: 0.5,
                warmup_required: true,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: true,
                sticky_session: true,
                notes: "Full browser + warm-up navigation required. 10-min cookie TTL. \
                        DataDome checks TLS fingerprint, H2 settings, and JS execution."
                    .into(),
            },
            AntiBotVendor::Kasada => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: true,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 300,
                max_requests_per_second: 0.25,
                warmup_required: true,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: true,
                sticky_session: true,
                notes: "Full stealth browser only — no HTTP-only path. \
                        Kasada proof-of-work runs in JS. \
                        Cookie generation requires full page execution."
                    .into(),
            },
            AntiBotVendor::ShapeSecurity => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: true,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 600,
                max_requests_per_second: 0.33,
                warmup_required: true,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: true,
                sticky_session: true,
                notes: "F5 Shape uses heavily obfuscated inline JS (100KB+). \
                        Full browser required. No known HTTP-only bypass."
                    .into(),
            },
            AntiBotVendor::Imperva | AntiBotVendor::Distil => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: false,
                requires_cookie_farm: true,
                cookie_ttl_seconds: 900,
                max_requests_per_second: 0.5,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: false,
                sticky_session: false,
                notes: "Cookie farm visid_incap_* + incap_ses_*. \
                        Incapsula JS challenge is solvable without full browser \
                        if cookies are farmed correctly."
                    .into(),
            },
            AntiBotVendor::AwsWaf => Self {
                min_proxy_tier: "datacenter".into(),
                requires_browser: false,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 3600,
                max_requests_per_second: 2.0,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: false,
                sticky_session: false,
                notes: "AWS WAF is IP-reputation + rate-limit based. \
                        Datacenter IPs often work if rate is reasonable. \
                        aws-waf-token cookie may need browser for CAPTCHA page."
                    .into(),
            },
            AntiBotVendor::GoogleRecaptcha => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: true,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 120,
                max_requests_per_second: 0.2,
                warmup_required: true,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: true,
                sticky_session: true,
                notes: "reCAPTCHA v2 needs click interaction. v3 scores behavior. \
                        Residential IP + warm browsing history improves score."
                    .into(),
            },
            AntiBotVendor::HCaptcha => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: true,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 120,
                max_requests_per_second: 0.2,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: true,
                sticky_session: false,
                notes: "hCaptcha requires visual puzzle solving. \
                        Consider accessibility cookie for bypass."
                    .into(),
            },
            AntiBotVendor::ArkoseLabs => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: true,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 300,
                max_requests_per_second: 0.2,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: true,
                sticky_session: true,
                notes: "FunCaptcha requires interactive puzzle solving in browser. \
                        No known automated bypass."
                    .into(),
            },
            AntiBotVendor::GeeTest => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: true,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 300,
                max_requests_per_second: 0.5,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: true,
                sticky_session: false,
                notes: "GeeTest slide/click CAPTCHA. Requires browser interaction.".into(),
            },
            AntiBotVendor::Reblaze => Self {
                min_proxy_tier: "datacenter".into(),
                requires_browser: false,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 1800,
                max_requests_per_second: 1.0,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: false,
                sticky_session: false,
                notes: "Reblaze is primarily rate-limit + geo-based. \
                        Generally passable with correct headers and moderate rate."
                    .into(),
            },
            AntiBotVendor::Radware => Self {
                min_proxy_tier: "residential".into(),
                requires_browser: false,
                requires_cookie_farm: true,
                cookie_ttl_seconds: 600,
                max_requests_per_second: 0.5,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: false,
                sticky_session: false,
                notes: "Radware Bot Manager uses JS challenge cookies. \
                        Cookie farm approach works for most deployments."
                    .into(),
            },
            AntiBotVendor::Barracuda => Self {
                min_proxy_tier: "datacenter".into(),
                requires_browser: false,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 3600,
                max_requests_per_second: 2.0,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: false,
                sticky_session: false,
                notes: "Barracuda WAF is primarily signature + rate-limit based. \
                        Usually passable with correct headers."
                    .into(),
            },
            AntiBotVendor::Unknown(_) => Self {
                min_proxy_tier: "datacenter".into(),
                requires_browser: false,
                requires_cookie_farm: false,
                cookie_ttl_seconds: 1800,
                max_requests_per_second: 1.0,
                warmup_required: false,
                tls_profile: "chrome136".into(),
                h2_profile: "chrome136".into(),
                behavioral_simulation: false,
                sticky_session: false,
                notes: "Unknown vendor. Start with moderate rate and escalate if blocked.".into(),
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection rules (private)
// ─────────────────────────────────────────────────────────────────────────────

/// Case-insensitive header lookup helper.
fn header_get<'a>(headers: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    let key_lower = key.to_lowercase();
    for (k, v) in headers {
        if k.to_lowercase() == key_lower {
            return Some(v.as_str());
        }
    }
    None
}

fn has_header(headers: &HashMap<String, String>, key: &str) -> bool {
    header_get(headers, key).is_some()
}

// ─────────────────────────────────────────────────────────────────────────────
// Vendor Detector
// ─────────────────────────────────────────────────────────────────────────────

/// Centralized anti-bot vendor detection engine.
///
/// Inspects HTTP response headers, cookies (via `Set-Cookie` or cookie names),
/// HTML body content, and script URLs to identify which anti-bot system(s) a
/// site is using.
pub struct VendorDetector {
    /// Cache of detected vendors per domain.
    cache: HashMap<String, VendorDetection>,
}

impl VendorDetector {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    // ── Header-based detection ──────────────────────────────────────────

    fn detect_headers(
        headers: &HashMap<String, String>,
        signals: &mut Vec<(AntiBotVendor, DetectionSignal)>,
    ) {
        // ── Cloudflare ──────────────────────────────────────────────────
        if let Some(server) = header_get(headers, "server") {
            if server.to_lowercase().contains("cloudflare") {
                signals.push((
                    AntiBotVendor::Cloudflare,
                    DetectionSignal {
                        signal_type: SignalType::ServerHeader,
                        value: format!("Server: {server}"),
                        weight: 0.9,
                    },
                ));
            }
        }
        for key in &["cf-ray", "cf-cache-status", "cf-request-id"] {
            if has_header(headers, key) {
                signals.push((
                    AntiBotVendor::Cloudflare,
                    DetectionSignal {
                        signal_type: SignalType::ResponseHeader,
                        value: format!("{key} present"),
                        weight: 0.7,
                    },
                ));
            }
        }

        // ── Akamai ──────────────────────────────────────────────────────
        for (k, _v) in headers {
            let kl = k.to_lowercase();
            if kl.starts_with("x-akamai") || kl == "akamai-origin-hop" {
                signals.push((
                    AntiBotVendor::Akamai,
                    DetectionSignal {
                        signal_type: SignalType::ResponseHeader,
                        value: format!("{k} present"),
                        weight: 0.8,
                    },
                ));
            }
        }

        // ── PerimeterX ──────────────────────────────────────────────────
        for (k, _v) in headers {
            if k.to_lowercase().starts_with("x-px") {
                signals.push((
                    AntiBotVendor::PerimeterX,
                    DetectionSignal {
                        signal_type: SignalType::ResponseHeader,
                        value: format!("{k} present"),
                        weight: 0.9,
                    },
                ));
            }
        }

        // ── DataDome ────────────────────────────────────────────────────
        for (k, _v) in headers {
            let kl = k.to_lowercase();
            if kl.starts_with("x-datadome") || kl.starts_with("x-dd-") {
                signals.push((
                    AntiBotVendor::DataDome,
                    DetectionSignal {
                        signal_type: SignalType::ResponseHeader,
                        value: format!("{k} present"),
                        weight: 0.9,
                    },
                ));
            }
        }

        // ── Kasada ──────────────────────────────────────────────────────
        for (k, _v) in headers {
            if k.to_lowercase().starts_with("x-kpsdk") {
                signals.push((
                    AntiBotVendor::Kasada,
                    DetectionSignal {
                        signal_type: SignalType::ResponseHeader,
                        value: format!("{k} present"),
                        weight: 0.9,
                    },
                ));
            }
        }

        // ── Imperva / Incapsula ─────────────────────────────────────────
        if has_header(headers, "x-iinfo") {
            signals.push((
                AntiBotVendor::Imperva,
                DetectionSignal {
                    signal_type: SignalType::ResponseHeader,
                    value: "X-Iinfo present".into(),
                    weight: 0.8,
                },
            ));
        }
        if let Some(cdn) = header_get(headers, "x-cdn") {
            if cdn.to_lowercase().contains("incapsula") || cdn.to_lowercase().contains("imperva") {
                signals.push((
                    AntiBotVendor::Imperva,
                    DetectionSignal {
                        signal_type: SignalType::ResponseHeader,
                        value: format!("X-CDN: {cdn}"),
                        weight: 0.9,
                    },
                ));
            }
        }

        // ── AWS WAF ─────────────────────────────────────────────────────
        // NOTE: `x-amzn-requestid` (ALB/ELB) and `x-amz-cf-id` (CloudFront)
        // are AWS *hosting* headers — they appear on every AWS-hosted site
        // and are NOT evidence of AWS WAF. Claiming AwsWaf from them would
        // be a fabricated vendor match, so they are intentionally NOT
        // treated as WAF signals. Real WAF evidence comes from the
        // `aws-waf-token` cookie (managed-challenge issuance) and the
        // awswaf challenge page in detect_body.

        // ── Reblaze ─────────────────────────────────────────────────────
        if let Some(server) = header_get(headers, "server") {
            if server.to_lowercase().contains("reblaze") {
                signals.push((
                    AntiBotVendor::Reblaze,
                    DetectionSignal {
                        signal_type: SignalType::ServerHeader,
                        value: format!("Server: {server}"),
                        weight: 0.9,
                    },
                ));
            }
        }

        // ── Radware ─────────────────────────────────────────────────────
        for (k, _v) in headers {
            if k.to_lowercase().starts_with("x-rdwr")
                || k.to_lowercase().starts_with("x-shieldsquare")
            {
                signals.push((
                    AntiBotVendor::Radware,
                    DetectionSignal {
                        signal_type: SignalType::ResponseHeader,
                        value: format!("{k} present"),
                        weight: 0.8,
                    },
                ));
            }
        }

        // ── Barracuda ───────────────────────────────────────────────────
        if let Some(server) = header_get(headers, "server") {
            if server.to_lowercase().contains("barracuda") {
                signals.push((
                    AntiBotVendor::Barracuda,
                    DetectionSignal {
                        signal_type: SignalType::ServerHeader,
                        value: format!("Server: {server}"),
                        weight: 0.9,
                    },
                ));
            }
        }
    }

    // ── Cookie-based detection ──────────────────────────────────────────

    fn detect_cookies(
        headers: &HashMap<String, String>,
        signals: &mut Vec<(AntiBotVendor, DetectionSignal)>,
    ) {
        // Collect all Set-Cookie values (there may be multiple, but in our
        // HashMap model they are collapsed; also check the raw cookie names
        // that callers can pass under a synthetic "cookie-names" key).
        let mut cookie_names: Vec<String> = Vec::new();

        // From Set-Cookie header(s)
        for (k, v) in headers {
            if k.to_lowercase() == "set-cookie" {
                if let Some(name) = v.split('=').next() {
                    cookie_names.push(name.trim().to_lowercase());
                }
            }
        }

        // Synthetic key: callers can pass "cookie-names" as a semicolon-
        // separated list of observed cookie names.
        if let Some(names) = header_get(headers, "cookie-names") {
            for name in names.split(';') {
                cookie_names.push(name.trim().to_lowercase());
            }
        }

        for name in &cookie_names {
            // Cloudflare
            if name == "__cf_bm" || name == "cf_clearance" || name == "__cflb" {
                signals.push((
                    AntiBotVendor::Cloudflare,
                    DetectionSignal {
                        signal_type: SignalType::Cookie,
                        value: format!("cookie: {name}"),
                        weight: 0.85,
                    },
                ));
            }

            // Akamai
            if name == "_abck"
                || name == "ak_bmsc"
                || name == "bm_sv"
                || name == "bm_sz"
                || name == "bm_mi"
            {
                signals.push((
                    AntiBotVendor::Akamai,
                    DetectionSignal {
                        signal_type: SignalType::Cookie,
                        value: format!("cookie: {name}"),
                        weight: 0.9,
                    },
                ));
            }

            // PerimeterX
            if name == "_px3" || name == "_pxvid" || name == "_pxhd" || name == "_pxde" {
                signals.push((
                    AntiBotVendor::PerimeterX,
                    DetectionSignal {
                        signal_type: SignalType::Cookie,
                        value: format!("cookie: {name}"),
                        weight: 0.9,
                    },
                ));
            }

            // DataDome
            if name == "datadome" {
                signals.push((
                    AntiBotVendor::DataDome,
                    DetectionSignal {
                        signal_type: SignalType::Cookie,
                        value: "cookie: datadome".into(),
                        weight: 0.95,
                    },
                ));
            }

            // Imperva / Incapsula
            if name.starts_with("visid_incap_")
                || name.starts_with("incap_ses_")
                || name.starts_with("nlbi_")
            {
                signals.push((
                    AntiBotVendor::Imperva,
                    DetectionSignal {
                        signal_type: SignalType::Cookie,
                        value: format!("cookie: {name}"),
                        weight: 0.9,
                    },
                ));
            }

            // AWS WAF
            if name == "aws-waf-token" {
                signals.push((
                    AntiBotVendor::AwsWaf,
                    DetectionSignal {
                        signal_type: SignalType::Cookie,
                        value: "cookie: aws-waf-token".into(),
                        weight: 0.9,
                    },
                ));
            }
        }
    }

    // ── Body / HTML content detection ───────────────────────────────────

    fn detect_body(body: &str, status: u16, signals: &mut Vec<(AntiBotVendor, DetectionSignal)>) {
        let body_lower = body.to_lowercase();

        // ── Cloudflare challenge page ───────────────────────────────────
        if body_lower.contains("<title>just a moment...</title>") {
            signals.push((
                AntiBotVendor::Cloudflare,
                DetectionSignal {
                    signal_type: SignalType::HtmlContent,
                    value: "<title>Just a moment...</title>".into(),
                    weight: 0.95,
                },
            ));
        }
        if body_lower.contains("challenges.cloudflare.com") {
            signals.push((
                AntiBotVendor::Cloudflare,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "challenges.cloudflare.com".into(),
                    weight: 0.95,
                },
            ));
        }
        if body_lower.contains("cdn-cgi/challenge-platform") {
            signals.push((
                AntiBotVendor::Cloudflare,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "cdn-cgi/challenge-platform".into(),
                    weight: 0.9,
                },
            ));
        }

        // ── Cloudflare Turnstile ────────────────────────────────────────
        if body_lower.contains("challenges.cloudflare.com/turnstile") {
            signals.push((
                AntiBotVendor::CloudflareTurnstile,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "challenges.cloudflare.com/turnstile".into(),
                    weight: 0.95,
                },
            ));
        }

        // ── Akamai ──────────────────────────────────────────────────────
        // Sensor script
        if body_lower.contains("/akam/") {
            signals.push((
                AntiBotVendor::Akamai,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "script URL containing /akam/".into(),
                    weight: 0.85,
                },
            ));
        }
        if body_lower.contains("/_sec/cp_challenge/") {
            signals.push((
                AntiBotVendor::Akamai,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "/_sec/cp_challenge/".into(),
                    weight: 0.9,
                },
            ));
        }

        // ── PerimeterX ──────────────────────────────────────────────────
        if body_lower.contains("client.perimeterx.net") {
            signals.push((
                AntiBotVendor::PerimeterX,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "client.perimeterx.net".into(),
                    weight: 0.95,
                },
            ));
        }
        if body_lower.contains("captcha.px-cdn.net") {
            signals.push((
                AntiBotVendor::PerimeterX,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "captcha.px-cdn.net".into(),
                    weight: 0.95,
                },
            ));
        }
        if body_lower.contains("/px/block") {
            signals.push((
                AntiBotVendor::PerimeterX,
                DetectionSignal {
                    signal_type: SignalType::HtmlContent,
                    value: "/px/block page".into(),
                    weight: 0.9,
                },
            ));
        }

        // ── DataDome ────────────────────────────────────────────────────
        if body_lower.contains("js.datadome.co/tags.js") {
            signals.push((
                AntiBotVendor::DataDome,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "js.datadome.co/tags.js".into(),
                    weight: 0.95,
                },
            ));
        }
        if body_lower.contains("geo.captcha-delivery.com") {
            signals.push((
                AntiBotVendor::DataDome,
                DetectionSignal {
                    signal_type: SignalType::ChallengeType,
                    value: "geo.captcha-delivery.com".into(),
                    weight: 0.95,
                },
            ));
        }

        // ── Kasada ──────────────────────────────────────────────────────
        // ips.js from same origin is a strong Kasada signal
        if body_lower.contains("src=\"/ips.js\"") || body_lower.contains("src='/ips.js'") {
            signals.push((
                AntiBotVendor::Kasada,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "/ips.js (Kasada loader)".into(),
                    weight: 0.9,
                },
            ));
        }

        // ── Imperva / Incapsula ─────────────────────────────────────────
        if body_lower.contains("_incapsula_resource") {
            signals.push((
                AntiBotVendor::Imperva,
                DetectionSignal {
                    signal_type: SignalType::HtmlContent,
                    value: "_Incapsula_Resource".into(),
                    weight: 0.9,
                },
            ));
        }

        // ── Shape Security (F5) ─────────────────────────────────────────
        // Shape injects very large obfuscated inline scripts.
        // Check for huge inline <script> blocks (>80KB).
        let mut pos = 0;
        while let Some(start) = body_lower[pos..].find("<script>") {
            let abs_start = pos + start + 8; // past "<script>"
            if let Some(end) = body_lower[abs_start..].find("</script>") {
                let script_len = end;
                if script_len > 80_000 {
                    signals.push((
                        AntiBotVendor::ShapeSecurity,
                        DetectionSignal {
                            signal_type: SignalType::HtmlContent,
                            value: format!(
                                "large inline script ({script_len} chars, Shape pattern)"
                            ),
                            weight: 0.6, // lower confidence — other systems can have big scripts too
                        },
                    ));
                }
                pos = abs_start + end + 9;
            } else {
                break;
            }
        }

        // ── Google reCAPTCHA ────────────────────────────────────────────
        if body_lower.contains("google.com/recaptcha")
            || body_lower.contains("www.gstatic.com/recaptcha")
        {
            signals.push((
                AntiBotVendor::GoogleRecaptcha,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "Google reCAPTCHA script".into(),
                    weight: 0.95,
                },
            ));
        }

        // ── hCaptcha ────────────────────────────────────────────────────
        if body_lower.contains("hcaptcha.com") || body_lower.contains("js.hcaptcha.com") {
            signals.push((
                AntiBotVendor::HCaptcha,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "hCaptcha script".into(),
                    weight: 0.95,
                },
            ));
        }

        // ── Arkose Labs / FunCaptcha ────────────────────────────────────
        if body_lower.contains("arkoselabs.com") || body_lower.contains("funcaptcha.com") {
            signals.push((
                AntiBotVendor::ArkoseLabs,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "Arkose Labs / FunCaptcha script".into(),
                    weight: 0.95,
                },
            ));
        }

        // ── GeeTest ────────────────────────────────────────────────────
        if body_lower.contains("geetest.com") || body_lower.contains("gt.js") {
            signals.push((
                AntiBotVendor::GeeTest,
                DetectionSignal {
                    signal_type: SignalType::ScriptUrl,
                    value: "GeeTest script".into(),
                    weight: 0.9,
                },
            ));
        }

        // ── Distil ──────────────────────────────────────────────────────
        if body_lower.contains("distil") && body_lower.contains("x-distil") {
            signals.push((
                AntiBotVendor::Distil,
                DetectionSignal {
                    signal_type: SignalType::HtmlContent,
                    value: "Distil Networks pattern".into(),
                    weight: 0.7,
                },
            ));
        }

        // ── AWS WAF challenge page ──────────────────────────────────────
        if (status == 403 || status == 405)
            && (body_lower.contains("aws-waf") || body_lower.contains("awswaf"))
        {
            signals.push((
                AntiBotVendor::AwsWaf,
                DetectionSignal {
                    signal_type: SignalType::ChallengeType,
                    value: "AWS WAF challenge page".into(),
                    weight: 0.85,
                },
            ));
        }

        // ── Status code boost for challenge pages ───────────────────────
        if (status == 403 || status == 503)
            && (body_lower.contains("challenge") || body_lower.contains("captcha"))
        {
            // If we already detected a vendor above, this status code is
            // confirmatory. We add a generic signal that will merge into
            // whichever vendor was already found.
            signals.push((
                AntiBotVendor::Unknown("challenge-page".into()),
                DetectionSignal {
                    signal_type: SignalType::StatusCode,
                    value: format!("HTTP {status} with challenge/captcha content"),
                    weight: 0.3,
                },
            ));
        }
    }

    // ── Aggregation ─────────────────────────────────────────────────────

    /// Aggregate raw signals into per-vendor detections, sorted by confidence
    /// descending.
    fn aggregate(raw: Vec<(AntiBotVendor, DetectionSignal)>) -> Vec<VendorDetection> {
        let mut by_vendor: HashMap<AntiBotVendor, Vec<DetectionSignal>> = HashMap::new();
        for (vendor, signal) in raw {
            // Skip the synthetic "challenge-page" unknown — it only adds
            // marginal weight and should not appear as its own detection.
            if let AntiBotVendor::Unknown(ref s) = vendor {
                if s == "challenge-page" {
                    continue;
                }
            }
            by_vendor.entry(vendor).or_default().push(signal);
        }

        let mut detections: Vec<VendorDetection> = by_vendor
            .into_iter()
            .map(|(vendor, signals)| {
                // Confidence = 1 - product(1 - weight_i), capped at 1.0.
                let confidence = signals
                    .iter()
                    .fold(0.0_f64, |acc, s| acc + s.weight * (1.0 - acc))
                    .min(1.0);

                let recommended_strategy = VendorStrategy::for_vendor(&vendor);

                VendorDetection {
                    vendor,
                    confidence,
                    signals,
                    recommended_strategy,
                }
            })
            .collect();

        detections.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        detections
    }

    // ── Public API ──────────────────────────────────────────────────────

    /// Detect anti-bot vendor(s) from a full HTTP response.
    ///
    /// `headers` is a map of header name to value. Multiple `Set-Cookie`
    /// values should be semicolon-separated or passed individually.
    /// `body` is the response body (HTML or other text content).
    pub fn detect_from_response(
        &self,
        status: u16,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> Vec<VendorDetection> {
        let mut signals: Vec<(AntiBotVendor, DetectionSignal)> = Vec::new();

        Self::detect_headers(headers, &mut signals);
        Self::detect_cookies(headers, &mut signals);
        Self::detect_body(body, status, &mut signals);

        Self::aggregate(signals)
    }

    /// Fast path: detect vendor from headers only (no body parsing).
    pub fn detect_from_headers(&self, headers: &HashMap<String, String>) -> Vec<VendorDetection> {
        let mut signals: Vec<(AntiBotVendor, DetectionSignal)> = Vec::new();

        Self::detect_headers(headers, &mut signals);
        Self::detect_cookies(headers, &mut signals);

        Self::aggregate(signals)
    }

    /// Get the recommended strategy for a specific vendor.
    pub fn get_strategy(&self, vendor: &AntiBotVendor) -> VendorStrategy {
        VendorStrategy::for_vendor(vendor)
    }

    /// Cache a detection result for a domain.
    pub fn cache_detection(&mut self, domain: &str, detection: VendorDetection) {
        self.cache.insert(domain.to_string(), detection);
    }

    /// Get a previously cached detection for a domain.
    pub fn get_cached(&self, domain: &str) -> Option<&VendorDetection> {
        self.cache.get(domain)
    }

    /// Clear the detection cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Number of cached domain detections.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }
}

impl Default for VendorDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn detect_cloudflare_from_headers() {
        let detector = VendorDetector::new();
        let h = headers(&[("server", "cloudflare"), ("cf-ray", "abc123")]);
        let results = detector.detect_from_headers(&h);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::Cloudflare);
        assert!(results[0].confidence > 0.9);
    }

    #[test]
    fn detect_akamai_from_cookies() {
        let detector = VendorDetector::new();
        let h = headers(&[("cookie-names", "_abck;ak_bmsc;bm_sv")]);
        let results = detector.detect_from_headers(&h);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::Akamai);
        assert!(results[0].confidence > 0.9);
    }

    #[test]
    fn detect_perimeterx_from_body() {
        let detector = VendorDetector::new();
        let h = headers(&[]);
        let body =
            r#"<html><script src="https://client.perimeterx.net/abc/main.min.js"></script></html>"#;
        let results = detector.detect_from_response(200, &h, body);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::PerimeterX);
    }

    #[test]
    fn detect_datadome_combined() {
        let detector = VendorDetector::new();
        let h = headers(&[("X-DataDome-CID", "abc123"), ("cookie-names", "datadome")]);
        let body = r#"<script src="https://js.datadome.co/tags.js"></script>"#;
        let results = detector.detect_from_response(200, &h, body);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::DataDome);
        assert!(results[0].confidence > 0.99);
    }

    #[test]
    fn detect_kasada_from_header_and_body() {
        let detector = VendorDetector::new();
        let h = headers(&[("X-Kpsdk-CT", "some-token")]);
        let body = r#"<html><script src="/ips.js"></script></html>"#;
        let results = detector.detect_from_response(200, &h, body);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::Kasada);
    }

    #[test]
    fn detect_imperva_from_cookies() {
        let detector = VendorDetector::new();
        let h = headers(&[("cookie-names", "visid_incap_12345;incap_ses_678")]);
        let results = detector.detect_from_headers(&h);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::Imperva);
    }

    #[test]
    fn detect_cloudflare_challenge_page() {
        let detector = VendorDetector::new();
        let h = headers(&[("server", "cloudflare")]);
        let body = r#"<html><head><title>Just a moment...</title></head>
            <body><script src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/scripts/jsd/abc.js"></script></body></html>"#;
        let results = detector.detect_from_response(403, &h, body);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::Cloudflare);
        assert!(results[0].confidence > 0.99);
        assert!(results[0].signals.len() >= 3);
    }

    #[test]
    fn detect_aws_waf() {
        let detector = VendorDetector::new();
        // Real WAF evidence: the managed-challenge token cookie.
        let h = headers(&[("cookie-names", "aws-waf-token")]);
        let results = detector.detect_from_headers(&h);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::AwsWaf);
    }

    #[test]
    fn aws_hosting_headers_do_not_claim_aws_waf() {
        let detector = VendorDetector::new();
        // x-amzn-requestid (ALB/ELB) + x-amz-cf-id (CloudFront) prove the site
        // runs on AWS, not that AWS WAF protects it. Must NOT claim AwsWaf.
        let h = headers(&[
            ("x-amzn-requestid", "abc123"),
            ("x-amz-cf-id", "cf-abc"),
            ("server", "nginx"),
        ]);
        let results = detector.detect_from_headers(&h);
        assert!(
            !results.iter().any(|d| d.vendor == AntiBotVendor::AwsWaf),
            "hosting headers alone must not fabricate an AWS WAF match"
        );
    }

    #[test]
    fn detect_recaptcha() {
        let detector = VendorDetector::new();
        let h = headers(&[]);
        let body = r#"<script src="https://www.google.com/recaptcha/api.js"></script>"#;
        let results = detector.detect_from_response(200, &h, body);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::GoogleRecaptcha);
    }

    #[test]
    fn detect_hcaptcha() {
        let detector = VendorDetector::new();
        let body = r#"<script src="https://js.hcaptcha.com/1/api.js"></script>"#;
        let results = detector.detect_from_response(200, &headers(&[]), body);
        assert!(!results.is_empty());
        assert_eq!(results[0].vendor, AntiBotVendor::HCaptcha);
    }

    #[test]
    fn detect_turnstile() {
        let detector = VendorDetector::new();
        let body =
            r#"<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>"#;
        let results = detector.detect_from_response(200, &headers(&[]), body);
        let vendors: Vec<_> = results.iter().map(|d| &d.vendor).collect();
        assert!(vendors.contains(&&AntiBotVendor::CloudflareTurnstile));
    }

    #[test]
    fn no_detection_on_clean_response() {
        let detector = VendorDetector::new();
        let h = headers(&[("content-type", "text/html"), ("server", "nginx")]);
        let body = "<html><body>Hello world</body></html>";
        let results = detector.detect_from_response(200, &h, body);
        assert!(results.is_empty());
    }

    #[test]
    fn multiple_vendors_detected() {
        let detector = VendorDetector::new();
        let h = headers(&[("cookie-names", "_abck;_px3")]);
        let results = detector.detect_from_headers(&h);
        assert!(results.len() >= 2);
        let vendors: Vec<_> = results.iter().map(|d| &d.vendor).collect();
        assert!(vendors.contains(&&AntiBotVendor::Akamai));
        assert!(vendors.contains(&&AntiBotVendor::PerimeterX));
    }

    #[test]
    fn cache_operations() {
        let mut detector = VendorDetector::new();
        assert_eq!(detector.cache_len(), 0);

        let detection = VendorDetection {
            vendor: AntiBotVendor::Cloudflare,
            confidence: 0.95,
            signals: vec![],
            recommended_strategy: VendorStrategy::for_vendor(&AntiBotVendor::Cloudflare),
        };
        detector.cache_detection("example.com", detection);
        assert_eq!(detector.cache_len(), 1);
        assert!(detector.get_cached("example.com").is_some());
        assert!(detector.get_cached("other.com").is_none());

        detector.clear_cache();
        assert_eq!(detector.cache_len(), 0);
    }

    #[test]
    fn strategy_defaults() {
        let strategy = VendorStrategy::for_vendor(&AntiBotVendor::Kasada);
        assert!(strategy.requires_browser);
        assert!(!strategy.requires_cookie_farm);
        assert!(strategy.sticky_session);

        let strategy = VendorStrategy::for_vendor(&AntiBotVendor::Cloudflare);
        assert!(!strategy.requires_browser);
        assert!(strategy.requires_cookie_farm);
        assert_eq!(strategy.cookie_ttl_seconds, 1800);

        let strategy = VendorStrategy::for_vendor(&AntiBotVendor::Akamai);
        assert!(strategy.requires_cookie_farm);
        assert!(strategy.sticky_session);
        assert!(strategy.behavioral_simulation);
        assert_eq!(strategy.cookie_ttl_seconds, 300);
    }

    #[test]
    fn vendor_names() {
        assert_eq!(AntiBotVendor::Cloudflare.name(), "Cloudflare");
        assert_eq!(AntiBotVendor::ShapeSecurity.name(), "Shape Security (F5)");
        assert_eq!(AntiBotVendor::Unknown("custom".into()).name(), "custom");
    }
}
