//! Standard library: `tallow.captcha` — multi-vendor CAPTCHA detection and classification.
//!
//! Detects and classifies CAPTCHA/WAF challenges across 7 providers:
//! Cloudflare Turnstile, hCaptcha, reCAPTCHA v2/v3, DataDome, PerimeterX,
//! Akamai Bot Manager, and custom JS challenges.
//!
//! # API
//! - `CAPTCHA.detect(html)` — detect CAPTCHA/WAF on page
//! - `CAPTCHA.classify(html, headers)` — classify challenge type and extract params
//! - `CAPTCHA.recommend(challenge)` — get bypass strategy recommendation
//! - `CAPTCHA.is_blocked(status, html)` — quick check if page is a block page

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::collections::HashMap;

/// A detected CAPTCHA or WAF challenge.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields kept for classification detail; constructed by dispatch
struct CaptchaChallenge {
    /// Provider: "turnstile", "hcaptcha", "recaptcha", "datadome", "perimeterx",
    /// "akamai", "cloudfront", "custom_js", "none"
    provider: String,
    /// Challenge type: "checkbox", "non_interactive", "invisible", "block_page",
    /// "js_challenge", "captcha", "managed"
    challenge_type: String,
    /// sitekey or form action for solving
    sitekey: Option<String>,
    /// CAPTCHA form action URL
    action: Option<String>,
    /// Any data-* attributes found
    data_attrs: Vec<(String, String)>,
    /// Detection confidence (0.0-1.0)
    confidence: f64,
    /// Specific detection signals found
    signals: Vec<String>,
}

impl CaptchaChallenge {
    fn none() -> Self {
        CaptchaChallenge {
            provider: "none".into(),
            challenge_type: "none".into(),
            sitekey: None,
            action: None,
            data_attrs: Vec::new(),
            confidence: 0.0,
            signals: Vec::new(),
        }
    }

    fn to_value(&self) -> Value {
        let mut fields = vec![
            ("provider".into(), Value::String(self.provider.clone())),
            ("challenge_type".into(), Value::String(self.challenge_type.clone())),
            ("confidence".into(), Value::Float(self.confidence)),
            ("signals".into(), {
                let arr: Vec<Value> = self.signals.iter()
                    .map(|s| Value::String(s.clone()))
                    .collect();
                Value::Array(arr)
            }),
        ];
        if let Some(ref sk) = self.sitekey {
            fields.push(("sitekey".into(), Value::String(sk.clone())));
        }
        if let Some(ref a) = self.action {
            fields.push(("action".into(), Value::String(a.clone())));
        }
        Value::Struct {
            name: "CaptchaChallenge".into(),
            fields,
        }
    }

    fn to_recommendation(&self) -> Value {
        let (strategy, notes) = match self.provider.as_str() {
            "turnstile" => ("Use `tallow.turnstile.solve()` if available, or escalate via `tallow.escalation`.",
                "Cloudflare Turnstile detected. Rotate fingerprint + proxy, then retry. Use `fingerprint.rotate()` and `proxy.next()` before re-requesting."),
            "hcaptcha" => ("Rotate fingerprint + residential proxy. Consider 2captcha/CapSolver integration.",
                "hCaptcha requires residential proxy + clean fingerprint. No built-in solver — use external service or bypass via session reuse."),
            "recaptcha" => ("Rotate to enterprise/residential proxy. Use `tallow.escalation.fetch()` with browser_render level.",
                "reCAPTCHA v3 scores are invisible — your fingerprint and behavior quality matters. v2 checkbox can be solved via external service."),
            "datadome" => ("High-security bot detection. Requires full browser + residential proxy + human-like behavior.",
                "DataDome uses ML-based behavioral detection. Use `tallow.browser` with human-like interaction patterns. Rotate everything."),
            "perimeterx" => ("Enterprise WAF. Requires browser fingerprint + JS rendering + residential proxy.",
                "PerimeterX (HUMAN Security) uses advanced fingerprinting. Full `tallow.fingerprint.from_profile()` + browser pool rotation needed."),
            "akamai" => ("CDN-level bot management. Requires TLS profile matching + clean fingerprint.",
                "Akamai uses TLS fingerprinting (JA3/JA4) and JS challenge. Use `tallow.tls_profile` matching target browser."),
            "cloudfront" => ("AWS CloudFront CDN. Standard browser rendering usually sufficient.",
                "Soft block — likely rate limiting. Use `tallow.rate_limit` to throttle. Browser render may not be needed."),
            "custom_js" => ("Custom JS challenge detected. Requires full browser CDP rendering.",
                "Unknown JS challenge — use `tallow.browser` or `tallow.escalation.fetch()` at browser_render level."),
            _ => ("No CAPTCHA detected. Page is accessible.",
                "No blocking mechanism found. Access should succeed."),
        };

        Value::Struct {
            name: "CaptchaRecommendation".into(),
            fields: vec![
                ("strategy".into(), Value::String(strategy.into())),
                ("notes".into(), Value::String(notes.into())),
                ("provider".into(), Value::String(self.provider.clone())),
            ],
        }
    }
}

// ── Detection Logic ──

fn detect_captcha(html: &str, headers: &HashMap<String, String>) -> CaptchaChallenge {
    let mut signals = Vec::new();

    // 1. Cloudflare Turnstile
    if html.contains("challenges.cloudflare.com/turnstile") ||
       html.contains("cf-chl-") ||
       html.contains("turnstile") {
        signals.push("turnstile_api".into());
        let sitekey = extract_attr(html, "data-sitekey");
        let action = extract_attr(html, "data-action");
        return CaptchaChallenge {
            provider: "turnstile".into(),
            challenge_type: if html.contains("invisible") { "invisible".into() } else { "managed".into() },
            sitekey,
            action,
            data_attrs: extract_data_attrs(html),
            confidence: 0.95,
            signals,
        };
    }

    // 2. hCaptcha
    if html.contains("hcaptcha.com") ||
       html.contains("h-captcha") ||
       html.contains("hcaptcha") {
        signals.push("hcaptcha_api".into());
        let sitekey = extract_attr(html, "data-sitekey");
        return CaptchaChallenge {
            provider: "hcaptcha".into(),
            challenge_type: if html.contains("invisible") { "invisible".into() } else { "checkbox".into() },
            sitekey,
            action: Some("https://hcaptcha.com/checkcaptcha".into()),
            data_attrs: extract_data_attrs(html),
            confidence: 0.95,
            signals,
        };
    }

    // 3. reCAPTCHA (Google)
    if html.contains("recaptcha") ||
       html.contains("g-recaptcha") ||
       html.contains("grecaptcha") ||
       html.contains("google.com/recaptcha") {
        signals.push("recaptcha_api".into());
        let sitekey = extract_attr(html, "data-sitekey");
        return CaptchaChallenge {
            provider: "recaptcha".into(),
            challenge_type: if html.contains("v3") || html.contains("score") { "invisible".into() }
                           else if html.contains("invisible") { "invisible".into() }
                           else { "checkbox".into() },
            sitekey,
            action: extract_attr(html, "data-action"),
            data_attrs: extract_data_attrs(html),
            confidence: 0.95,
            signals,
        };
    }

    // 4. DataDome
    if html.contains("datadome") ||
       html.contains("DataDome") ||
       html.contains("ddsettings") ||
       html.contains("captcha-delivery.com") {
        signals.push("datadome_detected".into());
        return CaptchaChallenge {
            provider: "datadome".into(),
            challenge_type: "captcha".into(),
            sitekey: None,
            action: None,
            data_attrs: Vec::new(),
            confidence: 0.90,
            signals,
        };
    }

    // 5. PerimeterX (HUMAN Security)
    if html.contains("perimeterx") ||
       html.contains("PerimeterX") ||
       html.contains("pxInit") ||
       html.contains("_pxAppId") ||
       html.contains("_pxCaptcha") {
        signals.push("perimeterx_detected".into());
        return CaptchaChallenge {
            provider: "perimeterx".into(),
            challenge_type: if html.contains("_pxCaptcha") { "captcha".into() } else { "js_challenge".into() },
            sitekey: None,
            action: None,
            data_attrs: Vec::new(),
            confidence: 0.90,
            signals,
        };
    }

    // 6. Akamai Bot Manager
    if html.contains("akamai") ||
       html.contains("ak_bmsc") ||
       html.contains("akamaihd.net") ||
       html.contains("akamaibotmanager") {
        signals.push("akamai_detected".into());
        return CaptchaChallenge {
            provider: "akamai".into(),
            challenge_type: "js_challenge".into(),
            sitekey: None,
            action: None,
            data_attrs: Vec::new(),
            confidence: 0.85,
            signals,
        };
    }

    // 7. CloudFront / AWS WAF (soft block)
    if let Some(svr) = headers.get("server") {
        if svr.contains("CloudFront") {
            signals.push("cloudfront_server".into());
        }
    }
    if html.contains("Generated by cloudfront") ||
       html.contains("Request blocked") && html.contains("CloudFront") {
        signals.push("cloudfront_block".into());
        return CaptchaChallenge {
            provider: "cloudfront".into(),
            challenge_type: "block_page".into(),
            sitekey: None,
            action: None,
            data_attrs: Vec::new(),
            confidence: 0.85,
            signals,
        };
    }

    // 8. Custom/unclassified JS challenge
    if html.contains("window._cf_chl_opt") ||
       html.contains("challenge") && html.contains("__"){
        signals.push("generic_js_challenge".into());
        return CaptchaChallenge {
            provider: "custom_js".into(),
            challenge_type: "js_challenge".into(),
            sitekey: None,
            action: None,
            data_attrs: Vec::new(),
            confidence: 0.60,
            signals,
        };
    }

    // 9. Detect via response headers
    if let Some(powered_by) = headers.get("x-powered-by") {
        signals.push(format!("header_x_powered_by: {powered_by}"));
    }
    if let Some(cf_ray) = headers.get("cf-ray") {
        signals.push(format!("cloudflare_proxied: {cf_ray}"));
    }
    if let Some(server) = headers.get("server") {
        if server.contains("cloudflare") {
            signals.push("cloudflare_server".into());
            return CaptchaChallenge {
                provider: "cloudfront".into(),
                challenge_type: "managed".into(),
                sitekey: None,
                action: None,
                data_attrs: Vec::new(),
                confidence: 0.70,
                signals,
            };
        }
    }

    CaptchaChallenge::none()
}

fn extract_attr(html: &str, attr: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr);
    if let Some(pos) = html.find(&pattern) {
        let start = pos + pattern.len();
        let end = html[start..].find('"').map(|p| start + p).unwrap_or(html.len());
        Some(html[start..end].to_string())
    } else {
        // Try single quotes
        let pattern = format!("{}='", attr);
        if let Some(pos) = html.find(&pattern) {
            let start = pos + pattern.len();
            let end = html[start..].find('\'').map(|p| start + p).unwrap_or(html.len());
            Some(html[start..end].to_string())
        } else {
            None
        }
    }
}

fn extract_data_attrs(html: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    for attr in &["data-sitekey", "data-action", "data-callback", "data-size",
                   "data-theme", "data-tabindex", "data-expired-callback", "data-error-callback"] {
        if let Some(val) = extract_attr(html, attr) {
            attrs.push((attr.to_string(), val));
        }
    }
    attrs
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "detect" => Some(captcha_detect(args)),
        "classify" => Some(captcha_classify(args)),
        "recommend" => Some(captcha_recommend(args)),
        "is_blocked" => Some(captcha_is_blocked(args)),
        _ => None,
    }
}

pub fn dispatch_method(
    object: &Value,
    method: &str,
    _args: Vec<Value>,
) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "CaptchaChallenge") {
        return None;
    }
    match method {
        "recommend" => {
            let challenge = match extract_challenge(object) {
                Ok(c) => c,
                Err(_) => return None,
            };
            Some(Ok(challenge.to_recommendation()))
        }
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "detect" | "classify" | "recommend" | "is_blocked")
}

// ── CAPTCHA.detect(html, headers?) ──

fn captcha_detect(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    let headers = if args.len() > 1 {
        parse_headers_value(&args[1])?
    } else {
        HashMap::new()
    };
    let challenge = detect_captcha(html, &headers);
    Ok(challenge.to_value())
}

// ── CAPTCHA.classify(html, headers?) ──

fn captcha_classify(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    let headers = if args.len() > 1 {
        parse_headers_value(&args[1])?
    } else {
        HashMap::new()
    };
    let challenge = detect_captcha(html, &headers);
    Ok(challenge.to_value())
}

// ── CAPTCHA.recommend(challenge) ──

fn captcha_recommend(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("CAPTCHA.recommend: requires (challenge)".into());
    }
    let challenge = extract_challenge(&args[0])?;
    Ok(challenge.to_recommendation())
}

// ── CAPTCHA.is_blocked(status, html?) ──

fn captcha_is_blocked(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("CAPTCHA.is_blocked: requires (status)".into());
    }
    let status = match &args[0] {
        Value::Int(s) => *s as u16,
        Value::Float(s) => *s as u16,
        _ => return Err("CAPTCHA.is_blocked: first argument must be a status code".into()),
    };

    // Common block status codes
    let blocked = match status {
        403 | 429 => true,
        503 if args.len() > 1 => {
            // Check if 503 has CAPTCHA content
            if let Value::String(html) = &args[1] {
                let challenge = detect_captcha(html, &HashMap::new());
                challenge.provider != "none"
            } else {
                false
            }
        }
        _ => false,
    };

    let signals = if blocked {
        let html = args.get(1).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("");
        let challenge = detect_captcha(html, &HashMap::new());
        vec![Value::String(format!("status_{}", status)),
             Value::String(format!("provider:{}", challenge.provider))]
    } else {
        Vec::new()
    };

    Ok(Value::Struct {
        name: "BlockCheck".into(),
        fields: vec![
            ("blocked".into(), Value::Bool(blocked)),
            ("status_code".into(), Value::Int(status as i128)),
            ("signals".into(), Value::Array(signals)),
        ],
    })
}

// ── Helpers ──

fn parse_headers_value(value: &Value) -> Result<HashMap<String, String>, String> {
    match value {
        Value::Map(entries) => {
            let mut h = HashMap::new();
            for (k, v) in entries {
                let key = match k {
                    Value::String(s) => s.clone(),
                    _ => format!("{}", type_name(k)),
                };
                let val = match v {
                    Value::String(s) => s.clone(),
                    _ => format!("{}", type_name(v)),
                };
                h.insert(key.to_lowercase(), val);
            }
            Ok(h)
        }
        Value::Struct { fields, .. } => {
            let mut h = HashMap::new();
            for (k, v) in fields {
                let val = match v {
                    Value::String(s) => s.clone(),
                    _ => format!("{}", type_name(v)),
                };
                h.insert(k.to_lowercase(), val);
            }
            Ok(h)
        }
        _ => Err(format!("Expected Map or Struct for headers, got {}", type_name(value))),
    }
}

fn extract_challenge(value: &Value) -> Result<CaptchaChallenge, String> {
    let fields = match value {
        Value::Struct { name, fields } if name == "CaptchaChallenge" => fields,
        _ => return Err(format!("Expected CaptchaChallenge, got {}", type_name(value))),
    };
    let provider = field_str(fields, "provider");
    let challenge_type = field_str(fields, "challenge_type");

    // Re-detect to get full data (simplified — just return the key fields)
    if provider.is_empty() {
        return Ok(CaptchaChallenge::none());
    }

    Ok(CaptchaChallenge {
        provider,
        challenge_type,
        sitekey: fields.iter().find(|(n,_)| n == "sitekey")
            .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None }),
        action: fields.iter().find(|(n,_)| n == "action")
            .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None }),
        data_attrs: Vec::new(),
        confidence: 0.85,
        signals: Vec::new(),
    })
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}
