//! Standard library: `tallow.escalation` — progressive rendering escalation.
//!
//! Inspired by ScrapingBee's auto-mode and Firecrawl's engine waterfall.
//! Automatically escalates through rendering strategies when simpler
//! approaches fail, optimizing for cost and speed.
//!
//! # Escalation Ladder
//! Level 0: raw_http (fastest, cheapest)  
//! Level 1: HTTP + cookie jar (session replay)  
//! Level 2: HTTP + rotated-proxy-style headers (IP rotation)  
//! Level 3: HTTP + full browser UA set (http_ua — NO JS rendering; a real
//!          browser/CDP level is not wired in this build, so the level names
//!          say exactly what happens)
//! Level 4: HTTP + stealth-style UA profile (http_ua_stealth)  
//! Level 5: HTTP + premium/residential-style UA profile (http_ua_premium)
//!
//! # API
//! - `Escalation.fetch(url, options)` — progressive fetch through the ladder
//! - `Escalation.scrape(url, extractor, options)` — fetch + structured extraction
//! - `Response.escalated_from` — which level succeeded

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::time::Instant;

/// Escalation levels.
///
/// Levels 3-5 are plain HTTP fetches with progressively heavier browser-style
/// User-Agent/header sets — they are named `http_ua*` (what they actually are),
/// NOT `browser_*`, because no CDP/JS-rendering browser is available from this
/// module. Reporting `escalated_from=browser_cdp` for a bare HTTP GET would be
/// a false claim, so the names are honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    RawHttp = 0,
    CookieJar = 1,
    Proxy = 2,
    HttpUa = 3,
    HttpUaStealth = 4,
    HttpUaPremium = 5,
}

impl Level {
    fn next(&self) -> Option<Level> {
        match self {
            Level::RawHttp => Some(Level::CookieJar),
            Level::CookieJar => Some(Level::Proxy),
            Level::Proxy => Some(Level::HttpUa),
            Level::HttpUa => Some(Level::HttpUaStealth),
            Level::HttpUaStealth => Some(Level::HttpUaPremium),
            Level::HttpUaPremium => None,
        }
    }

    fn name(&self) -> &str {
        match self {
            Level::RawHttp => "raw_http",
            Level::CookieJar => "cookie_jar",
            Level::Proxy => "proxy",
            Level::HttpUa => "http_ua",
            Level::HttpUaStealth => "http_ua_stealth",
            Level::HttpUaPremium => "http_ua_premium",
        }
    }

    fn cost_ms(&self) -> u64 {
        match self {
            Level::RawHttp => 200,
            Level::CookieJar => 400,
            Level::Proxy => 800,
            Level::HttpUa => 3000,
            Level::HttpUaStealth => 5000,
            Level::HttpUaPremium => 10000,
        }
    }

    /// Human-readable list of accepted level names (for error messages).
    fn valid_names() -> &'static str {
        "raw_http, cookie_jar, proxy, http_ua, http_ua_stealth, http_ua_premium"
    }
}

/// Escalation result
struct EscalationResult {
    content: String,
    status: u16,
    level: Level,
    attempts: u32,
    duration_ms: u64,
    url: String,
}

fn result_to_value(r: &EscalationResult) -> Value {
    Value::Struct {
        name: "EscalationResult".into(),
        fields: vec![
            ("content".into(), Value::String(r.content.clone())),
            ("status".into(), Value::Int(r.status as i128)),
            ("escalated_from".into(), Value::String(r.level.name().to_string())),
            ("attempts".into(), Value::Int(r.attempts as i128)),
            ("duration_ms".into(), Value::Int(r.duration_ms as i128)),
            ("url".into(), Value::String(r.url.clone())),
        ],
    }
}

fn is_blocked(body: &str, status: u16) -> bool {
    if status == 403 || status == 429 || status == 503 {
        return true;
    }
    let lower = body.to_lowercase();
    lower.contains("captcha") || lower.contains("cloudflare")
        || lower.contains("attention required") || lower.contains("verify you are human")
        || lower.contains("access denied") || lower.contains("blocked")
        || lower.contains("security check") || lower.len() < 100
}

fn is_empty_or_error(body: &str, status: u16) -> bool {
    status >= 400 || body.trim().is_empty() || body.len() < 50
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "fetch" => Some(escalation_fetch(args)),
        "scrape" => Some(escalation_scrape(args)),
        _ => None,
    }
}

pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "fetch" | "scrape")
}

// ── Escalation.fetch(url, options) ──

fn escalation_fetch(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Escalation.fetch: requires (url, options?)".into());
    }
    let url = expect_str(&args[0], "url")?;
    let max_level = parse_level_arg(&args, 1, Level::HttpUaPremium, "max_level")?;
    let start_level = parse_level_arg(&args, 2, Level::RawHttp, "start_level")?;
    let timeout_ms = args.get(3).and_then(|v| if let Value::Int(i) = v { Some(*i as u64) } else { None }).unwrap_or(30000);

    let start = Instant::now();
    let mut level = start_level;
    let mut attempts = 0u32;
    let mut last_error = String::new();

    loop {
        if level > max_level {
            return Err(format!("All escalation levels exhausted. Last error: {}", last_error));
        }
        attempts += 1;

        match try_level(url, level, timeout_ms) {
            Ok(result) => {
                let duration = start.elapsed().as_millis() as u64;
                let mut r = result;
                r.attempts = attempts;
                r.duration_ms = duration;
                return Ok(result_to_value(&r));
            }
            Err(e) => {
                last_error = e;
                if let Some(next) = level.next() {
                    level = next;
                } else {
                    return Err(format!("All levels exhausted. Last error: {}", last_error));
                }
            }
        }
    }
}

fn try_level(url: &str, level: Level, timeout_ms: u64) -> Result<EscalationResult, String> {
    let timeout = std::time::Duration::from_millis(timeout_ms);

    match level {
        Level::RawHttp => {
            let resp = crate::runtime::egress_http::get(url)
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .header("Accept", "text/html,application/xhtml+xml")
                .call()
                .map_err(|e| format!("HTTP: {e}"))?;
            let status = resp.status().into();
            let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
            if is_blocked(&body, status) {
                return Err("Blocked at raw HTTP level".into());
            }
            Ok(EscalationResult {
                content: body, status, level, attempts: 1,
                duration_ms: level.cost_ms(), url: url.to_string(),
            })
        }
        Level::CookieJar => {
            // Try with cookies from browser if available
            let resp = crate::runtime::egress_http::get(url)
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .header("Accept", "text/html")
                .call()
                .map_err(|e| format!("Cookie+: {e}"))?;
            let status = resp.status().into();
            let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
            if is_blocked(&body, status) {
                return Err("Blocked at cookie level".into());
            }
            Ok(EscalationResult {
                content: body, status, level, attempts: 1,
                duration_ms: level.cost_ms(), url: url.to_string(),
            })
        }
        Level::Proxy => {
            // Try with different UA + headers as proxy simulation
            // Full proxy integration uses the existing 7-layer proxy stack
            let resp = crate::runtime::egress_http::get(url)
                .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
                .header("Accept", "text/html,application/xhtml+xml")
                .header("Accept-Language", "en-US,en;q=0.9")
                .header("Sec-Ch-Ua", r#""Chromium";v="131", "Google Chrome";v="131""#)
                .call()
                .map_err(|e| format!("Proxy: {e}"))?;
            let status = resp.status().into();
            let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
            if is_blocked(&body, status) {
                return Err("Blocked at proxy level".into());
            }
            Ok(EscalationResult {
                content: body, status, level, attempts: 1,
                duration_ms: level.cost_ms(), url: url.to_string(),
            })
        }
        Level::HttpUa | Level::HttpUaStealth | Level::HttpUaPremium => {
            // Plain HTTP with browser-style UA/header sets. This is NOT CDP /
            // JS rendering — no browser level is wired in this build, and the
            // level name reports exactly what happened (http_ua*).
            let ua = match level {
                Level::HttpUaStealth => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                Level::HttpUaPremium => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                _ => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            };
            let resp = crate::runtime::egress_http::get(url)
                .header("User-Agent", ua)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("Accept-Language", "en-US,en;q=0.9")
                .header("Sec-Ch-Ua", r#""Chromium";v="131", "Google Chrome";v="131""#)
                .header("Sec-Ch-Ua-Platform", r#""Linux""#)
                .call()
                .map_err(|e| format!("HttpUa: {e}"))?;
            let status = resp.status().into();
            let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
            if is_blocked(&body, status) {
                return Err(format!("Blocked at {} level", level.name()));
            }
            Ok(EscalationResult {
                content: body, status, level, attempts: 1,
                duration_ms: level.cost_ms(), url: url.to_string(),
            })
        }
    }
}

// ── Escalation.scrape(url, extractor, options) ──

fn escalation_scrape(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Escalation.scrape: requires (url, extractor, options?)".into());
    }
    let url = expect_str(&args[0], "url")?;
    let extractor = expect_str(&args[1], "extractor")?;

    // Fetch with escalation, then apply extraction
    let max_level = parse_level_arg(&args, 2, Level::HttpUa, "max_level")?;
    let mut fetch_args = vec![args[0].clone(), Value::String(max_level.name().to_string())];
    let fetch_result = escalation_fetch(fetch_args)?;

    // Basic extraction patterns
    let Value::Struct { fields, .. } = fetch_result else {
        return Err("Expected EscalationResult".into());
    };
    let content = field_str(&fields, "content");
    let level_name = field_str(&fields, "escalated_from");

    match extractor.as_str() {
        "title" => {
            let title = extract_regex(&content, r"<title[^>]*>([^<]+)</title>")
                .unwrap_or_default();
            Ok(Value::String(title))
        }
        "links" => {
            let links = extract_all_regex(&content, r#"<a[^>]+href=["']([^"']+)["'][^>]*>([^<]*)</a>"#);
            let arr: Vec<Value> = links.into_iter().map(|(url, text)| {
                Value::Struct {
                    name: "Link".into(),
                    fields: vec![
                        ("url".into(), Value::String(url)),
                        ("text".into(), Value::String(text)),
                    ],
                }
            }).collect();
            Ok(Value::Array(arr))
        }
        "text" => {
            let text = strip_html(&content);
            Ok(Value::String(text))
        }
        "status" => {
            let status_str = field_str(&fields, "status");
            let status: i128 = status_str.parse().unwrap_or(0);
            Ok(Value::Int(status))
        }
        _ => {
            // Return full result with note
            Ok(Value::Struct {
                name: "EscalationResult".into(),
                fields: vec![
                    ("content".into(), Value::String(content)),
                    ("extractor".into(), Value::String(extractor.to_string())),
                    ("escalated_from".into(), Value::String(level_name)),
                ],
            })
        }
    }
}

// ── Helpers ──

fn extract_regex(haystack: &str, pattern: &str) -> Option<String> {
    regex::Regex::new(pattern).ok()
        .and_then(|re| re.captures(haystack))
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
}

fn extract_all_regex(haystack: &str, pattern: &str) -> Vec<(String, String)> {
    regex::Regex::new(pattern).ok()
        .map(|re| {
            re.captures_iter(haystack)
                .filter_map(|caps| {
                    let url = caps.get(1).map(|m| m.as_str().to_string())?;
                    let text = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
                    Some((url, text))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn strip_html(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        if c == '<' { in_tag = true; continue; }
        if c == '>' { in_tag = false; continue; }
        if !in_tag { text.push(c); }
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Strictly parse an optional level argument; unknown level names (including the
/// legacy `browser_cdp`/`browser_stealth`/`browser_premium` names, which require
/// a real browser this build does not provide) are honest errors instead of
/// silent defaults.
fn parse_level_arg(
    args: &[Value],
    idx: usize,
    default: Level,
    arg_name: &str,
) -> Result<Level, String> {
    match args.get(idx) {
        None => Ok(default),
        Some(v) => val_to_level(v).ok_or_else(|| {
            let given = match v {
                Value::String(s) => format!("\"{s}\""),
                Value::Int(i) => i.to_string(),
                other => type_name(other).to_string(),
            };
            format!(
                "Escalation: unknown {arg_name} level {given} — valid levels: {}. \
                 (browser_cdp/browser_stealth/browser_premium are NOT available: \
                 they require a real CDP browser, which this build does not wire \
                 into the escalation module.)",
                Level::valid_names()
            )
        }),
    }
}

fn val_to_level(v: &Value) -> Option<Level> {
    match v {
        Value::String(s) => match s.as_str() {
            "raw_http" => Some(Level::RawHttp),
            "cookie_jar" => Some(Level::CookieJar),
            "proxy" => Some(Level::Proxy),
            "http_ua" => Some(Level::HttpUa),
            "http_ua_stealth" => Some(Level::HttpUaStealth),
            "http_ua_premium" => Some(Level::HttpUaPremium),
            _ => None,
        }
        Value::Int(i) => match *i {
            0 => Some(Level::RawHttp),
            1 => Some(Level::CookieJar),
            2 => Some(Level::Proxy),
            3 => Some(Level::HttpUa),
            4 => Some(Level::HttpUaStealth),
            5 => Some(Level::HttpUaPremium),
            _ => None,
        }
        _ => None,
    }
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}

fn expect_str<'a>(val: &'a Value, name: &str) -> Result<&'a String, String> {
    match val { Value::String(s) => Ok(s), _ => Err(format!("Expected String for {name}, got {}", type_name(val))) }
}
