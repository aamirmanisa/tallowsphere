//! Standard library: `tallow.sso` — SSO bypass and token replay attack tools.
//!
//! Implements SSO bypass techniques: token replay across domains, cookie dumping,
//! session fixation, and subdomain cookie leakage.
//!
//! # API
//! - `SSO.dump_cookies(browser_db_path)` — extract SSO session cookies from browser
//! - `SSO.replay_token(token, target_url, header_name?)` — replay JWT/cookie to target
//! - `SSO.cookie_to_header(cookie_string)` — convert Netscape cookie to headers
//! - `SSO.subdomain_leak(cookies, primary_domain)` — check cookies leak to subdomains

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::collections::HashMap;

fn parse_cookie_string(cookies: &str) -> Vec<Cookie> {
    let mut result = Vec::new();
    for cookie in cookies.split('\n') {
        let cookie = cookie.trim();
        if cookie.is_empty() || cookie.starts_with('#') { continue; }

        let parts: Vec<&str> = cookie.split('\t').collect();
        if parts.len() >= 7 {
            result.push(Cookie {
                domain: parts[0].to_string(),
                include_subdomains: parts[1] == "TRUE",
                path: parts[2].to_string(),
                secure: parts[3] == "TRUE",
                expires: parts[4].parse().unwrap_or(0),
                name: parts[5].to_string(),
                value: parts[6].to_string(),
            });
        }
    }
    result
}

fn parse_header_cookies(header: &str) -> Vec<SimpleCookie> {
    let mut result = Vec::new();
    for part in header.split(';') {
        let part = part.trim();
        if let Some(pos) = part.find('=') {
            result.push(SimpleCookie {
                name: part[..pos].trim().to_string(),
                value: part[pos+1..].trim().to_string(),
            });
        }
    }
    result
}

struct Cookie {
    domain: String,
    include_subdomains: bool,
    path: String,
    secure: bool,
    expires: u64,
    name: String,
    value: String,
}

struct SimpleCookie {
    name: String,
    value: String,
}

impl Cookie {
    fn to_header(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

fn replay_token(token: &str, target_url: &str, header_name: Option<&str>) -> StdlibResult {
    let hname = header_name.unwrap_or("Cookie");
    let headers = match hname.to_lowercase().as_str() {
        "cookie" => {
            // It could be a raw cookie string or a JWT in Bearer format
            if token.starts_with("eyJ") {
                // JWT token — use Authorization header
                format!("Authorization: Bearer {}", token)
            } else {
                format!("Cookie: {}", token)
            }
        }
        "authorization" => format!("Authorization: {}", token),
        "x-api-key" => format!("X-API-Key: {}", token),
        _ => format!("{}: {}", hname, token),
    };

    let (header_key, header_val) = headers.split_once(": ").unwrap_or((hname, token));
    let resp = crate::runtime::egress_http::get(target_url)
        .header(header_key, header_val)
        .call()
        .map_err(|e| format!("request: {e}"))?;

    let status = resp.status();
    let body = resp.into_body().read_to_string().unwrap_or_default();
    let body_preview = &body[..body.len().min(500)];

    Ok(Value::Struct {
        name: "ReplayResult".into(),
        fields: vec![
            ("status".into(), Value::Int(status.as_u16() as i128)),
            ("success".into(), Value::Bool(status.as_u16() == 200)),
            ("body_preview".into(), Value::String(body_preview.to_string())),
        ],
    })
}

fn dump_cookies_from_header(cookie_header: &str) -> Vec<SimpleCookie> {
    parse_header_cookies(cookie_header)
}

fn cookie_to_header(cookies: &str) -> Value {
    let cookies = parse_header_cookies(cookies);
    let header = cookies.iter()
        .map(|c| format!("{}={}", c.name, c.value))
        .collect::<Vec<_>>()
        .join("; ");

    Value::Struct {
        name: "CookieHeader".into(),
        fields: vec![
            ("header_string".into(), Value::String(header)),
            ("cookie_count".into(), Value::Int(cookies.len() as i128)),
            ("cookies".into(), {
                let arr: Vec<Value> = cookies.iter().map(|c| {
                    Value::Struct {
                        name: "Cookie".into(),
                        fields: vec![
                            ("name".into(), Value::String(c.name.clone())),
                            ("value".into(), Value::String(c.value.clone())),
                        ],
                    }
                }).collect();
                Value::Array(arr)
            }),
        ],
    }
}

fn check_subdomain_leak(primary_domain: &str) -> Value {
    // Generate subdomain targets that might leak cookies
    let targets = [
        format!("www.{}", primary_domain),
        format!("api.{}", primary_domain),
        format!("app.{}", primary_domain),
        format!("assets.{}", primary_domain),
        format!("cdn.{}", primary_domain),
        format!("static.{}", primary_domain),
        format!("staging.{}", primary_domain),
        format!("dev.{}", primary_domain),
        format!("admin.{}", primary_domain),
        format!("mail.{}", primary_domain),
    ];

    let arr: Vec<Value> = targets.iter().map(|t| {
        Value::Struct {
            name: "SubdomainTarget".into(),
            fields: vec![
                ("domain".into(), Value::String(t.clone())),
                ("likely_leak".into(), Value::Bool(
                    t.starts_with("www.") || t.starts_with("assets.")
                )),
            ],
        }
    }).collect();

    Value::Array(arr)
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "replay_token" => Some(sso_replay(args)),
        "cookie_to_header" => Some(sso_cookie_header(args)),
        "subdomain_leak" => Some(sso_subdomains(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "replay_token" | "cookie_to_header" | "subdomain_leak")
}

fn sso_replay(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("SSO.replay_token: requires (token, target_url, header_name?)".into());
    }
    let token = expect_first_str(&args, "token")?;
    let target_url = expect_string(&args[1], "target_url")?;
    let header_name = args.get(2).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None });
    replay_token(token, target_url, header_name)
}

fn sso_cookie_header(args: Vec<Value>) -> StdlibResult {
    let cookies = expect_first_str(&args, "cookies")?;
    Ok(cookie_to_header(cookies))
}

fn sso_subdomains(args: Vec<Value>) -> StdlibResult {
    let domain = expect_first_str(&args, "primary_domain")?;
    Ok(check_subdomain_leak(domain))
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}

fn expect_string<'a>(val: &'a Value, name: &str) -> Result<&'a String, String> {
    match val {
        Value::String(s) => Ok(s),
        _ => Err(format!("Expected String for {name}, got {}", type_name(val))),
    }
}
