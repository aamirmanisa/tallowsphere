//! Standard library: `tallow.csrf` — CSRF token auto-extraction and request signing.
//!
//! Provides real browser-backed CSRF token extraction via CDP and request
//! signing. Launches Chromium via `BrowserProcess`, navigates to the target
//! URL, extracts tokens from meta tags, hidden inputs, and cookies, then
//! returns a `CsrfSession` that can sign subsequent requests.

use super::StdlibResult;
use crate::browser::cdp::CdpClient;
use crate::browser::page::{Page, WaitUntil};
use crate::browser::process::{BrowserConfig, BrowserProcess};
use crate::interp::Value;

/// Dispatch a `tallow.csrf.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "extract" => Some(extract_csrf(args)),
        "sign_request" => Some(sign_request_fn(args)),
        _ => None,
    }
}

/// Dispatch a method on CSRF struct types.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, .. } = object else {
        return None;
    };
    match name.as_str() {
        "CsrfSession" => match method {
            "extract" => Some(extract_csrf(args)),
            "sign_request" => Some(sign_request_method(object, args)),
            _ => None,
        },
        _ => None,
    }
}

// ── extract(url: String) -> CsrfSession ──────────────────────────────────

fn extract_csrf(args: Vec<Value>) -> StdlibResult {
    let url = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => {
            return Err("csrf.extract: expected a URL string argument".to_string());
        }
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        format!("csrf.extract: failed to create tokio runtime: {e}")
    })?;

    rt.block_on(async move { extract_csrf_async(&url).await })
}

async fn extract_csrf_async(url: &str) -> StdlibResult {
    // ── Launch browser ──────────────────────────────────────────────────
    let config = BrowserConfig::default();
    let browser = BrowserProcess::launch(&config).map_err(|e| {
        format!("csrf.extract: failed to launch browser: {e}")
    })?;
    let ws_url = browser.ws_url.clone();

    // ── Connect CDP client ──────────────────────────────────────────────
    let client = CdpClient::connect(&ws_url).await.map_err(|e| {
        format!("csrf.extract: failed to connect CDP: {e}")
    })?;

    // ── Create page and navigate ────────────────────────────────────────
    let page = client.create_page(None).await.map_err(|e| {
        format!("csrf.extract: failed to create page: {e}")
    })?;

    page
        .navigate(url, WaitUntil::DomContentLoaded)
        .await
        .map_err(|e| format!("csrf.extract: failed to navigate: {e}"))?;

    // ── Extract meta CSRF tokens ────────────────────────────────────────
    let csrf_meta_token = eval_optional_string(
        &page,
        "document.querySelector('meta[name=\"csrf-token\"]')?.getAttribute('content') || null",
    )
    .await;

    let csrf_meta_param = eval_optional_string(
        &page,
        "document.querySelector('meta[name=\"csrf-param\"]')?.getAttribute('content') || null",
    )
    .await;

    let request_verification_token = eval_optional_string(
        &page,
        "document.querySelector('input[name=\"__RequestVerificationToken\"]')?.value || null",
    )
    .await;

    let authenticity_token = eval_optional_string(
        &page,
        "document.querySelector('input[name=\"authenticity_token\"]')?.value || null",
    )
    .await;

    // ── Extract CSRF cookies ────────────────────────────────────────────
    // FIX12 (2026-08-27): Page::cookies() no longer exists — use get_cookies()
    // (Vec<CdpCookie>) and convert to the serde_json objects find_cookie_value expects.
    let cookies: Vec<serde_json::Value> = page
        .get_cookies()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|c| serde_json::to_value(c).ok())
        .collect();

    let xsrf_token_cookie = find_cookie_value(&cookies, "XSRF-TOKEN");
    let csrf_token_cookie = find_cookie_value(&cookies, "csrf_token");

    // ── Build CsrfToken list ────────────────────────────────────────────
    let mut tokens: Vec<Value> = Vec::new();

    if let Some(ref token) = csrf_meta_token {
        tokens.push(make_csrf_token(token, "csrf-token", "meta"));
    }
    if let Some(ref token) = csrf_meta_param {
        tokens.push(make_csrf_token(token, "csrf-param", "meta"));
    }
    if let Some(ref token) = request_verification_token {
        tokens.push(make_csrf_token(token, "__RequestVerificationToken", "input"));
    }
    if let Some(ref token) = authenticity_token {
        tokens.push(make_csrf_token(token, "authenticity_token", "input"));
    }
    if let Some(ref token) = xsrf_token_cookie {
        tokens.push(make_csrf_token(token, "XSRF-TOKEN", "cookie"));
    }
    if let Some(ref token) = csrf_token_cookie {
        tokens.push(make_csrf_token(token, "csrf_token", "cookie"));
    }

    // ── Build cookies Map ───────────────────────────────────────────────
    let cookie_map: Vec<(Value, Value)> = cookies
        .iter()
        .filter_map(|c| {
            let name = c.get("name")?.as_str()?;
            let value = c.get("value")?.as_str()?;
            Some((Value::String(name.to_string()), Value::String(value.to_string())))
        })
        .collect();

    // ── Close the page (browser auto-cleaned on drop) ───────────────────
    let _ = client.close_page(&page).await;

    // ── Build CsrfSession ───────────────────────────────────────────────
    Ok(Value::Struct {
        name: "CsrfSession".to_string(),
        fields: vec![
            ("landing_url".to_string(), Value::String(url.to_string())),
            ("tokens".to_string(), Value::Array(tokens)),
            ("cookies".to_string(), Value::Map(cookie_map)),
        ],
    })
}

// ── sign_request(session: CsrfSession, request: CsrfRequest) -> CsrfRequest ──

fn sign_request_fn(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("csrf.sign_request: expected (session, request)".to_string());
    }
    let session = &args[0];
    let request = &args[1];
    sign_request_impl(session, request)
}

fn sign_request_method(session: &Value, args: Vec<Value>) -> StdlibResult {
    let request = args.first().ok_or_else(|| {
        "csrf.CsrfSession.sign_request: expected a CsrfRequest argument".to_string()
    })?;
    sign_request_impl(session, request)
}

fn sign_request_impl(session: &Value, request: &Value) -> StdlibResult {
    // ── Extract session fields ──────────────────────────────────────────
    let session_fields = match session {
        Value::Struct { fields, .. } => fields,
        _ => return Err("csrf.sign_request: session must be a CsrfSession".to_string()),
    };

    let tokens: Vec<Value> = get_struct_field_opt(session_fields, "tokens")
        .and_then(|v| match v {
            Value::Array(arr) => Some(arr.clone()),
            _ => None,
        })
        .unwrap_or_default();

    let cookies_map: Vec<(Value, Value)> = get_struct_field_opt(session_fields, "cookies")
        .and_then(|v| match v {
            Value::Map(m) => Some(m.clone()),
            _ => None,
        })
        .unwrap_or_default();

    // ── Extract request fields ──────────────────────────────────────────
    let request_fields = match request {
        Value::Struct { fields, .. } => fields,
        _ => return Err("csrf.sign_request: request must be a CsrfRequest".to_string()),
    };

    let req_url = get_struct_field_str(request_fields, "url").unwrap_or_default();
    let req_method = get_struct_field_str(request_fields, "method").unwrap_or_else(|| "GET".to_string());
    let req_headers: Vec<(Value, Value)> =
        get_struct_field_opt(request_fields, "headers")
            .and_then(|v| match v {
                Value::Map(m) => Some(m.clone()),
                _ => None,
            })
            .unwrap_or_default();
    let req_body = get_struct_field_str(request_fields, "body");

    // ── Find CSRF tokens by type ────────────────────────────────────────
    let meta_token = find_token_value(&tokens, "csrf-token");
    let request_verification = find_token_value(&tokens, "__RequestVerificationToken");
    let authenticity = find_token_value(&tokens, "authenticity_token");
    let xsrf_cookie = find_token_value(&tokens, "XSRF-TOKEN");
    let csrf_cookie = find_token_value(&tokens, "csrf_token");

    // ── Build new headers ───────────────────────────────────────────────
    let mut new_headers: Vec<(Value, Value)> = req_headers.clone();

    // Add X-CSRF-Token header from meta token
    if let Some(ref token) = meta_token {
        new_headers.push((
            Value::String("X-CSRF-Token".to_string()),
            Value::String(token.clone()),
        ));
    }

    // Add Cookie header with CSRF cookies
    let cookie_header = build_cookie_header(&cookies_map, &xsrf_cookie, &csrf_cookie);
    if !cookie_header.is_empty() {
        // Merge with existing Cookie header if present
        let existing_cookie = new_headers.iter_mut().find(|(k, _)| {
            matches!(k, Value::String(s) if s.to_lowercase() == "cookie")
        });
        if let Some((_, v)) = existing_cookie {
            if let Value::String(existing) = v {
                *v = Value::String(format!("{existing}; {cookie_header}"));
            }
        } else {
            new_headers.push((
                Value::String("Cookie".to_string()),
                Value::String(cookie_header),
            ));
        }
    }

    // ── Build new body ──────────────────────────────────────────────────
    let new_body = if let Some(ref body) = req_body {
        let mut extra_fields = String::new();
        if let Some(ref token) = request_verification {
            if !body.contains("__RequestVerificationToken") {
                if !extra_fields.is_empty() {
                    extra_fields.push('&');
                }
                extra_fields.push_str(&format!(
                    "__RequestVerificationToken={}",
                    urlencoding(token)
                ));
            }
        }
        if let Some(ref token) = authenticity {
            if !body.contains("authenticity_token") {
                if !extra_fields.is_empty() {
                    extra_fields.push('&');
                }
                extra_fields.push_str(&format!("authenticity_token={}", urlencoding(token)));
            }
        }
        if extra_fields.is_empty() {
            Some(body.clone())
        } else if body.is_empty() {
            Some(extra_fields)
        } else {
            Some(format!("{body}&{extra_fields}"))
        }
    } else {
        // No body but we have tokens — create a form body
        let mut parts: Vec<String> = Vec::new();
        if let Some(ref token) = request_verification {
            parts.push(format!(
                "__RequestVerificationToken={}",
                urlencoding(token)
            ));
        }
        if let Some(ref token) = authenticity {
            parts.push(format!("authenticity_token={}", urlencoding(token)));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("&"))
        }
    };

    // ── Build CsrfRequest result ────────────────────────────────────────
    Ok(Value::Struct {
        name: "CsrfRequest".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(req_url)),
            ("method".to_string(), Value::String(req_method)),
            (
                "headers".to_string(),
                Value::Map(new_headers),
            ),
            (
                "body".to_string(),
                new_body.map(Value::String).unwrap_or(Value::Nil),
            ),
        ],
    })
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn make_csrf_token(token: &str, field_name: &str, source: &str) -> Value {
    Value::Struct {
        name: "CsrfToken".to_string(),
        fields: vec![
            ("token".to_string(), Value::String(token.to_string())),
            ("field_name".to_string(), Value::String(field_name.to_string())),
            ("source".to_string(), Value::String(source.to_string())),
        ],
    }
}

async fn eval_optional_string(page: &Page, expression: &str) -> Option<String> {
    match page.evaluate_expression(expression).await {
        Ok(v) => {
            let s = v.as_str().unwrap_or("");
            if !s.is_empty() && s != "null" {
                Some(s.to_string())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

fn find_cookie_value(cookies: &[serde_json::Value], name: &str) -> Option<String> {
    cookies.iter().find_map(|c| {
        if c.get("name")?.as_str()? == name {
            c.get("value")?.as_str().map(|s| s.to_string())
        } else {
            None
        }
    })
}

fn get_struct_field_str(fields: &[(String, Value)], name: &str) -> Option<String> {
    fields.iter().find_map(|(f, v)| {
        if f == name {
            match v {
                Value::String(s) => Some(s.clone()),
                other => Some(other.to_string()),
            }
        } else {
            None
        }
    })
}

fn get_struct_field_opt<'a>(fields: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    fields.iter().find_map(|(f, v)| if f == name { Some(v) } else { None })
}

fn find_token_value(tokens: &[Value], field_name: &str) -> Option<String> {
    tokens.iter().find_map(|t| {
        if let Value::Struct { fields, .. } = t {
            let matches = fields.iter().any(|(f, v)| {
                f == "field_name" && matches!(v, Value::String(s) if s == field_name)
            });
            if matches {
                get_struct_field_str(fields, "token")
            } else {
                None
            }
        } else {
            None
        }
    })
}

fn build_cookie_header(
    cookies: &[(Value, Value)],
    xsrf_token: &Option<String>,
    csrf_token: &Option<String>,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Include XSRF-TOKEN cookie
    if let Some(token) = xsrf_token {
        parts.push(format!("XSRF-TOKEN={}", urlencoding(token)));
    }
    // Include csrf_token cookie  
    if let Some(token) = csrf_token {
        parts.push(format!("csrf_token={}", urlencoding(token)));
    }

    // Also include the relevant cookies from the session's cookie map
    for (k, v) in cookies {
        let key = match k {
            Value::String(s) => s.as_str(),
            _ => continue,
        };
        let val = match v {
            Value::String(s) => s.as_str(),
            _ => continue,
        };
        if key == "XSRF-TOKEN" || key == "csrf_token" {
            let encoded = format!("{key}={}", urlencoding(val));
            if !parts.iter().any(|p| p.starts_with(&format!("{key}="))) {
                parts.push(encoded);
            }
        }
    }

    parts.join("; ")
}

fn urlencoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}
