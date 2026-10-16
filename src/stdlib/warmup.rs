//! Standard library: `tallow.warmup` contract dispatch.
//!
//! Provides a real pre-warming pipeline that launches a browser, runs the
//! warm-up sequence engine from `src/browser/warmup.rs`, and collects cookies
//! and storage from the session. The .tl declarations are in stdlib/warmup.tl.

use super::StdlibResult;
use crate::browser::cdp::CdpClient;
use crate::browser::page::WaitUntil;
use crate::browser::process::{BrowserConfig, BrowserProcess};
use crate::browser::session::{get_cookies, get_local_storage, get_session_storage, CdpCookie};
use crate::browser::warmup::{execute_warmup, WarmupSequence};
use crate::interp::Value;
use std::time::Instant;

/// Dispatch a `tallow.warmup.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "warmup_session" => Some(warmup_session_impl(args)),
        _ => None,
    }
}

/// Dispatch a method/field read on warmup structs.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, fields } = object else {
        return None;
    };

    match name.as_str() {
        "WarmupResult" => fields
            .iter()
            .find(|(field, _)| field == method)
            .map(|(_, value)| Ok(value.clone())),
        _ => None,
    }
}

/// Extract a String from a Value argument by position.
fn extract_string(args: &[Value], idx: usize, name: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(v) => {
            let s = v.as_string();
            if s.is_empty() && !matches!(v, Value::String(_)) {
                Err(format!("{name}: expected a string"))
            } else {
                Ok(s)
            }
        }
        None => Err(format!("missing argument {} ({name})", idx + 1)),
    }
}

/// Map a level string to a `WarmupSequence`.
fn level_to_sequence(level: &str) -> WarmupSequence {
    match level {
        "essential" => WarmupSequence::essential(),
        "standard" => WarmupSequence::standard(),
        "full" => WarmupSequence::full(),
        _ => WarmupSequence::standard(), // default
    }
}

/// Extract the security origin from a URL (scheme://host:port).
/// Used for CDP storage domain operations.
fn extract_security_origin(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        let host = rest.split('/').next().unwrap_or(rest);
        return format!("https://{host}");
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split('/').next().unwrap_or(rest);
        return format!("http://{host}");
    }
    url.to_string()
}

/// Real implementation of `warmup_session(url, level)`.
///
/// Launches a Chrome browser, connects via CDP, navigates to the target URL,
/// executes a warm-up sequence (human-like browsing), then extracts cookies,
/// localStorage, sessionStorage, and the User-Agent before cleaning up.
fn warmup_session_impl(args: Vec<Value>) -> StdlibResult {
    let url = extract_string(&args, 0, "url")?;
    let level = extract_string(&args, 1, "level").unwrap_or_else(|_| "standard".to_string());
    let sequence = level_to_sequence(&level);

    let start = Instant::now();

    // Create a dedicated tokio runtime for this operation.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("warmup_session: failed to create tokio runtime: {e}"))?;

    let result: Result<Value, String> = rt.block_on(async move {
        // ── Launch browser ────────────────────────────────────────────────
        let browser_config = BrowserConfig {
            headless: true,
            stealth: true,
            // Egress: the box's Tor/proxy contract, like every other launch
            // path (a bare default opened Chrome with no proxy at all).
            proxy: crate::runtime::fetch::egress_proxy_url(),
            ..BrowserConfig::default()
        };

        let mut process = BrowserProcess::launch(&browser_config)
            .map_err(|e| format!("warmup_session: failed to launch browser: {e}"))?;

        let client = CdpClient::connect(&process.ws_url)
            .await
            .map_err(|e| format!("warmup_session: failed to connect CDP client: {e}"))?;

        let page = client
            .create_page(None)
            .await
            .map_err(|e| format!("warmup_session: failed to create page: {e}"))?;

        // ── Navigate to target URL ────────────────────────────────────────
        page.navigate(&url, WaitUntil::Load)
            .await
            .map_err(|e| format!("warmup_session: failed to navigate to '{}': {e}", url))?;

        // ── Execute warm-up sequence ──────────────────────────────────────
        execute_warmup(&page, &sequence)
            .await
            .map_err(|e| format!("warmup_session: warmup execution failed: {e}"))?;

        // Count pages visited (we navigated to the target + each warmup step)
        let pages_visited = 1 + sequence.steps.len() as i32;

        // Derive the security origin from the URL for storage access
        let security_origin = extract_security_origin(&url);

        // ── Extract cookies via CDP Network.getCookies ────────────────────
        let cdp_cookies: Vec<CdpCookie> = get_cookies(&page.client, &page.session_id)
            .await
            .unwrap_or_default();

        let mut cookies_map: Vec<(Value, Value)> = Vec::new();
        for c in &cdp_cookies {
            cookies_map.push((
                Value::String(c.name.clone()),
                Value::String(c.value.clone()),
            ));
        }

        // ── Extract localStorage ──────────────────────────────────────────
        let local_storage_entries = get_local_storage(
            &page.client,
            &page.session_id,
            &security_origin,
        )
        .await
        .unwrap_or_default();

        let mut local_storage_map: Vec<(Value, Value)> = Vec::new();
        for (k, v) in &local_storage_entries {
            local_storage_map.push((
                Value::String(k.clone()),
                Value::String(v.clone()),
            ));
        }

        // ── Extract sessionStorage ────────────────────────────────────────
        let session_storage_entries = get_session_storage(
            &page.client,
            &page.session_id,
            &security_origin,
        )
        .await
        .unwrap_or_default();

        let mut session_storage_map: Vec<(Value, Value)> = Vec::new();
        for (k, v) in &session_storage_entries {
            session_storage_map.push((
                Value::String(k.clone()),
                Value::String(v.clone()),
            ));
        }

        // ── Extract User-Agent via JS evaluate ────────────────────────────
        let ua = page
            .evaluate_expression("navigator.userAgent")
            .await
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        // ── Clean up browser process ──────────────────────────────────────
        process.kill();

        let duration = start.elapsed().as_secs_f64();
        let proxy_used = browser_config.proxy.unwrap_or_default();

        Ok(Value::Struct {
            name: "WarmupResult".to_string(),
            fields: vec![
                ("cookies".to_string(), Value::Map(cookies_map)),
                ("local_storage".to_string(), Value::Map(local_storage_map)),
                (
                    "session_storage".to_string(),
                    Value::Map(session_storage_map),
                ),
                ("user_agent".to_string(), Value::String(ua)),
                ("proxy_used".to_string(), Value::String(proxy_used)),
                ("duration_seconds".to_string(), Value::Float(duration)),
                ("pages_visited".to_string(), Value::Int(pages_visited as i128)),
            ],
        })
    });

    result
}
