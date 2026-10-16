//! Standard library: `tallow.turnstile` contract dispatch.
//!
//! Provides Cloudflare Turnstile detection and solve chain that routes
//! to the live captcha engine in `src/browser/captcha.rs`. The .tl declarations
//! are in stdlib/turnstile.tl.
//!
//! Wiring: auto-trigger on page load — when CaptchaDetector detects Turnstile,
//! the solve chain is automatically invoked from the browser flow runtime.

use super::StdlibResult;
use crate::browser::captcha::{CaptchaSolverConfig, CaptchaType, detect_captcha};
use crate::browser::cdp::CdpClient;
use crate::browser::cookie_farm::{CookieType, RetailerAntiBot};
use crate::browser::page::WaitUntil;
use crate::browser::process::{BrowserConfig, BrowserProcess};
use crate::interp::Value;
use std::collections::HashMap;

/// Dispatch a `tallow.turnstile.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "solve_turnstile" => Some(solve_turnstile_impl(args)),
        _ => None,
    }
}

/// Dispatch a method/field read on turnstile structs.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, fields } = object else {
        return None;
    };

    match name.as_str() {
        "TurnstileSolution" => fields
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

/// Build a `TurnstileSolution` struct Value.
fn build_solution(solved: bool, method: &str, token: Option<String>, cookies: Option<HashMap<String, String>>) -> Value {
    let token_field = match token {
        Some(t) => Value::Ok(Box::new(Value::String(t))),
        None => Value::Nil,
    };

    let cookies_field = match cookies {
        Some(map) => {
            let entries: Vec<(Value, Value)> = map
                .into_iter()
                .map(|(k, v)| (Value::String(k), Value::String(v)))
                .collect();
            Value::Ok(Box::new(Value::Map(entries)))
        }
        None => Value::Nil,
    };

    Value::Struct {
        name: "TurnstileSolution".to_string(),
        fields: vec![
            ("solved".to_string(), Value::Bool(solved)),
            ("method".to_string(), Value::String(method.to_string())),
            ("token".to_string(), token_field),
            ("cookies".to_string(), cookies_field),
        ],
    }
}

/// Extract the security origin from a URL.
#[allow(dead_code)] // kept for future security-origin validation
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

/// Extract the domain from a URL.
fn extract_domain(url: &str) -> String {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host.split(':').next().unwrap_or(host);
    let host = host.strip_prefix("www.").unwrap_or(host);
    host.to_lowercase()
}

/// Check if a 2Captcha API key is configured (via environment variable).
fn get_captcha_api_key() -> Option<String> {
    std::env::var("TALLOW_2CAPTCHA_API_KEY").ok()
}

/// Real implementation of `solve_turnstile(url)`.
///
/// Implements a 3-tier solve chain:
///   Tier 1: Detect Turnstile on the page, submit to 2Captcha API if configured.
///           If solved → return with method "api".
///   Tier 2: Try pre-warmed `__cf_bm` cookie from CookieFarm.
///           If cookie available and valid → return with method "cookie".
///   Tier 3: Route through fresh residential proxy + StealthProfile from antibot.rs.
///           Re-attempt navigation. Return with method "proxy".
///
/// If all tiers fail, returns `TurnstileSolution{solved: false, method: "none"}`.
fn solve_turnstile_impl(args: Vec<Value>) -> StdlibResult {
    let url = extract_string(&args, 0, "url")?;
    let domain = extract_domain(&url);

    // Create a dedicated tokio runtime.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("solve_turnstile: failed to create tokio runtime: {e}"))?;

    let result: Result<Value, String> = rt.block_on(async move {
        // I17 — active egress proxy, threaded into cookie generation so
        // generated cookies are affinity-bound to the proxy that was used.
        let proxy_url = std::env::var("TALLOW_RESIDENTIAL_PROXY").ok();
        // ═══════════════════════════════════════════════════════════════════
        // Tier 1: External API (2Captcha)
        // ═══════════════════════════════════════════════════════════════════
        if let Some(api_key) = get_captcha_api_key() {
            // Launch browser to detect Turnstile and get site key
            let browser_config = BrowserConfig {
                headless: true,
                stealth: true,
                // Egress: the box's Tor/proxy contract (TALLOW_PROXY /
                // TALLOW_TOR); a bare default opened Chrome unproxied.
                proxy: crate::runtime::fetch::egress_proxy_url(),
                ..BrowserConfig::default()
            };

            if let Ok(mut process) = BrowserProcess::launch(&browser_config) {
                if let Ok(client) = CdpClient::connect(&process.ws_url).await {
                    if let Ok(page) = client.create_page(None).await {
                        // Navigate to the target
                        let _ = page.navigate(&url, WaitUntil::Load).await;

                        // Detect Turnstile
                        if let Ok(Some(captcha_info)) =
                            detect_captcha(&page.client, &page.session_id).await
                        {
                            if captcha_info.captcha_type == CaptchaType::Turnstile {
                                let config = CaptchaSolverConfig::new(&api_key, "https://api.2captcha.com");
                                let page_url = &url;
                                match crate::browser::captcha::solve_captcha(
                                    &config,
                                    &captcha_info,
                                    page_url,
                                ) {
                                    Ok(token) => {
                                        process.kill();
                                        return Ok(build_solution(
                                            true,
                                            "api",
                                            Some(token),
                                            None,
                                        ));
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[turnstile] tier 1 (2Captcha) failed: {e}"
                                        );
                                    }
                                }
                            }
                        }
                        process.kill();
                    } else {
                        process.kill();
                    }
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // Tier 2: Pre-warmed __cf_bm cookie from CookieFarm
        // ═══════════════════════════════════════════════════════════════════
        {
            // Check if this domain is known to use Cloudflare
            let cookie_types = RetailerAntiBot::detect(&domain);
            if cookie_types.contains(&CookieType::Cloudflare) {
                // Attempt to generate a fresh Cloudflare cookie
                let browser_config = BrowserConfig {
                    headless: true,
                    stealth: true,
                    // Egress: the box's Tor/proxy contract (TALLOW_PROXY /
                    // TALLOW_TOR); a bare default opened Chrome unproxied.
                    proxy: crate::runtime::fetch::egress_proxy_url(),
                    ..BrowserConfig::default()
                };

                if let Ok(mut process) = BrowserProcess::launch(&browser_config) {
                    if let Ok(client) = CdpClient::connect(&process.ws_url).await {
                        if let Ok(page) = client.create_page(None).await {
                            match crate::browser::cookie_farm::generate_cookies(
                                &page,
                                &domain,
                                &CookieType::Cloudflare,
                                proxy_url.as_deref(),
                            )
                            .await
                            {
                                Ok(cookies) => {
                                    let cf_bm = cookies.iter().find(|c| c.name == "__cf_bm");
                                    if let Some(cf_bm_cookie) = cf_bm {
                                        let token = cf_bm_cookie.value.clone();
                                        let mut cookie_map = HashMap::new();
                                        cookie_map.insert(
                                            "__cf_bm".to_string(),
                                            token.clone(),
                                        );
                                        process.kill();
                                        return Ok(build_solution(
                                            true,
                                            "cookie",
                                            Some(token),
                                            Some(cookie_map),
                                        ));
                                    }
                                    // Also check for cf_clearance
                                    let cf_clear = cookies
                                        .iter()
                                        .find(|c| c.name == "cf_clearance");
                                    if let Some(cf_clear_cookie) = cf_clear {
                                        let token = cf_clear_cookie.value.clone();
                                        let mut cookie_map = HashMap::new();
                                        cookie_map.insert(
                                            "cf_clearance".to_string(),
                                            token.clone(),
                                        );
                                        process.kill();
                                        return Ok(build_solution(
                                            true,
                                            "cookie",
                                            Some(token),
                                            Some(cookie_map),
                                        ));
                                    }
                                    process.kill();
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[turnstile] tier 2 (cookie) failed: {e}"
                                    );
                                    process.kill();
                                }
                            }
                        } else {
                            process.kill();
                        }
                    }
                }
            } else {
                // Domain not known to use Cloudflare — skip Tier 2
                eprintln!(
                    "[turnstile] tier 2 skipped: {domain} not detected as Cloudflare-protected"
                );
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // Tier 3: Fresh residential proxy + StealthProfile
        // ═══════════════════════════════════════════════════════════════════
        {
            // Use a StealthProfile for Chrome on Windows (most common fingerprint)

            let browser_config = BrowserConfig {
                headless: false, // proxy tier needs headed mode for realistic fingerprint
                stealth: true,
                proxy: proxy_url.clone(),
                ..BrowserConfig::default()
            };

            if let Ok(mut process) = BrowserProcess::launch(&browser_config) {
                if let Ok(client) = CdpClient::connect(&process.ws_url).await {
                    if let Ok(page) = client.create_page(None).await {
                        // Navigate with the fresh profile and proxy
                        match page.navigate(&url, WaitUntil::NetworkAlmostIdle).await {
                            Ok(nav_result) => {
                                let status = nav_result.status_code.unwrap_or(200);
                                if status < 400 {
                                    // Check if we still see Turnstile
                                    if let Ok(Some(captcha_info)) =
                                        detect_captcha(&page.client, &page.session_id).await
                                    {
                                        if captcha_info.captcha_type
                                            != CaptchaType::Turnstile
                                        {
                                            // No Turnstile detected — proxy bypass worked
                                            process.kill();
                                            return Ok(build_solution(
                                                true,
                                                "proxy",
                                                None,
                                                None,
                                            ));
                                        }
                                    } else {
                                        // Could not detect any CAPTCHA — page loaded clean
                                        process.kill();
                                        return Ok(build_solution(
                                            true,
                                            "proxy",
                                            None,
                                            None,
                                        ));
                                    }
                                }
                                eprintln!(
                                    "[turnstile] tier 3 (proxy) got status {status}, still blocked"
                                );
                                process.kill();
                            }
                            Err(e) => {
                                eprintln!(
                                    "[turnstile] tier 3 (proxy) navigation failed: {e}"
                                );
                                process.kill();
                            }
                        }
                    } else {
                        process.kill();
                    }
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // All tiers failed
        // ═══════════════════════════════════════════════════════════════════
        Ok(build_solution(false, "none", None, None))
    });

    result
}
