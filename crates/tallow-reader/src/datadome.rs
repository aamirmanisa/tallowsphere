//! DataDome challenge handling for the Tallow reader engine.
//!
//! DataDome sits at the edge of WSJ/MarketWatch/Barron's and many others. It has
//! two challenge modes, both delivered as a ~770-byte interstitial page:
//!
//! - **JS proof-of-work** (`rt:''` in the `dd` blob, or a "solving…" interstitial):
//!   the browser runs `ct.captcha-delivery.com/i.js`, which computes a proof-of-work
//!   and — IF the browser fingerprint passes DataDome's checks — sets a validated
//!   `datadome` cookie and reloads. This auto-resolves when our stealth profile
//!   (esp. `stealth_v3`, which targets DataDome Picasso) passes.
//! - **Interactive slider** (`rt:'i'`): shown to flagged datacenter ASNs even with
//!   perfect fingerprints. Requires a human drag OR an external CAPTCHA-solving
//!   service (`DataDomeSliderTask`).
//!
//! This module: detects the challenge, waits for JS proof-of-work to resolve, and
//! if a solver API key is configured (`TALLOW_2CAPTCHA_API_KEY` / capsolver/2captcha),
//! submits `DataDomeSliderTask`, injects the returned `datadome` cookie, reloads,
//! and returns the validated cookie for server-side replay.

use std::time::Duration;

use tallow::browser::Page;
use tallow::browser::captcha::{
    solve_captcha, CaptchaBackend, CaptchaInfo, CaptchaSolverConfig, CaptchaType,
};

/// Marker JS: returns whether the current page is a bot-check interstitial
/// (DataDome challenge OR PerimeterX/HUMAN "unusual activity" page), not the real
/// article.
const DETECT_JS: &str = r#"
(()=>{
  var html = (document.documentElement.outerHTML || '').toLowerCase();
  var body = (document.body ? document.body.innerText : '') || '';
  var ddCookie = document.cookie.match(/(?:^|;\s*)datadome=([^;]*)/);
  var isDdPage = html.indexOf('ct.captcha-delivery.com') !== -1
    || html.indexOf('captcha-delivery') !== -1
    || html.indexOf('var dd=') !== -1
    || (body.indexOf('enable js') !== -1 && body.indexOf('ad blocker') !== -1)
    || (ddCookie && body.length < 300);
  // PerimeterX / HUMAN interstitial ("Are you a robot?" / "unusual activity ... not a robot")
  var isPxPage = html.indexOf('_pxhd') !== -1
    || html.indexOf('px-captcha') !== -1
    || html.indexOf('perimeterx') !== -1
    || (body.indexOf('not a robot') !== -1 && body.length < 400)
    || (body.indexOf('unusual activity') !== -1 && body.indexOf('robot') !== -1);
  var dd = null;
  var m = html.match(/var\s+dd\s*=\s*(\{.*?\})<\/script>/s) || html.match(/var\s+dd\s*=\s*(\{.*?\})/s);
  if (m) { try { dd = JSON.parse(m[1].replace(/'/g,'"')); } catch(e){} }
  return JSON.stringify({isChallenge: isDdPage || isPxPage, dd: dd, bodyLen: body.length,
    hasDdCookie: !!ddCookie, ddCookieVal: ddCookie ? ddCookie[1] : null,
    rt: dd ? (dd.rt||'') : null, vendor: isDdPage ? 'datadome' : (isPxPage ? 'perimeterx' : null)});
})()
"#;

/// A parsed view of the current page's bot-check state.
#[derive(Debug, Clone)]
pub struct DatadomeState {
    pub is_challenge: bool,
    pub rt: String,          // DataDome: "" = JS PoW, "i" = interactive/slider
    pub has_cookie: bool,
    pub cookie: Option<String>,
    /// "datadome" | "perimeterx" | None
    pub vendor: Option<String>,
}

/// Detect whether the page is a DataDome challenge or PerimeterX interstitial.
pub async fn detect(page: &Page) -> DatadomeState {
    let s = page
        .evaluate_expression(DETECT_JS)
        .await
        .map(|v| v.to_string())
        .unwrap_or_default();
    let parsed = parse_double_json(&s);
    let is_challenge = parsed
        .get("isChallenge")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let rt = parsed.get("rt").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let has_cookie = parsed
        .get("hasDdCookie")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let cookie = parsed
        .get("ddCookieVal")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let vendor = parsed
        .get("vendor")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    DatadomeState { is_challenge, rt, has_cookie, cookie, vendor }
}

/// Parse a JS-returned string that is a JSON object (possibly double-encoded).
fn parse_double_json(s: &str) -> serde_json::Map<String, serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(s)
        .ok()
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            serde_json::Value::String(inner) => serde_json::from_str::<serde_json::Value>(&inner)
                .ok()
                .and_then(|v2| v2.as_object().cloned()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Wait up to `max_secs` for a DataDome JS proof-of-work challenge to auto-resolve
/// (i.e. the challenge page is replaced by the real article, which happens when the
/// stealth fingerprint passes). Polls every 1.5s. Returns `true` if resolved.
pub async fn wait_for_resolution(page: &Page, max_secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(max_secs);
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let st = detect(page).await;
        if !st.is_challenge {
            return true;
        }
    }
    false
}

/// Resolve a PerimeterX / HUMAN interstitial. PerimeterX is a JS proof-of-work +
/// a "not a robot" checkbox that the stealth browser can usually pass passively;
/// if it lingers, click the checkbox (if present). NOTE: do NOT reload — reloading
/// resets the proof-of-work and the `_pxhd` cookie, restarting the challenge.
/// Returns `true` if the challenge cleared and the real page loaded.
pub async fn resolve_perimeterx(page: &Page) -> bool {
    // Pass 1: passive wait (challenge auto-resolves when fingerprint passes).
    if wait_for_resolution(page, 15).await {
        return true;
    }
    // Pass 2: click the "not a robot" checkbox if a PerimeterX checkbox is visible.
    let _ = page
        .evaluate_expression(
            r#"(function(){
                // PerimeterX renders its checkbox in an iframe or a challenge frame;
                // also try common in-page selectors.
                var el = document.querySelector('[id*="px-captcha"], [class*="px-captcha"], [id*="captcha"], [class*="captcha"], iframe[src*="perimeterx"], iframe[src*="px-captcha"]');
                if (el) { try { el.click(); return 'clicked'; } catch(e){} }
                // Some PX builds expose window._pxCallback / a verify function.
                if (typeof window._pxCallback === 'function') { try { window._pxCallback(); return 'cb'; } catch(e){} }
                return 'none';
            })()"#,
        )
        .await;
    tokio::time::sleep(Duration::from_millis(2000)).await;
    wait_for_resolution(page, 10).await
}

/// Solver config loaded from env:
///   TALLOW_2CAPTCHA_API_KEY  (or TALLOW_CAPTCHA_API_KEY)
///   TALLOW_CAPTCHA_BACKEND   ("2captcha" | "capsolver" | "anticaptcha" | "capmonster")
fn solver_config() -> Option<CaptchaSolverConfig> {
    let api_key = std::env::var("TALLOW_2CAPTCHA_API_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .or_else(|| std::env::var("TALLOW_CAPTCHA_API_KEY").ok().filter(|k| !k.trim().is_empty()))?;
    let backend = match std::env::var("TALLOW_CAPTCHA_BACKEND").ok().unwrap_or_default().to_ascii_lowercase() {
        b if b.contains("capsolver") => CaptchaBackend::CapSolver,
        b if b.contains("anticaptcha") || b.contains("anti-captcha") => CaptchaBackend::AntiCaptcha,
        b if b.contains("capmonster") => CaptchaBackend::CapMonster,
        _ => CaptchaBackend::TwoCaptcha,
    };
    Some(CaptchaSolverConfig::new(&api_key, "").with_backend(backend))
}

/// Attempt to solve an interactive DataDome slider via a configured CAPTCHA-solving
/// service. On success, injects the validated `datadome` cookie into the browser,
/// reloads the page, and returns the cookie value for server-side replay.
///
/// Returns `Ok(Some(cookie))` on success, `Ok(None)` if no solver is configured or
/// it failed without producing a cookie, `Err(msg)` on hard errors.
pub async fn solve_interactive(page: &Page, url: &str) -> Result<Option<String>, String> {
    let Some(config) = solver_config() else {
        return Ok(None);
    };
    let st = detect(page).await;

    // The solver needs the current challenge page's dd cookie + the page URL.
    let dd_cookie = st.cookie.clone().unwrap_or_default();
    let mut extra = serde_json::Map::new();
    if !dd_cookie.is_empty() {
        extra.insert("datadomeCookie".to_string(), serde_json::Value::String(dd_cookie));
    }

    let captcha = CaptchaInfo {
        captcha_type: CaptchaType::DataDome,
        site_key: None,
        element_selector: String::new(),
        extra: if extra.is_empty() { None } else { Some(serde_json::Value::Object(extra)) },
    };

    // solve_captcha is blocking (ureq); run it off the async runtime.
    let config_for_thread = config;
    let captcha_for_thread = captcha;
    let url_owned = url.to_string();
    let solution = tokio::task::spawn_blocking(move || {
        solve_captcha(&config_for_thread, &captcha_for_thread, &url_owned)
    })
    .await
    .map_err(|e| format!("solver task join: {e}"))?;

    let cookie_val = solution.map_err(|e| format!("datadome solve failed: {e}"))?;
    if cookie_val.is_empty() {
        return Ok(None);
    }

    // Inject the validated cookie into the browser via CDP Network.setCookie.
    let domain = extract_registrable_domain(url);
    set_cookie(&page, "datadome", &cookie_val, &domain).await;

    // Reload so the article loads with the validated cookie.
    let _ = page.reload(tallow::browser::WaitUntil::DomContentLoaded).await;
    tokio::time::sleep(Duration::from_millis(4000)).await;

    // Confirm the challenge cleared.
    let after = detect(page).await;
    if after.is_challenge {
        // Challenge persists — still return the cookie for server-side replay.
        tracing::warn!("datadome challenge persists after solve; returning cookie anyway");
    } else {
        tracing::info!("datadome challenge cleared after solve");
    }
    Ok(Some(cookie_val))
}

/// Set a cookie in the browser context for `domain` (e.g. "wsj.com").
async fn set_cookie(page: &Page, name: &str, value: &str, domain: &str) {
    // Use document.cookie via CDP (works for non-HttpOnly, which is fine for
    // DataDome replay — the solver returns a client-side cookie).
    let _ = page
        .evaluate_expression(&format!(
            "document.cookie = '{}={}; domain={}; path=/; secure'; 'ok'",
            name, value, domain
        ))
        .await;
}

/// Extract a registrable-ish domain from a URL: strip scheme, port, and leading
/// "www." so the cookie applies to the whole site (e.g. "www.wsj.com" -> "wsj.com").
fn extract_registrable_domain(url: &str) -> String {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = after_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("").to_string();
    if let Some(stripped) = host.strip_prefix("www.") {
        stripped.to_string()
    } else {
        host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_strips_www_and_port() {
        assert_eq!(extract_registrable_domain("https://www.wsj.com/business/earnings/"), "wsj.com");
        assert_eq!(extract_registrable_domain("https://wsj.com/article"), "wsj.com");
        assert_eq!(extract_registrable_domain("https://www.marketwatch.com:443/x"), "marketwatch.com");
        assert_eq!(extract_registrable_domain("http://example.com"), "example.com");
    }
}
