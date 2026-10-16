//! Article extraction engine — warm BrowserPool + stealth.
//!
//! Acquires a pooled browser, wraps it as a `Page`, applies the stealth
//! profile, navigates, lets JS render, scrolls to force lazy-load, then
//! extracts title + article text. Returns a JSON-friendly struct.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use tallow::browser::{
    BrowserPool, Page, StealthProfile, WaitUntil,
};

/// POST /extract request body.
#[derive(Debug, Deserialize)]
pub struct ExtractRequest {
    pub url: String,
    #[serde(default)]
    pub anon: bool,
}

/// Extraction result returned to NixReader.
#[derive(Debug, Serialize)]
pub struct ExtractResult {
    pub url: String,
    pub title: String,
    pub content: String,
    pub length: usize,
    pub source: String,
    pub member: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Browser cookies harvested after navigation (e.g. DataDome `ct` for WSJ).
    /// Lets the caller replay the same session server-side with the bypass cookie.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub cookies: HashMap<String, String>,
}

impl ExtractResult {
    pub fn error(url: &str, msg: impl Into<String>) -> Self {
        let msg = msg.into();
        Self {
            url: url.to_string(),
            title: String::new(),
            content: String::new(),
            length: 0,
            source: "error".to_string(),
            member: false,
            exit_ip: None,
            error: Some(msg),
            cookies: HashMap::new(),
        }
    }
}

/// Run one full stealth extraction against the appropriate pool.
///
/// `anon=false` → default egress pool (Tor-routed since 2026-09-28: the
///               T-207 zone lockdown refuses unproxied browser egress and
///               Chromium can't present SOCKS credentials — see the pool
///               note in main.rs).
/// `anon=true`  → Tor-backed pool (socks5://127.0.0.1:9050).
///
/// The pool pairs `acquire()` with `release(index)` — we call release
/// explicitly (so cookies/cache are recycled) even on the error path.
pub async fn extract(
    pool: &Arc<BrowserPool>,
    tor_pool: &Arc<BrowserPool>,
    url: &str,
    anon: bool,
) -> ExtractResult {
    let target = if anon { tor_pool } else { pool };

    // Fail fast if an anon (Tor) request arrives while Tor is down, rather
    // than letting the browser hang trying to connect through a dead SOCKS.
    if anon && !tor_up() {
        return ExtractResult::error(url, "anonymous mode requested but Tor (127.0.0.1:9050) is not up");
    }

    let handle = match target.acquire().await {
        Ok(h) => h,
        Err(e) => return ExtractResult::error(url, format!("pool acquire: {e}")),
    };
    let idx = handle.index;

    // Wrap the acquired browser as a Page. pool_index + pool set so the
    // Page cooperates with the pool lifecycle.
    let page = Page::from_cdp(
        handle.client.clone(),
        handle.session_id.clone(),
        Some(idx),
        Some(Arc::clone(target)),
    );

    // Stealth profile (Chrome UA). Keeps Cloudflare/datacenter checks happy.
    let profile = StealthProfile::chrome_linux();
    if let Err(e) = page.apply_stealth(&profile).await {
        return ExtractResult::error(url, format!("stealth: {e}"));
    }

    // Site-specific referrer tricks via CDP headers (whitelisted heavy-traffic
    // referrers make the server serve the full body).
    //  - Medium: site-28.example referrer (Medium whitelists Twitter).
    //  - WSJ/Dow Jones family: drudgereport.com referrer (BPC: a heavy-traffic
    //    referrer WSJ whitelists).
    // Only meaningful from a non-anon (non-Tor) origin.
    if !anon {
        let mut hdrs = HashMap::new();
        if url.contains("site-18.example") {
            hdrs.insert("Referer".to_string(), "https://site-28.example/reader".to_string());
        } else if is_dowjones(url) {
            hdrs.insert(
                "Referer".to_string(),
                "https://www.drudgereport.com/".to_string(),
            );
        } else if is_cxense_site(url) {
            // Other Cxense-metered publishers: a search-engine/social referrer
            // makes the server serve the full (client-side-gated) body.
            hdrs.insert(
                "Referer".to_string(),
                "https://news.google.com/".to_string(),
            );
        }
        if !hdrs.is_empty() {
            let _ = handle
                .client
                .send_command(
                    "Network.setExtraHTTPHeaders",
                    Some(serde_json::json!({"headers": hdrs})),
                )
                .await;
        }
    }

    // Reset Cxense meter cookies before navigation so the pooled browser starts a
    // fresh free-article quota on every Cxense-metered page (cX_P/cX_C/_cX_…).
    // Leaving stale counters would let the meter gate the already-served body.
    if is_cxense_site(url) || is_dowjones(url) {
        match page.delete_cookies_by_prefix(&["cX_", "cX_P", "cX_C", "cX_G", "cX_S"]).await {
            Ok(n) if n > 0 => tracing::info!("cleared {n} Cxense meter cookies for {}", url),
            Ok(_) => {}
            Err(e) => tracing::debug!("clear Cxense cookies: {e}"),
        }
    }

    let mut result = run_extraction(&page, url).await;

    // Harvest cookies after navigation (DataDome `ct`, WSJ session, etc.) so the
    // caller can replay this exact session server-side with the bypass cookie.
    if let Ok(cookies) = page.get_cookies().await {
        let map: HashMap<String, String> = cookies
            .into_iter()
            .filter(|c| !c.name.is_empty())
            .map(|c| (c.name, c.value))
            .collect();
        result.cookies = map;
    }

    // Release back to the pool regardless of outcome.
    let _ = target.release(idx).await;

    result
}

/// Quick TCP check that the local Tor SOCKS port is accepting connections.
fn tor_up() -> bool {
    use std::net::TcpStream;
    TcpStream::connect_timeout(
        &"127.0.0.1:9050".parse().unwrap(),
        std::time::Duration::from_millis(1500),
    )
    .is_ok()
}

/// Dow Jones Cxense-metered family — served full body client-side; use the
/// drudgereport heavy-traffic referrer (BPC recipe).
fn is_dowjones(url: &str) -> bool {
    ["site-34.example", "marketwatch.com", "barrons.com", "dowjones.com"]
        .iter()
        .any(|d| url.contains(d))
}

/// Other Cxense-metered publishers — search-engine/social referrer unlocks the
/// client-side-gated full body.
fn is_cxense_site(url: &str) -> bool {
    [
        "theatlantic.com",
        "newyorker.com",
        "foreignpolicy.com",
        "foreignaffairs.com",
        "courant.com",
        "chicagotribune.com",
        "nypost.com",
        "theglobeandmail.com",
        "fortune.com",
        "statnews.com",
        "politico.com",
        "theinformation.com",
        "ft.com",
    ]
    .iter()
    .any(|d| url.contains(d))
}

async fn run_extraction(page: &Page, url: &str) -> ExtractResult {

    // Navigate; tolerate timeout (some sites never fire DOMContentLoaded).
    let nav = page.navigate(url, WaitUntil::DomContentLoaded).await;
    match &nav {
        Ok(n) => tracing::info!("nav status={:?} final={}", n.status_code, n.url),
        Err(e) => tracing::warn!("nav (soft) err: {e}"),
    }

    // Let JS render (paywall gate, lazy images, Cloudflare checks).
    tokio::time::sleep(std::time::Duration::from_millis(5000)).await;

    // Cxense mirrors its meter cookies (`cX_*`) in localStorage as `_cX_*`,
    // which can re-anchor the paywall profile even after the cookie is cleared.
    // Purge them for Cxense-metered / Dow Jones domains so the meter starts a
    // fresh quota. (Best-effort; the localStorage keys differ per publisher.)
    if is_cxense_site(url) || is_dowjones(url) {
        let _ = page
            .evaluate_expression(
                "(()=>{var n=0;try{for(var i=localStorage.length-1;i>=0;i--){var k=localStorage.key(i);if(k&&(k.startsWith('_cX_')||k.startsWith('cX_'))){localStorage.removeItem(k);n++;}}}catch(e){}return n})()",
            )
            .await;
    }

    // Scroll to force lazy-loading of the rest of the article body.
    for _ in 0..6 {
        let _ = page
            .evaluate_expression("window.scrollBy(0, document.body.scrollHeight/6)")
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Detect Cloudflare/JS challenge + DataDome interstitial.
    let mut dd_cookie_harvested: Option<String> = None;
    if let Ok(diag) = page
        .evaluate_expression(
            r#"JSON.stringify({
                url: location.href,
                title: document.title,
                bodyLen: (document.body ? document.body.innerText.length : 0),
                isChallenge: (document.querySelector('#challenge-form, .cf-please-wait, iframe[src*="challenges.cloudflare"], .g-recaptcha, [class*="challenge"]') !== null)
            })"#,
        )
        .await
    {
        let s = diag.to_string();
        if s.contains("\"isChallenge\":true") {
            return ExtractResult::error(url, "blocked by JS/Cloudflare challenge");
        }
    }

    // DataDome interstitial (WSJ/MarketWatch/Barron's + others). Two paths:
    // 1) JS proof-of-work that auto-resolves when the stealth fingerprint passes —
    //    wait for it; 2) interactive slider (flagged datacenter ASN) — solve via a
    //    configured CAPTCHA service, inject the cookie, reload. Either way, harvest
    //    the validated `datadome` cookie for the caller to replay server-side.
    let dd = crate::datadome::detect(&page).await;
    if dd.is_challenge {
        let vendor = dd.vendor.clone().unwrap_or_else(|| "datadome".to_string());
        tracing::info!("bot-check challenge detected (vendor={vendor}, rt={:?}, has_cookie={})", dd.rt, dd.has_cookie);
        if vendor == "perimeterx" {
            // PerimeterX / HUMAN interstitial is a JS proof-of-work that auto-resolves
            // when the stealth fingerprint passes (verified on Bloomberg). Resolve it
            // (passive wait → click checkbox → reload), then the extraction below reads
            // the real article. No solver needed, no cookie replay.
            tracing::info!("PerimeterX interstitial — resolving (passive → click → reload)");
            if crate::datadome::resolve_perimeterx(&page).await {
                tracing::info!("PerimeterX auto-resolved (stealth passed)");
            } else {
                tracing::warn!("PerimeterX challenge did not resolve");
            }
        } else {
            // DataDome: Path 1 — wait for JS proof-of-work to auto-resolve.
            let resolved = crate::datadome::wait_for_resolution(&page, 15).await;
            if resolved {
                tracing::info!("DataDome JS proof-of-work auto-resolved (stealth passed)");
            } else {
                // Path 2: challenge persists — try the configured CAPTCHA solver
                // (DataDomeSliderTask handles every DataDome mode).
                tracing::warn!("DataDome challenge persisted after PoW wait; attempting solver (if configured)");
                match crate::datadome::solve_interactive(&page, url).await {
                    Ok(Some(cookie)) => dd_cookie_harvested = Some(cookie),
                    Ok(None) => tracing::warn!("no CAPTCHA solver configured (set TALLOW_2CAPTCHA_API_KEY) — challenge unsolved"),
                    Err(e) => tracing::warn!("DataDome solve failed: {e}"),
                }
            }
            // Harvest whatever `datadome` cookie exists now (initial or validated) so
            // the caller can replay it server-side even if the browser couldn't read.
            if dd_cookie_harvested.is_none() {
                if let Ok(cookies) = page.get_cookies().await {
                    for c in cookies {
                        if c.name.eq_ignore_ascii_case("datadome") && !c.value.is_empty() {
                            dd_cookie_harvested = Some(c.value);
                            break;
                        }
                    }
                }
            }
        }
    }

    // Extract: prefer article body containers. Use textContent NOT innerText
    // (Medium's paywall is CSS-only; innerText omits CSS-hidden nodes).
    // Strip script/style/noscript/template nodes first so Next.js flight
    // payloads and inline styles never leak into the article text.
    let script = r#"
      (function(){
        function strip(root){
          var clone = root.cloneNode(true);
          clone.querySelectorAll('script, style, noscript, template, iframe, svg, canvas, [aria-hidden="true"]').forEach(function(n){ n.parentNode && n.parentNode.removeChild(n); });
          return clone;
        }
        var out = {};
        var root = document.querySelector('.meteredContent, .pw-post-body, [data-testid*="postContent"], article') || document.body;
        out.title = (document.querySelector('meta[property="og:title"]')||{}).content
                    || (document.querySelector('h1')||{}).textContent || document.title;
        var clean = strip(root);
        var raw = (clean.textContent || '').replace(/\u00a0/g,' ');
        raw = raw.replace(/[ \t]+/g,' ').replace(/\n{3,}/g,'\n\n').trim();
        var lines = raw.split('\n').filter(function(l){
            var t=l.trim(); if(!t) return true;
            if(/^(Get app|Write|Sign up|Sign in|Follow|Member-only story|Press enter or click to view image in full size)$/i.test(t)) return false;
            if(/^(\d+ min read|·|\d+ clap|\d+ response|\d+ repost)/.test(t)) return false;
            return true;
        });
        out.content = lines.join('\n').trim();
        out.member = (root.querySelector('.meteredContent, [class*="metered"]') !== null) || /medium/i.test(document.title) && out.content.length>500;
        return JSON.stringify(out);
      })()
    "#;
    let res = page.evaluate_expression(script).await;
    let s = res.map(|x| x.to_string()).unwrap_or_default();

    let parsed = parse_double_json(&s);
    let title = parsed.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let content = parsed.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let member = parsed.get("member").and_then(|v| v.as_bool()).unwrap_or(false);

    let length = content.len();

    // Fallback: if empty, grab full body text (scripts stripped).
    if length < 80 {
        if let Ok(alt) = page
            .evaluate_expression(
                "JSON.stringify({title:document.title, content:(function(){var c=document.body.cloneNode(true);c.querySelectorAll('script,style,noscript,template,iframe,svg').forEach(function(n){n.parentNode&&n.parentNode.removeChild(n)});return (c.textContent||'').trim().substring(0,200000)})()})",
            )
            .await
        {
            let alt_s = alt.to_string();
            let a = parse_double_json(&alt_s);
            let a_title = a.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let a_content = a.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let a_len = a_content.len();
            if !a_content.is_empty() {
                return ExtractResult {
                    url: url.to_string(),
                    title: if title.is_empty() { a_title } else { title },
                    content: a_content,
                    length: a_len,
                    source: "stealth-browser".to_string(),
                    member,
                    exit_ip: None,
                    error: None,
                    cookies: HashMap::new(),
                };
            }
        }
    }

    if length < 80 {
        // Even on failure, return the DataDome cookie so the caller can replay it.
        let mut cookies = HashMap::new();
        if let Some(c) = dd_cookie_harvested.clone() {
            cookies.insert("datadome".to_string(), c);
        }
        return ExtractResult {
            url: url.to_string(),
            title,
            content,
            length,
            source: "stealth-browser".to_string(),
            member,
            exit_ip: None,
            error: Some("no readable content extracted".to_string()),
            cookies,
        };
    }

    let mut cookies = HashMap::new();
    if let Some(c) = dd_cookie_harvested {
        cookies.insert("datadome".to_string(), c);
    }
    ExtractResult {
        url: url.to_string(),
        title,
        content,
        length,
        source: "stealth-browser".to_string(),
        member,
        exit_ip: None,
        error: None,
        cookies,
    }
}

/// Parse a JS-returned string that is a JSON object (possibly double-encoded:
/// the CDP result may itself be a String containing JSON).
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
