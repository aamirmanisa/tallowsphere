//! DrissionPage-style dual-mode engine + image-rendered price detection.
//!
//! Inspired by the Chinese scraping framework DrissionPage (30K+ GitHub stars),
//! this module provides seamless mid-session switching between browser mode
//! (full Chrome CDP) and HTTP mode (raw reqwest). The key workflow:
//!
//! 1. Start in browser mode to solve CAPTCHAs, handle JS challenges, get cookies
//! 2. Extract cookies, localStorage, User-Agent from the live browser session
//! 3. Switch to HTTP mode using those exact session artifacts for 10-100x speed
//! 4. Switch back to browser mode if HTTP gets blocked
//!
//! Also includes an image-rendered price detector for Chinese anti-scraping
//! techniques where prices are rendered as images instead of text.

use std::collections::HashMap;

use reqwest::header::{COOKIE, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::cdp::CdpClient;
use super::error::BrowserError;
use super::page::{Page, WaitUntil};
use super::process::{BrowserConfig, BrowserProcess};
use super::session::{CdpCookie, get_cookies, get_local_storage};

// ── Engine Mode ─────────────────────────────────────────────────────────

/// Operating mode for the dual-mode engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineMode {
    /// Fast HTTP-only mode using reqwest.
    Http,
    /// Full Chrome CDP browser mode.
    Browser,
    /// Engine decides per-request: try HTTP first, fall back to browser.
    Auto,
}

impl std::fmt::Display for EngineMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineMode::Http => write!(f, "HTTP"),
            EngineMode::Browser => write!(f, "Browser"),
            EngineMode::Auto => write!(f, "Auto"),
        }
    }
}

// ── Browser Session Info ────────────────────────────────────────────────

/// Captured browser session state for transfer to HTTP mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSessionInfo {
    /// WebSocket URL of the Chrome DevTools endpoint.
    pub ws_url: String,
    /// CDP session ID for the attached target.
    pub session_id: String,
    /// Cookies extracted from the browser: (name, value, domain).
    pub cookies: Vec<(String, String, String)>,
    /// localStorage key-value pairs.
    pub local_storage: HashMap<String, String>,
}

// ── Response type ───────────────────────────────────────────────────────

/// Unified response from either HTTP or browser fetch.
#[derive(Debug, Clone)]
pub struct DualModeResponse {
    /// HTTP status code (200 for successful browser navigations).
    pub status: u16,
    /// Response body as text.
    pub body: String,
    /// Final URL after redirects.
    pub url: String,
    /// Which mode produced this response.
    pub source: EngineMode,
}

// ── Dual Mode Engine ────────────────────────────────────────────────────

/// DrissionPage-style engine that seamlessly switches between browser and HTTP modes.
///
/// The engine maintains session continuity across mode switches by extracting
/// cookies, localStorage, and User-Agent from the browser and injecting them
/// into the HTTP client, so the server sees a single continuous session.
pub struct DualModeEngine {
    /// reqwest HTTP client built with extracted browser session cookies/headers.
    http_client: Option<reqwest::Client>,
    /// Captured browser session info for mode switching.
    browser_session: Option<BrowserSessionInfo>,
    /// Merged cookies from both modes: name -> value.
    cookies: HashMap<String, String>,
    /// Custom headers to send with HTTP requests.
    headers: HashMap<String, String>,
    /// Current operating mode.
    mode: EngineMode,
    /// User-Agent string (extracted from browser or default).
    ua: String,
    /// The live browser process (kept alive across mode switches).
    browser_process: Option<BrowserProcess>,
    /// The live CDP client (kept alive for switching back to browser).
    cdp_client: Option<CdpClient>,
    /// The live Page handle.
    page: Option<Page>,
    /// The security origin for localStorage access.
    last_origin: Option<String>,
}

impl DualModeEngine {
    /// Create a new dual-mode engine starting in Auto mode.
    pub fn new() -> Self {
        Self {
            http_client: None,
            browser_session: None,
            cookies: HashMap::new(),
            headers: HashMap::new(),
            mode: EngineMode::Auto,
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
                .to_string(),
            browser_process: None,
            cdp_client: None,
            page: None,
            last_origin: None,
        }
    }

    /// Create a new dual-mode engine with a specific User-Agent.
    pub fn with_user_agent(ua: &str) -> Self {
        let mut engine = Self::new();
        engine.ua = ua.to_string();
        engine
    }

    /// Start in browser mode: launch Chrome, navigate to the URL, return the page HTML.
    ///
    /// This is the entry point for the DrissionPage workflow: start in browser mode
    /// to solve CAPTCHAs, accept cookie banners, handle JS challenges, etc.
    pub async fn start_browser(&mut self, url: &str) -> Result<String, BrowserError> {
        // Launch Chrome if not already running
        if self.browser_process.is_none() {
            let config = BrowserConfig::default();
            let process = BrowserProcess::launch(&config)?;
            let ws_url = process.ws_url.clone();

            let client = CdpClient::connect(&ws_url).await?;

            // Attach to a target (create new page)
            let targets = client.send_command("Target.getTargets", None).await?;
            let target_id = targets["targetInfos"]
                .as_array()
                .and_then(|arr| {
                    arr.iter()
                        .find(|t| t["type"].as_str() == Some("page"))
                        .and_then(|t| t["targetId"].as_str())
                        .map(|s| s.to_string())
                })
                .ok_or_else(|| {
                    BrowserError::ConnectionFailed("no page target found".to_string())
                })?;

            let attach_result = client
                .send_command(
                    "Target.attachToTarget",
                    Some(json!({"targetId": target_id, "flatten": true})),
                )
                .await?;

            let session_id = attach_result["sessionId"]
                .as_str()
                .unwrap_or_default()
                .to_string();

            // Enable necessary domains
            client
                .send_command_with_session("Page.enable", None, &session_id)
                .await?;
            client
                .send_command_with_session("Network.enable", None, &session_id)
                .await?;

            let page = Page::from_cdp(client.clone(), session_id, None, None);
            self.browser_process = Some(process);
            self.cdp_client = Some(client);
            self.page = Some(page);
        }

        let page = self
            .page
            .as_ref()
            .ok_or_else(|| BrowserError::ConnectionFailed("no page available".to_string()))?;

        // Navigate
        page.navigate(url, WaitUntil::NetworkIdle).await?;

        // Extract the User-Agent from the live browser
        let ua_result = page.evaluate_expression("navigator.userAgent").await;
        if let Ok(val) = ua_result {
            if let Some(ua_str) = val
                .get("result")
                .and_then(|r| r.get("value"))
                .and_then(|v| v.as_str())
            {
                self.ua = ua_str.to_string();
            }
        }

        // Store the origin for localStorage access
        if let Ok(parsed) = url::Url::parse(url) {
            self.last_origin = Some(format!(
                "{}://{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or("localhost")
            ));
        }

        self.mode = EngineMode::Browser;

        // Return the page HTML
        let html = page
            .evaluate_expression("document.documentElement.outerHTML")
            .await?;
        let body = html
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(body)
    }

    /// Extract cookies and session from the browser and switch to HTTP mode.
    ///
    /// This is the core DrissionPage innovation: after the browser has solved
    /// CAPTCHAs and established a session, we extract ALL cookies (including
    /// httpOnly via CDP `Network.getCookies`), localStorage, and the User-Agent,
    /// then build an HTTP client with those exact session artifacts.
    pub async fn switch_to_http(&mut self) -> Result<(), BrowserError> {
        let page = self.page.as_ref().ok_or_else(|| {
            BrowserError::ConnectionFailed("no browser session to extract from".to_string())
        })?;

        // Extract all cookies via CDP (includes httpOnly cookies)
        let cdp_cookies = get_cookies(&page.client, &page.session_id).await?;

        // Build cookie map and session info
        let mut cookie_tuples = Vec::new();
        for c in &cdp_cookies {
            self.cookies.insert(c.name.clone(), c.value.clone());
            cookie_tuples.push((c.name.clone(), c.value.clone(), c.domain.clone()));
        }

        // Extract localStorage if we have an origin
        let mut local_storage = HashMap::new();
        if let Some(ref origin) = self.last_origin {
            if let Ok(items) = get_local_storage(&page.client, &page.session_id, origin).await {
                for (k, v) in items {
                    local_storage.insert(k, v);
                }
            }
        }

        // Save session info for potential switch back
        self.browser_session = Some(BrowserSessionInfo {
            ws_url: self
                .browser_process
                .as_ref()
                .map(|p| p.ws_url.clone())
                .unwrap_or_default(),
            session_id: page.session_id.clone(),
            cookies: cookie_tuples,
            local_storage,
        });

        // Build reqwest client with extracted cookies and headers
        self.http_client = Some(self.build_http_client(&cdp_cookies)?);
        self.mode = EngineMode::Http;

        Ok(())
    }

    /// Switch back to browser mode (reattach to the same Chrome instance).
    ///
    /// The browser process is kept alive across mode switches, so we can
    /// seamlessly return to full browser mode without relaunching Chrome.
    pub async fn switch_to_browser(&mut self) -> Result<(), BrowserError> {
        if self.page.is_some() && self.browser_process.is_some() {
            self.mode = EngineMode::Browser;
            return Ok(());
        }

        // If browser was somehow lost, reattach using saved session info
        let session = self.browser_session.as_ref().ok_or_else(|| {
            BrowserError::ConnectionFailed("no browser session to reattach to".to_string())
        })?;

        let client = CdpClient::connect(&session.ws_url).await?;
        let page = Page::from_cdp(client.clone(), session.session_id.clone(), None, None);

        // Sync any cookies accumulated in HTTP mode back to the browser
        let cdp_cookies: Vec<CdpCookie> = self
            .cookies
            .iter()
            .map(|(name, value)| CdpCookie {
                name: name.clone(),
                value: value.clone(),
                domain: String::new(),
                path: "/".to_string(),
                expires: 0.0,
                http_only: false,
                secure: false,
                same_site: String::new(),
                size: None,
            })
            .collect();

        if !cdp_cookies.is_empty() {
            super::session::set_cookies(&page.client, &page.session_id, &cdp_cookies).await?;
        }

        self.cdp_client = Some(client);
        self.page = Some(page);
        self.mode = EngineMode::Browser;

        Ok(())
    }

    /// Fetch a URL using the current mode.
    pub async fn fetch(&self, url: &str) -> Result<DualModeResponse, BrowserError> {
        match self.mode {
            EngineMode::Http => self.fetch_http(url).await,
            EngineMode::Browser => self.fetch_browser(url).await,
            EngineMode::Auto => {
                // In auto mode from a non-mutable context, try HTTP
                self.fetch_http(url).await
            }
        }
    }

    /// Fetch with auto mode selection: try HTTP first, fall back to browser if blocked.
    ///
    /// Detection heuristics for "blocked" responses:
    /// - Status 403/429/503
    /// - Body contains CAPTCHA markers
    /// - Body is suspiciously small (< 1KB for expected content pages)
    /// - Body contains JS challenge markers (Cloudflare, Akamai, etc.)
    pub async fn fetch_auto(&mut self, url: &str) -> Result<DualModeResponse, BrowserError> {
        // Try HTTP first (fast path)
        let http_result = self.fetch_http(url).await;

        match http_result {
            Ok(resp) if !is_blocked_response(&resp) => Ok(resp),
            _ => {
                // HTTP failed or got blocked, switch to browser
                if self.mode != EngineMode::Browser {
                    if self.page.is_none() {
                        self.start_browser(url).await?;
                        // start_browser already navigated, get the result
                        let page = self.page.as_ref().ok_or_else(|| {
                            BrowserError::ConnectionFailed(
                                "page not available after start_browser".to_string(),
                            )
                        })?;
                        let html = page
                            .evaluate_expression("document.documentElement.outerHTML")
                            .await?;
                        let body = html
                            .get("result")
                            .and_then(|r| r.get("value"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        return Ok(DualModeResponse {
                            status: 200,
                            body,
                            url: url.to_string(),
                            source: EngineMode::Browser,
                        });
                    }
                    self.switch_to_browser().await?;
                }
                self.fetch_browser(url).await
            }
        }
    }

    /// Get current cookies (merged from both modes).
    pub fn cookies(&self) -> &HashMap<String, String> {
        &self.cookies
    }

    /// Get current operating mode.
    pub fn mode(&self) -> &EngineMode {
        &self.mode
    }

    /// Get the captured browser session info.
    pub fn session_info(&self) -> Option<&BrowserSessionInfo> {
        self.browser_session.as_ref()
    }

    /// Set a custom cookie (applied to both modes on next switch).
    pub fn set_cookie(&mut self, name: &str, value: &str) {
        self.cookies.insert(name.to_string(), value.to_string());
    }

    /// Set a custom header (applied to HTTP mode).
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.insert(name.to_string(), value.to_string());
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Fetch a URL using the HTTP client.
    async fn fetch_http(&self, url: &str) -> Result<DualModeResponse, BrowserError> {
        let client = self.http_client.as_ref().cloned().unwrap_or_else(|| {
            // Build a basic client if none exists yet
            let mut headers = HeaderMap::new();
            if let Ok(ua_val) = HeaderValue::from_str(&self.ua) {
                headers.insert(USER_AGENT, ua_val);
            }
            // Add cookies
            let cookie_str = self.format_cookie_header();
            if !cookie_str.is_empty() {
                if let Ok(val) = HeaderValue::from_str(&cookie_str) {
                    headers.insert(COOKIE, val);
                }
            }
            let mut builder = reqwest::Client::builder()
                .default_headers(headers)
                .redirect(reqwest::redirect::Policy::limited(10))
                .timeout(std::time::Duration::from_secs(30));
            // T-207: in-process browser HTTP rides the zone contract.
            if let Some(zp) = crate::browser::zone::browser_zone_reqwest_proxy()
                .expect("browser-zone egress contract")
            {
                builder = builder.proxy(zp);
            }
            builder.build().unwrap_or_default()
        });

        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| BrowserError::ConnectionFailed(format!("HTTP fetch failed: {e}")))?;

        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        let body = resp
            .text()
            .await
            .map_err(|e| BrowserError::ConnectionFailed(format!("HTTP body read failed: {e}")))?;

        Ok(DualModeResponse {
            status,
            body,
            url: final_url,
            source: EngineMode::Http,
        })
    }

    /// Fetch a URL using the browser (CDP navigation).
    async fn fetch_browser(&self, url: &str) -> Result<DualModeResponse, BrowserError> {
        let page = self.page.as_ref().ok_or_else(|| {
            BrowserError::ConnectionFailed("no browser session available".to_string())
        })?;

        let nav_result = page.navigate(url, WaitUntil::NetworkIdle).await?;

        let html = page
            .evaluate_expression("document.documentElement.outerHTML")
            .await?;
        let body = html
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(DualModeResponse {
            status: nav_result.status_code.unwrap_or(200),
            body,
            url: nav_result.url,
            source: EngineMode::Browser,
        })
    }

    /// Build a reqwest client that mirrors the browser session exactly.
    fn build_http_client(
        &self,
        cdp_cookies: &[CdpCookie],
    ) -> Result<reqwest::Client, BrowserError> {
        let mut headers = HeaderMap::new();

        // Set User-Agent to match the browser
        if let Ok(ua_val) = HeaderValue::from_str(&self.ua) {
            headers.insert(USER_AGENT, ua_val);
        }

        // Set cookie header from extracted CDP cookies
        let cookie_str: String = cdp_cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ");

        if !cookie_str.is_empty() {
            if let Ok(val) = HeaderValue::from_str(&cookie_str) {
                headers.insert(COOKIE, val);
            }
        }

        // Add common browser headers for authenticity
        let browser_headers = [
            (
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            ),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Accept-Encoding", "gzip, deflate, br"),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Site", "none"),
            ("Sec-Fetch-User", "?1"),
            ("Upgrade-Insecure-Requests", "1"),
        ];

        for (name, value) in &browser_headers {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(n, v);
            }
        }

        // Add any custom headers
        for (name, value) in &self.headers {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(n, v);
            }
        }

        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::from_secs(30));
        if let Some(zp) = crate::browser::zone::browser_zone_reqwest_proxy()
            .map_err(BrowserError::ConnectionFailed)?
        {
            builder = builder.proxy(zp);
        }
        builder.build().map_err(|e| {
            BrowserError::ConnectionFailed(format!("failed to build HTTP client: {e}"))
        })
    }

    /// Format cookies as a Cookie header value.
    fn format_cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// ── Blocked response detection ──────────────────────────────────────────

/// Heuristics to detect if an HTTP response indicates blocking.
fn is_blocked_response(resp: &DualModeResponse) -> bool {
    // Status code checks
    if matches!(resp.status, 403 | 429 | 503) {
        return true;
    }

    let body_lower = resp.body.to_lowercase();

    // CAPTCHA markers
    let captcha_markers = [
        "captcha",
        "recaptcha",
        "hcaptcha",
        "cf-challenge",
        "challenge-platform",
        "turnstile",
    ];
    if captcha_markers.iter().any(|m| body_lower.contains(m)) {
        return true;
    }

    // JS challenge markers
    let challenge_markers = [
        "just a moment",         // Cloudflare
        "checking your browser", // Cloudflare
        "please wait",           // Generic
        "access denied",         // WAF
        "ray id",                // Cloudflare
        "_cf_chl_opt",           // Cloudflare challenge
        "akamai",                // Akamai Bot Manager
        "distil",                // Distil Networks
        "datadome",              // DataDome
        "incapsula",             // Imperva/Incapsula
        "perimeterx",            // PerimeterX
    ];
    if challenge_markers.iter().any(|m| body_lower.contains(m)) {
        return true;
    }

    // Suspiciously small body for a real page
    if resp.body.len() < 512 && resp.status == 200 {
        return true;
    }

    false
}

// ════════════════════════════════════════════════════════════════════════
// Feature 2: Image-Rendered Price Detection
// ════════════════════════════════════════════════════════════════════════

/// Result of image-rendered price detection analysis.
#[derive(Debug, Clone)]
pub struct ImagePriceDetection {
    /// Whether image-rendered prices were detected.
    pub has_image_prices: bool,
    /// Confidence score from 0.0 to 1.0.
    pub confidence: f64,
    /// Number of suspected image-price elements found.
    pub image_count: usize,
    /// Human-readable signals that triggered detection.
    pub signals: Vec<String>,
    /// Recommended action: "use_ocr", "use_browser_screenshot", or "normal_extraction".
    pub recommended_action: String,
}

/// Detector for Chinese anti-scraping technique of rendering prices as images.
///
/// Many Chinese e-commerce sites (and some Western ones) render prices as:
/// - `<img>` tags with price digits as sprite images
/// - CSS `background-image` with data URIs or sprite URLs
/// - `<canvas>` elements that draw price text programmatically
/// - Empty text nodes with visible dimensions (font-based icon rendering)
///
/// This detector identifies these patterns so the caller can decide whether
/// to use OCR, browser screenshots, or normal text extraction.
pub struct ImageTextDetector {
    /// CSS selectors for price-like elements.
    price_selectors: Vec<String>,
}

impl ImageTextDetector {
    /// Create a detector with default price selectors.
    pub fn new() -> Self {
        Self {
            price_selectors: vec![
                // Common price class patterns
                ".price".to_string(),
                ".product-price".to_string(),
                ".sale-price".to_string(),
                ".regular-price".to_string(),
                ".current-price".to_string(),
                ".offer-price".to_string(),
                "[class*=\"price\"]".to_string(),
                "[class*=\"Price\"]".to_string(),
                // Chinese e-commerce patterns
                ".J_Price".to_string(),
                ".tb-rmb-num".to_string(),
                ".tm-price".to_string(),
                ".p-price".to_string(),
                // Generic data attribute patterns
                "[data-price]".to_string(),
                "[itemprop=\"price\"]".to_string(),
            ],
        }
    }

    /// Create a detector with custom price selectors.
    pub fn with_selectors(selectors: Vec<String>) -> Self {
        Self {
            price_selectors: selectors,
        }
    }

    /// Detect if a page uses image-rendered text for prices.
    ///
    /// Analyzes the HTML for multiple signals:
    /// 1. Price containers with `<img>` children instead of text
    /// 2. Elements with `background-image` CSS (inline styles)
    /// 3. Empty text but visible dimensions (width/height attributes)
    /// 4. Class names containing sprite/image-price patterns
    /// 5. Canvas elements near price containers
    /// 6. Data URI images in price regions
    pub fn detect_image_prices(&self, html: &str) -> ImagePriceDetection {
        let document = Html::parse_document(html);
        let mut signals: Vec<String> = Vec::new();
        let mut image_count: usize = 0;
        let mut score: f64 = 0.0;

        // Signal 1: Price containers with <img> children
        let img_in_price_count = self.count_img_in_price_containers(&document);
        if img_in_price_count > 0 {
            signals.push(format!(
                "{img_in_price_count} price container(s) contain <img> elements instead of text"
            ));
            image_count += img_in_price_count;
            score += 0.35;
        }

        // Signal 2: Inline background-image CSS on price-like elements
        let bg_image_count = self.count_background_image_prices(&document);
        if bg_image_count > 0 {
            signals.push(format!(
                "{bg_image_count} price element(s) use CSS background-image"
            ));
            image_count += bg_image_count;
            score += 0.30;
        }

        // Signal 3: Empty text but with width/height attributes (sprite rendering)
        let empty_visible_count = self.count_empty_visible_elements(&document);
        if empty_visible_count > 0 {
            signals.push(format!(
                "{empty_visible_count} price element(s) have no text but have visible dimensions"
            ));
            image_count += empty_visible_count;
            score += 0.25;
        }

        // Signal 4: Sprite/image-price class patterns
        let sprite_class_count = count_sprite_classes(html);
        if sprite_class_count > 0 {
            signals.push(format!(
                "{sprite_class_count} element(s) have sprite/image-price class names"
            ));
            score += 0.25;
        }

        // Signal 5: Canvas elements near price regions
        let canvas_count = count_canvas_in_price_region(&document);
        if canvas_count > 0 {
            signals.push(format!(
                "{canvas_count} <canvas> element(s) found in price regions"
            ));
            score += 0.30;
        }

        // Signal 6: Data URI images in price areas
        let data_uri_count = self.count_data_uri_in_prices(&document);
        if data_uri_count > 0 {
            signals.push(format!(
                "{data_uri_count} data URI image(s) found in price containers"
            ));
            image_count += data_uri_count;
            score += 0.25;
        }

        // Clamp confidence to [0.0, 1.0]
        let confidence = score.min(1.0);
        let has_image_prices = confidence >= 0.25;

        let recommended_action = if confidence >= 0.7 {
            "use_ocr".to_string()
        } else if confidence >= 0.4 {
            "use_browser_screenshot".to_string()
        } else {
            "normal_extraction".to_string()
        };

        ImagePriceDetection {
            has_image_prices,
            confidence,
            image_count,
            signals,
            recommended_action,
        }
    }

    /// Extract image URLs that likely contain price text.
    ///
    /// Returns URLs from `<img>` src attributes and CSS `background-image`
    /// properties found within price containers.
    pub fn extract_price_images(&self, html: &str) -> Vec<String> {
        let document = Html::parse_document(html);
        let mut urls = Vec::new();

        // Collect <img> src from price containers
        for sel_str in &self.price_selectors {
            let Ok(selector) = Selector::parse(sel_str) else {
                continue;
            };
            for element in document.select(&selector) {
                // Direct <img> children
                let img_sel = Selector::parse("img").unwrap();
                for img in element.select(&img_sel) {
                    if let Some(src) = img.value().attr("src") {
                        if !src.is_empty() {
                            urls.push(src.to_string());
                        }
                    }
                    // Also check data-src (lazy loading)
                    if let Some(src) = img.value().attr("data-src") {
                        if !src.is_empty() {
                            urls.push(src.to_string());
                        }
                    }
                }

                // Check inline style for background-image URLs
                if let Some(style) = element.value().attr("style") {
                    urls.extend(extract_urls_from_css(style));
                }

                // Check children for inline styles with background-image
                let all_sel = Selector::parse("*").unwrap();
                for child in element.select(&all_sel) {
                    if let Some(style) = child.value().attr("style") {
                        urls.extend(extract_urls_from_css(style));
                    }
                }
            }
        }

        // Deduplicate
        urls.sort();
        urls.dedup();
        urls
    }

    // ── Internal detection helpers ──────────────────────────────────────

    /// Count price containers that have <img> children instead of meaningful text.
    fn count_img_in_price_containers(&self, document: &Html) -> usize {
        let mut count = 0;
        let img_sel = Selector::parse("img").unwrap();

        for sel_str in &self.price_selectors {
            let Ok(selector) = Selector::parse(sel_str) else {
                continue;
            };
            for element in document.select(&selector) {
                let has_img = element.select(&img_sel).next().is_some();
                let text = element.text().collect::<String>();
                let text_trimmed = text.trim();
                // Has images but no meaningful text (or only whitespace/symbols)
                let text_is_empty = text_trimmed.is_empty()
                    || text_trimmed.chars().all(|c| {
                        c == '$'
                            || c == '¥'
                            || c == '€'
                            || c == '£'
                            || c.is_whitespace()
                            || c == '.'
                            || c == ','
                    });
                if has_img && text_is_empty {
                    count += 1;
                }
            }
        }
        count
    }

    /// Count price elements that use CSS background-image (inline styles).
    fn count_background_image_prices(&self, document: &Html) -> usize {
        let mut count = 0;

        for sel_str in &self.price_selectors {
            let Ok(selector) = Selector::parse(sel_str) else {
                continue;
            };
            for element in document.select(&selector) {
                if let Some(style) = element.value().attr("style") {
                    if style.contains("background-image") || style.contains("background:") {
                        count += 1;
                    }
                }
                // Also check children
                let all_sel = Selector::parse("*").unwrap();
                for child in element.select(&all_sel) {
                    if let Some(style) = child.value().attr("style") {
                        if style.contains("background-image") {
                            count += 1;
                        }
                    }
                }
            }
        }
        count
    }

    /// Count elements with no text content but with explicit width/height.
    fn count_empty_visible_elements(&self, document: &Html) -> usize {
        let mut count = 0;

        for sel_str in &self.price_selectors {
            let Ok(selector) = Selector::parse(sel_str) else {
                continue;
            };
            for element in document.select(&selector) {
                let text = element.text().collect::<String>();
                if !text.trim().is_empty() {
                    continue;
                }
                // Check for width/height attributes or inline style dimensions
                let has_dimensions_attr = element.value().attr("width").is_some()
                    || element.value().attr("height").is_some();

                let has_dimensions_style = element
                    .value()
                    .attr("style")
                    .map(|s| {
                        (s.contains("width") && !s.contains("width:0") && !s.contains("width: 0"))
                            || (s.contains("height")
                                && !s.contains("height:0")
                                && !s.contains("height: 0"))
                    })
                    .unwrap_or(false);

                if has_dimensions_attr || has_dimensions_style {
                    count += 1;
                }
            }
        }
        count
    }

    /// Count data URI images within price containers.
    fn count_data_uri_in_prices(&self, document: &Html) -> usize {
        let mut count = 0;
        let img_sel = Selector::parse("img").unwrap();

        for sel_str in &self.price_selectors {
            let Ok(selector) = Selector::parse(sel_str) else {
                continue;
            };
            for element in document.select(&selector) {
                for img in element.select(&img_sel) {
                    if let Some(src) = img.value().attr("src") {
                        if src.starts_with("data:image/") {
                            count += 1;
                        }
                    }
                }
                // Also check inline style background data URIs
                if let Some(style) = element.value().attr("style") {
                    if style.contains("data:image/") {
                        count += 1;
                    }
                }
            }
        }
        count
    }
}

/// Count elements with class names matching sprite/image-price patterns.
fn count_sprite_classes(html: &str) -> usize {
    let patterns = [
        "price-img",
        "num-img",
        "price-sprite",
        "num-sprite",
        "price_img",
        "num_img",
        "img-price",
        "sprite-price",
        "price-icon",
        "icon-price",
        "digit-img",
        "char-img",
        "font-img",
        "css-sprite",
    ];

    let html_lower = html.to_lowercase();
    patterns.iter().filter(|p| html_lower.contains(*p)).count()
}

/// Count <canvas> elements within price-related parent elements.
fn count_canvas_in_price_region(document: &Html) -> usize {
    let mut count = 0;

    // Look for canvas elements globally, then check if they are near price elements
    let canvas_sel = Selector::parse("canvas").unwrap();
    for canvas in document.select(&canvas_sel) {
        // Check if any ancestor has a price-related class
        // Since scraper doesn't easily traverse parents, we check canvas attributes
        if let Some(cls) = canvas.value().attr("class") {
            let cls_lower = cls.to_lowercase();
            if cls_lower.contains("price")
                || cls_lower.contains("num")
                || cls_lower.contains("digit")
            {
                count += 1;
                continue;
            }
        }
        if let Some(id) = canvas.value().attr("id") {
            let id_lower = id.to_lowercase();
            if id_lower.contains("price") || id_lower.contains("num") || id_lower.contains("digit")
            {
                count += 1;
            }
        }
    }

    // Also check for price containers that contain canvas
    let price_selectors = ["[class*=\"price\"]", "[class*=\"Price\"]"];
    for sel_str in &price_selectors {
        if let Ok(selector) = Selector::parse(sel_str) {
            let canvas_child = Selector::parse("canvas").unwrap();
            for element in document.select(&selector) {
                if element.select(&canvas_child).next().is_some() {
                    count += 1;
                }
            }
        }
    }

    count
}

/// Extract URLs from CSS property values (background-image, etc.).
fn extract_urls_from_css(css: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut search = css;

    while let Some(start) = search.find("url(") {
        let rest = &search[start + 4..];
        // Handle url('...'), url("..."), and url(...)
        let (url_str, advance) = if rest.starts_with('\'') || rest.starts_with('"') {
            let quote = rest.chars().next().unwrap();
            let inner = &rest[1..];
            if let Some(end) = inner.find(quote) {
                (inner[..end].to_string(), start + 4 + 1 + end + 1)
            } else {
                break;
            }
        } else if let Some(end) = rest.find(')') {
            (rest[..end].trim().to_string(), start + 4 + end)
        } else {
            break;
        };

        if !url_str.is_empty() {
            urls.push(url_str);
        }
        if advance >= search.len() {
            break;
        }
        search = &search[advance..];
    }

    urls
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── DualModeEngine tests ────────────────────────────────────────────

    #[test]
    fn test_engine_new_defaults() {
        let engine = DualModeEngine::new();
        assert_eq!(*engine.mode(), EngineMode::Auto);
        assert!(engine.cookies().is_empty());
        assert!(engine.session_info().is_none());
        assert!(engine.ua.contains("Chrome"));
    }

    #[test]
    fn test_engine_with_user_agent() {
        let engine = DualModeEngine::with_user_agent("CustomBot/1.0");
        assert_eq!(engine.ua, "CustomBot/1.0");
    }

    #[test]
    fn test_engine_set_cookie() {
        let mut engine = DualModeEngine::new();
        engine.set_cookie("session_id", "abc123");
        engine.set_cookie("csrf_token", "xyz789");
        assert_eq!(engine.cookies().get("session_id").unwrap(), "abc123");
        assert_eq!(engine.cookies().get("csrf_token").unwrap(), "xyz789");
        assert_eq!(engine.cookies().len(), 2);
    }

    #[test]
    fn test_engine_set_header() {
        let mut engine = DualModeEngine::new();
        engine.set_header("X-Custom", "test-value");
        assert_eq!(engine.headers.get("X-Custom").unwrap(), "test-value");
    }

    #[test]
    fn test_format_cookie_header() {
        let mut engine = DualModeEngine::new();
        engine.set_cookie("a", "1");
        engine.set_cookie("b", "2");
        let header = engine.format_cookie_header();
        // HashMap order is non-deterministic, so check both parts
        assert!(header.contains("a=1"));
        assert!(header.contains("b=2"));
        assert!(header.contains("; "));
    }

    #[test]
    fn test_format_cookie_header_empty() {
        let engine = DualModeEngine::new();
        assert!(engine.format_cookie_header().is_empty());
    }

    #[test]
    fn test_engine_mode_display() {
        assert_eq!(format!("{}", EngineMode::Http), "HTTP");
        assert_eq!(format!("{}", EngineMode::Browser), "Browser");
        assert_eq!(format!("{}", EngineMode::Auto), "Auto");
    }

    // ── Blocked response detection tests ────────────────────────────────

    #[test]
    fn test_blocked_response_403() {
        let resp = DualModeResponse {
            status: 403,
            body: "Forbidden".to_string(),
            url: "https://example.com".to_string(),
            source: EngineMode::Http,
        };
        assert!(is_blocked_response(&resp));
    }

    #[test]
    fn test_blocked_response_429() {
        let resp = DualModeResponse {
            status: 429,
            body: "Too Many Requests".to_string(),
            url: "https://example.com".to_string(),
            source: EngineMode::Http,
        };
        assert!(is_blocked_response(&resp));
    }

    #[test]
    fn test_blocked_response_503() {
        let resp = DualModeResponse {
            status: 503,
            body: "Service Unavailable".to_string(),
            url: "https://example.com".to_string(),
            source: EngineMode::Http,
        };
        assert!(is_blocked_response(&resp));
    }

    #[test]
    fn test_blocked_response_captcha() {
        let resp = DualModeResponse {
            status: 200,
            body: r#"<html><body><div class="g-recaptcha" data-sitekey="abc"></div></body></html>"#
                .to_string(),
            url: "https://example.com".to_string(),
            source: EngineMode::Http,
        };
        assert!(is_blocked_response(&resp));
    }

    #[test]
    fn test_blocked_response_cloudflare() {
        let resp = DualModeResponse {
            status: 200,
            body:
                "<html><body>Just a moment... Checking your browser before accessing</body></html>"
                    .to_string(),
            url: "https://example.com".to_string(),
            source: EngineMode::Http,
        };
        assert!(is_blocked_response(&resp));
    }

    #[test]
    fn test_blocked_response_small_body() {
        let resp = DualModeResponse {
            status: 200,
            body: "OK".to_string(),
            url: "https://example.com".to_string(),
            source: EngineMode::Http,
        };
        assert!(is_blocked_response(&resp));
    }

    #[test]
    fn test_not_blocked_response() {
        let body = "x".repeat(2000);
        let resp = DualModeResponse {
            status: 200,
            body: format!(
                "<html><body><h1>Products</h1><div class=\"results\">{body}</div></body></html>"
            ),
            url: "https://example.com".to_string(),
            source: EngineMode::Http,
        };
        assert!(!is_blocked_response(&resp));
    }

    #[test]
    fn test_blocked_response_incapsula() {
        let resp = DualModeResponse {
            status: 200,
            body: "<html><body>Request unsuccessful. Incapsula incident ID: 123</body></html>"
                .to_string(),
            url: "https://example.com".to_string(),
            source: EngineMode::Http,
        };
        assert!(is_blocked_response(&resp));
    }

    // ── ImageTextDetector tests ─────────────────────────────────────────

    #[test]
    fn test_detector_new_has_default_selectors() {
        let detector = ImageTextDetector::new();
        assert!(!detector.price_selectors.is_empty());
        assert!(detector.price_selectors.contains(&".price".to_string()));
    }

    #[test]
    fn test_detector_custom_selectors() {
        let detector = ImageTextDetector::with_selectors(vec![".custom-price".to_string()]);
        assert_eq!(detector.price_selectors.len(), 1);
        assert_eq!(detector.price_selectors[0], ".custom-price");
    }

    #[test]
    fn test_detect_normal_text_prices() {
        let html = r#"
            <html><body>
                <div class="price">$29.99</div>
                <div class="price">$49.99</div>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let result = detector.detect_image_prices(html);
        assert!(!result.has_image_prices);
        assert_eq!(result.recommended_action, "normal_extraction");
        assert!(result.confidence < 0.25);
    }

    #[test]
    fn test_detect_img_in_price_container() {
        let html = r#"
            <html><body>
                <div class="price">
                    <img src="https://cdn.example.com/prices/2999.png" alt="">
                </div>
                <div class="price">
                    <img src="https://cdn.example.com/prices/4999.png" alt="">
                </div>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let result = detector.detect_image_prices(html);
        assert!(result.has_image_prices);
        assert!(result.confidence >= 0.25);
        assert!(result.image_count >= 2);
        assert!(result.signals.iter().any(|s| s.contains("<img>")));
    }

    #[test]
    fn test_detect_background_image_prices() {
        let html = r#"
            <html><body>
                <span class="price" style="background-image: url('sprite.png'); width: 80px; height: 20px;"></span>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let result = detector.detect_image_prices(html);
        assert!(result.has_image_prices);
        assert!(
            result
                .signals
                .iter()
                .any(|s| s.contains("background-image"))
        );
    }

    #[test]
    fn test_detect_empty_visible_elements() {
        let html = r#"
            <html><body>
                <span class="price" style="width: 100px; height: 24px; display: inline-block;"></span>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let result = detector.detect_image_prices(html);
        assert!(result.has_image_prices);
        assert!(result.signals.iter().any(|s| s.contains("no text")));
    }

    #[test]
    fn test_detect_sprite_classes() {
        let html = r#"
            <html><body>
                <span class="price-sprite digit-3"></span>
                <span class="price-sprite digit-9"></span>
                <span class="num-img n-9"></span>
            </body></html>
        "#;
        let count = count_sprite_classes(html);
        assert!(count >= 2); // price-sprite and num-img
    }

    #[test]
    fn test_detect_canvas_price() {
        let html = r#"
            <html><body>
                <div class="price">
                    <canvas id="price-canvas" width="120" height="30"></canvas>
                </div>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let result = detector.detect_image_prices(html);
        assert!(result.has_image_prices);
    }

    #[test]
    fn test_detect_data_uri_prices() {
        let html = r#"
            <html><body>
                <div class="price">
                    <img src="data:image/png;base64,iVBORw0KGgoAAAANS..." alt="price">
                </div>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let result = detector.detect_image_prices(html);
        assert!(result.has_image_prices);
        assert!(result.image_count >= 1);
        assert!(result.signals.iter().any(|s| s.contains("data URI")));
    }

    #[test]
    fn test_extract_price_images_img_src() {
        let html = r#"
            <html><body>
                <div class="price">
                    <img src="https://cdn.example.com/p/29.png">
                    <img data-src="https://cdn.example.com/p/99.png">
                </div>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let urls = detector.extract_price_images(html);
        assert!(urls.contains(&"https://cdn.example.com/p/29.png".to_string()));
        assert!(urls.contains(&"https://cdn.example.com/p/99.png".to_string()));
    }

    #[test]
    fn test_extract_price_images_background() {
        let html = r#"
            <html><body>
                <span class="price" style="background-image: url('https://cdn.example.com/sprite.png');"></span>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let urls = detector.extract_price_images(html);
        assert!(urls.contains(&"https://cdn.example.com/sprite.png".to_string()));
    }

    #[test]
    fn test_extract_price_images_no_images() {
        let html = r#"
            <html><body>
                <div class="price">$29.99</div>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let urls = detector.extract_price_images(html);
        assert!(urls.is_empty());
    }

    #[test]
    fn test_high_confidence_ocr_recommendation() {
        // Multiple strong signals = OCR recommendation
        let html = r#"
            <html><body>
                <div class="price" style="background-image: url('sprite.png');">
                    <img src="data:image/png;base64,abc123" alt="">
                </div>
                <div class="price">
                    <img src="https://cdn.example.com/digit-sprite.png" alt="">
                </div>
                <span class="price-img num-sprite"></span>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let result = detector.detect_image_prices(html);
        assert!(result.has_image_prices);
        assert!(result.confidence >= 0.7);
        assert_eq!(result.recommended_action, "use_ocr");
    }

    // ── CSS URL extraction tests ────────────────────────────────────────

    #[test]
    fn test_extract_urls_single_quotes() {
        let urls = extract_urls_from_css("background-image: url('test.png')");
        assert_eq!(urls, vec!["test.png"]);
    }

    #[test]
    fn test_extract_urls_double_quotes() {
        let urls = extract_urls_from_css("background-image: url(\"test.png\")");
        assert_eq!(urls, vec!["test.png"]);
    }

    #[test]
    fn test_extract_urls_no_quotes() {
        let urls = extract_urls_from_css("background-image: url(test.png)");
        assert_eq!(urls, vec!["test.png"]);
    }

    #[test]
    fn test_extract_urls_multiple() {
        let urls = extract_urls_from_css(
            "background: url('a.png') no-repeat; border-image: url('b.png');",
        );
        assert_eq!(urls, vec!["a.png", "b.png"]);
    }

    #[test]
    fn test_extract_urls_data_uri() {
        let urls = extract_urls_from_css("background-image: url('data:image/png;base64,iVBOR')");
        assert_eq!(urls, vec!["data:image/png;base64,iVBOR"]);
    }

    #[test]
    fn test_extract_urls_empty() {
        let urls = extract_urls_from_css("color: red; font-size: 14px;");
        assert!(urls.is_empty());
    }

    // ── BrowserSessionInfo serialization test ───────────────────────────

    #[test]
    fn test_session_info_serialization() {
        let info = BrowserSessionInfo {
            ws_url: "ws://127.0.0.1:9222/devtools/browser/abc".to_string(),
            session_id: "sess-123".to_string(),
            cookies: vec![(
                "sid".to_string(),
                "val1".to_string(),
                ".example.com".to_string(),
            )],
            local_storage: {
                let mut m = HashMap::new();
                m.insert("theme".to_string(), "dark".to_string());
                m
            },
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: BrowserSessionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ws_url, info.ws_url);
        assert_eq!(deserialized.session_id, info.session_id);
        assert_eq!(deserialized.cookies.len(), 1);
        assert_eq!(deserialized.local_storage.get("theme").unwrap(), "dark");
    }

    // ── Mixed content tests ─────────────────────────────────────────────

    #[test]
    fn test_mixed_text_and_image_prices() {
        // Some prices are text, some are images — should still detect
        let html = r#"
            <html><body>
                <div class="price">$29.99</div>
                <div class="price">
                    <img src="https://cdn.example.com/p/49.png" alt="">
                </div>
                <div class="price">$19.99</div>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let result = detector.detect_image_prices(html);
        assert!(result.has_image_prices);
        assert!(result.image_count >= 1);
    }

    #[test]
    fn test_currency_symbol_only_with_image() {
        // Currency symbol as text, digits as image (common pattern)
        let html = r#"
            <html><body>
                <div class="price">¥
                    <img src="digits.png" alt="">
                </div>
            </body></html>
        "#;
        let detector = ImageTextDetector::new();
        let result = detector.detect_image_prices(html);
        assert!(result.has_image_prices);
    }
}
