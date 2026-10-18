//! Adaptive crawler that auto-decides between fast HTTP and browser rendering.
//!
//! Tries a lightweight HTTP fetch first (via ureq). If the response looks
//! JS-rendered (thin body, `<noscript>` markers, framework root divs), it
//! falls back to full browser rendering through the CDP-based Page API.

use super::error::BrowserError;
use super::page::{Page, WaitUntil};

/// Where the content was obtained from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlSource {
    /// Fast HTTP fetch — no browser involved.
    Http,
    /// Full browser rendering via CDP.
    Browser,
}

/// Result of a single crawl operation.
#[derive(Debug, Clone)]
pub struct CrawlResult {
    /// Final URL (after redirects).
    pub url: String,
    /// Response body as UTF-8 text.
    pub body: String,
    /// HTTP status code.
    pub status: u16,
    /// Whether the content came from HTTP or browser rendering.
    pub source: CrawlSource,
    /// Content-Type header value, if present.
    pub content_type: Option<String>,
    /// Whether this fetch produced content identical to a prior crawl
    /// (content-hash unchanged / `304 Not Modified`). When `true` the caller
    /// may skip re-extraction (delta / incremental crawl).
    pub unchanged: bool,
}

/// Adaptive crawler that tries fast HTTP first and falls back to browser
/// rendering when the page requires JavaScript.
pub struct AdaptiveCrawler {
    http_client: ureq::Agent,
    /// Minimum body length (in bytes) to consider HTTP response meaningful.
    min_content_length: usize,
    /// User-Agent header for HTTP requests.
    user_agent: String,
    /// Timeout for HTTP requests in seconds.
    http_timeout_secs: u64,
}

impl AdaptiveCrawler {
    /// Create a new adaptive crawler with default settings.
    pub fn new() -> Self {
        // T-207 browser-zone lockdown: contract-bound client (Tor by default).
        let http_client = crate::runtime::egress_http::agent_with_timeouts(
            Some(std::time::Duration::from_secs(15)),
            None,
        );
        Self {
            http_client,
            min_content_length: 1024,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            http_timeout_secs: 15,
        }
    }

    /// Create a crawler with custom settings.
    pub fn with_config(min_content_length: usize, user_agent: &str, http_timeout_secs: u64) -> Self {
        // T-207 browser-zone lockdown: contract-bound client (Tor by default).
        let http_client = crate::runtime::egress_http::agent_with_timeouts(
            Some(std::time::Duration::from_secs(http_timeout_secs)),
            None,
        );
        Self {
            http_client,
            min_content_length,
            user_agent: user_agent.to_string(),
            http_timeout_secs,
        }
    }

    /// Try fast HTTP first, fall back to browser if JS-rendered.
    ///
    /// If `page` is `None`, only HTTP is attempted. If the HTTP response
    /// looks like it needs JS rendering and a `Page` is available, the
    /// browser will be used as a fallback.
    pub async fn fetch(
        &self,
        url: &str,
        page: Option<&Page>,
    ) -> Result<CrawlResult, BrowserError> {
        // 1. Try HTTP GET first
        match self.try_http(url) {
            Ok(result) => {
                // 2. Check if the response has meaningful content
                if self.looks_complete(&result.body) {
                    return Ok(result);
                }
                // Content looks JS-rendered — try browser if available
                if let Some(p) = page {
                    self.fetch_with_browser(p, url).await
                } else {
                    // No browser available, return what we have
                    Ok(result)
                }
            }
            Err(_) => {
                // HTTP failed entirely — try browser
                if let Some(p) = page {
                    self.fetch_with_browser(p, url).await
                } else {
                    Err(BrowserError::ActionFailed(format!(
                        "HTTP fetch failed and no browser page available for: {url}"
                    )))
                }
            }
        }
    }

    /// Perform a blocking HTTP GET and return the result.
    fn try_http(&self, url: &str) -> Result<CrawlResult, BrowserError> {
        let resp = self
            .http_client
            .get(url)
            .header("User-Agent", &self.user_agent)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.9")
            .call()
            .map_err(|e| BrowserError::ActionFailed(format!("HTTP request failed: {e}")))?;

        let status = resp.status().as_u16();
        let content_type: Option<String> = resp
            .headers()
            .get("content-type")
            .and_then(|v: &ureq::http::HeaderValue| v.to_str().ok())
            .map(|s: &str| s.to_string());

        let final_url: String = resp
            .headers()
            .get("location")
            .and_then(|v: &ureq::http::HeaderValue| v.to_str().ok())
            .map(|s: &str| s.to_string())
            .unwrap_or_else(|| url.to_string());

        let body = resp
            .into_body()
            .read_to_string()
            .map_err(|e| BrowserError::ActionFailed(format!("Failed to read response body: {e}")))?;

        Ok(CrawlResult {
            url: final_url,
            body,
            status,
            source: CrawlSource::Http,
            content_type,
            unchanged: false,
        })
    }

    /// Navigate a browser page to the URL and extract the rendered HTML.
    async fn fetch_with_browser(
        &self,
        page: &Page,
        url: &str,
    ) -> Result<CrawlResult, BrowserError> {
        // Bounded, not `NetworkIdle`: a page that keeps a request open (long
        // poll, SSE, analytics retry) never reaches network idle, so the crawl
        // sat on the navigation timeout for two minutes and returned nothing —
        // measured on a static loopback page (register #32). DomContentLoaded
        // with a soft timeout plus an explicit readiness settle returns the
        // rendered DOM for those pages instead of a timeout error.
        let nav = page.navigate(url, WaitUntil::DomContentLoaded).await?;
        // Bounded settle: give DOMContentLoaded handlers (the ones that fill
        // the skeleton) a chance to finish before the DOM is read.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(2_000);
        loop {
            let ready = page
                .evaluate_expression("document.readyState")
                .await
                .ok()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| v.to_string())
                })
                .unwrap_or_default();
            if ready.contains("complete") || std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        let status = nav.status_code.unwrap_or(200);

        // Get the fully rendered HTML from the page
        let result = page
            .evaluate_expression("document.documentElement.outerHTML")
            .await?;

        // `evaluate_expression` already returns the `Runtime.evaluate`
        // result's `value`; unwrapping `result.result.value` again (the raw
        // CDP envelope) reads through a String and yields "" — the crawl then
        // reports `source=Browser` with an empty body.
        let body = result
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| result.to_string());

        Ok(CrawlResult {
            url: nav.url,
            body,
            status,
            source: CrawlSource::Browser,
            content_type: Some("text/html".to_string()),
            unchanged: false,
        })
    }

    /// Heuristic: does the HTTP response body look like fully rendered content?
    ///
    /// Returns `false` (needs browser) when:
    /// - Body is shorter than `min_content_length`
    /// - Body has `<noscript>` with redirect/warning text
    /// - Body is dominated by a single framework root with no inner content
    /// - Body has very little visible text relative to its size
    fn looks_complete(&self, body: &str) -> bool {
        // Too short — probably a JS shell
        if body.len() < self.min_content_length {
            return false;
        }

        let lower = body.to_lowercase();

        // Noscript tags with content suggest the page needs JS
        if let Some(ns_start) = lower.find("<noscript") {
            if let Some(ns_end) = lower[ns_start..].find("</noscript>") {
                let noscript_content = &body[ns_start..ns_start + ns_end];
                // If noscript has meaningful content (redirect, enable JS message),
                // the real content likely requires JS
                let nc_lower = noscript_content.to_lowercase();
                if nc_lower.contains("enable javascript")
                    || nc_lower.contains("javascript is required")
                    || nc_lower.contains("you need to enable")
                    || nc_lower.contains("please enable")
                    || nc_lower.contains("meta http-equiv=\"refresh\"")
                {
                    return false;
                }
            }
        }

        // Common SPA framework root divs rendered with no server content.
        // A bare root div is *not* proof of a shell — many sites server-render
        // their real content *inside* the root element — so we only flag it
        // when the page is also essentially textless (which a true JS shell
        // always is). This keeps detection robust without false-positiving on
        // SSR'd SPA pages.
        let text_len = extract_visible_text_length(&lower);
        // A shell is near-textless: under 100 visible chars, or <5% of a large body.
        let is_textless = text_len < 100 || (body.len() > 2000 && text_len < body.len() / 20);
        let spa_root_divs = [
            "<div id=\"root\"",     // React / CRA
            "<div id=\"app\"",      // Vue / React CRA
            "<div id=\"__next\"",   // Next.js
            "<div id=\"__nuxt\"",   // Nuxt
            "<div id=\"__app\"",    // Vue 3 / Vite
            "<div id=\"app-root\"", // Angular
            "<app-root",            // Angular element
        ];
        if spa_root_divs.iter().any(|m| lower.contains(m)) && is_textless {
            return false;
        }

        // General text-to-markup ratio — a large body with almost no visible
        // text is a JS shell regardless of which framework marker it uses.
        if body.len() > 2000 && text_len < body.len() / 20 {
            return false;
        }

        true
    }
}

impl Default for AdaptiveCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Rough estimate of visible text length by stripping tags.
fn extract_visible_text_length(html: &str) -> usize {
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let mut text_len = 0;
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'<' {
            in_tag = true;
            // Check for script/style opening
            if i + 7 < len {
                let slice = &html[i..std::cmp::min(i + 10, len)].to_lowercase();
                if slice.starts_with("<script") {
                    in_script = true;
                } else if slice.starts_with("<style") {
                    in_style = true;
                } else if slice.starts_with("</script") {
                    in_script = false;
                } else if slice.starts_with("</style") {
                    in_style = false;
                }
            }
            i += 1;
            continue;
        }
        if bytes[i] == b'>' {
            in_tag = false;
            i += 1;
            continue;
        }
        if !in_tag && !in_script && !in_style && !bytes[i].is_ascii_whitespace() {
            text_len += 1;
        }
        i += 1;
    }
    text_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_complete_with_real_content() {
        let crawler = AdaptiveCrawler::new();
        let html = format!(
            "<html><body><h1>Hello World</h1><p>{}</p></body></html>",
            "Lorem ipsum dolor sit amet. ".repeat(100)
        );
        assert!(crawler.looks_complete(&html));
    }

    #[test]
    fn test_looks_incomplete_spa_shell() {
        let crawler = AdaptiveCrawler::new();
        let html = r#"<html><head><script src="app.js"></script></head><body><div id="root"></div></body></html>"#;
        assert!(!crawler.looks_complete(html));
    }

    #[test]
    fn test_looks_incomplete_noscript_warning() {
        let crawler = AdaptiveCrawler::new();
        let html = format!(
            r#"<html><body><noscript>You need to enable JavaScript to run this app.</noscript><div id="root"></div>{}</body></html>"#,
            "x".repeat(2000)
        );
        assert!(!crawler.looks_complete(&html));
    }

    #[test]
    fn test_looks_incomplete_too_short() {
        let crawler = AdaptiveCrawler::new();
        assert!(!crawler.looks_complete("<html><body></body></html>"));
    }

    #[test]
    fn test_looks_incomplete_textless_spa_root_variants() {
        // Any common SPA root div that is essentially textless is a shell.
        let crawler = AdaptiveCrawler::new();
        let variants = [
            r#"<html><body><div id="root"></div><script src="app.js"></script></body></html>"#,
            r#"<html><body><div id="__next"></div><script src="b.js"></script></body></html>"#,
            r#"<html><body><div id="__nuxt"></div><script src="c.js"></script></body></html>"#,
            r#"<html><body><div id="__app"></div><script src="d.js"></script></body></html>"#,
            r#"<html><body><app-root></app-root><script src="e.js"></script></body></html>"#,
            // root div with a lone whitespace placeholder is still a shell.
            r#"<html><body><div id="root"> </div><script src="f.js"></script></body></html>"#,
        ];
        for html in variants {
            assert!(!crawler.looks_complete(html), "should flag shell: {html}");
        }
    }

    #[test]
    fn test_looks_complete_ssr_spa_root_with_real_content() {
        // A root div that already contains server-rendered text is complete —
        // do NOT false-positive on SSR'd SPA pages.
        let crawler = AdaptiveCrawler::new();
        let html = format!(
            r#"<html><body><div id="root"><h1>Products</h1><p>{}</p></div></body></html>"#,
            "real content here. ".repeat(300)
        );
        assert!(crawler.looks_complete(&html));
    }

    #[test]
    fn test_looks_incomplete_large_textless_spa_shell() {
        // A *large* body (above min_content_length) that is dominated by
        // scripts/CSS and carries a framework root div but no visible text is
        // a JS shell and must be flagged incomplete via the SPA-marker path
        // (not merely the length check).
        let crawler = AdaptiveCrawler::new();
        let filler = "/* ".to_string() + &"x".repeat(3000) + " */";
        let html = format!(
            r#"<html><head><script>{}</script><style>{}</style></head><body><div id="__next"></div></body></html>"#,
            filler, filler
        );
        assert!(html.len() > 1024);
        assert!(!crawler.looks_complete(&html));
    }

    #[test]
    fn test_crawl_source_variants() {
        assert_ne!(CrawlSource::Http, CrawlSource::Browser);
    }

    #[test]
    fn test_extract_visible_text_length() {
        let html = "<p>Hello</p><script>var x = 1;</script><p>World</p>";
        let len = extract_visible_text_length(html);
        assert_eq!(len, 10); // "Hello" + "World"
    }
}
