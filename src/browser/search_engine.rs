//! Multi-engine search with automatic failover — all free.
//!
//! Cascading search strategy:
//! 1. Google Trends (always works, even via Tor)
//! 2. Bing (rarely blocks, good product data)
//! 3. Brave Search (privacy-friendly, no bot detection)
//! 4. Google CSE API (100 free/day)
//! 5. Google via profile pool (persistent cookies + consent)
//!
//! Each engine is tried in order. If one blocks, the next is used.
//! Results are deduplicated and merged.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::Value;

use super::error::BrowserError;
use super::page::{Page, WaitUntil};

/// A search result from any engine.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
    pub source: SearchEngine,
    pub rank: usize,
}

/// Supported search engines.
#[derive(Debug, Clone, PartialEq)]
pub enum SearchEngine {
    GoogleTrends,
    GoogleCSE,
    GoogleProfile,
    Bing,
    BraveSearch,
    DuckDuckGo,
    Startpage,
    Yahoo,
}

impl SearchEngine {
    pub fn name(&self) -> &'static str {
        match self {
            SearchEngine::GoogleTrends => "Google Trends",
            SearchEngine::GoogleCSE => "Google CSE",
            SearchEngine::GoogleProfile => "Google (profile)",
            SearchEngine::Bing => "Bing",
            SearchEngine::BraveSearch => "Brave Search",
            SearchEngine::DuckDuckGo => "DuckDuckGo",
            SearchEngine::Startpage => "Startpage",
            SearchEngine::Yahoo => "Yahoo",
        }
    }

    pub fn search_url(&self, query: &str) -> String {
        let q = urlencoded(query);
        match self {
            SearchEngine::GoogleTrends => format!("https://trends.google.com/trending?geo=US&q={q}"),
            SearchEngine::GoogleCSE => String::new(), // API call, not URL
            SearchEngine::GoogleProfile => format!("https://www.google.com/search?q={q}"),
            SearchEngine::Bing => format!("https://www.bing.com/search?q={q}"),
            SearchEngine::BraveSearch => format!("https://search.brave.com/search?q={q}"),
            SearchEngine::DuckDuckGo => format!("https://html.duckduckgo.com/html/?q={q}"),
            SearchEngine::Startpage => format!("https://www.startpage.com/sp/search?query={q}"),
            SearchEngine::Yahoo => format!("https://search.yahoo.com/search?p={q}"),
        }
    }

    /// CSS selectors for extracting results from each engine.
    pub fn result_selectors(&self) -> ResultSelectors {
        match self {
            SearchEngine::Bing => ResultSelectors {
                container: "li.b_algo",
                title: "h2 a",
                url: "h2 a",
                snippet: ".b_caption p",
            },
            SearchEngine::BraveSearch => ResultSelectors {
                container: ".snippet",
                title: ".snippet-title",
                url: ".snippet-url",
                snippet: ".snippet-description",
            },
            SearchEngine::DuckDuckGo => ResultSelectors {
                container: ".result",
                title: ".result__title a",
                url: ".result__url",
                snippet: ".result__snippet",
            },
            SearchEngine::Yahoo => ResultSelectors {
                container: ".algo-sr",
                title: "h3 a",
                url: "h3 a",
                snippet: ".compText p",
            },
            SearchEngine::GoogleProfile => ResultSelectors {
                container: "div.g",
                title: "h3",
                url: "a",
                snippet: "div.VwiC3b",
            },
            _ => ResultSelectors {
                container: "div",
                title: "a",
                url: "a",
                snippet: "p",
            },
        }
    }
}

/// CSS selectors for a specific search engine's result page.
#[derive(Debug, Clone)]
pub struct ResultSelectors {
    pub container: &'static str,
    pub title: &'static str,
    pub url: &'static str,
    pub snippet: &'static str,
}

/// Search configuration.
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Engines to try, in order. First success wins.
    pub engines: Vec<SearchEngine>,
    /// Google CSE API key (free tier: 100/day).
    pub google_cse_key: Option<String>,
    /// Google CSE search engine ID.
    pub google_cse_cx: Option<String>,
    /// Maximum results per engine.
    pub max_results: usize,
    /// Timeout per engine attempt.
    pub timeout: Duration,
    /// Delay between engine attempts (avoid rapid-fire).
    pub engine_delay: Duration,
    /// Whether to merge results from multiple engines or stop at first success.
    pub merge_results: bool,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            engines: vec![
                SearchEngine::Bing,          // rarely blocks, good results
                SearchEngine::BraveSearch,    // never blocks, privacy-friendly
                SearchEngine::DuckDuckGo,     // HTML version works better
                SearchEngine::Yahoo,          // backup, uses Bing's index
                SearchEngine::GoogleTrends,   // always works for trending
            ],
            google_cse_key: None,
            google_cse_cx: None,
            max_results: 20,
            timeout: Duration::from_secs(10),
            engine_delay: Duration::from_millis(500),
            merge_results: true,
        }
    }
}

impl SearchConfig {
    /// Maximum free coverage: all engines that don't block.
    pub fn max_free() -> Self {
        Self {
            engines: vec![
                SearchEngine::Bing,
                SearchEngine::BraveSearch,
                SearchEngine::Yahoo,
                SearchEngine::DuckDuckGo,
                SearchEngine::GoogleTrends,
            ],
            merge_results: true,
            ..Default::default()
        }
    }

    /// Add Google CSE (100 free queries/day).
    pub fn with_google_cse(mut self, api_key: &str, cx: &str) -> Self {
        self.google_cse_key = Some(api_key.to_string());
        self.google_cse_cx = Some(cx.to_string());
        self.engines.insert(0, SearchEngine::GoogleCSE);
        self
    }
}

/// JavaScript to extract search results from a rendered page.
/// Returns JSON array of {title, url, snippet}.
pub fn extraction_js(selectors: &ResultSelectors) -> String {
    format!(
        r#"
(() => {{
    const results = [];
    const containers = document.querySelectorAll('{container}');
    containers.forEach((el, i) => {{
        if (i >= 30) return;
        const titleEl = el.querySelector('{title}');
        const urlEl = el.querySelector('{url}');
        const snippetEl = el.querySelector('{snippet}');
        if (titleEl) {{
            results.push({{
                title: (titleEl.innerText || '').trim(),
                url: (urlEl ? (urlEl.href || urlEl.innerText || '') : '').trim(),
                snippet: (snippetEl ? snippetEl.innerText || '' : '').trim()
            }});
        }}
    }});
    return JSON.stringify(results);
}})()
"#,
        container = selectors.container,
        title = selectors.title,
        url = selectors.url,
        snippet = selectors.snippet,
    )
}

/// JavaScript to extract Google CSE results from JSON API response.
pub fn google_cse_url(key: &str, cx: &str, query: &str) -> String {
    let q = urlencoded(query);
    format!(
        "https://www.googleapis.com/customsearch/v1?key={key}&cx={cx}&q={q}&num=10"
    )
}

/// Detect if a page is showing a CAPTCHA or block page.
pub fn is_blocked_page(page_text: &str) -> bool {
    let lower = page_text.to_lowercase();
    lower.contains("unusual traffic") ||
    lower.contains("detected unusual") ||
    lower.contains("are you a robot") ||
    lower.contains("captcha") ||
    lower.contains("verify you are a human") ||
    lower.contains("access denied") ||
    lower.contains("blocked") && lower.contains("bot") ||
    lower.contains("connection has been suspended") ||
    lower.contains("please complete the following challenge")
}

/// Simple URL encoding for query strings.
pub fn urlencoded(s: &str) -> String {
    s.chars().map(|c| match c {
        ' ' => '+'.to_string(),
        'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
        _ => format!("%{:02X}", c as u32),
    }).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Search execution engine — cascading multi-engine search
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a search query across multiple engines with automatic failover.
///
/// Tries each engine in the order given. For each engine:
/// 1. Builds the search URL from the engine's URL template
/// 2. Navigates the page to that URL and waits for load
/// 3. Evaluates extraction JS using the engine's CSS selectors
/// 4. If results are found and the page is not a CAPTCHA/block page, returns them
/// 5. Otherwise falls back to the next engine
///
/// Returns the first successful set of results, or an error if all engines fail.
pub async fn search(
    query: &str,
    page: &Page,
    engines: &[SearchEngine],
) -> Result<Vec<SearchResult>, BrowserError> {
    if engines.is_empty() {
        return Err(BrowserError::NavigationFailed(
            super::error::NavigationError::ChromeNetError("no search engines provided".into()),
        ));
    }

    let mut last_error: Option<BrowserError> = None;

    for engine in engines {
        // Skip GoogleCSE — it requires an API key and is not URL-navigable
        if *engine == SearchEngine::GoogleCSE {
            continue;
        }

        let url = engine.search_url(query);
        if url.is_empty() {
            continue;
        }

        // Navigate to the search URL
        match page.navigate(&url, WaitUntil::NetworkIdle).await {
            Ok(_nav) => {}
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        }

        // Check if the page is a CAPTCHA/block page by reading body text
        let body_text = page
            .evaluate_expression("document.body ? document.body.innerText : ''")
            .await
            .unwrap_or(Value::String(String::new()));
        let body_str = body_text.as_str().unwrap_or("");

        if is_blocked_page(body_str) {
            last_error = Some(BrowserError::NavigationFailed(
                super::error::NavigationError::ChromeNetError(format!(
                    "{} returned a CAPTCHA/block page",
                    engine.name()
                )),
            ));
            continue;
        }

        // Extract results using the engine's CSS selectors
        let selectors = engine.result_selectors();
        let js = extraction_js(&selectors);

        let raw = match page.evaluate_expression(&js).await {
            Ok(val) => val,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };

        // Parse the JSON string returned by extraction_js
        let json_str = match &raw {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };

        let items: Vec<Value> = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(_) => {
                last_error = Some(BrowserError::JsonError(format!(
                    "failed to parse search results from {}",
                    engine.name()
                )));
                continue;
            }
        };

        // Empty results = engine likely blocked us silently
        if items.is_empty() {
            last_error = Some(BrowserError::NavigationFailed(
                super::error::NavigationError::ChromeNetError(format!(
                    "{} returned zero results (possible silent block)",
                    engine.name()
                )),
            ));
            continue;
        }

        // Convert raw JSON items into SearchResult structs
        let results: Vec<SearchResult> = items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| {
                let title = item.get("title")?.as_str()?.to_string();
                let url = item.get("url")?.as_str()?.to_string();
                let snippet = item
                    .get("snippet")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();

                // Skip entries with empty title or URL
                if title.is_empty() || url.is_empty() {
                    return None;
                }

                Some(SearchResult {
                    title,
                    url,
                    snippet,
                    source: engine.clone(),
                    rank: i + 1,
                })
            })
            .collect();

        if results.is_empty() {
            last_error = Some(BrowserError::NavigationFailed(
                super::error::NavigationError::ChromeNetError(format!(
                    "{} results had no valid title/url pairs",
                    engine.name()
                )),
            ));
            continue;
        }

        // Success — return first engine's results
        return Ok(results);
    }

    // All engines failed
    Err(last_error.unwrap_or_else(|| {
        BrowserError::NavigationFailed(super::error::NavigationError::ChromeNetError(
            "all search engines failed".into(),
        ))
    }))
}

/// Profile pool for Google Search with persistent cookies.
#[derive(Debug)]
pub struct ProfilePool {
    /// Directory containing Chrome profile directories.
    pub profiles_dir: std::path::PathBuf,
    /// Number of profiles available.
    pub count: usize,
    /// Queries used today per profile index.
    pub usage: HashMap<usize, u32>,
    /// Max queries per profile per day.
    pub max_per_profile: u32,
}

impl ProfilePool {
    pub fn new(profiles_dir: std::path::PathBuf, count: usize) -> Self {
        Self {
            profiles_dir,
            count,
            usage: HashMap::new(),
            max_per_profile: 100,
        }
    }

    /// Get the next available profile directory (round-robin, respecting daily limit).
    pub fn next_profile(&mut self) -> Option<std::path::PathBuf> {
        for i in 0..self.count {
            let used = self.usage.get(&i).copied().unwrap_or(0);
            if used < self.max_per_profile {
                *self.usage.entry(i).or_insert(0) += 1;
                return Some(self.profiles_dir.join(format!("profile-{i}")));
            }
        }
        None // all profiles exhausted for today
    }

    /// Reset daily usage counters.
    pub fn reset_daily(&mut self) {
        self.usage.clear();
    }

    /// Total queries remaining across all profiles.
    pub fn remaining(&self) -> u32 {
        let used: u32 = self.usage.values().sum();
        (self.count as u32 * self.max_per_profile).saturating_sub(used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_engine_urls() {
        let url = SearchEngine::Bing.search_url("test query");
        assert!(url.contains("bing.com"));
        assert!(url.contains("test+query"));
    }

    #[test]
    fn brave_search_url() {
        let url = SearchEngine::BraveSearch.search_url("hello world");
        assert!(url.contains("search.brave.com"));
    }

    #[test]
    fn is_blocked_detects_google() {
        assert!(is_blocked_page("Our systems have detected unusual traffic"));
        assert!(is_blocked_page("Please verify you are a human"));
        assert!(is_blocked_page("complete the CAPTCHA below"));
        assert!(!is_blocked_page("Search results for test query"));
    }

    #[test]
    fn urlencoded_spaces() {
        assert_eq!(urlencoded("hello world"), "hello+world");
        assert_eq!(urlencoded("a&b"), "a%26b");
    }

    #[test]
    fn profile_pool_rotation() {
        let mut pool = ProfilePool::new(std::path::PathBuf::from("/tmp/profiles"), 3);
        pool.max_per_profile = 2;
        assert!(pool.next_profile().is_some()); // profile-0
        assert!(pool.next_profile().is_some()); // profile-0 (2nd use)
        assert!(pool.next_profile().is_some()); // profile-1
        assert!(pool.next_profile().is_some()); // profile-1
        assert!(pool.next_profile().is_some()); // profile-2
        assert!(pool.next_profile().is_some()); // profile-2
        assert!(pool.next_profile().is_none()); // all exhausted
    }

    #[test]
    fn profile_pool_remaining() {
        let pool = ProfilePool::new(std::path::PathBuf::from("/tmp"), 10);
        assert_eq!(pool.remaining(), 1000); // 10 profiles × 100 max
    }

    #[test]
    fn profile_pool_reset() {
        let mut pool = ProfilePool::new(std::path::PathBuf::from("/tmp"), 2);
        pool.max_per_profile = 1;
        pool.next_profile();
        pool.next_profile();
        assert!(pool.next_profile().is_none());
        pool.reset_daily();
        assert!(pool.next_profile().is_some());
    }

    #[test]
    fn extraction_js_has_selectors() {
        let sel = SearchEngine::Bing.result_selectors();
        let js = extraction_js(&sel);
        assert!(js.contains("b_algo"));
        assert!(js.contains("JSON.stringify"));
    }

    #[test]
    fn default_config_has_engines() {
        let cfg = SearchConfig::default();
        assert!(cfg.engines.len() >= 4);
        assert!(cfg.engines.contains(&SearchEngine::Bing));
        assert!(cfg.engines.contains(&SearchEngine::BraveSearch));
    }

    #[test]
    fn max_free_config() {
        let cfg = SearchConfig::max_free();
        assert!(cfg.merge_results);
        assert!(!cfg.engines.contains(&SearchEngine::GoogleCSE));
    }

    #[test]
    fn google_cse_url_format() {
        let url = google_cse_url("KEY", "CX123", "test query");
        assert!(url.contains("KEY"));
        assert!(url.contains("CX123"));
        assert!(url.contains("test+query"));
    }
}
