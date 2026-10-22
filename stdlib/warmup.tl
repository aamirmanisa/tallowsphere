// tallow.warmup — Browser session pre-warming pipeline
//
// Warms up a fresh browser session by performing human-like browsing activity
// before scraping a protected domain. Builds cookies, local storage, session
// storage, and organic-looking browsing history to avoid anti-bot detection.
//
// Connects to the existing warmup.rs engine and cookie_farm.rs.

/// Result of a browser session warm-up operation.
struct WarmupResult {
    /// Cookies collected during warm-up (name → value).
    cookies: Map<String, String>,
    /// Local storage entries collected (key → value).
    local_storage: Map<String, String>,
    /// Session storage entries collected (key → value).
    session_storage: Map<String, String>,
    /// User-Agent string used during warm-up.
    user_agent: String,
    /// Proxy used during warm-up (empty string if none).
    proxy_used: String,
    /// Total warm-up duration in seconds.
    duration_seconds: f64,
    /// Number of pages visited during warm-up.
    pages_visited: i32,
}

/// Warm up a browser session before scraping a protected domain.
///
/// level controls the warm-up intensity:
///   - "essential": Visit homepage only (fastest, ~3-8s)
///   - "standard": Visit 3 pages with scroll and click activity (~15-30s)
///   - "full": Visit 10 pages with human-like browsing and Weibull timing (~60-120s)
///
/// Returns a WarmupResult containing cookies, storage, and metadata that
/// can be injected into subsequent scraping sessions.
// native: connects to src/browser/warmup.rs execute_warmup engine,
//          uses traffic_morph.rs for realistic Weibull timing,
//          collects cookies/storage from the browser context
native fn warmup_session(url: String, level: String) -> WarmupResult
