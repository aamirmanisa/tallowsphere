// tallow.escalation — progressive rendering escalation.
//
// Automatically escalates through rendering strategies when simpler
// approaches fail. Inspired by ScrapingBee auto-mode and Firecrawl engine waterfall.
//
// Escalation ladder (0-5):
//   0: raw_http — fastest/cheapest, plain HTTP GET
//   1: cookie_jar — HTTP + session cookies
//   2: proxy — HTTP + rotated IP
//   3: browser_cdp — CDP browser rendering
//   4: browser_stealth — CDP + fingerprint spoofing
//   5: browser_premium — CDP + stealth + premium residential proxy

struct EscalationResult {
    content: String,
    status: Int,
    escalated_from: String,
    attempts: Int,
    duration_ms: Int,
    url: String,
}

// Progressive fetch: start at start_level, escalate to max_level on failure.
// Returns content from the first level that succeeds.
fn Escalation.fetch(url: String, max_level: String?, start_level: String?, timeout_ms: Int?) -> EscalationResult

// Fetch + extraction. Built-in extractors: "title", "links", "text", "status".
fn Escalation.scrape(url: String, extractor: String, max_level: String?) -> EscalationResult
