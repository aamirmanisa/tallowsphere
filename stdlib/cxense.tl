// tallow.cxense — Cxense-metered paywall bypass.
//
// Cxense (Piano) meters news paywalls client-side: the full article IS in the
// served HTML but Cxense JS (cdn.cxense.com) gates it with a CSS overlay after a
// free-article quota. Bypass = reset meter cookies + whitelisted referrer +
// block Cxense JS + JSON-LD articleBody leak.
//
// See src/stdlib/cxense.rs for the implementation.

// Extract a Cxense-metered article using every whitelisted referrer in order.
// Optional cookie_header (str) lets you pass harvested cookies (Cxense meter
// counters are stripped automatically).
fn get_article(url: String, cookie_header: String?) -> Map

// Fetch with one explicit referrer style:
//   "drudge" | "social" | "google" | "facebook" | "hn"
fn get_with_referrer(url: String, referrer_style: String) -> Map

// Pure JSON-LD `articleBody` extraction for a URL (no referrer tricks).
fn extract_jsonld(url: String) -> Map

// Instructions for clearing the Cxense meter-cookie quota.
fn reset_meter() -> Map

// The whitelisted referrer styles available to get_with_referrer.
fn referrer_map() -> Map
