// tallow.turnstile — Cloudflare Turnstile detection and solve chain
//
// Detects and automatically solves Cloudflare Turnstile challenges using
// a tiered approach: external solving API, pre-warmed cookie injection,
// and fresh proxy + stealth profile rotation.
//
// Wires into the existing captcha.rs Turnstile detection path.

/// Result of a Turnstile solve attempt.
struct TurnstileSolution {
    /// Whether the Turnstile challenge was successfully solved.
    solved: bool,
    /// The method that produced the solution.
    /// One of: "api", "cookie", "proxy", "manual"
    method: String,
    /// The Turnstile token obtained from the solving service.
    token: String?,
    /// Cookies injected to bypass the challenge (cf_clearance, __cf_bm).
    cookies: Map<String, String>?,
}

/// Solve a Cloudflare Turnstile challenge on a page.
///
/// Tries the following methods in order:
///   1. External API (2Captcha/Anti-Captcha) — submits the Turnstile task
///      and polls for a valid token.
///   2. Pre-warmed cookies — injects cf_clearance and __cf_bm cookies from
///      the cookie farm to bypass Turnstile without solving.
///   3. Fresh proxy + stealth profile — rotates to a new proxy IP and
///      launches a browser with a fresh, un-flagged stealth profile.
///
/// Returns a TurnstileSolution indicating success/failure and the method used.
// native: connects to src/browser/captcha.rs captcha detection engine,
//          uses 2Captcha solver integration (BRCA-02),
//          integrates with warmup.rs cookie farm for pre-warmed cookies,
//          auto-triggers when CaptchaDetector detects Turnstile on page load
native fn solve_turnstile(url: String) -> TurnstileSolution
