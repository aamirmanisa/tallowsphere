// tallow.captcha — multi-vendor CAPTCHA detection and classification.
//
// Detects 7+ CAPTCHA/WAF providers and provides bypass strategy
// recommendations. Works with tallow.escalation for automated handling.

struct CaptchaChallenge {
    provider: String,       // turnstile, hcaptcha, recaptcha, datadome, etc.
    challenge_type: String, // checkbox, non_interactive, invisible, block_page, etc.
    sitekey: String?,       // CAPTCHA sitekey if available
    action: String?,        // Form action URL
    confidence: Float,      // Detection confidence 0.0-1.0
    signals: [String],      // Detection signals found
}

struct CaptchaRecommendation {
    strategy: String,
    notes: String,
    provider: String,
}

struct BlockCheck {
    blocked: Bool,
    status_code: Int,
    signals: [String],
}

// Detect CAPTCHA/WAF on page HTML. Optional headers Map for server detection.
fn CAPTCHA.detect(html: String, headers: Map<String, String>?) -> CaptchaChallenge

// Classify challenge type and extract sitekey params. Same as detect.
fn CAPTCHA.classify(html: String, headers: Map<String, String>?) -> CaptchaChallenge

// Get bypass strategy recommendation for a challenge
fn CAPTCHA.recommend(challenge: CaptchaChallenge) -> CaptchaRecommendation
fn CaptchaChallenge.recommend(self) -> CaptchaRecommendation

// Quick check if a response status code indicates a block page
fn CAPTCHA.is_blocked(status: Int, html: String?) -> BlockCheck
