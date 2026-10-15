// tallow.fingerprint — browser fingerprint randomization.
//
// Generates random browser fingerprints (WebGL, canvas, audio, navigator,
// screen, fonts) and produces JavaScript injection code to evade
// browser fingerprinting detection.

struct Fingerprint {
    user_agent: String,
    platform: String,
    language: String,
    screen_width: Int,
    screen_height: Int,
    timezone: String,
}

// Generate a random fingerprint profile
fn Fingerprint.generate() -> Fingerprint

// Generate a new random fingerprint (same as generate, for rotation)
fn Fingerprint.rotate() -> Fingerprint

// Generate JavaScript to inject this fingerprint into a page
fn Fingerprint.inject_js(self) -> String

// Generate matching HTTP headers (User-Agent, Accept-Language, Sec-Ch-Ua, etc.)
fn Fingerprint.to_headers(self) -> Map<String, String>
