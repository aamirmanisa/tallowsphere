//! Tor-aware stealth profile for Tallow browser automation.
//!
//! When routing through Tor, the browser fingerprint must match the Tor Browser
//! to avoid detection. This module provides a Tor Browser-specific stealth
//! profile and utilities for detecting Tor proxy connections.

use super::stealth::StealthProfile;

/// Mint a per-construction canvas/audio noise seed.
///
/// A literal `0` was a **fleet-uniform** seed: every Tallow instance using a
/// Tor profile emitted the identical deterministic noise pattern — a
/// cross-instance cluster signal (P1 C1: no fleet-uniform fingerprint
/// material). Each profile construction mints a fresh nonzero seed instead:
/// stable for the life of the profile (no per-read drift) and unique per
/// instance. Rotate by rebuilding the profile at persona burn.
fn mint_canvas_seed() -> u64 {
    use rand::Rng as _;
    let seed: u64 = rand::rng().random();
    if seed == 0 { 1 } else { seed }
}

/// Returns a `StealthProfile` matching the Tor Browser fingerprint.
///
/// Tor Browser is based on Firefox ESR with specific hardened defaults:
/// - Window size is fixed at 1000x900
/// - WebGL is blocked (vendor/renderer report empty)
/// - Canvas noise uses a per-instance minted seed (never a fleet constant)
/// - Hardware concurrency is clamped to 2
/// - Timezone is always UTC regardless of locale
pub fn tor_browser_profile() -> StealthProfile {
    StealthProfile {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
            .to_string(),
        platform: "Win32".to_string(),
        vendor: String::new(),
        languages: vec!["en-US".to_string(), "en".to_string()],
        hardware_concurrency: 2,
        device_memory: 8.0,
        max_touch_points: 0,
        viewport: (1000, 900),
        device_scale_factor: 1.0,
        webgl_vendor: String::new(),
        webgl_renderer: String::new(),
        timezone: "UTC".to_string(),
        locale: "en-US".to_string(),
        canvas_noise_seed: mint_canvas_seed(),
        is_firefox_profile: true,
    }
}

/// Returns a Tor-privacy `StealthProfile` that is **Chrome-consistent**.
///
/// The Tallow browser backend is Chromium (Firefox-family backends need a
/// Juggler-enabled Firefox that may not be present). A Firefox fingerprint
/// injected into a Chromium engine is a WAF-visible contradiction (JS says
/// Firefox, TLS/engine say Chrome). This profile keeps the Tor privacy posture
/// — no local timezone leak (UTC), canvas/WebGL blocked, hardware concurrency
/// clamped — but reports a **Chrome** UA / `is_firefox_profile: false` so the
/// on-wire fingerprint is internally consistent with the Chromium engine.
pub fn tor_chrome_profile() -> StealthProfile {
    StealthProfile {
        user_agent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                .to_string(),
        platform: "Win32".to_string(),
        vendor: "Google Inc.".to_string(),
        languages: vec!["en-US".to_string(), "en".to_string()],
        hardware_concurrency: 2,
        device_memory: 8.0,
        max_touch_points: 0,
        viewport: (1000, 900),
        device_scale_factor: 1.0,
        webgl_vendor: String::new(),
        webgl_renderer: String::new(),
        timezone: "UTC".to_string(),
        locale: "en-US".to_string(),
        canvas_noise_seed: mint_canvas_seed(),
        is_firefox_profile: false,
    }
}

/// Returns `true` if the proxy URL looks like a Tor SOCKS proxy.
///
/// Checks for `socks5://` or `socks5h://` schemes pointing to localhost
/// (`127.0.0.1` or `localhost`) on standard Tor ports 9050-9059
/// (multi-instance range).
pub fn is_tor_proxy(proxy: &str) -> bool {
    let lower = proxy.to_lowercase();

    // Must be a SOCKS5 proxy (Tor uses SOCKS5)
    let rest = if let Some(r) = lower.strip_prefix("socks5h://") {
        r
    } else if let Some(r) = lower.strip_prefix("socks5://") {
        r
    } else {
        return false;
    };

    // Must be localhost
    let after_host = if let Some(r) = rest.strip_prefix("127.0.0.1:") {
        r
    } else if let Some(r) = rest.strip_prefix("localhost:") {
        r
    } else {
        return false;
    };

    // Extract port number (strip any trailing path/query)
    let port_str = after_host.split(&['/', '?', '#'][..]).next().unwrap_or("");
    if let Ok(port) = port_str.parse::<u16>() {
        (9050..=9059).contains(&port)
    } else {
        false
    }
}

/// Adjusts an existing `StealthProfile` to match the Tor Browser fingerprint.
///
/// Overrides user agent, viewport, timezone, locale, hardware concurrency,
/// WebGL vendor/renderer, and canvas noise seed to match `tor_browser_profile()`.
pub fn adjust_stealth_for_tor(profile: &mut StealthProfile) {
    let tor = tor_browser_profile();
    profile.user_agent = tor.user_agent;
    profile.viewport = tor.viewport;
    profile.timezone = tor.timezone;
    profile.locale = tor.locale;
    profile.hardware_concurrency = tor.hardware_concurrency;
    profile.webgl_vendor = tor.webgl_vendor;
    profile.webgl_renderer = tor.webgl_renderer;
    profile.canvas_noise_seed = tor.canvas_noise_seed;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_profile_matches_tor_browser() {
        let p = tor_browser_profile();
        assert!(
            p.user_agent.contains("Firefox/128.0"),
            "UA should contain Firefox/128.0"
        );
        assert_eq!(p.viewport, (1000, 900), "viewport should be 1000x900");
        assert_eq!(p.timezone, "UTC", "timezone should be UTC");
        assert_eq!(
            p.hardware_concurrency, 2,
            "hardware_concurrency should be 2"
        );
        assert!(
            p.webgl_vendor.is_empty(),
            "webgl_vendor should be empty (blocked)"
        );
        assert!(
            p.webgl_renderer.is_empty(),
            "webgl_renderer should be empty (blocked)"
        );
        assert_ne!(
            p.canvas_noise_seed, 0,
            "canvas seed must be minted per construction, never the fleet-uniform 0"
        );
    }

    #[test]
    fn is_tor_proxy_detection() {
        // Should detect standard Tor SOCKS proxies
        assert!(is_tor_proxy("socks5://127.0.0.1:9050"));
        assert!(is_tor_proxy("socks5://127.0.0.1:9052"));
        assert!(is_tor_proxy("socks5h://127.0.0.1:9050"));
        assert!(is_tor_proxy("socks5://localhost:9050"));

        // Should reject non-Tor proxies
        assert!(!is_tor_proxy("socks5://127.0.0.1:1080"));
        assert!(!is_tor_proxy("http://proxy.example.com:8080"));
    }

    #[test]
    fn adjust_stealth_modifies_profile() {
        let mut profile = StealthProfile::chrome_windows();
        assert_eq!(profile.viewport, (1920, 1080));
        assert_eq!(profile.timezone, "America/New_York");

        adjust_stealth_for_tor(&mut profile);

        assert_eq!(profile.viewport, (1000, 900));
        assert_eq!(profile.timezone, "UTC");
    }

    #[test]
    fn tor_profile_is_firefox() {
        let p = tor_browser_profile();
        assert!(
            p.is_firefox_profile,
            "Tor profile must be flagged as Firefox to skip Chrome-specific evasions"
        );
    }

    #[test]
    fn tor_profiles_mint_unique_seeds() {
        let a = tor_browser_profile();
        let b = tor_browser_profile();
        assert_ne!(a.canvas_noise_seed, 0);
        assert_ne!(b.canvas_noise_seed, 0);
        assert_ne!(
            a.canvas_noise_seed, b.canvas_noise_seed,
            "two profile constructions must not share a canvas seed (fleet-uniform signal)"
        );
        // adjust_stealth_for_tor carries the freshly minted seed through.
        let mut c = StealthProfile::chrome_windows();
        adjust_stealth_for_tor(&mut c);
        assert_ne!(c.canvas_noise_seed, 0);
    }

    #[test]
    fn tor_chrome_profile_is_chrome_consistent() {
        let p = tor_chrome_profile();
        // Fingerprint normalization: the Chromium engine must NOT claim a
        // Firefox profile (JS/TLS/engine all Chrome-consistent).
        assert!(
            !p.is_firefox_profile,
            "Tor Chrome profile must be Chrome-flagged (not Firefox) to match the Chromium engine"
        );
        assert!(
            p.user_agent.contains("Chrome/"),
            "Tor Chrome profile must use a Chrome UA, got: {}",
            p.user_agent
        );
        // But it must still keep the Tor privacy posture (no tz leak, blocked
        // canvas/WebGL, clamped concurrency, 1000x900).
        assert_eq!(p.timezone, "UTC", "must stay UTC (no local tz leak)");
        assert_eq!(p.viewport, (1000, 900));
        assert_eq!(p.hardware_concurrency, 2);
        assert!(p.webgl_vendor.is_empty() && p.webgl_renderer.is_empty());
    }
}
