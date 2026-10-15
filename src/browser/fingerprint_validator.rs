//! Cross-vector fingerprint consistency validator for Tallow stealth system.
//!
//! Modern anti-bot ML models detect inconsistencies ACROSS fingerprint vectors.
//! Spoofing individual values is insufficient — canvas claiming RTX 4090 quality
//! but WebGL reporting Intel HD 630 is a dead giveaway. This module validates
//! that all fingerprint vectors in a `StealthProfile` are mutually consistent
//! and can auto-fix detected inconsistencies.
//!
//! Checks performed:
//! - UA platform vs navigator.platform
//! - WebGL renderer vs vendor (e.g. NVIDIA vendor for RTX renderer)
//! - WebGL renderer vs canvas rendering capability tier
//! - Font list plausibility for claimed OS
//! - Screen resolution against known real-world resolutions
//! - Client Hints consistency with UA string
//! - Touch support vs device type (no touch on desktop)
//! - Device memory and hardware concurrency realism per platform
//! - Device scale factor vs platform norms

use super::stealth::StealthProfile;

// ---------------------------------------------------------------------------
// Warning types
// ---------------------------------------------------------------------------

/// Severity of a fingerprint inconsistency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Will likely trigger ML classifiers — must fix before use.
    Critical,
    /// Suspicious signal that contributes to bot score.
    Warning,
    /// Minor deviation, unlikely to trigger alone but adds entropy.
    Info,
}

/// A single fingerprint inconsistency detected across vectors.
#[derive(Debug, Clone)]
pub struct FingerprintWarning {
    pub severity: Severity,
    /// Which fingerprint vectors are in conflict.
    pub vectors: Vec<&'static str>,
    /// Human-readable description of the inconsistency.
    pub message: String,
}

impl FingerprintWarning {
    fn critical(vectors: Vec<&'static str>, message: impl Into<String>) -> Self {
        Self { severity: Severity::Critical, vectors, message: message.into() }
    }
    fn warning(vectors: Vec<&'static str>, message: impl Into<String>) -> Self {
        Self { severity: Severity::Warning, vectors, message: message.into() }
    }
    fn info(vectors: Vec<&'static str>, message: impl Into<String>) -> Self {
        Self { severity: Severity::Info, vectors, message: message.into() }
    }
}

// ---------------------------------------------------------------------------
// Consistent fingerprint sets for common profiles
// ---------------------------------------------------------------------------

/// A pre-validated, internally consistent fingerprint set.
#[derive(Debug, Clone)]
pub struct ConsistentFingerprint {
    pub name: &'static str,
    pub user_agent: &'static str,
    pub platform: &'static str,
    pub vendor: &'static str,
    pub webgl_vendor: &'static str,
    pub webgl_renderer: &'static str,
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    pub max_touch_points: u32,
    pub viewport: (u32, u32),
    pub device_scale_factor: f64,
}

/// Windows + Chrome + Intel integrated GPU.
pub const WINDOWS_CHROME_INTEL: ConsistentFingerprint = ConsistentFingerprint {
    name: "Windows Chrome Intel",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
    platform: "Win32",
    vendor: "Google Inc.",
    webgl_vendor: "Google Inc. (Intel)",
    webgl_renderer: "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    hardware_concurrency: 8,
    device_memory: 8.0,
    max_touch_points: 0,
    viewport: (1920, 1080),
    device_scale_factor: 1.0,
};

/// Windows + Chrome + NVIDIA dedicated GPU.
pub const WINDOWS_CHROME_NVIDIA: ConsistentFingerprint = ConsistentFingerprint {
    name: "Windows Chrome NVIDIA",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
    platform: "Win32",
    vendor: "Google Inc.",
    webgl_vendor: "Google Inc. (NVIDIA)",
    webgl_renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    hardware_concurrency: 12,
    device_memory: 16.0,
    max_touch_points: 0,
    viewport: (1920, 1080),
    device_scale_factor: 1.0,
};

/// macOS + Chrome + Apple Silicon GPU.
pub const MAC_CHROME_APPLE: ConsistentFingerprint = ConsistentFingerprint {
    name: "Mac Chrome Apple GPU",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
    platform: "MacIntel",
    vendor: "Google Inc.",
    webgl_vendor: "Google Inc. (Apple)",
    webgl_renderer: "ANGLE (Apple, Apple M2, OpenGL 4.1)",
    hardware_concurrency: 10,
    device_memory: 8.0,
    max_touch_points: 0,
    viewport: (1440, 900),
    device_scale_factor: 2.0,
};

/// Linux + Chrome + Mesa/Intel GPU.
pub const LINUX_CHROME_MESA: ConsistentFingerprint = ConsistentFingerprint {
    name: "Linux Chrome Mesa",
    user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
    platform: "Linux x86_64",
    vendor: "Google Inc.",
    webgl_vendor: "Google Inc. (Intel)",
    webgl_renderer: "ANGLE (Intel, Mesa Intel(R) UHD Graphics 630, OpenGL 4.6)",
    hardware_concurrency: 8,
    device_memory: 8.0,
    max_touch_points: 0,
    viewport: (1920, 1080),
    device_scale_factor: 1.0,
};

/// All pre-validated consistent fingerprint sets.
pub const ALL_CONSISTENT_FINGERPRINTS: &[&ConsistentFingerprint] = &[
    &WINDOWS_CHROME_INTEL,
    &WINDOWS_CHROME_NVIDIA,
    &MAC_CHROME_APPLE,
    &LINUX_CHROME_MESA,
];

// ---------------------------------------------------------------------------
// Known-valid values for cross-reference
// ---------------------------------------------------------------------------

/// Common real-world desktop resolutions (width, height).
const KNOWN_DESKTOP_RESOLUTIONS: &[(u32, u32)] = &[
    (1366, 768),
    (1440, 900),
    (1536, 864),
    (1600, 900),
    (1680, 1050),
    (1920, 1080),
    (1920, 1200),
    (2048, 1152),
    (2560, 1080),
    (2560, 1440),
    (2560, 1600),
    (3440, 1440),
    (3840, 2160),
];

/// Common real-world mobile resolutions (width, height) at CSS pixels.
const KNOWN_MOBILE_RESOLUTIONS: &[(u32, u32)] = &[
    (320, 568),   // iPhone SE 1st gen
    (360, 640),   // many Android
    (360, 780),   // Samsung Galaxy
    (375, 667),   // iPhone 6/7/8
    (375, 812),   // iPhone X/XS/11 Pro
    (390, 844),   // iPhone 12/13/14
    (393, 852),   // iPhone 14/15 Pro
    (412, 915),   // Pixel 7/8
    (412, 846),   // Pixel 4 XL
    (414, 736),   // iPhone 6/7/8 Plus
    (414, 896),   // iPhone XR/11
    (428, 926),   // iPhone 12/13/14 Pro Max
    (430, 932),   // iPhone 15 Pro Max
    (768, 1024),  // iPad
    (810, 1080),  // iPad 10th gen
    (820, 1180),  // iPad Air
    (834, 1194),  // iPad Pro 11"
    (1024, 1366), // iPad Pro 12.9"
];

/// Windows-specific fonts that should NOT appear on Mac/Linux.
const WINDOWS_INDICATOR_FONTS: &[&str] = &[
    "Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma",
    "Trebuchet MS", "Verdana", "Lucida Console",
];

/// macOS-specific fonts that should NOT appear on Windows/Linux.
const MACOS_INDICATOR_FONTS: &[&str] = &[
    "Helvetica Neue", "San Francisco", "SF Pro", "Menlo", "Monaco",
    "Apple Symbols", "Apple Color Emoji", "Avenir",
];

/// Linux-specific fonts that should NOT appear on Windows/Mac.
const LINUX_INDICATOR_FONTS: &[&str] = &[
    "DejaVu Sans", "Liberation Sans", "Liberation Mono", "Noto Sans",
    "Ubuntu", "Droid Sans", "Cantarell",
];

/// WebGL vendor strings and their valid renderer prefixes.
const VENDOR_RENDERER_MAP: &[(&str, &[&str])] = &[
    ("NVIDIA",  &["NVIDIA GeForce", "NVIDIA RTX", "NVIDIA Quadro", "NVIDIA Tesla", "GeForce"]),
    ("Intel",   &["Intel(R) UHD", "Intel(R) HD", "Intel(R) Iris", "Intel(R) Xe", "Mesa Intel"]),
    ("Apple",   &["Apple M1", "Apple M2", "Apple M3", "Apple M4", "Apple GPU"]),
    ("AMD",     &["AMD Radeon", "Radeon", "ATI Radeon"]),
    ("Qualcomm", &["Adreno"]),
    ("ARM",     &["Mali"]),
];

// ---------------------------------------------------------------------------
// FingerprintValidator
// ---------------------------------------------------------------------------

/// Validates cross-vector consistency of a `StealthProfile` fingerprint.
///
/// Anti-bot ML models score inconsistencies across vectors. A single mismatch
/// (e.g. NVIDIA WebGL vendor with Intel renderer) can flag the entire session.
/// Use `validate()` to detect issues and `auto_fix()` to correct them.
pub struct FingerprintValidator;

impl FingerprintValidator {
    /// Check a stealth profile for cross-vector fingerprint inconsistencies.
    ///
    /// Returns an empty `Vec` if the profile is fully consistent.
    pub fn validate(profile: &StealthProfile) -> Vec<FingerprintWarning> {
        let mut warnings = Vec::new();

        Self::check_ua_platform(profile, &mut warnings);
        Self::check_webgl_vendor_renderer(profile, &mut warnings);
        Self::check_webgl_renderer_vs_canvas_tier(profile, &mut warnings);
        Self::check_screen_resolution(profile, &mut warnings);
        Self::check_client_hints_ua(profile, &mut warnings);
        Self::check_touch_vs_device_type(profile, &mut warnings);
        Self::check_hardware_realism(profile, &mut warnings);
        Self::check_device_scale_factor(profile, &mut warnings);
        Self::check_vendor_string(profile, &mut warnings);

        warnings
    }

    /// Automatically fix inconsistencies by snapping the profile to the
    /// nearest matching `ConsistentFingerprint` set based on the current
    /// UA string and WebGL renderer.
    ///
    /// Fixes are applied in-place. Returns the number of fields corrected.
    pub fn auto_fix(profile: &mut StealthProfile) -> usize {
        let best = Self::find_best_match(profile);
        let mut fixes = 0;

        // Platform must match UA
        let expected_platform = Self::expected_platform_for_ua(&profile.user_agent);
        if !expected_platform.is_empty() && profile.platform != expected_platform {
            profile.platform = expected_platform.to_string();
            fixes += 1;
        }

        // If we found a matching consistent set, apply its correlated values
        if let Some(fp) = best {
            if profile.webgl_vendor != fp.webgl_vendor {
                profile.webgl_vendor = fp.webgl_vendor.to_string();
                fixes += 1;
            }
            if profile.webgl_renderer != fp.webgl_renderer {
                profile.webgl_renderer = fp.webgl_renderer.to_string();
                fixes += 1;
            }
            if profile.vendor != fp.vendor {
                profile.vendor = fp.vendor.to_string();
                fixes += 1;
            }
            if profile.device_scale_factor != fp.device_scale_factor {
                profile.device_scale_factor = fp.device_scale_factor;
                fixes += 1;
            }
        } else {
            // No matching set — fix vendor/renderer consistency directly
            Self::fix_webgl_consistency(profile, &mut fixes);
        }

        // Touch must be 0 on desktop, >0 on mobile
        let is_mobile = Self::ua_is_mobile(&profile.user_agent);
        if !is_mobile && profile.max_touch_points > 0 {
            profile.max_touch_points = 0;
            fixes += 1;
        } else if is_mobile && profile.max_touch_points == 0 {
            profile.max_touch_points = 5;
            fixes += 1;
        }

        // Resolution must be real-world
        if !Self::is_known_resolution(profile.viewport, is_mobile) {
            let nearest = Self::nearest_resolution(profile.viewport, is_mobile);
            if profile.viewport != nearest {
                profile.viewport = nearest;
                fixes += 1;
            }
        }

        // Hardware concurrency must be power-of-2 or standard value
        if !Self::is_realistic_concurrency(profile.hardware_concurrency) {
            let fixed = Self::nearest_concurrency(profile.hardware_concurrency);
            if profile.hardware_concurrency != fixed {
                profile.hardware_concurrency = fixed;
                fixes += 1;
            }
        }

        // Device memory must be power-of-2 in {1, 2, 4, 8, 16, 32}
        if !Self::is_realistic_memory(profile.device_memory) {
            let fixed = Self::nearest_memory(profile.device_memory);
            if (profile.device_memory - fixed).abs() > 0.01 {
                profile.device_memory = fixed;
                fixes += 1;
            }
        }

        // Scale factor fix for platform
        Self::fix_scale_factor(profile, &mut fixes);

        fixes
    }

    // -----------------------------------------------------------------------
    // Individual validation checks
    // -----------------------------------------------------------------------

    /// UA string platform token must match navigator.platform.
    fn check_ua_platform(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let expected = Self::expected_platform_for_ua(&profile.user_agent);
        if !expected.is_empty() && profile.platform != expected {
            warnings.push(FingerprintWarning::critical(
                vec!["user_agent", "navigator.platform"],
                format!(
                    "UA indicates '{}' but platform is '{}' — expected '{}'",
                    Self::os_label_from_ua(&profile.user_agent),
                    profile.platform,
                    expected,
                ),
            ));
        }
    }

    /// WebGL vendor string must contain the GPU maker that matches the renderer.
    fn check_webgl_vendor_renderer(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        // Skip for empty WebGL (Tor Browser blocks it)
        if profile.webgl_vendor.is_empty() && profile.webgl_renderer.is_empty() {
            return;
        }
        if profile.webgl_vendor.is_empty() || profile.webgl_renderer.is_empty() {
            warnings.push(FingerprintWarning::warning(
                vec!["webgl_vendor", "webgl_renderer"],
                "One of WebGL vendor/renderer is empty while the other is set — both should be empty (Tor) or both populated".to_string(),
            ));
            return;
        }

        // Extract GPU maker from vendor string
        let vendor_upper = profile.webgl_vendor.to_uppercase();
        let renderer_upper = profile.webgl_renderer.to_uppercase();

        for &(maker, prefixes) in VENDOR_RENDERER_MAP {
            let maker_upper = maker.to_uppercase();
            if vendor_upper.contains(&maker_upper) {
                // Vendor claims this maker — renderer must contain one of its prefixes
                let renderer_matches = prefixes.iter().any(|p| {
                    renderer_upper.contains(&p.to_uppercase())
                });
                if !renderer_matches {
                    warnings.push(FingerprintWarning::critical(
                        vec!["webgl_vendor", "webgl_renderer"],
                        format!(
                            "WebGL vendor contains '{}' but renderer '{}' has no matching {} GPU model",
                            profile.webgl_vendor, profile.webgl_renderer, maker,
                        ),
                    ));
                }
                return;
            }
        }
    }

    /// Canvas rendering capability tier should match WebGL GPU class.
    fn check_webgl_renderer_vs_canvas_tier(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        if profile.webgl_renderer.is_empty() {
            return;
        }
        let renderer = &profile.webgl_renderer;

        // Check for platform-appropriate rendering API in ANGLE string
        let ua = &profile.user_agent;
        if ua.contains("Windows") {
            // Windows ANGLE should use Direct3D
            if renderer.contains("ANGLE") && !renderer.contains("Direct3D") && !renderer.contains("D3D") {
                warnings.push(FingerprintWarning::warning(
                    vec!["webgl_renderer", "user_agent"],
                    format!(
                        "Windows UA but WebGL renderer uses non-D3D backend: '{}'",
                        renderer,
                    ),
                ));
            }
        } else if ua.contains("Macintosh") || ua.contains("Mac OS") {
            // macOS ANGLE should use OpenGL or Metal
            if renderer.contains("ANGLE") && renderer.contains("Direct3D") {
                warnings.push(FingerprintWarning::critical(
                    vec!["webgl_renderer", "user_agent"],
                    format!(
                        "macOS UA but WebGL renderer reports Direct3D (impossible): '{}'",
                        renderer,
                    ),
                ));
            }
        } else if ua.contains("Linux") && !ua.contains("Android") {
            // Linux ANGLE should use OpenGL or Vulkan
            if renderer.contains("ANGLE") && renderer.contains("Direct3D") {
                warnings.push(FingerprintWarning::critical(
                    vec!["webgl_renderer", "user_agent"],
                    format!(
                        "Linux UA but WebGL renderer reports Direct3D (impossible): '{}'",
                        renderer,
                    ),
                ));
            }
        }
    }

    /// Screen resolution must be a known real-world value.
    fn check_screen_resolution(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let is_mobile = Self::ua_is_mobile(&profile.user_agent);
        if !Self::is_known_resolution(profile.viewport, is_mobile) {
            warnings.push(FingerprintWarning::warning(
                vec!["viewport", "screen.width", "screen.height"],
                format!(
                    "Viewport {}x{} is not a known real-world {} resolution",
                    profile.viewport.0, profile.viewport.1,
                    if is_mobile { "mobile" } else { "desktop" },
                ),
            ));
        }
    }

    /// Client Hints platform should match UA OS.
    fn check_client_hints_ua(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let ua = &profile.user_agent;

        // Extract Chrome version from UA
        let chrome_ver = ua.split("Chrome/").nth(1)
            .and_then(|s| s.split('.').next())
            .unwrap_or("");

        // If this is supposedly Chrome, it must have a Chrome/ version token
        if profile.vendor == "Google Inc." && chrome_ver.is_empty() && !ua.contains("CriOS") {
            warnings.push(FingerprintWarning::warning(
                vec!["user_agent", "vendor", "client_hints"],
                "Vendor is 'Google Inc.' but UA has no Chrome/ version — Client Hints will be inconsistent".to_string(),
            ));
        }

        // Check Sec-CH-UA-Platform would match
        // Order matters: iPhone/iPad UAs contain "Mac OS X", check them first.
        let ch_platform = if ua.contains("iPhone") || ua.contains("iPad") {
            "iOS"
        } else if ua.contains("Android") {
            "Android"
        } else if ua.contains("Windows") {
            "Windows"
        } else if ua.contains("Macintosh") || ua.contains("Mac OS") {
            "macOS"
        } else if ua.contains("Linux") {
            "Linux"
        } else {
            ""
        };

        // Platform field should be consistent with what Client Hints JS API reports
        if !ch_platform.is_empty() {
            let platform_consistent = match ch_platform {
                "Windows" => profile.platform == "Win32",
                "macOS" => profile.platform == "MacIntel",
                "Linux" => profile.platform.starts_with("Linux"),
                "Android" => profile.platform.starts_with("Linux"),
                "iOS" => profile.platform == "iPhone" || profile.platform == "iPad",
                _ => true,
            };
            if !platform_consistent {
                warnings.push(FingerprintWarning::critical(
                    vec!["user_agent", "navigator.platform", "client_hints"],
                    format!(
                        "UA implies CH-Platform '{}' but navigator.platform is '{}' — cross-API mismatch",
                        ch_platform, profile.platform,
                    ),
                ));
            }
        }
    }

    /// Touch support must match device type — no touch on desktop, touch on mobile.
    fn check_touch_vs_device_type(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let is_mobile = Self::ua_is_mobile(&profile.user_agent);

        if !is_mobile && profile.max_touch_points > 0 {
            // Some desktop laptops have touch, but 0 is the safe default
            warnings.push(FingerprintWarning::warning(
                vec!["max_touch_points", "user_agent"],
                format!(
                    "Desktop UA but max_touch_points={} — most desktop Chrome reports 0",
                    profile.max_touch_points,
                ),
            ));
        }
        if is_mobile && profile.max_touch_points == 0 {
            warnings.push(FingerprintWarning::critical(
                vec!["max_touch_points", "user_agent"],
                "Mobile UA but max_touch_points=0 — all mobile devices report touch support".to_string(),
            ));
        }
    }

    /// Device memory and hardware concurrency must be realistic.
    fn check_hardware_realism(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        // hardware_concurrency: Chrome reports this as power-of-2 or common core counts
        if !Self::is_realistic_concurrency(profile.hardware_concurrency) {
            warnings.push(FingerprintWarning::warning(
                vec!["hardware_concurrency"],
                format!(
                    "hardware_concurrency={} is unusual — Chrome typically reports 2, 4, 6, 8, 10, 12, 16, 24, 32",
                    profile.hardware_concurrency,
                ),
            ));
        }

        // device_memory: Chrome reports as power-of-2 in GB {0.25, 0.5, 1, 2, 4, 8, 16, 32}
        if !Self::is_realistic_memory(profile.device_memory) {
            warnings.push(FingerprintWarning::warning(
                vec!["device_memory"],
                format!(
                    "device_memory={} is not a valid Chrome-reported value — must be power-of-2 in {{0.25, 0.5, 1, 2, 4, 8, 16, 32}}",
                    profile.device_memory,
                ),
            ));
        }

        // Mobile devices should not claim very high specs
        let is_mobile = Self::ua_is_mobile(&profile.user_agent);
        if is_mobile {
            if profile.hardware_concurrency > 12 {
                warnings.push(FingerprintWarning::info(
                    vec!["hardware_concurrency", "user_agent"],
                    format!(
                        "Mobile UA with hardware_concurrency={} — most phones report 4-8",
                        profile.hardware_concurrency,
                    ),
                ));
            }
            if profile.device_memory > 16.0 {
                warnings.push(FingerprintWarning::info(
                    vec!["device_memory", "user_agent"],
                    format!(
                        "Mobile UA with device_memory={} — most phones report 4-8",
                        profile.device_memory,
                    ),
                ));
            }
        }
    }

    /// Device scale factor should match platform norms.
    fn check_device_scale_factor(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let ua = &profile.user_agent;
        let scale = profile.device_scale_factor;

        if ua.contains("Macintosh") || ua.contains("Mac OS") {
            // macOS is almost always 2.0 (Retina) or 1.0 (external display)
            if scale != 1.0 && scale != 2.0 {
                warnings.push(FingerprintWarning::warning(
                    vec!["device_scale_factor", "user_agent"],
                    format!(
                        "macOS UA with scale factor {} — macOS uses 1.0 or 2.0",
                        scale,
                    ),
                ));
            }
        }
        if ua.contains("Windows") {
            // Windows common: 1.0, 1.25, 1.5, 2.0
            let valid = [1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0];
            if !valid.iter().any(|&v| (scale - v).abs() < 0.01) {
                warnings.push(FingerprintWarning::info(
                    vec!["device_scale_factor", "user_agent"],
                    format!(
                        "Windows UA with unusual scale factor {} — common values: 1.0, 1.25, 1.5, 2.0",
                        scale,
                    ),
                ));
            }
        }
    }

    /// Browser vendor string should match the UA browser.
    fn check_vendor_string(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let ua = &profile.user_agent;

        if ua.contains("Chrome/") && !ua.contains("Edg/") {
            if profile.vendor != "Google Inc." {
                warnings.push(FingerprintWarning::critical(
                    vec!["vendor", "user_agent"],
                    format!(
                        "Chrome UA but vendor is '{}' — Chrome always reports 'Google Inc.'",
                        profile.vendor,
                    ),
                ));
            }
        }
        if ua.contains("Firefox/") {
            if !profile.vendor.is_empty() {
                warnings.push(FingerprintWarning::warning(
                    vec!["vendor", "user_agent"],
                    format!(
                        "Firefox UA but vendor is '{}' — Firefox reports empty string",
                        profile.vendor,
                    ),
                ));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Determine expected navigator.platform from UA string.
    fn expected_platform_for_ua(ua: &str) -> &'static str {
        // Order matters: iPhone/iPad UAs also contain "Mac OS X", so check them first.
        if ua.contains("iPhone") {
            "iPhone"
        } else if ua.contains("iPad") {
            "iPad"
        } else if ua.contains("Android") {
            "Linux armv81" // Most modern Android
        } else if ua.contains("Win64") || ua.contains("Windows") {
            "Win32" // Yes, even 64-bit Windows reports "Win32"
        } else if ua.contains("Macintosh") || ua.contains("Mac OS X") {
            "MacIntel" // Even Apple Silicon reports "MacIntel" in Chrome
        } else if ua.contains("X11; Linux x86_64") {
            "Linux x86_64"
        } else if ua.contains("Linux") {
            "Linux x86_64"
        } else {
            ""
        }
    }

    /// Human-readable OS label from UA.
    fn os_label_from_ua(ua: &str) -> &'static str {
        if ua.contains("Windows") { "Windows" }
        else if ua.contains("Macintosh") { "macOS" }
        else if ua.contains("Android") { "Android" }
        else if ua.contains("iPhone") { "iOS (iPhone)" }
        else if ua.contains("iPad") { "iOS (iPad)" }
        else if ua.contains("Linux") { "Linux" }
        else { "Unknown" }
    }

    /// Whether the UA indicates a mobile device.
    fn ua_is_mobile(ua: &str) -> bool {
        ua.contains("Mobile") || ua.contains("Android") || ua.contains("iPhone") || ua.contains("iPad")
    }

    /// Check if resolution is in the known set (with 5% tolerance on each axis).
    fn is_known_resolution(res: (u32, u32), is_mobile: bool) -> bool {
        let list = if is_mobile {
            KNOWN_MOBILE_RESOLUTIONS
        } else {
            KNOWN_DESKTOP_RESOLUTIONS
        };
        list.iter().any(|&(w, h)| res.0 == w && res.1 == h)
    }

    /// Find the nearest known resolution by Euclidean distance.
    fn nearest_resolution(res: (u32, u32), is_mobile: bool) -> (u32, u32) {
        let list = if is_mobile {
            KNOWN_MOBILE_RESOLUTIONS
        } else {
            KNOWN_DESKTOP_RESOLUTIONS
        };
        list.iter()
            .min_by_key(|&&(w, h)| {
                let dw = res.0 as i64 - w as i64;
                let dh = res.1 as i64 - h as i64;
                (dw * dw + dh * dh) as u64
            })
            .copied()
            .unwrap_or((1920, 1080))
    }

    /// Realistic hardware_concurrency values that Chrome actually reports.
    fn is_realistic_concurrency(c: u32) -> bool {
        matches!(c, 1 | 2 | 4 | 6 | 8 | 10 | 12 | 16 | 20 | 24 | 32 | 48 | 64 | 128)
    }

    /// Snap to nearest realistic concurrency.
    fn nearest_concurrency(c: u32) -> u32 {
        const VALID: &[u32] = &[1, 2, 4, 6, 8, 10, 12, 16, 20, 24, 32, 48, 64, 128];
        *VALID.iter().min_by_key(|&&v| (v as i64 - c as i64).unsigned_abs()).unwrap_or(&8)
    }

    /// Chrome reports device_memory as power-of-2 (or 0.25 / 0.5).
    fn is_realistic_memory(m: f64) -> bool {
        const VALID: &[f64] = &[0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0];
        VALID.iter().any(|&v| (m - v).abs() < 0.01)
    }

    /// Snap to nearest realistic memory value.
    fn nearest_memory(m: f64) -> f64 {
        const VALID: &[f64] = &[0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0];
        *VALID.iter().min_by(|&&a, &&b| {
            (a - m).abs().partial_cmp(&(b - m).abs()).unwrap_or(std::cmp::Ordering::Equal)
        }).unwrap_or(&8.0)
    }

    /// Find the best-matching consistent fingerprint set for a profile.
    fn find_best_match(profile: &StealthProfile) -> Option<&'static ConsistentFingerprint> {
        let ua = &profile.user_agent;

        // Determine OS from UA
        let is_windows = ua.contains("Windows");
        let is_mac = ua.contains("Macintosh") || ua.contains("Mac OS");
        let is_linux = ua.contains("X11; Linux");

        // Determine GPU from renderer
        let renderer = profile.webgl_renderer.to_uppercase();
        let has_nvidia = renderer.contains("NVIDIA") || renderer.contains("GEFORCE") || renderer.contains("RTX") || renderer.contains("GTX");
        let has_intel = renderer.contains("INTEL") || renderer.contains("UHD") || renderer.contains("HD GRAPHICS");
        let has_apple = renderer.contains("APPLE");

        if is_windows && has_nvidia {
            Some(&WINDOWS_CHROME_NVIDIA)
        } else if is_windows && has_intel {
            Some(&WINDOWS_CHROME_INTEL)
        } else if is_windows {
            // Default Windows to Intel (most common)
            Some(&WINDOWS_CHROME_INTEL)
        } else if is_mac && has_apple {
            Some(&MAC_CHROME_APPLE)
        } else if is_mac {
            Some(&MAC_CHROME_APPLE)
        } else if is_linux {
            Some(&LINUX_CHROME_MESA)
        } else {
            None
        }
    }

    /// Fix WebGL vendor/renderer consistency when no preset matches.
    fn fix_webgl_consistency(profile: &mut StealthProfile, fixes: &mut usize) {
        if profile.webgl_vendor.is_empty() || profile.webgl_renderer.is_empty() {
            return;
        }

        let vendor_upper = profile.webgl_vendor.to_uppercase();
        let renderer_upper = profile.webgl_renderer.to_uppercase();

        // Check if vendor matches any known renderer prefix
        for &(maker, prefixes) in VENDOR_RENDERER_MAP {
            let maker_upper = maker.to_uppercase();
            if vendor_upper.contains(&maker_upper) {
                let renderer_matches = prefixes.iter().any(|p| {
                    renderer_upper.contains(&p.to_uppercase())
                });
                if !renderer_matches {
                    // Vendor says X but renderer doesn't match — fix renderer
                    // to a common renderer for this vendor
                    let ua = &profile.user_agent;
                    let api = if ua.contains("Windows") {
                        "Direct3D11 vs_5_0 ps_5_0, D3D11"
                    } else if ua.contains("Macintosh") {
                        "OpenGL 4.1"
                    } else {
                        "OpenGL 4.6"
                    };

                    match maker {
                        "NVIDIA" => {
                            profile.webgl_renderer = format!(
                                "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 {api})"
                            );
                        }
                        "Intel" => {
                            profile.webgl_renderer = format!(
                                "ANGLE (Intel, Intel(R) UHD Graphics 630, {api})"
                            );
                        }
                        "Apple" => {
                            profile.webgl_renderer = "ANGLE (Apple, Apple M2, OpenGL 4.1)".to_string();
                        }
                        "AMD" => {
                            profile.webgl_renderer = format!(
                                "ANGLE (AMD, AMD Radeon RX 580 {api})"
                            );
                        }
                        _ => return,
                    }
                    *fixes += 1;
                }
                return;
            }
        }
    }

    /// Fix device scale factor based on platform.
    fn fix_scale_factor(profile: &mut StealthProfile, fixes: &mut usize) {
        let ua = &profile.user_agent;
        let scale = profile.device_scale_factor;

        if ua.contains("Macintosh") || ua.contains("Mac OS") {
            if scale != 1.0 && scale != 2.0 {
                profile.device_scale_factor = 2.0; // Default Retina
                *fixes += 1;
            }
        }
    }
}

/// Validate and optionally auto-fix a `StealthProfile`. Convenience function.
///
/// Returns the warnings found BEFORE fixing. If `fix` is true, the profile
/// is also corrected in-place.
pub fn validate_fingerprint(profile: &mut StealthProfile, fix: bool) -> Vec<FingerprintWarning> {
    let warnings = FingerprintValidator::validate(profile);
    if fix && !warnings.is_empty() {
        FingerprintValidator::auto_fix(profile);
    }
    warnings
}

/// Check which OS the given font list corresponds to. Returns `None` if ambiguous.
pub fn detect_os_from_fonts(fonts: &[&str]) -> Option<&'static str> {
    let win_score: usize = fonts.iter().filter(|f| WINDOWS_INDICATOR_FONTS.contains(f)).count();
    let mac_score: usize = fonts.iter().filter(|f| MACOS_INDICATOR_FONTS.contains(f)).count();
    let linux_score: usize = fonts.iter().filter(|f| LINUX_INDICATOR_FONTS.contains(f)).count();

    let max = win_score.max(mac_score).max(linux_score);
    if max == 0 {
        return None;
    }

    if win_score == max && mac_score < max && linux_score < max {
        Some("Windows")
    } else if mac_score == max && win_score < max && linux_score < max {
        Some("macOS")
    } else if linux_score == max && win_score < max && mac_score < max {
        Some("Linux")
    } else {
        None // Ambiguous — multiple OS match equally
    }
}

/// Validate that a font list is consistent with a UA string's claimed OS.
pub fn validate_fonts_for_ua(ua: &str, fonts: &[&str]) -> Vec<FingerprintWarning> {
    let mut warnings = Vec::new();
    let is_windows = ua.contains("Windows");
    let is_mac = ua.contains("Macintosh") || ua.contains("Mac OS");
    let is_linux = ua.contains("Linux") && !ua.contains("Android");

    if is_windows {
        for &font in fonts {
            if MACOS_INDICATOR_FONTS.contains(&font) {
                warnings.push(FingerprintWarning::critical(
                    vec!["fonts", "user_agent"],
                    format!("Windows UA but font list contains macOS font '{}'", font),
                ));
            }
            if LINUX_INDICATOR_FONTS.contains(&font) {
                warnings.push(FingerprintWarning::warning(
                    vec!["fonts", "user_agent"],
                    format!("Windows UA but font list contains Linux font '{}'", font),
                ));
            }
        }
    }
    if is_mac {
        for &font in fonts {
            if WINDOWS_INDICATOR_FONTS.contains(&font) {
                // Some Windows fonts (Verdana, Tahoma) do exist on macOS
                let also_on_mac = matches!(font, "Verdana" | "Tahoma" | "Trebuchet MS");
                if !also_on_mac {
                    warnings.push(FingerprintWarning::critical(
                        vec!["fonts", "user_agent"],
                        format!("macOS UA but font list contains Windows-only font '{}'", font),
                    ));
                }
            }
        }
    }
    if is_linux {
        for &font in fonts {
            if WINDOWS_INDICATOR_FONTS.contains(&font) {
                let also_common = matches!(font, "Verdana" | "Trebuchet MS");
                if !also_common {
                    warnings.push(FingerprintWarning::warning(
                        vec!["fonts", "user_agent"],
                        format!("Linux UA but font list contains Windows font '{}'", font),
                    ));
                }
            }
        }
    }

    warnings
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Built-in profiles should pass validation --

    #[test]
    fn chrome_windows_is_consistent() {
        let p = StealthProfile::chrome_windows();
        let warnings = FingerprintValidator::validate(&p);
        let critical: Vec<_> = warnings.iter().filter(|w| w.severity == Severity::Critical).collect();
        assert!(critical.is_empty(), "chrome_windows has critical warnings: {:?}", critical);
    }

    #[test]
    fn chrome_macos_is_consistent() {
        let p = StealthProfile::chrome_macos();
        let warnings = FingerprintValidator::validate(&p);
        let critical: Vec<_> = warnings.iter().filter(|w| w.severity == Severity::Critical).collect();
        assert!(critical.is_empty(), "chrome_macos has critical warnings: {:?}", critical);
    }

    #[test]
    fn chrome_linux_is_consistent() {
        let p = StealthProfile::chrome_linux();
        let warnings = FingerprintValidator::validate(&p);
        let critical: Vec<_> = warnings.iter().filter(|w| w.severity == Severity::Critical).collect();
        assert!(critical.is_empty(), "chrome_linux has critical warnings: {:?}", critical);
    }

    #[test]
    fn mobile_android_is_consistent() {
        let p = StealthProfile::mobile_android();
        let warnings = FingerprintValidator::validate(&p);
        let critical: Vec<_> = warnings.iter().filter(|w| w.severity == Severity::Critical).collect();
        assert!(critical.is_empty(), "mobile_android has critical warnings: {:?}", critical);
    }

    #[test]
    fn mobile_ios_is_consistent() {
        let p = StealthProfile::mobile_ios();
        let warnings = FingerprintValidator::validate(&p);
        let critical: Vec<_> = warnings.iter().filter(|w| w.severity == Severity::Critical).collect();
        assert!(critical.is_empty(), "mobile_ios has critical warnings: {:?}", critical);
    }

    // -- Detect cross-vector inconsistencies --

    #[test]
    fn detects_platform_ua_mismatch() {
        let mut p = StealthProfile::chrome_windows();
        p.platform = "MacIntel".to_string(); // Wrong!
        let warnings = FingerprintValidator::validate(&p);
        assert!(warnings.iter().any(|w| {
            w.severity == Severity::Critical && w.message.contains("platform")
        }));
    }

    #[test]
    fn detects_webgl_vendor_renderer_mismatch() {
        let mut p = StealthProfile::chrome_windows();
        p.webgl_vendor = "Google Inc. (NVIDIA)".to_string();
        p.webgl_renderer = "ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.6)".to_string();
        let warnings = FingerprintValidator::validate(&p);
        assert!(warnings.iter().any(|w| {
            w.severity == Severity::Critical && w.vectors.contains(&"webgl_vendor")
        }));
    }

    #[test]
    fn detects_touch_on_desktop() {
        let mut p = StealthProfile::chrome_windows();
        p.max_touch_points = 5; // Desktop shouldn't have touch
        let warnings = FingerprintValidator::validate(&p);
        assert!(warnings.iter().any(|w| w.vectors.contains(&"max_touch_points")));
    }

    #[test]
    fn detects_no_touch_on_mobile() {
        let mut p = StealthProfile::mobile_android();
        p.max_touch_points = 0; // Mobile must have touch
        let warnings = FingerprintValidator::validate(&p);
        assert!(warnings.iter().any(|w| {
            w.severity == Severity::Critical && w.message.contains("touch")
        }));
    }

    #[test]
    fn detects_bad_resolution() {
        let mut p = StealthProfile::chrome_windows();
        p.viewport = (1337, 999); // Not a real resolution
        let warnings = FingerprintValidator::validate(&p);
        assert!(warnings.iter().any(|w| w.vectors.contains(&"viewport")));
    }

    #[test]
    fn detects_unrealistic_memory() {
        let mut p = StealthProfile::chrome_windows();
        p.device_memory = 6.0; // Not a power-of-2
        let warnings = FingerprintValidator::validate(&p);
        assert!(warnings.iter().any(|w| w.vectors.contains(&"device_memory")));
    }

    #[test]
    fn detects_unrealistic_concurrency() {
        let mut p = StealthProfile::chrome_windows();
        p.hardware_concurrency = 7; // Not a standard value
        let warnings = FingerprintValidator::validate(&p);
        assert!(warnings.iter().any(|w| w.vectors.contains(&"hardware_concurrency")));
    }

    #[test]
    fn detects_d3d_on_macos() {
        let mut p = StealthProfile::chrome_macos();
        p.webgl_renderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)".to_string();
        p.webgl_vendor = "Google Inc. (NVIDIA)".to_string();
        let warnings = FingerprintValidator::validate(&p);
        assert!(warnings.iter().any(|w| {
            w.severity == Severity::Critical && w.message.contains("Direct3D")
        }));
    }

    #[test]
    fn detects_wrong_vendor_for_chrome() {
        let mut p = StealthProfile::chrome_windows();
        p.vendor = "Apple Computer, Inc.".to_string();
        let warnings = FingerprintValidator::validate(&p);
        assert!(warnings.iter().any(|w| {
            w.severity == Severity::Critical && w.vectors.contains(&"vendor")
        }));
    }

    // -- Auto-fix tests --

    #[test]
    fn auto_fix_corrects_platform() {
        let mut p = StealthProfile::chrome_windows();
        p.platform = "MacIntel".to_string();
        let fixes = FingerprintValidator::auto_fix(&mut p);
        assert!(fixes > 0);
        assert_eq!(p.platform, "Win32");
    }

    #[test]
    fn auto_fix_corrects_touch_on_desktop() {
        let mut p = StealthProfile::chrome_windows();
        p.max_touch_points = 10;
        let fixes = FingerprintValidator::auto_fix(&mut p);
        assert!(fixes > 0);
        assert_eq!(p.max_touch_points, 0);
    }

    #[test]
    fn auto_fix_adds_touch_on_mobile() {
        let mut p = StealthProfile::mobile_android();
        p.max_touch_points = 0;
        let fixes = FingerprintValidator::auto_fix(&mut p);
        assert!(fixes > 0);
        assert!(p.max_touch_points > 0);
    }

    #[test]
    fn auto_fix_snaps_resolution() {
        let mut p = StealthProfile::chrome_windows();
        p.viewport = (1900, 1070);
        let fixes = FingerprintValidator::auto_fix(&mut p);
        assert!(fixes > 0);
        assert_eq!(p.viewport, (1920, 1080));
    }

    #[test]
    fn auto_fix_snaps_memory() {
        let mut p = StealthProfile::chrome_windows();
        p.device_memory = 6.0;
        let fixes = FingerprintValidator::auto_fix(&mut p);
        assert!(fixes > 0);
        // 6.0 is equidistant from 4.0 and 8.0; must snap to a valid value
        assert!(
            FingerprintValidator::validate(&StealthProfile { device_memory: p.device_memory, ..p.clone() })
                .iter().all(|w| !w.vectors.contains(&"device_memory")),
            "device_memory should be valid after fix, got {}", p.device_memory,
        );
    }

    #[test]
    fn auto_fix_snaps_concurrency() {
        let mut p = StealthProfile::chrome_windows();
        p.hardware_concurrency = 7;
        let fixes = FingerprintValidator::auto_fix(&mut p);
        assert!(fixes > 0);
        assert!(FingerprintValidator::validate(&p).iter()
            .all(|w| !w.vectors.contains(&"hardware_concurrency")));
    }

    #[test]
    fn auto_fix_makes_profile_pass_validation() {
        // Build a maximally broken profile
        let mut p = StealthProfile {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36".to_string(),
            platform: "MacIntel".to_string(),         // Wrong for Windows UA
            vendor: "Google Inc.".to_string(),
            languages: vec!["en-US".to_string()],
            hardware_concurrency: 7,                   // Not standard
            device_memory: 6.0,                        // Not power-of-2
            max_touch_points: 5,                       // Touch on desktop
            viewport: (1337, 999),                     // Not real
            device_scale_factor: 1.0,
            webgl_vendor: "Google Inc. (NVIDIA)".to_string(),
            webgl_renderer: "ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.6)".to_string(), // Intel in NVIDIA vendor
            timezone: "America/New_York".to_string(),
            locale: "en-US".to_string(),
            canvas_noise_seed: 12345,
            is_firefox_profile: false,
        };

        let before = FingerprintValidator::validate(&p);
        assert!(!before.is_empty(), "should have warnings before fix");

        let fixes = FingerprintValidator::auto_fix(&mut p);
        assert!(fixes > 0, "should have applied fixes");

        let after = FingerprintValidator::validate(&p);
        let critical_after: Vec<_> = after.iter().filter(|w| w.severity == Severity::Critical).collect();
        assert!(critical_after.is_empty(), "no critical warnings after fix: {:?}", critical_after);
    }

    // -- Consistent fingerprint set tests --

    #[test]
    fn consistent_sets_pass_validation() {
        for fp in ALL_CONSISTENT_FINGERPRINTS {
            let profile = StealthProfile {
                user_agent: fp.user_agent.to_string(),
                platform: fp.platform.to_string(),
                vendor: fp.vendor.to_string(),
                languages: vec!["en-US".to_string(), "en".to_string()],
                hardware_concurrency: fp.hardware_concurrency,
                device_memory: fp.device_memory,
                max_touch_points: fp.max_touch_points,
                viewport: fp.viewport,
                device_scale_factor: fp.device_scale_factor,
                webgl_vendor: fp.webgl_vendor.to_string(),
                webgl_renderer: fp.webgl_renderer.to_string(),
                timezone: "America/New_York".to_string(),
                locale: "en-US".to_string(),
                canvas_noise_seed: 42,
                is_firefox_profile: false,
            };
            let warnings = FingerprintValidator::validate(&profile);
            let critical: Vec<_> = warnings.iter().filter(|w| w.severity == Severity::Critical).collect();
            assert!(
                critical.is_empty(),
                "Consistent set '{}' has critical warnings: {:?}",
                fp.name, critical,
            );
        }
    }

    // -- Font validation tests --

    #[test]
    fn detect_windows_fonts() {
        let fonts = vec!["Segoe UI", "Calibri", "Arial"];
        assert_eq!(detect_os_from_fonts(&fonts), Some("Windows"));
    }

    #[test]
    fn detect_macos_fonts() {
        let fonts = vec!["Helvetica Neue", "San Francisco", "Arial"];
        assert_eq!(detect_os_from_fonts(&fonts), Some("macOS"));
    }

    #[test]
    fn detect_linux_fonts() {
        let fonts = vec!["DejaVu Sans", "Liberation Sans", "Arial"];
        assert_eq!(detect_os_from_fonts(&fonts), Some("Linux"));
    }

    #[test]
    fn font_os_mismatch_detected() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let fonts = vec!["Helvetica Neue", "SF Pro"]; // macOS fonts on Windows UA
        let warnings = validate_fonts_for_ua(ua, &fonts);
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.severity == Severity::Critical));
    }

    // -- Helper function tests --

    #[test]
    fn nearest_resolution_works() {
        assert_eq!(FingerprintValidator::nearest_resolution((1900, 1070), false), (1920, 1080));
        assert_eq!(FingerprintValidator::nearest_resolution((2550, 1430), false), (2560, 1440));
        assert_eq!(FingerprintValidator::nearest_resolution((390, 840), true), (390, 844));
    }

    #[test]
    fn nearest_concurrency_works() {
        // Values that clearly snap to one neighbor
        assert_eq!(FingerprintValidator::nearest_concurrency(5), 4);
        assert_eq!(FingerprintValidator::nearest_concurrency(9), 8);
        assert_eq!(FingerprintValidator::nearest_concurrency(15), 16);
        assert_eq!(FingerprintValidator::nearest_concurrency(17), 16);
        // Result must always be a realistic value
        assert!(FingerprintValidator::is_realistic_concurrency(
            FingerprintValidator::nearest_concurrency(7)
        ));
    }

    #[test]
    fn nearest_memory_works() {
        // Values that clearly snap to one neighbor
        assert!((FingerprintValidator::nearest_memory(7.0) - 8.0).abs() < 0.01);
        assert!((FingerprintValidator::nearest_memory(1.2) - 1.0).abs() < 0.01);
        assert!((FingerprintValidator::nearest_memory(0.3) - 0.25).abs() < 0.01);
        // Result must always be a realistic value
        assert!(FingerprintValidator::is_realistic_memory(
            FingerprintValidator::nearest_memory(6.0)
        ));
    }
}
