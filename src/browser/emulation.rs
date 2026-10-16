//! Environment spoofing via CDP Emulation domain for Tallow browser automation.
//!
//! Provides per-context environment configuration: viewport size, device scale factor,
//! touch emulation, timezone, locale, geolocation, and User-Agent overrides.
//! All functions use CDP Emulation domain commands (except User-Agent which uses
//! Network.setUserAgentOverride).
//!
//! `apply_stealth_profile` applies ALL environment properties from a `StealthProfile`
//! atomically, ensuring cross-correlation consistency for anti-bot evasion.

use serde_json::json;

use super::cdp::CdpClient;
use super::error::BrowserError;
use super::fingerprint_coherence::GeoContext;
use super::stealth::StealthProfile;

// ---------------------------------------------------------------------------
// Device Profile Presets
// ---------------------------------------------------------------------------

/// Common device viewport presets for quick environment configuration.
///
/// Each variant returns `(width, height, device_scale_factor, mobile)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceProfile {
    /// 1920x1080 desktop at 1x scale.
    Desktop1080p,
    /// 2560x1440 desktop at 1x scale.
    Desktop1440p,
    /// iPhone 14 (390x844 at 3x, mobile).
    IPhone14,
    /// iPhone 15 Pro (393x852 at 3x, mobile).
    IPhone15Pro,
    /// Pixel 7 (412x915 at 2.625x, mobile).
    Pixel7,
    /// iPad Pro (1024x1366 at 2x, mobile/tablet).
    IPadPro,
}

impl DeviceProfile {
    /// Returns `(width, height, device_scale_factor, mobile)` for this device preset.
    pub fn viewport(&self) -> (u32, u32, f64, bool) {
        match self {
            DeviceProfile::Desktop1080p => (1920, 1080, 1.0, false),
            DeviceProfile::Desktop1440p => (2560, 1440, 1.0, false),
            DeviceProfile::IPhone14 => (390, 844, 3.0, true),
            DeviceProfile::IPhone15Pro => (393, 852, 3.0, true),
            DeviceProfile::Pixel7 => (412, 915, 2.625, true),
            DeviceProfile::IPadPro => (1024, 1366, 2.0, true),
        }
    }
}

// ---------------------------------------------------------------------------
// Individual Spoofing Functions
// ---------------------------------------------------------------------------

/// Set viewport size and device scale factor via `Emulation.setDeviceMetricsOverride`.
///
/// This is the canonical way to set viewport dimensions in CDP. The `mobile` flag
/// controls whether the meta viewport tag is respected.
pub async fn set_viewport(
    client: &CdpClient,
    session_id: &str,
    width: u32,
    height: u32,
    scale: f64,
    mobile: bool,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session(
            "Emulation.setDeviceMetricsOverride",
            Some(json!({
                "width": width,
                "height": height,
                "deviceScaleFactor": scale,
                "mobile": mobile,
            })),
            session_id,
        )
        .await
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("set_viewport failed: {}", e),
        })?;

    Ok(())
}

/// Enable or disable touch event emulation via `Emulation.setTouchEmulationEnabled`.
///
/// When enabled, the browser synthesizes touch events from mouse input.
/// `max_touch_points` sets `navigator.maxTouchPoints`.
pub async fn set_touch_emulation(
    client: &CdpClient,
    session_id: &str,
    enabled: bool,
    max_touch_points: u32,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session(
            "Emulation.setTouchEmulationEnabled",
            Some(json!({
                "enabled": enabled,
                "maxTouchPoints": max_touch_points,
            })),
            session_id,
        )
        .await
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("set_touch_emulation failed: {}", e),
        })?;

    Ok(())
}

/// Override the browser timezone via `Emulation.setTimezoneOverride`.
///
/// Example timezone IDs: "America/New_York", "Europe/London", "Asia/Tokyo".
pub async fn set_timezone(
    client: &CdpClient,
    session_id: &str,
    timezone_id: &str,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session(
            "Emulation.setTimezoneOverride",
            Some(json!({
                "timezoneId": timezone_id,
            })),
            session_id,
        )
        .await
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("set_timezone failed: {}", e),
        })?;

    Ok(())
}

/// Override the browser locale via `Emulation.setLocaleOverride`.
///
/// Example locale values: "en-US", "de-DE", "ja-JP".
pub async fn set_locale(
    client: &CdpClient,
    session_id: &str,
    locale: &str,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session(
            "Emulation.setLocaleOverride",
            Some(json!({
                "locale": locale,
            })),
            session_id,
        )
        .await
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("set_locale failed: {}", e),
        })?;

    Ok(())
}

/// Override geolocation coordinates via `Emulation.setGeolocationOverride`.
///
/// The CDP command overrides the Geolocation API return values. Note: for the
/// Geolocation API to work, the page origin must have the geolocation permission
/// granted (either via browser settings or `Browser.grantPermissions`).
pub async fn set_geolocation(
    client: &CdpClient,
    session_id: &str,
    latitude: f64,
    longitude: f64,
    accuracy: f64,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session(
            "Emulation.setGeolocationOverride",
            Some(json!({
                "latitude": latitude,
                "longitude": longitude,
                "accuracy": accuracy,
            })),
            session_id,
        )
        .await
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("set_geolocation failed: {}", e),
        })?;

    Ok(())
}

/// Set the HTTP-level User-Agent, platform, and Accept-Language via
/// `Network.setUserAgentOverride`.
///
/// This overrides the User-Agent header in HTTP requests AND `navigator.userAgent`,
/// `navigator.platform`. Note: this is a Network domain command, not Emulation.
pub async fn set_user_agent(
    client: &CdpClient,
    session_id: &str,
    user_agent: &str,
    platform: &str,
    accept_language: &str,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session(
            "Network.setUserAgentOverride",
            Some(json!({
                "userAgent": user_agent,
                "platform": platform,
                "acceptLanguage": accept_language,
            })),
            session_id,
        )
        .await
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("set_user_agent failed: {}", e),
        })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Geo-coherence helpers (session–fingerprint–proxy coherence)
// ---------------------------------------------------------------------------

/// Pick the IANA timezone that matches a network `GeoContext`.
///
/// Prefers the geo-reported timezone (e.g. `America/Chicago` for a Houston IP);
/// falls back to `Etc/UTC` if none is known.
pub fn timezone_for_geo(geo: &GeoContext) -> String {
    if geo.timezone.is_empty() {
        "Etc/UTC".to_string()
    } else {
        geo.timezone.clone()
    }
}

/// Pick a browser locale (BCP-47) that matches a network `GeoContext`.
///
/// Maps the geo's ISO country code to a matching language+region locale so the
/// browser's `navigator.language` co-varies with the IP's country. Falls back to
/// `en-US`.
pub fn locale_for_geo(geo: &GeoContext) -> String {
    match geo.country_code.as_str() {
        "US" => "en-US",
        "GB" => "en-GB",
        "CA" => "en-CA",
        "AU" => "en-AU",
        "DE" => "de-DE",
        "AT" => "de-AT",
        "CH" => "de-CH",
        "FR" => "fr-FR",
        "BE" => "fr-BE",
        "ES" => "es-ES",
        "MX" => "es-MX",
        "AR" => "es-AR",
        "IT" => "it-IT",
        "PT" => "pt-PT",
        "BR" => "pt-BR",
        "NL" => "nl-NL",
        "PL" => "pl-PL",
        "RU" => "ru-RU",
        "UA" => "uk-UA",
        "TR" => "tr-TR",
        "JP" => "ja-JP",
        "KR" => "ko-KR",
        "CN" => "zh-CN",
        "TW" => "zh-TW",
        "HK" => "zh-HK",
        "IN" => "en-IN",
        "SE" => "sv-SE",
        "NO" => "nb-NO",
        "DK" => "da-DK",
        "FI" => "fi-FI",
        "GR" => "el-GR",
        "CZ" => "cs-CZ",
        "HU" => "hu-HU",
        "RO" => "ro-RO",
        _ => "en-US",
    }
    .to_string()
}

/// Configure a browser context coherently from a network `GeoContext`.
///
/// Applies the geo-matching timezone, locale, and geolocation coordinates in a
/// single call, plus an optional User-Agent override. This ensures a session's
/// browser environment always co-varies with its proxy/IP identity (B3 §4
/// timezone↔IP rule) instead of leaking the datacenter/host default.
///
/// This is the entry point called from session binding
/// (`session::bind_session_emulation`) so timezone/locale/IP/UA form one
/// coherent seeded unit.
pub async fn configure_geo_context(
    client: &CdpClient,
    session_id: &str,
    geo: &GeoContext,
    user_agent: Option<&str>,
) -> Result<(), BrowserError> {
    // 1. Timezone from geo.
    set_timezone(client, session_id, &timezone_for_geo(geo)).await?;

    // 2. Locale from geo country.
    set_locale(client, session_id, &locale_for_geo(geo)).await?;

    // 3. Geolocation from geo coordinates (accuracy ~10m is a realistic IP-lookup value).
    set_geolocation(client, session_id, geo.latitude, geo.longitude, 10.0).await?;

    // 4. Optional User-Agent override (with geo-matching Accept-Language).
    if let Some(ua) = user_agent {
        let accept_language = locale_for_geo(geo);
        let platform = if ua.contains("Android") {
            "Linux armv81"
        } else if ua.contains("iPhone") || ua.contains("iPad") {
            "iPhone"
        } else if ua.contains("Windows") {
            "Win32"
        } else if ua.contains("Macintosh") {
            "MacIntel"
        } else if ua.contains("X11") {
            "Linux x86_64"
        } else {
            "Win32"
        };
        set_user_agent(client, session_id, ua, platform, &accept_language).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Atomic Profile Application
// ---------------------------------------------------------------------------

/// Apply ALL environment properties from a `StealthProfile` atomically.
///
/// Configures viewport, touch emulation, timezone, locale, and User-Agent in a
/// single call, ensuring all properties are consistent and won't trigger
/// anti-bot cross-correlation checks.
///
/// Call order:
/// 1. Viewport + device scale factor (mobile based on touch points)
/// 2. Touch emulation (enabled if max_touch_points > 0)
/// 3. Timezone
/// 4. Locale
/// 5. User-Agent with platform and languages
pub async fn apply_stealth_profile(
    client: &CdpClient,
    session_id: &str,
    profile: &StealthProfile,
) -> Result<(), BrowserError> {
    let mobile = profile.max_touch_points > 0;

    // 1. Viewport
    set_viewport(
        client,
        session_id,
        profile.viewport.0,
        profile.viewport.1,
        profile.device_scale_factor,
        mobile,
    )
    .await?;

    // 2. Touch emulation
    set_touch_emulation(client, session_id, mobile, profile.max_touch_points).await?;

    // 3. Timezone
    set_timezone(client, session_id, &profile.timezone).await?;

    // 4. Locale
    set_locale(client, session_id, &profile.locale).await?;

    // 5. User-Agent
    let accept_language = profile.languages.join(", ");
    set_user_agent(
        client,
        session_id,
        &profile.user_agent,
        &profile.platform,
        &accept_language,
    )
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Clear/Reset Functions
// ---------------------------------------------------------------------------

/// Clear geolocation override, reverting to the browser's real location.
pub async fn clear_geolocation(
    client: &CdpClient,
    session_id: &str,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session(
            "Emulation.clearGeolocationOverride",
            None,
            session_id,
        )
        .await
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("clear_geolocation failed: {}", e),
        })?;

    Ok(())
}

/// Clear device metrics override, reverting to the browser's default viewport.
pub async fn clear_device_metrics(
    client: &CdpClient,
    session_id: &str,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session(
            "Emulation.clearDeviceMetricsOverride",
            None,
            session_id,
        )
        .await
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("clear_device_metrics failed: {}", e),
        })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DeviceProfile viewport tests --

    #[test]
    fn device_profile_desktop_1080p() {
        let (w, h, scale, mobile) = DeviceProfile::Desktop1080p.viewport();
        assert_eq!(w, 1920);
        assert_eq!(h, 1080);
        assert_eq!(scale, 1.0);
        assert!(!mobile);
    }

    #[test]
    fn device_profile_desktop_1440p() {
        let (w, h, scale, mobile) = DeviceProfile::Desktop1440p.viewport();
        assert_eq!(w, 2560);
        assert_eq!(h, 1440);
        assert_eq!(scale, 1.0);
        assert!(!mobile);
    }

    #[test]
    fn device_profile_iphone_14() {
        let (w, h, scale, mobile) = DeviceProfile::IPhone14.viewport();
        assert_eq!(w, 390);
        assert_eq!(h, 844);
        assert_eq!(scale, 3.0);
        assert!(mobile);
    }

    #[test]
    fn device_profile_iphone_15_pro() {
        let (w, h, scale, mobile) = DeviceProfile::IPhone15Pro.viewport();
        assert_eq!(w, 393);
        assert_eq!(h, 852);
        assert_eq!(scale, 3.0);
        assert!(mobile);
    }

    #[test]
    fn device_profile_pixel_7() {
        let (w, h, scale, mobile) = DeviceProfile::Pixel7.viewport();
        assert_eq!(w, 412);
        assert_eq!(h, 915);
        assert_eq!(scale, 2.625);
        assert!(mobile);
    }

    #[test]
    fn device_profile_ipad_pro() {
        let (w, h, scale, mobile) = DeviceProfile::IPadPro.viewport();
        assert_eq!(w, 1024);
        assert_eq!(h, 1366);
        assert_eq!(scale, 2.0);
        assert!(mobile);
    }

    #[test]
    fn device_profile_mobile_variants_have_high_scale() {
        let mobile_profiles = [
            DeviceProfile::IPhone14,
            DeviceProfile::IPhone15Pro,
            DeviceProfile::Pixel7,
            DeviceProfile::IPadPro,
        ];
        for profile in &mobile_profiles {
            let (_, _, scale, mobile) = profile.viewport();
            assert!(scale > 1.0, "{:?} should have scale > 1.0", profile);
            assert!(mobile, "{:?} should be mobile", profile);
        }
    }

    #[test]
    fn device_profile_desktop_variants_not_mobile() {
        let desktop_profiles = [DeviceProfile::Desktop1080p, DeviceProfile::Desktop1440p];
        for profile in &desktop_profiles {
            let (_, _, _, mobile) = profile.viewport();
            assert!(!mobile, "{:?} should not be mobile", profile);
        }
    }

    // -- CDP command JSON structure tests --

    #[test]
    fn viewport_command_json_structure() {
        let params = json!({
            "width": 1920u32,
            "height": 1080u32,
            "deviceScaleFactor": 1.0f64,
            "mobile": false,
        });
        assert_eq!(params["width"], 1920);
        assert_eq!(params["height"], 1080);
        assert_eq!(params["deviceScaleFactor"], 1.0);
        assert_eq!(params["mobile"], false);
    }

    #[test]
    fn touch_emulation_command_json_structure() {
        let params = json!({
            "enabled": true,
            "maxTouchPoints": 5u32,
        });
        assert_eq!(params["enabled"], true);
        assert_eq!(params["maxTouchPoints"], 5);
    }

    #[test]
    fn timezone_command_json_structure() {
        let params = json!({
            "timezoneId": "America/New_York",
        });
        assert_eq!(params["timezoneId"], "America/New_York");
    }

    #[test]
    fn locale_command_json_structure() {
        let params = json!({
            "locale": "de-DE",
        });
        assert_eq!(params["locale"], "de-DE");
    }

    #[test]
    fn geolocation_command_json_structure() {
        let params = json!({
            "latitude": 40.7128f64,
            "longitude": -74.0060f64,
            "accuracy": 10.0f64,
        });
        assert!((params["latitude"].as_f64().unwrap() - 40.7128).abs() < 0.001);
        assert!((params["longitude"].as_f64().unwrap() - (-74.0060)).abs() < 0.001);
        assert_eq!(params["accuracy"], 10.0);
    }

    #[test]
    fn user_agent_command_json_structure() {
        let params = json!({
            "userAgent": "Mozilla/5.0 Test",
            "platform": "Win32",
            "acceptLanguage": "en-US, en",
        });
        assert_eq!(params["userAgent"], "Mozilla/5.0 Test");
        assert_eq!(params["platform"], "Win32");
        assert_eq!(params["acceptLanguage"], "en-US, en");
    }

    // -- apply_stealth_profile field usage tests --

    #[test]
    fn apply_stealth_profile_uses_correct_fields() {
        // Verify that a StealthProfile has all the fields that apply_stealth_profile reads
        let profile = StealthProfile::chrome_windows();

        // These are the fields apply_stealth_profile reads:
        let _viewport_w = profile.viewport.0;
        let _viewport_h = profile.viewport.1;
        let _scale = profile.device_scale_factor;
        let mobile = profile.max_touch_points > 0;
        let _touch = profile.max_touch_points;
        let _tz = &profile.timezone;
        let _locale = &profile.locale;
        let _ua = &profile.user_agent;
        let _platform = &profile.platform;
        let _accept_lang = profile.languages.join(", ");

        // Desktop profile: not mobile
        assert!(!mobile);
        assert_eq!(_viewport_w, 1920);
        assert_eq!(_viewport_h, 1080);
    }

    #[test]
    fn apply_stealth_profile_mobile_detection() {
        // Mobile profile: touch points > 0 means mobile = true
        let android = StealthProfile::mobile_android();
        assert!(android.max_touch_points > 0);

        let ios = StealthProfile::mobile_ios();
        assert!(ios.max_touch_points > 0);

        // Desktop profiles: touch points == 0 means mobile = false
        let windows = StealthProfile::chrome_windows();
        assert_eq!(windows.max_touch_points, 0);

        let macos = StealthProfile::chrome_macos();
        assert_eq!(macos.max_touch_points, 0);

        let linux = StealthProfile::chrome_linux();
        assert_eq!(linux.max_touch_points, 0);
    }

    #[test]
    fn apply_stealth_profile_language_join() {
        let profile = StealthProfile::chrome_windows();
        let accept_language = profile.languages.join(", ");
        assert_eq!(accept_language, "en-US, en");
    }

    #[test]
    fn timezone_for_geo_matches_context() {
        let geo = GeoContext::us_residential("Houston", "Texas", "America/Chicago");
        assert_eq!(timezone_for_geo(&geo), "America/Chicago");

        // Empty timezone falls back to UTC.
        let no_tz = GeoContext { timezone: String::new(), ..geo.clone() };
        assert_eq!(timezone_for_geo(&no_tz), "Etc/UTC");
    }

    #[test]
    fn locale_for_geo_matches_country() {
        let us = GeoContext::us_residential("Houston", "Texas", "America/Chicago");
        assert_eq!(locale_for_geo(&us), "en-US");

        let de = GeoContext {
            country_code: "DE".to_string(),
            timezone: "Europe/Berlin".to_string(),
            ..us.clone()
        };
        assert_eq!(locale_for_geo(&de), "de-DE");

        // Unknown country code falls back to en-US.
        let unknown = GeoContext {
            country_code: "ZZ".to_string(),
            ..us.clone()
        };
        assert_eq!(locale_for_geo(&unknown), "en-US");
    }
}
