//! Device emulation configuration (emulation.toml).

use serde::{Deserialize, Serialize};

/// Device emulation, viewport, timezone, locale, and geolocation.
///
/// ```toml
/// # emulation.toml
/// device = ""                    # empty = no device emulation
///                                # "iphone_15_pro", "pixel_8", "ipad_pro", etc.
///                                # Run `tallow browser devices` for full list
///
/// [viewport]
/// width = 0                      # 0 = use device default or browser default
/// height = 0
/// device_scale_factor = 0.0      # 0 = use device default
/// mobile = false
///
/// [locale]
/// timezone = ""                  # IANA timezone (e.g., "America/New_York")
/// language = ""                  # BCP-47 locale (e.g., "en-US")
///
/// [geolocation]
/// enabled = false
/// latitude = 0.0
/// longitude = 0.0
/// accuracy = 100.0
///
/// [touch]
/// enabled = false                # Enable touch events
/// max_touch_points = 0
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmulationToml {
    /// Device profile name from the device registry (163 devices).
    /// Empty = no device emulation.
    pub device: String,
    /// Manual viewport override.
    pub viewport: ViewportToml,
    /// Locale and timezone settings.
    pub locale: LocaleToml,
    /// Geolocation spoofing.
    pub geolocation: GeolocationToml,
    /// Touch emulation.
    pub touch: TouchToml,
}

impl Default for EmulationToml {
    fn default() -> Self {
        Self {
            device: String::new(),
            viewport: ViewportToml::default(),
            locale: LocaleToml::default(),
            geolocation: GeolocationToml::default(),
            touch: TouchToml::default(),
        }
    }
}

/// Manual viewport dimensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ViewportToml {
    /// Width in pixels (0 = default).
    pub width: u32,
    /// Height in pixels (0 = default).
    pub height: u32,
    /// Device pixel ratio (0 = default).
    pub device_scale_factor: f64,
    /// Mobile viewport mode.
    pub mobile: bool,
}

impl Default for ViewportToml {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
            device_scale_factor: 0.0,
            mobile: false,
        }
    }
}

/// Timezone and language locale.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LocaleToml {
    /// IANA timezone ID (e.g., "America/New_York", "Europe/London").
    pub timezone: String,
    /// BCP-47 locale (e.g., "en-US", "de-DE").
    pub language: String,
}

impl Default for LocaleToml {
    fn default() -> Self {
        Self {
            timezone: String::new(),
            language: String::new(),
        }
    }
}

/// GPS geolocation spoofing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeolocationToml {
    pub enabled: bool,
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy: f64,
}

impl Default for GeolocationToml {
    fn default() -> Self {
        Self {
            enabled: false,
            latitude: 0.0,
            longitude: 0.0,
            accuracy: 100.0,
        }
    }
}

/// Touch input emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TouchToml {
    pub enabled: bool,
    pub max_touch_points: u32,
}

impl Default for TouchToml {
    fn default() -> Self {
        Self {
            enabled: false,
            max_touch_points: 0,
        }
    }
}
