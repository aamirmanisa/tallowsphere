//! Stealth and anti-detection configuration (stealth.toml).

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Stealth profile and evasion vector toggles.
///
/// ```toml
/// # stealth.toml
/// profile = "chrome_windows"     # chrome_windows | chrome_macos | chrome_linux
///                                # mobile_android | mobile_ios | tor | custom
/// v1_enabled = true              # Classic stealth scripts
/// v2_enabled = true              # Advanced V2 evasion vectors
/// v3_enabled = true              # Advanced V3 anti-fingerprinting patches
///
/// [evasions]
/// webdriver = true               # Hide navigator.webdriver
/// chrome_runtime = true          # Fake window.chrome
/// plugins_spoof = true           # Spoof navigator.plugins
/// languages = true               # Override navigator.languages
/// canvas = true                  # Add canvas noise
/// webgl = true                   # Spoof WebGL vendor/renderer
/// navigator = true               # Override navigator properties
/// connection = true              # Fake navigator.connection
/// screen_dimensions = true       # Match outerWidth to viewport
/// performance_memory = true      # Spoof performance.memory
/// performance_timing = true      # Add timing noise
/// chrome_extended = true         # Extended window.chrome props
/// permissions = true             # Override Permissions API
/// speech_synthesis = true        # Spoof speechSynthesis.getVoices
/// media_devices = true           # Spoof MediaDevices
/// webrtc = true                  # Prevent WebRTC IP leaks
/// battery = true                 # Spoof Battery API
/// iframe = true                  # Protect iframe contentWindow
/// client_hints = true            # Generate Sec-CH-UA headers
/// timezone = true                # Timezone consistency
/// audio_context = true           # Spoof AudioContext fingerprint
/// webgpu = true                  # Spoof WebGPU adapter strings
/// fonts = true                   # Limit font enumeration
///
/// [custom]
/// user_agent = ""
/// platform = ""
/// vendor = ""
/// languages = ["en-US", "en"]
/// hardware_concurrency = 8
/// device_memory = 8.0
/// max_touch_points = 0
/// viewport_width = 1920
/// viewport_height = 1080
/// device_scale_factor = 1.0
/// webgl_vendor = ""
/// webgl_renderer = ""
/// timezone = ""
/// locale = "en-US"
/// canvas_noise_seed = 0          # canvas/audio noise seed — set a unique
///                                 # non-zero value per deployment/persona;
///                                 # no "random on 0" behavior exists
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StealthToml {
    /// Base profile preset.
    pub profile: String,
    /// Enable V1 stealth scripts (classic evasions).
    pub v1_enabled: bool,
    /// Enable V2 stealth scripts (advanced evasions).
    pub v2_enabled: bool,
    /// Enable V3 stealth scripts (anti-fingerprinting patches).
    pub v3_enabled: bool,
    /// Individual evasion vector toggles.
    pub evasions: StealthEvasions,
    /// Custom profile fields (only used when profile = "custom").
    pub custom: CustomStealthProfile,
}

impl Default for StealthToml {
    fn default() -> Self {
        Self {
            profile: "chrome_windows".into(),
            v1_enabled: true,
            v2_enabled: true,
            v3_enabled: true,
            evasions: StealthEvasions::default(),
            custom: CustomStealthProfile::default(),
        }
    }
}

/// Per-vector evasion toggles. All enabled by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StealthEvasions {
    pub webdriver: bool,
    pub chrome_runtime: bool,
    pub plugins_spoof: bool,
    pub languages: bool,
    pub canvas: bool,
    pub webgl: bool,
    pub navigator: bool,
    // V2 vectors
    pub connection: bool,
    pub screen_dimensions: bool,
    pub performance_memory: bool,
    pub performance_timing: bool,
    pub chrome_extended: bool,
    pub permissions: bool,
    pub speech_synthesis: bool,
    pub media_devices: bool,
    pub webrtc: bool,
    pub battery: bool,
    pub iframe: bool,
    pub client_hints: bool,
    pub timezone: bool,
    // V2 vectors without dedicated toml docs (still default-enabled)
    pub audio_context: bool,
    pub webgpu: bool,
    pub fonts: bool,
}

impl Default for StealthEvasions {
    fn default() -> Self {
        Self {
            webdriver: true,
            chrome_runtime: true,
            plugins_spoof: true,
            languages: true,
            canvas: true,
            webgl: true,
            navigator: true,
            connection: true,
            screen_dimensions: true,
            performance_memory: true,
            performance_timing: true,
            chrome_extended: true,
            permissions: true,
            speech_synthesis: true,
            media_devices: true,
            webrtc: true,
            battery: true,
            iframe: true,
            client_hints: true,
            timezone: true,
            audio_context: true,
            webgpu: true,
            fonts: true,
        }
    }
}

/// Custom stealth profile overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomStealthProfile {
    pub user_agent: String,
    pub platform: String,
    pub vendor: String,
    pub languages: Vec<String>,
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    pub max_touch_points: u32,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub device_scale_factor: f64,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    pub timezone: String,
    pub locale: String,
    pub canvas_noise_seed: u64,
}

impl Default for CustomStealthProfile {
    fn default() -> Self {
        Self {
            user_agent: String::new(),
            platform: "Win32".into(),
            vendor: "Google Inc.".into(),
            languages: vec!["en-US".into(), "en".into()],
            hardware_concurrency: 8,
            device_memory: 8.0,
            max_touch_points: 0,
            viewport_width: 1920,
            viewport_height: 1080,
            device_scale_factor: 1.0,
            webgl_vendor: "Google Inc. (NVIDIA)".into(),
            webgl_renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)".into(),
            timezone: "America/New_York".into(),
            locale: "en-US".into(),
            canvas_noise_seed: 0,
        }
    }
}

/// Process-wide stealth configuration, registered once per process.
///
/// `inject_stealth_scripts` consults this when deciding which evasion vectors
/// to inject, so a `stealth.toml` on disk is honored even by callers that do
/// not explicitly pass a config (e.g. `page.apply_stealth` from `.tl`).
static GLOBAL_STEALTH_CONFIG: OnceLock<StealthToml> = OnceLock::new();

impl StealthToml {
    /// The currently registered process-wide stealth config, if any.
    pub fn global() -> Option<&'static StealthToml> {
        GLOBAL_STEALTH_CONFIG.get()
    }

    /// Register the process-wide stealth config. The first call wins;
    /// subsequent calls return `Err(previous)`.
    ///
    /// Typical usage after loading the on-disk config:
    /// `StealthToml::set_global(crate::browser::config::BrowserFullConfig::load().stealth)`
    /// or just `StealthToml::global_or_load()` (lazy, from disk).
    pub fn set_global(config: StealthToml) -> Result<(), StealthToml> {
        GLOBAL_STEALTH_CONFIG.set(config)
    }

    /// Return the process-wide stealth config, lazily loading it from the
    /// standard config directory (`~/.tallow/browser/config/stealth.toml`)
    /// on first use. A missing or unparseable file falls back to
    /// `StealthToml::default()` (every vector enabled) — identical to the
    /// historical behavior of injecting the full script set.
    pub fn global_or_load() -> &'static StealthToml {
        GLOBAL_STEALTH_CONFIG.get_or_init(|| {
            let dir = super::loader::config_dir();
            super::loader::load_toml(&dir.join("stealth.toml"))
        })
    }

    /// Convert to runtime `StealthProfile`.
    pub fn to_stealth_profile(&self) -> crate::browser::stealth::StealthProfile {
        match self.profile.as_str() {
            "chrome_macos" => crate::browser::stealth::StealthProfile::chrome_macos(),
            "chrome_linux" => crate::browser::stealth::StealthProfile::chrome_linux(),
            "mobile_android" => crate::browser::stealth::StealthProfile::mobile_android(),
            "mobile_ios" => crate::browser::stealth::StealthProfile::mobile_ios(),
            "tor" => crate::browser::tor_stealth::tor_browser_profile(),
            "custom" => {
                let c = &self.custom;
                crate::browser::stealth::StealthProfile {
                    user_agent: if c.user_agent.is_empty() {
                        crate::browser::stealth::StealthProfile::chrome_windows().user_agent
                    } else {
                        c.user_agent.clone()
                    },
                    platform: c.platform.clone(),
                    vendor: c.vendor.clone(),
                    languages: c.languages.clone(),
                    hardware_concurrency: c.hardware_concurrency,
                    device_memory: c.device_memory,
                    max_touch_points: c.max_touch_points,
                    viewport: (c.viewport_width, c.viewport_height),
                    device_scale_factor: c.device_scale_factor,
                    webgl_vendor: c.webgl_vendor.clone(),
                    webgl_renderer: c.webgl_renderer.clone(),
                    timezone: c.timezone.clone(),
                    locale: c.locale.clone(),
                    canvas_noise_seed: c.canvas_noise_seed,
                    // Detect Firefox UA in custom profiles automatically
                    is_firefox_profile: c.user_agent.contains("Firefox/")
                        && !c.user_agent.contains("Chrome/"),
                }
            }
            _ => crate::browser::stealth::StealthProfile::chrome_windows(), // default
        }
    }
}
