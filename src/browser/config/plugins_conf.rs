//! Plugin toggle configuration (plugins.toml).

use serde::{Deserialize, Serialize};

/// Per-plugin enable/disable toggles.
///
/// ```toml
/// # plugins.toml
/// preset = "balanced"          # "balanced" | "max" | "none" | "custom"
///
/// # Individual overrides (only used when preset = "custom")
/// adblock = true
/// tracker_block = true
/// https_everywhere = true
/// noscript = false
/// clear_urls = true
/// cookie_autoblock = false
/// fingerprint_protect = true
/// popup_block = true
/// miner_block = true
/// social_block = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginsToml {
    /// Preset mode: "balanced", "max", "none", "custom".
    /// When not "custom", the preset overrides individual toggles.
    pub preset: String,
    /// Block ads (uBlock Origin patterns).
    pub adblock: bool,
    /// Block known tracking domains.
    pub tracker_block: bool,
    /// Force HTTPS on all navigations.
    pub https_everywhere: bool,
    /// Block all JavaScript (breaks many sites).
    pub noscript: bool,
    /// Strip tracking parameters from URLs.
    pub clear_urls: bool,
    /// Auto-block third-party cookies.
    pub cookie_autoblock: bool,
    /// Randomize canvas/navigator fingerprint.
    pub fingerprint_protect: bool,
    /// Block popup windows.
    pub popup_block: bool,
    /// Block cryptocurrency miners.
    pub miner_block: bool,
    /// Block social media widgets/trackers.
    pub social_block: bool,
}

impl Default for PluginsToml {
    fn default() -> Self {
        Self {
            preset: "balanced".into(),
            adblock: true,
            tracker_block: true,
            https_everywhere: true,
            noscript: false,
            clear_urls: true,
            cookie_autoblock: false,
            fingerprint_protect: true,
            popup_block: true,
            miner_block: true,
            social_block: true,
        }
    }
}

impl PluginsToml {
    /// Convert to runtime `BrowserPlugins`.
    pub fn to_browser_plugins(&self) -> crate::browser::plugins::BrowserPlugins {
        match self.preset.as_str() {
            "max" => crate::browser::plugins::BrowserPlugins::max_privacy(),
            "none" => crate::browser::plugins::BrowserPlugins::none(),
            "custom" => crate::browser::plugins::BrowserPlugins {
                adblock: self.adblock,
                tracker_block: self.tracker_block,
                https_everywhere: self.https_everywhere,
                noscript: self.noscript,
                clear_urls: self.clear_urls,
                cookie_autoblock: self.cookie_autoblock,
                fingerprint_protect: self.fingerprint_protect,
                popup_block: self.popup_block,
                miner_block: self.miner_block,
                social_block: self.social_block,
            },
            _ => crate::browser::plugins::BrowserPlugins::default(), // "balanced"
        }
    }
}
