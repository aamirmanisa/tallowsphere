//! Comprehensive browser configuration system.
//!
//! All settings are stored as TOML files in `~/.tallow/browser/config/`
//! (or `%LOCALAPPDATA%\tallow\browser\config\` on Windows).
//!
//! Each config domain has its own file:
//! - `browser.toml` — Chrome launch, transport, performance
//! - `plugins.toml` — 10 plugin toggles (adblock, tracker, etc.)
//! - `stealth.toml` — Anti-detection profiles + 20 evasion vectors
//! - `privacy.toml` — PII scanning, redaction, retention
//! - `network.toml` — Request interception, HAR, WebSocket
//! - `recording.toml` — Video capture (codec, resolution, fps)
//! - `search.toml` — Engine cascade, CSE keys, profile pool
//! - `emulation.toml` — Device profiles, viewport, timezone, geo
//! - `accessibility.toml` — WCAG level, consent banners
//! - `session.toml` — Cookie/storage persistence, encryption
//! - `captcha.toml` — Solver backend, API keys, type support
//! - `pool.toml` — Browser pool size, proxies, distributed mode
//! - `tor.toml` — Circuit rotation, stream isolation, ports
//! - `scheduler.toml` — Job scheduling defaults, missed policy
//! - `retry.toml` — Backoff strategy, robots.txt, rate limiting
//!
//! # Usage
//! ```no_run
//! use tallow::browser::config::BrowserFullConfig;
//!
//! let config = BrowserFullConfig::load();
//! let browser_config = config.browser.to_browser_config();
//! let plugins = config.plugins.to_browser_plugins();
//! let stealth = config.stealth.to_stealth_profile();
//! ```

pub mod loader;
pub mod browser_conf;
pub mod plugins_conf;
pub mod stealth_conf;
pub mod privacy_conf;
pub mod network_conf;
pub mod recording_conf;
pub mod search_conf;
pub mod emulation_conf;
pub mod accessibility_conf;
pub mod session_conf;
pub mod captcha_conf;
pub mod pool_conf;
pub mod tor_conf;
pub mod scheduler_conf;
pub mod retry_conf;

pub use browser_conf::BrowserToml;
pub use plugins_conf::PluginsToml;
pub use stealth_conf::{StealthToml, StealthEvasions, CustomStealthProfile};
pub use privacy_conf::{PrivacyToml, PiiTypeToggles, RedactionStyle};
pub use network_conf::{NetworkToml, BlockedResources, InterceptRuleToml};
pub use recording_conf::RecordingToml;
pub use search_conf::{SearchToml, GoogleCseToml, ProfilePoolToml};
pub use emulation_conf::{EmulationToml, ViewportToml, LocaleToml, GeolocationToml, TouchToml};
pub use accessibility_conf::{AccessibilityToml, ConsentToml};
pub use session_conf::{SessionToml, CookiePolicyToml, StorageQuotaToml};
pub use captcha_conf::{CaptchaToml, CaptchaSolverToml, CaptchaTypesToml};
pub use pool_conf::{PoolToml, DistributedPoolToml};
pub use tor_conf::{TorToml, CircuitToml, IsolationToml, TorPortsToml, TorFingerprintToml};
pub use scheduler_conf::{SchedulerToml, SchedulerRetryToml, MissedPolicyToml};
pub use retry_conf::{RetryToml, RobotsToml, RateLimitToml};

use std::path::PathBuf;

/// Complete browser configuration, loaded from `~/.tallow/browser/config/`.
///
/// Each field corresponds to a separate TOML file. Missing files fall back
/// to sensible defaults. Partial files work — only specify what you want
/// to override (all fields have `#[serde(default)]`).
#[derive(Debug, Clone)]
pub struct BrowserFullConfig {
    pub browser: BrowserToml,
    pub plugins: PluginsToml,
    pub stealth: StealthToml,
    pub privacy: PrivacyToml,
    pub network: NetworkToml,
    pub recording: RecordingToml,
    pub search: SearchToml,
    pub emulation: EmulationToml,
    pub accessibility: AccessibilityToml,
    pub session: SessionToml,
    pub captcha: CaptchaToml,
    pub pool: PoolToml,
    pub tor: TorToml,
    pub scheduler: SchedulerToml,
    pub retry: RetryToml,
}

impl Default for BrowserFullConfig {
    fn default() -> Self {
        Self {
            browser: BrowserToml::default(),
            plugins: PluginsToml::default(),
            stealth: StealthToml::default(),
            privacy: PrivacyToml::default(),
            network: NetworkToml::default(),
            recording: RecordingToml::default(),
            search: SearchToml::default(),
            emulation: EmulationToml::default(),
            accessibility: AccessibilityToml::default(),
            session: SessionToml::default(),
            captcha: CaptchaToml::default(),
            pool: PoolToml::default(),
            tor: TorToml::default(),
            scheduler: SchedulerToml::default(),
            retry: RetryToml::default(),
        }
    }
}

impl BrowserFullConfig {
    /// Resolve the config directory path.
    pub fn config_dir() -> PathBuf {
        loader::config_dir()
    }

    /// Convert the full TOML-based config into the `BrowserConfig` struct used
    /// by `BrowserProcess::launch()`.
    ///
    /// This bridges the gap between the on-disk config system (`~/.tallow/browser/config/*.toml`)
    /// and the runtime launch config. It reads from `browser.toml` as the primary source,
    /// then overlays relevant settings from `emulation.toml`, `stealth.toml`, and `pool.toml`.
    ///
    /// # Field mapping
    /// - `browser.chrome_path` -> `BrowserConfig.chrome_path` ("auto" = detect)
    /// - `browser.headless` -> `BrowserConfig.headless`
    /// - `browser.port` -> `BrowserConfig.port` (0 = None/auto)
    /// - `browser.timeout_secs` -> `BrowserConfig.timeout`
    /// - `browser.stealth` -> `BrowserConfig.stealth`
    /// - `browser.proxy` -> `BrowserConfig.proxy` (empty = None)
    /// - `browser.use_pipe` -> `BrowserConfig.use_pipe`
    /// - `browser.user_data_dir` -> `BrowserConfig.user_data_dir` (empty = None)
    /// - `browser.performance` -> extra args via `BrowserConfig::performance_flags()` / `max_performance_flags()`
    /// - `browser.extra_args` -> appended to `BrowserConfig.args`
    /// - `emulation.viewport` -> `--window-size=WxH` arg if non-zero
    /// - `stealth.user_agent` (from profile) -> `--user-agent=...` arg if non-empty
    /// - `pool.proxy` override -> `BrowserConfig.proxy` if browser.proxy is empty
    pub fn to_launch_config(&self) -> crate::browser::process::BrowserConfig {
        use crate::browser::process::BrowserConfig;

        // Start from browser.toml conversion (handles chrome_path, headless, etc.)
        let mut config = self.browser.to_browser_config();

        // --- Performance preset: inject Chrome flags ---
        match self.browser.performance.as_str() {
            "fast" => {
                let perf_flags = BrowserConfig::performance_flags();
                for flag in perf_flags {
                    if !config.args.contains(&flag) {
                        config.args.push(flag);
                    }
                }
            }
            "max" => {
                let max_flags = BrowserConfig::max_performance_flags();
                for flag in max_flags {
                    if !config.args.contains(&flag) {
                        config.args.push(flag);
                    }
                }
            }
            _ => {} // "normal" — no extra performance flags
        }

        // --- Emulation: viewport as --window-size ---
        let vp = &self.emulation.viewport;
        if vp.width > 0 && vp.height > 0 {
            let window_size = format!("--window-size={},{}", vp.width, vp.height);
            if !config.args.iter().any(|a| a.starts_with("--window-size=")) {
                config.args.push(window_size);
            }
        }

        // --- Stealth: inject user-agent from stealth profile ---
        let stealth_profile = self.stealth.to_stealth_profile();
        if !stealth_profile.user_agent.is_empty() {
            let ua_flag = format!("--user-agent={}", stealth_profile.user_agent);
            if !config.args.iter().any(|a| a.starts_with("--user-agent=")) {
                config.args.push(ua_flag);
            }
        }

        // --- Pool proxy fallback: if browser.proxy is empty, use first pool proxy ---
        if config.proxy.is_none() {
            if let Some(first_proxy) = self.pool.proxies.first() {
                if !first_proxy.is_empty() {
                    config.proxy = Some(first_proxy.clone());
                }
            }
        }

        config
    }

    /// Load all config files from the config directory.
    /// Missing files fall back to defaults.
    pub fn load() -> Self {
        let dir = Self::config_dir();
        Self {
            browser: loader::load_toml(&dir.join("browser.toml")),
            plugins: loader::load_toml(&dir.join("plugins.toml")),
            stealth: loader::load_toml(&dir.join("stealth.toml")),
            privacy: loader::load_toml(&dir.join("privacy.toml")),
            network: loader::load_toml(&dir.join("network.toml")),
            recording: loader::load_toml(&dir.join("recording.toml")),
            search: loader::load_toml(&dir.join("search.toml")),
            emulation: loader::load_toml(&dir.join("emulation.toml")),
            accessibility: loader::load_toml(&dir.join("accessibility.toml")),
            session: loader::load_toml(&dir.join("session.toml")),
            captcha: loader::load_toml(&dir.join("captcha.toml")),
            pool: loader::load_toml(&dir.join("pool.toml")),
            tor: loader::load_toml(&dir.join("tor.toml")),
            scheduler: loader::load_toml(&dir.join("scheduler.toml")),
            retry: loader::load_toml(&dir.join("retry.toml")),
        }
    }

    /// Write all default config files to the config directory.
    /// Creates the directory if it doesn't exist.
    pub fn save_defaults() -> std::io::Result<()> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)?;

        let defaults = Self::default();
        loader::save_toml(&dir.join("browser.toml"), &defaults.browser)?;
        loader::save_toml(&dir.join("plugins.toml"), &defaults.plugins)?;
        loader::save_toml(&dir.join("stealth.toml"), &defaults.stealth)?;
        loader::save_toml(&dir.join("privacy.toml"), &defaults.privacy)?;
        loader::save_toml(&dir.join("network.toml"), &defaults.network)?;
        loader::save_toml(&dir.join("recording.toml"), &defaults.recording)?;
        loader::save_toml(&dir.join("search.toml"), &defaults.search)?;
        loader::save_toml(&dir.join("emulation.toml"), &defaults.emulation)?;
        loader::save_toml(&dir.join("accessibility.toml"), &defaults.accessibility)?;
        loader::save_toml(&dir.join("session.toml"), &defaults.session)?;
        loader::save_toml(&dir.join("captcha.toml"), &defaults.captcha)?;
        loader::save_toml(&dir.join("pool.toml"), &defaults.pool)?;
        loader::save_toml(&dir.join("tor.toml"), &defaults.tor)?;
        loader::save_toml(&dir.join("scheduler.toml"), &defaults.scheduler)?;
        loader::save_toml(&dir.join("retry.toml"), &defaults.retry)?;

        Ok(())
    }

    /// Save a single default config file (by name without .toml extension).
    pub fn save_default_file(name: &str) -> std::io::Result<()> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)?;
        let defaults = Self::default();

        match name {
            "browser" => loader::save_toml(&dir.join("browser.toml"), &defaults.browser),
            "plugins" => loader::save_toml(&dir.join("plugins.toml"), &defaults.plugins),
            "stealth" => loader::save_toml(&dir.join("stealth.toml"), &defaults.stealth),
            "privacy" => loader::save_toml(&dir.join("privacy.toml"), &defaults.privacy),
            "network" => loader::save_toml(&dir.join("network.toml"), &defaults.network),
            "recording" => loader::save_toml(&dir.join("recording.toml"), &defaults.recording),
            "search" => loader::save_toml(&dir.join("search.toml"), &defaults.search),
            "emulation" => loader::save_toml(&dir.join("emulation.toml"), &defaults.emulation),
            "accessibility" => loader::save_toml(&dir.join("accessibility.toml"), &defaults.accessibility),
            "session" => loader::save_toml(&dir.join("session.toml"), &defaults.session),
            "captcha" => loader::save_toml(&dir.join("captcha.toml"), &defaults.captcha),
            "pool" => loader::save_toml(&dir.join("pool.toml"), &defaults.pool),
            "tor" => loader::save_toml(&dir.join("tor.toml"), &defaults.tor),
            "scheduler" => loader::save_toml(&dir.join("scheduler.toml"), &defaults.scheduler),
            "retry" => loader::save_toml(&dir.join("retry.toml"), &defaults.retry),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unknown config file: {name}"),
            )),
        }
    }

    /// Display the config for a specific file (or all files).
    pub fn show(&self, file: Option<&str>) -> String {
        let mut out = String::new();

        let sections: Vec<(&str, String)> = vec![
            ("browser", toml::to_string_pretty(&self.browser).unwrap_or_default()),
            ("plugins", toml::to_string_pretty(&self.plugins).unwrap_or_default()),
            ("stealth", toml::to_string_pretty(&self.stealth).unwrap_or_default()),
            ("privacy", toml::to_string_pretty(&self.privacy).unwrap_or_default()),
            ("network", toml::to_string_pretty(&self.network).unwrap_or_default()),
            ("recording", toml::to_string_pretty(&self.recording).unwrap_or_default()),
            ("search", toml::to_string_pretty(&self.search).unwrap_or_default()),
            ("emulation", toml::to_string_pretty(&self.emulation).unwrap_or_default()),
            ("accessibility", toml::to_string_pretty(&self.accessibility).unwrap_or_default()),
            ("session", toml::to_string_pretty(&self.session).unwrap_or_default()),
            ("captcha", toml::to_string_pretty(&self.captcha).unwrap_or_default()),
            ("pool", toml::to_string_pretty(&self.pool).unwrap_or_default()),
            ("tor", toml::to_string_pretty(&self.tor).unwrap_or_default()),
            ("scheduler", toml::to_string_pretty(&self.scheduler).unwrap_or_default()),
            ("retry", toml::to_string_pretty(&self.retry).unwrap_or_default()),
        ];

        for (name, content) in &sections {
            if let Some(filter) = file {
                if *name != filter {
                    continue;
                }
            }
            out.push_str(&format!("# ═══ {name}.toml ═══\n"));
            out.push_str(content);
            out.push('\n');
        }

        if out.is_empty() {
            if let Some(f) = file {
                out = format!("Unknown config file: {f}\nAvailable: browser, plugins, stealth, privacy, network, recording, search, emulation, accessibility, session, captcha, pool, tor, scheduler, retry\n");
            }
        }

        out
    }

    /// Set a dotted key in the appropriate config file.
    /// Key format: "file.key" or "file.section.key" (e.g., "plugins.adblock", "tor.circuit.rotation_secs").
    pub fn set_value(key: &str, value: &str) -> Result<(), String> {
        let parts: Vec<&str> = key.splitn(2, '.').collect();
        if parts.len() < 2 {
            return Err(format!(
                "key must be in format 'file.key' (e.g., 'plugins.adblock')\nAvailable files: browser, plugins, stealth, privacy, network, recording, search, emulation, accessibility, session, captcha, pool, tor, scheduler, retry"
            ));
        }

        let file_name = parts[0];
        let inner_key = parts[1];
        let dir = Self::config_dir();
        let path = dir.join(format!("{file_name}.toml"));

        if !loader::CONFIG_FILES.iter().any(|f| f.starts_with(file_name)) {
            return Err(format!(
                "unknown config file: {file_name}\nAvailable: browser, plugins, stealth, privacy, network, recording, search, emulation, accessibility, session, captcha, pool, tor, scheduler, retry"
            ));
        }

        // Create default file if it doesn't exist
        if !path.exists() {
            Self::save_default_file(file_name)
                .map_err(|e| format!("failed to create default config: {e}"))?;
        }

        loader::set_toml_value(&path, inner_key, value)
    }

    /// List all config file names.
    pub fn file_names() -> &'static [&'static str] {
        &[
            "browser", "plugins", "stealth", "privacy", "network",
            "recording", "search", "emulation", "accessibility", "session",
            "captcha", "pool", "tor", "scheduler", "retry",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrip() {
        let config = BrowserFullConfig::default();
        // Verify all sections serialize to TOML
        let output = config.show(None);
        assert!(output.contains("browser.toml"));
        assert!(output.contains("plugins.toml"));
        assert!(output.contains("stealth.toml"));
        assert!(output.contains("tor.toml"));
        assert!(output.contains("retry.toml"));
    }

    #[test]
    fn show_single_file() {
        let config = BrowserFullConfig::default();
        let output = config.show(Some("plugins"));
        assert!(output.contains("plugins.toml"));
        assert!(!output.contains("browser.toml"));
    }

    #[test]
    fn show_unknown_file() {
        let config = BrowserFullConfig::default();
        let output = config.show(Some("nonexistent"));
        assert!(output.contains("Unknown config file"));
    }

    #[test]
    fn plugins_preset_balanced() {
        let toml = PluginsToml::default();
        let plugins = toml.to_browser_plugins();
        assert!(plugins.adblock);
        assert!(plugins.tracker_block);
        assert!(!plugins.noscript);
    }

    #[test]
    fn plugins_preset_max() {
        let toml = PluginsToml { preset: "max".into(), ..Default::default() };
        let plugins = toml.to_browser_plugins();
        assert!(plugins.noscript);
        assert!(plugins.cookie_autoblock);
    }

    #[test]
    fn plugins_preset_none() {
        let toml = PluginsToml { preset: "none".into(), ..Default::default() };
        let plugins = toml.to_browser_plugins();
        assert!(!plugins.adblock);
        assert!(!plugins.tracker_block);
    }

    #[test]
    fn plugins_custom() {
        let toml = PluginsToml {
            preset: "custom".into(),
            adblock: true,
            tracker_block: false,
            noscript: true,
            ..Default::default()
        };
        let plugins = toml.to_browser_plugins();
        assert!(plugins.adblock);
        assert!(!plugins.tracker_block);
        assert!(plugins.noscript);
    }

    #[test]
    fn stealth_profiles() {
        let toml = StealthToml { profile: "chrome_macos".into(), ..Default::default() };
        let profile = toml.to_stealth_profile();
        assert!(profile.user_agent.contains("Macintosh"));

        let toml = StealthToml { profile: "mobile_android".into(), ..Default::default() };
        let profile = toml.to_stealth_profile();
        assert!(profile.user_agent.contains("Android"));
    }

    #[test]
    fn retry_strategies() {
        let toml = RetryToml { strategy: "linear".into(), ..Default::default() };
        let config = toml.to_retry_config();
        assert_eq!(config.max_retries, 3);

        let toml = RetryToml { strategy: "fixed".into(), ..Default::default() };
        let _config = toml.to_retry_config();

        let toml = RetryToml::default();
        let _config = toml.to_retry_config();
    }

    #[test]
    fn browser_config_conversion() {
        let toml = BrowserToml::default();
        let config = toml.to_browser_config();
        assert!(config.headless);
        assert!(config.stealth);
        assert!(config.port.is_none());
        assert!(config.proxy.is_none());
    }

    #[test]
    fn file_names_count() {
        assert_eq!(BrowserFullConfig::file_names().len(), 15);
    }

    #[test]
    fn toml_deserialize_partial() {
        // Partial TOML should fill missing fields from Default
        let partial = r#"
            preset = "max"
            adblock = false
        "#;
        let toml: PluginsToml = toml::from_str(partial).unwrap();
        assert_eq!(toml.preset, "max");
        assert!(!toml.adblock);
        // Missing fields get defaults
        assert!(toml.tracker_block);
        assert!(toml.https_everywhere);
    }

    #[test]
    fn toml_deserialize_empty() {
        let toml: BrowserToml = toml::from_str("").unwrap();
        assert_eq!(toml.chrome_path, "auto");
        assert!(toml.headless);
    }

    #[test]
    fn set_value_validation() {
        let result = BrowserFullConfig::set_value("nope", "true");
        assert!(result.is_err());
    }
}
