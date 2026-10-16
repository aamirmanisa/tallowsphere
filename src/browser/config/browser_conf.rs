//! Core browser process configuration (browser.toml).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Core browser launch and transport settings.
///
/// ```toml
/// # browser.toml
/// chrome_path = "auto"           # "auto" or explicit path
/// headless = true
/// port = 0                       # 0 = auto-find
/// timeout_secs = 30
/// stealth = true
/// proxy = ""                     # socks5://host:port, http://host:port
/// use_pipe = false               # pipe transport (lower latency)
/// performance = "normal"         # "normal" | "fast" | "max"
/// extra_args = []
/// user_data_dir = ""             # empty = temp dir
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BrowserToml {
    /// Path to Chrome/Chromium. "auto" = detect system install.
    pub chrome_path: String,
    /// Browser engine: "chromium" (default), "camoufox", or "firefox".
    pub engine: String,
    /// Run headless (no visible window).
    pub headless: bool,
    /// Debug port. 0 = auto-find available port.
    pub port: u16,
    /// Browser startup timeout in seconds.
    pub timeout_secs: u64,
    /// Enable stealth flags on launch (--disable-blink-features=AutomationControlled).
    pub stealth: bool,
    /// Proxy URL: socks5://host:port, http://host:port, https://host:port.
    pub proxy: String,
    /// Use pipe transport instead of WebSocket (~1.5x lower latency).
    pub use_pipe: bool,
    /// Performance preset: "normal", "fast", "max".
    pub performance: String,
    /// Additional Chrome CLI arguments.
    pub extra_args: Vec<String>,
    /// Custom user data directory. Empty = use temp dir.
    pub user_data_dir: String,
}

impl Default for BrowserToml {
    fn default() -> Self {
        Self {
            chrome_path: "auto".into(),
            engine: "chromium".into(),
            headless: true,
            port: 0,
            timeout_secs: 30,
            stealth: true,
            proxy: String::new(),
            use_pipe: false,
            performance: "normal".into(),
            extra_args: vec![],
            user_data_dir: String::new(),
        }
    }
}

impl BrowserToml {
    /// Convert to runtime `BrowserConfig`.
    pub fn to_browser_config(&self) -> crate::browser::process::BrowserConfig {
        let backend = crate::browser::process::BrowserBackend::from_name(&self.engine)
            .unwrap_or(crate::browser::process::BrowserBackend::Chromium);
        // Discover the engine's own binary so a Camoufox/Firefox backend never
        // accidentally launches Chrome.
        let chrome_path = if self.chrome_path == "auto" {
            crate::browser::download::find_browser_for_backend(&backend)
                .unwrap_or_else(|| PathBuf::from("chrome"))
        } else {
            PathBuf::from(&self.chrome_path)
        };

        crate::browser::process::BrowserConfig {
            chrome_path,
            headless: self.headless,
            port: if self.port == 0 { None } else { Some(self.port) },
            args: self.extra_args.clone(),
            user_data_dir: if self.user_data_dir.is_empty() {
                None
            } else {
                Some(PathBuf::from(&self.user_data_dir))
            },
            timeout: Duration::from_secs(self.timeout_secs),
            stealth: self.stealth,
            proxy: if self.proxy.is_empty() {
                None
            } else {
                Some(self.proxy.clone())
            },
            proxy_pac: None,
            use_pipe: self.use_pipe,
            backend,
        }
    }
}
