//! CAPTCHA solving configuration (captcha.toml).

use serde::{Deserialize, Serialize};

/// CAPTCHA detection and solving backend settings.
///
/// ```toml
/// # captcha.toml
/// auto_detect = true             # Detect CAPTCHAs on page load
/// auto_solve = false             # Automatically submit to solver
/// manual_fallback = true         # Pause for manual solve if auto fails
///
/// [solver]
/// backend = ""                   # "2captcha" | "anti-captcha" | "capsolver"
///                                # "capmonster" | "https://custom-url.com"
///                                # empty = disabled
/// api_key = ""
/// timeout_secs = 120
/// poll_interval_secs = 5
///
/// [supported_types]
/// recaptcha_v2 = true
/// recaptcha_v3 = true
/// hcaptcha = true
/// turnstile = true               # Cloudflare Turnstile
/// aws_waf = true
/// arkose_labs = true
/// datadome = true
/// funcaptcha = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptchaToml {
    /// Automatically detect CAPTCHAs in page DOM.
    pub auto_detect: bool,
    /// Automatically submit detected CAPTCHAs to solver backend.
    pub auto_solve: bool,
    /// If auto-solve fails, pause and wait for manual input.
    pub manual_fallback: bool,
    /// Solver backend settings.
    pub solver: CaptchaSolverToml,
    /// Which CAPTCHA types to handle.
    pub supported_types: CaptchaTypesToml,
}

impl Default for CaptchaToml {
    fn default() -> Self {
        Self {
            auto_detect: true,
            auto_solve: false,
            manual_fallback: true,
            solver: CaptchaSolverToml::default(),
            supported_types: CaptchaTypesToml::default(),
        }
    }
}

/// CAPTCHA solver backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptchaSolverToml {
    /// Backend: "2captcha", "anti-captcha", "capsolver", "capmonster",
    /// or a custom URL. Empty = disabled.
    pub backend: String,
    /// API key for the solver service.
    pub api_key: String,
    /// Max time to wait for a solution in seconds.
    pub timeout_secs: u64,
    /// How often to poll for solution in seconds.
    pub poll_interval_secs: u64,
}

impl Default for CaptchaSolverToml {
    fn default() -> Self {
        Self {
            backend: String::new(),
            api_key: String::new(),
            timeout_secs: 120,
            poll_interval_secs: 5,
        }
    }
}

/// Which CAPTCHA types the system handles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptchaTypesToml {
    pub recaptcha_v2: bool,
    pub recaptcha_v3: bool,
    pub hcaptcha: bool,
    pub turnstile: bool,
    pub aws_waf: bool,
    pub arkose_labs: bool,
    pub datadome: bool,
    pub funcaptcha: bool,
}

impl Default for CaptchaTypesToml {
    fn default() -> Self {
        Self {
            recaptcha_v2: true,
            recaptcha_v3: true,
            hcaptcha: true,
            turnstile: true,
            aws_waf: true,
            arkose_labs: true,
            datadome: true,
            funcaptcha: true,
        }
    }
}
