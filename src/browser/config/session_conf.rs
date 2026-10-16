//! Session persistence configuration (session.toml).

use serde::{Deserialize, Serialize};

/// Browser session, cookie, and storage persistence settings.
///
/// ```toml
/// # session.toml
/// persist_cookies = false        # Save/restore cookies between runs
/// persist_local_storage = false  # Save/restore localStorage
/// persist_session_storage = false
/// encrypt_sessions = true        # PQC-encrypt saved sessions
/// session_dir = ""               # empty = auto (~/.tallow/browser/sessions/)
///
/// [cookies]
/// block_third_party = false
/// clear_on_exit = false
/// allowed_domains = []           # empty = allow all
/// blocked_domains = []
///
/// [storage]
/// max_size_mb = 50               # Max localStorage per origin
/// quota_per_origin_mb = 10
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionToml {
    /// Persist cookies between browser sessions.
    pub persist_cookies: bool,
    /// Persist localStorage between sessions.
    pub persist_local_storage: bool,
    /// Persist sessionStorage between sessions.
    pub persist_session_storage: bool,
    /// Encrypt saved sessions with PQC (ML-KEM-768).
    pub encrypt_sessions: bool,
    /// Directory for saved sessions. Empty = auto.
    pub session_dir: String,
    /// Cookie policy settings.
    pub cookies: CookiePolicyToml,
    /// Storage quota settings.
    pub storage: StorageQuotaToml,
}

impl Default for SessionToml {
    fn default() -> Self {
        Self {
            persist_cookies: false,
            persist_local_storage: false,
            persist_session_storage: false,
            encrypt_sessions: true,
            session_dir: String::new(),
            cookies: CookiePolicyToml::default(),
            storage: StorageQuotaToml::default(),
        }
    }
}

/// Cookie acceptance policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CookiePolicyToml {
    /// Block third-party cookies.
    pub block_third_party: bool,
    /// Clear all cookies when browser closes.
    pub clear_on_exit: bool,
    /// Allowlist of domains (empty = allow all).
    pub allowed_domains: Vec<String>,
    /// Blocklist of domains.
    pub blocked_domains: Vec<String>,
}

impl Default for CookiePolicyToml {
    fn default() -> Self {
        Self {
            block_third_party: false,
            clear_on_exit: false,
            allowed_domains: vec![],
            blocked_domains: vec![],
        }
    }
}

/// Storage quota limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageQuotaToml {
    /// Max total localStorage size in MB.
    pub max_size_mb: u32,
    /// Max localStorage per origin in MB.
    pub quota_per_origin_mb: u32,
}

impl Default for StorageQuotaToml {
    fn default() -> Self {
        Self {
            max_size_mb: 50,
            quota_per_origin_mb: 10,
        }
    }
}
