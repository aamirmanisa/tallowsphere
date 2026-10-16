//! Search engine configuration (search.toml).

use serde::{Deserialize, Serialize};

/// Multi-engine search cascade and API key settings.
///
/// ```toml
/// # search.toml
/// merge_results = true
/// max_results = 20
/// timeout_secs = 10
/// engine_delay_ms = 500
///
/// # Engine cascade order (first success wins, or merge all)
/// engines = ["bing", "brave", "duckduckgo", "yahoo", "google_trends"]
///
/// # Google Custom Search Engine (100 free queries/day)
/// [google_cse]
/// enabled = false
/// api_key = ""
/// cx = ""
///
/// # Profile pool for Google Search (persistent cookies)
/// [profile_pool]
/// enabled = false
/// profiles_dir = ""              # empty = auto (~/.tallow/browser/profiles/)
/// count = 5
/// max_per_profile = 100
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SearchToml {
    /// Merge results from multiple engines (true) or stop at first success (false).
    pub merge_results: bool,
    /// Maximum results to return per engine.
    pub max_results: usize,
    /// Timeout per engine attempt in seconds.
    pub timeout_secs: u64,
    /// Delay between engine attempts in milliseconds.
    pub engine_delay_ms: u64,
    /// Engine cascade order. Valid: "bing", "brave", "duckduckgo", "yahoo",
    /// "google_trends", "google_cse", "google_profile", "startpage".
    pub engines: Vec<String>,
    /// Google CSE settings.
    pub google_cse: GoogleCseToml,
    /// Google profile pool settings.
    pub profile_pool: ProfilePoolToml,
}

impl Default for SearchToml {
    fn default() -> Self {
        Self {
            merge_results: true,
            max_results: 20,
            timeout_secs: 10,
            engine_delay_ms: 500,
            engines: vec![
                "bing".into(),
                "brave".into(),
                "duckduckgo".into(),
                "yahoo".into(),
                "google_trends".into(),
            ],
            google_cse: GoogleCseToml::default(),
            profile_pool: ProfilePoolToml::default(),
        }
    }
}

/// Google Custom Search Engine API settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GoogleCseToml {
    pub enabled: bool,
    pub api_key: String,
    pub cx: String,
}

impl Default for GoogleCseToml {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: String::new(),
            cx: String::new(),
        }
    }
}

/// Profile pool for Google Search with persistent cookies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfilePoolToml {
    pub enabled: bool,
    pub profiles_dir: String,
    pub count: usize,
    pub max_per_profile: u32,
}

impl Default for ProfilePoolToml {
    fn default() -> Self {
        Self {
            enabled: false,
            profiles_dir: String::new(),
            count: 5,
            max_per_profile: 100,
        }
    }
}
