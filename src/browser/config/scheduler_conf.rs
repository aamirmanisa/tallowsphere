//! Scheduler configuration (scheduler.toml).

use serde::{Deserialize, Serialize};

/// Default settings for scheduled browser jobs.
///
/// ```toml
/// # scheduler.toml
/// max_concurrent_jobs = 4
/// default_timeout_secs = 300
/// default_headless = true
/// default_plugins = "balanced"
///
/// [retry]
/// max_retries = 3
/// delay_secs = 60
/// backoff = true                 # Exponential backoff on retry
///
/// [missed]
/// policy = "run_once"            # "skip" | "run_once" | "run_all"
///
/// [persistence]
/// store_path = ""                # empty = auto (~/.tallow/browser/schedule.json)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SchedulerToml {
    /// Max concurrent scheduled jobs.
    pub max_concurrent_jobs: usize,
    /// Default timeout per job in seconds.
    pub default_timeout_secs: u64,
    /// Default headless mode for jobs.
    pub default_headless: bool,
    /// Default plugin preset for jobs.
    pub default_plugins: String,
    /// Job retry settings.
    pub retry: SchedulerRetryToml,
    /// Missed job policy.
    pub missed: MissedPolicyToml,
    /// Storage path.
    pub persistence: SchedulerPersistenceToml,
}

impl Default for SchedulerToml {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 4,
            default_timeout_secs: 300,
            default_headless: true,
            default_plugins: "balanced".into(),
            retry: SchedulerRetryToml::default(),
            missed: MissedPolicyToml::default(),
            persistence: SchedulerPersistenceToml::default(),
        }
    }
}

/// Retry settings for failed scheduled jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SchedulerRetryToml {
    pub max_retries: u32,
    pub delay_secs: u64,
    pub backoff: bool,
}

impl Default for SchedulerRetryToml {
    fn default() -> Self {
        Self {
            max_retries: 3,
            delay_secs: 60,
            backoff: true,
        }
    }
}

/// What to do with missed scheduled jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MissedPolicyToml {
    /// "skip", "run_once", "run_all".
    pub policy: String,
}

impl Default for MissedPolicyToml {
    fn default() -> Self {
        Self {
            policy: "run_once".into(),
        }
    }
}

/// Scheduler persistence settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SchedulerPersistenceToml {
    /// Path to schedule store file. Empty = auto.
    pub store_path: String,
}

impl Default for SchedulerPersistenceToml {
    fn default() -> Self {
        Self {
            store_path: String::new(),
        }
    }
}
