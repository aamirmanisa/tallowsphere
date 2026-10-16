//! Retry and backoff configuration (retry.toml).

use serde::{Deserialize, Serialize};

/// Retry logic and backoff strategy settings.
///
/// ```toml
/// # retry.toml
/// max_retries = 3
/// strategy = "exponential"       # "exponential" | "linear" | "fixed"
///
/// [exponential]
/// initial_ms = 100
/// multiplier = 2.0
/// max_ms = 5000
///
/// [linear]
/// interval_ms = 1000
///
/// [fixed]
/// interval_ms = 2000
///
/// [robots]
/// respect = true                 # Obey robots.txt by default
/// policy = "permissive"          # "permissive" (allow if missing) | "strict" (block if missing)
/// user_agent = "TallowBot/0.4"
/// cache_ttl_secs = 3600
///
/// [rate_limit]
/// enabled = true
/// default_rps = 2.0              # Default requests per second
/// respect_crawl_delay = true     # Use Crawl-delay from robots.txt
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryToml {
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Backoff strategy: "exponential", "linear", "fixed".
    pub strategy: String,
    /// Exponential backoff parameters.
    pub exponential: ExponentialBackoffToml,
    /// Linear backoff parameters.
    pub linear: LinearBackoffToml,
    /// Fixed backoff parameters.
    pub fixed: FixedBackoffToml,
    /// robots.txt compliance settings.
    pub robots: RobotsToml,
    /// Rate limiting settings.
    pub rate_limit: RateLimitToml,
}

impl Default for RetryToml {
    fn default() -> Self {
        Self {
            max_retries: 3,
            strategy: "exponential".into(),
            exponential: ExponentialBackoffToml::default(),
            linear: LinearBackoffToml::default(),
            fixed: FixedBackoffToml::default(),
            robots: RobotsToml::default(),
            rate_limit: RateLimitToml::default(),
        }
    }
}

/// Exponential backoff: delay = initial * multiplier^attempt, capped at max.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExponentialBackoffToml {
    pub initial_ms: u64,
    pub multiplier: f64,
    pub max_ms: u64,
}

impl Default for ExponentialBackoffToml {
    fn default() -> Self {
        Self {
            initial_ms: 100,
            multiplier: 2.0,
            max_ms: 5000,
        }
    }
}

/// Linear backoff: constant delay between attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LinearBackoffToml {
    pub interval_ms: u64,
}

impl Default for LinearBackoffToml {
    fn default() -> Self {
        Self { interval_ms: 1000 }
    }
}

/// Fixed backoff: same as linear but with explicit name.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FixedBackoffToml {
    pub interval_ms: u64,
}

impl Default for FixedBackoffToml {
    fn default() -> Self {
        Self { interval_ms: 2000 }
    }
}

/// robots.txt compliance settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RobotsToml {
    /// Respect robots.txt rules.
    pub respect: bool,
    /// Policy when robots.txt is missing: "permissive" or "strict".
    pub policy: String,
    /// User-Agent sent in robots.txt requests.
    pub user_agent: String,
    /// Cache TTL for parsed robots.txt files in seconds.
    pub cache_ttl_secs: u64,
}

impl Default for RobotsToml {
    fn default() -> Self {
        Self {
            respect: true,
            policy: "permissive".into(),
            user_agent: "TallowBot/0.4".into(),
            cache_ttl_secs: 3600,
        }
    }
}

/// Rate limiting settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitToml {
    /// Enable rate limiting.
    pub enabled: bool,
    /// Default requests per second.
    pub default_rps: f64,
    /// Honor Crawl-delay directives from robots.txt.
    pub respect_crawl_delay: bool,
}

impl Default for RateLimitToml {
    fn default() -> Self {
        Self {
            enabled: true,
            default_rps: 2.0,
            respect_crawl_delay: true,
        }
    }
}

impl RetryToml {
    /// Convert to runtime `RetryConfig`.
    pub fn to_retry_config(&self) -> crate::browser::retry::RetryConfig {
        let backoff = match self.strategy.as_str() {
            "linear" => crate::browser::retry::BackoffStrategy::Linear {
                interval_ms: self.linear.interval_ms,
            },
            "fixed" => crate::browser::retry::BackoffStrategy::Fixed {
                interval_ms: self.fixed.interval_ms,
            },
            _ => crate::browser::retry::BackoffStrategy::Exponential {
                initial_ms: self.exponential.initial_ms,
                multiplier: self.exponential.multiplier,
                max_ms: self.exponential.max_ms,
            },
        };
        crate::browser::retry::RetryConfig {
            max_retries: self.max_retries,
            backoff,
        }
    }
}
