//! Tor integration configuration (tor.toml).

use serde::{Deserialize, Serialize};

/// Tor proxy, circuit rotation, and stream isolation settings.
///
/// ```toml
/// # tor.toml
/// enabled = false
/// instances = 1                  # Number of Tor daemons to run
/// auto_start = false             # Start Tor daemons with browser pool
///
/// [circuit]
/// rotation_secs = 600            # Rotate circuit every N seconds (min: 10)
/// rotation_policy = "periodic"   # "periodic" | "per_request" | "per_batch" | "manual"
/// batch_size = 10                # Requests per circuit (for per_batch)
///
/// [isolation]
/// stream_isolation = true        # Unique SOCKS auth per request
/// isolate_by_domain = false      # One circuit per target domain
///
/// [ports]
/// socks_base = 9050              # First SOCKS port (increments by 2)
/// control_base = 9051            # First control port (increments by 2)
///
/// [fingerprint]
/// use_tor_profile = true         # Use Tor Browser fingerprint (Firefox UA, 1000x900)
/// auto_adjust = true             # Detect Tor proxy and adjust stealth profile
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TorToml {
    /// Enable Tor routing for browser traffic.
    pub enabled: bool,
    /// Number of Tor daemon instances to manage.
    pub instances: usize,
    /// Automatically start Tor daemons with browser pool.
    pub auto_start: bool,
    /// Circuit rotation settings.
    pub circuit: CircuitToml,
    /// Stream isolation settings.
    pub isolation: IsolationToml,
    /// Port configuration.
    pub ports: TorPortsToml,
    /// Fingerprint adjustment for Tor.
    pub fingerprint: TorFingerprintToml,
}

impl Default for TorToml {
    fn default() -> Self {
        Self {
            enabled: false,
            instances: 1,
            auto_start: false,
            circuit: CircuitToml::default(),
            isolation: IsolationToml::default(),
            ports: TorPortsToml::default(),
            fingerprint: TorFingerprintToml::default(),
        }
    }
}

/// Tor circuit rotation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CircuitToml {
    /// Seconds between circuit rotations (minimum: 10).
    pub rotation_secs: u64,
    /// Rotation policy: "periodic", "per_request", "per_batch", "manual".
    pub rotation_policy: String,
    /// Requests per circuit (for "per_batch" policy).
    pub batch_size: u32,
}

impl Default for CircuitToml {
    fn default() -> Self {
        Self {
            rotation_secs: 600,
            rotation_policy: "periodic".into(),
            batch_size: 10,
        }
    }
}

/// Stream isolation settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IsolationToml {
    /// Use unique SOCKS auth per request (IsolateSOCKSAuth).
    pub stream_isolation: bool,
    /// Use separate circuits per target domain.
    pub isolate_by_domain: bool,
}

impl Default for IsolationToml {
    fn default() -> Self {
        Self {
            stream_isolation: true,
            isolate_by_domain: false,
        }
    }
}

/// Tor daemon port layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TorPortsToml {
    /// First SOCKS port (subsequent instances: +2 each).
    pub socks_base: u16,
    /// First control port (subsequent instances: +2 each).
    pub control_base: u16,
}

impl Default for TorPortsToml {
    fn default() -> Self {
        Self {
            socks_base: 9050,
            control_base: 9051,
        }
    }
}

/// Tor Browser fingerprint matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TorFingerprintToml {
    /// Use Tor Browser Bundle fingerprint (Firefox ESR UA, 1000x900 viewport, UTC).
    pub use_tor_profile: bool,
    /// Automatically detect socks5://127.0.0.1:905x and adjust stealth.
    pub auto_adjust: bool,
}

impl Default for TorFingerprintToml {
    fn default() -> Self {
        Self {
            use_tor_profile: true,
            auto_adjust: true,
        }
    }
}
