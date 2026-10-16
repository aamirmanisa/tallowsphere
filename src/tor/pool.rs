//! Tor connection pool with circuit rotation policies.
//!
//! [`TorPool`] wraps a [`TorManager`] and provides high-level methods for
//! obtaining fresh Tor circuits, stream-isolated proxy configs, and
//! round-robin instance selection with configurable rotation.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use tallow_net::privacy::socks5::{ProxyAuth, ProxyConfig};
use tallow_net::privacy::tor_control::{AuthMethod, TorControlPort, TorError};

use crate::browser::stealth::StealthProfile;
use crate::browser::tor_stealth::{adjust_stealth_for_tor, tor_browser_profile};

use super::manager::TorManager;

// ---------------------------------------------------------------------------
// RotationPolicy
// ---------------------------------------------------------------------------

/// Determines when the pool requests a new Tor circuit (NEWNYM).
#[derive(Debug, Clone)]
pub enum RotationPolicy {
    /// Signal NEWNYM before every request.
    PerRequest,
    /// Signal NEWNYM every `n` requests.
    PerBatch(u32),
    /// Signal NEWNYM once this duration has elapsed since the last rotation.
    PerDuration(Duration),
    /// User calls [`TorPool::new_circuit`] explicitly.
    Manual,
}

// ---------------------------------------------------------------------------
// TorPool
// ---------------------------------------------------------------------------

/// A pool of Tor instances with automatic circuit rotation.
///
/// The pool round-robins across instances and applies the configured
/// [`RotationPolicy`] to decide when to signal NEWNYM for fresh circuits.
pub struct TorPool {
    manager: Arc<Mutex<TorManager>>,
    rotation: RotationPolicy,
    request_counter: AtomicU64,
    instance_index: AtomicU64,
    /// Time of the last circuit rotation performed by this pool (set at
    /// construction, refreshed after every rotation). Consulted at rotation
    /// check points by [`RotationPolicy::PerDuration`].
    last_rotation: Mutex<Instant>,
}

/// Browser-egress configuration produced by [`TorPool::attach_browser`].
///
/// The `proxy_url` (e.g. `socks5h://<run-id>:<pw>@127.0.0.1:9050`) is directly
/// assignable to `BrowserConfig.proxy`; it carries a **per-launch SOCKS5
/// identity** (RFC 1929) so Tor's `IsolateSOCKSAuth` gives that launch its own
/// circuit (P1 W1-E1: no browser path builds a bare, circuit-sharing URL).
/// `profile` carries the Tor Browser fingerprint to apply to the session so
/// browser TLS/JS/UA match a real Tor Browser.
pub struct TorBrowserEgress {
    /// SOCKS5h proxy URL for `BrowserConfig.proxy` (remote DNS, .onion-capable,
    /// per-launch circuit credentials bound).
    pub proxy_url: String,
    /// Tor Browser stealth fingerprint to apply to the session.
    pub profile: StealthProfile,
}

/// Format a [`ProxyConfig`] as a browser `--proxy-server` URL, embedding the
/// SOCKS5 credentials (RFC 1929) so Tor's `IsolateSOCKSAuth` assigns that
/// stream its own circuit.
///
/// Returns e.g. `socks5://<user>:<pass>@127.0.0.1:9050` when auth is present,
/// or `socks5://127.0.0.1:9050` when not.
pub fn tor_proxy_url(cfg: &ProxyConfig) -> String {
    let addr = cfg.socks5_addr;
    match &cfg.auth {
        Some(a) => format!(
            "socks5://{}:{}@{}:{}",
            a.username,
            a.password,
            addr.ip(),
            addr.port()
        ),
        None => format!("socks5://{}:{}", addr.ip(), addr.port()),
    }
}

impl TorPool {
    /// Start `instances` Tor daemons and wrap them in a pool with the given
    /// rotation policy.
    pub async fn new(instances: usize, rotation: RotationPolicy) -> Result<Self, TorError> {
        let manager = TorManager::start(instances).await?;
        Ok(Self {
            manager: Arc::new(Mutex::new(manager)),
            rotation,
            request_counter: AtomicU64::new(0),
            instance_index: AtomicU64::new(0),
            last_rotation: Mutex::new(Instant::now()),
        })
    }

    /// Attach a Tor instance to browser egress.
    ///
    /// Picks the next round-robin instance, signals NEWNYM so the browser
    /// exits through a fresh circuit, applies the [`tor_browser_profile`]
    /// fingerprint adjustments, and returns a [`TorBrowserEgress`] whose
    /// `proxy_url` (e.g. `socks5h://<run-id>:<pw>@127.0.0.1:9050`) can be
    /// assigned to `BrowserConfig.proxy`.
    ///
    /// **Circuit isolation (P1 W1-E1):** the returned URL binds a fresh
    /// per-launch SOCKS5 identity (RFC 1929), so `IsolateSOCKSAuth` keeps this
    /// launch on its own circuit even if the NEWNYM were ignored, and no two
    /// launches ever share a circuit.
    ///
    /// **Circuit rotation** happens at `BrowserConfig` boundaries: call this
    /// once per browser launch so each launch exits through a different
    /// circuit (NEWNYM). The returned `profile` should be merged into the
    /// session's stealth profile before the browser is spawned.
    pub async fn attach_browser(&self) -> Result<TorBrowserEgress, TorError> {
        // Build + apply the Tor Browser fingerprint profile.
        let mut profile = tor_browser_profile();
        adjust_stealth_for_tor(&mut profile);

        let mut mgr = self.manager.lock().await;
        let n = mgr.count();
        if n == 0 {
            return Err(TorError::Protocol("no tor instances running".into()));
        }
        let idx = (self.instance_index.fetch_add(1, Ordering::Relaxed) % n as u64) as usize;

        // Always request a fresh circuit at the browser boundary (NEWNYM).
        let instance = &mut mgr.instances_mut()[idx];
        let ctrl = instance.connect_control().await?;
        ctrl.signal_newnym().await?;
        let auth = isolation_credentials("browser-launch");
        let proxy_url = format!(
            "socks5h://{}:{}@127.0.0.1:{}",
            auth.username, auth.password, instance.socks_port
        );
        drop(mgr);

        // A rotation happened: reset the PerDuration timer.
        *self.last_rotation.lock().await = Instant::now();

        Ok(TorBrowserEgress { proxy_url, profile })
    }

    /// Obtain a [`ProxyConfig`] for the next Tor instance, applying the
    /// rotation policy to decide whether to request a fresh circuit first.
    ///
    /// Instance selection is round-robin across all running instances.
    pub async fn fresh_circuit(&self) -> Result<ProxyConfig, TorError> {
        let count = self.request_counter.fetch_add(1, Ordering::Relaxed);

        let mut mgr = self.manager.lock().await;
        let n = mgr.count();
        if n == 0 {
            return Err(TorError::Protocol("no tor instances running".into()));
        }

        let idx = (self.instance_index.fetch_add(1, Ordering::Relaxed) % n as u64) as usize;

        // Apply rotation policy at this check point. The time-based decision
        // (PerRequest always; PerDuration once `d` has elapsed) is owned by
        // `should_rotate`; PerBatch is counter-driven and Manual never rotates
        // here.
        let rotate_now = match &self.rotation {
            RotationPolicy::PerRequest | RotationPolicy::PerDuration(_) => should_rotate(
                &self.rotation,
                *self.last_rotation.lock().await,
                Instant::now(),
            ),
            RotationPolicy::PerBatch(batch_size) => {
                *batch_size > 0 && count % (*batch_size as u64) == 0
            }
            RotationPolicy::Manual => false,
        };
        if rotate_now {
            let instance = &mut mgr.instances_mut()[idx];
            let ctrl = instance.connect_control().await?;
            ctrl.signal_newnym().await?;
            // Record the rotation: this resets the PerDuration timer.
            *self.last_rotation.lock().await = Instant::now();
        }

        let socks_port = mgr.instances()[idx].socks_port;
        let socks5_addr: SocketAddr = ([127, 0, 0, 1], socks_port).into();

        Ok(ProxyConfig {
            socks5_addr,
            tor_mode: true,
            auth: Some(isolation_credentials("pool-task")),
        })
    }

    /// Return a [`ProxyConfig`] with unique SOCKS5 authentication credentials
    /// so that Tor's `IsolateSOCKSAuth` gives this stream its own circuit.
    ///
    /// The username is the caller-supplied `stream_id` and the password is a
    /// random hex string, ensuring each call gets an isolated circuit.
    pub async fn isolate(&self, stream_id: &str) -> Result<ProxyConfig, TorError> {
        let mgr = self.manager.lock().await;
        let n = mgr.count();
        if n == 0 {
            return Err(TorError::Protocol("no tor instances running".into()));
        }

        let idx = (self.instance_index.fetch_add(1, Ordering::Relaxed) % n as u64) as usize;
        let socks_port = mgr.instances()[idx].socks_port;
        let socks5_addr: SocketAddr = ([127, 0, 0, 1], socks_port).into();

        Ok(ProxyConfig {
            socks5_addr,
            tor_mode: true,
            auth: Some(ProxyAuth {
                username: stream_id.to_owned(),
                password: rand_hex_16(),
            }),
        })
    }

    /// Signal NEWNYM on **all** running instances, requesting fresh circuits.
    ///
    /// Honest when the pool is empty (after [`TorPool::stop`] or a failed
    /// start): returns an error instead of silently reporting success — a
    /// `Ok(())` here MUST mean a real NEWNYM was signaled on at least one
    /// instance.
    pub async fn new_circuit(&self) -> Result<(), TorError> {
        let mut mgr = self.manager.lock().await;
        let n = mgr.count();
        if n == 0 {
            return Err(TorError::Protocol(
                "no tor instances running — cannot rotate circuits".into(),
            ));
        }
        for i in 0..n {
            let instance = &mut mgr.instances_mut()[i];
            let ctrl = instance.connect_control().await?;
            ctrl.signal_newnym().await?;
        }
        // An explicit rotation also resets the PerDuration timer.
        *self.last_rotation.lock().await = Instant::now();
        Ok(())
    }

    /// Query the exit IP address of a specific Tor instance.
    pub async fn exit_ip(&self, instance_idx: usize) -> Result<IpAddr, TorError> {
        let mut mgr = self.manager.lock().await;
        let instances = mgr.instances_mut();
        if instance_idx >= instances.len() {
            return Err(TorError::Protocol(format!(
                "instance index {instance_idx} out of range (have {})",
                instances.len()
            )));
        }
        let ctrl = instances[instance_idx].connect_control().await?;
        ctrl.get_exit_ip().await
    }

    /// Stop all managed Tor instances.
    pub async fn stop(&self) {
        let mut mgr = self.manager.lock().await;
        mgr.stop().await;
    }
}

// ---------------------------------------------------------------------------
// External-daemon rotation (unified pool surface)
// ---------------------------------------------------------------------------

/// Rotate the circuit of a daemon this pool did **not** spawn (system Tor or
/// any external local instance) by issuing a real `SIGNAL NEWNYM` over its
/// control port.
///
/// This is the single rotation primitive the stdlib `net.TorPool.new_circuit`
/// facade and `net.tor_new_circuit` delegate to, so .tl callers share one
/// rotation API with the native pool regardless of which personality they
/// reached. Authentication uses [`AuthMethod::AutoDetect`] (extended to cover
/// managed-instance data dirs and `/tmp/tor_data`); when no daemon answers or
/// authentication fails, an honest error is returned — rotation is never
/// claimed otherwise.
pub async fn rotate_external_daemon(control_addr: SocketAddr) -> Result<(), TorError> {
    let mut ctrl = TorControlPort::connect(control_addr).await?;
    ctrl.authenticate(AuthMethod::AutoDetect).await?;
    ctrl.signal_newnym().await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Mint a fresh SOCKS5 identity for one browser launch / pool hand-out.
///
/// `stream_id` labels the consumer; both credential halves carry entropy from
/// [`rand_hex_16`]. Tor's `IsolateSOCKSAuth` assigns each distinct credential
/// pair its own circuit, so a bare URL (no credentials) is a shared-circuit
/// footgun — every browser/run path must bind one (P1 W1-E1).
pub fn isolation_credentials(stream_id: &str) -> ProxyAuth {
    ProxyAuth {
        username: format!("{stream_id}-{}", rand_hex_16()),
        password: rand_hex_16(),
    }
}

/// Build a browser-egress proxy URL from a **bare local SOCKS port** (no known
/// [`ProxyConfig`] yet): `socks5h://<iso-creds>@127.0.0.1:<port>`.
///
/// The `tallow browser --tor` CLI path knows only the SOCKS port — this binds
/// a per-invocation Tor circuit (`IsolateSOCKSAuth`) to the browser instead of
/// sharing the box-wide bare-port circuit (P1 W1-E1). Call ONCE per
/// invocation and reuse the URL for the whole session (sticky circuit).
///
/// Precedence caveat: when a launch also carries a PAC
/// (`BrowserConfig::proxy_pac`, the analytics-blocking route), the PAC
/// supersedes this URL in both engines and the PAC's `SOCKS5 host:port`
/// default cannot carry credentials — the run then egresses on the shared
/// circuit. See `docs/operations/egress-tiers.md` ("Browser CLI caveat").
pub fn isolated_proxy_url(stream_id: &str, socks_port: u16) -> String {
    let auth = isolation_credentials(stream_id);
    format!(
        "socks5h://{}:{}@127.0.0.1:{}",
        auth.username, auth.password, socks_port
    )
}

/// Generate a 16-character hex string unique per call **and** per process.
///
/// This is used to produce unique SOCKS auth credentials for stream isolation.
/// It is **not** cryptographically secure — a `(monotonic counter, pid, nanos)`
/// mix, not a CSPRNG; it only needs to never repeat within or across agent runs
/// so Tor assigns a distinct circuit (W1-E1: no shared, no reused circuit).
/// Time alone is insufficient: two launches in the same clock tick (parallel
/// scripts, coarse clocks) would mint identical credentials.
fn rand_hex_16() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    // SplitMix64-style odd multipliers: bijective in `c`, so a counter change
    // always changes the output even when the clock is frozen.
    let mixed = nanos
        ^ c.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ u64::from(std::process::id()).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    format!("{mixed:016x}")
}

/// Pure timing decision for the time-based [`RotationPolicy`] variants: should
/// a fresh circuit (NEWNYM) be requested at `now`, given the last rotation
/// happened at `last`?
///
/// [`RotationPolicy::PerRequest`] rotates at every rotation check point;
/// [`RotationPolicy::PerDuration`] rotates once `d` has elapsed since `last`.
/// [`RotationPolicy::PerBatch`] is driven by the request counter and
/// [`RotationPolicy::Manual`] never rotates automatically, so both report
/// `false` here.
fn should_rotate(policy: &RotationPolicy, last: Instant, now: Instant) -> bool {
    match policy {
        RotationPolicy::PerRequest => true,
        RotationPolicy::PerDuration(d) => now.saturating_duration_since(last) >= *d,
        RotationPolicy::PerBatch(_) | RotationPolicy::Manual => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_policy_constructible() {
        let _a = RotationPolicy::PerRequest;
        let _b = RotationPolicy::PerBatch(10);
        let _c = RotationPolicy::PerDuration(Duration::from_secs(60));
        let _d = RotationPolicy::Manual;
    }

    #[test]
    fn should_rotate_per_duration_rotates_once_elapsed() {
        let t0 = Instant::now();
        let period = Duration::from_secs(60);

        // Not yet due: no rotation.
        assert!(!should_rotate(&RotationPolicy::PerDuration(period), t0, t0));
        assert!(!should_rotate(
            &RotationPolicy::PerDuration(period),
            t0,
            t0 + Duration::from_secs(59)
        ));

        // Due at exactly the period and beyond: rotate.
        assert!(should_rotate(
            &RotationPolicy::PerDuration(period),
            t0,
            t0 + period
        ));
        assert!(should_rotate(
            &RotationPolicy::PerDuration(period),
            t0,
            t0 + Duration::from_secs(3600)
        ));

        // `last` in the future (clock skew) saturates: no spurious rotation.
        assert!(!should_rotate(
            &RotationPolicy::PerDuration(period),
            t0 + Duration::from_secs(5),
            t0
        ));

        // Degenerate zero period rotates at every check point.
        assert!(should_rotate(
            &RotationPolicy::PerDuration(Duration::ZERO),
            t0,
            t0
        ));
    }

    #[test]
    fn should_rotate_keeps_per_request_and_manual_semantics() {
        let t0 = Instant::now();
        let much_later = t0 + Duration::from_secs(86_400);

        // PerRequest rotates at every check point, independent of elapsed time.
        assert!(should_rotate(&RotationPolicy::PerRequest, t0, t0));
        assert!(should_rotate(&RotationPolicy::PerRequest, t0, much_later));

        // PerBatch is counter-driven and Manual is caller-driven: the time
        // check must never claim a rotation for them.
        for now in [t0, much_later] {
            assert!(!should_rotate(&RotationPolicy::PerBatch(10), t0, now));
            assert!(!should_rotate(&RotationPolicy::Manual, t0, now));
        }
    }

    #[test]
    fn rand_hex_16_is_16_chars() {
        let hex = rand_hex_16();
        assert_eq!(hex.len(), 16, "expected 16 hex chars, got {}: {hex}", hex.len());
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "expected all hex digits, got: {hex}"
        );
    }

    #[test]
    fn isolation_credentials_are_unique_per_call() {
        let a = isolation_credentials("launch");
        let b = isolation_credentials("launch");
        assert_ne!(
            (&a.username, &a.password),
            (&b.username, &b.password),
            "each call must mint a distinct identity (its own circuit)"
        );
        assert!(
            a.username.starts_with("launch-"),
            "the stream label must lead the SOCKS username: {}",
            a.username
        );
        assert_eq!(a.password.len(), 16, "passwords are 16 hex chars");
        assert!(
            a.password.chars().all(|c| c.is_ascii_hexdigit()),
            "password must be hex: {}",
            a.password
        );
    }

    #[test]
    fn tor_proxy_url_formats_with_and_without_auth() {
        let no_auth = ProxyConfig {
            socks5_addr: ([127, 0, 0, 1], 9050).into(),
            tor_mode: true,
            auth: None,
        };
        assert_eq!(tor_proxy_url(&no_auth), "socks5://127.0.0.1:9050");

        let with_auth = ProxyConfig {
            socks5_addr: ([127, 0, 0, 1], 9052).into(),
            tor_mode: true,
            auth: Some(ProxyAuth {
                username: "example.com".into(),
                password: "deadbeefdeadbeef".into(),
            }),
        };
        let url = tor_proxy_url(&with_auth);
        assert_eq!(
            url,
            "socks5://example.com:deadbeefdeadbeef@127.0.0.1:9052"
        );
        // The SOCKS username (RFC 1929) must carry the stream/domain id so Tor's
        // IsolateSOCKSAuth assigns a distinct circuit per domain.
        assert!(
            url.starts_with("socks5://example.com:"),
            "domain id must be the SOCKS username in the proxy URL: {url}"
        );
    }

    #[test]
    fn isolated_proxy_url_binds_credentials_per_call() {
        let a = isolated_proxy_url("browser-cli", 9050);
        let b = isolated_proxy_url("browser-cli", 9050);
        assert!(
            a.starts_with("socks5h://browser-cli-"),
            "stream id must label the SOCKS username: {a}"
        );
        assert!(a.contains("@127.0.0.1:9050"), "port must be the given one: {a}");
        assert_ne!(a, b, "each call must mint a fresh isolation identity");
    }
}
