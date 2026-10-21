//! Tor daemon manager — detect system Tor, spawn multiple instances,
//! and manage their lifecycle.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use tallow_net::privacy::tor_control::{AuthMethod, TorControlPort, TorError};

// ---------------------------------------------------------------------------
// TorInstance
// ---------------------------------------------------------------------------

/// A single managed Tor daemon process.
pub struct TorInstance {
    /// OS process ID of the Tor daemon.
    pub pid: u32,
    /// SOCKS5 proxy port this instance listens on.
    pub socks_port: u16,
    /// Control port for issuing commands to this instance.
    pub control_port: u16,
    /// On-disk data directory for this instance.
    pub data_dir: PathBuf,
    /// The child process handle (None for externally-managed / system Tor).
    child: Option<Child>,
    /// Lazily-connected control port client.
    control: Option<TorControlPort>,
}

impl TorInstance {
    /// Returns the SOCKS5 proxy URL for this instance.
    pub fn socks_url(&self) -> String {
        format!("socks5://127.0.0.1:{}", self.socks_port)
    }

    /// Lazily connect to the control port, returning a mutable reference
    /// to the [`TorControlPort`] client.
    ///
    /// Managed instances (spawned by [`TorManager::start`]) authenticate
    /// with the **instance data-dir cookie** — the manager wrote an explicit
    /// `CookieAuthFile` into the instance torrc, so the path is
    /// deterministic. System/external instances keep [`AuthMethod::AutoDetect`].
    pub async fn connect_control(&mut self) -> Result<&mut TorControlPort, TorError> {
        if self.control.is_none() {
            let addr: SocketAddr = ([127, 0, 0, 1], self.control_port).into();
            let mut ctrl = TorControlPort::connect(addr).await?;
            if self.child.is_some() {
                // Audit B2: AutoDetect never probed instance data dirs, so
                // every manager-spawned daemon got 515 and bootstrap failed.
                // The torrc pins CookieAuthFile to our own data dir — use it.
                let cookie = self.data_dir.join("control_auth_cookie");
                ctrl.authenticate(AuthMethod::Cookie(cookie)).await?;
            } else {
                ctrl.authenticate(AuthMethod::AutoDetect).await?;
            }
            self.control = Some(ctrl);
        }
        // SAFETY: we just set it to Some above if it was None.
        Ok(self.control.as_mut().unwrap())
    }
}

impl Drop for TorInstance {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// TorManager
// ---------------------------------------------------------------------------

/// Manages one or more Tor daemon instances.
pub struct TorManager {
    /// Running Tor instances.
    instances: Vec<TorInstance>,
    /// Directory where a managed Tor binary may be installed.
    install_dir: PathBuf,
}

impl TorManager {
    /// Try to connect to a system-wide Tor daemon at `127.0.0.1:9051`.
    ///
    /// Returns `Some(TorInstance)` if a Tor daemon is listening and accepts
    /// authentication, or `None` otherwise.
    pub async fn detect_system_tor() -> Option<TorInstance> {
        let addr: SocketAddr = ([127, 0, 0, 1], 9051).into();
        let mut ctrl = TorControlPort::connect(addr).await.ok()?;
        ctrl.authenticate(AuthMethod::AutoDetect).await.ok()?;

        Some(TorInstance {
            pid: 0, // unknown for system Tor
            socks_port: 9050,
            control_port: 9051,
            data_dir: PathBuf::from("/var/lib/tor"),
            child: None,
            control: Some(ctrl),
        })
    }

    /// Spawn `count` Tor daemon processes with sequential port pairs.
    ///
    /// Instance *i* listens on:
    ///   - SOCKS port  `9050 + i * 2`
    ///   - Control port `9051 + i * 2`
    ///
    /// Each instance gets its own data directory and `torrc`.
    /// The manager waits up to 30 seconds for each instance to bootstrap.
    pub async fn start(count: usize) -> Result<Self, TorError> {
        let tor_bin = find_tor_binary().ok_or(TorError::NotInstalled)?;
        let base_dir = tor_data_dir();

        let mut instances = Vec::with_capacity(count);

        for i in 0..count {
            let socks_port = 9050u16.saturating_add((i as u16) * 2);
            let control_port = 9051u16.saturating_add((i as u16) * 2);
            let data_dir = base_dir.join(format!("instance_{i}"));

            // Ensure the data directory exists.
            std::fs::create_dir_all(&data_dir).map_err(|e| {
                TorError::Io(format!(
                    "cannot create data dir {}: {e}",
                    data_dir.display()
                ))
            })?;

            // Write a minimal torrc. `CookieAuthFile` is pinned to the
            // instance data dir (audit finding B2): the manager's control
            // client authenticates with exactly this cookie, and Tor writes
            // it there on startup — without the explicit line the cookie path
            // is only Tor's implicit default, and AutoDetect-style lookups
            // that never probe the instance dir fail auth with 515.
            let torrc_path = data_dir.join("torrc");
            let torrc_content = render_torrc(socks_port, control_port, &data_dir);
            std::fs::write(&torrc_path, &torrc_content).map_err(|e| {
                TorError::Io(format!(
                    "cannot write torrc {}: {e}",
                    torrc_path.display()
                ))
            })?;

            // Spawn the Tor process.
            let child = Command::new(&tor_bin)
                .arg("-f")
                .arg(&torrc_path)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|e| {
                    TorError::Io(format!("failed to spawn tor: {e}"))
                })?;

            let pid = child.id();

            let mut instance = TorInstance {
                pid,
                socks_port,
                control_port,
                data_dir,
                child: Some(child),
                control: None,
            };

            // Wait up to 30 seconds for the instance to become reachable.
            let deadline =
                tokio::time::Instant::now() + Duration::from_secs(30);
            let mut connected = false;

            while tokio::time::Instant::now() < deadline {
                match instance.connect_control().await {
                    Ok(_) => {
                        connected = true;
                        break;
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }

            if !connected {
                return Err(TorError::ControlPortRefused(format!(
                    "instance {i} (port {control_port}) did not bootstrap within 30s"
                )));
            }

            instances.push(instance);
        }

        Ok(Self {
            instances,
            install_dir: base_dir,
        })
    }

    /// Stop all managed instances and clear the list.
    pub async fn stop(&mut self) {
        // Dropping each instance will kill the child process.
        self.instances.clear();
    }

    /// Immutable view of all running instances.
    pub fn instances(&self) -> &[TorInstance] {
        &self.instances
    }

    /// Mutable access to the instance list.
    pub fn instances_mut(&mut self) -> &mut Vec<TorInstance> {
        &mut self.instances
    }

    /// Number of running instances.
    pub fn count(&self) -> usize {
        self.instances.len()
    }
}

impl Drop for TorManager {
    fn drop(&mut self) {
        // Each TorInstance::drop kills its child process.
        self.instances.clear();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Render the torrc for one managed instance.
///
/// The `CookieAuthFile` line is explicit (not Tor's implicit
/// `<DataDirectory>/control_auth_cookie` default) so the manager's control
/// client can authenticate against the exact path it knows — audit finding
/// B2 fix. Pure so it is unit-testable without spawning a daemon.
fn render_torrc(socks_port: u16, control_port: u16, data_dir: &PathBuf) -> String {
    format!(
        "SocksPort {socks_port}\n\
         ControlPort {control_port}\n\
         DataDirectory {dir}\n\
         CookieAuthentication 1\n\
         CookieAuthFile {cookie}\n",
        dir = data_dir.display(),
        cookie = data_dir.join("control_auth_cookie").display(),
    )
}

/// Locate the `tor` binary on the system.
///
/// Search order:
/// 1. `$PATH` (via `tor --version`)
/// 2. Common installation paths
/// 3. Managed install directory
pub fn find_tor_binary() -> Option<PathBuf> {
    // 1. Check PATH
    if let Ok(output) = Command::new("tor").arg("--version").output() {
        if output.status.success() {
            return Some(PathBuf::from("tor"));
        }
    }

    // 2. Well-known locations
    let candidates: &[&str] = &[
        "/usr/bin/tor",
        "/usr/local/bin/tor",
        "/opt/homebrew/bin/tor",
    ];
    for path in candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    // 3. Managed install directory
    let managed = tor_data_dir().join("bin").join("tor");
    if managed.exists() {
        return Some(managed);
    }

    None
}

/// Platform-appropriate data directory for managed Tor instances.
///
/// - **Windows**: `%LOCALAPPDATA%\tallow\tor`
/// - **macOS**: `~/Library/Application Support/tallow/tor`
/// - **Linux**: `~/.local/share/tallow/tor`
pub fn tor_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local).join("tallow").join("tor");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return home
                .join("Library")
                .join("Application Support")
                .join("tallow")
                .join("tor");
        }
    }

    // Linux / fallback
    if let Some(home) = dirs::home_dir() {
        return home
            .join(".local")
            .join("share")
            .join("tallow")
            .join("tor");
    }

    // Last resort
    PathBuf::from("/tmp/tallow/tor")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_instance_socks_url() {
        let instance = TorInstance {
            pid: 1234,
            socks_port: 9050,
            control_port: 9051,
            data_dir: PathBuf::from("/tmp/tor/0"),
            child: None,
            control: None,
        };
        assert_eq!(instance.socks_url(), "socks5://127.0.0.1:9050");

        let instance2 = TorInstance {
            pid: 5678,
            socks_port: 9060,
            control_port: 9061,
            data_dir: PathBuf::from("/tmp/tor/5"),
            child: None,
            control: None,
        };
        assert_eq!(instance2.socks_url(), "socks5://127.0.0.1:9060");
    }

    #[test]
    fn tor_data_dir_is_not_empty() {
        let dir = tor_data_dir();
        let dir_str = dir.to_string_lossy();
        assert!(
            dir_str.contains("tallow"),
            "data dir should contain 'tallow', got: {dir_str}"
        );
    }

    #[test]
    fn sequential_ports() {
        // Verify the port calculation for 5 instances.
        for i in 0u16..5 {
            let socks = 9050u16 + i * 2;
            let control = 9051u16 + i * 2;
            assert_eq!(socks, 9050 + i * 2);
            assert_eq!(control, 9051 + i * 2);
            // SOCKS port is always even offset from base, control is odd.
            assert_eq!(socks % 2, 0);
            assert_eq!(control % 2, 1);
        }

        // Spot-check specific values
        assert_eq!(9050 + 0 * 2, 9050); // instance 0: socks=9050
        assert_eq!(9051 + 0 * 2, 9051); // instance 0: control=9051
        assert_eq!(9050 + 1 * 2, 9052); // instance 1: socks=9052
        assert_eq!(9051 + 1 * 2, 9053); // instance 1: control=9053
        assert_eq!(9050 + 4 * 2, 9058); // instance 4: socks=9058
        assert_eq!(9051 + 4 * 2, 9059); // instance 4: control=9059
    }

    #[test]
    fn torrc_pins_cookie_auth_file_to_instance_data_dir() {
        // Audit B2 regression: the generated torrc must name the instance
        // cookie explicitly so the manager's control client (which
        // authenticates with AuthMethod::Cookie(data_dir/control_auth_cookie))
        // and any AutoDetect probing can find it. Without this line,
        // manager-spawned daemons failed control auth with 515.
        let data_dir = PathBuf::from("/tmp/tor-test/instance_3");
        let torrc = render_torrc(9056, 9057, &data_dir);

        assert!(
            torrc.contains("CookieAuthentication 1"),
            "torrc must enable cookie auth: {torrc}"
        );
        let want = format!(
            "CookieAuthFile {}",
            data_dir.join("control_auth_cookie").display()
        );
        assert!(
            torrc.contains(&want),
            "torrc must pin CookieAuthFile to the instance data dir ({want}): {torrc}"
        );
        // The cookie path the manager authenticates with must be derivable
        // from the rendered torrc (one source of truth).
        let expected = data_dir.join("control_auth_cookie");
        let rendered_line = torrc
            .lines()
            .find(|l| l.starts_with("CookieAuthFile"))
            .expect("CookieAuthFile line present");
        assert_eq!(
            rendered_line,
            format!("CookieAuthFile {}", expected.display()),
            "rendered CookieAuthFile must equal the instance cookie path"
        );
        // Ports still rendered.
        assert!(torrc.contains("SocksPort 9056"));
        assert!(torrc.contains("ControlPort 9057"));
        assert!(torrc.contains("DataDirectory /tmp/tor-test/instance_3"));
    }
}
