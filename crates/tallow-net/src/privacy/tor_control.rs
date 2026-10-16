//! Tor control port protocol client.
//!
//! Connects to a running Tor daemon's control port and issues commands
//! such as AUTHENTICATE and SIGNAL NEWNYM (circuit rotation).

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// Minimum interval between NEWNYM signals (Tor enforces 10 seconds).
const NEWNYM_MIN_INTERVAL: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by Tor control port operations.
#[derive(Debug)]
pub enum TorError {
    /// Cannot connect to the control port.
    ControlPortRefused(String),
    /// Authentication was rejected by the Tor daemon.
    AuthFailed(String),
    /// SIGNAL NEWNYM was issued too soon after the previous one.
    NewnymTooFast {
        /// Milliseconds the caller should wait before retrying.
        wait_ms: u64,
    },
    /// A new circuit could not be built.
    CircuitBuildFailed,
    /// The Tor daemon process has exited unexpectedly.
    DaemonCrashed {
        /// Process ID of the crashed daemon.
        pid: u32,
    },
    /// The `tor` binary was not found on `$PATH`.
    NotInstalled,
    /// Generic I/O error.
    Io(String),
    /// Unexpected / malformed control-port response.
    Protocol(String),
}

impl fmt::Display for TorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TorError::ControlPortRefused(msg) => {
                write!(f, "tor control port refused: {msg}")
            }
            TorError::AuthFailed(msg) => write!(f, "tor auth failed: {msg}"),
            TorError::NewnymTooFast { wait_ms } => {
                write!(f, "NEWNYM too fast, wait {wait_ms}ms")
            }
            TorError::CircuitBuildFailed => write!(f, "circuit build failed"),
            TorError::DaemonCrashed { pid } => {
                write!(f, "tor daemon crashed (pid {pid})")
            }
            TorError::NotInstalled => write!(f, "tor binary not found"),
            TorError::Io(msg) => write!(f, "tor I/O error: {msg}"),
            TorError::Protocol(msg) => {
                write!(f, "tor protocol error: {msg}")
            }
        }
    }
}

impl std::error::Error for TorError {}

impl From<std::io::Error> for TorError {
    fn from(e: std::io::Error) -> Self {
        TorError::Io(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// How to authenticate with the Tor control port.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// No authentication required (ControlPort has no auth configured).
    None,
    /// Cookie-based authentication — read the cookie file and present it.
    Cookie(PathBuf),
    /// Password (hashed-password) authentication.
    Password(String),
    /// Try well-known cookie paths, then fall back to `None`.
    AutoDetect,
}

/// Ordered candidate control-auth cookie paths probed by
/// [`AuthMethod::AutoDetect`]:
///
/// 1. system Tor conventions (`/var/run/tor`, `/run/tor`, `/var/lib/tor`)
/// 2. the `/tmp/tor_data` manual-daemon layout used by Tallow ops
/// 3. Tallow managed-instance data dirs (`<data_dir>/instance_*/control_auth_cookie`)
///    — a daemon spawned by `TorManager::start` writes its cookie here, and
///    without this candidate every manager-spawned daemon fails control-port
///    auth with a 515 (audit finding B2).
///
/// Pure (no filesystem probing) so it is unit-testable without a daemon.
pub fn autodetect_cookie_candidates() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = vec![
        "/var/run/tor/control.authcookie".into(),
        "/run/tor/control.authcookie".into(),
        "/var/lib/tor/control_auth_cookie".into(),
        "/tmp/tor_data/control_auth_cookie".into(),
    ];
    if let Some(base) = tallow_tor_base_dir() {
        // An external daemon run with the data dir as its DataDirectory.
        out.push(base.join("control_auth_cookie"));
        // Managed instances: `instance_0`, `instance_1`, ...
        if let Ok(entries) = std::fs::read_dir(&base) {
            let mut instances: Vec<_> = entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("instance_"))
                .collect();
            instances.sort_by_key(|e| e.file_name());
            for entry in instances {
                out.push(entry.path().join("control_auth_cookie"));
            }
        }
    }
    out
}

/// Tallow's managed-Tor data-dir root for the current platform
/// (`~/.local/share/tallow/tor` on Linux, the macOS Application Support
/// equivalent, or `%LOCALAPPDATA%\tallow\tor` on Windows).
fn tallow_tor_base_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|d| PathBuf::from(d).join("tallow").join("tor"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME").ok().map(|h| {
            PathBuf::from(h)
                .join("Library")
                .join("Application Support")
                .join("tallow")
                .join("tor")
        })
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::var("HOME").ok().map(|h| {
            PathBuf::from(h)
                .join(".local")
                .join("share")
                .join("tallow")
                .join("tor")
        })
    }
}

/// Information about a single Tor circuit.
#[derive(Debug, Clone)]
pub struct CircuitInfo {
    /// Circuit identifier.
    pub id: u32,
    /// Current status string (e.g. `"BUILT"`, `"EXTENDED"`).
    pub status: String,
    /// Relay fingerprints / nicknames forming the circuit path.
    pub path: Vec<String>,
}

// ---------------------------------------------------------------------------
// TorControlPort
// ---------------------------------------------------------------------------

/// A client for the Tor control-port protocol (spec: `control-spec.txt`).
///
/// All public methods require `&mut self` because the underlying TCP
/// connection is stateful.
pub struct TorControlPort {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
    authenticated: bool,
    last_newnym: Option<Instant>,
}

impl TorControlPort {
    /// Connect to a Tor control port at the given address.
    pub async fn connect(addr: SocketAddr) -> Result<Self, TorError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| TorError::ControlPortRefused(format!("{addr}: {e}")))?;

        let (read_half, write_half) = tokio::io::split(stream);

        Ok(Self {
            reader: BufReader::new(read_half),
            writer: write_half,
            authenticated: false,
            last_newnym: None,
        })
    }

    /// Authenticate with the Tor daemon.
    pub async fn authenticate(&mut self, method: AuthMethod) -> Result<(), TorError> {
        // Resolve AutoDetect into a concrete method first to avoid
        // async recursion (which requires boxing).
        let resolved = match method {
            AuthMethod::AutoDetect => {
                // Probe well-known cookie locations, the `/tmp/tor_data`
                // manual-daemon layout used by Tallow ops, and Tallow's own
                // managed-instance data dirs (`~/.local/share/tallow/tor/
                // instance_*/control_auth_cookie`, etc.). A daemon spawned by
                // `TorManager::start` writes its cookie into its instance
                // data dir — without these candidates every manager-spawned
                // daemon fails control-port auth with a 515 (audit finding B2).
                let mut found = None;
                for path in autodetect_cookie_candidates() {
                    if tokio::fs::metadata(&path).await.is_ok() {
                        found = Some(AuthMethod::Cookie(path));
                        break;
                    }
                }
                found.unwrap_or(AuthMethod::None)
            }
            other => other,
        };

        match resolved {
            AuthMethod::None => {
                self.send_command("AUTHENTICATE\r\n").await?;
            }
            AuthMethod::Cookie(path) => {
                let cookie = tokio::fs::read(&path).await.map_err(|e| {
                    TorError::AuthFailed(format!("cannot read cookie {}: {e}", path.display()))
                })?;
                let hex = hex::encode(&cookie);
                self.send_command(&format!("AUTHENTICATE {hex}\r\n"))
                    .await?;
            }
            AuthMethod::Password(ref pw) => {
                let escaped = pw.replace('\\', "\\\\").replace('"', "\\\"");
                self.send_command(&format!("AUTHENTICATE \"{escaped}\"\r\n"))
                    .await?;
            }
            AuthMethod::AutoDetect => unreachable!(),
        }

        self.expect_ok().await?;
        self.authenticated = true;
        Ok(())
    }

    /// Request a new Tor circuit via `SIGNAL NEWNYM`.
    ///
    /// If fewer than 10 seconds have elapsed since the last NEWNYM, this
    /// method **sleeps** for the remaining time before issuing the signal
    /// (Tor silently ignores rapid NEWNYM requests).
    pub async fn signal_newnym(&mut self) -> Result<(), TorError> {
        if let Some(last) = self.last_newnym {
            let elapsed = last.elapsed();
            if elapsed < NEWNYM_MIN_INTERVAL {
                let remaining = NEWNYM_MIN_INTERVAL - elapsed;
                tokio::time::sleep(remaining).await;
            }
        }

        self.send_command("SIGNAL NEWNYM\r\n").await?;
        self.expect_ok().await?;
        self.last_newnym = Some(Instant::now());
        Ok(())
    }

    /// Issue a `GETINFO` command and return the value string.
    pub async fn get_info(&mut self, key: &str) -> Result<String, TorError> {
        self.send_command(&format!("GETINFO {key}\r\n")).await?;
        let response = self.read_response().await?;

        // Successful GETINFO returns a multi-line reply:
        //   250-{key}={value}
        //   250 OK
        // We extract the value from the first line.
        for line in &response {
            // Match both "250-key=value" and "250+key=value"
            if let Some(rest) = line
                .strip_prefix("250-")
                .or_else(|| line.strip_prefix("250+"))
            {
                if let Some((_k, v)) = rest.split_once('=') {
                    return Ok(v.to_string());
                }
            }
            // Single-line "250 key=value" (some Tor versions)
            if let Some(rest) = line.strip_prefix("250 ") {
                if let Some((_k, v)) = rest.split_once('=') {
                    return Ok(v.to_string());
                }
            }
        }

        Err(TorError::Protocol(format!(
            "no value in GETINFO response: {response:?}"
        )))
    }

    /// Convenience wrapper: retrieve the current exit-node IP address.
    pub async fn get_exit_ip(&mut self) -> Result<IpAddr, TorError> {
        let addr_str = self.get_info("address").await?;
        addr_str
            .parse::<IpAddr>()
            .map_err(|e| TorError::Protocol(format!("invalid IP from Tor: {e}")))
    }

    /// Resolve a hostname through the Tor network via the control-port
    /// `RESOLVE` command — DNS happens at the exit, so there is no local DNS
    /// leak. Returns the first resolved address.
    ///
    /// This is the real, daemon-backed primitive behind the stdlib
    /// `net.tor_resolve` facade (one documented API for .tl callers).
    pub async fn resolve(&mut self, hostname: &str) -> Result<IpAddr, TorError> {
        validate_resolve_hostname(hostname)?;
        self.send_command(&format!("RESOLVE {hostname}\r\n"))
            .await?;
        let response = self.read_response().await?;
        parse_resolve_response(&response)
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Write a raw command string to the control port.
    async fn send_command(&mut self, cmd: &str) -> Result<(), TorError> {
        self.writer
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| TorError::Io(e.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|e| TorError::Io(e.to_string()))?;
        Ok(())
    }

    /// Read a complete (possibly multi-line) control-port response.
    ///
    /// Responses consist of one or more lines:
    ///   - Continuation lines: `{code}-{text}`
    ///   - Final line:         `{code} {text}`
    async fn read_response(&mut self) -> Result<Vec<String>, TorError> {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .await
                .map_err(|e| TorError::Io(e.to_string()))?;
            if n == 0 {
                return Err(TorError::Io("control port connection closed".into()));
            }
            let trimmed = line.trim_end().to_string();

            // Determine if this is the final line.
            // Final lines have a space as the 4th character; continuation
            // lines have a dash (or '+' for data replies).
            let is_final = trimmed.as_bytes().get(3).is_none_or(|&ch| ch == b' ');

            lines.push(trimmed);

            if is_final {
                break;
            }
        }
        Ok(lines)
    }

    /// Read a response and assert that the status code is 250 (OK).
    async fn expect_ok(&mut self) -> Result<(), TorError> {
        let lines = self.read_response().await?;
        let last = lines
            .last()
            .ok_or_else(|| TorError::Protocol("empty response".into()))?;

        if last.starts_with("250") {
            return Ok(());
        }
        if last.starts_with("515") {
            return Err(TorError::AuthFailed(last.clone()));
        }
        Err(TorError::Protocol(format!("expected 250, got: {last}")))
    }
}

/// Reject hostnames that would break out of the single-line `RESOLVE`
/// command (whitespace / CR / LF would let a caller inject extra
/// control-port commands).
fn validate_resolve_hostname(hostname: &str) -> Result<(), TorError> {
    if hostname.is_empty()
        || hostname
            .chars()
            .any(|c| c.is_whitespace() || c == '\r' || c == '\n')
    {
        return Err(TorError::Protocol(format!(
            "invalid hostname for RESOLVE: {hostname:?}"
        )));
    }
    Ok(())
}

/// Parse a control-port `RESOLVE` reply into the first resolved address.
///
/// Successful replies look like (final line is `250 OK`, data lines carry
/// `hostname=ip`; a one-line reply is `250 hostname=ip`). Any non-250 status
/// (e.g. `511` — resolution failed at the exit) is an honest error.
fn parse_resolve_response(response: &[String]) -> Result<IpAddr, TorError> {
    let last = response
        .last()
        .ok_or_else(|| TorError::Protocol("empty RESOLVE response".into()))?;
    if !last.starts_with("250") {
        return Err(TorError::Protocol(format!(
            "RESOLVE failed at the exit: {last}"
        )));
    }
    for line in response {
        let rest = line
            .strip_prefix("250-")
            .or_else(|| line.strip_prefix("250+"))
            .or_else(|| line.strip_prefix("250 "));
        if let Some(rest) = rest {
            // Data line is "hostname=1.2.3.4" (possibly "ip1,ip2" answers).
            if let Some((_host, v)) = rest.split_once('=') {
                let first = v.split(',').next().unwrap_or(v).trim();
                if let Ok(ip) = first.parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
        }
    }
    Err(TorError::Protocol(format!(
        "no address in RESOLVE response: {response:?}"
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_error_display() {
        let e = TorError::ControlPortRefused("conn refused".into());
        assert!(e.to_string().contains("refused"));

        let e = TorError::AuthFailed("bad password".into());
        assert!(e.to_string().contains("auth failed"));

        let e = TorError::NewnymTooFast { wait_ms: 4200 };
        let msg = e.to_string();
        assert!(msg.contains("NEWNYM"));
        assert!(msg.contains("4200"));

        let e = TorError::CircuitBuildFailed;
        assert!(e.to_string().contains("circuit"));

        let e = TorError::DaemonCrashed { pid: 1234 };
        assert!(e.to_string().contains("1234"));

        let e = TorError::NotInstalled;
        assert!(e.to_string().contains("not found"));

        let e = TorError::Io("broken pipe".into());
        assert!(e.to_string().contains("broken pipe"));

        let e = TorError::Protocol("unexpected".into());
        assert!(e.to_string().contains("protocol"));
    }

    #[test]
    fn auth_method_autodetect_is_constructible() {
        let method = AuthMethod::AutoDetect;
        assert!(matches!(method, AuthMethod::AutoDetect));

        let method = AuthMethod::None;
        assert!(matches!(method, AuthMethod::None));

        let method = AuthMethod::Password("secret".into());
        assert!(matches!(method, AuthMethod::Password(_)));

        let method = AuthMethod::Cookie(PathBuf::from("/tmp/cookie"));
        assert!(matches!(method, AuthMethod::Cookie(_)));
    }

    #[test]
    fn circuit_info_is_constructible() {
        let ci = CircuitInfo {
            id: 42,
            status: "BUILT".into(),
            path: vec!["guard1".into(), "middle2".into(), "exit3".into()],
        };
        assert_eq!(ci.id, 42);
        assert_eq!(ci.status, "BUILT");
        assert_eq!(ci.path.len(), 3);
        assert_eq!(ci.path[2], "exit3");
    }

    #[test]
    fn autodetect_candidates_cover_system_tmp_and_tallow_layouts() {
        let candidates = autodetect_cookie_candidates();
        let strs: Vec<String> = candidates
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        // System Tor conventions (Debian /var/run, Arch /run, /var/lib).
        assert!(strs.iter().any(|s| s == "/var/run/tor/control.authcookie"));
        assert!(strs.iter().any(|s| s == "/run/tor/control.authcookie"));
        assert!(strs.iter().any(|s| s == "/var/lib/tor/control_auth_cookie"));
        // The /tmp/tor_data manual-daemon layout used by Tallow ops.
        assert!(
            strs.iter()
                .any(|s| s == "/tmp/tor_data/control_auth_cookie"),
            "AutoDetect must probe /tmp/tor_data/control_auth_cookie, got: {strs:?}"
        );
        // Tallow managed-instance data dir candidates (B2: manager-spawned
        // daemons write their cookie into instance_* dirs, never the
        // /var/run|/var/lib paths the old AutoDetect probed).
        assert!(
            strs.iter()
                .any(|s| s.contains("instance_") && s.ends_with("control_auth_cookie")),
            "AutoDetect must include instance_* cookie paths, got: {strs:?}"
        );
        // Base data dir itself (external daemon run with DataDirectory there).
        assert!(
            strs.iter()
                .any(|s| s.ends_with("/tallow/tor/control_auth_cookie")),
            "AutoDetect must include the tallow base data-dir cookie, got: {strs:?}"
        );
    }

    #[test]
    fn parse_resolve_response_extracts_address() {
        // Multi-line reply: data lines prefixed "250-", final "250 OK".
        let multi = vec![
            "250-example.com=93.184.216.34".to_string(),
            "250 OK".to_string(),
        ];
        let ip = parse_resolve_response(&multi).unwrap();
        assert_eq!(ip.to_string(), "93.184.216.34");

        // One-line reply: "250 hostname=ip".
        let single = vec!["250 example.com=93.184.216.34".to_string()];
        let ip = parse_resolve_response(&single).unwrap();
        assert_eq!(ip.to_string(), "93.184.216.34");

        // Multiple answers, comma separated — first wins.
        let multi_ip =
            vec!["250 example.com=93.184.216.34,2606:2800:220:1:248:1893:25c8:1946".to_string()];
        let ip = parse_resolve_response(&multi_ip).unwrap();
        assert_eq!(ip.to_string(), "93.184.216.34");
    }

    #[test]
    fn parse_resolve_response_fails_honestly() {
        // Exit refused to resolve (511) — must not fabricate an address.
        let refused = vec!["511 DNS resolution failed for example.invalid".to_string()];
        let err = parse_resolve_response(&refused).unwrap_err();
        assert!(err.to_string().contains("RESOLVE failed"));

        // No address lines at all.
        let empty = vec!["250 OK".to_string()];
        let err = parse_resolve_response(&empty).unwrap_err();
        assert!(err.to_string().contains("no address"));
    }

    #[test]
    fn resolve_rejects_unsafe_hostnames() {
        // A hostname with CR/LF would be a control-port injection vector —
        // the guard must reject it before any bytes hit the wire.
        assert!(validate_resolve_hostname("").is_err());
        assert!(validate_resolve_hostname("example.com\r\nSIGNAL NEWNYM").is_err());
        assert!(validate_resolve_hostname("example.com\nSIGNAL NEWNYM").is_err());
        assert!(validate_resolve_hostname("exa mple.com").is_err());
        assert!(validate_resolve_hostname("example.com").is_ok());
    }
}
