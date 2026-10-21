//! Browser process lifecycle management.
//!
//! Handles launching Chromium with the correct flags, parsing the WebSocket
//! debug URL from stderr, PID file tracking for zombie cleanup, and
//! Drop-based process cleanup.

use std::collections::HashSet;
use std::io::{BufRead, BufReader};
#[cfg(unix)]
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::error::BrowserError;
use super::juggler::JugglerClient;

/// Browser engine backend.
///
/// Tallow historically drives Chromium/Chrome over the Chrome DevTools
/// Protocol (CDP). This enum adds Firefox-family engines for native-level
/// stealth that JS-level spoofing on Chromium cannot match (WebGL
/// `WEBGL_debug_renderer_info`, AudioContext, `hardwareConcurrency`,
/// WebRTC host-candidate suppression, font rasterization).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrowserBackend {
    /// Chromium/Chrome via CDP over `--remote-debugging-port`. Default.
    #[default]
    Chromium,
    /// Camoufox — a from-source Firefox ESR rebuild with native (C++) stealth
    /// patches. Exposes a CDP subset via `--remote-debugging-port`.
    Camoufox,
    /// Stock Firefox via geckodriver/Marionette (WebDriver BiDi).
    Firefox,
}

impl BrowserBackend {
    /// Human-readable engine name (for logs / config / diagnostics).
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserBackend::Chromium => "chromium",
            BrowserBackend::Camoufox => "camoufox",
            BrowserBackend::Firefox => "firefox",
        }
    }

    /// Parse an engine name (for config files / CLI flags).
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "chromium" | "chrome" | "chromium-headless-shell" => Some(BrowserBackend::Chromium),
            "camoufox" | "camou" => Some(BrowserBackend::Camoufox),
            "firefox" | "geckodriver" | "gecko" => Some(BrowserBackend::Firefox),
            _ => None,
        }
    }
}

/// Configuration for launching a browser process.
///
/// # TLS Fingerprinting (BRST-03)
///
/// Tallow launches the real Chrome/Chromium binary, so TLS handshakes produce
/// authentic JA3/JA4 fingerprints identical to a normal browser session.
/// No additional configuration is needed — this is satisfied by architecture.
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// Path to the Chromium/Chrome executable.
    pub chrome_path: PathBuf,
    /// Run in headless mode (default: true).
    pub headless: bool,
    /// Specific debugging port (None = auto-find).
    pub port: Option<u16>,
    /// Additional command-line arguments.
    pub args: Vec<String>,
    /// Custom user data directory (None = temp dir).
    pub user_data_dir: Option<PathBuf>,
    /// Timeout for browser startup (default: 30s).
    pub timeout: Duration,
    /// Enable stealth mode: adds Chrome flags to reduce automation detection.
    ///
    /// When true, adds `--disable-blink-features=AutomationControlled` and
    /// `--disable-infobars` to the launch arguments. JS-level evasion is
    /// handled separately by `Page::apply_stealth()`.
    pub stealth: bool,
    /// Proxy server for all browser traffic.
    ///
    /// Supports: `socks5://host:port`, `http://host:port`, `https://host:port`
    /// For Tor: set to `socks5://127.0.0.1:9050`
    /// For I2P: set to `http://127.0.0.1:4444`
    pub proxy: Option<String>,
    /// PAC (proxy auto-config) URL for all browser traffic. When set, passed as
    /// `--proxy-pac-url` instead of `--proxy-server`. A PAC file can route
    /// specific (e.g. analytics) domains to a dead proxy to block them at the
    /// network layer — before frame 1 — while everything else goes through the
    /// normal egress (e.g. Tor SOCKS5). Supersedes `proxy` when both are set.
    pub proxy_pac: Option<String>,
    /// Use pipe transport (`--remote-debugging-pipe`) instead of WebSocket.
    ///
    /// Pipe transport communicates via inherited file descriptors 3/4 on Unix
    /// (NUL-terminated CDP JSON — Chromium's ASCIIZ pipe protocol), offering
    /// lower latency than WebSocket. When enabled, `--remote-debugging-port`
    /// is NOT passed and no TCP port is opened — nothing is exposed on the
    /// network. Launch the browser with `use_pipe = true` (Chromium backend,
    /// unix only), then connect with
    /// [`BrowserProcess::connect_pipe_cdp`] / `CdpClient::connect_pipe`.
    ///
    /// On non-unix platforms (and for the Camoufox/Firefox backends) pipe
    /// mode is not supported; `BrowserProcess::launch` fails with a clear
    /// error rather than spawning a browser it cannot drive. WebSocket
    /// transport remains the default (`false`).
    pub use_pipe: bool,
    /// Browser engine backend (Chromium, Camoufox, Firefox). Default: Chromium.
    ///
    /// Selecting a Firefox-family backend changes launch args (`-marionette` /
    /// `--remote-debugging-port` + Firefox prefs instead of Blink flags) and the
    /// automation endpoint discovery. The wire protocol is CDP for Chromium and
    /// WebDriver BiDi (or a CDP subset) for Camoufox/Firefox.
    pub backend: BrowserBackend,
}

/// Stealth-mode launch flags (headless-only; applied verbatim by
/// [`BrowserProcess::launch`]).
///
/// Named rather than inline so the W2-10 (S4 / audit-05 F-5) password-store
/// decision is unit-testable: `--password-store=basic` is deliberately ABSENT.
/// Chrome therefore uses its platform default (`detect`) — a keyring-backed
/// store where a keyring exists, the `basic` fallback otherwise. The profile
/// dirs these runs use are per-run, owner-only (0700) and deleted on exit;
/// restore the flag via `browser.extra_args` if an environment requires it.
const STEALTH_LAUNCH_FLAGS: [&str; 24] = [
    "--disable-blink-features=AutomationControlled",
    "--disable-infobars",
    "--disable-features=TranslateUI,BlinkGenPropertyTrees,ChromeWhatsNewUI",
    "--disable-features=IsolateOrigins,site-per-process",
    "--disable-component-extensions-with-background-pages",
    "--disable-field-trial-config",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-default-apps",
    "--disable-popup-blocking",
    "--disable-prompt-on-repost",
    "--disable-hang-monitor",
    "--disable-client-side-phishing-detection",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--no-default-browser-check",
    "--no-first-run",
    "--use-gl=swiftshader",
    "--use-angle=swiftshader",
    "--window-size=1920,1080",
    "--window-position=0,0",
    "--enable-features=NetworkService,NetworkServiceInProcess",
    "--disable-extensions",
    "--mute-audio",
];

impl BrowserConfig {
    /// Performance-optimized Chrome flags for headless scraping.
    ///
    /// Returns a list of 21 flags that disable unnecessary Chrome features
    /// for maximum performance when doing data extraction.
    ///
    /// W2-10 (S4 / audit-05 F-5): `--password-store=basic` was deliberately
    /// removed from this preset — Chrome now uses its platform default
    /// (`detect`): keyring-backed where a keyring exists, `basic` fallback
    /// otherwise. Restore it per-run with `browser.extra_args` if an
    /// environment needs it (see `research/tallow-v1/exec/W2-10-profile-lifecycle.md`).
    pub fn performance_flags() -> Vec<String> {
        vec![
            "--disable-gpu".into(),
            "--disable-gpu-sandbox".into(),
            "--disable-software-rasterizer".into(),
            "--disable-extensions".into(),
            "--disable-background-networking".into(),
            "--disable-default-apps".into(),
            "--disable-sync".into(),
            "--disable-translate".into(),
            "--no-first-run".into(),
            "--disable-component-update".into(),
            "--disable-domain-reliability".into(),
            "--disable-client-side-phishing-detection".into(),
            "--disable-ipc-flooding-protection".into(),
            "--disable-hang-monitor".into(),
            "--disable-prompt-on-repost".into(),
            "--disable-background-timer-throttling".into(),
            "--disable-renderer-backgrounding".into(),
            "--disable-backgrounding-occluded-windows".into(),
            "--force-color-profile=srgb".into(),
            "--metrics-recording-only".into(),
            "--mute-audio".into(),
        ]
    }

    /// Maximum performance flags (more aggressive, may affect some sites).
    ///
    /// Includes all `performance_flags()` plus additional flags that disable
    /// site isolation and limit renderer processes. Use when maximum throughput
    /// is needed and page fidelity is less important.
    pub fn max_performance_flags() -> Vec<String> {
        let mut flags = Self::performance_flags();
        flags.extend([
            "--disable-features=AudioServiceOutOfProcess,IsolateOrigins,site-per-process".into(),
            "--renderer-process-limit=5".into(),
            "--js-flags=--max-old-space-size=512".into(),
        ]);
        flags
    }
}

/// Normalize a proxy URL for Chrome. Chrome understands `socks5://` (and does
/// remote DNS by default), but NOT libcurl's `socks5h://` remote-DNS variant
/// that leaks in from `TALLOW_PROXY`/Tor env vars. Without this, `--proxy-server`
/// receives an unrecognized scheme and the browser tunnel fails with
/// `ERR_TUNNEL_CONNECTION_FAILED`.
fn normalize_proxy_scheme(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("socks5h://") {
        format!("socks5://{rest}")
    } else {
        url.to_string()
    }
}

/// Strip a `user[:pass]@` userinfo section from a proxy URL for Chrome.
///
/// Chromium implements no SOCKS5 authentication (RFC 1929) and accepts no
/// userinfo in `--proxy-server`: with credentials attached, every navigation
/// fails and returns an empty document (verified 2026-10-02 against the
/// fail-closed per-run identity URL — `socks5h://tallow-<pid>-<rand>:<hex>@`).
/// Firefox-family backends keep credentials instead, expressed as profile
/// prefs (`crate::browser::zone::firefox_user_js_proxy_prefs`).
fn strip_proxy_credentials(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.rsplit_once('@') {
            Some((_, hostport)) => format!("{scheme}://{hostport}"),
            None => url.to_string(),
        },
        None => url.to_string(),
    }
}

/// Chromium proxy-bypass list for the browser zone.
///
/// `<-loopback>` is Chromium's documented token that REMOVES Chromium's
/// implicit loopback bypass, forcing `127.0.0.1` / `::1` through
/// `--proxy-server`. Without it, every page the browser loads can reach the
/// box's own loopback services — prometheus 9090, node_exporter 9100,
/// tallow-admin 9337 and the Tor control port 9051 all answered page JS from a
/// headless Chromium launched with the previous value (verified 2026-10-12,
/// including with the flag omitted entirely: Chromium bypasses loopback by
/// default).
///
/// The previous value was `--proxy-bypass-list=localhost;127.0.0.1`, justified
/// in a comment as "so the CDP debugging connection is not itself proxied".
/// That rationale is wrong: CDP is an INBOUND connection from the controller
/// to the browser's own listening port, which the browser's outbound proxy
/// configuration never governs. Measured 2026-10-12 with a real
/// `--remote-debugging-port` transport and this value: the DevTools HTTP
/// endpoint served, the CDP connection established, page loads still egressed
/// through Tor, and loopback was unreachable from page JS.
///
/// Tallow's pipe transport (`use_pipe`) opens no TCP port at all and is
/// unaffected either way.
pub const CHROME_PROXY_BYPASS_LIST: &str = "--proxy-bypass-list=<-loopback>";

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            chrome_path: find_chrome_path(),
            headless: true,
            port: None,
            args: Vec::new(),
            user_data_dir: None,
            timeout: Duration::from_secs(30),
            stealth: false,
            proxy: None,
            proxy_pac: None,
            use_pipe: false,
            backend: BrowserBackend::default(),
        }
    }
}

/// A managed browser process with its WebSocket debug URL.
pub struct BrowserProcess {
    child: Child,
    /// The WebSocket URL for CDP connections (e.g., `ws://127.0.0.1:9222/devtools/browser/...`).
    pub ws_url: String,
    /// The debug port the browser is listening on.
    pub port: u16,
    /// Path to the PID file, if one was created.
    pid_file: Option<PathBuf>,
    /// Per-run profile directory this process created and therefore owns
    /// (deleted on `Drop`/`kill`). `None` when the caller supplied an explicit
    /// `user_data_dir` — an operator-owned persistent profile is never deleted.
    profile_dir: Option<PathBuf>,
    /// Juggler client for Firefox-family backends (Camoufox/Firefox). `None` for
    /// Chromium (which uses `ws_url` + CDP).
    pub juggler: Option<Arc<JugglerClient>>,
    /// Loopback SOCKS5 credential-injection relay for this launch's per-run
    /// circuit identity (Chromium engine, in-process). `None` when the
    /// launch had no credentialed proxy or the relay could not start;
    /// dropping the struct stops the relay (see `browser::socks_shim`).
    socks_shim: Option<super::socks_shim::SocksShimGuard>,
}

impl BrowserProcess {
    /// Launch a new browser process with the given configuration.
    ///
    /// Finds an available port, spawns Chromium with debugging flags,
    /// parses the WebSocket URL from stderr, and writes a PID file.
    pub fn launch(config: &BrowserConfig) -> Result<Self, BrowserError> {
        // Clean up stale processes first
        cleanup_stale_processes();
        // …and stale profile dirs left by browsers that are confirmed dead
        // (crash / SIGKILL / pre-W2-10 runs). Live siblings are never touched.
        cleanup_stale_profile_dirs();

        // Pipe transport (`--remote-debugging-pipe`) is a Chromium CDP
        // transport. Firefox-family backends speak Juggler over their own
        // `-juggler-pipe`; a use_pipe request for them would be silently
        // ignored, so reject it explicitly.
        if config.use_pipe && config.backend != BrowserBackend::Chromium {
            return Err(BrowserError::ConnectionFailed(
                "use_pipe (--remote-debugging-pipe CDP transport) is only supported \
                 for the Chromium backend; Camoufox/Firefox use their own \
                 -juggler-pipe transport (BrowserConfig::use_pipe = false)"
                    .to_string(),
            ));
        }

        // Pipe transport (Chromium `--remote-debugging-pipe`) is unix-only: it
        // needs the child's fds 3/4 wired to real pipes (see create_pipe_io /
        // the pre_exec dup2 below). On platforms without that wiring, reject
        // BEFORE spawning so pipe mode never launches a browser it cannot drive.
        #[cfg(not(unix))]
        if config.use_pipe {
            return Err(BrowserError::ConnectionFailed(
                "--remote-debugging-pipe transport requires unix fd 3/4 wiring \
                 and is not supported on this platform; use WebSocket CDP \
                 (use_pipe=false)"
                    .to_string(),
            ));
        }

        // The fd 3/4 pipe ends must exist before the Command is spawned: the
        // child dup2s them onto fds 3/4 (pre_exec) so Chromium's pipe handler
        // inherits them. WebSocket launches leave this None.
        #[cfg(unix)]
        let pipe_io = if config.use_pipe {
            Some(create_pipe_io().map_err(|e| {
                BrowserError::ConnectionFailed(format!(
                    "failed to create CDP pipe fds (3/4): {e}"
                ))
            })?)
        } else {
            None
        };
        #[cfg(not(unix))]
        let _pipe_io: Option<()> = None;

        // Find an available debug port — only the WebSocket transport needs
        // one. Pipe mode opens no TCP port at all (port 0).
        let port = if config.use_pipe {
            0
        } else {
            match config.port {
                Some(p) => p,
                None => find_available_port().map_err(|e| {
                    BrowserError::ConnectionFailed(format!("no available port: {e}"))
                })?,
            }
        };

        // Firefox-family backends (Camoufox/Firefox) use the Juggler protocol
        // over a pipe (`-juggler-pipe`), NOT CDP. Early-return keeps the Chromium
        // path below unchanged.
        //
        // T-207-fu: this path applies the same zone egress contract as the
        // Chromium branch below — `JugglerClient::launch` resolves the zone
        // proxy (or refuses on a malformed one) and writes it into the
        // profile's `user.js`, since Firefox has no `--proxy-server`.
        if config.backend != BrowserBackend::Chromium {
            let (mut child, juggler, profile_dir) = JugglerClient::launch(config)?;
            let pid_file = write_pid_file(child.id());
            return Ok(BrowserProcess {
                child,
                ws_url: String::new(),
                port,
                pid_file,
                profile_dir,
                juggler: Some(Arc::new(juggler)),
                socks_shim: None,
            });
        }

        // Build command (Chromium)
        let mut cmd = Command::new(&config.chrome_path);

        // Core debugging flag — pipe vs WebSocket transport
        if config.use_pipe {
            cmd.arg("--remote-debugging-pipe");
        } else {
            cmd.arg(format!("--remote-debugging-port={port}"));
        }

        // Headless mode
        if config.headless {
            cmd.arg("--headless=new");
            cmd.arg("--no-sandbox");
            cmd.arg("--disable-gpu");
            cmd.arg("--window-size=1920,1080");
        } else {
            // Non-headless: pick the display backend that actually exists.
            // Wayland is forced only when a compositor is present; otherwise
            // ozone stays on auto-detect so an X11 DISPLAY works — including
            // a virtual display (Xvfb / `xvfb-run`), the Camoufox-parity
            // launch mode. Forcing `--ozone-platform=wayland` with no
            // compositor aborts the launch ("Failed to initialize Wayland
            // platform", verified 2026-09-16).
            if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                cmd.arg("--ozone-platform=wayland");
            }
            cmd.arg("--no-sandbox");
            cmd.arg("--disable-gpu");
            cmd.arg("--window-size=1920,1080");
            cmd.arg("--window-position=0,0");
        }

        // Standard flags for automation (headless only — non-headless skips these)
        if config.headless {
            cmd.args([
                "--disable-background-networking",
                "--disable-extensions",
                "--no-first-run",
                "--disable-dev-shm-usage",
                "--disable-default-apps",
                "--disable-translate",
                "--disable-sync",
            ]);
        } else {
            // Non-headless: minimal flags to avoid display issues
            cmd.args([
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
            ]);
        }

        // Stealth flags: only for headless (break non-headless display)
        if config.stealth && config.headless {
            cmd.args(STEALTH_LAUNCH_FLAGS);
        }

        // Proxy: route ALL browser traffic through proxy (Tor, SOCKS5, HTTP).
        // Clear inherited proxy env vars so Chrome relies solely on
        // `--proxy-server` — otherwise a `socks5h://` env var (Hermes Tor drop-in)
        // leaks into the child and Chrome can't parse it (ERR_TUNNEL_CONNECTION_FAILED).
        for key in [
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "no_proxy",
            "NO_PROXY",
        ] {
            cmd.env_remove(key);
        }
        // W2 (2026-10-02): per-run circuit identity for the Chromium engine.
        // `Some` once the proxy branch below starts a credential-injection
        // relay; moved into whichever `BrowserProcess` construction runs.
        let mut socks_shim_guard: Option<super::socks_shim::SocksShimGuard> = None;
        if let Some(ref pac) = config.proxy_pac {
            cmd.arg(format!("--proxy-pac-url={pac}"));
            cmd.arg(CHROME_PROXY_BYPASS_LIST);
        } else {
            // T-207 (P4-15 browser-zone lockdown): an unset `proxy` no longer
            // means "launch direct" — the single zone predicate decides
            // (contract Tor SOCKS by default; direct only on the explicit
            // TALLOW_ALLOW_DIRECT opt-in). A malformed proxy refuses the
            // launch instead of spawning a browser that can egress from the
            // box IP.
            let zone_proxy = match config.proxy.as_deref() {
                Some(p) => Some(p.to_string()),
                None => super::zone::browser_zone_chrome_proxy()
                    .map_err(BrowserError::ConnectionFailed)?,
            };
            if let Some(proxy) = zone_proxy {
                let proxy = normalize_proxy_scheme(&proxy);
                // Chromium cannot speak the fail-closed per-run identity URL
                // (no SOCKS5 auth in Chromium): with credentials attached
                // every page load fails empty (verified 2026-10-02).
                // Preferred path: a local credential-injection relay restores
                // the per-run circuit — Chromium talks plain SOCKS5 to
                // 127.0.0.1 and the relay re-originates upstream with the
                // per-run credentials (browser::socks_shim). Fallback: strip
                // credentials (shared unauthenticated Tor circuit — still
                // proxied, never direct). `TALLOW_BROWSER_NO_SHIM=1` forces
                // the fallback. Firefox-family backends keep credentials via
                // `user.js` prefs (browser::zone).
                let shim_disabled = matches!(
                    std::env::var("TALLOW_BROWSER_NO_SHIM").ok().as_deref(),
                    Some("1") | Some("true") | Some("yes")
                );
                let proxy_arg = if super::socks_shim::has_credentials(&proxy) && !shim_disabled {
                    match super::socks_shim::spawn_for_credentials(&proxy) {
                        Ok(guard) => {
                            let url = guard.proxy_url();
                            socks_shim_guard = Some(guard);
                            url
                        }
                        Err(reason) => {
                            eprintln!("[tallow] warning: socks-auth relay unavailable ({reason}); Chromium rides the shared Tor circuit (credentials stripped)");
                            strip_proxy_credentials(&proxy)
                        }
                    }
                } else {
                    strip_proxy_credentials(&proxy)
                };
                cmd.arg(format!("--proxy-server={proxy_arg}"));
                cmd.arg(CHROME_PROXY_BYPASS_LIST);
            }
        }

        // User data directory — a per-run, owner-only (0700) directory keyed on
        // (pid, launch seq) instead of the debug port, so two runs can never
        // share a profile (audit-05 F-5/F-14). `profile_guard` owns it until
        // this function returns successfully; on any error return (spawn
        // failure, ws-URL timeout, HTTP discovery failure) the guard's Drop
        // deletes it. A caller-supplied `user_data_dir` is used as-is and never
        // deleted or guarded.
        let (profile_arg, mut profile_guard) = match config.user_data_dir.as_deref() {
            Some(dir) if !dir.as_os_str().is_empty() => (dir.to_path_buf(), None),
            _ => {
                let guard = RunProfileDir::create(RUN_PROFILE_PREFIXES[0]).map_err(|e| {
                    BrowserError::ConnectionFailed(format!(
                        "failed to create per-run browser profile dir: {e}"
                    ))
                })?;
                (guard.path().to_path_buf(), Some(guard))
            }
        };
        cmd.arg(format!("--user-data-dir={}", profile_arg.display()));

        // Additional user args
        for arg in &config.args {
            cmd.arg(arg);
        }

        // Pipe stderr AND stdout so we can read the ws:// URL
        cmd.stderr(Stdio::piped());
        cmd.stdout(Stdio::piped());

        // Pass Wayland environment if available (needed for headed Chrome on Wayland)
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            cmd.env("XDG_RUNTIME_DIR", &runtime_dir);
        }
        if std::env::var("WAYLAND_DISPLAY").is_ok() {
            cmd.env("WAYLAND_DISPLAY", std::env::var("WAYLAND_DISPLAY").unwrap_or_default());
        } else if std::env::var("XDG_RUNTIME_DIR").is_ok() {
            // WAYLAND_DISPLAY not set but XDG_RUNTIME_DIR is — auto-detect wayland-0
            let socket = format!(
                "{}/wayland-0",
                std::env::var("XDG_RUNTIME_DIR").unwrap_or_default()
            );
            if std::path::Path::new(&socket).exists() {
                cmd.env("WAYLAND_DISPLAY", "wayland-0");
            }
        }

        // Pipe transport: in the child, move the pipe ends onto fds 3 and 4
        // (Chromium's kReadFD / kWriteFD for `--remote-debugging-pipe`) and
        // clear CLOEXEC there so they survive exec. Only async-signal-safe
        // syscalls (dup2/fcntl/close) run here.
        #[cfg(unix)]
        if let Some(io) = &pipe_io {
            use std::os::unix::process::CommandExt;
            let read_fd = io.child_read_fd;
            let write_fd = io.child_write_fd;
            // SAFETY: dup2/fcntl/close are async-signal-safe; the fds were
            // freshly created above and targets 3/4 are reserved for the child.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::dup2(read_fd, 3) < 0 || libc::dup2(write_fd, 4) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::fcntl(3, libc::F_SETFD, 0);
                    libc::fcntl(4, libc::F_SETFD, 0);
                    // The originals carry CLOEXEC and would close at exec
                    // anyway; close them now unless they alias the dup targets.
                    if read_fd > 4 {
                        libc::close(read_fd);
                    }
                    if write_fd > 4 {
                        libc::close(write_fd);
                    }
                    Ok(())
                });
            }
        }

        // 2026-10-02: a TMPDIR under the Hermes scratch tree breaks Chromium
        // page loads in browser subprocesses on this host — bisected live:
        // scratch → every navigation comes up empty (renderer path; persists
        // with Landlock disabled, so it is not the read fence), while /tmp,
        // /var/tmp and other roots are fine. The same condition is documented
        // host-side by the Hermes 2026-09-30 hotfix, which routes its own
        // browser sessions' temp root to /tmp unconditionally. Mirror that:
        // pin the child's temp to /tmp whenever the inherited temp would be
        // under the Hermes home; every other context keeps its temp as-is.
        {
            let inherited_tmp = std::env::temp_dir();
            let inherited_str = inherited_tmp.to_string_lossy();
            if inherited_str.starts_with("/home/user/.hermes/") && std::path::Path::new("/tmp").is_dir()
            {
                cmd.env("TMPDIR", "/tmp");
                cmd.env("TMP", "/tmp");
                cmd.env("TEMP", "/tmp");
            }
        }

        // RT-FIX-7A (W8 red-team → fix): Landlock read+execute confinement for
        // the browser child. The seccomp/Landlock runtime existed but had no
        // production caller; this wires it into the one real browser spawn.
        // Best-effort by construction: kernels without Landlock skip the hook
        // silently (see `sandbox_runtime`), so this only *adds* a read/exec
        // fence around the child. `TALLOW_BROWSER_LANDLOCK=0` opts out;
        // `TALLOW_BROWSER_LANDLOCK_PATHS` (colon-separated) adds read roots
        // for unusual installs.
        #[cfg(target_os = "linux")]
        if !browser_landlock_disabled() {
            let read_paths = browser_landlock_read_paths(config, &profile_arg);
            let _ = crate::sandbox_runtime::run_sandboxed(&mut cmd, &read_paths);
        }

        // Spawn the process
        let mut child = cmd.spawn().map_err(|e| {
            #[cfg(unix)]
            if let Some(io) = &pipe_io {
                // Never leak the raw pipe ends if exec failed.
                unsafe {
                    libc::close(io.child_read_fd);
                    libc::close(io.child_write_fd);
                }
            }
            BrowserError::ConnectionFailed(format!(
                "failed to launch browser at {}: {e}",
                config.chrome_path.display()
            ))
        })?;

        // Pipe transport bookkeeping: close the parent's copies of the child
        // ends so EOF works in both directions, keep stdout/stderr drained for
        // the browser's whole lifetime, and register the owned ends for
        // `CdpClient::connect_pipe` / `BrowserProcess::connect_pipe_cdp`.
        #[cfg(unix)]
        if let Some(io) = pipe_io {
            unsafe {
                libc::close(io.child_read_fd);
                libc::close(io.child_write_fd);
            }
            drain_child_output(&mut child);

            let pid = child.id();
            let ends = PipeEnds {
                to_browser: io.to_browser,
                from_browser: io.from_browser,
            };
            register_pipe_ends(pid, ends);
            let pid_file = write_pid_file(pid);
            return Ok(BrowserProcess {
                child,
                ws_url: String::new(),
                port,
                pid_file,
                profile_dir: profile_guard.take().map(RunProfileDir::into_path),
                juggler: None,
                socks_shim: socks_shim_guard.take(),
            });
        }

        // Write PID file
        let pid_file = write_pid_file(child.id());

        // Parse ws:// URL from stderr with timeout; fallback to HTTP if that fails
        let ws_url = match parse_ws_url_from_stderr(&mut child, config.timeout) {
            Ok(url) => url,
            Err(_) => {
                // Wayland/non-headless Chrome sends ws:// to controlling terminal, not pipes.
                // Fall back to HTTP discovery on the known debugging port.
                let http_url = format!("http://127.0.0.1:{port}/json/version");
                discover_ws_url_via_http(&http_url, config.timeout)?
            }
        };

        Ok(BrowserProcess {
            child,
            ws_url,
            port,
            pid_file,
            profile_dir: profile_guard.take().map(RunProfileDir::into_path),
            juggler: None,
            socks_shim: socks_shim_guard.take(),
        })
    }

    /// Kill the browser process and clean up.
    pub fn kill(&mut self) {
        #[cfg(unix)]
        unregister_pipe_ends(self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.remove_pid_file();
        self.remove_profile_dir();
        // Full stop: also kill the credential relay (its own Drop would too).
        self.socks_shim = None;
    }

    /// Connect a CDP client over the pipe transport (fds 3/4).
    ///
    /// Only valid for processes launched with `use_pipe = true` (Chromium
    /// backend, unix) — the launch registered this child's fd 3/4 pipe ends.
    /// For WebSocket launches use `CdpClient::connect(&process.ws_url)`
    /// instead; this method fails with an honest error when the launch did
    /// not create pipe ends.
    ///
    /// # Example
    /// ```ignore
    /// let config = BrowserConfig { use_pipe: true, ..BrowserConfig::default() };
    /// let mut proc = BrowserProcess::launch(&config)?;
    /// let client = proc.connect_pipe_cdp().await?;   // no TCP port exposed
    /// let page = client.create_page(None).await?;
    /// ```
    #[cfg(unix)]
    pub async fn connect_pipe_cdp(&mut self) -> Result<super::cdp::CdpClient, BrowserError> {
        super::cdp::CdpClient::connect_pipe(&mut self.child).await
    }

    /// Remove the PID file if it exists.
    fn remove_pid_file(&self) {
        if let Some(ref path) = self.pid_file {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Delete the per-run profile directory this process created (no-op for a
    /// caller-supplied persistent `user_data_dir`).
    fn remove_profile_dir(&mut self) {
        if let Some(path) = self.profile_dir.take() {
            remove_run_profile_dir(&path);
        }
    }
}

impl Drop for BrowserProcess {
    fn drop(&mut self) {
        #[cfg(unix)]
        unregister_pipe_ends(self.child.id());
        if let Err(e) = self.child.kill() {
            eprintln!("[tallow] warning: failed to kill browser process: {e}");
        }
        let _ = self.child.wait();
        self.remove_pid_file();
        // After the child is reaped: nothing can write to the profile any more.
        self.remove_profile_dir();
        // Kill the credential relay last (browser traffic is down by now).
        self.socks_shim = None;
    }
}

// ---------------------------------------------------------------------------
// CDP pipe transport (fd 3/4) plumbing
// ---------------------------------------------------------------------------

/// Owned pipe ends for the `--remote-debugging-pipe` transport.
///
/// Chromium reads DevTools protocol messages from fd 3 (`kReadFD`) and writes
/// them to fd 4 (`kWriteFD`), each message terminated by a NUL byte (ASCIIZ
/// framing). The parent keeps the write end of the fd-3 pipe (`to_browser`)
/// and the read end of the fd-4 pipe (`from_browser`); the child's ends are
/// dup2'd onto 3/4 before exec.
#[cfg(unix)]
pub(crate) struct PipeEnds {
    /// Parent→browser: commands written here are read by the browser on fd 3.
    pub(crate) to_browser: std::os::fd::OwnedFd,
    /// Browser→parent: responses/events written by the browser on fd 4.
    pub(crate) from_browser: std::os::fd::OwnedFd,
}

/// Pipe ends registered per live pipe-mode child (keyed by pid) so
/// `CdpClient::connect_pipe(&mut child)` can claim them after launch. The
/// `Child` struct itself cannot carry arbitrary fds, so the registry is the
/// custody hand-off between `launch` and `connect`.
#[cfg(unix)]
static PIPE_ENDS: OnceLock<Mutex<HashMap<u32, PipeEnds>>> = OnceLock::new();

#[cfg(unix)]
fn pipe_ends_map() -> &'static Mutex<HashMap<u32, PipeEnds>> {
    PIPE_ENDS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register the pipe ends of a freshly spawned pipe-mode child.
#[cfg(unix)]
pub(crate) fn register_pipe_ends(pid: u32, ends: PipeEnds) {
    if let Ok(mut map) = pipe_ends_map().lock() {
        map.insert(pid, ends);
    }
}

/// Claim (and remove) the registered pipe ends for `pid`, if any.
#[cfg(unix)]
pub(crate) fn take_pipe_ends(pid: u32) -> Option<PipeEnds> {
    pipe_ends_map().lock().ok()?.remove(&pid)
}

/// Drop any registered pipe ends for `pid` (browser killed / reaped / never
/// connected). Closes the owned fds.
#[cfg(unix)]
pub(crate) fn unregister_pipe_ends(pid: u32) {
    if let Ok(mut map) = pipe_ends_map().lock() {
        map.remove(&pid);
    }
}

/// Child-side fd numbers plus parent-owned ends for one pipe-mode launch.
#[cfg(unix)]
struct PipeIo {
    /// Raw child-side read end — dup2'd to fd 3 in the child, closed in the
    /// parent right after spawn.
    child_read_fd: i32,
    /// Raw child-side write end — dup2'd to fd 4 in the child, closed in the
    /// parent right after spawn.
    child_write_fd: i32,
    /// Owned parent write end (commands → fd 3).
    to_browser: std::os::fd::OwnedFd,
    /// Owned parent read end (messages ← fd 4).
    from_browser: std::os::fd::OwnedFd,
}

/// Create the two OS pipes backing a `--remote-debugging-pipe` launch.
///
/// `cmd_pipe` is [read, write]: the child reads commands at fd 3 and the
/// parent writes. `msg_pipe` is [read, write]: the child writes messages at
/// fd 4 and the parent reads. All ends are created CLOEXEC; the child's dup2
/// targets (3/4) get CLOEXEC cleared in `pre_exec`.
/// Create an OS pipe and mark both ends close-on-exec (portable `pipe2`).
#[cfg(unix)]
fn pipe_cloexec(fds: &mut [std::os::raw::c_int; 2]) -> std::io::Result<()> {
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for fd in fds.iter() {
        unsafe {
            libc::fcntl(*fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_pipe_io() -> Result<PipeIo, std::io::Error> {
    use std::os::fd::{FromRawFd, OwnedFd};

    let mut cmd_pipe: [std::os::raw::c_int; 2] = [0; 2];
    pipe_cloexec(&mut cmd_pipe)?;
    let mut msg_pipe: [std::os::raw::c_int; 2] = [0; 2];
    if let Err(err) = pipe_cloexec(&mut msg_pipe) {
        unsafe {
            libc::close(cmd_pipe[0]);
            libc::close(cmd_pipe[1]);
        }
        return Err(err);
    }

    Ok(PipeIo {
        child_read_fd: cmd_pipe[0],
        child_write_fd: msg_pipe[1],
        to_browser: unsafe { OwnedFd::from_raw_fd(cmd_pipe[1]) },
        from_browser: unsafe { OwnedFd::from_raw_fd(msg_pipe[0]) },
    })
}

/// Drain a pipe-mode child's stdout/stderr for its whole lifetime.
///
/// Chromium blocks (and proxy connections fail) if its stderr or stdout pipe
/// fills while nobody reads — the WebSocket path drains inside
/// `parse_ws_url_from_stderr`; pipe mode has no ws:// URL to wait for, so it
/// uses pure drain threads instead.
#[cfg(unix)]
fn drain_child_output(child: &mut Child) {
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for _line in reader.lines() {}
        });
    }
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for _line in reader.lines() {}
        });
    }
}

/// Discover the WebSocket debugging URL via Chrome's HTTP JSON endpoint.
///
/// Polls `http://127.0.0.1:{port}/json/version` with retries until timeout.
/// Returns the `webSocketDebuggerUrl` field from the JSON response.
fn discover_ws_url_via_http(http_url: &str, timeout: Duration) -> Result<String, BrowserError> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let deadline = Instant::now() + timeout;
    // Parse host:port from http_url. The path must be stripped as well: a
    // leftover "/json/version" made the SocketAddr parse fail, and the old
    // silent fallback then probed 127.0.0.1:9222 — a port the launch never
    // used — until the timeout, masking real launch failures (2026-10-02).
    let host_port = http_url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next());
    let addr: std::net::SocketAddr = match host_port.and_then(|hp| hp.parse().ok()) {
        Some(a) => a,
        None => {
            return Err(BrowserError::ConnectionFailed(format!(
                "invalid debug endpoint URL: {http_url}"
            )))
        }
    };
    let path = "/json/version";

    loop {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let request = format!(
                    "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    path, addr
                );
                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut buf = String::new();
                    if stream.read_to_string(&mut buf).is_ok() {
                        // Extract JSON body (after HTTP headers)
                        if let Some(body_start) = buf.find("\r\n\r\n") {
                            let body = &buf[body_start + 4..];
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
                                if let Some(ws_url) = parsed
                                    .get("webSocketDebuggerUrl")
                                    .and_then(|v| v.as_str())
                                {
                                    return Ok(ws_url.to_string());
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }

        if Instant::now() >= deadline {
            return Err(BrowserError::ConnectionFailed(
                "timeout waiting for Chrome HTTP endpoint (try headless=true)".to_string(),
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Parse the WebSocket debug URL from Chrome's stderr output.
///
/// Chrome writes a line like:
///   `DevTools listening on ws://127.0.0.1:9222/devtools/browser/<guid>`
///
/// This function reads stderr lines in a background thread to avoid
/// blocking the async runtime.
fn parse_ws_url_from_stderr(child: &mut Child, timeout: Duration) -> Result<String, BrowserError> {
    let stderr = child.stderr.take().ok_or_else(|| {
        BrowserError::ConnectionFailed("failed to capture browser stderr".to_string())
    })?;

    // Also take stdout — non-headless Chrome sometimes sends DevTools URL there
    let stdout = child.stdout.take();

    let (tx, rx) = std::sync::mpsc::channel();
    let deadline = Instant::now() + timeout;
    let tx2 = tx.clone(); // clone before first thread takes ownership

    // Read stderr in a background thread. Keep draining stderr for the browser's
    // WHOLE lifetime — Chrome BLOCKS (and proxy connections fail) if its stderr
    // pipe fills up because nobody is reading it. Previously this thread returned
    // right after finding the ws:// URL, leaving the pipe un-drained.
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut sent = false;
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if !sent {
                        if let Some(ws_pos) = line.find("ws://") {
                            let ws_url: String = line[ws_pos..]
                                .chars()
                                .take_while(|c| !c.is_whitespace())
                                .collect();
                            let _ = tx.send(Ok(ws_url));
                            sent = true;
                        }
                    }
                    // Otherwise drain and discard (keep the pipe empty).
                }
                Err(_) => break,
            }
        }
        if !sent {
            let _ = tx.send(Err("stderr closed without ws:// URL".to_string()));
        }
    });

    // Also read stdout — non-headless Chrome sometimes outputs DevTools URL there.
    // Same lifetime-drain requirement as stderr.
    if let Some(stdout) = stdout {
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let mut sent = false;
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        if !sent {
                            if let Some(ws_pos) = line.find("ws://") {
                                let ws_url: String = line[ws_pos..]
                                    .chars()
                                    .take_while(|c| !c.is_whitespace())
                                    .collect();
                                let _ = tx2.send(Ok(ws_url));
                                sent = true;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Wait for the URL with timeout
    let remaining = deadline.saturating_duration_since(Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(Ok(url)) => Ok(url),
        Ok(Err(e)) => Err(BrowserError::ConnectionFailed(format!(
            "failed to parse ws:// URL: {e}"
        ))),
        Err(_) => Err(BrowserError::ConnectionFailed(
            "timeout waiting for browser to start (no ws:// URL on stderr or stdout)".to_string(),
        )),
    }
}

/// Find an available TCP port by binding to port 0.
pub fn find_available_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

// ---------------------------------------------------------------------------
// Per-run profile directories (W2-10 / S4 — audit-05 F-5, F-14)
// ---------------------------------------------------------------------------
//
// Every browser Tallow launches gets its own profile dir under the system temp
// dir, created owner-only (0700) and deleted when the browser exits. Two
// properties matter and are tested:
//
//   * uniqueness — the name is `<prefix><pid>-<seq>`, never the debug port, so
//     a port TOCTOU (F-14) or a second launch in the same process can never
//     make two browsers share a profile lock;
//   * bounded lifetime — Drop/kill delete exactly the directory this process
//     created; a caller-supplied `user_data_dir` (operator-owned persistent
//     profile) is NEVER deleted, and `remove_run_profile_dir` refuses any path
//     that is not our own under `temp_dir()`.
//
// Residue from crashes (SIGKILL) is swept by [`cleanup_stale_profile_dirs`],
// which only removes dirs whose PID is confirmed dead — same liveness rule as
// the PID files in `~/.tallow/browsers/`.

/// Prefixes of every temp-dir profile Tallow owns.
pub(crate) const RUN_PROFILE_PREFIXES: [&str; 2] = ["tallow-chrome-", "tallow-juggler-"];

/// Monotonic per-process suffix so two launches in one process never share a
/// profile directory (the previous pipe path shared one dir per process and the
/// WebSocket path keyed on the debug port).
static RUN_PROFILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Create `temp_dir()/<prefix><pid>-<seq>` with mode `0700`.
///
/// Skips suffixes whose directory already exists (e.g. a leftover from a
/// previous run that happened to reuse this PID) instead of ever reusing
/// another run's profile.
fn create_run_profile_dir(prefix: &str) -> std::io::Result<PathBuf> {
    let base = std::env::temp_dir();
    for _ in 0..16 {
        let seq = RUN_PROFILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("{prefix}{}-{seq}", std::process::id()));
        match create_private_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("could not allocate a unique {prefix} profile directory in {}", base.display()),
    ))
}

/// `mkdir` mode 0700 on unix (owner-only), plain `create_dir` elsewhere.
fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
        // mkdir(2) modes are filtered through umask; set the mode explicitly so
        // the guarantee does not depend on the caller's umask.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}

/// True when `path` is a profile directory this crate owns: **directly** inside
/// the system temp dir and carrying one of [`RUN_PROFILE_PREFIXES`].
fn is_managed_profile_path(path: &std::path::Path) -> bool {
    let base = std::env::temp_dir();
    let directly_in_temp = path.parent() == Some(base.as_path());
    let named = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| RUN_PROFILE_PREFIXES.iter().any(|p| n.starts_with(p)))
        .unwrap_or(false);
    directly_in_temp && named
}

/// Best-effort `remove_dir_all` for one profile directory this process created.
///
/// Refuses (and logs) any path that is not a managed profile path — the
/// `remove_dir_all` is deliberately guarded to the exact created naming scheme
/// so a bug upstream can never turn it into a general-purpose delete.
pub(crate) fn remove_run_profile_dir(path: &std::path::Path) {
    if !is_managed_profile_path(path) {
        eprintln!(
            "[tallow] warning: refusing to remove non-profile path: {}",
            path.display()
        );
        return;
    }
    // Chromium children can still be flushing into the profile dir for a few
    // ms after the process tree is torn down, so a single attempt can race
    // with ENOTEMPTY ("Directory not empty"). Retry briefly before giving up;
    // NotFound at any point means someone else already cleaned it.
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..3u32 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(
                    if attempt == 0 { 25 } else { 100 },
                ));
            }
        }
    }
    if let Some(e) = last_err {
        eprintln!(
            "[tallow] warning: failed to remove profile dir {}: {e}",
            path.display()
        );
    }
}

/// RAII guard owning a freshly created per-run profile directory.
///
/// Removes the directory on drop unless ownership was transferred with
/// [`RunProfileDir::into_path`]. This is what makes the *failure* paths of
/// `BrowserProcess::launch` (spawn error, ws-URL timeout, HTTP discovery
/// failure) leak-free: the guard is in scope for all of them.
pub(crate) struct RunProfileDir {
    path: PathBuf,
    armed: bool,
}

impl RunProfileDir {
    /// Create the process-private per-run profile directory.
    pub(crate) fn create(prefix: &str) -> std::io::Result<Self> {
        Ok(Self {
            path: create_run_profile_dir(prefix)?,
            armed: true,
        })
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Give up ownership **without** deleting: the caller becomes responsible
    /// for the directory (used when a `BrowserProcess` records it for
    /// `Drop`/`kill` cleanup).
    pub(crate) fn into_path(mut self) -> PathBuf {
        self.armed = false;
        std::mem::take(&mut self.path)
    }
}

impl Drop for RunProfileDir {
    fn drop(&mut self) {
        if self.armed {
            remove_run_profile_dir(&self.path);
        }
    }
}

/// First numeric `-`-separated field of a profile dir name suffix.
///
/// Per-run names are `<pid>-<seq>`; the legacy pipe form was
/// `pipe-<pid>-<seq>` and the legacy WebSocket form was the bare debug port.
/// The port case can only ever make the sweep *skip* a dir (a live PID equals
/// the port), never remove a live one.
fn first_numeric_field(s: &str) -> Option<u32> {
    s.split('-').find_map(|part| part.parse::<u32>().ok())
}

/// Remove stale per-run profile directories left behind by browsers that are
/// confirmed dead (crash / SIGKILL, or runs from before this cleanup existed).
///
/// Mirrors [`cleanup_stale_processes`]: liveness is probed with `kill(pid, 0)`,
/// so a profile belonging to a live — or unprobeable — PID is never removed,
/// and the current process's own dirs are skipped outright.
pub fn cleanup_stale_profile_dirs() {
    let base = std::env::temp_dir();
    let entries = match std::fs::read_dir(&base) {
        Ok(e) => e,
        Err(_) => return,
    };
    let own_pid = std::process::id();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = RUN_PROFILE_PREFIXES
            .iter()
            .find_map(|p| name.strip_prefix(p))
        else {
            continue;
        };
        let Some(pid) = first_numeric_field(rest) else {
            continue;
        };
        if pid == own_pid || process_is_alive(pid) {
            continue;
        }
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        remove_run_profile_dir(&path);
    }
}

/// Get the directory for Tallow browser PID files.
fn tallow_browsers_dir() -> Option<PathBuf> {
    // Use LOCALAPPDATA on Windows, HOME/.tallow on others
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|p| PathBuf::from(p).join("tallow").join("browsers"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .ok()
            .map(|p| PathBuf::from(p).join(".tallow").join("browsers"))
    }
}

/// PIDs of browsers launched by the CURRENT process.
///
/// `cleanup_stale_processes` skips these so a second `BrowserProcess::launch`
/// can never reap (or remove the PID file of) a sibling browser owned by this
/// process.
static OWN_BROWSER_PIDS: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();

fn own_browser_pids() -> &'static Mutex<HashSet<u32>> {
    OWN_BROWSER_PIDS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Write a PID file for zombie cleanup.
///
/// The PID is registered in [`OWN_BROWSER_PIDS`] first so stale-process
/// cleanup never touches it, even if the file write fails.
fn write_pid_file(pid: u32) -> Option<PathBuf> {
    if let Ok(mut own) = own_browser_pids().lock() {
        own.insert(pid);
    }
    let dir = tallow_browsers_dir()?;
    if std::fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let path = dir.join(format!("{pid}.pid"));
    if std::fs::write(&path, pid.to_string()).is_ok() {
        Some(path)
    } else {
        None
    }
}

/// Remove stale browser PID files left behind by previous runs.
///
/// Reads PID files from `~/.tallow/browsers/` and removes only those whose
/// recorded process is *confirmed dead* (liveness probe `kill(pid, 0)`
/// returning ESRCH — no such process).
///
/// SAFETY: this function NEVER kills a process and NEVER deletes the PID file
/// of a running browser. A live PID may belong to a sibling browser launched
/// by another session or another process of this program; PID files carry no
/// ownership information, so the only safe action is to leave live processes
/// (and their PID files) alone. PID files written by the CURRENT process are
/// always skipped. This replaces the previous behavior that SIGKILLed every
/// PID found in the directory, which murdered still-running sibling browsers
/// on every second `BrowserProcess::launch`.
pub fn cleanup_stale_processes() {
    let Some(dir) = tallow_browsers_dir() else {
        return;
    };

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let own = own_browser_pids()
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "pid").unwrap_or(false) {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(pid) = content.trim().parse::<u32>() {
                    // Never touch browsers owned by the current process.
                    if own.contains(&pid) {
                        continue;
                    }
                    // Only remove the file when the process is confirmed gone.
                    // Running (or unknown) processes keep their PID files.
                    if !process_is_alive(pid) {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
    }
}

/// Liveness probe for a PID.
///
/// Returns `false` only when the process is confirmed gone (`kill(pid, 0)`
/// failed with ESRCH — no such process). Every other outcome — signal
/// delivered (alive), EPERM (exists but not ours to signal), EINVAL, or a
/// probe failure — returns `true` so callers err on the side of NOT touching
/// the process or its PID file.
fn process_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: signal 0 only probes for process existence; it never
        // delivers a signal to the target process.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return true; // process exists (and we may signal it)
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => false, // no such process → stale
            _ => true,                  // EPERM etc. → assume alive
        }
    }
    #[cfg(windows)]
    {
        // `tasklist /FI "PID eq N" /NH` lists the process iff it is running.
        match Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
        {
            Ok(out) => String::from_utf8_lossy(&out.stdout).contains(&pid.to_string()),
            Err(_) => true, // probe failed → assume alive
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        true
    }
}

/// Find the Chrome/Chromium executable path on the current platform.
///
/// Linux: prefers a Tallow-managed install (see `browser::download`) over
/// PATH probes — snap-branded `chromium` builds cannot expose CDP under root.
pub fn find_chrome_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ];
        for path in &candidates {
            let p = PathBuf::from(path);
            if p.exists() {
                return p;
            }
        }
        // Check LOCALAPPDATA
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(&local).join(r"Google\Chrome\Application\chrome.exe");
            if p.exists() {
                return p;
            }
        }
        PathBuf::from("chrome.exe")
    }
    #[cfg(target_os = "macos")]
    {
        let candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ];
        for path in &candidates {
            let p = PathBuf::from(path);
            if p.exists() {
                return p;
            }
        }
        PathBuf::from("google-chrome")
    }
    #[cfg(target_os = "linux")]
    {
        // Prefer the browser Tallow manages itself (checksum-stamped under
        // ~/.local/share/tallow/browsers; the calibrated D4 legs use it). The
        // `which` chain below can otherwise resolve to a snap/system chromium
        // whose confinement never opens the DevTools HTTP endpoint under root
        // (observed 2026-09-14: /snap/bin/chromium → check_egress browser arms
        // timed out with no CDP endpoint).
        if let Some(managed) = crate::browser::download::find_installed_chrome() {
            return managed;
        }
        let candidates = [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
        ];
        for name in &candidates {
            if Command::new("which")
                .arg(name)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
            {
                return PathBuf::from(name);
            }
        }
        PathBuf::from("google-chrome")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        PathBuf::from("chrome")
    }
}

/// Environment values that disable the browser-child Landlock confinement
/// (RT-FIX-7A). Any of `0|off|false|no` (case-insensitive).
fn browser_landlock_disabled_from(value: Option<&str>) -> bool {
    matches!(
        value.map(str::to_ascii_lowercase).as_deref(),
        Some("0" | "off" | "false" | "no")
    )
}

fn browser_landlock_disabled() -> bool {
    browser_landlock_disabled_from(std::env::var("TALLOW_BROWSER_LANDLOCK").ok().as_deref())
}

/// Resolve a possibly-relative chrome path to an executable path: absolute
/// paths pass through (canonicalized when possible); bare names are looked up
/// on `PATH` (mirrors `find_chrome_path`'s name-only fallback).
fn resolve_chrome_binary(chrome: &std::path::Path) -> Option<PathBuf> {
    if chrome.is_absolute() {
        return Some(chrome.canonicalize().unwrap_or_else(|_| chrome.to_path_buf()));
    }
    let name = chrome.to_str()?;
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(name);
        if cand.exists() {
            return Some(cand);
        }
    }
    None
}

/// Read+execute roots granted to the browser child under Landlock (RT-FIX-7A).
///
/// System roots cover the loader, TLS stores, fonts and `/proc`/`/sys`/`/dev`
/// probes; the browser's own install tree (managed browsers live under user
/// dirs) and the per-run profile directory are added explicitly. Everything
/// else — notably home/root trees that are not part of the install — stays
/// unreadable to the child. Best-effort by construction: kernels without
/// Landlock skip the hook (see `crate::sandbox_runtime`), so this only *adds*
/// a fence. `TALLOW_BROWSER_LANDLOCK_PATHS` (colon-separated) extends the set
/// for unusual installs.
pub fn browser_landlock_read_paths(
    config: &BrowserConfig,
    profile: &std::path::Path,
) -> Vec<PathBuf> {
    browser_landlock_read_paths_with(
        config,
        profile,
        std::env::var("TALLOW_BROWSER_LANDLOCK_PATHS").ok().as_deref(),
    )
}

fn browser_landlock_read_paths_with(
    config: &BrowserConfig,
    profile: &std::path::Path,
    extra: Option<&str>,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = [
        "/usr", "/etc", "/lib", "/lib64", "/bin", "/sbin", "/opt", "/snap", "/run", "/dev",
        "/proc", "/sys", "/tmp", "/var/tmp", "/var/cache",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|p| p.exists())
    .collect();

    if let Some(bin) = resolve_chrome_binary(&config.chrome_path) {
        if let Some(dir) = bin.parent() {
            paths.push(dir.to_path_buf());
        }
    }
    if profile.is_dir() {
        paths.push(profile.to_path_buf());
    }
    // The browser child creates its shared-memory files directly in TMPDIR
    // (`--disable-dev-shm-usage`) and crashpad state under the same temp.
    // When the invoking environment carries a non-standard temp dir (Hermes
    // worker scratch dirs, playwright caches, ...), denying it here made
    // Chromium die immediately with EACCES on that create — surfacing as a
    // misleading devtools-endpoint timeout (observed live 2026-10-02).
    // Grant whatever temp the child will actually use, not just /tmp.
    let env_tmp = std::env::temp_dir();
    if env_tmp.is_absolute() {
        paths.push(env_tmp);
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime_dir.is_empty() {
            paths.push(PathBuf::from(runtime_dir));
        }
    }
    if let Some(extra) = extra {
        for p in extra.split(':').filter(|s| !s.is_empty()) {
            let p = PathBuf::from(p);
            if p.exists() || p.is_absolute() {
                paths.push(p);
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page loaded in the browser must not be able to reach the box's own
    /// loopback services. Chromium bypasses the proxy for loopback unless the
    /// bypass list carries `<-loopback>`, so asserting the token is the cheap
    /// guard against a regression that reopens prometheus/node_exporter/
    /// tallow-admin/Tor-control to every visited page.
    #[test]
    fn chrome_proxy_bypass_forces_loopback_through_the_proxy() {
        assert!(
            CHROME_PROXY_BYPASS_LIST.contains("<-loopback>"),
            "bypass list must remove Chromium's implicit loopback bypass"
        );
        // The old value named exactly the hosts that must stay unreachable.
        assert!(!CHROME_PROXY_BYPASS_LIST.contains("localhost"));
        assert!(!CHROME_PROXY_BYPASS_LIST.contains("127.0.0.1"));
    }

    #[test]
    fn test_browser_config_default() {
        let config = BrowserConfig::default();
        assert!(config.headless);
        assert!(config.port.is_none());
        assert!(config.args.is_empty());
        assert!(config.user_data_dir.is_none());
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_backend_default_is_chromium() {
        let config = BrowserConfig::default();
        assert_eq!(config.backend, BrowserBackend::Chromium);
    }

    #[test]
    fn test_backend_from_name_parses_all_variants() {
        assert_eq!(BrowserBackend::from_name("chromium"), Some(BrowserBackend::Chromium));
        assert_eq!(BrowserBackend::from_name("chrome"), Some(BrowserBackend::Chromium));
        assert_eq!(BrowserBackend::from_name("camoufox"), Some(BrowserBackend::Camoufox));
        assert_eq!(BrowserBackend::from_name("CAMOU"), Some(BrowserBackend::Camoufox));
        assert_eq!(BrowserBackend::from_name("firefox"), Some(BrowserBackend::Firefox));
        assert_eq!(BrowserBackend::from_name("geckodriver"), Some(BrowserBackend::Firefox));
        assert_eq!(BrowserBackend::from_name("unknown"), None);
    }

    #[test]
    fn test_backend_as_str() {
        assert_eq!(BrowserBackend::Chromium.as_str(), "chromium");
        assert_eq!(BrowserBackend::Camoufox.as_str(), "camoufox");
        assert_eq!(BrowserBackend::Firefox.as_str(), "firefox");
    }

    #[test]
    fn test_strip_proxy_credentials_drops_per_run_identity() {
        // The fail-closed default binds a per-run SOCKS identity into the
        // URL; Chromium can't speak it and every load fails empty (2026-10-02).
        assert_eq!(
            strip_proxy_credentials("socks5://tallow-1234-abcd:deadbeef@127.0.0.1:9050"),
            "socks5://127.0.0.1:9050"
        );
        assert_eq!(
            strip_proxy_credentials("socks5://127.0.0.1:9050"),
            "socks5://127.0.0.1:9050"
        );
        assert_eq!(
            strip_proxy_credentials("http://user:pass@10.0.0.1:3128"),
            "http://10.0.0.1:3128"
        );
    }

    #[test]
    fn test_normalize_then_strip_composes_like_the_launch_path() {
        let url = normalize_proxy_scheme("socks5h://tallow-9-ffff:0011@127.0.0.1:9050");
        assert_eq!(strip_proxy_credentials(&url), "socks5://127.0.0.1:9050");
    }

    
    
    
    #[test]
    fn test_browser_config_custom() {
        let config = BrowserConfig {
            chrome_path: PathBuf::from("/usr/bin/chromium"),
            headless: false,
            port: Some(9222),
            args: vec!["--no-sandbox".to_string()],
            user_data_dir: Some(PathBuf::from("/tmp/chrome-data")),
            timeout: Duration::from_secs(60),
            stealth: false,
            proxy: None,
            proxy_pac: None,
            use_pipe: false,
            backend: BrowserBackend::Chromium,
        };

        assert!(!config.headless);
        assert_eq!(config.port, Some(9222));
        assert_eq!(config.args.len(), 1);
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_browser_config_headless_default_is_true() {
        let config = BrowserConfig::default();
        assert!(config.headless, "BrowserConfig should default to headless: true");
    }

    #[test]
    fn test_browser_config_headless_false_omits_headless_flag() {
        // When headless is false, the --headless=new flag should NOT be in args
        let config = BrowserConfig {
            headless: false,
            ..BrowserConfig::default()
        };
        // Build a Command manually to verify args would be set correctly
        // We can't easily inspect Command args, so we verify the config field
        assert!(!config.headless);
    }

    #[test]
    fn test_browser_config_headless_true_has_headless_flag() {
        let config = BrowserConfig {
            headless: true,
            ..BrowserConfig::default()
        };
        assert!(config.headless);
    }

    #[test]
    fn test_find_available_port() {
        let port = find_available_port().unwrap();
        assert!(port > 0);
        // Verify the port is in the ephemeral range
        assert!(port >= 1024);
    }

    #[test]
    fn test_find_available_port_is_unique() {
        let port1 = find_available_port().unwrap();
        let port2 = find_available_port().unwrap();
        // Ports may or may not be different (OS can reuse), but both should be valid
        assert!(port1 > 0);
        assert!(port2 > 0);
    }

    #[test]
    fn test_stealth_flag_default_false() {
        let config = BrowserConfig::default();
        assert!(!config.stealth, "BrowserConfig should default to stealth: false");
    }

    #[test]
    fn test_stealth_flag_enables_stealth_args() {
        // Verify that stealth: true would add the correct flags.
        // We can't easily inspect Command args, so we verify the config
        // and test the flag names that would be passed.
        let config = BrowserConfig {
            stealth: true,
            proxy: None,
            ..BrowserConfig::default()
        };
        assert!(config.stealth);
        // The flags that should be added when stealth=true:
        let expected_flags = [
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
        ];
        for flag in &expected_flags {
            assert!(!flag.is_empty());
        }
    }

    #[test]
    fn test_stealth_false_does_not_add_stealth_args() {
        let config = BrowserConfig {
            stealth: false,
            proxy: None,
            ..BrowserConfig::default()
        };
        assert!(!config.stealth);
    }

    #[test]
    fn test_find_chrome_path_returns_something() {
        let path = find_chrome_path();
        // Should return a non-empty path (even if Chrome isn't installed)
        assert!(!path.to_string_lossy().is_empty());
    }

    #[test]
    fn test_tallow_browsers_dir() {
        let dir = tallow_browsers_dir();
        // Should return Some on most systems (HOME or LOCALAPPDATA is set)
        if dir.is_some() {
            let d = dir.unwrap();
            assert!(d.to_string_lossy().contains("tallow"));
            assert!(d.to_string_lossy().contains("browsers"));
        }
    }

    // -----------------------------------------------------------------------
    // Phase 48-01: Performance flags tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_performance_flags_count() {
        let flags = BrowserConfig::performance_flags();
        assert!(
            flags.len() >= 20,
            "performance_flags should have at least 20 flags, got {}",
            flags.len()
        );
    }

    #[test]
    fn test_performance_flags_content() {
        let flags = BrowserConfig::performance_flags();
        assert!(flags.contains(&"--disable-gpu".to_string()));
        assert!(flags.contains(&"--disable-extensions".to_string()));
        assert!(flags.contains(&"--no-first-run".to_string()));
        assert!(flags.contains(&"--mute-audio".to_string()));
        assert!(flags.contains(&"--disable-background-networking".to_string()));
        assert!(flags.contains(&"--disable-background-timer-throttling".to_string()));
        assert!(flags.contains(&"--disable-renderer-backgrounding".to_string()));
        assert!(flags.contains(&"--disable-backgrounding-occluded-windows".to_string()));
        assert!(flags.contains(&"--metrics-recording-only".to_string()));
        // W2-10 / S4 (audit-05 F-5): the preset no longer downgrades Chrome's
        // cookie encryption — see `test_no_password_store_basic_in_production_code`
        // and the stealth-list test below.
        assert!(
            !flags.contains(&"--password-store=basic".to_string()),
            "performance preset must not force --password-store=basic (W2-10/S4)"
        );
    }

    #[test]
    fn test_performance_flags_no_duplicates() {
        let flags = BrowserConfig::performance_flags();
        let mut seen = std::collections::HashSet::new();
        for flag in &flags {
            assert!(seen.insert(flag), "duplicate flag: {flag}");
        }
    }

    #[test]
    fn test_max_performance_flags_extends_performance_flags() {
        let perf_flags = BrowserConfig::performance_flags();
        let max_flags = BrowserConfig::max_performance_flags();
        assert!(max_flags.len() > perf_flags.len());
        for flag in &perf_flags {
            assert!(
                max_flags.contains(flag),
                "max_performance_flags missing: {flag}"
            );
        }
    }

    #[test]
    fn test_max_performance_flags_extra_content() {
        let max_flags = BrowserConfig::max_performance_flags();
        let has_disable_features = max_flags.iter().any(|f| f.contains("--disable-features="));
        assert!(has_disable_features, "max_performance_flags should include --disable-features");
        assert!(max_flags.contains(&"--renderer-process-limit=5".to_string()));
        assert!(max_flags.contains(&"--js-flags=--max-old-space-size=512".to_string()));
    }

    #[test]
    fn test_max_performance_flags_count() {
        let flags = BrowserConfig::max_performance_flags();
        assert!(
            flags.len() >= 23,
            "max_performance_flags should have at least 23 flags, got {}",
            flags.len()
        );
    }
    // -----------------------------------------------------------------------
    // Pipe transport (--remote-debugging-pipe, fds 3/4)
    // -----------------------------------------------------------------------

    /// Write a tiny executable "chrome" stand-in that dumps its argv to
    /// `argv_file` and then parks until killed. Lets launch() be exercised
    /// without a real browser.
    #[cfg(unix)]
    fn fake_chrome(argv_file: &std::path::Path) -> PathBuf {
        let script = std::env::temp_dir().join(format!(
            "tallow-fake-chrome-{}-{}.sh",
            std::process::id(),
            argv_file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        let body = format!(
            "#!/bin/sh\necho \"$@\" > {}\nexec sleep 120\n",
            argv_file.display()
        );
        std::fs::write(&script, body).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[cfg(unix)]
    #[test]
    fn test_launch_accepts_use_pipe_and_passes_remote_debugging_pipe() {
        let argv_file = std::env::temp_dir().join(format!(
            "tallow-pipe-argv-launch-{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&argv_file);
        let script = fake_chrome(&argv_file);

        let config = BrowserConfig {
            chrome_path: script.clone(),
            use_pipe: true,
            timeout: Duration::from_secs(10),
            ..BrowserConfig::default()
        };
        let mut proc =
            BrowserProcess::launch(&config).expect("use_pipe launch must be accepted");

        // The fake chrome echoes its argv to the file; wait for it to land.
        let deadline = Instant::now() + Duration::from_secs(5);
        let argv = loop {
            if let Ok(text) = std::fs::read_to_string(&argv_file) {
                if !text.trim().is_empty() {
                    break text;
                }
            }
            assert!(
                Instant::now() < deadline,
                "fake chrome never wrote argv to {}",
                argv_file.display()
            );
            std::thread::sleep(Duration::from_millis(20));
        };

        assert!(
            argv.contains("--remote-debugging-pipe"),
            "pipe launch argv missing --remote-debugging-pipe: {argv}"
        );
        assert!(
            !argv.contains("--remote-debugging-port"),
            "pipe launch must not pass --remote-debugging-port: {argv}"
        );
        assert_eq!(proc.port, 0, "pipe mode must not reserve a TCP debug port");

        proc.kill();
        let _ = std::fs::remove_file(&argv_file);
        let _ = std::fs::remove_file(&script);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_launch_pipe_registers_ends_and_connects() {
        let argv_file = std::env::temp_dir().join(format!(
            "tallow-pipe-argv-connect-{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&argv_file);
        let script = fake_chrome(&argv_file);

        let config = BrowserConfig {
            chrome_path: script.clone(),
            use_pipe: true,
            timeout: Duration::from_secs(10),
            ..BrowserConfig::default()
        };
        let mut proc =
            BrowserProcess::launch(&config).expect("use_pipe launch must be accepted");

        // The launch registered fd 3/4 ends for this child's pid, so
        // connecting must succeed and yield a genuine pipe-transport client.
        let client = proc
            .connect_pipe_cdp()
            .await
            .expect("pipe ends registered by launch should connect");
        assert!(client.is_pipe_transport());
        assert_eq!(client.transport_mode(), crate::browser::TransportMode::Pipe);

        proc.kill();
        drop(client);
        let _ = std::fs::remove_file(&argv_file);
        let _ = std::fs::remove_file(&script);
    }

    // -----------------------------------------------------------------------
    // W2-10 / S4: per-run profile-directory lifecycle (audit-05 F-5, F-14)
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    fn dir_mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn test_run_profile_dir_is_owner_only_and_unique() {
        let a = RunProfileDir::create(RUN_PROFILE_PREFIXES[0]).unwrap();
        let b = RunProfileDir::create(RUN_PROFILE_PREFIXES[0]).unwrap();
        let (pa, pb) = (a.path().to_path_buf(), b.path().to_path_buf());

        assert_ne!(pa, pb, "two allocations must not share a profile dir");
        for p in [&pa, &pb] {
            assert!(p.is_dir(), "profile dir not created: {}", p.display());
            assert_eq!(
                dir_mode(p),
                0o700,
                "profile dir must be owner-only (0700): {}",
                p.display()
            );
            assert!(p.starts_with(std::env::temp_dir()));
            assert!(p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(RUN_PROFILE_PREFIXES[0]));
        }

        drop(a);
        assert!(!pa.exists(), "guard drop must delete its profile dir");
        assert!(pb.exists(), "one guard must not delete another dir");
        drop(b);
        assert!(!pb.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_profile_dir_ownership_transfer_and_removal_guard() {
        // `into_path` hands the dir to the caller without deleting it…
        let guard = RunProfileDir::create(RUN_PROFILE_PREFIXES[0]).unwrap();
        let path = guard.into_path();
        assert!(path.is_dir(), "into_path must not delete the directory");
        // …and `remove_run_profile_dir` deletes exactly that dir.
        remove_run_profile_dir(&path);
        assert!(!path.exists(), "remove_run_profile_dir must delete the dir");

        // Refusal 1: a foreign (unprefixed) dir under temp_dir() is left alone.
        let foreign = std::env::temp_dir().join(format!(
            "tallow-not-a-profile-{}-refusal",
            std::process::id()
        ));
        std::fs::create_dir_all(&foreign).unwrap();
        remove_run_profile_dir(&foreign);
        assert!(foreign.is_dir(), "unprefixed dir must be refused");
        let _ = std::fs::remove_dir_all(&foreign);

        // Refusal 2: a prefixed name that is NOT directly in temp_dir() is
        // refused too — the guard is the exact parent + prefix pair.
        let nested_root = std::env::temp_dir().join(format!(
            "tallow-nested-{}-refusal",
            std::process::id()
        ));
        let nested = nested_root.join(format!("{}{}-0", RUN_PROFILE_PREFIXES[0], std::process::id()));
        std::fs::create_dir_all(&nested).unwrap();
        remove_run_profile_dir(&nested);
        assert!(nested.is_dir(), "prefixed dir outside temp_dir() must be refused");
        let _ = std::fs::remove_dir_all(&nested_root);
    }

    #[cfg(unix)]
    #[test]
    fn test_cleanup_stale_profile_dirs_removes_dead_pid_only() {
        // A genuinely dead PID: spawn a trivial child and reap it.
        let mut child = Command::new("true").spawn().unwrap();
        let dead_pid = child.id();
        let _ = child.wait();

        // High seq numbers: never allocated by `RunProfileDir`, so this cannot
        // race parallel tests that own real per-run dirs.
        let stale = std::env::temp_dir().join(format!("{}{}-999999", RUN_PROFILE_PREFIXES[0], dead_pid));
        let live = std::env::temp_dir().join(format!(
            "{}{}-999998",
            RUN_PROFILE_PREFIXES[0],
            std::process::id()
        ));
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::create_dir_all(&live).unwrap();

        cleanup_stale_profile_dirs();

        assert!(!stale.exists(), "dead-PID profile dir must be swept");
        assert!(live.is_dir(), "current-process profile dir must be kept");
        let _ = std::fs::remove_dir_all(&live);
    }

    #[cfg(unix)]
    #[test]
    fn test_launch_creates_private_per_run_profile_and_kill_removes_it() {
        let argv_file = std::env::temp_dir().join(format!(
            "tallow-pipe-argv-profile-{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&argv_file);
        let script = fake_chrome(&argv_file);

        let config = BrowserConfig {
            chrome_path: script.clone(),
            use_pipe: true,
            timeout: Duration::from_secs(10),
            ..BrowserConfig::default()
        };
        let mut proc = BrowserProcess::launch(&config).expect("launch must succeed");

        let dir = proc
            .profile_dir
            .clone()
            .expect("launch must record the per-run profile dir it created");
        assert!(dir.is_dir(), "profile dir must exist while the browser runs");
        assert_eq!(dir_mode(&dir), 0o700, "profile dir must be 0700");
        assert!(dir.starts_with(std::env::temp_dir()));
        // F-14: the dir is keyed on (pid, launch seq), never on the debug port.
        assert!(
            dir.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&format!("{}{}-", RUN_PROFILE_PREFIXES[0], std::process::id())),
            "profile dir must be named <prefix><pid>-<seq>: {}",
            dir.display()
        );

        // The stub browser was pointed at exactly this dir.
        let deadline = Instant::now() + Duration::from_secs(5);
        let argv = loop {
            if let Ok(text) = std::fs::read_to_string(&argv_file) {
                if !text.trim().is_empty() {
                    break text;
                }
            }
            assert!(Instant::now() < deadline, "fake chrome never wrote argv");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            argv.contains(&format!("--user-data-dir={}", dir.display())),
            "stub browser argv missing --user-data-dir: {argv}"
        );

        proc.kill();
        assert!(
            !dir.exists(),
            "kill() must delete the per-run profile dir ({} still exists)",
            dir.display()
        );

        let _ = std::fs::remove_file(&argv_file);
        let _ = std::fs::remove_file(&script);
    }

    #[cfg(unix)]
    #[test]
    fn test_launch_keeps_caller_supplied_user_data_dir() {
        let owned = std::env::temp_dir().join(format!(
            "tallow-explicit-profile-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&owned).unwrap();

        let argv_file = std::env::temp_dir().join(format!(
            "tallow-pipe-argv-explicit-{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&argv_file);
        let script = fake_chrome(&argv_file);

        let config = BrowserConfig {
            chrome_path: script.clone(),
            use_pipe: true,
            user_data_dir: Some(owned.clone()),
            timeout: Duration::from_secs(10),
            ..BrowserConfig::default()
        };
        let mut proc = BrowserProcess::launch(&config).expect("launch must succeed");

        assert!(
            proc.profile_dir.is_none(),
            "an explicit user_data_dir must not be recorded for deletion"
        );
        proc.kill();
        assert!(
            owned.is_dir(),
            "caller-supplied profile dir must never be deleted by cleanup"
        );

        let _ = std::fs::remove_dir_all(&owned);
        let _ = std::fs::remove_file(&argv_file);
        let _ = std::fs::remove_file(&script);
    }

    /// Static guard (design S4): the decided-against locations must not
    /// reintroduce a CLI password-store downgrade anywhere in the browser stack.
    #[test]
    fn test_no_cli_password_store_downgrade_under_src_browser() {
        fn rs_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    rs_files(&path, out);
                } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                    out.push(path);
                }
            }
        }

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/browser");
        let mut files = Vec::new();
        rs_files(&root, &mut files);
        assert!(!files.is_empty(), "no rust files found under {}", root.display());

        let mut hits = Vec::new();
        for file in &files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            // Launch code only: unit-test modules legitimately name the flag in
            // their assertions, so the scan stops at `mod tests` and skips
            // comment lines.
            let production = text.split("\nmod tests").next().unwrap_or(&text);
            for (n, line) in production.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue; // comments may discuss the decision
                }
                if line.contains("--password-store") {
                    hits.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "CLI password-store flag found in browser launch code (W2-10/S4 decision: \
             use Chrome's platform default; restore per-run via browser.extra_args):\n{}",
            hits.join("\n")
        );
    }

    #[test]
    fn test_stealth_launch_flags_do_not_downgrade_password_store() {
        for flag in STEALTH_LAUNCH_FLAGS {
            assert!(
                !flag.contains("password-store"),
                "stealth flags must not force a password store: {flag}"
            );
        }
        // The list is the pre-W2-10 stealth set minus the password-store
        // downgrade (25 launch flags before, 24 now).
        assert_eq!(STEALTH_LAUNCH_FLAGS.len(), 24);
        assert!(STEALTH_LAUNCH_FLAGS.contains(&"--disable-blink-features=AutomationControlled"));
        assert!(STEALTH_LAUNCH_FLAGS.contains(&"--use-gl=swiftshader"));
        assert!(STEALTH_LAUNCH_FLAGS.contains(&"--enable-features=NetworkService,NetworkServiceInProcess"));
    }
}

#[cfg(test)]
mod landlock_tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")] // asserts the Linux Landlock root set
    fn landlock_read_paths_core_roots_profile_and_extra() {
        let cfg = BrowserConfig {
            chrome_path: PathBuf::from("/nonexistent/not-a-browser"),
            ..BrowserConfig::default()
        };
        let profile = std::env::temp_dir().join(format!("tallow-chrome-{}-0", std::process::id()));
        let _ = std::fs::create_dir_all(&profile);
        let paths = browser_landlock_read_paths_with(&cfg, &profile, Some("/opt/extra-root"));
        let has = |p: &std::path::Path| paths.iter().any(|x| x == p);
        assert!(has(std::path::Path::new("/usr")), "system root: {paths:?}");
        assert!(has(std::path::Path::new("/etc")));
        assert!(has(std::path::Path::new("/tmp")));
        assert!(
            has(std::env::temp_dir().as_path()),
            "env temp dir (TMPDIR) must be granted so the child's shm files work: {paths:?}"
        );
        assert!(has(profile.as_path()), "profile dir: {paths:?}");
        assert!(has(std::path::Path::new("/opt/extra-root")), "extra env root: {paths:?}");
        let _ = std::fs::remove_dir(&profile);
    }

    #[test]
    fn debug_endpoint_parse_strips_path_forbidden() {
        // Regression (2026-10-02): the URL path leaked into the SocketAddr
        // parse, so discovery silently polled 127.0.0.1:9222 forever.
        let url = "http://127.0.0.1:2365/json/version";
        let hp = url
            .strip_prefix("http://")
            .and_then(|rest| rest.split('/').next())
            .and_then(|hp| hp.parse::<std::net::SocketAddr>().ok())
            .expect("host:port must parse with path present");
        assert_eq!(hp.port(), 2365);
        assert_eq!(hp.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn landlock_read_paths_include_install_tree_and_managed_browser() {
        // Synthetic install tree (hermetic): the binary's directory must be
        // granted read+execute.
        let tmp = std::env::temp_dir().join(format!("tallow-fake-browsers-{}", std::process::id()));
        let bin_dir = tmp.join("chrome-v1");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let bin = bin_dir.join("chrome");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        let cfg = BrowserConfig { chrome_path: bin.clone(), ..BrowserConfig::default() };
        let profile = std::env::temp_dir().join(format!("tallow-chrome-{}-1", std::process::id()));
        let _ = std::fs::create_dir_all(&profile);
        let paths = browser_landlock_read_paths_with(&cfg, &profile, None);
        // Compare after canonicalize: macOS resolves /var -> /private/var, so a
        // raw comparison against env::temp_dir() fails for a correct result.
        let want = bin_dir.canonicalize().unwrap_or_else(|_| bin_dir.clone());
        assert!(
            paths.iter().any(|p| p.canonicalize().unwrap_or_else(|_| p.clone()) == want),
            "install tree: {paths:?}"
        );

        // Real managed browser on this box (when present): its directory too.
        let managed = find_chrome_path();
        if managed.is_absolute() && managed.exists() {
            let cfg = BrowserConfig { chrome_path: managed.clone(), ..BrowserConfig::default() };
            let paths = browser_landlock_read_paths_with(&cfg, &profile, None);
            let dir = managed.canonicalize().unwrap_or(managed.clone());
            let dir = dir.parent().expect("binary has a parent").to_path_buf();
            assert!(paths.iter().any(|p| p == &dir), "managed tree: {paths:?}");
        }
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir(&profile);
    }

    #[test]
    fn landlock_disable_env_parsing() {
        assert!(browser_landlock_disabled_from(Some("0")));
        assert!(browser_landlock_disabled_from(Some("OFF")));
        assert!(browser_landlock_disabled_from(Some("False")));
        assert!(browser_landlock_disabled_from(Some("no")));
        assert!(!browser_landlock_disabled_from(None));
        assert!(!browser_landlock_disabled_from(Some("1")));
        assert!(!browser_landlock_disabled_from(Some("on")));
    }
}

