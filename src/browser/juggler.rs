//! Juggler protocol client for Firefox-family browsers (Camoufox / Firefox).
//!
//! Playwright drives Firefox via the "Juggler" protocol over a pipe
//! (`-juggler-pipe`): JSON messages delimited by a NUL byte. Commands are
//! written to fd 3, responses/events are read from fd 4. The message model
//! mirrors CDP (`Domain.method` + `id`/`result`/`error`/`sessionId`).
//!
//! This module implements the minimal client needed for Tallow's browser path:
//! launch, `Browser.enable`, `Browser.newPage`, `Page.navigate`,
//! `Runtime.evaluate`, `Browser.close`, plus event delivery (used to learn a
//! page's `sessionId` from `Browser.attachedToTarget`).
//!
//! Reference: Playwright's `server/firefox/{firefox,ffBrowser,ffConnection,
//! pipeTransport,ffExecutionContext}.js`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, Read, Write};
// The pipe transport below passes file descriptors 3/4 to the child, so it is
// Unix-only; the Windows build gets a `launch` that refuses with that reason
// instead of a module that does not compile.
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::error::BrowserError;
use super::process::{BrowserConfig, RunProfileDir, RUN_PROFILE_PREFIXES};

type Pending = Arc<Mutex<HashMap<i64, Sender<Result<serde_json::Value, String>>>>>;
type Events = Arc<Mutex<mpsc::Receiver<serde_json::Value>>>;

/// A connected Juggler session (browser root + page sessions share this client;
/// page-level commands are multiplexed via `sessionId`).
pub struct JugglerClient {
    writer: Arc<Mutex<File>>,
    next_id: AtomicI64,
    pending: Pending,
    events: Events,
    /// Default per-command timeout.
    timeout: Duration,
}

impl JugglerClient {
    /// Spawn a Firefox-family binary with `-juggler-pipe` and connect to it.
    ///
    /// Returns the child process (for lifecycle/cleanup), a connected client,
    /// and — when this call created the profile itself — the profile directory
    /// so the caller can delete it on browser exit (W2-10 / S4). `None` means
    /// the caller supplied an explicit `user_data_dir`.
    /// Blocks until Firefox signals readiness (`Juggler listening to the pipe`).
    #[cfg(unix)]
    pub fn launch(
        config: &BrowserConfig,
    ) -> Result<(Child, Self, Option<std::path::PathBuf>), BrowserError> {
        // T-207-fu (P4-15 residual): the Firefox/Camoufox launch rides the
        // zone egress contract exactly like the Chromium branch in
        // `process.rs` — an explicit per-launch proxy wins; otherwise the
        // zone predicate decides (Tor SOCKS by default, `TALLOW_PROXY`
        // override, `TALLOW_ALLOW_DIRECT=1` the only direct opt-in). A
        // malformed contract proxy refuses HERE, before a process exists:
        // Firefox must never spawn unproxied off the box IP (N3).
        let zone_proxy: Option<String> = match config.proxy.as_deref() {
            Some(p) => Some(p.to_string()),
            None => super::zone::browser_zone_firefox_proxy()
                .map_err(BrowserError::ConnectionFailed)?,
        };
        // Firefox has no `--proxy-server`; the contract reaches it through
        // profile `user.js` prefs. A contract proxy the prefs cannot express
        // refuses the launch rather than spawning a direct Firefox.
        let proxy_prefs = match &zone_proxy {
            Some(p) => super::zone::firefox_user_js_proxy_prefs(p)
                .map_err(BrowserError::ConnectionFailed)?,
            None => Vec::new(),
        };

        // Two unix socket pairs: commands (we write → firefox fd 3) and
        // responses (firefox fd 4 → we read).
        let (cmd_write, cmd_read) = std::os::unix::net::UnixStream::pair()
            .map_err(|e| BrowserError::ConnectionFailed(format!("pipe cmd: {e}")))?;
        let (resp_write, resp_read) = std::os::unix::net::UnixStream::pair()
            .map_err(|e| BrowserError::ConnectionFailed(format!("pipe resp: {e}")))?;

        let mut cmd = Command::new(&config.chrome_path);
        cmd.arg("-no-remote");
        if config.headless {
            cmd.arg("-headless");
        }

        // The Juggler remote protocol is only active when `remote.enabled=true`,
        // which must be written to `user.js` in the profile BEFORE launch
        // (otherwise `-juggler-pipe` silently does nothing). Prepare the profile
        // dir, then point `-profile` at it. Treat an empty-string
        // `user_data_dir` as "none" (an empty path makes Firefox use the CWD as
        // its profile, where `remote.enabled` never activates and Juggler
        // silently never starts).
        // Juggler profiles get the same per-run lifecycle as Chromium ones
        // (W2-10 / S4): owner-only (0700), keyed on (pid, launch seq) — the old
        // name was per-pid only, so two Firefox launches in one process shared
        // a profile — and deleted when the browser exits.
        let (profile_dir, profile_guard) = match &config.user_data_dir {
            Some(dir) if !dir.to_string_lossy().is_empty() => (dir.clone(), None),
            _ => {
                let guard = RunProfileDir::create(RUN_PROFILE_PREFIXES[1]).map_err(|e| {
                    BrowserError::ConnectionFailed(format!(
                        "failed to create per-run juggler profile dir: {e}"
                    ))
                })?;
                (guard.path().to_path_buf(), Some(guard))
            }
        };
        prepare_profile(&profile_dir, &proxy_prefs).map_err(|e| {
            BrowserError::ConnectionFailed(format!("failed to prepare profile: {e}"))
        })?;
        cmd.arg("-profile");
        cmd.arg(&profile_dir);

        cmd.arg("-juggler-pipe");
        cmd.arg("-silent");
        // Mirror the Chromium branch: inherited proxy env vars must not
        // survive into the child — the contract reaches Firefox through the
        // profile prefs above, and a stale `socks5h://` env var would fight
        // them (unparseable in env form) instead of composing.
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
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let cmd_read_fd = cmd_read.as_raw_fd();
        let resp_write_fd = resp_write.as_raw_fd();

        // In the child, wire fd 3 = command read end, fd 4 = response write end.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(cmd_read_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(resp_write_fd, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = cmd.spawn().map_err(|e| {
            BrowserError::ConnectionFailed(format!(
                "failed to launch {} at {}: {e}",
                config.backend.as_str(),
                config.chrome_path.display()
            ))
        })?;

        // Parent no longer needs the child-side ends.
        drop(cmd_read);
        drop(resp_write);

        // Drain stdout AND stderr on background threads (so Firefox never blocks
        // on a full pipe buffer). The Juggler ready signal ("Juggler listening to
        // the pipe") is written to STDOUT — watch the combined stream with a hard
        // timeout.
        let (log_tx, log_rx) = mpsc::channel::<String>();
        if let Some(stdout) = child.stdout.take() {
            let tx = log_tx.clone();
            std::thread::spawn(move || drain_lines(stdout, tx));
        }
        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || drain_lines(stderr, log_tx));
        }

        wait_for_juggler_ready(&log_rx, config.timeout).map_err(|e| {
            let _ = child.kill();
            e
        })?;

        let writer = File::from(OwnedFd::from(cmd_write));
        let reader = File::from(OwnedFd::from(resp_read));

        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, event_rx) = mpsc::channel();
        let events: Events = Arc::new(Mutex::new(event_rx));

        let pending_clone = pending.clone();
        std::thread::spawn(move || read_loop(reader, pending_clone, event_tx));

        Ok((
            child,
            JugglerClient {
                writer: Arc::new(Mutex::new(writer)),
                next_id: AtomicI64::new(0),
                pending,
                events,
                timeout: config.timeout,
            },
            profile_guard.map(RunProfileDir::into_path),
        ))
    }

    /// Send a command and block for its result.
    /// Windows: the Juggler pipe transport is unavailable.
    ///
    /// `-juggler-pipe` hands the browser two descriptors (3 = commands in,
    /// 4 = responses out) that are only expressible as inherited file
    /// descriptors on a Unix-like OS. Rather than ship a silent no-op, the
    /// launch refuses and names the working alternative.
    #[cfg(not(unix))]
    pub fn launch(
        config: &BrowserConfig,
    ) -> Result<(Child, Self, Option<std::path::PathBuf>), BrowserError> {
        let _ = config;
        Err(BrowserError::ConnectionFailed(
            "the Firefox/Camoufox Juggler transport passes its protocol pipes as \
             file descriptors 3 and 4, which requires a Unix-like OS; use the \
             Chromium/CDP backend on this platform"
                .to_string(),
        ))
    }

    pub fn send(
        &self,
        method: &str,
        params: serde_json::Value,
        session_id: Option<&str>,
    ) -> Result<serde_json::Value, BrowserError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let mut msg = serde_json::json!({ "id": id, "method": method, "params": params });
        if let Some(sid) = session_id {
            msg.as_object_mut()
                .unwrap()
                .insert("sessionId".into(), serde_json::Value::String(sid.into()));
        }
        let line = format!("{}\0", serde_json::to_string(&msg).unwrap());

        {
            let mut w = self.writer.lock().unwrap();
            w.write_all(line.as_bytes()).map_err(|e| {
                BrowserError::ConnectionFailed(format!("juggler write {method}: {e}"))
            })?;
            w.flush()
                .map_err(|e| BrowserError::ConnectionFailed(format!("juggler flush: {e}")))?;
        }

        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(id, tx);

        let deadline = Instant::now() + self.timeout;
        loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(msg)) => {
                    return Err(BrowserError::ConnectionFailed(format!("{method}: {msg}")))
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if Instant::now() > deadline {
                        self.pending.lock().unwrap().remove(&id);
                        return Err(BrowserError::ConnectionFailed(format!(
                            "juggler command {method} timed out after {:?}",
                            self.timeout
                        )));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(BrowserError::ConnectionFailed(format!(
                        "juggler reader terminated during {method}"
                    )))
                }
            }
        }
    }

    /// Pop the next browser event (e.g. `Browser.attachedToTarget`), if any.
    pub fn next_event(&self) -> Result<serde_json::Value, BrowserError> {
        let rx = self.events.lock().unwrap();
        // Re-lock-free recv: we hold the mutex; recv is a blocking call but that
        // is fine — callers only poll when they expect an event.
        drop(rx);
        let ev = self
            .events
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| BrowserError::ConnectionFailed("juggler event channel closed".into()))?;
        Ok(ev)
    }

    /// Wait for a `Browser.attachedToTarget` event whose `targetInfo.targetId`
    /// matches `target_id`, returning the page's `sessionId`.
    pub fn wait_for_session(&self, target_id: &str, timeout: Duration) -> Result<String, BrowserError> {
        let deadline = Instant::now() + timeout;
        loop {
            let rx = self.events.lock().unwrap();
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(ev) => {
                    if ev.get("method").and_then(|m| m.as_str()) == Some("Browser.attachedToTarget") {
                        let params = ev.get("params").cloned().unwrap_or_default();
                        let target = params
                            .get("targetInfo")
                            .and_then(|t| t.get("targetId"))
                            .and_then(|t| t.as_str())
                            .unwrap_or("");
                        if target == target_id {
                            if let Some(sid) = params.get("sessionId").and_then(|s| s.as_str()) {
                                return Ok(sid.to_string());
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if Instant::now() > deadline {
                        return Err(BrowserError::ConnectionFailed(
                            "timed out waiting for Browser.attachedToTarget".into(),
                        ));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(BrowserError::ConnectionFailed("event channel closed".into()));
                }
            }
        }
    }

    /// `Browser.enable` on the root session.
    pub fn enable(&self, attach_to_default_context: bool) -> Result<serde_json::Value, BrowserError> {
        self.send(
            "Browser.enable",
            serde_json::json!({ "attachToDefaultContext": attach_to_default_context, "userPrefs": [] }),
            None,
        )
    }

    /// `Browser.getInfo` → `{ version, userAgent }`.
    pub fn get_info(&self) -> Result<serde_json::Value, BrowserError> {
        self.send("Browser.getInfo", serde_json::json!({}), None)
    }

    /// `Browser.newPage` → `{ targetId }`. Call `wait_for_session` next.
    pub fn new_page(&self) -> Result<String, BrowserError> {
        let r = self.send("Browser.newPage", serde_json::json!({}), None)?;
        r.get("targetId")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| BrowserError::ConnectionFailed("Browser.newPage returned no targetId".into()))
    }

    /// `Page.navigate` on a page session. `frame_id` is the main frame's id
    /// (from `wait_for_main_frame`).
    pub fn navigate(
        &self,
        session_id: &str,
        frame_id: &str,
        url: &str,
    ) -> Result<serde_json::Value, BrowserError> {
        self.send(
            "Page.navigate",
            serde_json::json!({ "url": url, "frameId": frame_id }),
            Some(session_id),
        )
    }

    /// Wait for the main frame's `Page.frameAttached` event on a page session
    /// (the main frame has no `parentFrameId`), returning its `frameId`.
    pub fn wait_for_main_frame(
        &self,
        session_id: &str,
        timeout: Duration,
    ) -> Result<String, BrowserError> {
        let deadline = Instant::now() + timeout;
        loop {
            let rx = self.events.lock().unwrap();
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(ev) => {
                    if ev.get("method").and_then(|m| m.as_str()) == Some("Page.frameAttached")
                        && ev.get("sessionId").and_then(|s| s.as_str()) == Some(session_id)
                    {
                        let params = ev.get("params").cloned().unwrap_or_default();
                        // Main frame has a null / absent parentFrameId.
                        let is_main = params
                            .get("parentFrameId")
                            .map(|p| p.is_null())
                            .unwrap_or(true);
                        if is_main {
                            if let Some(fid) = params.get("frameId").and_then(|f| f.as_str()) {
                                return Ok(fid.to_string());
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if Instant::now() > deadline {
                        return Err(BrowserError::ConnectionFailed(
                            "timed out waiting for Page.frameAttached".into(),
                        ));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(BrowserError::ConnectionFailed("event channel closed".into()));
                }
            }
        }
    }

    /// `Runtime.evaluate` on a page session; returns the `result.value` (the
    /// JSON-serialized JS value). `execution_context_id` comes from
    /// `wait_for_execution_context`.
    pub fn evaluate(
        &self,
        session_id: &str,
        execution_context_id: &str,
        expression: &str,
    ) -> Result<serde_json::Value, BrowserError> {
        let r = self.send(
            "Runtime.evaluate",
            serde_json::json!({
                "expression": expression,
                "returnByValue": true,
                "executionContextId": execution_context_id
            }),
            Some(session_id),
        )?;
        if let Some(exc) = r.get("exceptionDetails") {
            let text = exc
                .get("exception")
                .and_then(|e| e.get("description"))
                .and_then(|d| d.as_str())
                .unwrap_or("unknown JS exception");
            return Err(BrowserError::ConnectionFailed(format!("Runtime.evaluate: {text}")));
        }
        Ok(r.get("result")
            .and_then(|res| res.get("value"))
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Wait for the `Runtime.executionContextCreated` event for a frame, tracking
    /// the LATEST execution context (a navigation replaces the context, so the
    /// newest one is the one to use for evaluation). Returns after a short settle.
    pub fn wait_for_execution_context(
        &self,
        session_id: &str,
        frame_id: &str,
        timeout: Duration,
    ) -> Result<String, BrowserError> {
        let deadline = Instant::now() + timeout;
        let mut last_id: Option<String> = None;
        let mut last_seen = Instant::now();
        loop {
            let rx = self.events.lock().unwrap();
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(ev) => {
                    if ev.get("method").and_then(|m| m.as_str())
                        == Some("Runtime.executionContextCreated")
                        && ev.get("sessionId").and_then(|s| s.as_str()) == Some(session_id)
                    {
                        let params = ev.get("params").cloned().unwrap_or_default();
                        let ctx_frame = params
                            .get("auxData")
                            .and_then(|a| a.get("frameId"))
                            .and_then(|f| f.as_str());
                        if ctx_frame == Some(frame_id) {
                            if let Some(c) =
                                params.get("executionContextId").and_then(|c| c.as_str())
                            {
                                last_id = Some(c.to_string());
                                last_seen = Instant::now();
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(id) = &last_id {
                        if last_seen.elapsed() > Duration::from_millis(500) {
                            return Ok(id.clone());
                        }
                    }
                    if Instant::now() > deadline {
                        if let Some(id) = last_id {
                            return Ok(id);
                        }
                        return Err(BrowserError::ConnectionFailed(
                            "timed out waiting for Runtime.executionContextCreated".into(),
                        ));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(BrowserError::ConnectionFailed("event channel closed".into()));
                }
            }
        }
    }

    /// `Browser.close` on the root session.
    pub fn close(&self) -> Result<serde_json::Value, BrowserError> {
        self.send("Browser.close", serde_json::json!({}), None)
    }

    /// Set the browser-wide proxy via `Browser.setBrowserProxy`.
    ///
    /// Accepts `socks5://host:port`, `socks5h://host:port`, `http://host:port`,
    /// `https://host:port`.
    pub fn set_proxy(&self, proxy: &str) -> Result<serde_json::Value, BrowserError> {
        let (typ, host, port) = parse_proxy_url(proxy);
        self.send(
            "Browser.setBrowserProxy",
            serde_json::json!({
                "type": typ,
                "host": host,
                "port": port,
                "bypass": []
            }),
            None,
        )
    }
}

/// Split a proxy URL into Juggler `(type, host, port)`.
fn parse_proxy_url(proxy: &str) -> (&'static str, String, u16) {
    let (typ, rest) = if let Some(r) = proxy.strip_prefix("socks5h://") {
        ("socks", r)
    } else if let Some(r) = proxy.strip_prefix("socks5://") {
        ("socks", r)
    } else if let Some(r) = proxy.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = proxy.strip_prefix("http://") {
        ("http", r)
    } else {
        ("http", proxy)
    };
    let (host, port_str) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => (rest, "9050"),
    };
    (typ, host.to_string(), port_str.parse::<u16>().unwrap_or(9050))
}

/// A Juggler-driven page (Firefox-family backend: Camoufox / Firefox).
///
/// Wraps a connected [`JugglerClient`] plus the page's session/frame/execution
/// context so callers can drive navigation, JS evaluation, and title reads the
/// same way they do a CDP [`crate::browser::page::Page`], but over the Juggler
/// pipe transport instead of WebSocket CDP.
pub struct JugglerPage {
    client: Arc<JugglerClient>,
    session_id: String,
    frame_id: String,
    ctx: String,
    timeout: Duration,
}

impl JugglerPage {
    /// Enable the browser, open a new page, and resolve its session, main
    /// frame, and (latest) execution context.
    pub fn new(client: Arc<JugglerClient>, timeout: Duration) -> Result<Self, BrowserError> {
        client.enable(true)?;
        let target_id = client.new_page()?;
        let session_id = client.wait_for_session(&target_id, timeout)?;
        let frame_id = client.wait_for_main_frame(&session_id, timeout)?;
        let ctx = client.wait_for_execution_context(&session_id, &frame_id, timeout)?;
        Ok(Self {
            client,
            session_id,
            frame_id,
            ctx,
            timeout,
        })
    }

    /// Evaluate a JS expression in the page and return the JSON result value.
    pub fn evaluate(&self, expression: &str) -> Result<serde_json::Value, BrowserError> {
        self.client.evaluate(&self.session_id, &self.ctx, expression)
    }

    /// Apply the analytics/session-replay kill layer for the page.
    ///
    /// PRIMARY: registers the analytics-kill JS via
    /// `Page.addScriptToEvaluateOnNewDocument` so it runs before every new
    /// document — stubbing `window.clarity` (MS Clarity), `window.Sentry`,
    /// GTM/GA4 (`gtag`/`dataLayer`), and `sendBeacon`, and removing analytics
    /// script tags. This is the resilient layer (works even if the Network
    /// domain is unavailable).
    ///
    /// BEST-EFFORT: `Network.enable` + `Network.setBlockedURLs` hard-block the
    /// analytics domains at the network layer when the Juggler build supports
    /// it. Failures of the Network domain are tolerated (the JS layer covers it).
    pub fn apply_privacy(&self) -> Result<(), BrowserError> {
        let session = Some(self.session_id.as_str());
        let js = crate::browser::plugins::analytics_kill_js();
        self.client.send(
            "Page.addScriptToEvaluateOnNewDocument",
            serde_json::json!({ "source": js }),
            session,
        )?;
        let urls: Vec<String> = crate::browser::plugins::ANALYTICS_URLS
            .iter()
            .map(|s| s.to_string())
            .collect();
        let _ = self.client.send("Network.enable", serde_json::json!({}), session);
        let _ = self.client.send(
            "Network.setBlockedURLs",
            serde_json::json!({ "urls": urls }),
            session,
        );
        Ok(())
    }

    /// Evaluate a JS expression that reports whether the analytics kill took
    /// effect on the loaded document. Returns a compact JSON string describing
    /// the state of `window.clarity` / `window.Sentry` / `window.gtag` and the
    /// count of any `clarity.ms` / `sentry.io` script tags still present.
    pub fn privacy_status(&self) -> String {
        self.evaluate(
            r#"JSON.stringify({
                killed: (typeof window.__tallow_analytics_killed !== 'undefined'),
                clarity: (typeof window.clarity),
                sentry: (typeof window.Sentry),
                gtag: (typeof window.gtag),
                clarityScripts: Array.from(document.querySelectorAll('script[src*="clarity"]')).length,
                sentryScripts: Array.from(document.querySelectorAll('script[src*="sentry"]')).length
            })"#,
        )
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "{\"error\":\"evaluate failed\"}".to_string())
    }

    /// Navigate to `url`, then re-resolve the execution context (navigation
    /// replaces it).
    pub fn navigate(&mut self, url: &str) -> Result<serde_json::Value, BrowserError> {
        let r = self
            .client
            .navigate(&self.session_id, &self.frame_id, url)?;
        self.ctx = self
            .client
            .wait_for_execution_context(&self.session_id, &self.frame_id, self.timeout)?;
        Ok(r)
    }

    /// Read the current page title.
    pub fn title(&self) -> Result<String, BrowserError> {
        Ok(self
            .evaluate("document.title")?
            .as_str()
            .unwrap_or("")
            .to_string())
    }
}

/// Drain a child stdout/stderr stream line-by-line into a channel (so the child
/// never blocks on a full pipe buffer).
fn drain_lines(stream: impl Read, tx: mpsc::Sender<String>) {
    let mut r = std::io::BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if tx.send(line.clone()).is_err() {
                    break;
                }
            }
        }
    }
}

/// Prepare a Firefox profile directory with the prefs needed to enable the
/// Juggler remote protocol (`remote.enabled`) plus, when the zone contract
/// resolves to a proxy, the `network.proxy.*` lines that route the whole
/// browser over it (T-207-fu).
fn prepare_profile(dir: &std::path::Path, proxy_prefs: &[String]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut prefs = String::from(
        r#"user_pref("remote.enabled", true);
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.startup.page", 0);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.warnOnQuit", false);
"#,
    );
    for line in proxy_prefs {
        prefs.push_str(line);
        prefs.push('\n');
    }
    std::fs::write(dir.join("user.js"), prefs)
}

/// Block (with timeout) until `Juggler listening to the pipe` appears on the
/// stderr log channel.
fn wait_for_juggler_ready(
    rx: &mpsc::Receiver<String>,
    timeout: Duration,
) -> Result<(), BrowserError> {
    let deadline = Instant::now() + timeout;
    let mut acc = String::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(chunk) => {
                acc.push_str(&chunk);
                if acc.contains("Juggler listening to the pipe") {
                    return Ok(());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() > deadline {
                    return Err(BrowserError::ConnectionFailed(format!(
                        "timed out waiting for 'Juggler listening to the pipe'; stderr so far: {}",
                        acc.trim()
                    )));
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(BrowserError::ConnectionFailed(format!(
                    "Firefox stderr closed before Juggler ready; stderr: {}",
                    acc.trim()
                )));
            }
        }
    }
}

/// Background reader thread: split fd-4 stream on NUL, dispatch responses to
/// pending callers and events to the event channel.
fn read_loop(mut reader: File, pending: Pending, event_tx: Sender<serde_json::Value>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                while let Some(pos) = buf.iter().position(|&b| b == 0) {
                    let msg_bytes: Vec<u8> = buf.drain(..pos).collect();
                    if !buf.is_empty() {
                        buf.remove(0); // consume the NUL
                    }
                    if let Ok(msg) = serde_json::from_slice::<serde_json::Value>(&msg_bytes) {
                        match msg.get("id").and_then(|v| v.as_i64()) {
                            Some(id) => {
                                if let Some(tx) = pending.lock().unwrap().remove(&id) {
                                    if let Some(err) = msg.get("error") {
                                        let text = err
                                            .get("message")
                                            .and_then(|m| m.as_str())
                                            .unwrap_or("juggler error")
                                            .to_string();
                                        let _ = tx.send(Err(text));
                                    } else {
                                        let result = msg.get("result").cloned().unwrap_or_default();
                                        let _ = tx.send(Ok(result));
                                    }
                                }
                            }
                            None => {
                                // Event (no id).
                                let _ = event_tx.send(msg);
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-207-fu: the zone contract reaches Firefox launches through the
    /// profile's `user.js` (Firefox has no `--proxy-server`) — and the
    /// Juggler transport keeps working (`remote.enabled` must survive).
    #[test]
    fn prepare_profile_carries_the_zone_proxy_prefs() {
        let dir = std::env::temp_dir().join(format!(
            "t207fu-juggler-profile-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let prefs = crate::browser::zone::firefox_user_js_proxy_prefs("socks5h://127.0.0.1:9050")
            .expect("Tor spelling must be expressible");
        prepare_profile(&dir, &prefs).expect("write profile");
        let body = std::fs::read_to_string(dir.join("user.js")).expect("user.js exists");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            body.contains("user_pref(\"remote.enabled\", true);"),
            "juggler must stay enabled: {body}"
        );
        assert!(
            body.contains("user_pref(\"network.proxy.socks\", \"127.0.0.1\");"),
            "the contract proxy must reach Firefox: {body}"
        );
        assert!(
            body.contains("user_pref(\"network.proxy.socks_port\", 9050);"),
            "the contract proxy port must reach Firefox: {body}"
        );
        assert!(
            body.contains("user_pref(\"network.proxy.socks_remote_dns\", true);"),
            "remote DNS must survive: {body}"
        );
    }

    /// T-207-fu: a malformed contract proxy refuses the Firefox launch BEFORE
    /// spawning anything — the probe binary does not exist, so a spawn attempt
    /// would surface as a launch error, not a refusal (N3).
    #[test]
    #[cfg(unix)] // the pre-spawn refusal path is the Unix launch; Windows refuses earlier by design
    fn launch_refuses_before_spawn_when_contract_proxy_is_malformed() {
        let _guard = crate::browser::zone::ZONE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("TALLOW_PROXY").ok();
        unsafe { std::env::set_var("TALLOW_PROXY", "::::nope") };
        let config = BrowserConfig {
            chrome_path: std::path::PathBuf::from("/nonexistent/tallow-juggler-refusal-probe"),
            backend: crate::browser::process::BrowserBackend::Firefox,
            ..BrowserConfig::default()
        };
        let result = JugglerClient::launch(&config);
        match prior {
            Some(v) => unsafe { std::env::set_var("TALLOW_PROXY", v) },
            None => unsafe { std::env::remove_var("TALLOW_PROXY") },
        }
        let err = match result {
            Ok(_) => panic!("malformed contract proxy must refuse the launch"),
            Err(e) => e,
        };
        let msg = format!("{err:?}");
        assert!(msg.contains("refusing"), "refusal must say so: {msg}");
        assert!(
            !msg.contains("failed to launch"),
            "refusal must happen BEFORE spawning: {msg}"
        );
    }
}
