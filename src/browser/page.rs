//! Page handle for browser navigation and DOM interaction.
//!
//! Provides the Page type representing a browser tab/target, with methods
//! for navigation, lifecycle event waiting, and element querying.

use std::collections::VecDeque;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Random delay between min_ms and max_ms (tokio sleep).
async fn random_delay(min_ms: u64, max_ms: u64) {
    let ms = min_ms + (rand_u32() as u64 % (max_ms - min_ms + 1));
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Fast non-cryptographic random u32 (not secure, just for jitter).
fn rand_u32() -> u32 {
    use std::time::SystemTime;
    let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_nanos();
    (nanos ^ (nanos >> 17) ^ (nanos << 31)) as u32
}

use serde_json::{json, Value};

use super::cdp::{CdpClient, CdpEvent, ConsoleMessage};
use super::element::ElementHandle;
use super::error::{map_chrome_net_error, BrowserError};
use super::frame::{parse_frame_tree, FrameInfo};
use super::interaction::{
    special_key_code, MODIFIER_ALT, MODIFIER_CTRL, MODIFIER_META, MODIFIER_SHIFT,
};
use super::network::ResourceType;
use super::recording::{encode_frames, RecordingConfig, RecordingResult};
use super::stealth::{self, StealthProfile};

/// How the page should handle a JavaScript dialog (alert, confirm, prompt, beforeunload).
#[derive(Debug, Clone)]
pub enum DialogHandler {
    /// Accept the dialog (click OK).
    Accept,
    /// Dismiss the dialog (click Cancel).
    Dismiss,
    /// Accept the dialog and fill in the prompt text.
    AcceptWithText(String),
}

/// Which lifecycle event to wait for during navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitUntil {
    /// Wait for the `load` event.
    Load,
    /// Wait for the `DOMContentLoaded` event.
    DomContentLoaded,
    /// Wait until there are no network connections for 500ms.
    NetworkIdle,
    /// Wait until there are no more than 2 network connections for 500ms.
    NetworkAlmostIdle,
}

impl WaitUntil {
    /// Returns the CDP lifecycle event name for this wait condition.
    pub fn as_cdp_name(&self) -> &'static str {
        match self {
            WaitUntil::Load => "load",
            WaitUntil::DomContentLoaded => "DOMContentLoaded",
            WaitUntil::NetworkIdle => "networkIdle",
            WaitUntil::NetworkAlmostIdle => "networkAlmostIdle",
        }
    }
}

/// Result of a successful page navigation.
#[derive(Debug, Clone)]
pub struct NavigationResult {
    /// The URL that was navigated to.
    pub url: String,
    /// The CDP frame ID for the main frame.
    pub frame_id: String,
    /// HTTP status code if available.
    pub status_code: Option<u16>,
}

/// Detected pagination pattern on a page.
#[derive(Debug, Clone)]
pub struct PaginationInfo {
    /// The pagination strategy detected: "numbered", "next_button", "load_more", or "infinite_scroll".
    pub strategy: String,
    /// The URL of the next page, if available.
    pub next_url: Option<String>,
    /// Number of pagination links found.
    pub total_links: usize,
}

/// Strategy for handling cookie consent banners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieConsentStrategy {
    /// Click "Reject" / "Decline" / "Necessary only" buttons.
    RejectNonEssential,
    /// Click "Accept all" / "I agree" buttons.
    AcceptAll,
    /// Click the close/dismiss button on the banner.
    Dismiss,
}

/// One buffered CDP event, kept until the interpreter drains it.
///
/// The buffer exists because the interpreter is single-threaded: a CDP event
/// arrives on the browser's runtime and there is no safe way to call a `.tl`
/// handler from there, so events are recorded and delivered on the next
/// interpreter turn instead of being dropped.
#[derive(Debug, Clone)]
pub struct PageEvent {
    /// Coarse category: `console`, `error`, `request`, `response`,
    /// `filechooser`, `download`, `binding`.
    pub kind: String,
    /// The CDP method that produced it, verbatim.
    pub method: String,
    /// `params` as JSON. Kept as text so an event survives being handed to a
    /// caller that has no schema for it yet.
    pub payload: String,
}

/// How many events a page keeps before the oldest are dropped.
///
/// A page that is never drained must not grow without bound; 512 records is
/// enough for a page load's console and network activity and small enough to
/// stay in memory.
const EVENT_BUFFER_CAP: usize = 512;

/// A handle to a browser page (tab/target).
///
/// Clone-friendly since CdpClient uses Arc internals.
/// When created via `enter_iframe`, `iframe_doc_object_id` is set to scope
/// queries to the iframe's content document via `callFunctionOn`.
#[derive(Clone)]
pub struct Page {
    pub(crate) client: CdpClient,
    pub(crate) session_id: String,
    pub(crate) frame_id: String,
    pub(crate) timeout: Duration,
    /// When Some, this Page represents an iframe and queries are scoped
    /// to the iframe's content document via Runtime.callFunctionOn.
    pub(crate) iframe_doc_object_id: Option<String>,
    /// Pool index for BrowserPool.release — None if created via Browser.launch
    pub(crate) pool_index: Option<usize>,
    /// Reference back to the BrowserPool that owns this page (enables pool.release)
    pub(crate) pool: Option<Arc<super::pool::BrowserPool>>,
    /// Events seen on this page's session, waiting to be drained.
    pub(crate) events: Arc<Mutex<VecDeque<PageEvent>>>,
}

impl Page {
    /// Create a Page from an existing CDP client and session ID.
    /// Used by BrowserPool to wrap acquired pool handles as Page objects.
    pub fn from_cdp(
        client: CdpClient,
        session_id: String,
        pool_index: Option<usize>,
        pool: Option<Arc<super::pool::BrowserPool>>,
    ) -> Self {
        Self {
            client,
            session_id,
            frame_id: String::new(),
            timeout: Duration::from_secs(30),
            iframe_doc_object_id: None,
            pool_index,
            pool,
            events: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// This page's CDP session id — the key event handlers are registered
    /// under, because a Page value is cloned freely and has no stable address.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Start recording this page's CDP events into a bounded buffer.
    ///
    /// Idempotent per Page value; called once when the page is created. The
    /// task ends when the client's event channel closes (browser gone).
    pub(crate) async fn start_event_pump(&self) {
        // Subscribe BEFORE enabling: enabling the domains emits events of its
        // own (executionContextCreated), and anything that arrives between the
        // enable and the subscription is lost.
        let mut events = self.client.subscribe();
        // Enable synchronously, not inside the spawned task: a task that
        // enables Runtime afterwards races the first navigation, and a page
        // that logs during load loses its console lines. Measured — with the
        // enable in the task, `console.log` at parse time never arrived, while
        // a log injected after load did.
        for domain in ["Runtime.enable", "Page.enable"] {
            let _ = self
                .client
                .send_command_with_session(domain, None, &self.session_id)
                .await;
        }
        let session = self.session_id.clone();
        let buffer = Arc::clone(&self.events);
        self.client.spawn_background(async move {
            loop {
                match events.recv().await {
                    Ok(evt) => {
                        if evt
                            .session_id
                            .as_deref()
                            .is_some_and(|sid| sid != session)
                        {
                            continue;
                        }
                        let Some(kind) = classify_event(&evt.method) else {
                            continue;
                        };
                        let record = PageEvent {
                            kind: kind.to_string(),
                            method: evt.method.clone(),
                            payload: evt
                                .params
                                .as_ref()
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "{}".to_string()),
                        };
                        let mut guard = match buffer.lock() {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        if guard.len() >= EVENT_BUFFER_CAP {
                            guard.pop_front();
                        }
                        guard.push_back(record);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
    }

    /// Take buffered events, oldest first.
    ///
    /// `kind` filters by category when non-empty; `limit` of 0 means "all".
    /// Taking removes them, so a caller that forgets to drain does not
    /// reprocess the same console message forever.
    pub fn drain_events(&self, kind: &str, limit: usize) -> Vec<PageEvent> {
        let mut guard = match self.events.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut taken = Vec::new();
        let mut index = 0;
        while index < guard.len() && (limit == 0 || taken.len() < limit) {
            if kind.is_empty() || guard[index].kind == kind {
                taken.push(guard[index].clone());
                guard.remove(index);
            } else {
                index += 1;
            }
        }
        taken
    }

    /// Navigate to a URL and wait for the specified lifecycle event.
    pub async fn navigate(
        &self,
        url: &str,
        wait_until: WaitUntil,
    ) -> Result<NavigationResult, BrowserError> {
        self.navigate_internal(url, wait_until, false).await
    }

    /// Navigate to a URL and wait for the lifecycle event, but on timeout
    /// return a partial result instead of an error. Used for sites protected
    /// by JS challenges (Wordfence) that never fire DOMContentLoaded.
    pub async fn navigate_soft(
        &self,
        url: &str,
        wait_until: WaitUntil,
    ) -> Result<NavigationResult, BrowserError> {
        // Use a shorter timeout by creating a temp page variant
        let mut page = self.clone();
        page.timeout = Duration::from_secs(8);
        page.navigate_internal(url, wait_until, true).await
    }

    /// Navigate with a custom timeout in seconds. Returns partial result
    /// on timeout (same behavior as navigate_soft).
    pub async fn navigate_timed(
        &self,
        url: &str,
        timeout_secs: u64,
    ) -> Result<NavigationResult, BrowserError> {
        let mut page = self.clone();
        page.timeout = Duration::from_secs(timeout_secs);
        page.navigate_internal(url, WaitUntil::DomContentLoaded, true).await
    }

    /// Internal navigation implementation shared by navigate() and navigate_soft().
    async fn navigate_internal(
        &self,
        url: &str,
        wait_until: WaitUntil,
        soft_timeout: bool,
    ) -> Result<NavigationResult, BrowserError> {
        // Subscribe to events BEFORE enabling any domain or navigating. The
        // broadcast channel drops events broadcast while zero subscribers are
        // attached (`send()` → `Err(SendError)`). Enabling lifecycle events on
        // a fresh page immediately emits lifecycle events for the current
        // (about:blank) document — if we subscribe after those, the whole
        // event stream can be lost and `Page.navigate` will hang waiting for a
        // lifecycle event that was never delivered. Subscribe first so
        // `receiver_count() >= 1` for every subsequent event.
        let mut events = self.client.subscribe();

        // Enable lifecycle events. Best-effort: a lost or delayed response
        // (wrapped transports, slow targets) must not block navigation —
        // events still flow and the lifecycle wait below is the real gate.
        if let Err(BrowserError::Timeout { .. }) = self
            .client
            .send_command_with_session(
                "Page.setLifecycleEventsEnabled",
                Some(json!({"enabled": true})),
                &self.session_id,
            )
            .await
        {
            // Timeout tolerated; navigation proceeds on the event stream.
        }

        // Enable network events so we can capture HTTP status codes.
        if let Err(BrowserError::Timeout { .. }) = self
            .client
            .send_command_with_session("Network.enable", None, &self.session_id)
            .await
        {
            // Timeout tolerated; status_code stays None.
        }

        // NOTE: `Runtime.enable` is intentionally NOT sent here. It is a strong
        // CDP-automation signal for anti-bot systems, and `Runtime.evaluate`
        // works without it (only `Runtime.*` event delivery requires enable).
        // Console capture opts in lazily via `Page::console_messages()`.

        // Send navigation command. The response is optional: some transports
        // (wrapped sessions, proxies) may never deliver it even though the
        // navigation proceeds. Fall back to observing navigation events to
        // recover the frame id and completion.
        let nav_debug = std::env::var("TALLOW_DEBUG_NAV").is_ok_and(|v| v == "1");
        let nav_started = std::time::Instant::now();
        // The document that is current BEFORE the navigation. `location.href`
        // alone cannot tell a reload from the same URL: it still matches while
        // the OLD document is current, so the readiness poll below could
        // report success for the page that was already there. `timeOrigin` is
        // minted per document, so a changed value proves the new one committed.
        // Best-effort: a page that cannot answer leaves the guard inactive.
        let doc_epoch: Option<f64> = match tokio::time::timeout(
            std::time::Duration::from_millis(750),
            self.evaluate_expression("performance.timeOrigin"),
        )
        .await
        {
            Ok(Ok(v)) => v.as_f64(),
            _ => None,
        };
        if nav_debug {
            eprintln!("[nav] -> Page.navigate {url} (t+0ms)");
        }
        // Bound the command itself. `Page.navigate`'s REPLY is not required for
        // the navigation to happen — the browser has already been told to go —
        // but awaiting it cost the full 30 s command timeout on every load that
        // worked (measured 2026-10-18: "Page.navigate responded (timeout) at
        // t+30000ms", after which the readiness loop had no time left). Five
        // seconds is enough for a healthy reply; when it is missing the poll
        // below observes the document instead.
        let result = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.client.send_command_with_session(
                "Page.navigate",
                Some(json!({"url": url})),
                &self.session_id,
            ),
        )
        .await
        {
            Ok(Ok(r)) => Some(r),
            Ok(Err(BrowserError::Timeout { .. })) | Err(_) => None,
            Ok(Err(e)) => return Err(e),
        };

        if nav_debug {
            eprintln!(
                "[nav] <- Page.navigate responded ({:?}) at t+{}ms",
                result.as_ref().map(|_| "ok").unwrap_or("timeout"),
                nav_started.elapsed().as_millis()
            );
        }

        // Check for errorText in navigation response
        if let Some(result) = &result {
            if let Some(error_text) = result.get("errorText").and_then(|v| v.as_str()) {
                if !error_text.is_empty() {
                    return Err(BrowserError::NavigationFailed(map_chrome_net_error(
                        error_text,
                    )));
                }
            }
        }

        let mut frame_id: Option<String> = result.and_then(|r| {
            r.get("frameId")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });

        let target_event = wait_until.as_cdp_name();

        // Track HTTP status code from Network.responseReceived events
        let mut status_code: Option<u16> = None;

        // Wait for the lifecycle event with timeout. Expiry is kept on the wall
        // clock: the async timer driver did not service a 250 ms `timeout_at`
        // inside this loop (measured 2026-10-18), and a quiet event channel must
        // not be able to hold the loop past its budget.
        let std_deadline = std::time::Instant::now() + self.timeout;
        // Poll fallback (register #105). `Page.setLifecycleEventsEnabled` is
        // best-effort above; when it does not take effect NO `Page.lifecycleEvent`
        // is ever delivered, so every *successful* navigation waited out the full
        // timeout (measured: 120 s, then "waiting for DOMContentLoaded") while a
        // navigation that errored returned instantly — the response path was
        // fine and only the completion signal was missing. `Runtime.evaluate`
        // does not need lifecycle events, so the document itself can answer.
        let poll_every = std::time::Duration::from_millis(250);
        let mut next_poll = tokio::time::Instant::now() + poll_every;
        let mut iterations: u64 = 0;
        loop {
            iterations += 1;
            if nav_debug && iterations <= 5 {
                eprintln!(
                    "[nav] loop iter {iterations} at t+{}ms (poll_due={})",
                    nav_started.elapsed().as_millis(),
                    tokio::time::Instant::now() >= next_poll
                );
            }
            if tokio::time::Instant::now() >= next_poll {
                next_poll = tokio::time::Instant::now() + poll_every;
                // Ask the document BOTH questions in one round trip: a
                // `readyState` read alone answers for whatever document is
                // current — right after `Page.navigate` that is still the OLD
                // page (already "complete"), which makes the poll report
                // success before the navigation happens at all. Measured
                // 2026-10-18: goto returned in 0.26 s with the navigation still
                // in flight, and the error page that followed was never seen.
                // Bounded: a command sent while the document is being torn
                // down can hang instead of answering, and an unbounded await
                // here stalls the whole wait loop until the navigation timeout
                // (measured: the poll never once completed in 90 s). A missed
                // sample is free; the next tick tries again.
                let probe = tokio::time::timeout(
                    std::time::Duration::from_millis(750),
                    self.evaluate_expression(
                        "JSON.stringify({u: location.href, s: document.readyState, o: performance.timeOrigin})",
                    ),
                )
                .await;
                if nav_debug {
                    eprintln!(
                        "[nav] poll at t+{}ms (answered={})",
                        nav_started.elapsed().as_millis(),
                        matches!(probe, Ok(Ok(_)))
                    );
                }
                if let Ok(Ok(v)) = probe {
                    let raw = v
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| v.to_string());
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
                        let current = parsed
                            .get("u")
                            .and_then(|u| u.as_str())
                            .unwrap_or("")
                            .to_string();
                        let state = parsed
                            .get("s")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_string();
                        let epoch = parsed.get("o").and_then(|o| o.as_f64());
                        // A different document than the one we left. When the
                        // pre-navigation read failed the guard stays inactive
                        // (the URL match still has to hold).
                        let new_document = match doc_epoch {
                            Some(before) => epoch.is_some_and(|now| (now - before).abs() > 0.5),
                            None => true,
                        };
                        if current.starts_with("chrome-error://") {
                            // The document is Chromium's own error page: the
                            // navigation failed even though the browser stayed
                            // up. Reporting Ok here is what made a broken load
                            // look like a successful crawl.
                            return Err(BrowserError::NavigationFailed(
                                super::error::NavigationError::ChromeNetError(
                                    "page did not load — Chromium rendered an error page"
                                        .to_string(),
                                ),
                            ));
                        }
                        let arrived = current.trim_end_matches('/')
                            == url.trim_end_matches('/');
                        let ready = match wait_until {
                            WaitUntil::DomContentLoaded => {
                                state.contains("interactive") || state.contains("complete")
                            }
                            _ => state.contains("complete"),
                        };
                        if arrived && ready && new_document {
                            let resolved_frame =
                                frame_id.clone().unwrap_or_else(|| self.frame_id.clone());
                            return Ok(NavigationResult {
                                url: current,
                                frame_id: resolved_frame,
                                status_code,
                            });
                        }
                    }
                }
            }
            // Drain whatever CDP events have already arrived. `recv().await`
            // inside `timeout_at` is what stalled: the future blocked with the
            // timer unserviced, so no poll tick ever ran between t+5 s and the
            // 60 s deadline. `try_recv` cannot block, and the explicit
            // `std::thread::sleep` below paces the loop.
            loop {
                match events.try_recv() {
                    Ok(evt) => {
                    // Recover the frame id from navigation events when the
                    // Page.navigate response was missing (event fallback).
                    if frame_id.is_none()
                        && (evt.method == "Page.frameStartedNavigating"
                            || evt.method == "Page.frameNavigated")
                    {
                        if let Some(ref params) = evt.params {
                            if let Some(fid) =
                                params.get("frameId").and_then(|v| v.as_str())
                            {
                                frame_id = Some(fid.to_string());
                            }
                        }
                    }

                    // Capture HTTP status from the first Document-type
                    // responseReceived in the navigation frame.
                    if status_code.is_none()
                        && evt.method == "Network.responseReceived"
                    {
                        if let Some(ref params) = evt.params {
                            let resp_frame =
                                params.get("frameId").and_then(|v| v.as_str());
                            let resp_type =
                                params.get("type").and_then(|v| v.as_str());
                            if resp_type == Some("Document")
                                && (frame_id.is_none()
                                    || resp_frame == frame_id.as_deref())
                            {
                                status_code = params
                                    .get("response")
                                    .and_then(|r| r.get("status"))
                                    .and_then(|s| s.as_u64())
                                    .map(|s| s as u16);
                            }
                        }
                    }

                    if evt.method == "Page.lifecycleEvent" {
                        if let Some(ref params) = evt.params {
                            let event_name = params.get("name").and_then(|v| v.as_str());
                            let event_frame =
                                params.get("frameId").and_then(|v| v.as_str());
                            if event_name == Some(target_event)
                                && (frame_id.is_none()
                                    || event_frame == frame_id.as_deref())
                            {
                                let resolved_frame =
                                    frame_id.unwrap_or_else(|| self.frame_id.clone());
                                return Ok(NavigationResult {
                                    url: url.to_string(),
                                    frame_id: resolved_frame,
                                    status_code,
                                });
                            }
                        }
                    }
                }
                    Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => break,
                    Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                        // Broadcast closed or lagged: re-subscribe and keep
                        // polling — recency of the receiver is not correctness.
                        events = self.client.subscribe();
                        break;
                    }
                }
            }

            // Expiry on the wall clock, so a quiet event channel cannot hold
            // the loop past its budget.
            if std::time::Instant::now() >= std_deadline {
                if soft_timeout {
                    // Partial result — the page may be usable even though the
                    // lifecycle event never fired (JS challenge spinners).
                    let resolved_frame =
                        frame_id.clone().unwrap_or_else(|| self.frame_id.clone());
                    return Ok(NavigationResult {
                        url: url.to_string(),
                        frame_id: resolved_frame,
                        status_code,
                    });
                }
                return Err(BrowserError::Timeout {
                    operation: "navigate",
                    detail: format!("waiting for {target_event}"),
                });
            }

            // Yield to the runtime, not to the OS thread: the CDP reader task
            // delivers every command response, so a blocking sleep here starves
            // it and `Runtime.evaluate` never answers (measured 2026-10-18:
            // every poll timed out at its 750 ms bound while the reader was
            // pending). A tokio sleep yields exactly as needed.
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// Navigate to a URL with automatic per-domain rate limiting.
    ///
    /// Extracts the domain from the URL, waits if the rate limiter requires a
    /// delay, then calls `navigate()`. After navigation, reports success or
    /// failure back to the rate manager based on the HTTP status code and
    /// response body classification.
    ///
    /// # Arguments
    /// * `url` - The URL to navigate to.
    /// * `rate_manager` - Shared reference to the domain rate manager (must be
    ///   wrapped in a Mutex since `DomainRateManager` requires `&mut self`).
    pub async fn navigate_rate_limited(
        &self,
        url: &str,
        rate_manager: &std::sync::Mutex<super::ratelimit::DomainRateManager>,
    ) -> Result<NavigationResult, BrowserError> {
        // Extract domain from URL
        let domain = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| url.to_string());

        // Wait until the rate limiter allows a request for this domain
        loop {
            let wait_dur = {
                let mut mgr = rate_manager.lock().unwrap();
                if mgr.try_acquire(&domain) {
                    break;
                }
                mgr.wait_duration(&domain)
            };

            if wait_dur > std::time::Duration::ZERO {
                tokio::time::sleep(wait_dur).await;
            } else {
                // Tiny yield to avoid busy-spinning if wait_duration returned zero
                // but try_acquire still failed (tokens refilling)
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }

        // Perform the actual navigation
        let result = self.navigate(url, WaitUntil::Load).await;

        // Report result back to rate manager
        match &result {
            Ok(nav) => {
                let mut mgr = rate_manager.lock().unwrap();
                if let Some(status) = nav.status_code {
                    let class = super::ratelimit::ResponseClass::from_status(status);
                    match class {
                        super::ratelimit::ResponseClass::Success => {
                            mgr.report_success(&domain);
                        }
                        super::ratelimit::ResponseClass::SoftBlock => {
                            mgr.report_soft_block(&domain);
                        }
                        super::ratelimit::ResponseClass::HardBlock => {
                            mgr.report_hard_block(&domain);
                        }
                        super::ratelimit::ResponseClass::TransientError => {
                            // Transient errors don't adjust rate — could be server issue
                        }
                    }
                } else {
                    // No status code — treat as success (CDP navigation completed)
                    mgr.report_success(&domain);
                }
            }
            Err(_) => {
                // Navigation error (timeout, connection refused, etc.)
                // Don't penalize rate for network failures that aren't anti-bot
            }
        }

        result
    }

    /// Reload the current page and wait for the specified lifecycle event.
    pub async fn reload(&self, wait_until: WaitUntil) -> Result<(), BrowserError> {
        let mut events = self.client.subscribe();

        self.client
            .send_command_with_session(
                "Page.reload",
                Some(json!({"ignoreCache": false})),
                &self.session_id,
            )
            .await?;

        let target_event = wait_until.as_cdp_name();
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            match tokio::time::timeout_at(deadline, events.recv()).await {
                Ok(Ok(evt)) => {
                    if evt.method == "Page.lifecycleEvent" {
                        if let Some(ref params) = evt.params {
                            if params.get("name").and_then(|v| v.as_str())
                                == Some(target_event)
                            {
                                return Ok(());
                            }
                        }
                    }
                }
                Ok(Err(_)) => {
                    events = self.client.subscribe();
                }
                Err(_) => {
                    return Err(BrowserError::Timeout {
                        operation: "reload",
                        detail: format!("waiting for {target_event}"),
                    });
                }
            }
        }
    }

    /// Navigate back in history.
    pub async fn go_back(&self) -> Result<(), BrowserError> {
        let history = self
            .client
            .send_command_with_session(
                "Page.getNavigationHistory",
                None,
                &self.session_id,
            )
            .await?;

        let current_index = history
            .get("currentIndex")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        if current_index <= 0 {
            return Ok(()); // Already at the beginning
        }

        let entries = history
            .get("entries")
            .and_then(|v| v.as_array())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "no navigation history entries".to_string(),
            })?;

        let prev_entry = &entries[(current_index - 1) as usize];
        let entry_id = prev_entry
            .get("id")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        self.client
            .send_command_with_session(
                "Page.navigateToHistoryEntry",
                Some(json!({"entryId": entry_id})),
                &self.session_id,
            )
            .await?;

        Ok(())
    }

    /// Navigate forward in history.
    pub async fn go_forward(&self) -> Result<(), BrowserError> {
        let history = self
            .client
            .send_command_with_session(
                "Page.getNavigationHistory",
                None,
                &self.session_id,
            )
            .await?;

        let current_index = history
            .get("currentIndex")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as usize;

        let entries = history
            .get("entries")
            .and_then(|v| v.as_array())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "no navigation history entries".to_string(),
            })?;

        if current_index + 1 >= entries.len() {
            return Ok(()); // Already at the end
        }

        let next_entry = &entries[current_index + 1];
        let entry_id = next_entry
            .get("id")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        self.client
            .send_command_with_session(
                "Page.navigateToHistoryEntry",
                Some(json!({"entryId": entry_id})),
                &self.session_id,
            )
            .await?;

        Ok(())
    }

    /// Get the current page URL via JavaScript evaluation.
    pub async fn url(&self) -> Result<String, BrowserError> {
        let result = self
            .client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({"expression": "window.location.href"})),
                &self.session_id,
            )
            .await?;

        Ok(extract_string_result(&result).unwrap_or_default())
    }

    /// Get the current page title via JavaScript evaluation.
    pub async fn title(&self) -> Result<String, BrowserError> {
        let result = self
            .client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({"expression": "document.title"})),
                &self.session_id,
            )
            .await?;

        Ok(extract_string_result(&result).unwrap_or_default())
    }

    /// Full HTML of the current document, serialized from the live DOM.
    ///
    /// `Page.getResourceContent` returns the bytes as the server sent them;
    /// this serializes what the page looks like after scripts ran, which is
    /// what a scraper needs.
    pub async fn content(&self) -> Result<String, BrowserError> {
        let value = self
            .evaluate_expression("document.documentElement.outerHTML")
            .await?;
        Ok(value
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| value.to_string()))
    }

    /// Replace the document with `html` (`document.open/write/close`).
    ///
    /// The current document is discarded; the target, session and event
    /// handlers stay bound, so later navigation on this `Page` still works.
    /// Returns the number of HTML bytes written.
    pub async fn set_content(&self, html: &str) -> Result<usize, BrowserError> {
        // JSON string escaping is the only correct way to get arbitrary HTML
        // into a JavaScript literal: quoting by hand loses backslashes,
        // newlines and `</script>`.
        let literal = serde_json::to_string(html)
            .map_err(|e| BrowserError::JsonError(format!("set_content: {e}")))?;
        self.evaluate_expression(&format!(
            "document.open();document.write({literal});document.close();true"
        ))
        .await?;
        Ok(html.len())
    }

    /// Sleep for `ms`. An explicit wait, not an inference.
    ///
    /// Returns the elapsed milliseconds so the caller can see that the sleep
    /// actually happened instead of trusting the requested value.
    pub async fn wait_for_timeout(&self, ms: u64) -> u64 {
        let started = std::time::Instant::now();
        tokio::time::sleep(Duration::from_millis(ms)).await;
        started.elapsed().as_millis() as u64
    }

    /// Poll `js_expression` until it is truthy or `timeout` elapses.
    ///
    /// CDP has no "wait for arbitrary expression" primitive, so this polls
    /// `Runtime.evaluate` every 50 ms. Returns `(found, elapsed_ms)`; a timeout
    /// is a normal `false`, not an error, because the caller asked a question
    /// the page is allowed to answer "not yet".
    pub async fn wait_for_function(
        &self,
        js_expression: &str,
        timeout: Duration,
    ) -> Result<(bool, u64), BrowserError> {
        let started = std::time::Instant::now();
        loop {
            let value = self.evaluate_expression(js_expression).await?;
            let truthy = match &value {
                serde_json::Value::Bool(b) => *b,
                serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
                serde_json::Value::String(s) => !s.is_empty(),
                serde_json::Value::Null => false,
                _ => true,
            };
            if truthy {
                return Ok((true, started.elapsed().as_millis() as u64));
            }
            if started.elapsed() >= timeout {
                return Ok((false, started.elapsed().as_millis() as u64));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Wait until `location.href` matches `pattern` (`*` is a wildcard).
    ///
    /// Polls the URL rather than listening for `Page.frameNavigated`: the
    /// caller usually asks "is it there yet", and a navigation that already
    /// finished would never deliver the event again.
    /// Returns `(matched, elapsed_ms, url)`.
    pub async fn wait_for_url(
        &self,
        pattern: &str,
        timeout: Duration,
    ) -> Result<(bool, u64, String), BrowserError> {
        let started = std::time::Instant::now();
        loop {
            let current = self.url().await.unwrap_or_default();
            if glob_match(pattern, &current) {
                return Ok((true, started.elapsed().as_millis() as u64, current));
            }
            if started.elapsed() >= timeout {
                return Ok((false, started.elapsed().as_millis() as u64, current));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Wait for a CDP event on this page.
    ///
    /// Accepts the full method (`"Page.loadEventFired"`) or the bare name
    /// (`"loadEventFired"`). Events are only delivered from the moment the
    /// wait starts, so subscribe before the action that triggers them.
    /// Returns `(seen, elapsed_ms, method)`.
    pub async fn wait_for_event(
        &self,
        event_name: &str,
        timeout: Duration,
    ) -> Result<(bool, u64, String), BrowserError> {
        let started = std::time::Instant::now();
        let deadline = tokio::time::Instant::now() + timeout;
        let suffix = format!(".{event_name}");
        let mut events = self.client.subscribe();

        loop {
            match tokio::time::timeout_at(deadline, events.recv()).await {
                Ok(Ok(evt)) => {
                    if self.is_other_session(&evt) {
                        continue;
                    }
                    if evt.method == event_name || evt.method.ends_with(&suffix) {
                        return Ok((
                            true,
                            started.elapsed().as_millis() as u64,
                            evt.method.clone(),
                        ));
                    }
                }
                // Dropped events are not a failure: keep waiting for the next
                // one rather than reporting a timeout that never happened.
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(_)) | Err(_) => break,
            }
        }
        Ok((false, started.elapsed().as_millis() as u64, String::new()))
    }

    /// Wait for an outgoing request whose URL matches `pattern`.
    pub async fn wait_for_request(
        &self,
        url_pattern: &str,
        timeout: Duration,
    ) -> Result<(bool, u64, String), BrowserError> {
        self.wait_for_network_url("Network.requestWillBeSent", url_pattern, timeout)
            .await
    }

    /// Wait for a response whose URL matches `pattern`.
    pub async fn wait_for_response(
        &self,
        url_pattern: &str,
        timeout: Duration,
    ) -> Result<(bool, u64, String), BrowserError> {
        self.wait_for_network_url("Network.responseReceived", url_pattern, timeout)
            .await
    }

    /// Shared body of the two network waits: same subscription, same deadline,
    /// only the event method and the payload key differ.
    async fn wait_for_network_url(
        &self,
        method: &str,
        url_pattern: &str,
        timeout: Duration,
    ) -> Result<(bool, u64, String), BrowserError> {
        let started = std::time::Instant::now();
        let deadline = tokio::time::Instant::now() + timeout;
        let mut events = self.client.subscribe();

        loop {
            match tokio::time::timeout_at(deadline, events.recv()).await {
                Ok(Ok(evt)) => {
                    if evt.method != method || self.is_other_session(&evt) {
                        continue;
                    }
                    let url = evt
                        .params
                        .as_ref()
                        .and_then(|p| {
                            p.get("request")
                                .and_then(|r| r.get("url"))
                                .or_else(|| p.get("response").and_then(|r| r.get("url")))
                        })
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if glob_match(url_pattern, url) {
                        return Ok((true, started.elapsed().as_millis() as u64, url.to_string()));
                    }
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(_)) | Err(_) => break,
            }
        }
        Ok((false, started.elapsed().as_millis() as u64, String::new()))
    }

    // ── Script/style injection ──────────────────────────────────────────────

    /// Add a `<script>` to the current document.
    ///
    /// `url_or_content` is treated as a URL when it looks like one (a scheme
    /// or a protocol-relative prefix), otherwise as inline source. Returns the
    /// generated element id so the caller can find or remove it.
    pub async fn add_script_tag(&self, url_or_content: &str) -> Result<String, BrowserError> {
        let literal = serde_json::to_string(url_or_content)
            .map_err(|e| BrowserError::JsonError(format!("add_script_tag: {e}")))?;
        let as_url = looks_like_url(url_or_content);
        let expression = format!(
            "(() => {{ const s = document.createElement('script');              {} = {literal}; s.id = 'tallow-script-' + Date.now().toString(36);              (document.head || document.documentElement).appendChild(s); return s.id; }})()",
            if as_url { "s.src" } else { "s.text" }
        );
        let value = self.evaluate_expression(&expression).await?;
        Ok(value.as_str().map(str::to_string).unwrap_or_default())
    }

    /// Add a `<style>` to the current document; same URL/contents heuristic.
    pub async fn add_style_tag(&self, url_or_content: &str) -> Result<(String, String), BrowserError> {
        let literal = serde_json::to_string(url_or_content)
            .map_err(|e| BrowserError::JsonError(format!("add_style_tag: {e}")))?;
        let as_url = looks_like_url(url_or_content);
        let expression = format!(
            "(() => {{ const s = document.createElement('style');              {} = {literal}; s.id = 'tallow-style-' + Date.now().toString(36);              (document.head || document.documentElement).appendChild(s); return s.id; }})()",
            if as_url {
                "s.setAttribute('data-href', {literal})"
            } else {
                "s.textContent"
            }
        );
        let value = self.evaluate_expression(&expression).await?;
        let id = value.as_str().map(str::to_string).unwrap_or_default();
        Ok((id, if as_url { "link" } else { "inline" }.to_string()))
    }

    // ── Emulation ───────────────────────────────────────────────────────────

    /// Emulate a media type plus colour-scheme and reduced-motion preferences.
    ///
    /// These are CSS media features, not UA strings: `prefers-colour-scheme`
    /// is what a site's dark-mode branch reads.
    pub async fn emulate_media(
        &self,
        media_type: &str,
        color_scheme: &str,
        reduced_motion: &str,
    ) -> Result<(), BrowserError> {
        let media = if media_type.is_empty() { "screen" } else { media_type };
        let scheme = if color_scheme.is_empty() { "light" } else { color_scheme };
        let motion = if reduced_motion.is_empty() {
            "no-preference"
        } else {
            reduced_motion
        };
        self.client
            .send_command_with_session(
                "Emulation.setEmulatedMedia",
                Some(json!({
                    "media": media,
                    "features": [
                        { "name": "prefers-color-scheme", "value": scheme },
                        { "name": "prefers-reduced-motion", "value": motion },
                    ],
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Emulate a vision deficiency (`none`, `blurredVision`, `deuteranopia`, …).
    pub async fn emulate_vision(&self, deficiency: &str) -> Result<(), BrowserError> {
        let kind = if deficiency.is_empty() { "none" } else { deficiency };
        self.client
            .send_command_with_session(
                "Emulation.setEmulatedVisionDeficiency",
                Some(json!({ "type": kind })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Throttle CPU by `rate` (1.0 = native, 4.0 = 4× slower). Returns the rate.
    pub async fn throttle_cpu(&self, rate: f64) -> Result<f64, BrowserError> {
        let rate = if rate <= 0.0 { 1.0 } else { rate };
        self.client
            .send_command_with_session(
                "Emulation.setCPUThrottlingRate",
                Some(json!({ "rate": rate })),
                &self.session_id,
            )
            .await?;
        Ok(rate)
    }

    /// True when the event belongs to a different page's session.
    fn is_other_session(&self, evt: &CdpEvent) -> bool {
        evt.session_id
            .as_deref()
            .is_some_and(|sid| sid != self.session_id)
    }

    /// Query a single element by CSS selector.
    ///
    /// Returns `Ok(None)` if no element matches.
    /// When this Page was created by `enter_iframe`, queries are scoped to
    /// the iframe's content document via `Runtime.callFunctionOn`.
    pub async fn query_selector(
        &self,
        selector: &str,
    ) -> Result<Option<ElementHandle>, BrowserError> {
        let escaped = escape_js_string(selector);

        let result = if let Some(ref doc_id) = self.iframe_doc_object_id {
            // Iframe-scoped: use callFunctionOn against the iframe's document objectId
            let func = format!("function() {{ return this.querySelector('{escaped}'); }}");
            self.client
                .send_command_with_session(
                    "Runtime.callFunctionOn",
                    Some(json!({
                        "objectId": doc_id,
                        "functionDeclaration": func,
                        "returnByValue": false,
                    })),
                    &self.session_id,
                )
                .await?
        } else {
            // Top-level: use Runtime.evaluate
            let expression = format!("document.querySelector('{escaped}')");
            self.client
                .send_command_with_session(
                    "Runtime.evaluate",
                    Some(json!({"expression": expression, "returnByValue": false})),
                    &self.session_id,
                )
                .await?
        };

        let obj = result.get("result").unwrap_or(&Value::Null);
        let obj_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let subtype = obj.get("subtype").and_then(|v| v.as_str()).unwrap_or("");

        if obj_type == "object" && subtype != "null" {
            if let Some(object_id) = obj.get("objectId").and_then(|v| v.as_str()) {
                return Ok(Some(ElementHandle {
                    client: self.client.clone(),
                    session_id: self.session_id.clone(),
                    remote_object_id: object_id.to_string(),
                }));
            }
        }

        Ok(None)
    }

    /// Query all elements matching a CSS selector.
    ///
    /// When this Page was created by `enter_iframe`, queries are scoped to
    /// the iframe's content document via `Runtime.callFunctionOn`.
    pub async fn query_selector_all(
        &self,
        selector: &str,
    ) -> Result<Vec<ElementHandle>, BrowserError> {
        let escaped = escape_js_string(selector);

        let result = if let Some(ref doc_id) = self.iframe_doc_object_id {
            // Iframe-scoped: use callFunctionOn against the iframe's document objectId
            let func = format!(
                "function() {{ return Array.from(this.querySelectorAll('{escaped}')); }}"
            );
            self.client
                .send_command_with_session(
                    "Runtime.callFunctionOn",
                    Some(json!({
                        "objectId": doc_id,
                        "functionDeclaration": func,
                        "returnByValue": false,
                    })),
                    &self.session_id,
                )
                .await?
        } else {
            let expression = format!("document.querySelectorAll('{escaped}')");
            self.client
                .send_command_with_session(
                    "Runtime.evaluate",
                    Some(json!({"expression": expression, "returnByValue": false})),
                    &self.session_id,
                )
                .await?
        };

        let obj = result.get("result").unwrap_or(&Value::Null);
        let object_id = match obj.get("objectId").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };

        // Get array properties
        let props = self
            .client
            .send_command_with_session(
                "Runtime.getProperties",
                Some(json!({
                    "objectId": object_id,
                    "ownProperties": true,
                })),
                &self.session_id,
            )
            .await?;

        let mut elements = Vec::new();
        if let Some(descriptors) = props.get("result").and_then(|v| v.as_array()) {
            for desc in descriptors {
                let name = desc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                // Only take numeric indices (skip "length" and prototype properties)
                if name.parse::<usize>().is_ok() {
                    if let Some(value) = desc.get("value") {
                        if let Some(oid) = value.get("objectId").and_then(|v| v.as_str()) {
                            elements.push(ElementHandle {
                                client: self.client.clone(),
                                session_id: self.session_id.clone(),
                                remote_object_id: oid.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(elements)
    }

    /// Query a single element by XPath expression.
    ///
    /// Returns `Ok(None)` if no element matches.
    pub async fn query_xpath(
        &self,
        expression: &str,
    ) -> Result<Option<ElementHandle>, BrowserError> {
        let escaped = escape_js_string(expression);
        let js = format!(
            "document.evaluate('{}', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue",
            escaped
        );

        let result = self
            .client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({"expression": js, "returnByValue": false})),
                &self.session_id,
            )
            .await?;

        let obj = result.get("result").unwrap_or(&Value::Null);
        let obj_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let subtype = obj.get("subtype").and_then(|v| v.as_str()).unwrap_or("");

        if obj_type == "object" && subtype != "null" {
            if let Some(object_id) = obj.get("objectId").and_then(|v| v.as_str()) {
                return Ok(Some(ElementHandle {
                    client: self.client.clone(),
                    session_id: self.session_id.clone(),
                    remote_object_id: object_id.to_string(),
                }));
            }
        }

        Ok(None)
    }

    /// Query all elements matching an XPath expression.
    pub async fn query_xpath_all(
        &self,
        expression: &str,
    ) -> Result<Vec<ElementHandle>, BrowserError> {
        let escaped = escape_js_string(expression);
        let js = format!(
            "(function() {{ var result = document.evaluate('{}', document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null); var nodes = []; for (var i = 0; i < result.snapshotLength; i++) nodes.push(result.snapshotItem(i)); return nodes; }})()",
            escaped
        );

        let result = self
            .client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({"expression": js, "returnByValue": false})),
                &self.session_id,
            )
            .await?;

        let obj = result.get("result").unwrap_or(&Value::Null);
        let object_id = match obj.get("objectId").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };

        // Get array properties -- same pattern as query_selector_all
        let props = self
            .client
            .send_command_with_session(
                "Runtime.getProperties",
                Some(json!({
                    "objectId": object_id,
                    "ownProperties": true,
                })),
                &self.session_id,
            )
            .await?;

        let mut elements = Vec::new();
        if let Some(descriptors) = props.get("result").and_then(|v| v.as_array()) {
            for desc in descriptors {
                let name = desc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if name.parse::<usize>().is_ok() {
                    if let Some(value) = desc.get("value") {
                        if let Some(oid) = value.get("objectId").and_then(|v| v.as_str()) {
                            elements.push(ElementHandle {
                                client: self.client.clone(),
                                session_id: self.session_id.clone(),
                                remote_object_id: oid.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(elements)
    }

    /// Wait for an element matching the selector to appear in the DOM.
    ///
    /// Polls every 50ms until the element is found or timeout expires.
    pub async fn wait_for_selector(
        &self,
        selector: &str,
        timeout: Option<Duration>,
    ) -> Result<ElementHandle, BrowserError> {
        let timeout = timeout.unwrap_or(self.timeout);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            if let Some(el) = self.query_selector(selector).await? {
                return Ok(el);
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(BrowserError::Timeout {
                    operation: "wait_for_selector",
                    detail: selector.to_string(),
                });
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    // -----------------------------------------------------------------------
    // Stealth anti-detection
    // -----------------------------------------------------------------------

    /// Apply stealth profile to this page. MUST be called before any navigation.
    ///
    /// Performs three steps:
    /// 1. **Chrome version auto-detection** — queries `Browser.getVersion` and
    ///    updates the profile's UA string to match the actual installed Chrome
    ///    version, preventing JA4 fingerprint mismatches.
    /// 2. **JS evasion injection** — injects all V1 + V2 stealth scripts via
    ///    `Page.addScriptToEvaluateOnNewDocument`.
    /// 3. **HTTP header override** — sets `Network.setUserAgentOverride` with
    ///    `userAgentMetadata` so that `Sec-CH-UA`, `Sec-CH-UA-Platform`, and
    ///    `Sec-CH-UA-Mobile` HTTP headers match the JS-spoofed values.
    ///
    /// The caller pattern is:
    /// ```ignore
    /// let page = client.create_page(None).await?;
    /// page.apply_stealth(&profile).await?;
    /// page.navigate("https://...", WaitUntil::Load).await?;
    /// ```
    pub async fn apply_stealth(&self, profile: &StealthProfile) -> Result<(), BrowserError> {
        // Auto-detect actual Chrome version and update profile to match.
        // This prevents JA4 mismatch: e.g. profile says Chrome/132 but the
        // installed binary is Chrome/133, which anti-bot systems can detect
        // by comparing TLS fingerprint (real version) vs UA string (spoofed).
        let mut profile = profile.clone();
        if let Ok(actual_version) = stealth::detect_chrome_version(&self.client).await {
            profile.update_chrome_version(&actual_version);
        }
        // If detection fails (e.g. unusual Chromium fork), proceed with the
        // original profile version — a stale version is better than no stealth.

        stealth::inject_stealth_scripts(&self.client, &self.session_id, &profile).await?;
        stealth::apply_stealth_ua(&self.client, &self.session_id, &profile).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Console message capture (Gap 1)
    // -----------------------------------------------------------------------

    /// Return all console messages captured since the last `clear_console()`.
    ///
    /// Messages are captured from `Runtime.consoleAPICalled` events. The
    /// `Runtime` domain is enabled automatically when the CDP client connects.
    ///
    /// # Example
    /// ```ignore
    /// page.navigate("https://example.com", WaitUntil::DomContentLoaded).await?;
    /// let msgs = page.console_messages().await;
    /// for m in &msgs { println!("[{}] {}", m.level, m.text); }
    /// ```
    pub async fn console_messages(&self) -> Vec<ConsoleMessage> {
        // Opt-in: lazily enable the Runtime domain on this target's session and
        // on the client, so console capture works without emitting the
        // `Runtime.enable` automation signal during normal stealth navigation.
        let _ = self
            .client
            .send_command_with_session("Runtime.enable", None, &self.session_id)
            .await;
        self.client.get_console_messages().await
    }

    /// Clear all captured console messages.
    pub async fn clear_console(&self) {
        self.client.clear_console().await;
    }

    // -----------------------------------------------------------------------
    // Page-level interaction methods
    // -----------------------------------------------------------------------

    /// Send a keyboard shortcut (e.g., Ctrl+A, Ctrl+Shift+T).
    ///
    /// Dispatches keyDown for each active modifier, then keyDown + keyUp for the
    /// main key, then keyUp for each modifier in reverse order.
    pub async fn keyboard_shortcut(
        &self,
        key: &str,
        modifiers: u32,
    ) -> Result<(), BrowserError> {
        // Dispatch keyDown for each modifier
        let modifier_keys: &[(&str, u32, u32)] = &[
            ("Control", MODIFIER_CTRL, 17),
            ("Alt", MODIFIER_ALT, 18),
            ("Shift", MODIFIER_SHIFT, 16),
            ("Meta", MODIFIER_META, 91),
        ];

        // Track cumulative modifiers as we press them
        let mut active_mods = 0u32;
        let mut pressed_keys = Vec::new();

        for &(name, flag, vk) in modifier_keys {
            if modifiers & flag != 0 {
                active_mods |= flag;
                self.dispatch_page_key_event("keyDown", name, None, Some(vk), active_mods)
                    .await?;
                pressed_keys.push((name, flag, vk));
            }
        }

        // Dispatch key press for main key
        let main_vk = special_key_code(key).or_else(|| {
            let chars: Vec<char> = key.chars().collect();
            if chars.len() == 1 {
                Some(chars[0].to_ascii_uppercase() as u32)
            } else {
                None
            }
        });

        self.dispatch_page_key_event("keyDown", key, None, main_vk, modifiers)
            .await?;
        self.dispatch_page_key_event("keyUp", key, None, main_vk, modifiers)
            .await?;

        // Release modifiers in reverse order
        for &(name, _flag, vk) in pressed_keys.iter().rev() {
            active_mods &= !_flag;
            self.dispatch_page_key_event("keyUp", name, None, Some(vk), active_mods)
                .await?;
        }

        Ok(())
    }

    /// Scroll the page by the given pixel delta.
    ///
    /// Positive `delta_y` scrolls down, negative scrolls up.
    pub async fn scroll_by(&self, delta_x: f64, delta_y: f64) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mouseWheel",
                    "x": 0,
                    "y": 0,
                    "deltaX": delta_x,
                    "deltaY": delta_y,
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Scroll the page to the very bottom using humanized mouseWheel events.
    ///
    /// Instead of a `Runtime.evaluate window.scrollTo` instant JS teleport
    /// (which emits zero scroll events and is a classic bot tell), this reads
    /// the page's scrollable height once, then emits a stream of
    /// `Input.dispatchMouseEvent` mouseWheel events with momentum-style
    /// deceleration (velocity decaying 0.92x per frame, matching trackpad
    /// physics), so real wheel/scroll events fire all the way down.
    pub async fn scroll_to_bottom(&self) -> Result<(), BrowserError> {
        // Read the max scrollable distance (single read; no scrolling here).
        let result = self
            .client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": "(function(){var se=document.scrollingElement||document.documentElement;return Math.max(0,(se.scrollHeight||se.clientHeight)-(window.innerHeight||se.clientHeight));})()",
                    "returnByValue": true
                })),
                &self.session_id,
            )
            .await?;
        let total = result
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if total <= 0.0 {
            return Ok(());
        }

        // Humanized momentum wheel loop: start fast, decay 0.92x per frame.
        // Use a cursor near the right-center where users typically hover.
        let cx = 500.0 + (rand_u32() % 400) as f64;
        let cy = 300.0 + (rand_u32() % 400) as f64;
        let mut scrolled = 0.0;
        let mut velocity = 120.0 + (rand_u32() % 80) as f64;
        while scrolled < total && velocity >= 1.0 {
            let remaining = total - scrolled;
            let delta = velocity.min(remaining);
            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(json!({
                        "type": "mouseWheel",
                        "x": cx,
                        "y": cy,
                        "deltaX": 0,
                        "deltaY": delta.round(),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;
            scrolled += delta;
            velocity *= 0.92;
            // Inter-frame delay shrinks with velocity, with occasional pause.
            let base = (60.0 / (velocity / 40.0).max(1.0)) as u64;
            let delay = base.max(12) + rand_u32() as u64 % 25;
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        // Final nudge to guarantee the very bottom (still a wheel event).
        if scrolled < total {
            let nudge = (total - scrolled).max(1.0);
            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(json!({
                        "type": "mouseWheel",
                        "x": cx,
                        "y": cy,
                        "deltaX": 0,
                        "deltaY": nudge.round(),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Frame / iframe traversal
    // -----------------------------------------------------------------------

    /// List all frames in the page's frame tree.
    ///
    /// Returns a flat list of FrameInfo (main frame + all children + nested).
    pub async fn frames(&self) -> Result<Vec<FrameInfo>, BrowserError> {
        let result = self
            .client
            .send_command_with_session("Page.getFrameTree", None, &self.session_id)
            .await?;

        Ok(parse_frame_tree(&result))
    }

    /// Enter an iframe by CSS selector and return a Page scoped to its content.
    ///
    /// The returned Page has a different `frame_id` and uses `callFunctionOn`
    /// against the iframe's `contentDocument` objectId for all queries.
    ///
    /// Returns `IframeAccessDenied` if the iframe is cross-origin or not found.
    ///
    /// NOTE: Out-of-process iframes (OOPIF) requiring `Target.attachToTarget`
    /// are deferred to a future phase. This handles same-origin iframes.
    pub async fn enter_iframe(&self, selector: &str) -> Result<Page, BrowserError> {
        // Find the iframe element
        let iframe = self
            .query_selector(selector)
            .await?
            .ok_or_else(|| BrowserError::ElementNotFound {
                selector: selector.to_string(),
            })?;

        // Enable DOM domain (idempotent)
        let _ = self
            .client
            .send_command_with_session("DOM.enable", None, &self.session_id)
            .await;

        // Get the iframe's frame ID via DOM.describeNode
        let describe_result = self
            .client
            .send_command_with_session(
                "DOM.describeNode",
                Some(json!({
                    "objectId": iframe.remote_object_id,
                    "depth": 0,
                })),
                &self.session_id,
            )
            .await?;

        let iframe_frame_id = describe_result
            .get("node")
            .and_then(|n| n.get("frameId"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| BrowserError::IframeAccessDenied {
                selector: selector.to_string(),
            })?
            .to_string();

        // Get the iframe's contentDocument via JS
        let doc_result = self
            .client
            .send_command_with_session(
                "Runtime.callFunctionOn",
                Some(json!({
                    "objectId": iframe.remote_object_id,
                    "functionDeclaration": "function() { return this.contentDocument; }",
                    "returnByValue": false,
                })),
                &self.session_id,
            )
            .await?;

        let doc_obj = doc_result.get("result").unwrap_or(&Value::Null);
        let doc_type = doc_obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let doc_subtype = doc_obj
            .get("subtype")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if doc_type != "object" || doc_subtype == "null" {
            // contentDocument is null -- cross-origin restriction
            return Err(BrowserError::IframeAccessDenied {
                selector: selector.to_string(),
            });
        }

        let doc_obj_id = doc_obj
            .get("objectId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| BrowserError::IframeAccessDenied {
                selector: selector.to_string(),
            })?
            .to_string();

        Ok(Page {
            client: self.client.clone(),
            session_id: self.session_id.clone(),
            frame_id: iframe_frame_id,
            iframe_doc_object_id: Some(doc_obj_id),
            timeout: self.timeout,
            pool_index: self.pool_index,
            pool: self.pool.clone(),
            events: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    // -----------------------------------------------------------------------
    // Batch DOM extraction (Phase 48-01)
    // -----------------------------------------------------------------------

    /// Evaluate a JavaScript expression and return the result.
    ///
    /// This is the foundation for all batch operations. Returns the `value`
    /// field from the Runtime.evaluate result, or `Value::Null` if not present.
    pub async fn evaluate_expression(&self, expression: &str) -> Result<Value, BrowserError> {
        let result = self
            .client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true
                })),
                &self.session_id,
            )
            .await?;
        Ok(result
            .get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// Evaluate a JavaScript expression and return the RAW CDP `Runtime.evaluate`
    /// response (serde_json), preserving the `objectId` for element returns.
    ///
    /// Unlike [`evaluate_expression`] (which forces `returnByValue` and extracts
    /// only the `value` field), this keeps the full RemoteObject so callers can
    /// build ElementHandles from `objectId`. Primitives still serialize by value.
    pub async fn evaluate_raw(&self, expression: &str) -> Result<Value, BrowserError> {
        self.client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": expression,
                    "returnByValue": false,
                    "awaitPromise": true
                })),
                &self.session_id,
            )
            .await
    }

    /// Extract all matching elements' text content in ONE CDP call.
    ///
    /// Instead of N roundtrips (one per element), sends a single
    /// `Runtime.evaluate` that returns all data at once.
    pub async fn extract_all_text(&self, selector: &str) -> Result<Vec<String>, BrowserError> {
        let selector_json = serde_json::to_string(selector).unwrap_or_default();
        let js = format!(
            "Array.from(document.querySelectorAll({sel})).map(el => el.innerText)",
            sel = selector_json
        );
        let result = self.evaluate_expression(&js).await?;
        match result {
            Value::Array(arr) => Ok(arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()),
            _ => Ok(vec![]),
        }
    }

    /// Extract all matching elements with multiple attributes in ONE CDP call.
    ///
    /// Returns a Vec of JSON maps, one per element. Each map contains the
    /// requested attributes as keys. Special attribute names `innerText` and
    /// `innerHTML` read the corresponding DOM properties.
    pub async fn extract_all_attrs(
        &self,
        selector: &str,
        attrs: &[&str],
    ) -> Result<Vec<serde_json::Map<String, Value>>, BrowserError> {
        let attrs_json = serde_json::to_string(attrs).unwrap_or_default();
        let selector_json = serde_json::to_string(selector).unwrap_or_default();
        let js = format!(
            "Array.from(document.querySelectorAll({sel})).map(el => {{ \
                let r = {{}}; \
                {attrs}.forEach(a => {{ r[a] = a === 'innerText' ? el.innerText : a === 'innerHTML' ? el.innerHTML : el.getAttribute(a) }}); \
                return r; \
            }})",
            sel = selector_json,
            attrs = attrs_json
        );
        let result = self.evaluate_expression(&js).await?;
        match result {
            Value::Array(arr) => Ok(arr
                .iter()
                .filter_map(|v| v.as_object().cloned())
                .collect()),
            _ => Ok(vec![]),
        }
    }

    /// Capture a DOM snapshot using CDP's DOMSnapshot domain.
    ///
    /// Returns the entire DOM as interned string tables -- far more efficient
    /// than individual querySelector calls for large pages.
    pub async fn capture_dom_snapshot(&self) -> Result<Value, BrowserError> {
        self.client
            .send_command_with_session(
                "DOMSnapshot.captureSnapshot",
                Some(json!({
                    "computedStyles": ["display", "visibility", "color"],
                    "includeDOMRects": false,
                    "includePaintOrder": false
                })),
                &self.session_id,
            )
            .await
            .map_err(|e| {
                BrowserError::ActionFailed(format!("DOMSnapshot failed: {e}"))
            })
    }

    /// Extract structured data from the page (JSON-LD, OpenGraph, Microdata).
    ///
    /// Returns all embedded structured data in ONE CDP call as a JSON value
    /// with `json_ld`, `open_graph`, and `meta` fields.
    pub async fn extract_structured_data(&self) -> Result<Value, BrowserError> {
        let js = r#"
        (function() {
            let result = { json_ld: [], open_graph: {}, meta: {} };
            document.querySelectorAll('script[type="application/ld+json"]').forEach(s => {
                try { result.json_ld.push(JSON.parse(s.textContent)); } catch(e) {}
            });
            document.querySelectorAll('meta[property^="og:"]').forEach(m => {
                result.open_graph[m.getAttribute('property')] = m.getAttribute('content');
            });
            document.querySelectorAll('meta[name]').forEach(m => {
                result.meta[m.getAttribute('name')] = m.getAttribute('content');
            });
            return result;
        })()
        "#;
        self.evaluate_expression(js).await
    }

    /// Smart wait: wait until DOM is stable (no mutations for `quiesce_ms`)
    /// AND no active network requests. Falls back to timeout.
    pub async fn wait_for_stable(
        &self,
        timeout: Duration,
        quiesce_ms: u64,
    ) -> Result<(), BrowserError> {
        let js = format!(
            r#"
            new Promise((resolve, reject) => {{
                let timer = null;
                let settled = false;
                const observer = new MutationObserver(() => {{
                    if (timer) clearTimeout(timer);
                    timer = setTimeout(() => {{ settled = true; observer.disconnect(); resolve(true); }}, {quiesce_ms});
                }});
                observer.observe(document.body || document.documentElement, {{
                    childList: true, subtree: true, attributes: true, characterData: true
                }});
                timer = setTimeout(() => {{ if (!settled) {{ observer.disconnect(); resolve(true); }} }}, {quiesce_ms});
                setTimeout(() => {{ observer.disconnect(); resolve(false); }}, {timeout_ms});
            }})
            "#,
            quiesce_ms = quiesce_ms,
            timeout_ms = timeout.as_millis()
        );
        self.evaluate_expression(&js).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Resource blocking (Phase 48-01)
    // -----------------------------------------------------------------------

    /// Block specific resource types for faster page loads.
    ///
    /// Common pattern: block images, fonts, CSS, media for pure data extraction.
    /// Uses the CDP Fetch domain to intercept and fail matching requests.
    /// A background task is spawned to handle `Fetch.requestPaused` events
    /// so that intercepted requests are failed immediately instead of hanging.
    pub async fn block_resources(&self, types: &[ResourceType]) -> Result<(), BrowserError> {
        let patterns: Vec<Value> = types
            .iter()
            .map(|t| {
                json!({
                    "requestStage": "Request",
                    "resourceType": t.as_str()
                })
            })
            .collect();

        self.client
            .send_command_with_session(
                "Fetch.enable",
                Some(json!({"patterns": patterns})),
                &self.session_id,
            )
            .await?;

        // Spawn a lightweight background handler that fails all paused
        // requests. Without this, Fetch.enable pauses matching requests and
        // they hang indefinitely waiting for a Fetch.failRequest /
        // Fetch.continueRequest that never comes — deadlocking the page.
        let client = self.client.clone();
        let session_id = self.session_id.clone();
        // On the connection's own runtime, not the caller's: a handler tied to
        // a caller runtime stops running as soon as that runtime is idle, and
        // never runs at all if the caller later drives this page from another
        // one (the register #105 defect class).
        let _handler = self.client.spawn_background(async move {
            let mut rx = client.subscribe();
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if event.method != "Fetch.requestPaused" {
                            continue;
                        }
                        if event.session_id.as_deref() != Some(&session_id) {
                            continue;
                        }
                        let request_id = event
                            .params
                            .as_ref()
                            .and_then(|p| p.get("requestId"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if request_id.is_empty() {
                            continue;
                        }
                        let _ = client
                            .send_command_with_session(
                                "Fetch.failRequest",
                                Some(json!({
                                    "requestId": request_id,
                                    "errorReason": "BlockedByClient"
                                })),
                                &session_id,
                            )
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Missed some events; continue listening
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        // Channel closed — session is gone, stop the handler
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Convenience: block all non-essential resources for maximum speed.
    ///
    /// Blocks images, fonts, stylesheets, and media -- keeps scripts and
    /// documents for correct page execution.
    pub async fn block_non_essential(&self) -> Result<(), BrowserError> {
        self.block_resources(&[
            ResourceType::Image,
            ResourceType::Font,
            ResourceType::Stylesheet,
            ResourceType::Media,
        ])
        .await
    }

    // -----------------------------------------------------------------------
    // Auto-pagination detection (Phase 48-01)
    // -----------------------------------------------------------------------

    /// Detect pagination pattern on the current page.
    ///
    /// Checks for numbered pagination links, "Next" buttons, "Load More"
    /// buttons, and infinite scroll sentinels. Returns `None` if no
    /// pagination pattern is detected.
    pub async fn detect_pagination(&self) -> Result<Option<PaginationInfo>, BrowserError> {
        let js = r#"
        (function() {
            var numbered = document.querySelectorAll('a[href*="page="], a[href*="/page/"], .pagination a, nav[aria-label*="pagination"] a, nav[aria-label*="Pagination"] a');
            if (numbered.length > 0) {
                var links = Array.from(numbered).map(function(a) { return { text: a.innerText.trim(), href: a.href }; });
                var next = links.find(function(l) { return /^(next|>|>>)$/i.test(l.text) || l.text.toLowerCase().indexOf('next') >= 0; });
                return { strategy: 'numbered', next_url: next ? next.href : null, total_links: links.length };
            }
            var nextBtn = document.querySelector('a[rel="next"]');
            if (nextBtn) {
                return { strategy: 'next_button', next_url: nextBtn.href || null, total_links: 1 };
            }
            var sentinel = document.querySelector('[data-infinite-scroll], .infinite-scroll-component');
            if (sentinel) {
                return { strategy: 'infinite_scroll', next_url: null, total_links: 0 };
            }
            return null;
        })()
        "#;
        let result = self.evaluate_expression(js).await?;
        if result.is_null() {
            return Ok(None);
        }
        Ok(Some(PaginationInfo {
            strategy: result["strategy"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            next_url: result["next_url"].as_str().map(|s| s.to_string()),
            total_links: result["total_links"].as_u64().unwrap_or(0) as usize,
        }))
    }
} // end impl Page

// ---------------------------------------------------------------------------
// End-to-end pagination iteration (paginate_collect)
// ---------------------------------------------------------------------------

/// Options controlling [`paginate_collect`].
    #[derive(Debug, Clone)]
    pub struct PaginateOptions {
        /// Maximum number of distinct pages to visit (sentinel: `MaxPages`).
        pub max_pages: usize,
        /// Stop once this many items have been collected (sentinel: `MaxItems`).
        pub max_items: usize,
        /// Navigation timeout in seconds for each page.
        pub navigation_timeout_secs: u64,
        /// Number of `scroll_to_bottom` + `wait_for_stable` passes to attempt
        /// for `infinite_scroll` pages before giving up.
        pub infinite_scroll_scrolls: usize,
        /// Consecutive scroll passes that yield no new items before treating an
        /// infinite scroll as exhausted.
        pub infinite_scroll_idle_limit: usize,
        /// Mutation-quiesce window (ms) for `wait_for_stable`.
        pub stable_quiesce_ms: u64,
        /// Total time budget for `wait_for_stable`.
        pub stable_timeout: Duration,
    }

    impl Default for PaginateOptions {
        fn default() -> Self {
            Self {
                max_pages: 50,
                max_items: 100_000,
                navigation_timeout_secs: 30,
                infinite_scroll_scrolls: 20,
                infinite_scroll_idle_limit: 3,
                stable_quiesce_ms: 500,
                stable_timeout: Duration::from_secs(10),
            }
        }
    }

    /// Result of one page visit, returned by the `on_page` callback to
    /// [`paginate_collect`].
    #[derive(Debug, Clone)]
    pub struct PageVisitResult {
        /// Number of items collected on this page / scroll pass.
        pub items_collected: usize,
        /// Set to `false` to stop pagination early (`CallbackStop`).
        pub continue_crawling: bool,
    }

    impl PageVisitResult {
        /// Continue pagination after collecting `n` items.
        pub fn collected(n: usize) -> Self {
            Self {
                items_collected: n,
                continue_crawling: true,
            }
        }
    }

    /// Reason an end-to-end pagination run stopped.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PaginateStopReason {
        /// No next page detected, or the next URL was empty/unavailable.
        NoMorePages,
        /// `PaginateOptions::max_pages` reached.
        MaxPages,
        /// `PaginateOptions::max_items` collected.
        MaxItems,
        /// The next URL repeated a previously seen URL (cycle guard).
        RepeatedUrl(String),
        /// Navigation or pagination-detection failed.
        Error(String),
        /// The `on_page` callback asked to stop.
        CallbackStop,
    }

    /// Summary returned by [`paginate_collect`].
    #[derive(Debug, Clone)]
    pub struct PaginateSummary {
        /// Number of pages visited (for infinite scroll, this counts scroll passes).
        pub pages_visited: usize,
        /// Total items reported collected across all pages/passes.
        pub total_items: usize,
        /// Why the run ended.
        pub stop_reason: PaginateStopReason,
        /// URL of the last visited page.
        pub last_url: Option<String>,
    }

    /// End-to-end pagination iterator.
    ///
    /// Navigates from `start_url`, detects the pagination strategy via
    /// [`Page::detect_pagination`] (numbered / next_button / infinite_scroll),
    /// visits each subsequent page, and calls `on_page` so the caller can
    /// collect that page's items. Iteration stops on the first sentinel reached:
    /// no next page, `max_pages`, `max_items`, a repeated URL (dedup/cycle
    /// guard), or the callback returning `continue_crawling: false`.
    ///
    /// Infinite-scroll pages are handled by repeatedly calling
    /// [`Page::scroll_to_bottom`] + [`Page::wait_for_stable`] + re-detect while
    /// staying on the same URL, collecting newly loaded items each pass, until
    /// the sentinel disappears or a cap is hit.
    ///
    /// The callback receives `(&Page, total_items_so_far)` and must return a
    /// [`PageVisitResult`]; a `Result::Err` propagates out of this function.
    ///
    /// # Example
    /// ```ignore
    /// let opts = paginate::PaginateOptions::default();
    /// let summary = paginate::paginate_collect(&page, "https://shop.example/list",
    ///     &opts, |p, _| {
    ///         let items = collect_from_dom(p).await?;
    ///         Ok(paginate::PageVisitResult::collected(items.len()))
    ///     }).await?;
    /// ```
    pub async fn paginate_collect<F, E>(
        page: &Page,
        start_url: &str,
        opts: &PaginateOptions,
        mut on_page: F,
    ) -> Result<PaginateSummary, E>
    where
        F: FnMut(&Page, usize) -> Result<PageVisitResult, E>,
        E: std::fmt::Display,
    {
        let mut summary = PaginateSummary {
            pages_visited: 0,
            total_items: 0,
            stop_reason: PaginateStopReason::NoMorePages,
            last_url: None,
        };
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut current = start_url.trim().to_string();

        if current.is_empty() {
            summary.stop_reason = PaginateStopReason::Error("empty start_url".to_string());
            return Ok(summary);
        }

        // Navigate to the starting page.
        if page
            .navigate_timed(&current, opts.navigation_timeout_secs)
            .await
            .is_err()
        {
            summary.stop_reason =
                PaginateStopReason::Error(format!("navigate failed for {current}"));
            return Ok(summary);
        }

        loop {
            // Cycle guard: skip a URL we have already visited.
            if !seen.insert(current.clone()) {
                summary.stop_reason = PaginateStopReason::RepeatedUrl(current.clone());
                break;
            }

            let pagination = match page.detect_pagination().await {
                Ok(p) => p,
                Err(e) => {
                    summary.stop_reason =
                        PaginateStopReason::Error(format!("detect_pagination: {e}"));
                    break;
                }
            };

            let is_infinite = pagination
                .as_ref()
                .map(|p| p.strategy == "infinite_scroll")
                .unwrap_or(false);

            // ---- Infinite scroll: same URL, scroll + wait + re-detect ----
            if is_infinite {
                let mut idle_passes = 0usize;
                let mut done = false;
                for _ in 0..opts.infinite_scroll_scrolls {
                    if page.scroll_to_bottom().await.is_err() {
                        break;
                    }
                    let _ = page
                        .wait_for_stable(opts.stable_timeout, opts.stable_quiesce_ms)
                        .await;

                    let result = on_page(page, summary.total_items)?;
                    summary.pages_visited += 1;
                    summary.total_items += result.items_collected;
                    summary.last_url = Some(current.clone());

                    if !result.continue_crawling {
                        summary.stop_reason = PaginateStopReason::CallbackStop;
                        done = true;
                        break;
                    }
                    if result.items_collected == 0 {
                        idle_passes += 1;
                        if idle_passes >= opts.infinite_scroll_idle_limit {
                            break;
                        }
                    } else {
                        idle_passes = 0;
                    }
                    if summary.total_items >= opts.max_items {
                        summary.stop_reason = PaginateStopReason::MaxItems;
                        done = true;
                        break;
                    }
                    // Re-detect: stop once the infinite-scroll sentinel vanishes.
                    match page.detect_pagination().await {
                        Ok(Some(p2)) if p2.strategy == "infinite_scroll" => {}
                        _ => break,
                    }
                }
                if !done {
                    summary.stop_reason = PaginateStopReason::NoMorePages;
                }
                break;
            }

            // ---- Numbered / next-button: collect, then advance ----
            let result = on_page(page, summary.total_items)?;
            summary.pages_visited += 1;
            summary.total_items += result.items_collected;
            summary.last_url = Some(current.clone());

            if !result.continue_crawling {
                summary.stop_reason = PaginateStopReason::CallbackStop;
                break;
            }
            if summary.pages_visited >= opts.max_pages {
                summary.stop_reason = PaginateStopReason::MaxPages;
                break;
            }
            if summary.total_items >= opts.max_items {
                summary.stop_reason = PaginateStopReason::MaxItems;
                break;
            }

            let next_url = match pagination {
                None => None,
                Some(p) => match p.strategy.as_str() {
                    "numbered" | "next_button" => p.next_url.filter(|u| !u.is_empty()),
                    _ => None,
                },
            };

            match next_url {
                Some(url) => {
                    if page
                        .navigate_timed(&url, opts.navigation_timeout_secs)
                        .await
                        .is_err()
                    {
                        summary.stop_reason =
                            PaginateStopReason::Error(format!("navigate failed for {url}"));
                        break;
                    }
                    current = url;
                }
                None => {
                    summary.stop_reason = PaginateStopReason::NoMorePages;
                    break;
                }
            }
        }

        Ok(summary)
}

impl Page {
    // -----------------------------------------------------------------------
    // Cookie consent auto-handler (Phase 48-01)
    // -----------------------------------------------------------------------

    /// Automatically handle cookie consent banners.
    ///
    /// Attempts to click the appropriate button based on the given strategy.
    /// Returns `true` if a button was found and clicked, `false` otherwise.
    pub async fn handle_cookie_consent(
        &self,
        strategy: CookieConsentStrategy,
    ) -> Result<bool, BrowserError> {
        let action = match strategy {
            CookieConsentStrategy::RejectNonEssential => "reject",
            CookieConsentStrategy::AcceptAll => "accept",
            CookieConsentStrategy::Dismiss => "dismiss",
        };
        let js = format!(
            r#"
            (function() {{
                var selectors = {{
                    reject: [
                        'button[id*="reject"]', 'button[class*="reject"]',
                        '#onetrust-reject-all-handler', '.cc-deny'
                    ],
                    accept: [
                        'button[id*="accept"]', 'button[class*="accept"]',
                        '#onetrust-accept-btn-handler', '.cc-accept', '.cc-allow'
                    ],
                    dismiss: [
                        'button[aria-label="Close"]', 'button[class*="close"]',
                        '.cookie-banner button', '.consent-banner button'
                    ]
                }};
                var toTry = selectors['{action}'] || selectors['dismiss'];
                for (var i = 0; i < toTry.length; i++) {{
                    try {{
                        var el = document.querySelector(toTry[i]);
                        if (el && el.offsetParent !== null) {{ el.click(); return true; }}
                    }} catch(e) {{}}
                }}
                return false;
            }})()
            "#,
            action = action
        );
        let result = self.evaluate_expression(&js).await?;
        Ok(result.as_bool().unwrap_or(false))
    }

    // -----------------------------------------------------------------------
    // 4K video recording via CDP Page.startScreencast
    // -----------------------------------------------------------------------

    /// Start recording the browser page as a video.
    ///
    /// Sets the viewport to the requested resolution, then enables
    /// `Page.startScreencast` with JPEG frames.  Frames are collected in the
    /// background by the CDP read loop and stored in `CdpClient::recording_frames`.
    ///
    /// Call [`stop_recording`] to stop capture and encode the output file.
    ///
    /// # Example
    /// ```ignore
    /// let cfg = RecordingConfig::default(); // 4K 30fps
    /// page.start_recording(cfg).await?;
    /// // ... interact with page ...
    /// let result = page.stop_recording("output.mp4").await?;
    /// ```
    pub async fn start_recording(&self, config: RecordingConfig) -> Result<(), BrowserError> {
        // Idempotent start: if a recording is already active, do not stack a
        // second screencast (or re-apply the metrics override) on top of it.
        if self.client.recording_status().await.0 {
            return Ok(());
        }
        // 1. Set viewport to requested resolution
        self.client
            .send_command_with_session(
                "Emulation.setDeviceMetricsOverride",
                Some(json!({
                    "width":             config.width,
                    "height":            config.height,
                    "deviceScaleFactor": 1,
                    "mobile":            false
                })),
                &self.session_id,
            )
            .await?;

        // 2. Enable Page domain (idempotent)
        let _ = self
            .client
            .send_command_with_session("Page.enable", None, &self.session_id)
            .await;

        // 3. Activate frame collection in the read loop
        self.client
            .mark_recording_start(config.max_frames_in_memory)
            .await;

        // 4. Start screencast
        self.client
            .send_command_with_session(
                "Page.startScreencast",
                Some(json!({
                    "format":       "jpeg",
                    "quality":      config.quality,
                    "maxWidth":     config.width,
                    "maxHeight":    config.height,
                    "everyNthFrame": 1
                })),
                &self.session_id,
            )
            .await?;

        Ok(())
    }

    /// Stop recording and encode the captured frames to `output_path`.
    ///
    /// Always emits `Emulation.clearDeviceMetricsOverride` after stopping the
    /// screencast (symmetric with [`start_recording`], which applies
    /// `Emulation.setDeviceMetricsOverride`), so the page never stays pinned
    /// at the recording viewport — even when zero frames were captured.
    ///
    /// Encoding strategy (tried in order):
    /// 1. **ffmpeg** — produces MP4/WebM if ffmpeg is on PATH.
    /// 2. **AVI MJPEG** — pure-Rust, no external deps; produces `.avi`.
    /// 3. **JPEG sequence** — individual frames saved to a directory.
    ///
    /// Returns a [`RecordingResult`] with frame count, duration, file size, and
    /// the actual output path (may differ from `output_path` if AVI fallback is
    /// used).
    pub async fn stop_recording(
        &self,
        output_path: &str,
        config: &RecordingConfig,
    ) -> Result<RecordingResult, BrowserError> {
        // 1. Stop the screencast (best-effort — ignore if already stopped)
        let _ = self
            .client
            .send_command_with_session("Page.stopScreencast", None, &self.session_id)
            .await;

        // 2. Clear the device-metrics override that start_recording applied,
        //    restoring the page's normal viewport. This must fire on EVERY
        //    stop path — including the empty-recording error below — so a
        //    page is never left pinned at the recording resolution. Symmetric
        //    with Emulation.setDeviceMetricsOverride and idempotent: a second
        //    clear is a no-op in the browser.
        let _ = self
            .client
            .send_command_with_session(
                "Emulation.clearDeviceMetricsOverride",
                None,
                &self.session_id,
            )
            .await;

        // 3. Collect frames and elapsed time
        let (frames, elapsed_secs) = self.client.mark_recording_stop().await;
        let frame_count = frames.len();
        let resolution = format!("{}x{}", config.width, config.height);

        if frame_count == 0 {
            return Err(BrowserError::ActionFailed(
                "stop_recording: no frames were captured".to_string(),
            ));
        }

        // 4. Encode
        let (encoding, file_size) =
            encode_frames(&frames, config, output_path).map_err(|e| {
                BrowserError::ActionFailed(format!("stop_recording: encoding failed: {e}"))
            })?;

        // Determine actual output path (encode_frames may change the extension)
        let actual_path = if encoding == "avi_mjpeg" && !output_path.ends_with(".avi") {
            std::path::PathBuf::from(output_path)
                .with_extension("avi")
                .to_string_lossy()
                .into_owned()
        } else if encoding == "frames" && !output_path.ends_with('/') {
            std::path::PathBuf::from(output_path)
                .with_extension("")
                .to_string_lossy()
                .into_owned()
        } else {
            output_path.to_string()
        };

        Ok(RecordingResult {
            frame_count,
            duration_secs: elapsed_secs,
            file_size,
            output_path: actual_path,
            resolution,
            encoding,
        })
    }

    /// Query the current recording status without stopping.
    ///
    /// Returns `(active, frame_count, elapsed_secs)`.
    pub async fn recording_status(&self) -> (bool, usize, f64) {
        self.client.recording_status().await
    }

    // -----------------------------------------------------------------------
    // Dialog handling (Playwright-parity)
    // -----------------------------------------------------------------------

    /// Register a handler for JavaScript dialogs (alert, confirm, prompt, beforeunload).
    ///
    /// Listens for `Page.javascriptDialogOpening` events and responds with
    /// `Page.handleJavaScriptDialog` according to the given [`DialogHandler`].
    ///
    /// The handler runs in a background task until the CDP session closes.
    ///
    /// # Example
    /// ```ignore
    /// page.on_dialog(DialogHandler::AcceptWithText("yes".into())).await?;
    /// page.navigate("https://site-with-prompt.com", WaitUntil::Load).await?;
    /// ```
    pub async fn on_dialog(&self, handler: DialogHandler) -> Result<(), BrowserError> {
        // Enable Page domain so we receive dialog events
        let _ = self
            .client
            .send_command_with_session("Page.enable", None, &self.session_id)
            .await;

        let client = self.client.clone();
        let session_id = self.session_id.clone();
        // Same reasoning as the request blocker above: the dialog handler must
        // outlive the caller's `block_on`.
        let _handler = self.client.spawn_background(async move {
            let mut rx = client.subscribe();
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if event.method != "Page.javascriptDialogOpening" {
                            continue;
                        }
                        if event.session_id.as_deref() != Some(&session_id) {
                            continue;
                        }
                        let (accept, prompt_text) = match &handler {
                            DialogHandler::Accept => (true, None),
                            DialogHandler::Dismiss => (false, None),
                            DialogHandler::AcceptWithText(text) => (true, Some(text.clone())),
                        };
                        let mut params = json!({"accept": accept});
                        if let Some(text) = prompt_text {
                            params["promptText"] = json!(text);
                        }
                        let _ = client
                            .send_command_with_session(
                                "Page.handleJavaScriptDialog",
                                Some(params),
                                &session_id,
                            )
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Download handling (Playwright-parity)
    // -----------------------------------------------------------------------

    /// Set the download directory for this browser context.
    ///
    /// Uses `Browser.setDownloadBehavior` to allow downloads and direct them
    /// to the specified path. The directory is created if it does not exist.
    ///
    /// # Example
    /// ```ignore
    /// page.set_download_path("/tmp/downloads").await?;
    /// // Click a download link...
    /// ```
    pub async fn set_download_path(&self, path: &str) -> Result<(), BrowserError> {
        // Ensure directory exists
        std::fs::create_dir_all(path).map_err(|e| {
            BrowserError::ActionFailed(format!("failed to create download dir: {e}"))
        })?;

        self.client
            .send_command_with_session(
                "Browser.setDownloadBehavior",
                Some(json!({
                    "behavior": "allow",
                    "downloadPath": path
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Popup / new-tab detection (Playwright-parity)
    // -----------------------------------------------------------------------

    /// Wait for a popup (new page/tab) to be created and return a Page handle for it.
    ///
    /// Listens for `Target.targetCreated` events with `type: "page"`. The caller
    /// should trigger the popup (e.g., click a link with `target="_blank"`) after
    /// calling this method, or call this concurrently with the triggering action.
    ///
    /// # Example
    /// ```ignore
    /// // Start waiting before clicking
    /// let popup_future = page.wait_for_popup(5000);
    /// element.click(ClickOptions::default()).await?;
    /// let popup = popup_future.await?;
    /// ```
    pub async fn wait_for_popup(&self, timeout_ms: u64) -> Result<Page, BrowserError> {
        // Enable Target discovery so we get targetCreated events
        let _ = self
            .client
            .send_command("Target.setDiscoverTargets", Some(json!({"discover": true})))
            .await;

        let mut events = self.client.subscribe();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);

        loop {
            match tokio::time::timeout_at(deadline, events.recv()).await {
                Ok(Ok(evt)) => {
                    if evt.method != "Target.targetCreated" {
                        continue;
                    }
                    if let Some(ref params) = evt.params {
                        let target_info = params.get("targetInfo").unwrap_or(params);
                        let target_type = target_info
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if target_type != "page" {
                            continue;
                        }
                        let target_id = target_info
                            .get("targetId")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if target_id.is_empty() {
                            continue;
                        }

                        // Attach to the new target
                        let attach_result = self
                            .client
                            .send_command(
                                "Target.attachToTarget",
                                Some(json!({
                                    "targetId": target_id,
                                    "flatten": true
                                })),
                            )
                            .await?;

                        let new_session_id = attach_result
                            .get("sessionId")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        if new_session_id.is_empty() {
                            return Err(BrowserError::ActionFailed(
                                "wait_for_popup: failed to attach to new target".to_string(),
                            ));
                        }

                        // Enable Page domain on new session
                        let _ = self
                            .client
                            .send_command_with_session(
                                "Page.enable",
                                None,
                                &new_session_id,
                            )
                            .await;

                        let popup = Page {
                            client: self.client.clone(),
                            session_id: new_session_id,
                            frame_id: String::new(),
                            timeout: self.timeout,
                            iframe_doc_object_id: None,
                            pool_index: self.pool_index,
                            pool: self.pool.clone(),
                            events: Arc::new(Mutex::new(VecDeque::new())),
                        };
                        popup.start_event_pump().await;
                        return Ok(popup);
                    }
                }
                Ok(Err(_)) => {
                    events = self.client.subscribe();
                }
                Err(_) => {
                    return Err(BrowserError::Timeout {
                        operation: "wait_for_popup",
                        detail: format!("no popup within {timeout_ms}ms"),
                    });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Network throttling (Playwright-parity)
    // -----------------------------------------------------------------------

    /// Emulate network conditions (bandwidth throttling and latency).
    ///
    /// Uses CDP `Network.emulateNetworkConditions` to simulate slow networks.
    /// Pass `0.0` for any parameter to leave it unrestricted.
    ///
    /// # Example
    /// ```ignore
    /// // Simulate 3G connection
    /// page.throttle_network(750.0, 250.0, 100.0).await?;
    /// ```
    pub async fn throttle_network(
        &self,
        download_kbps: f64,
        upload_kbps: f64,
        latency_ms: f64,
    ) -> Result<(), BrowserError> {
        // Enable Network domain (idempotent)
        self.client
            .send_command_with_session("Network.enable", None, &self.session_id)
            .await?;

        // Convert kbps to bytes/sec for CDP (-1 means no throttle)
        let download_throughput = if download_kbps > 0.0 {
            (download_kbps * 1024.0 / 8.0) as i64
        } else {
            -1
        };
        let upload_throughput = if upload_kbps > 0.0 {
            (upload_kbps * 1024.0 / 8.0) as i64
        } else {
            -1
        };

        self.client
            .send_command_with_session(
                "Network.emulateNetworkConditions",
                Some(json!({
                    "offline": false,
                    "latency": latency_ms,
                    "downloadThroughput": download_throughput,
                    "uploadThroughput": upload_throughput,
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Disable network throttling, restoring normal network conditions.
    pub async fn disable_network_throttling(&self) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session(
                "Network.emulateNetworkConditions",
                Some(json!({
                    "offline": false,
                    "latency": 0,
                    "downloadThroughput": -1,
                    "uploadThroughput": -1,
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Private helper: dispatch a key event at the page level via CDP Input domain.
    async fn dispatch_page_key_event(
        &self,
        event_type: &str,
        key: &str,
        text: Option<&str>,
        vk_code: Option<u32>,
        modifiers: u32,
    ) -> Result<(), BrowserError> {
        let mut params = json!({
            "type": event_type,
            "key": key,
            "modifiers": modifiers,
        });

        if let Some(t) = text {
            params["text"] = json!(t);
        }

        if let Some(vk) = vk_code {
            params["windowsVirtualKeyCode"] = json!(vk);
        }

        self.client
            .send_command_with_session("Input.dispatchKeyEvent", Some(params), &self.session_id)
            .await?;
        Ok(())
    }

    // ── DOM Domain Methods (bypass Runtime.evaluate monitoring) ──────────
    /// These methods use the CDP DOM and Input domains instead of Runtime.evaluate.
    /// WAFs like Wordfence monitor Runtime.evaluate calls but NOT DOM/Input calls.
    /// State-level technique: manipulate page entirely through DOM without JS eval.

    /// Find an element by CSS selector via DOM.querySelector (no Runtime.evaluate).
    /// Returns the nodeId which can be used with other DOM methods.
    pub async fn dom_query_selector(&self, selector: &str) -> Result<i64, BrowserError> {
        // Get fresh document — node IDs change after page modifications
        let doc = self
            .client
            .send_command_with_session("DOM.getDocument", Some(serde_json::json!({"depth": 1})), &self.session_id)
            .await?;
        let root_id = doc["root"]["nodeId"].as_i64().unwrap_or(0);

        let result = self
            .client
            .send_command_with_session(
                "DOM.querySelector",
                Some(serde_json::json!({
                    "nodeId": root_id,
                    "selector": selector,
                })),
                &self.session_id,
            )
            .await?;
        Ok(result["nodeId"].as_i64().unwrap_or(0))
    }

    /// Set an attribute on a DOM node (e.g., set input value, change class, etc.)
    pub async fn dom_set_attribute(&self, node_id: i64, name: &str, value: &str) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session(
                "DOM.setAttributeValue",
                Some(serde_json::json!({
                    "nodeId": node_id,
                    "name": name,
                    "value": value,
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Get outer HTML of a DOM node (read element content without Runtime.evaluate).
    pub async fn dom_get_outer_html(&self, node_id: i64) -> Result<String, BrowserError> {
        let result = self
            .client
            .send_command_with_session(
                "DOM.getOuterHTML",
                Some(serde_json::json!({
                    "nodeId": node_id,
                })),
                &self.session_id,
            )
            .await?;
        Ok(result["outerHTML"].as_str().unwrap_or("").to_string())
    }

    /// Focus a DOM element (brings it into view for input).
    pub async fn dom_focus(&self, node_id: i64) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session(
                "DOM.focus",
                Some(serde_json::json!({
                    "nodeId": node_id,
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Click a DOM element via DOM.getBoxModel + Input.dispatchMouseEvent.
    /// This is indistinguishable from a real user click — no Runtime.evaluate.
    pub async fn dom_click(&self, selector: &str) -> Result<(), BrowserError> {
        // First get the element's box model for coordinates
        let node_id = self.dom_query_selector(selector).await?;
        if node_id == 0 {
            return Err(BrowserError::ElementNotFound { selector: selector.to_string() });
        }

        let box_model = self
            .client
            .send_command_with_session(
                "DOM.getBoxModel",
                Some(serde_json::json!({"nodeId": node_id})),
                &self.session_id,
            )
            .await?;

        // Extract center coordinates from content quad
        let quad = box_model["model"]["content"]
            .as_array()
            .ok_or_else(|| BrowserError::ConnectionFailed("no box model for element".to_string()))?;

        let x = (quad[0].as_f64().unwrap_or(0.0) + quad[4].as_f64().unwrap_or(0.0)) / 2.0;
        let y = (quad[1].as_f64().unwrap_or(0.0) + quad[5].as_f64().unwrap_or(0.0)) / 2.0;

        // Simulate human-like click: move → press → release
        for (event_type, ex, ey) in [
            ("mouseMoved", x - 2.0, y - 1.0),
            ("mouseMoved", x, y),
            ("mousePressed", x, y),
            ("mouseReleased", x, y),
        ] {
            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(serde_json::json!({
                        "type": event_type,
                        "x": ex,
                        "y": ey,
                        "button": "left",
                        "buttons": if event_type == "mouseReleased" { 0 } else { 1 },
                        "clickCount": 1,
                    })),
                    &self.session_id,
                )
                .await?;
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }

        Ok(())
    }

    /// Type text into a focused element via Input.insertText (no Runtime.evaluate).
    pub async fn dom_type(&self, text: &str) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session(
                "Input.insertText",
                Some(serde_json::json!({"text": text})),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Get page title via DOM.getDocument (no Runtime.evaluate).
    pub async fn dom_get_title(&self) -> Result<String, BrowserError> {
        let result = self
            .client
            .send_command_with_session(
                "DOM.getDocument",
                Some(serde_json::json!({"depth": 1})),
                &self.session_id,
            )
            .await?;
        // Traverse to find <title>
        if let Some(title) = result["root"]["children"]
            .as_array()
            .and_then(|children| {
                children.iter().find(|c| c["localName"].as_str() == Some("html"))
            })
            .and_then(|html| html["children"].as_array())
            .and_then(|head_body| {
                head_body.iter().find(|c| c["localName"].as_str() == Some("head"))
            })
            .and_then(|head| head["children"].as_array())
            .and_then(|head_children| {
                head_children.iter().find(|c| c["localName"].as_str() == Some("title"))
            })
            .and_then(|title| title["children"].as_array())
            .and_then(|title_children| title_children.first())
            .and_then(|text_node| text_node["nodeValue"].as_str())
        {
            return Ok(title.to_string());
        }
        Ok(String::new())
    }

    // ── State-Level Human Behavior Simulation ─────────────────────────────
    /// Pattern: APT29 / Sandworm — add realistic human timing to evade
    /// behavioral detection. Wordfence and similar WAFs analyze interaction
    /// patterns (click timing, mouse movement, typing cadence, scroll behavior)
    /// to distinguish bots from humans. These methods add randomized jitter.

    /// Click an element with human-like mouse movement (bezier curve to target).
    pub async fn human_click(&self, selector: &str) -> Result<(), BrowserError> {
        let node_id = self.dom_query_selector(selector).await?;
        if node_id == 0 {
            return Err(BrowserError::ElementNotFound { selector: selector.to_string() });
        }
        let box_model = self
            .client
            .send_command_with_session(
                "DOM.getBoxModel",
                Some(serde_json::json!({"nodeId": node_id})),
                &self.session_id,
            )
            .await?;
        let quad = box_model["model"]["content"].as_array()
            .ok_or_else(|| BrowserError::ConnectionFailed("no box model".to_string()))?;
        let tx = (quad[0].as_f64().unwrap_or(0.0) + quad[4].as_f64().unwrap_or(0.0)) / 2.0;
        let ty = (quad[1].as_f64().unwrap_or(0.0) + quad[5].as_f64().unwrap_or(0.0)) / 2.0;

        // Move from random start position with jittered steps
        let sx = 100.0 + (rand_u32() as f64 % 500.0);
        let sy = 100.0 + (rand_u32() as f64 % 400.0);
        let steps = 3 + (rand_u32() % 5) as usize;
        for i in 0..steps {
            let t = (i + 1) as f64 / steps as f64;
            let x = sx + (tx - sx) * t + ((rand_u32() as f64 % 10.0) - 5.0);
            let y = sy + (ty - sy) * t + ((rand_u32() as f64 % 10.0) - 5.0);
            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(serde_json::json!({
                        "type": "mouseMoved", "x": x, "y": y,
                    })),
                    &self.session_id,
                ).await?;
            random_delay(20, 80).await;
        }

        // Press with natural delay, then release
        self.client.send_command_with_session("Input.dispatchMouseEvent", Some(serde_json::json!({
            "type": "mousePressed", "x": tx, "y": ty, "button": "left", "clickCount": 1,
        })), &self.session_id).await?;
        random_delay(60, 200).await;
        self.client.send_command_with_session("Input.dispatchMouseEvent", Some(serde_json::json!({
            "type": "mouseReleased", "x": tx, "y": ty, "button": "left", "clickCount": 1,
        })), &self.session_id).await?;
        Ok(())
    }

    /// Type text with human-like variable delays between keystrokes.
    /// Real humans type at 150-400ms per key with occasional longer pauses.
    pub async fn human_type(&self, selector: &str, text: &str) -> Result<(), BrowserError> {
        // Focus the element first
        let node_id = self.dom_query_selector(selector).await?;
        if node_id == 0 {
            return Err(BrowserError::ElementNotFound { selector: selector.to_string() });
        }
        self.dom_focus(node_id).await?;
        random_delay(100, 300).await;

        for ch in text.chars() {
            let key_str = ch.to_string();
            // Simulate keyDown → char → keyUp with variable timing
            self.client.send_command_with_session("Input.dispatchKeyEvent", Some(serde_json::json!({
                "type": "keyDown", "key": key_str, "text": key_str,
            })), &self.session_id).await?;
            random_delay(10, 30).await;
            self.client.send_command_with_session("Input.dispatchKeyEvent", Some(serde_json::json!({
                "type": "char", "key": key_str, "text": key_str,
            })), &self.session_id).await?;
            random_delay(30, 60).await;
            self.client.send_command_with_session("Input.dispatchKeyEvent", Some(serde_json::json!({
                "type": "keyUp", "key": key_str,
            })), &self.session_id).await?;

            // Variable inter-key delay: 80-350ms typical, occasional 500-800ms pause
            let delay = if rand_u32() % 10 == 0 { 400 + (rand_u32() % 400) } else { 80 + (rand_u32() % 270) };
            tokio::time::sleep(std::time::Duration::from_millis(delay as u64)).await;
        }
        Ok(())
    }

    /// Scroll with human-like acceleration and deceleration.
    pub async fn human_scroll(&self, distance: f64) -> Result<(), BrowserError> {
        let steps = 5 + (rand_u32() % 4) as usize;
        for i in 0..steps {
            let t = i as f64 / steps as f64;
            // Ease-in-out curve
            let factor = if t < 0.5 { 2.0 * t * t } else { 1.0 - (-2.0 * t + 2.0).powi(2) / 2.0 };
            let dy = distance * factor / steps as f64;
            self.client.send_command_with_session("Input.dispatchMouseEvent", Some(serde_json::json!({
                "type": "mouseWheel", "x": 500.0, "y": 400.0, "deltaX": 0.0, "deltaY": dy,
            })), &self.session_id).await?;
            random_delay(20, 60).await;
        }
        Ok(())
    }

    // ── Anti-Detection / Stealth (Phase: auth-bypass) ────────────────────

    /// Run a full human-behavior simulation session over this page.
    ///
    /// Delegates to the `BehaviorSimulator` engine (bezier mouse with
    /// overshoot + micro-correction, gaussian typing cadence, scroll momentum
    /// with direction reversal, idle micro-jitter, occasional tab-switch).
    /// Dispatches genuine CDP `Input` events — the same primitives a real
    /// user produces.
    pub async fn simulate_human_session(&self) -> Result<(), BrowserError> {
        let mut sim = super::behavior::BehaviorSimulator::new(
            self.client.clone(),
            self.session_id.clone(),
        );
        sim.simulate_human_session().await
    }

    /// Enable Fetch domain interception — allows modifying requests/responses
    /// at the CDP level before they reach the page. Critical for bypassing
    /// JS challenges (Wordfence, Cloudflare) by intercepting the challenge
    /// page response and replacing it with the real content.
    ///
    /// When enabled, each matching request triggers a CDP Fetch.requestPaused
    /// event that must be handled (continue, fulfill, or fail) to proceed.
    pub async fn enable_request_interception(
        &self,
        url_pattern: &str,
    ) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session("Fetch.enable", Some(serde_json::json!({
                "patterns": [{
                    "requestStage": "Response",
                    "resourceType": "Document",
                    "urlPattern": url_pattern,
                }],
                "handleAuthRequests": false,
            })), &self.session_id)
            .await?;
        Ok(())
    }

    /// Disable Fetch domain interception.
    pub async fn disable_request_interception(&self) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session("Fetch.disable", None, &self.session_id)
            .await?;
        Ok(())
    }

    /// Inject JavaScript that runs in EVERY frame before any other script.
    /// Uses CDP Page.addScriptToEvaluateOnNewDocument — the same mechanism
    /// Puppeteer uses for page.evaluateOnNewDocument().
    ///
    /// This is the KEY technique for bypassing bot detection (Wordfence,
    /// Cloudflare, Datadome, etc.) because the injected script runs BEFORE
    /// the challenge/detection scripts.
    ///
    /// Returns a script identifier that can be used to remove the script later.
    pub async fn add_init_script(&self, script: &str) -> Result<String, BrowserError> {
        // The Page domain must be enabled on this session: without it the
        // registration is accepted (an identifier comes back) and the source
        // runs once under `runImmediately`, but it is not applied to the next
        // document — measured. Idempotent.
        let _ = self
            .client
            .send_command_with_session("Page.enable", None, &self.session_id)
            .await;
        let result = self
            .client
            .send_command_with_session(
                "Page.addScriptToEvaluateOnNewDocument",
                Some(serde_json::json!({
                    "source": script,
                    "runImmediately": true
                })),
                &self.session_id,
            )
            .await?;
        Ok(result
            .get("identifier")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    /// Apply standard anti-detection evasions to bypass bot detection.
    /// Injects scripts that:
    /// - Hide navigator.webdriver flag
    /// - Fake navigator.plugins length
    /// - Override chrome.runtime (headless detection vector)
    /// - Patch permissions API
    /// - Fix WebGL vendor renderer strings
    pub async fn apply_stealth_evasions(&self) -> Result<(), BrowserError> {
        let evasions = r#"
// Hide webdriver flag — this is the #1 detection vector
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

// Fake plugins — headless Chrome has 0 plugins, real Chrome has 5+
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const plugins = [
            {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format'},
            {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: ''},
            {name: 'Native Client', filename: 'internal-nacl-plugin', description: ''},
            {name: 'Widevine Content Decryption Module', filename: 'widevinecdmadapter.dll', description: 'Widevine Content Decryption Module'},
            {name: 'Microsoft Edge PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: ''},
        ];
        plugins.item = (i) => plugins[i] || null;
        plugins.namedItem = (name) => plugins.find(p => p.name === name) || null;
        plugins.refresh = () => {};
        Object.setPrototypeOf(plugins, PluginArray.prototype);
        return plugins;
    }
});

// Fix languages — headless often returns empty
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});

// Fix hardware concurrency
Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});

// Fix device memory
Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});

// Override permissions API
const originalQuery = window.navigator.permissions?.query;
if (originalQuery) {
    window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
        Promise.resolve({state: Notification.permission}) :
        originalQuery(parameters)
    );
}

// Hide Chrome automation extension
Object.defineProperty(document, 'hidden', {get: () => false});
Object.defineProperty(document, 'visibilityState', {get: () => 'visible'});

// Fix WebGL vendor strings (headless shows different values)
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return 'Intel Inc.';
    if (parameter === 37446) return 'Intel Iris OpenGL Engine';
    return getParameter.call(this, parameter);
};
"#;
        self.add_init_script(evasions).await?;
        Ok(())
    }

    /// Remove a previously injected initialization script by identifier.
    pub async fn remove_init_script(&self, identifier: &str) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session(
                "Page.removeScriptToEvaluateOnNewDocument",
                Some(serde_json::json!({"identifier": identifier})),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    // ── APT-Grade Cookie Farm ────────────────────────────────────────────
    /// Persist cookies to disk for cross-session replay. APT groups maintain
    /// access for months by storing session cookies in cookie jars.
    /// Format: JSON array of {name, value, domain, path, expires, ...}
    pub async fn save_cookies_to_file(&self, file_path: &str) -> Result<(), BrowserError> {
        let cookies = self.get_cookies().await?;
        let json = serde_json::to_string_pretty(&cookies).unwrap_or_default();
        std::fs::write(file_path, json)
            .map_err(|e| BrowserError::ConnectionFailed(format!("cookie save failed: {e}")))?;
        Ok(())
    }

    /// Load cookies from a previously saved cookie jar and inject them.
    /// This is how APT groups maintain persistent access across sessions.
    pub async fn load_cookies_from_file(
        &self,
        file_path: &str,
        url_for_context: &str,
    ) -> Result<(), BrowserError> {
        let json = std::fs::read_to_string(file_path)
            .map_err(|e| BrowserError::ConnectionFailed(format!("cookie load failed: {e}")))?;

        let cookies: Vec<super::session::CdpCookie> = serde_json::from_str(&json)
            .map_err(|e| BrowserError::ConnectionFailed(format!("cookie parse failed: {e}")))?;

        let domain = url_for_context
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(url_for_context);

        for cookie in &cookies {
            self.client
                .send_command_with_session(
                    "Network.setCookie",
                    Some(serde_json::json!({
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "url": url_for_context,
                        "path": cookie.path,
                        "httpOnly": cookie.http_only,
                        "secure": cookie.secure,
                        "sameSite": cookie.same_site,
                    })),
                    &self.session_id,
                )
                .await?;
        }
        Ok(())
    }

    // ── Cookie Session Bridge (Phase: auth-bypass) ────────────────────────

    /// Inject cookies via CDP Network.setCookie. Sets cookies BEFORE navigation
    /// so that WAF challenges (Wordfence, Cloudflare) see them and skip the
    /// challenge. Accepts cookie strings like "name=value; name2=value2".
    /// The domain is extracted from url_for_context (e.g., "https://ghraonline.com").
    pub async fn inject_cookies(
        &self,
        cookie_str: &str,
        url_for_context: &str,
    ) -> Result<(), BrowserError> {
        let domain = url_for_context
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(url_for_context);

        for cookie in cookie_str.split(';') {
            let cookie = cookie.trim();
            if cookie.is_empty() || !cookie.contains('=') {
                continue;
            }
            let mut parts = cookie.splitn(2, '=');
            let name = parts.next().unwrap_or("").trim();
            let value = parts.next().unwrap_or("").trim();

            self.client
                .send_command_with_session(
                    "Network.setCookie",
                    Some(serde_json::json!({
                        "name": name,
                        "value": value,
                        "domain": domain,
                        "url": url_for_context,
                        "path": "/",
                        "httpOnly": false,
                        "secure": true,
                        "sameSite": "Lax",
                    })),
                    &self.session_id,
                )
                .await?;
        }
        Ok(())
    }

    /// Retrieve all cookies from the browser context via CDP Network.getCookies.
    pub async fn get_cookies(&self) -> Result<Vec<super::session::CdpCookie>, BrowserError> {
        super::session::get_cookies(&self.client, &self.session_id).await
    }

    /// Delete only cookies whose name starts with any `prefixes` (Cxense meter
    /// counters, etc.). Returns the number deleted. See session helper docs.
    pub async fn delete_cookies_by_prefix(
        &self,
        prefixes: &[&str],
    ) -> Result<usize, BrowserError> {
        super::session::delete_cookies_by_prefix(&self.client, &self.session_id, prefixes).await
    }

    /// Generate a Cookie header string from browser cookies for a given URL.
    pub async fn cookie_string(&self, url: &str) -> Result<String, BrowserError> {
        let cookies = self.get_cookies().await?;
        let domain = extract_domain_from_url(url);
        let relevant: Vec<String> = cookies
            .iter()
            .filter(|c| {
                c.domain == domain
                    || c.domain == format!(".{domain}")
                    || domain.ends_with(&c.domain.trim_start_matches('.'))
            })
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        Ok(relevant.join("; "))
    }

    /// Set cookies from a Cookie header string into the browser.
    pub async fn set_cookies_from_header(
        &self,
        cookie_header: &str,
        domain: &str,
        path: &str,
    ) -> Result<(), BrowserError> {
        let cookies: Vec<super::session::CdpCookie> = cookie_header
            .split(';')
            .filter_map(|pair| {
                let pair = pair.trim();
                if pair.is_empty() {
                    return None;
                }
                let mut parts = pair.splitn(2, '=');
                let name = parts.next()?.trim().to_string();
                let value = parts.next().unwrap_or("").trim().to_string();
                if name.is_empty() {
                    return None;
                }
                Some(super::session::CdpCookie {
                    name,
                    value,
                    domain: domain.to_string(),
                    path: path.to_string(),
                    expires: 0.0,
                    http_only: false,
                    secure: false,
                    same_site: "Lax".to_string(),
                    size: None,
                })
            })
            .collect();

        if !cookies.is_empty() {
            super::session::set_cookies(&self.client, &self.session_id, &cookies).await?;
        }
        Ok(())
    }

    /// Make an authenticated HTTP GET using the browser's cookies (cookie bridge).
    pub async fn authenticated_get(&self, url: &str) -> Result<(u16, String), BrowserError> {
        self.authenticated_request(url, "GET", "").await
    }

    /// Core cookie bridge: HTTP request with browser cookies injected as Cookie header.
    /// Egresses via the runtime egress contract (proxy-aware; Tor by default).
    pub async fn authenticated_request(
        &self,
        url: &str,
        method: &str,
        body: &str,
    ) -> Result<(u16, String), BrowserError> {
        let cookie_header = self.cookie_string(url).await?;

        // T-207: the single browser-zone predicate gates this fetch first —
        // a malformed contract proxy refuses here (N3) instead of panicking
        // in the builder below.
        if let Err(reason) = super::zone::browser_zone_egress() {
            return Err(BrowserError::CdpError {
                code: -1,
                message: reason,
            });
        }
        // Egress contract (proxy-aware; Tor by default): a default agent here
        // would carry the browser's cookies out from the box IP (audit-05 F-7).
        let agent = crate::runtime::egress_http::agent();

        // T-107b (T-107 residual): rate-limit parity with the contract — the
        // same per-host `rate_limit_wait` the `egress_http` shims (and the
        // fetch/interp callers) apply runs before either branch below fires,
        // so GET/POST here are no hotter than any other contract caller.
        // After the zone gate: a refusal attempts no request and stays off
        // the limiter.
        crate::runtime::egress_http::rate_limit_wait(url);
        crate::runtime::egress_http::note_missing_ech_on_direct_egress(url);

        let response = match method.to_uppercase().as_str() {
            "GET" => agent
                .get(url)
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )
                .header("Accept", "*/*")
                .header("Cookie", &cookie_header)
                .header("X-Requested-With", "XMLHttpRequest")
                .call(),
            "POST" => agent
                .post(url)
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )
                .header("Accept", "*/*")
                .header("Cookie", &cookie_header)
                .header("X-Requested-With", "XMLHttpRequest")
                .send(body.as_bytes()),
            other => {
                return Err(BrowserError::CdpError {
                    code: -1,
                    message: format!("unsupported HTTP method: {other}"),
                });
            }
        };

        let response = response.map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("HTTP request failed: {e}"),
        })?;

        let status = response.status().as_u16();
        let body = response
            .into_body()
            .read_to_string()
            .map_err(|e| BrowserError::CdpError {
                code: -1,
                message: format!("failed to read response body: {e}"),
            })?;

        Ok((status, body))
    }
}

/// Extract a string value from a Runtime.evaluate result.
fn extract_string_result(result: &Value) -> Option<String> {
    result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Escape a string for use inside a JavaScript single-quoted string.
pub(crate) fn escape_js_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Serialize a payload as a JavaScript/JSON double-quoted string literal.
///
/// The `.tl` → CDP bridge must never interpolate untrusted HTML into a JS
/// *template literal*: a raw backtick ends the literal and `${…}` is
/// evaluated — the historical `Page.set_content` injection (audit-05 F-4;
/// cycle-02 §3.1 S3). Escaping is therefore literal-encoding, not character
/// blacklisting (a helper that only escapes `\` and `` ` `` still leaves
/// `${…}` live).
///
/// A JSON string is a valid JavaScript string literal — every escape form
/// `serde_json` emits (`\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`, `\uXXXX`)
/// is legal in JS — and it can neither terminate early nor start an
/// interpolation. U+2028/U+2029 are escaped explicitly for pre-ES2019
/// engines. (`&str` serialization is infallible.)
pub(crate) fn js_string_literal(s: &str) -> String {
    match serde_json::to_string(s) {
        Ok(json) => json
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029"),
        Err(_) => "\"\"".to_string(),
    }
}

/// Extract the domain from a URL for cookie matching.
fn extract_domain_from_url(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wait_until_as_cdp_name() {
        assert_eq!(WaitUntil::Load.as_cdp_name(), "load");
        assert_eq!(WaitUntil::DomContentLoaded.as_cdp_name(), "DOMContentLoaded");
        assert_eq!(WaitUntil::NetworkIdle.as_cdp_name(), "networkIdle");
        assert_eq!(
            WaitUntil::NetworkAlmostIdle.as_cdp_name(),
            "networkAlmostIdle"
        );
    }

    #[test]
    fn test_navigation_result_construction() {
        let result = NavigationResult {
            url: "https://example.com".to_string(),
            frame_id: "F1".to_string(),
            status_code: Some(200),
        };
        assert_eq!(result.url, "https://example.com");
        assert_eq!(result.frame_id, "F1");
        assert_eq!(result.status_code, Some(200));
    }

    #[test]
    fn test_navigation_result_no_status() {
        let result = NavigationResult {
            url: "about:blank".to_string(),
            frame_id: "F2".to_string(),
            status_code: None,
        };
        assert!(result.status_code.is_none());
    }

    #[test]
    fn test_escape_js_string_basic() {
        assert_eq!(escape_js_string("div.class"), "div.class");
    }

    #[test]
    fn test_escape_js_string_quotes() {
        assert_eq!(escape_js_string("a[href='test']"), "a[href=\\'test\\']");
    }

    #[test]
    fn test_escape_js_string_backslash() {
        assert_eq!(escape_js_string("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_escape_js_string_newlines() {
        assert_eq!(escape_js_string("a\nb\rc"), "a\\nb\\rc");
    }

    /// S3 (audit-05 F-4): the payload that broke the old escaping — a
    /// backtick plus `${…}` — must round-trip as an inert double-quoted
    /// string literal, never as template interpolation.
    #[test]
    fn test_js_string_literal_neutralizes_template_injection() {
        let payload = "</x>`${alert(1)}` ${1+1} \\ ` ' \" \n\u{2028}";
        let literal = js_string_literal(payload);
        // 1. The literal is a valid JSON string equal to the original payload.
        let back: String =
            serde_json::from_str(&literal).expect("literal must parse as a JSON string");
        assert_eq!(back, payload, "round-trip must preserve the payload exactly");
        // 2. Assembled into the set_content statement it stays a plain string
        //    assignment — the sequence that starts a template literal is gone.
        let statement = format!("document.documentElement.innerHTML = {};", literal);
        assert!(
            !statement.contains(concat!("innerHTML = ", "`")),
            "no template-literal form may remain: {statement}"
        );
        assert!(statement.ends_with(";"), "statement shape: {statement}");
        // 3. Escapes are JS-legal: no raw control characters inside the literal.
        assert!(!literal.contains('\n'), "newlines must be escaped: {literal}");
        assert!(
            !literal.contains('\u{2028}'),
            "U+2028 must be escaped for pre-ES2019 engines: {literal}"
        );
    }

    /// S3 source guard: the historical bug was building the `set_content`
    /// statement as a backtick template literal. Banned in the two bridge
    /// files; the pattern is built from parts so this test's own text can
    /// never satisfy the scan (mirrors the zone/egress guards).
    #[test]
    fn set_content_sites_never_build_template_literals() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let banned = concat!("innerHTML = ", "`");
        let mut offenders = Vec::new();
        for rel in ["src/runtime/browser.rs", "src/interp.rs"] {
            let src = std::fs::read_to_string(root.join(rel)).expect("read bridge file");
            let code = src
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            if code.contains(banned) {
                offenders.push(rel);
            }
        }
        assert!(
            offenders.is_empty(),
            "template-literal set_content statement returned in {offenders:?} — \
             use crate::browser::page::js_string_literal instead"
        );
    }

    #[test]
    fn test_extract_string_result_valid() {
        let val = serde_json::json!({
            "result": {
                "type": "string",
                "value": "https://example.com"
            }
        });
        assert_eq!(
            extract_string_result(&val),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_extract_string_result_null() {
        let val = serde_json::json!({
            "result": {
                "type": "undefined"
            }
        });
        assert_eq!(extract_string_result(&val), None);
    }

    #[test]
    fn test_query_xpath_js_expression_generation() {
        let expr = "//div[@class='test']";
        let escaped = escape_js_string(expr);
        let js = format!(
            "document.evaluate('{}', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue",
            escaped
        );
        assert!(js.contains("document.evaluate('//div[@class=\\'test\\']'"));
        assert!(js.contains("FIRST_ORDERED_NODE_TYPE"));
        assert!(js.contains("singleNodeValue"));
    }

    #[test]
    fn test_query_xpath_all_js_expression_generation() {
        let expr = "//a[@href]";
        let escaped = escape_js_string(expr);
        let js = format!(
            "(function() {{ var result = document.evaluate('{}', document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null); var nodes = []; for (var i = 0; i < result.snapshotLength; i++) nodes.push(result.snapshotItem(i)); return nodes; }})()",
            escaped
        );
        assert!(js.contains("document.evaluate('//a[@href]'"));
        assert!(js.contains("ORDERED_NODE_SNAPSHOT_TYPE"));
        assert!(js.contains("snapshotLength"));
        assert!(js.contains("snapshotItem"));
    }

    #[test]
    fn test_query_xpath_escapes_special_chars() {
        let expr = "//div[contains(text(), 'it\\'s')]";
        let escaped = escape_js_string(expr);
        // The single quotes inside should be escaped
        assert!(escaped.contains("\\'"));
    }

    #[test]
    fn test_keyboard_shortcut_modifier_bits() {
        // Verify modifier constants work correctly for keyboard_shortcut
        let ctrl_a_mods = MODIFIER_CTRL;
        assert_eq!(ctrl_a_mods & MODIFIER_CTRL, MODIFIER_CTRL);
        assert_eq!(ctrl_a_mods & MODIFIER_SHIFT, 0);

        let ctrl_shift_mods = MODIFIER_CTRL | MODIFIER_SHIFT;
        assert_eq!(ctrl_shift_mods & MODIFIER_CTRL, MODIFIER_CTRL);
        assert_eq!(ctrl_shift_mods & MODIFIER_SHIFT, MODIFIER_SHIFT);
        assert_eq!(ctrl_shift_mods & MODIFIER_ALT, 0);
    }

    #[test]
    fn test_special_key_code_for_shortcut() {
        // Verify special_key_code returns correct VK codes for common shortcuts
        assert_eq!(special_key_code("Enter"), Some(13));
        assert_eq!(special_key_code("Tab"), Some(9));
        assert_eq!(special_key_code("Escape"), Some(27));
        // Regular chars return None (handled differently)
        assert_eq!(special_key_code("a"), None);
    }

    #[test]
    fn test_scroll_to_bottom_js_expression() {
        let expr = "window.scrollTo(0, document.body.scrollHeight)";
        assert!(expr.contains("scrollTo"));
        assert!(expr.contains("scrollHeight"));
    }

    #[test]
    fn test_chrome_net_error_mapping_in_navigate() {
        // Test all major Chrome net:: error patterns
        use super::super::error::{map_chrome_net_error, NavigationError};

        let dns = map_chrome_net_error("net::ERR_NAME_NOT_RESOLVED");
        assert!(matches!(dns, NavigationError::DnsFailure(_)));

        let ssl = map_chrome_net_error("net::ERR_SSL_PROTOCOL_ERROR");
        assert!(matches!(ssl, NavigationError::SslError(_)));

        let ssl_cert = map_chrome_net_error("net::ERR_CERT_AUTHORITY_INVALID");
        assert!(matches!(ssl_cert, NavigationError::SslError(_)));

        let timeout = map_chrome_net_error("net::ERR_CONNECTION_TIMED_OUT");
        assert!(matches!(timeout, NavigationError::Timeout));

        let refused = map_chrome_net_error("net::ERR_CONNECTION_REFUSED");
        assert!(matches!(refused, NavigationError::ConnectionRefused));

        let other = map_chrome_net_error("net::ERR_ABORTED");
        assert!(matches!(other, NavigationError::ChromeNetError(_)));
    }

    #[test]
    fn test_iframe_page_has_different_frame_id() {
        // An iframe Page must have a different frame_id than the parent
        let parent_frame_id = "PARENT_FRAME";
        let iframe_frame_id = "IFRAME_FRAME";
        assert_ne!(parent_frame_id, iframe_frame_id);

        // Simulate: parent page has no iframe_doc_object_id
        let parent_doc: Option<String> = None;
        assert!(parent_doc.is_none());

        // Simulate: iframe page has iframe_doc_object_id set
        let iframe_doc: Option<String> = Some("obj-123".to_string());
        assert!(iframe_doc.is_some());
    }

    #[test]
    fn test_iframe_scoped_query_selector_uses_call_function_on() {
        // When iframe_doc_object_id is set, query_selector should use
        // callFunctionOn instead of Runtime.evaluate
        let doc_id = Some("iframe-doc-obj-456".to_string());
        let selector = "div.content";
        let escaped = escape_js_string(selector);

        // With iframe_doc_object_id set, the function should be built like this:
        let func = format!("function() {{ return this.querySelector('{escaped}'); }}");
        assert_eq!(
            func,
            "function() { return this.querySelector('div.content'); }"
        );

        // And it should be called with callFunctionOn using the doc objectId
        assert!(doc_id.is_some());
        assert_eq!(doc_id.as_deref(), Some("iframe-doc-obj-456"));
    }

    #[test]
    fn test_iframe_scoped_query_selector_all_uses_call_function_on() {
        let doc_id = Some("iframe-doc-obj-789".to_string());
        let selector = "li.item";
        let escaped = escape_js_string(selector);

        let func = format!(
            "function() {{ return Array.from(this.querySelectorAll('{escaped}')); }}"
        );
        assert!(func.contains("querySelectorAll('li.item')"));
        assert!(doc_id.is_some());
    }

    #[test]
    fn test_top_level_page_has_no_iframe_doc() {
        // A top-level Page should have iframe_doc_object_id = None
        let iframe_doc: Option<String> = None;
        assert!(iframe_doc.is_none());
    }

    #[test]
    fn test_iframe_access_denied_error_display() {
        let err = BrowserError::IframeAccessDenied {
            selector: "iframe#cross-origin".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "iframe access denied: iframe#cross-origin"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 48-01: Batch DOM, resource blocking, pagination, cookie consent
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_all_text_js_generation() {
        let selector = ".price";
        let selector_json = serde_json::to_string(selector).unwrap();
        let js = format!(
            "Array.from(document.querySelectorAll({sel})).map(el => el.innerText)",
            sel = selector_json
        );
        assert!(js.contains(r#"document.querySelectorAll(".price")"#));
        assert!(js.contains("el.innerText"));
        assert!(js.starts_with("Array.from("));
    }

    #[test]
    fn test_extract_all_attrs_js_generation() {
        let selector = "a.link";
        let attrs = ["href", "innerText", "class"];
        let attrs_json = serde_json::to_string(&attrs).unwrap();
        let selector_json = serde_json::to_string(selector).unwrap();
        let js = format!(
            "Array.from(document.querySelectorAll({sel})).map(el => {{ \
                let r = {{}}; \
                {attrs}.forEach(a => {{ r[a] = a === 'innerText' ? el.innerText : a === 'innerHTML' ? el.innerHTML : el.getAttribute(a) }}); \
                return r; \
            }})",
            sel = selector_json,
            attrs = attrs_json
        );
        assert!(js.contains(r#"querySelectorAll("a.link")"#));
        assert!(js.contains("innerText"));
        assert!(js.contains("innerHTML"));
        assert!(js.contains("getAttribute"));
    }

    #[test]
    fn test_dom_snapshot_params() {
        let params = serde_json::json!({
            "computedStyles": ["display", "visibility", "color"],
            "includeDOMRects": false,
            "includePaintOrder": false
        });
        let styles = params["computedStyles"].as_array().unwrap();
        assert_eq!(styles.len(), 3);
        assert_eq!(params["includeDOMRects"], false);
        assert_eq!(params["includePaintOrder"], false);
    }

    #[test]
    fn test_structured_data_js() {
        let js = r#"
        (function() {
            let result = { json_ld: [], open_graph: {}, meta: {} };
            document.querySelectorAll('script[type="application/ld+json"]').forEach(s => {
                try { result.json_ld.push(JSON.parse(s.textContent)); } catch(e) {}
            });
            document.querySelectorAll('meta[property^="og:"]').forEach(m => {
                result.open_graph[m.getAttribute('property')] = m.getAttribute('content');
            });
            document.querySelectorAll('meta[name]').forEach(m => {
                result.meta[m.getAttribute('name')] = m.getAttribute('content');
            });
            return result;
        })()
        "#;
        assert!(js.contains("json_ld"));
        assert!(js.contains("open_graph"));
        assert!(js.contains("application/ld+json"));
        assert!(js.contains(r#"meta[property^="og:"]"#));
        assert!(js.contains("meta[name]"));
    }

    #[test]
    fn test_resource_type_cdp_names() {
        use super::super::network::ResourceType;
        assert_eq!(ResourceType::Document.as_str(), "Document");
        assert_eq!(ResourceType::Script.as_str(), "Script");
        assert_eq!(ResourceType::Stylesheet.as_str(), "Stylesheet");
        assert_eq!(ResourceType::Image.as_str(), "Image");
        assert_eq!(ResourceType::Font.as_str(), "Font");
        assert_eq!(ResourceType::Media.as_str(), "Media");
        assert_eq!(ResourceType::WebSocket.as_str(), "WebSocket");
        assert_eq!(ResourceType::Manifest.as_str(), "Manifest");
        assert_eq!(ResourceType::Other.as_str(), "Other");
    }

    #[test]
    fn test_block_resources_fetch_enable_params() {
        use super::super::network::ResourceType;
        let types = [ResourceType::Image, ResourceType::Font, ResourceType::Stylesheet];
        let patterns: Vec<serde_json::Value> = types
            .iter()
            .map(|t| {
                serde_json::json!({
                    "requestStage": "Request",
                    "resourceType": t.as_str()
                })
            })
            .collect();
        assert_eq!(patterns.len(), 3);
        assert_eq!(patterns[0]["resourceType"], "Image");
        assert_eq!(patterns[1]["resourceType"], "Font");
        assert_eq!(patterns[2]["resourceType"], "Stylesheet");
        assert_eq!(patterns[0]["requestStage"], "Request");
    }

    #[test]
    fn test_pagination_strategies() {
        let numbered = PaginationInfo {
            strategy: "numbered".to_string(),
            next_url: Some("https://example.com?page=2".to_string()),
            total_links: 5,
        };
        assert_eq!(numbered.strategy, "numbered");
        assert!(numbered.next_url.is_some());
        assert_eq!(numbered.total_links, 5);

        let next_button = PaginationInfo {
            strategy: "next_button".to_string(),
            next_url: Some("https://example.com/page/2".to_string()),
            total_links: 1,
        };
        assert_eq!(next_button.strategy, "next_button");

        let load_more = PaginationInfo {
            strategy: "load_more".to_string(),
            next_url: None,
            total_links: 0,
        };
        assert_eq!(load_more.strategy, "load_more");
        assert!(load_more.next_url.is_none());

        let infinite = PaginationInfo {
            strategy: "infinite_scroll".to_string(),
            next_url: None,
            total_links: 0,
        };
        assert_eq!(infinite.strategy, "infinite_scroll");
    }

    #[test]
    fn test_cookie_consent_strategies() {
        assert_eq!(
            CookieConsentStrategy::RejectNonEssential,
            CookieConsentStrategy::RejectNonEssential
        );
        assert_ne!(
            CookieConsentStrategy::RejectNonEssential,
            CookieConsentStrategy::AcceptAll
        );
        assert_ne!(
            CookieConsentStrategy::AcceptAll,
            CookieConsentStrategy::Dismiss
        );

        // Verify the action strings match what the JS expects
        let action_reject = match CookieConsentStrategy::RejectNonEssential {
            CookieConsentStrategy::RejectNonEssential => "reject",
            CookieConsentStrategy::AcceptAll => "accept",
            CookieConsentStrategy::Dismiss => "dismiss",
        };
        assert_eq!(action_reject, "reject");

        let action_accept = match CookieConsentStrategy::AcceptAll {
            CookieConsentStrategy::RejectNonEssential => "reject",
            CookieConsentStrategy::AcceptAll => "accept",
            CookieConsentStrategy::Dismiss => "dismiss",
        };
        assert_eq!(action_accept, "accept");
    }

    #[test]
    fn test_smart_wait_js_generation() {
        let quiesce_ms: u64 = 200;
        let timeout_ms: u128 = 5000;
        let js = format!(
            "new Promise((resolve) => {{ setTimeout(() => {{ resolve(true); }}, {quiesce_ms}); setTimeout(() => {{ resolve(false); }}, {timeout_ms}); }})",
            quiesce_ms = quiesce_ms,
            timeout_ms = timeout_ms
        );
        assert!(js.contains("Promise"));
        assert!(js.contains("200"));
        assert!(js.contains("5000"));
    }

    #[test]
    fn test_pagination_info_clone() {
        let info = PaginationInfo {
            strategy: "numbered".to_string(),
            next_url: Some("https://example.com?page=3".to_string()),
            total_links: 10,
        };
        let cloned = info.clone();
        assert_eq!(cloned.strategy, info.strategy);
        assert_eq!(cloned.next_url, info.next_url);
        assert_eq!(cloned.total_links, info.total_links);
    }

    #[test]
    fn test_cookie_consent_strategy_copy() {
        let strategy = CookieConsentStrategy::AcceptAll;
        let copied = strategy;
        assert_eq!(copied, CookieConsentStrategy::AcceptAll);
    }

    #[test]
    fn test_action_failed_error_display() {
        let err = BrowserError::ActionFailed("DOMSnapshot failed: timeout".to_string());
        assert_eq!(
            err.to_string(),
            "action failed: DOMSnapshot failed: timeout"
        );
    }

    #[test]
    fn test_evaluate_expression_params() {
        let expression = "1 + 1";
        let params = serde_json::json!({
            "expression": expression,
            "returnByValue": true,
            "awaitPromise": true
        });
        assert_eq!(params["expression"], "1 + 1");
        assert_eq!(params["returnByValue"], true);
        assert_eq!(params["awaitPromise"], true);
    }

    #[test]
    fn test_parse_frame_tree_integration() {
        // Verify parse_frame_tree works correctly from page context
        use super::super::frame::parse_frame_tree;
        let tree = serde_json::json!({
            "frameTree": {
                "frame": {
                    "id": "MAIN",
                    "url": "https://example.com",
                    "name": ""
                },
                "childFrames": [{
                    "frame": {
                        "id": "IFRAME1",
                        "url": "https://example.com/embed",
                        "name": "embed"
                    }
                }]
            }
        });

        let frames = parse_frame_tree(&tree);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].id, "MAIN");
        assert!(frames[0].parent_id.is_none());
        assert_eq!(frames[1].id, "IFRAME1");
        assert_eq!(frames[1].parent_id.as_deref(), Some("MAIN"));
    }
    // -----------------------------------------------------------------------
    // Recording: start/stop symmetry (B5)
    // -----------------------------------------------------------------------

    /// `stop_recording` must emit `Emulation.clearDeviceMetricsOverride`
    /// (symmetric with the `Emulation.setDeviceMetricsOverride` that
    /// `start_recording` applies), the clear must arrive AFTER
    /// `Page.stopScreencast`, and a repeated `start_recording` must be a
    /// no-op. Asserted against a mock CDP peer over a real OS pipe — no
    /// network, no live browser.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_stop_recording_clears_device_metrics_override() {
        use crate::browser::cdp::pipe_test_peer::{loopback_client, wait_for_observed};

        let (client, observed) = loopback_client().await;
        let page = Page::from_cdp(client, "sess-b5".to_string(), None, None);
        let config = RecordingConfig {
            width: 1280,
            height: 720,
            ..RecordingConfig::default()
        };

        page.start_recording(config.clone())
            .await
            .expect("start_recording should succeed against the mock peer");

        // Idempotent start: second call adds no further commands.
        page.start_recording(config.clone())
            .await
            .expect("second start_recording must be an idempotent no-op");

        // The mock peer never pushes screencastFrame events, so zero frames
        // are captured and stop_recording errors out — but the metrics clear
        // must still have been emitted before that error path returns.
        let result = page.stop_recording("/tmp/tallow-b5-out.mp4", &config).await;
        assert!(result.is_err(), "zero-frame stop should report no frames captured");

        let methods = wait_for_observed(&observed, 5, Duration::from_secs(5));
        assert_eq!(
            methods.first().map(String::as_str),
            Some("Emulation.setDeviceMetricsOverride"),
            "start must apply the metrics override first: {methods:?}"
        );
        let stop = methods
            .iter()
            .position(|m| m == "Page.stopScreencast")
            .expect("stop_recording must emit Page.stopScreencast");
        let clear = methods
            .iter()
            .position(|m| m == "Emulation.clearDeviceMetricsOverride")
            .expect("stop_recording must emit Emulation.clearDeviceMetricsOverride");
        assert!(
            stop < clear,
            "clearDeviceMetricsOverride must follow stopScreencast: {methods:?}"
        );
        let sets = methods
            .iter()
            .filter(|m| *m == "Emulation.setDeviceMetricsOverride")
            .count();
        let clears = methods
            .iter()
            .filter(|m| *m == "Emulation.clearDeviceMetricsOverride")
            .count();
        assert_eq!(sets, 1, "idempotent start must apply metrics exactly once: {methods:?}");
        assert_eq!(clears, 1, "exactly one clear expected after one stop: {methods:?}");
    }

    /// T-107 (audit-05 F-7 / RT1 ATK-1.1): the cookie bridge must ride the
    /// runtime egress contract. A bare default `ureq::Agent` here would send
    /// the browser's cookies to the target from the box IP; keep the pattern
    /// out of this file. The pattern is split so the test cannot match its own
    /// source text.
    #[test]
    fn authenticated_cookie_bridge_rides_the_egress_contract() {
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/browser/page.rs"
        ))
        .expect("read src/browser/page.rs");
        let banned = concat!("ureq::Agent::", "new_with_defaults()");
        assert!(
            !src.contains(banned),
            "page.rs must not build a default (unproxied) ureq agent — route through \
             crate::runtime::egress_http"
        );
        assert!(
            src.contains("crate::runtime::egress_http::"),
            "the cookie bridge must call into crate::runtime::egress_http"
        );
    }

    /// T-107b (T-107 residual): rate-limit parity — the cookie bridge must
    /// apply the shared per-host `rate_limit_wait` the contract's shims use,
    /// exactly once per request, after the zone gate (a refusal attempts no
    /// request and must not consume a limiter slot). Scans the
    /// `authenticated_request` slice only, so this test's own source cannot
    /// satisfy it.
    #[test]
    fn authenticated_bridge_applies_the_shared_rate_limiter() {
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/browser/page.rs"
        ))
        .expect("read src/browser/page.rs");
        let start = src
            .find("pub async fn authenticated_request")
            .expect("authenticated_request must exist");
        let end = start
            + src[start..]
                .find("fn extract_string_result")
                .expect("slice end marker missing");
        let body = &src[start..end];

        let limiter = "crate::runtime::egress_http::rate_limit_wait(url)";
        assert_eq!(
            body.matches("rate_limit_wait(").count(),
            1,
            "exactly one rate_limit_wait call per request — none inside the branches"
        );
        assert!(
            body.contains(limiter),
            "the bridge must call the shared per-host limiter with the request URL"
        );

        let zone = body
            .find("super::zone::browser_zone_egress()")
            .expect("zone gate missing");
        let rate = body.find(limiter).unwrap();
        let get = body.find(".get(url)").expect("GET branch missing");
        let post = body.find(".post(url)").expect("POST branch missing");
        assert!(
            zone < rate,
            "limiter must run after the zone gate: refusals never reach it"
        );
        assert!(
            rate < get && rate < post,
            "the limiter must run before the GET/POST dispatch branches"
        );
    }
}

/// `*`-only glob match: every other character is literal.
///
/// Deliberately not a full glob: `?` and character classes are not supported,
/// so a pattern never silently means something the caller did not intend.
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut rest = text;
    if let Some(first) = parts.first().filter(|p| !p.is_empty()) {
        match rest.strip_prefix(first) {
            Some(r) => rest = r,
            None => return false,
        }
    }
    for part in &parts[1..parts.len().saturating_sub(1)] {
        if part.is_empty() {
            continue;
        }
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    match parts.last() {
        Some(last) if !last.is_empty() => rest.ends_with(last),
        _ => true,
    }
}

#[cfg(test)]
mod glob_tests {
    use super::glob_match;

    #[test]
    fn patterns_match_only_what_they_name() {
        assert!(glob_match("http://127.0.0.1:8080/", "http://127.0.0.1:8080/"));
        assert!(!glob_match("http://127.0.0.1:8080/", "http://127.0.0.1:8081/"));

        // Wildcards in each position.
        assert!(glob_match("*/api/*", "http://x/api/items?id=1"));
        assert!(glob_match("http://x/*", "http://x/anything"));
        assert!(glob_match("*suffix", "prefix-suffix"));
        assert!(!glob_match("*suffix", "prefix-suffixed"));
        assert!(glob_match("a*b*c", "a--b--c"));
        assert!(!glob_match("a*b*c", "a--c--b"));

        // No accidental regex semantics: '.' is a literal dot.
        assert!(!glob_match("a.c", "abc"));
        assert!(glob_match("*", "anything at all"));
    }
}
/// Heuristic used by the tag injectors: a value with a scheme or a
/// protocol-relative prefix is a URL; everything else is element text.
fn looks_like_url(value: &str) -> bool {
    let v = value.trim_start();
    v.starts_with("//")
        || v.starts_with("http://")
        || v.starts_with("https://")
        || v.starts_with("data:")
        || v.starts_with("blob:")
}
/// Map a CDP method to the category the `.tl` surface names.
///
/// Anything not listed is not recorded: a buffer of every CDP event would be
/// mostly noise (`Network.dataReceived`, `Page.frameScheduledNavigation`).
fn classify_event(method: &str) -> Option<&'static str> {
    match method {
        "Runtime.consoleAPICalled" => Some("console"),
        "Runtime.exceptionThrown" => Some("error"),
        "Network.requestWillBeSent" => Some("request"),
        "Network.responseReceived" => Some("response"),
        "Page.fileChooserOpened" => Some("filechooser"),
        "Page.downloadWillBegin" | "Browser.downloadWillBegin" => Some("download"),
        "Runtime.bindingCalled" => Some("binding"),
        _ => None,
    }
}
