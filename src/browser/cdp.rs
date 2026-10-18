//! Chrome DevTools Protocol (CDP) client over WebSocket.
//!
//! Provides a JSON-RPC client that communicates with Chromium via the CDP protocol.
//! Handles command/response correlation, event broadcasting, and session multiplexing.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::error::BrowserError;

/// A console message captured from a `Runtime.consoleAPICalled` CDP event.
#[derive(Debug, Clone)]
pub struct ConsoleMessage {
    /// Log level: `"log"`, `"warn"`, `"error"`, `"info"`, or `"debug"`.
    pub level: String,
    /// The concatenated text of all message arguments.
    pub text: String,
    /// CDP timestamp (milliseconds since Unix epoch).
    pub timestamp: f64,
}

/// Transport mode for communicating with the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// WebSocket transport (default). Uses `--remote-debugging-port`.
    WebSocket,
    /// Pipe transport (lower latency). Uses `--remote-debugging-pipe`.
    /// Communicates via stdin/stdout pipes (fd 3/4 on Unix, named pipes on Windows).
    Pipe,
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportMode::WebSocket => write!(f, "WebSocket"),
            TransportMode::Pipe => write!(f, "Pipe"),
        }
    }
}

/// A CDP command to be sent over the WebSocket connection.
#[derive(Debug, Clone, Serialize)]
pub struct CdpCommand {
    pub id: u64,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
}

/// A CDP response received from the browser.
#[derive(Debug, Clone, Deserialize)]
pub struct CdpResponse {
    pub id: u64,
    pub result: Option<Value>,
    pub error: Option<CdpErrorDetail>,
}

/// A CDP event pushed from the browser.
#[derive(Debug, Clone, Deserialize)]
pub struct CdpEvent {
    pub method: String,
    pub params: Option<Value>,
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
}

/// CDP error detail returned in a response.
#[derive(Debug, Clone, Deserialize)]
pub struct CdpErrorDetail {
    pub code: i64,
    pub message: String,
}

type WsSink =
    futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

/// Response map: pending command ID -> oneshot sender for the response Value.
type ResponseMap = Arc<Mutex<std::collections::HashMap<u64, oneshot::Sender<CdpResponse>>>>;

/// Abstraction over CDP write transports (WebSocket or pipe).
///
/// This enum allows `CdpClient` to hold a single `write` field regardless of
/// whether the underlying transport is a WebSocket connection or a pipe to the
/// browser process.
pub enum CdpWriter {
    /// WebSocket transport — wraps the tungstenite split-sink.
    WebSocket(WsSink),
    /// Pipe transport (Unix only) — NUL-terminated CDP JSON over an async
    /// file descriptor (Chromium's ASCIIZ `--remote-debugging-pipe` framing).
    #[cfg(unix)]
    Pipe(tokio::io::BufWriter<tokio::fs::File>),
}

impl CdpWriter {
    /// Send a serialized CDP JSON message over the underlying transport.
    pub async fn send_message(&mut self, msg: String) -> Result<(), BrowserError> {
        match self {
            CdpWriter::WebSocket(sink) => {
                sink.send(Message::Text(msg.into()))
                    .await
                    .map_err(|e| BrowserError::ConnectionFailed(e.to_string()))
            }
            #[cfg(unix)]
            CdpWriter::Pipe(writer) => {
                use tokio::io::AsyncWriteExt;
                writer
                    .write_all(msg.as_bytes())
                    .await
                    .map_err(|e| BrowserError::ConnectionFailed(e.to_string()))?;
                writer
                    .write_all(b"\0")
                    .await
                    .map_err(|e| BrowserError::ConnectionFailed(e.to_string()))?;
                writer
                    .flush()
                    .await
                    .map_err(|e| BrowserError::ConnectionFailed(e.to_string()))
            }
        }
    }
}


/// Incremental decoder for Chromium's NUL-terminated CDP pipe frames
/// (ASCIIZ mode of `--remote-debugging-pipe`).
///
/// Feed raw bytes as they arrive from the pipe; complete frames (JSON text
/// followed by a NUL byte) are returned as strings. Partial frames are held
/// until their terminator arrives.
#[cfg(unix)]
#[derive(Default)]
pub(crate) struct PipeFrameDecoder {
    buf: Vec<u8>,
}

#[cfg(unix)]
impl PipeFrameDecoder {
    /// Create an empty decoder.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk of raw pipe bytes; returns all complete frames decoded so
    /// far (each without its trailing NUL terminator).
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut start = 0usize;
        for i in 0..self.buf.len() {
            if self.buf[i] == 0 {
                if i > start {
                    out.push(String::from_utf8_lossy(&self.buf[start..i]).into_owned());
                }
                start = i + 1;
            }
        }
        if start > 0 {
            self.buf.drain(..start);
        }
        out
    }

    /// Drop any trailing partial frame. Call at EOF — the peer died before
    /// terminating its last message, so it can never be a valid frame.
    pub(crate) fn finish(self) {}
}

/// Encode one CDP JSON message as a pipe frame: message bytes + NUL.
///
/// The live write path (`CdpWriter::Pipe::send_message`) writes the bytes and
/// terminator separately to avoid the copy; this helper exists for framing
/// tests and any future buffered writer.
#[cfg(all(test, unix))]
pub(crate) fn encode_pipe_frame(msg: &str) -> Vec<u8> {
    let mut frame = msg.as_bytes().to_vec();
    frame.push(0);
    frame
}

/// CDP WebSocket client for communicating with a Chromium browser.
///
/// All methods take `&self` -- the client is cheaply cloneable via Arc internals.
#[derive(Clone)]
pub struct CdpClient {
    write: Arc<Mutex<CdpWriter>>,
    responses: ResponseMap,
    event_tx: broadcast::Sender<CdpEvent>,
    next_id: Arc<AtomicU64>,
    /// Default timeout for CDP commands (default: 30s).
    pub timeout: Duration,
    /// Transport mode used for this connection.
    transport_mode: TransportMode,
    /// Console messages captured from `Runtime.consoleAPICalled` events (Gap 1).
    console_messages: Arc<Mutex<Vec<ConsoleMessage>>>,
    /// Whether the `Runtime` domain has been enabled. Defaults to `false` so
    /// that stealth connections never emit the `Runtime.enable` CDP signal
    /// (a strong automation marker) unless console capture is explicitly
    /// requested. Flipped once by `ensure_runtime_enabled()`.
    runtime_enabled: Arc<AtomicBool>,
    // ── Screencast / recording state ──────────────────────────────────────
    /// Decoded JPEG frames collected from `Page.screencastFrame` events.
    pub recording_frames: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Whether a recording is currently in progress.
    pub recording_active: Arc<AtomicBool>,
    /// Wall-clock instant when the current recording started.
    pub recording_start: Arc<Mutex<Option<Instant>>>,
    /// Maximum frames to keep in memory (oldest are dropped when exceeded).
    pub recording_max_frames: Arc<std::sync::atomic::AtomicUsize>,
    /// Handle to the dedicated runtime that owns this connection's read loop
    /// and every background handler derived from it. See
    /// [`CdpClient::spawn_background`] for why it is not `tokio::spawn`.
    runtime: tokio::runtime::Handle,
}

impl std::fmt::Debug for CdpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdpClient")
            .field("transport_mode", &self.transport_mode)
            .finish_non_exhaustive()
    }
}

impl CdpClient {
    /// Spawn `fut` on a dedicated single-thread runtime belonging to this
    /// connection and hand back that runtime's handle.
    ///
    /// The read loop must NOT be a task on the caller's runtime. `tokio::spawn`
    /// binds a task to whichever runtime is current at spawn time and that
    /// runtime polls it only while it is being driven; any later command issued
    /// from a different runtime (or from a thread that is not inside
    /// `block_on`) writes to the socket while nothing routes the replies. That
    /// is register #105: `Page.navigate` timed out and every
    /// `Runtime.evaluate` poll went unanswered while Chrome loaded the page.
    /// Owning the runtime here makes reply routing independent of the caller.
    ///
    /// The thread lives until `fut` returns, which for the read loop is the
    /// connection closing.
    fn spawn_owned_runtime<F>(
        name: &'static str,
        fut: F,
    ) -> Result<tokio::sync::oneshot::Receiver<tokio::runtime::Handle>, BrowserError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                // Built here, dropped here: a `Runtime` cannot be dropped from
                // inside an async context, and this thread is not one.
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => {
                        // Sent before the first poll, so the caller's await
                        // resolves immediately.
                        let _ = tx.send(rt.handle().clone());
                        rt.block_on(fut);
                    }
                    Err(e) => {
                        eprintln!("[tallow] cdp: {name} runtime could not start: {e}");
                    }
                }
            })
            .map_err(|e| {
                BrowserError::ConnectionFailed(format!("failed to spawn {name} thread: {e}"))
            })?;
        Ok(rx)
    }

    /// Spawn a long-lived handler task on this connection's own runtime.
    ///
    /// Page-level handlers (dialog handling, blocking paused requests) must
    /// keep running after the caller's `block_on` returns and while the caller
    /// is not driving any runtime at all. `tokio::spawn` ties them to the
    /// caller's runtime, which is the same defect class as #105 — the handler
    /// then silently never runs between bridge calls.
    pub fn spawn_background<F>(&self, fut: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.runtime.spawn(fut)
    }

    /// Connect to a running browser via WebSocket at the given URL.
    ///
    /// Spawns a background read loop that demultiplexes responses and events.
    /// Sends `Runtime.enable` immediately after connecting so that
    /// `Runtime.consoleAPICalled` events are delivered (Gap 1).
    pub async fn connect(ws_url: &str) -> Result<Self, BrowserError> {
        // T-207 browser-zone lockdown: the CDP target is the in-zone relay
        // (loopback WebSocket or pipe). A non-loopback endpoint would be
        // unauthenticated CDP exposed on the network (CHAIN-5-4) and is
        // refused before any connection attempt.
        if !super::zone::is_in_zone_target(ws_url) {
            super::zone::emit_zone_refusal(ws_url);
            return Err(BrowserError::ConnectionFailed(format!(
                "[browser-zone] refusing non-in-zone CDP target {ws_url:?} — \
                 loopback/pipe only (P4-15)"
            )));
        }
        let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url)
            .await
            .map_err(|e| BrowserError::ConnectionFailed(e.to_string()))?;

        let (write, read) = ws_stream.split();

        let (event_tx, _) = broadcast::channel::<CdpEvent>(256);
        let responses: ResponseMap = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let console_messages: Arc<Mutex<Vec<ConsoleMessage>>> =
            Arc::new(Mutex::new(Vec::new()));
        let recording_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let recording_active: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let recording_max_frames: Arc<std::sync::atomic::AtomicUsize> =
            Arc::new(std::sync::atomic::AtomicUsize::new(1800));

        let responses_clone = responses.clone();
        let event_tx_clone = event_tx.clone();
        let console_clone = console_messages.clone();
        let frames_clone = recording_frames.clone();
        let active_clone = recording_active.clone();
        let write_clone: Arc<Mutex<CdpWriter>> = Arc::new(Mutex::new(CdpWriter::WebSocket(write)));
        let write_ref = write_clone.clone();
        let max_frames_clone = recording_max_frames.clone();

        // Rebuild read from ws_stream split — we already split above but need
        // write_clone for acking. Re-split via the original stream.
        // Actually we need to re-think: write is consumed by write_clone; read
        // is used by the task. This is correct — we pass write_clone to the
        // task for sending acks, and the main CdpClient also uses write_clone.

        // Own the read loop's runtime: replies must be routed regardless of
        // which runtime later drives a command (register #105).
        let reader = Self::spawn_owned_runtime("cdp-reader", async move {
            Self::read_loop(
                read,
                responses_clone,
                event_tx_clone,
                console_clone,
                frames_clone,
                active_clone,
                write_ref,
                max_frames_clone,
            )
            .await;
        })?;
        let runtime = reader.await.map_err(|_| {
            BrowserError::ConnectionFailed("cdp reader runtime failed to start".to_string())
        })?;

        let client = CdpClient {
            write: write_clone,
            responses,
            event_tx,
            next_id: Arc::new(AtomicU64::new(1)),
            timeout: Duration::from_secs(30),
            transport_mode: TransportMode::WebSocket,
            console_messages,
            recording_frames,
            recording_active,
            recording_start: Arc::new(Mutex::new(None)),
            recording_max_frames,
            runtime_enabled: Arc::new(AtomicBool::new(false)),
            runtime,
        };

        // NOTE: `Runtime.enable` is intentionally NOT sent here. It is a
        // strong CDP-attachment signal for anti-bot systems. The Runtime
        // domain is lazily enabled by `ensure_runtime_enabled()` only when
        // console capture is actually requested (see `get_console_messages`).

        Ok(client)
    }

    /// Background task that reads all WebSocket messages and routes them.
    ///
    /// Messages with an `id` field are command responses routed to the pending
    /// oneshot sender. Messages with a `method` field are events broadcast
    /// to all subscribers.
    ///
    /// Additionally:
    /// - Captures `Runtime.consoleAPICalled` events into the shared console
    ///   message store (Gap 1).
    /// - Collects `Page.screencastFrame` events into `recording_frames` when
    ///   a recording is active, and immediately sends `Page.screencastFrameAck`
    ///   so Chrome continues delivering frames (Chrome pauses until each frame
    ///   is acknowledged).
    #[allow(clippy::too_many_arguments)]
    async fn read_loop(
        mut read: futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        responses: ResponseMap,
        event_tx: broadcast::Sender<CdpEvent>,
        console_messages: Arc<Mutex<Vec<ConsoleMessage>>>,
        recording_frames: Arc<Mutex<Vec<Vec<u8>>>>,
        recording_active: Arc<AtomicBool>,
        write: Arc<Mutex<CdpWriter>>,
        recording_max_frames: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        // Monotonically increasing command ID for acks sent from the read loop.
        let ack_id = AtomicU64::new(10_000_000);

        while let Some(msg_result) = read.next().await {
            let msg = match msg_result {
                Ok(m) => m,
                Err(_) => break, // WebSocket closed or errored
            };

            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Close(_) => break,
                _ => continue,
            };

            Self::route_frame(
                text,
                &responses,
                &event_tx,
                &console_messages,
                &recording_frames,
                &recording_active,
                &write,
                &recording_max_frames,
                &ack_id,
            )
            .await;
        }
    }

    /// Route one decoded CDP frame (a single JSON message) to its destination:
    /// command responses, screencast-frame capture, console capture, or the
    /// event broadcast. Shared by the WebSocket read loop and the pipe
    /// transport reader so every transport demultiplexes identically.
    #[allow(clippy::too_many_arguments)]
    async fn route_frame(
        text: String,
        responses: &ResponseMap,
        event_tx: &broadcast::Sender<CdpEvent>,
        console_messages: &Arc<Mutex<Vec<ConsoleMessage>>>,
        recording_frames: &Arc<Mutex<Vec<Vec<u8>>>>,
        recording_active: &AtomicBool,
        write: &Arc<Mutex<CdpWriter>>,
        recording_max_frames: &Arc<std::sync::atomic::AtomicUsize>,
        ack_id: &AtomicU64,
    ) {
        let raw: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            // Not JSON (empty/partial frame) — nothing to route.
            Err(_) => return,
        };

        // Unwrap `Target.receivedMessageFromTarget` envelopes (wrapped /
        // flat session transport). Responses and events for a target
        // arrive nested inside `params.message`; without unwrapping they
        // never match the pending command id and every command times out.
        let raw = if raw
            .get("method")
            .and_then(|m| m.as_str())
            == Some("Target.receivedMessageFromTarget")
        {
            match raw
                .get("params")
                .and_then(|p| p.get("message"))
                .and_then(|m| m.as_str())
            {
                Some(msg_str) => match serde_json::from_str::<Value>(msg_str) {
                    Ok(mut inner) => {
                        // Preserve the envelope's sessionId on the nested
                        // payload when the inner message lacks one.
                        if inner.get("sessionId").is_none() {
                            if let Some(sid) = raw
                                .get("params")
                                .and_then(|p| p.get("sessionId"))
                            {
                                inner["sessionId"] = sid.clone();
                            }
                        }
                        inner
                    }
                    Err(_) => raw,
                },
                None => raw,
            }
        } else {
            raw
        };

        if raw.get("id").is_some() {
            // This is a command response
            if let Ok(response) = serde_json::from_value::<CdpResponse>(raw) {
                let mut map = responses.lock().await;
                if let Some(sender) = map.remove(&response.id) {
                    let _ = sender.send(response);
                }
            }
        } else if let Some(method) = raw.get("method").and_then(|v| v.as_str()) {
            // ── Page.screencastFrame — collect frame and ack ──────────
            if method == "Page.screencastFrame" {
                if recording_active.load(Ordering::SeqCst) {
                    if let Some(params) = raw.get("params") {
                        // Extract base64-encoded JPEG data
                        if let Some(b64) = params.get("data").and_then(|v| v.as_str()) {
                            if let Ok(frame_bytes) = base64::engine::general_purpose::STANDARD
                                .decode(b64)
                            {
                                let max =
                                    recording_max_frames.load(Ordering::SeqCst);
                                let mut frames = recording_frames.lock().await;
                                // Drop oldest frames if memory cap is reached
                                while frames.len() >= max {
                                    frames.remove(0);
                                }
                                frames.push(frame_bytes);
                            }
                        }

                        // Ack the frame — Chrome will not send the next
                        // frame until we acknowledge the current one.
                        let session_id = params
                            .get("sessionId")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let id = ack_id.fetch_add(1, Ordering::SeqCst);
                        let ack = CdpCommand {
                            id,
                            method: "Page.screencastFrameAck".to_string(),
                            params: Some(serde_json::json!({
                                "sessionId": params
                                    .get("sessionId")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0)
                            })),
                            session_id,
                        };
                        if let Ok(ack_text) = serde_json::to_string(&ack) {
                            let mut w = write.lock().await;
                            let _ = w.send_message(ack_text).await;
                        }
                    }
                }
            }

            // Capture console messages before broadcasting (Gap 1)
            if method == "Runtime.consoleAPICalled" {
                if let Some(params) = raw.get("params") {
                    let level = params
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("log")
                        .to_string();
                    let timestamp = params
                        .get("timestamp")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    // Concatenate all args as text
                    let text = if let Some(args) = params.get("args").and_then(|v| v.as_array()) {
                        args.iter()
                            .map(|arg| {
                                // Prefer the string value, fall back to description
                                arg.get("value")
                                    .and_then(|v| {
                                        if v.is_string() {
                                            v.as_str().map(|s| s.to_string())
                                        } else if v.is_null() {
                                            None
                                        } else {
                                            Some(v.to_string())
                                        }
                                    })
                                    .or_else(|| {
                                        arg.get("description")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string())
                                    })
                                    .unwrap_or_else(|| "undefined".to_string())
                            })
                            .collect::<Vec<_>>()
                            .join(" ")
                    } else {
                        String::new()
                    };
                    let mut msgs = console_messages.lock().await;
                    msgs.push(ConsoleMessage { level, text, timestamp });
                }
            }

            // Broadcast event to all subscribers regardless
            if let Ok(event) = serde_json::from_value::<CdpEvent>(raw) {
                let _ = event_tx.send(event);
            }
        }    }


    /// Send a CDP command and wait for its response.
    ///
    /// Returns the `result` field from the response, or a `BrowserError` on
    /// timeout, CDP error, or connection failure.
    pub async fn send_command(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, BrowserError> {
        self.send_command_internal(method, params, None).await
    }

    /// Send a CDP command with a specific session ID (for per-target commands).
    pub async fn send_command_with_session(
        &self,
        method: &str,
        params: Option<Value>,
        session_id: &str,
    ) -> Result<Value, BrowserError> {
        self.send_command_internal(method, params, Some(session_id.to_string()))
            .await
    }

    /// Internal implementation for sending CDP commands.
    async fn send_command_internal(
        &self,
        method: &str,
        params: Option<Value>,
        session_id: Option<String>,
    ) -> Result<Value, BrowserError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let session_label = match &session_id {
            Some(s) => format!(" session={s}"),
            None => String::new(),
        };

        let cmd = CdpCommand {
            id,
            method: method.to_string(),
            params,
            session_id,
        };

        let (tx, rx) = oneshot::channel::<CdpResponse>();

        // Register the pending response
        {
            let mut map = self.responses.lock().await;
            map.insert(id, tx);
        }

        // Serialize and send
        let msg_text = serde_json::to_string(&cmd)?;
        {
            let mut write = self.write.lock().await;
            write.send_message(msg_text).await?;
        }

        // Wait for response with timeout
        let response = match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) => {
                // oneshot sender dropped -- read loop died
                let mut map = self.responses.lock().await;
                map.remove(&id);
                return Err(BrowserError::ConnectionFailed(
                    "read loop terminated".to_string(),
                ));
            }
            Err(_) => {
                // Timeout
                let mut map = self.responses.lock().await;
                map.remove(&id);
                return Err(BrowserError::Timeout {
                    operation: "send_command",
                    detail: format!("method={method}{session_label} id={id}"),
                });
            }
        };

        // Check for CDP-level error
        if let Some(err) = response.error {
            return Err(BrowserError::CdpError {
                code: err.code,
                message: err.message,
            });
        }

        Ok(response.result.unwrap_or(Value::Null))
    }

    /// Subscribe to CDP events. Returns a broadcast receiver.
    ///
    /// Events include lifecycle events, network events, console messages, etc.
    pub fn subscribe(&self) -> broadcast::Receiver<CdpEvent> {
        self.event_tx.subscribe()
    }

    // ── Console message capture (Gap 1) ─────────────────────────────────────

    /// Return all console messages captured since the last `clear_console()`.
    ///
    /// Messages are populated from `Runtime.consoleAPICalled` CDP events.
    /// Call `Runtime.enable` (done automatically in `connect`) before navigating.
    ///
    /// # Example
    /// ```ignore
    /// let page = client.create_page(None).await?;
    /// page.navigate("https://example.com", WaitUntil::DomContentLoaded).await?;
    /// let msgs = client.get_console_messages().await;
    /// for m in &msgs { println!("[{}] {}", m.level, m.text); }
    /// ```
    pub async fn get_console_messages(&self) -> Vec<ConsoleMessage> {
        self.ensure_runtime_enabled().await;
        self.console_messages.lock().await.clone()
    }

    /// Lazily enable the `Runtime` domain exactly once (idempotent).
    ///
    /// This is deliberately NOT called on connect/navigate — firing
    /// `Runtime.enable` unconditionally is a well-known CDP-automation signal.
    /// Instead, callers that want `Runtime.consoleAPICalled` events opt in here.
    pub async fn ensure_runtime_enabled(&self) {
        if !self.runtime_enabled.swap(true, Ordering::SeqCst) {
            let _ = self.send_command("Runtime.enable", None).await;
        }
    }

    /// Whether console-capture (`Runtime.enable`) has been opted into.
    pub fn runtime_capture_enabled(&self) -> bool {
        self.runtime_enabled.load(Ordering::SeqCst)
    }

    /// Clear all captured console messages.
    pub async fn clear_console(&self) {
        self.console_messages.lock().await.clear();
    }

    /// Create an isolated browser context.
    ///
    /// Returns the `browserContextId` for creating isolated pages.
    /// Browser contexts provide cookie/storage isolation between sessions.
    pub async fn create_browser_context(&self) -> Result<String, BrowserError> {
        let result = self
            .send_command(
                "Target.createBrowserContext",
                Some(serde_json::json!({"disposeOnDetach": true})),
            )
            .await?;

        result
            .get("browserContextId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "missing browserContextId in response".to_string(),
            })
    }

    /// Dispose (close) a browser context and all its targets.
    pub async fn dispose_browser_context(&self, context_id: &str) -> Result<(), BrowserError> {
        self.send_command(
            "Target.disposeBrowserContext",
            Some(serde_json::json!({"browserContextId": context_id})),
        )
        .await?;
        Ok(())
    }

    /// Create a new page (target) within a specific browser context.
    ///
    /// Attaches to the target with a flattened session for CDP communication.
    pub async fn create_page_in_context(
        &self,
        context_id: &str,
        url: Option<&str>,
    ) -> Result<super::page::Page, BrowserError> {
        let target_url = url.unwrap_or("about:blank");
        let result = self
            .send_command(
                "Target.createTarget",
                Some(serde_json::json!({
                    "url": target_url,
                    "browserContextId": context_id
                })),
            )
            .await?;

        let target_id = result
            .get("targetId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "missing targetId in response".to_string(),
            })?
            .to_string();

        // Attach to target to get a session
        let attach_result = self
            .send_command(
                "Target.attachToTarget",
                Some(serde_json::json!({
                    "targetId": target_id,
                    "flatten": true
                })),
            )
            .await?;

        let session_id = attach_result
            .get("sessionId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "missing sessionId in attach response".to_string(),
            })?
            .to_string();

        let page = super::page::Page {
            client: self.clone(),
            session_id,
            frame_id: target_id,
            timeout: self.timeout,
            iframe_doc_object_id: None,
            pool_index: None,
            pool: None,
            events: Arc::new(StdMutex::new(VecDeque::new())),
        };
        page.start_event_pump();
        Ok(page)
    }

    /// Create a new page (target) in the default browser context.
    ///
    /// Shortcut for creating a page without isolation.
    pub async fn create_page(&self, url: Option<&str>) -> Result<super::page::Page, BrowserError> {
        let target_url = url.unwrap_or("about:blank");
        let result = self
            .send_command(
                "Target.createTarget",
                Some(serde_json::json!({"url": target_url})),
            )
            .await?;

        let target_id = result
            .get("targetId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "missing targetId in response".to_string(),
            })?
            .to_string();

        let attach_result = self
            .send_command(
                "Target.attachToTarget",
                Some(serde_json::json!({
                    "targetId": target_id,
                    "flatten": true
                })),
            )
            .await?;

        let session_id = attach_result
            .get("sessionId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "missing sessionId in attach response".to_string(),
            })?
            .to_string();

        let page = super::page::Page {
            client: self.clone(),
            session_id,
            frame_id: target_id,
            timeout: self.timeout,
            iframe_doc_object_id: None,
            pool_index: None,
            pool: None,
            events: Arc::new(StdMutex::new(VecDeque::new())),
        };
        page.start_event_pump();
        Ok(page)
    }

    /// Close a page (target).
    pub async fn close_page(
        &self,
        page: &super::page::Page,
    ) -> Result<(), BrowserError> {
        self.send_command(
            "Target.closeTarget",
            Some(serde_json::json!({"targetId": page.frame_id})),
        )
        .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Screencast / recording support
    // -----------------------------------------------------------------------

    /// Mark a recording as started: activate frame collection and record the
    /// start timestamp.
    ///
    /// Called by `Page::start_recording` after `Page.startScreencast` succeeds.
    pub async fn mark_recording_start(&self, max_frames: usize) {
        self.recording_max_frames
            .store(max_frames, Ordering::SeqCst);
        // Clear any leftover frames from a previous session
        self.recording_frames.lock().await.clear();
        *self.recording_start.lock().await = Some(Instant::now());
        self.recording_active.store(true, Ordering::SeqCst);
    }

    /// Mark a recording as stopped and return `(frames, elapsed_secs)`.
    ///
    /// Called by `Page::stop_recording` after `Page.stopScreencast` succeeds.
    pub async fn mark_recording_stop(&self) -> (Vec<Vec<u8>>, f64) {
        self.recording_active.store(false, Ordering::SeqCst);
        let elapsed = self
            .recording_start
            .lock()
            .await
            .map(|t| t.elapsed().as_secs_f64())
            .unwrap_or(0.0);
        *self.recording_start.lock().await = None;
        let frames = std::mem::take(&mut *self.recording_frames.lock().await);
        (frames, elapsed)
    }

    /// Return current recording status without stopping.
    ///
    /// Returns `(active, frame_count, elapsed_secs)`.
    pub async fn recording_status(&self) -> (bool, usize, f64) {
        let active = self.recording_active.load(Ordering::SeqCst);
        let count = self.recording_frames.lock().await.len();
        let elapsed = self
            .recording_start
            .lock()
            .await
            .map(|t| t.elapsed().as_secs_f64())
            .unwrap_or(0.0);
        (active, count, elapsed)
    }

    // -----------------------------------------------------------------------
    // Pipe transport (Chromium `--remote-debugging-pipe`, fds 3/4)
    // -----------------------------------------------------------------------

    /// Connect to a browser process via the CDP pipe transport.
    ///
    /// The child must have been spawned with the NUL-framed debugging pipe on
    /// fds 3/4 — i.e. [`BrowserProcess::launch`](crate::browser::process::BrowserProcess::launch)
    /// with `use_pipe = true`, which registers the pipe ends for the child's
    /// pid. Any other child (no registered fds) fails closed with an explicit
    /// error: this method never fabricates a transport.
    ///
    /// Wire protocol (Chromium ASCIIZ pipe mode): CDP JSON messages terminated
    /// by a NUL byte. Commands go out on fd 3 (Chromium `kReadFD`); responses
    /// and events come back on fd 4 (Chromium `kWriteFD`).
    #[cfg(unix)]
    pub async fn connect_pipe(
        process: &mut std::process::Child,
    ) -> Result<Self, BrowserError> {
        let pid = process.id();
        let Some(ends) = crate::browser::process::take_pipe_ends(pid) else {
            return Err(BrowserError::ConnectionFailed(format!(
                "CDP pipe transport: child process {pid} has no pipe fds (3/4). \
                 Spawn the browser with BrowserProcess::launch(use_pipe = true) \
                 so fds 3/4 carry the NUL-framed debugging pipe, or use the \
                 WebSocket transport (use_pipe = false, the default)."
            )));
        };
        Self::connect_pipe_fds(ends.to_browser, ends.from_browser).await
    }

    #[cfg(windows)]
    pub async fn connect_pipe(
        _process: &mut std::process::Child,
    ) -> Result<Self, BrowserError> {
        Err(BrowserError::ConnectionFailed(
            "CDP pipe transport is not supported on windows: named-pipe client \
             setup is not implemented. Use WebSocket transport \
             (BrowserConfig::use_pipe = false, the default)."
                .into(),
        ))
    }

    #[cfg(not(any(unix, windows)))]
    pub async fn connect_pipe(
        _process: &mut std::process::Child,
    ) -> Result<Self, BrowserError> {
        Err(BrowserError::ConnectionFailed(
            "CDP pipe transport is not supported on this platform. Use \
             WebSocket transport (BrowserConfig::use_pipe = false, the default)."
                .into(),
        ))
    }

    /// Build a pipe-transport client from the two owned pipe ends.
    ///
    /// `to_browser` is the write end that Chromium reads commands from on
    /// fd 3; `from_browser` is the read end that Chromium writes responses and
    /// events to on fd 4. A dedicated reader thread splits the NUL-terminated
    /// frames and feeds the shared [`Self::route_frame`] demultiplexer, so the
    /// pipe and WebSocket transports behave identically downstream.
    #[cfg(unix)]
    async fn connect_pipe_fds(
        to_browser: std::os::fd::OwnedFd,
        from_browser: std::os::fd::OwnedFd,
    ) -> Result<Self, BrowserError> {
        let writer_file = tokio::fs::File::from(std::fs::File::from(to_browser));
        let write: Arc<Mutex<CdpWriter>> = Arc::new(Mutex::new(CdpWriter::Pipe(
            tokio::io::BufWriter::new(writer_file),
        )));

        let (event_tx, _) = broadcast::channel::<CdpEvent>(256);
        let responses: ResponseMap = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let console_messages: Arc<Mutex<Vec<ConsoleMessage>>> =
            Arc::new(Mutex::new(Vec::new()));
        let recording_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let recording_active: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let recording_start: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let recording_max_frames: Arc<std::sync::atomic::AtomicUsize> =
            Arc::new(std::sync::atomic::AtomicUsize::new(1800));

        // Reader side: a blocking thread on the fd-4 read end feeds an
        // unbounded frame channel; the async task below routes each frame.
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        std::thread::spawn(move || {
            Self::pipe_read_thread(from_browser, frame_tx);
        });

        let write_route = write.clone();
        let responses_route = responses.clone();
        let event_tx_route = event_tx.clone();
        let console_route = console_messages.clone();
        let frames_route = recording_frames.clone();
        let active_route = recording_active.clone();
        let max_frames_route = recording_max_frames.clone();
        let ack_id = Arc::new(AtomicU64::new(10_000_000));
        let reader = Self::spawn_owned_runtime("cdp-pipe-reader", async move {
            while let Some(frame) = frame_rx.recv().await {
                Self::route_frame(
                    frame,
                    &responses_route,
                    &event_tx_route,
                    &console_route,
                    &frames_route,
                    &active_route,
                    &write_route,
                    &max_frames_route,
                    &ack_id,
                )
                .await;
            }
        })?;
        let runtime = reader.await.map_err(|_| {
            BrowserError::ConnectionFailed("cdp pipe reader runtime failed to start".to_string())
        })?;

        Ok(CdpClient {
            write,
            responses,
            event_tx,
            next_id: Arc::new(AtomicU64::new(1)),
            timeout: Duration::from_secs(30),
            transport_mode: TransportMode::Pipe,
            console_messages,
            recording_frames,
            recording_active,
            recording_start,
            recording_max_frames,
            runtime_enabled: Arc::new(AtomicBool::new(false)),
            runtime,
        })
    }

    /// Blocking reader for the fd-4 end of the CDP debugging pipe.
    ///
    /// Reads bytes until EOF, splits them on the NUL byte Chromium uses to
    /// terminate every pipe message (ASCIIZ framing), and forwards complete
    /// frames to the async route task. A partial trailing frame at EOF is
    /// discarded — the browser is gone.
    #[cfg(unix)]
    fn pipe_read_thread(
        from_browser: std::os::fd::OwnedFd,
        frames: tokio::sync::mpsc::UnboundedSender<String>,
    ) {
        let mut file = std::fs::File::from(from_browser);
        let mut decoder = PipeFrameDecoder::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let n = match std::io::Read::read(&mut file, &mut chunk) {
                Ok(0) => break, // EOF: browser closed fd 4
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            for frame in decoder.push(&chunk[..n]) {
                if frames.send(frame).is_err() {
                    return; // route task is gone
                }
            }
        }
        decoder.finish();
    }

    /// Returns true if this client is using pipe transport.
    pub fn is_pipe_transport(&self) -> bool {
        self.transport_mode == TransportMode::Pipe
    }

    /// Returns the transport mode used by this client.
    pub fn transport_mode(&self) -> TransportMode {
        self.transport_mode
    }

    // -----------------------------------------------------------------------
    // Flat session multiplexing (Phase 48-01)
    // -----------------------------------------------------------------------

    /// Create an isolated browser context with optional proxy routing.
    ///
    /// Returns the `browserContextId`. Browser contexts provide cookie/storage
    /// isolation and per-context proxy support for IPPool-style routing.
    pub async fn create_browser_context_with_proxy(
        &self,
        proxy_server: Option<&str>,
    ) -> Result<String, BrowserError> {
        let mut params = serde_json::json!({"disposeOnDetach": false});
        if let Some(proxy) = proxy_server {
            params["proxyServer"] = serde_json::json!(proxy);
        }
        let result = self
            .send_command("Target.createBrowserContext", Some(params))
            .await?;
        result
            .get("browserContextId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "missing browserContextId in response".to_string(),
            })
    }

    /// Create a new page/target within a browser context.
    ///
    /// Returns the `targetId` of the newly created target.
    pub async fn create_target_in_context(
        &self,
        url: &str,
        context_id: &str,
    ) -> Result<String, BrowserError> {
        let result = self
            .send_command(
                "Target.createTarget",
                Some(serde_json::json!({
                    "url": url,
                    "browserContextId": context_id
                })),
            )
            .await?;
        result
            .get("targetId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "missing targetId in response".to_string(),
            })
    }

    /// Attach to a target with flat session mode.
    ///
    /// All sessions are multiplexed over the single WebSocket connection.
    /// Returns the `sessionId` for sending commands to this target.
    pub async fn attach_flat(&self, target_id: &str) -> Result<String, BrowserError> {
        let result = self
            .send_command(
                "Target.attachToTarget",
                Some(serde_json::json!({
                    "targetId": target_id,
                    "flatten": true
                })),
            )
            .await?;
        result
            .get("sessionId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| BrowserError::CdpError {
                code: -1,
                message: "missing sessionId in attach response".to_string(),
            })
    }

    /// Enable auto-attach with flat sessions for all new targets.
    ///
    /// When enabled, newly created targets are automatically attached with
    /// flat session multiplexing. Useful for managing 50+ tabs from a single
    /// browser instance.
    pub async fn enable_auto_attach_flat(&self) -> Result<(), BrowserError> {
        self.send_command(
            "Target.setAutoAttach",
            Some(serde_json::json!({
                "autoAttach": true,
                "waitForDebuggerOnStart": false,
                "flatten": true
            })),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_cdp_command_serialization() {
        let cmd = CdpCommand {
            id: 1,
            method: "Page.navigate".to_string(),
            params: Some(json!({"url": "https://example.com"})),
            session_id: None,
        };

        let json_str = serde_json::to_string(&cmd).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["id"], 1);
        assert_eq!(parsed["method"], "Page.navigate");
        assert_eq!(parsed["params"]["url"], "https://example.com");
        // session_id should be absent (skip_serializing_if)
        assert!(parsed.get("sessionId").is_none());
    }

    #[test]
    fn test_cdp_command_serialization_with_session() {
        let cmd = CdpCommand {
            id: 42,
            method: "Runtime.evaluate".to_string(),
            params: Some(json!({"expression": "1+1"})),
            session_id: Some("session-abc".to_string()),
        };

        let json_str = serde_json::to_string(&cmd).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["sessionId"], "session-abc");
    }

    #[test]
    fn test_cdp_command_no_params() {
        let cmd = CdpCommand {
            id: 5,
            method: "Page.reload".to_string(),
            params: None,
            session_id: None,
        };

        let json_str = serde_json::to_string(&cmd).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["id"], 5);
        assert_eq!(parsed["method"], "Page.reload");
        assert!(parsed.get("params").is_none());
    }

    #[test]
    fn test_cdp_response_deserialization_success() {
        let json = r#"{"id": 1, "result": {"frameId": "abc123"}}"#;
        let resp: CdpResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.id, 1);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["frameId"], "abc123");
    }

    #[test]
    fn test_cdp_response_deserialization_error() {
        let json = r#"{"id": 2, "error": {"code": -32601, "message": "method not found"}}"#;
        let resp: CdpResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.id, 2);
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "method not found");
    }

    #[test]
    fn test_cdp_event_deserialization() {
        let json =
            r#"{"method": "Page.lifecycleEvent", "params": {"name": "load", "frameId": "F1"}}"#;
        let evt: CdpEvent = serde_json::from_str(json).unwrap();

        assert_eq!(evt.method, "Page.lifecycleEvent");
        assert!(evt.params.is_some());
        assert!(evt.session_id.is_none());
        assert_eq!(evt.params.unwrap()["name"], "load");
    }

    #[test]
    fn test_cdp_event_with_session() {
        let json = r#"{"method": "Console.messageAdded", "params": {}, "sessionId": "sess-1"}"#;
        let evt: CdpEvent = serde_json::from_str(json).unwrap();

        assert_eq!(evt.method, "Console.messageAdded");
        assert_eq!(evt.session_id.unwrap(), "sess-1");
    }

    #[test]
    fn test_cdp_error_detail_deserialization() {
        let json = r#"{"code": -32000, "message": "Cannot navigate to invalid URL"}"#;
        let err: CdpErrorDetail = serde_json::from_str(json).unwrap();

        assert_eq!(err.code, -32000);
        assert_eq!(err.message, "Cannot navigate to invalid URL");
    }

    // -----------------------------------------------------------------------
    // Pipe transport config
    // -----------------------------------------------------------------------

    #[test]
    fn transport_mode_pipe_variant_exists() {
        let mode = TransportMode::Pipe;
        assert_eq!(mode, TransportMode::Pipe);
    }

    // -----------------------------------------------------------------------
    // Phase 48-01: Transport mode and flat session tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_transport_mode_enum() {
        assert_eq!(TransportMode::WebSocket, TransportMode::WebSocket);
        assert_eq!(TransportMode::Pipe, TransportMode::Pipe);
        assert_ne!(TransportMode::WebSocket, TransportMode::Pipe);
    }

    #[test]
    fn test_transport_mode_display() {
        assert_eq!(format!("{}", TransportMode::WebSocket), "WebSocket");
        assert_eq!(format!("{}", TransportMode::Pipe), "Pipe");
    }

    #[test]
    fn test_transport_mode_debug() {
        assert_eq!(format!("{:?}", TransportMode::WebSocket), "WebSocket");
        assert_eq!(format!("{:?}", TransportMode::Pipe), "Pipe");
    }

    #[test]
    fn test_transport_mode_copy_clone() {
        let mode = TransportMode::WebSocket;
        let copied = mode;
        let cloned = mode.clone();
        assert_eq!(copied, TransportMode::WebSocket);
        assert_eq!(cloned, TransportMode::WebSocket);
    }

    #[test]
    fn test_browser_context_create_params() {
        // Verify the JSON params for create_browser_context_with_proxy
        let params_no_proxy = json!({"disposeOnDetach": false});
        assert_eq!(params_no_proxy["disposeOnDetach"], false);
        assert!(params_no_proxy.get("proxyServer").is_none());

        let mut params_with_proxy = json!({"disposeOnDetach": false});
        params_with_proxy["proxyServer"] = json!("socks5://proxy:1080");
        assert_eq!(params_with_proxy["proxyServer"], "socks5://proxy:1080");
    }

    #[test]
    fn test_flat_attach_params() {
        // Verify the JSON params for attach_flat
        let target_id = "TARGET_123";
        let params = json!({
            "targetId": target_id,
            "flatten": true
        });
        assert_eq!(params["targetId"], "TARGET_123");
        assert_eq!(params["flatten"], true);
    }

    #[test]
    fn test_auto_attach_flat_params() {
        // Verify the JSON params for enable_auto_attach_flat
        let params = json!({
            "autoAttach": true,
            "waitForDebuggerOnStart": false,
            "flatten": true
        });
        assert_eq!(params["autoAttach"], true);
        assert_eq!(params["waitForDebuggerOnStart"], false);
        assert_eq!(params["flatten"], true);
    }

    #[test]
    fn test_create_target_in_context_params() {
        // Verify the JSON params for create_target_in_context
        let url = "https://example.com";
        let context_id = "CTX_456";
        let params = json!({
            "url": url,
            "browserContextId": context_id
        });
        assert_eq!(params["url"], "https://example.com");
        assert_eq!(params["browserContextId"], "CTX_456");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_connect_pipe_errors_honestly_when_spawn_lacks_pipe_fds() {
        // A child spawned WITHOUT the fd 3/4 pipe ends (any ordinary spawn,
        // like this `echo`) is not a pipe-mode browser — connecting must fail
        // closed with a clear error instead of returning a client that can
        // never talk to a browser.
        let mut cmd = std::process::Command::new("echo")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let result = CdpClient::connect_pipe(&mut cmd).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no pipe fds"), "unexpected error: {err}");
        let _ = cmd.kill();
        let _ = cmd.wait();
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn test_connect_pipe_fails_closed_on_non_unix() {
        // Non-unix platforms keep the documented fail-closed behavior.
        let mut cmd = std::process::Command::new("echo")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let result = CdpClient::connect_pipe(&mut cmd).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not supported"), "unexpected error: {err}");
        let _ = cmd.kill();
        let _ = cmd.wait();
    }

    #[cfg(unix)]
    #[test]
    fn test_pipe_frame_encoder_decoder_roundtrip() {
        let messages = [
            r#"{"id":1,"method":"Target.createTarget","params":{"url":"about:blank"}}"#,
            r#"{"id":2,"method":"Page.enable"}"#,
            "{\"method\":\"Page.lifecycleEvent\",\"params\":{\"name\":\"load\"}}",
        ];
        // Encode every message with its NUL terminator and concatenate.
        let mut wire = Vec::new();
        for m in &messages {
            wire.extend_from_slice(&encode_pipe_frame(m));
        }
        // Decode in awkward chunk sizes so frame boundaries fall mid-chunk.
        let mut decoder = PipeFrameDecoder::new();
        let mut decoded = Vec::new();
        let mut offset = 0;
        let mut chunk_size = 1usize;
        while offset < wire.len() {
            let end = (offset + chunk_size).min(wire.len());
            decoded.extend(decoder.push(&wire[offset..end]));
            offset = end;
            chunk_size = (chunk_size * 3 + 1) % 7 + 1; // 1..=7 bytes
        }
        assert_eq!(
            decoded.len(),
            messages.len(),
            "roundtrip frame count mismatch: {decoded:?}"
        );
        for (got, want) in decoded.iter().zip(messages.iter()) {
            assert_eq!(got, want);
        }

        // A partial trailing frame without a NUL terminator must not be
        // emitted as a frame, and finish() at EOF drops it silently.
        let mut partial = PipeFrameDecoder::new();
        let frames = partial.push(b"{\"id\":9}\0{\"half");
        assert_eq!(frames, vec!["{\"id\":9}".to_string()]);
        let none = partial.push(b"-written");
        assert!(none.is_empty(), "partial frame leaked: {none:?}");
        partial.finish();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_connect_pipe_loopback_roundtrip() {
        // Full loopback: a genuine pipe-transport client talking to an
        // in-process fake browser over real OS pipes. Proves the fd wiring,
        // frame decoder, reader thread, and route_frame all work together.
        let (client, observed) = super::pipe_test_peer::loopback_client().await;
        assert!(client.is_pipe_transport());
        assert_eq!(client.transport_mode(), TransportMode::Pipe);

        let result = client
            .send_command("Browser.getVersion", None)
            .await
            .expect("loopback command should resolve");
        assert_eq!(result, serde_json::json!({}));

        let seen = super::pipe_test_peer::wait_for_observed(&observed, 1, std::time::Duration::from_secs(5));
        assert_eq!(seen, vec!["Browser.getVersion".to_string()]);
    }

    // ── Gap 1: Console message capture tests ────────────────────────────────

    #[test]
    fn test_console_message_struct() {
        let msg = ConsoleMessage {
            level: "warn".to_string(),
            text: "something went wrong".to_string(),
            timestamp: 1_700_000_000.0,
        };
        assert_eq!(msg.level, "warn");
        assert_eq!(msg.text, "something went wrong");
        assert_eq!(msg.timestamp, 1_700_000_000.0);
    }

    #[test]
    fn test_console_message_clone() {
        let msg = ConsoleMessage {
            level: "error".to_string(),
            text: "Uncaught TypeError".to_string(),
            timestamp: 42.0,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.level, msg.level);
        assert_eq!(cloned.text, msg.text);
        assert_eq!(cloned.timestamp, msg.timestamp);
    }

    #[test]
    fn test_console_message_debug() {
        let msg = ConsoleMessage {
            level: "log".to_string(),
            text: "hello".to_string(),
            timestamp: 0.0,
        };
        let debug_str = format!("{:?}", msg);
        assert!(debug_str.contains("log"));
        assert!(debug_str.contains("hello"));
    }

    #[test]
    fn test_console_api_called_event_parsing() {
        // Verify the JSON structure of Runtime.consoleAPICalled events
        let event_json = r#"{
            "method": "Runtime.consoleAPICalled",
            "params": {
                "type": "warn",
                "timestamp": 1700000000.5,
                "args": [
                    {"type": "string", "value": "hello"},
                    {"type": "string", "value": "world"}
                ]
            }
        }"#;
        let raw: Value = serde_json::from_str(event_json).unwrap();
        let method = raw.get("method").and_then(|v| v.as_str()).unwrap();
        assert_eq!(method, "Runtime.consoleAPICalled");

        let params = raw.get("params").unwrap();
        let level = params.get("type").and_then(|v| v.as_str()).unwrap();
        assert_eq!(level, "warn");

        let ts = params.get("timestamp").and_then(|v| v.as_f64()).unwrap();
        assert_eq!(ts, 1_700_000_000.5);

        let args = params.get("args").and_then(|v| v.as_array()).unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0]["value"].as_str().unwrap(), "hello");
        assert_eq!(args[1]["value"].as_str().unwrap(), "world");
    }

    #[test]
    fn test_runtime_enable_command_name() {
        // Verify Runtime.enable is the correct command name
        let cmd = CdpCommand {
            id: 1,
            method: "Runtime.enable".to_string(),
            params: None,
            session_id: None,
        };
        let json_str = serde_json::to_string(&cmd).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["method"], "Runtime.enable");
        assert!(parsed.get("params").is_none());
    }

    #[test]
    fn test_console_message_text_concatenation() {
        // Simulate how the read loop concatenates multiple args
        let args = vec![
            json!({"type": "string", "value": "count:"}),
            json!({"type": "number", "value": 42}),
        ];
        let text = args
            .iter()
            .map(|arg| {
                arg.get("value")
                    .and_then(|v| {
                        if v.is_string() {
                            v.as_str().map(|s| s.to_string())
                        } else if v.is_null() {
                            None
                        } else {
                            Some(v.to_string())
                        }
                    })
                    .or_else(|| {
                        arg.get("description")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "undefined".to_string())
            })
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(text, "count: 42");
    }
}

/// Test-only loopback CDP peer speaking the NUL-framed pipe protocol over a
/// real OS pipe pair — a stand-in for the browser side of the fd 3/4 wiring
/// that `BrowserProcess::launch(use_pipe = true)` performs. Exposed to sibling
/// modules (page.rs tests) so recording behaviour can be asserted against a
/// mock browser without any network or live Chrome.
#[cfg(all(test, unix))]
pub(crate) mod pipe_test_peer {
    use std::os::fd::OwnedFd;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Create a [`CdpClient`] wired to an in-process fake browser over real OS
    /// pipes.
    ///
    /// The returned client is a genuine pipe-transport client: commands it
    /// sends cross a real OS pipe to a reader thread that records every method
    /// name into the returned `observed` list and answers each command with
    /// `{"id": N, "result": {}}` so async CDP calls resolve immediately.
    pub(crate) async fn loopback_client() -> (CdpClient, Arc<Mutex<Vec<String>>>) {
        use std::os::fd::FromRawFd;
        // Command pipe: client writes (fd-3 role), peer reads.
        // Message pipe: peer writes (fd-4 role), client reads.
        let mut cmd_pipe = [0i32; 2];
        let mut msg_pipe = [0i32; 2];
        let rc = unsafe { libc::pipe(cmd_pipe.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe(cmd) failed: {rc}");
        let rc = unsafe { libc::pipe(msg_pipe.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe(msg) failed: {rc}");

        let to_browser = unsafe { OwnedFd::from_raw_fd(cmd_pipe[1]) }; // client -> peer
        let from_browser = unsafe { OwnedFd::from_raw_fd(msg_pipe[0]) }; // peer -> client
        let peer_read = unsafe { OwnedFd::from_raw_fd(cmd_pipe[0]) };
        let peer_write = unsafe { OwnedFd::from_raw_fd(msg_pipe[1]) };

        let observed = Arc::new(Mutex::new(Vec::<String>::new()));
        let peer_observed = observed.clone();
        std::thread::spawn(move || peer_loop(peer_read, peer_write, peer_observed));

        let client = super::CdpClient::connect_pipe_fds(to_browser, from_browser)
            .await
            .expect("pipe loopback client should connect");
        (client, observed)
    }

    /// Block until at least `min` commands have been observed (or `timeout`
    /// elapses), then return the observed method names in order.
    pub(crate) fn wait_for_observed(
        observed: &Arc<Mutex<Vec<String>>>,
        min: usize,
        timeout: std::time::Duration,
    ) -> Vec<String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let current = observed.lock().unwrap().clone();
            if current.len() >= min || std::time::Instant::now() >= deadline {
                return current;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn peer_loop(peer_read: OwnedFd, peer_write: OwnedFd, observed: Arc<Mutex<Vec<String>>>) {
        use std::io::{Read, Write};

        let mut input = std::fs::File::from(peer_read);
        let mut output = std::fs::File::from(peer_write);
        let mut decoder = super::PipeFrameDecoder::new();
        let mut chunk = [0u8; 8192];

        loop {
            let n = match input.read(&mut chunk) {
                Ok(0) => break, // client dropped its write end
                Ok(n) => n,
                Err(_) => break,
            };
            for frame in decoder.push(&chunk[..n]) {
                let parsed: serde_json::Value = match serde_json::from_str(&frame) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(method) = parsed.get("method").and_then(|m| m.as_str()) {
                    observed.lock().unwrap().push(method.to_string());
                }
                if let Some(id) = parsed.get("id").and_then(|i| i.as_u64()) {
                    let response = serde_json::json!({ "id": id, "result": {} });
                    let _ = output.write_all(response.to_string().as_bytes());
                    let _ = output.write_all(b"\0");
                    let _ = output.flush();
                }
            }
        }
    }
}

