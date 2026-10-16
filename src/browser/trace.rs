//! Trace recording and HTML viewer for debugging browser automation sessions.
//!
//! Captures actions (navigate, click, type, etc.), viewport screenshots, and network
//! events into a ZIP archive. An embedded HTML viewer can be extracted alongside the
//! data and opened in the default browser for inspection.

use std::io::Write;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::error::BrowserError;

// ---------------------------------------------------------------------------
// Trace data types
// ---------------------------------------------------------------------------

/// A single recorded action in a browser automation trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAction {
    /// Milliseconds since recording started.
    pub timestamp_ms: u64,
    /// Type of action: "navigate", "click", "type", "screenshot", "wait", etc.
    pub action_type: String,
    /// CSS selector used (if applicable).
    pub selector: Option<String>,
    /// Value typed, URL navigated to, etc.
    pub value: Option<String>,
    /// URL context for the action.
    pub url: Option<String>,
    /// Index into the screenshots list (if a screenshot was taken for this action).
    pub screenshot_index: Option<usize>,
    /// Duration of the action in milliseconds.
    pub duration_ms: Option<u64>,
}

/// A network event captured during trace recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceNetworkEvent {
    /// Milliseconds since recording started.
    pub timestamp_ms: u64,
    /// "request" or "response".
    pub event_type: String,
    /// Request URL.
    pub url: String,
    /// HTTP method (GET, POST, etc.).
    pub method: Option<String>,
    /// HTTP status code (for responses).
    pub status: Option<u16>,
    /// MIME type of the response.
    pub mime_type: Option<String>,
    /// Response body size in bytes.
    pub size_bytes: Option<u64>,
    /// Time for the request/response round trip.
    pub duration_ms: Option<u64>,
}

/// Metadata stored in the trace ZIP archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMetadata {
    /// Schema version.
    pub version: u32,
    /// Number of recorded actions.
    pub action_count: usize,
    /// Number of screenshots captured.
    pub screenshot_count: usize,
    /// Number of network events recorded.
    pub network_event_count: usize,
    /// Total recording duration in milliseconds.
    pub duration_ms: u64,
}

/// Records actions, screenshots, and network events during a browser session.
///
/// Start recording with `start()`, add events via `record_*` methods, then
/// call `save_to_zip()` to create a replayable trace archive.
pub struct TraceRecorder {
    actions: Vec<TraceAction>,
    screenshots: Vec<(u64, Vec<u8>)>, // (timestamp_ms, png_bytes)
    network_events: Vec<TraceNetworkEvent>,
    recording: bool,
    start_time: Instant,
}

impl TraceRecorder {
    /// Create a new idle recorder.
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            screenshots: Vec::new(),
            network_events: Vec::new(),
            recording: false,
            start_time: Instant::now(),
        }
    }

    /// Start recording. Resets the start timestamp.
    pub fn start(&mut self) {
        self.recording = true;
        self.start_time = Instant::now();
    }

    /// Stop recording.
    pub fn stop(&mut self) {
        self.recording = false;
    }

    /// Whether the recorder is currently active.
    pub fn is_recording(&self) -> bool {
        self.recording
    }

    /// Milliseconds elapsed since `start()` was called.
    fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    /// Record an action (navigate, click, type, wait, etc.).
    ///
    /// No-op if the recorder is not currently active.
    pub fn record_action(
        &mut self,
        action_type: &str,
        selector: Option<&str>,
        value: Option<&str>,
        url: Option<&str>,
    ) {
        if !self.recording {
            return;
        }
        self.actions.push(TraceAction {
            timestamp_ms: self.elapsed_ms(),
            action_type: action_type.to_string(),
            selector: selector.map(|s| s.to_string()),
            value: value.map(|s| s.to_string()),
            url: url.map(|s| s.to_string()),
            screenshot_index: None,
            duration_ms: None,
        });
    }

    /// Record a screenshot and attach it to the most recent action.
    ///
    /// Returns the screenshot index. No-op (returns 0) if not recording.
    pub fn record_screenshot(&mut self, png_data: Vec<u8>) -> usize {
        if !self.recording {
            return 0;
        }
        let ts = self.elapsed_ms();
        let idx = self.screenshots.len();
        self.screenshots.push((ts, png_data));

        // Link to the last action
        if let Some(last) = self.actions.last_mut() {
            last.screenshot_index = Some(idx);
        }

        idx
    }

    /// Record a network event (request or response).
    ///
    /// No-op if the recorder is not currently active.
    pub fn record_network_event(
        &mut self,
        event_type: &str,
        url: &str,
        method: Option<&str>,
        status: Option<u16>,
        mime_type: Option<&str>,
        size_bytes: Option<u64>,
    ) {
        if !self.recording {
            return;
        }
        self.network_events.push(TraceNetworkEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: event_type.to_string(),
            url: url.to_string(),
            method: method.map(|s| s.to_string()),
            status,
            mime_type: mime_type.map(|s| s.to_string()),
            size_bytes,
            duration_ms: None,
        });
    }

    /// Save the recorded trace to a ZIP archive.
    ///
    /// The archive contains:
    /// - `actions.jsonl` -- one JSON object per line for each action
    /// - `network.jsonl` -- one JSON object per line for each network event
    /// - `screenshots/0001.png`, `screenshots/0002.png`, etc.
    /// - `metadata.json` -- summary counts and duration
    pub fn save_to_zip(&self, path: &Path) -> Result<(), BrowserError> {
        let file = std::fs::File::create(path).map_err(|e| {
            BrowserError::FileNotFound(format!("cannot create {}: {e}", path.display()))
        })?;

        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();

        // actions.jsonl
        zip.start_file("actions.jsonl", options)
            .map_err(|e| BrowserError::FileNotFound(format!("zip error: {e}")))?;
        for action in &self.actions {
            let line = serde_json::to_string(action)?;
            writeln!(zip, "{line}")
                .map_err(|e| BrowserError::FileNotFound(format!("zip write error: {e}")))?;
        }

        // network.jsonl
        zip.start_file("network.jsonl", options)
            .map_err(|e| BrowserError::FileNotFound(format!("zip error: {e}")))?;
        for event in &self.network_events {
            let line = serde_json::to_string(event)?;
            writeln!(zip, "{line}")
                .map_err(|e| BrowserError::FileNotFound(format!("zip write error: {e}")))?;
        }

        // screenshots
        for (i, (_ts, png)) in self.screenshots.iter().enumerate() {
            let name = format!("screenshots/{:04}.png", i + 1);
            zip.start_file(&name, options)
                .map_err(|e| BrowserError::FileNotFound(format!("zip error: {e}")))?;
            zip.write_all(png)
                .map_err(|e| BrowserError::FileNotFound(format!("zip write error: {e}")))?;
        }

        // metadata.json
        let duration_ms = if self.actions.is_empty() {
            0
        } else {
            self.elapsed_ms()
        };
        let metadata = TraceMetadata {
            version: 1,
            action_count: self.actions.len(),
            screenshot_count: self.screenshots.len(),
            network_event_count: self.network_events.len(),
            duration_ms,
        };
        zip.start_file("metadata.json", options)
            .map_err(|e| BrowserError::FileNotFound(format!("zip error: {e}")))?;
        let meta_json = serde_json::to_string_pretty(&metadata)?;
        zip.write_all(meta_json.as_bytes())
            .map_err(|e| BrowserError::FileNotFound(format!("zip write error: {e}")))?;

        zip.finish()
            .map_err(|e| BrowserError::FileNotFound(format!("zip finish error: {e}")))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trace viewer
// ---------------------------------------------------------------------------

/// Embedded self-contained HTML page for viewing trace archives.
///
/// Renders a three-panel layout:
/// - Left: timeline of actions (type, selector, timestamp)
/// - Right: screenshot for the selected action
/// - Bottom: network events table
///
/// All data is loaded via relative `fetch()` calls against sibling files
/// extracted from the trace ZIP.
pub fn create_trace_viewer_html() -> &'static str {
    TRACE_VIEWER_HTML
}

const TRACE_VIEWER_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tallow Trace Viewer</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; flex-direction: column; height: 100vh; }
  header { background: #161b22; padding: 10px 20px; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 16px; color: #58a6ff; }
  header .meta { font-size: 12px; color: #8b949e; }
  .main { display: flex; flex: 1; overflow: hidden; }
  .panel-left { width: 340px; overflow-y: auto; border-right: 1px solid #30363d; background: #0d1117; }
  .panel-right { flex: 1; display: flex; align-items: center; justify-content: center; overflow: auto; background: #010409; }
  .panel-right img { max-width: 100%; max-height: 100%; object-fit: contain; }
  .panel-right .empty { color: #484f58; font-size: 14px; }
  .panel-bottom { height: 220px; overflow-y: auto; border-top: 1px solid #30363d; background: #161b22; }
  .action-item { padding: 8px 12px; border-bottom: 1px solid #21262d; cursor: pointer; font-size: 13px; }
  .action-item:hover { background: #161b22; }
  .action-item.selected { background: #1f2937; border-left: 3px solid #58a6ff; }
  .action-item .ts { color: #8b949e; font-size: 11px; margin-right: 8px; font-family: monospace; }
  .action-item .type { color: #7ee787; font-weight: 600; }
  .action-item .sel { color: #d2a8ff; margin-left: 6px; }
  .action-item .val { color: #79c0ff; margin-left: 6px; font-size: 12px; }
  .action-item .has-screenshot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #f0883e; margin-left: 4px; vertical-align: middle; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { background: #21262d; color: #8b949e; text-align: left; padding: 6px 10px; position: sticky; top: 0; }
  td { padding: 5px 10px; border-bottom: 1px solid #21262d; }
  td.url { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  tr:hover td { background: #161b22; }
  .status-ok { color: #7ee787; }
  .status-err { color: #f85149; }
</style>
</head>
<body>
<header>
  <h1>Tallow Trace Viewer</h1>
  <span class="meta" id="meta-info">Loading...</span>
</header>
<div class="main">
  <div class="panel-left" id="action-list"></div>
  <div class="panel-right" id="screenshot-pane"><span class="empty">Select an action to view its screenshot</span></div>
</div>
<div class="panel-bottom" id="network-table">
  <table>
    <thead><tr><th>Time</th><th>Type</th><th>Method</th><th>Status</th><th>URL</th><th>MIME</th><th>Size</th></tr></thead>
    <tbody id="network-body"></tbody>
  </table>
</div>
<script>
(async function() {
  const [metaResp, actResp, netResp] = await Promise.all([
    fetch('metadata.json'), fetch('actions.jsonl'), fetch('network.jsonl')
  ]);
  const meta = await metaResp.json();
  document.getElementById('meta-info').textContent =
    `${meta.action_count} actions | ${meta.screenshot_count} screenshots | ${meta.network_event_count} network events | ${(meta.duration_ms/1000).toFixed(1)}s`;

  const actions = (await actResp.text()).trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
  const network = (await netResp.text()).trim().split('\n').filter(Boolean).map(l => JSON.parse(l));

  const list = document.getElementById('action-list');
  actions.forEach((a, i) => {
    const div = document.createElement('div');
    div.className = 'action-item';
    div.dataset.index = i;
    let html = `<span class="ts">${String(a.timestamp_ms).padStart(6,' ')}ms</span>`;
    html += `<span class="type">${a.action_type}</span>`;
    if (a.selector) html += `<span class="sel">${a.selector}</span>`;
    if (a.value) html += `<span class="val">${a.value.length > 40 ? a.value.slice(0,40)+'...' : a.value}</span>`;
    if (a.screenshot_index != null) html += `<span class="has-screenshot"></span>`;
    div.innerHTML = html;
    div.addEventListener('click', () => selectAction(i, a));
    list.appendChild(div);
  });

  const netBody = document.getElementById('network-body');
  network.forEach(n => {
    const tr = document.createElement('tr');
    const sc = n.status ? (n.status < 400 ? 'status-ok' : 'status-err') : '';
    tr.innerHTML = `<td>${n.timestamp_ms}ms</td><td>${n.event_type}</td><td>${n.method||''}</td>` +
      `<td class="${sc}">${n.status||''}</td><td class="url" title="${n.url}">${n.url}</td>` +
      `<td>${n.mime_type||''}</td><td>${n.size_bytes != null ? n.size_bytes : ''}</td>`;
    netBody.appendChild(tr);
  });

  function selectAction(idx, action) {
    document.querySelectorAll('.action-item').forEach(el => el.classList.remove('selected'));
    document.querySelector(`.action-item[data-index="${idx}"]`).classList.add('selected');
    const pane = document.getElementById('screenshot-pane');
    if (action.screenshot_index != null) {
      const num = String(action.screenshot_index + 1).padStart(4, '0');
      pane.innerHTML = `<img src="screenshots/${num}.png" alt="Screenshot ${num}">`;
    } else {
      pane.innerHTML = '<span class="empty">No screenshot for this action</span>';
    }
  }
})();
</script>
</body>
</html>
"##;

/// Open a trace archive in the default browser.
///
/// Extracts the ZIP to a temp directory, writes the viewer HTML alongside it,
/// and opens the HTML file in the system's default browser. Returns immediately.
pub fn open_trace_viewer(trace_path: &Path) -> Result<(), BrowserError> {
    let file = std::fs::File::open(trace_path).map_err(|e| {
        BrowserError::FileNotFound(format!("{}: {e}", trace_path.display()))
    })?;

    let mut archive = zip::ZipArchive::new(file).map_err(|e| {
        BrowserError::FileNotFound(format!("invalid trace archive: {e}"))
    })?;

    // Extract to a temp directory
    let tmp = std::env::temp_dir().join(format!(
        "tallow-trace-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    std::fs::create_dir_all(&tmp).map_err(|e| {
        BrowserError::FileNotFound(format!("cannot create temp dir: {e}"))
    })?;

    // Extract all files
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            BrowserError::FileNotFound(format!("zip entry error: {e}"))
        })?;
        let out_path = tmp.join(entry.name());

        if entry.is_dir() {
            std::fs::create_dir_all(&out_path).map_err(|e| {
                BrowserError::FileNotFound(format!("mkdir error: {e}"))
            })?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    BrowserError::FileNotFound(format!("mkdir error: {e}"))
                })?;
            }
            let mut out_file = std::fs::File::create(&out_path).map_err(|e| {
                BrowserError::FileNotFound(format!("create file error: {e}"))
            })?;
            std::io::copy(&mut entry, &mut out_file).map_err(|e| {
                BrowserError::FileNotFound(format!("extract error: {e}"))
            })?;
        }
    }

    // Write viewer HTML
    let viewer_path = tmp.join("index.html");
    std::fs::write(&viewer_path, TRACE_VIEWER_HTML).map_err(|e| {
        BrowserError::FileNotFound(format!("write viewer error: {e}"))
    })?;

    // Open in default browser
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &viewer_path.to_string_lossy()])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(&viewer_path)
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(&viewer_path)
            .spawn();
    }

    eprintln!(
        "Trace viewer opened: {}",
        viewer_path.display()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recorder_start_stop() {
        let mut rec = TraceRecorder::new();
        assert!(!rec.is_recording());

        rec.start();
        assert!(rec.is_recording());

        rec.stop();
        assert!(!rec.is_recording());
    }

    #[test]
    fn test_record_action_when_not_recording() {
        let mut rec = TraceRecorder::new();
        // Not recording -- action should be ignored
        rec.record_action("click", Some(".btn"), None, None);
        assert!(rec.actions.is_empty());
    }

    #[test]
    fn test_record_action_stores_fields() {
        let mut rec = TraceRecorder::new();
        rec.start();

        rec.record_action("navigate", None, Some("https://example.com"), Some("https://example.com"));
        rec.record_action("click", Some("button#submit"), None, None);

        assert_eq!(rec.actions.len(), 2);
        assert_eq!(rec.actions[0].action_type, "navigate");
        assert!(rec.actions[0].selector.is_none());
        assert_eq!(rec.actions[0].value.as_deref(), Some("https://example.com"));
        assert_eq!(rec.actions[0].url.as_deref(), Some("https://example.com"));

        assert_eq!(rec.actions[1].action_type, "click");
        assert_eq!(rec.actions[1].selector.as_deref(), Some("button#submit"));
    }

    #[test]
    fn test_record_action_timestamp_progression() {
        let mut rec = TraceRecorder::new();
        rec.start();

        rec.record_action("navigate", None, None, None);
        std::thread::sleep(std::time::Duration::from_millis(10));
        rec.record_action("click", None, None, None);

        // Second action should have a later timestamp
        assert!(rec.actions[1].timestamp_ms >= rec.actions[0].timestamp_ms);
    }

    #[test]
    fn test_record_screenshot_returns_incrementing_indices() {
        let mut rec = TraceRecorder::new();
        rec.start();

        rec.record_action("navigate", None, None, None);
        let idx0 = rec.record_screenshot(vec![1, 2, 3]);
        assert_eq!(idx0, 0);

        rec.record_action("click", None, None, None);
        let idx1 = rec.record_screenshot(vec![4, 5, 6]);
        assert_eq!(idx1, 1);

        let idx2 = rec.record_screenshot(vec![7, 8, 9]);
        assert_eq!(idx2, 2);
    }

    #[test]
    fn test_record_screenshot_links_to_last_action() {
        let mut rec = TraceRecorder::new();
        rec.start();

        rec.record_action("navigate", None, None, None);
        rec.record_screenshot(vec![1]);

        assert_eq!(rec.actions[0].screenshot_index, Some(0));
    }

    #[test]
    fn test_record_screenshot_not_recording() {
        let mut rec = TraceRecorder::new();
        let idx = rec.record_screenshot(vec![1, 2, 3]);
        assert_eq!(idx, 0);
        assert!(rec.screenshots.is_empty());
    }

    #[test]
    fn test_record_network_event_stores_all_fields() {
        let mut rec = TraceRecorder::new();
        rec.start();

        rec.record_network_event(
            "response",
            "https://api.example.com/data",
            Some("GET"),
            Some(200),
            Some("application/json"),
            Some(4096),
        );

        assert_eq!(rec.network_events.len(), 1);
        let ev = &rec.network_events[0];
        assert_eq!(ev.event_type, "response");
        assert_eq!(ev.url, "https://api.example.com/data");
        assert_eq!(ev.method.as_deref(), Some("GET"));
        assert_eq!(ev.status, Some(200));
        assert_eq!(ev.mime_type.as_deref(), Some("application/json"));
        assert_eq!(ev.size_bytes, Some(4096));
    }

    #[test]
    fn test_record_network_event_not_recording() {
        let mut rec = TraceRecorder::new();
        rec.record_network_event("request", "https://example.com", None, None, None, None);
        assert!(rec.network_events.is_empty());
    }

    #[test]
    fn test_save_to_zip_creates_valid_archive() {
        let mut rec = TraceRecorder::new();
        rec.start();

        rec.record_action("navigate", None, Some("https://example.com"), Some("https://example.com"));
        rec.record_screenshot(vec![0x89, 0x50, 0x4E, 0x47]); // PNG magic bytes (not real PNG but sufficient for archive test)
        rec.record_network_event("request", "https://example.com", Some("GET"), None, None, None);
        rec.record_network_event("response", "https://example.com", Some("GET"), Some(200), Some("text/html"), Some(12345));

        rec.stop();

        let zip_path = std::env::temp_dir().join("tallow_trace_test.zip");
        rec.save_to_zip(&zip_path).unwrap();

        // Verify ZIP contents
        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        // Check file list
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();

        assert!(names.contains(&"actions.jsonl".to_string()));
        assert!(names.contains(&"network.jsonl".to_string()));
        assert!(names.contains(&"screenshots/0001.png".to_string()));
        assert!(names.contains(&"metadata.json".to_string()));

        // Verify actions.jsonl
        let actions_content = {
            let mut f = archive.by_name("actions.jsonl").unwrap();
            let mut s = String::new();
            std::io::Read::read_to_string(&mut f, &mut s).unwrap();
            s
        };
        let action_lines: Vec<&str> = actions_content.trim().lines().collect();
        assert_eq!(action_lines.len(), 1);
        let parsed: TraceAction = serde_json::from_str(action_lines[0]).unwrap();
        assert_eq!(parsed.action_type, "navigate");
        assert_eq!(parsed.screenshot_index, Some(0));

        // Verify network.jsonl
        let net_content = {
            let mut f = archive.by_name("network.jsonl").unwrap();
            let mut s = String::new();
            std::io::Read::read_to_string(&mut f, &mut s).unwrap();
            s
        };
        let net_lines: Vec<&str> = net_content.trim().lines().collect();
        assert_eq!(net_lines.len(), 2);

        // Verify screenshot
        let ss_data = {
            let mut f = archive.by_name("screenshots/0001.png").unwrap();
            let mut d = Vec::new();
            std::io::Read::read_to_end(&mut f, &mut d).unwrap();
            d
        };
        assert_eq!(ss_data, vec![0x89, 0x50, 0x4E, 0x47]);

        // Clean up
        let _ = std::fs::remove_file(&zip_path);
    }

    #[test]
    fn test_save_to_zip_metadata_json() {
        let mut rec = TraceRecorder::new();
        rec.start();

        rec.record_action("a", None, None, None);
        rec.record_action("b", None, None, None);
        rec.record_action("c", None, None, None);
        rec.record_screenshot(vec![1]);
        rec.record_network_event("request", "http://x", None, None, None, None);

        let zip_path = std::env::temp_dir().join("tallow_trace_meta_test.zip");
        rec.save_to_zip(&zip_path).unwrap();

        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let mut meta_file = archive.by_name("metadata.json").unwrap();
        let mut meta_content = String::new();
        std::io::Read::read_to_string(&mut meta_file, &mut meta_content).unwrap();
        let meta: TraceMetadata = serde_json::from_str(&meta_content).unwrap();

        assert_eq!(meta.version, 1);
        assert_eq!(meta.action_count, 3);
        assert_eq!(meta.screenshot_count, 1);
        assert_eq!(meta.network_event_count, 1);

        let _ = std::fs::remove_file(&zip_path);
    }

    #[test]
    fn test_trace_action_serialization_jsonl() {
        let action = TraceAction {
            timestamp_ms: 150,
            action_type: "click".to_string(),
            selector: Some("button.submit".to_string()),
            value: None,
            url: Some("https://example.com".to_string()),
            screenshot_index: Some(2),
            duration_ms: Some(45),
        };

        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("\"action_type\":\"click\""));
        assert!(json.contains("\"timestamp_ms\":150"));
        assert!(json.contains("\"screenshot_index\":2"));

        // Round-trip
        let deser: TraceAction = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.action_type, "click");
        assert_eq!(deser.timestamp_ms, 150);
        assert_eq!(deser.screenshot_index, Some(2));
    }

    #[test]
    fn test_trace_network_event_serialization() {
        let event = TraceNetworkEvent {
            timestamp_ms: 200,
            event_type: "response".to_string(),
            url: "https://api.example.com".to_string(),
            method: Some("POST".to_string()),
            status: Some(201),
            mime_type: Some("application/json".to_string()),
            size_bytes: Some(512),
            duration_ms: Some(85),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deser: TraceNetworkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.event_type, "response");
        assert_eq!(deser.status, Some(201));
        assert_eq!(deser.size_bytes, Some(512));
    }

    #[test]
    fn test_trace_metadata_serialization() {
        let meta = TraceMetadata {
            version: 1,
            action_count: 42,
            screenshot_count: 10,
            network_event_count: 100,
            duration_ms: 5000,
        };

        let json = serde_json::to_string(&meta).unwrap();
        let deser: TraceMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.version, 1);
        assert_eq!(deser.action_count, 42);
    }

    #[test]
    fn test_create_trace_viewer_html_not_empty() {
        let html = create_trace_viewer_html();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Tallow Trace Viewer"));
        assert!(html.contains("actions.jsonl"));
        assert!(html.contains("network.jsonl"));
        assert!(html.contains("screenshots/"));
    }

    #[test]
    fn test_save_to_zip_empty_trace() {
        let mut rec = TraceRecorder::new();
        rec.start();
        rec.stop();

        let zip_path = std::env::temp_dir().join("tallow_trace_empty_test.zip");
        rec.save_to_zip(&zip_path).unwrap();

        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        // Should still have actions.jsonl, network.jsonl, and metadata.json
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.contains(&"actions.jsonl".to_string()));
        assert!(names.contains(&"network.jsonl".to_string()));
        assert!(names.contains(&"metadata.json".to_string()));

        let mut meta_file = archive.by_name("metadata.json").unwrap();
        let mut content = String::new();
        std::io::Read::read_to_string(&mut meta_file, &mut content).unwrap();
        let meta: TraceMetadata = serde_json::from_str(&content).unwrap();
        assert_eq!(meta.action_count, 0);
        assert_eq!(meta.screenshot_count, 0);
        assert_eq!(meta.network_event_count, 0);

        let _ = std::fs::remove_file(&zip_path);
    }
}
