//! Standard library: `tallow.frame` — iFrame traversal and interaction.
//!
//! Provides real CDP-backed frame discovery, content extraction, and DOM
//! querying within iframe contexts. Uses `Page.getFrameTree()` for frame
//! enumeration and `Runtime.evaluate` with frame-specific execution contexts
//! (obtained via `Page.createIsolatedWorld`) for cross-frame interaction.

use super::StdlibResult;
use crate::browser::cdp::CdpClient;
use crate::browser::frame::parse_frame_tree;
use crate::browser::page::WaitUntil;
use crate::browser::process::{BrowserConfig, BrowserProcess};
use crate::interp::Value;

/// Dispatch a `tallow.frame.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "page_frames" => Some(page_frames(args)),
        _ => None,
    }
}

/// Dispatch a method on Frame struct types.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, .. } = object else {
        return None;
    };
    match name.as_str() {
        "Frame" => match method {
            "content" => Some(frame_content(object)),
            "query_selector" => Some(frame_query_selector(object, args)),
            "query_selector_all" => Some(frame_query_selector_all(object, args)),
            "inner_html" => Some(frame_inner_html(object)),
            _ => None,
        },
        _ => None,
    }
}

// ── page_frames([url]) -> [Frame] ──────────────────────────────────────

fn page_frames(args: Vec<Value>) -> StdlibResult {
    let url = match args.first() {
        Some(Value::String(s)) => s.clone(),
        None => "about:blank".to_string(),
        Some(other) => other.to_string(),
    };

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("frame.page_frames: failed to create tokio runtime: {e}"))?;

    rt.block_on(async move { page_frames_async(&url).await })
}

async fn page_frames_async(url: &str) -> StdlibResult {
    // ── Launch browser ──────────────────────────────────────────────────
    // Egress: inherit the box's Tor/proxy contract (TALLOW_PROXY /
    // TALLOW_TOR) like every other launch path — a bare `default()`
    // opened Chrome with no proxy at all, so this helper egressed from
    // the box IP and resolved DNS locally.
    let config = BrowserConfig {
        proxy: crate::runtime::fetch::egress_proxy_url(),
        ..BrowserConfig::default()
    };
    let browser = BrowserProcess::launch(&config)
        .map_err(|e| format!("frame.page_frames: failed to launch browser: {e}"))?;
    let ws_url = browser.ws_url.clone();

    // ── Connect CDP client ──────────────────────────────────────────────
    let client = CdpClient::connect(&ws_url)
        .await
        .map_err(|e| format!("frame.page_frames: failed to connect CDP: {e}"))?;

    // ── Create page and navigate ────────────────────────────────────────
    let page = client
        .create_page(None)
        .await
        .map_err(|e| format!("frame.page_frames: failed to create page: {e}"))?;

    page.navigate(url, WaitUntil::DomContentLoaded)
        .await
        .map_err(|e| format!("frame.page_frames: failed to navigate: {e}"))?;

    // ── Get frame tree via CDP ──────────────────────────────────────────
    let frame_tree_result = client
        .send_command_with_session("Page.getFrameTree", None, &page.session_id)
        .await
        .map_err(|e| format!("frame.page_frames: Page.getFrameTree failed: {e}"))?;

    let frame_infos = parse_frame_tree(&frame_tree_result);

    // ── Build Frame structs with internal CDP connection info ───────────
    let frames: Vec<Value> = frame_infos
        .iter()
        .map(|fi| {
            Value::Struct {
                name: "Frame".to_string(),
                fields: vec![
                    ("url".to_string(), Value::String(fi.url.clone())),
                    ("name".to_string(), Value::String(fi.name.clone())),
                    // Internal fields for CDP reconnection
                    (
                        "_ws_url".to_string(),
                        Value::String(ws_url.clone()),
                    ),
                    (
                        "_session_id".to_string(),
                        Value::String(page.session_id.clone()),
                    ),
                    (
                        "_frame_id".to_string(),
                        Value::String(fi.id.clone()),
                    ),
                ],
            }
        })
        .collect();

    // Don't close the page — the Frame structs may need to reconnect.
    // The browser and page will be cleaned up when the CdpClient drops,
    // but since we store ws_url, reconnection creates a new connection.

    Ok(Value::Array(frames))
}

// ── Frame.content() -> String ──────────────────────────────────────────

fn frame_content(frame: &Value) -> StdlibResult {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Frame.content: failed to create tokio runtime: {e}"))?;

    rt.block_on(async move {
        let (client, frame_id) = connect_to_frame(frame).await?;
        let expression = "document.documentElement.outerHTML";
        eval_in_frame(&client, &frame_id, expression).await
    })
}

// ── Frame.query_selector(selector) -> String? ──────────────────────────

fn frame_query_selector(frame: &Value, args: Vec<Value>) -> StdlibResult {
    let selector = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => return Err("Frame.query_selector: expected a CSS selector string".to_string()),
    };

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Frame.query_selector: failed to create tokio runtime: {e}"))?;

    rt.block_on(async move {
        let (client, frame_id) = connect_to_frame(frame).await?;
        // Use optional chaining — returns null if no match
        let js_selector = serde_json::to_string(&selector).unwrap_or_default();
        let expression = format!(
            "document.querySelector({sel})?.outerHTML || null",
            sel = js_selector
        );
        eval_in_frame(&client, &frame_id, &expression).await
    })
}

// ── Frame.query_selector_all(selector) -> [String] ─────────────────────

fn frame_query_selector_all(frame: &Value, args: Vec<Value>) -> StdlibResult {
    let selector = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => {
            return Err(
                "Frame.query_selector_all: expected a CSS selector string".to_string(),
            )
        }
    };

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Frame.query_selector_all: failed to create tokio runtime: {e}"))?;

    rt.block_on(async move {
        let (client, frame_id) = connect_to_frame(frame).await?;
        let js_selector = serde_json::to_string(&selector).unwrap_or_default();
        let expression = format!(
            "Array.from(document.querySelectorAll({sel})).map(el => el.outerHTML)",
            sel = js_selector
        );
        eval_in_frame(&client, &frame_id, &expression).await
    })
}

// ── Frame.inner_html() -> String ───────────────────────────────────────

fn frame_inner_html(frame: &Value) -> StdlibResult {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Frame.inner_html: failed to create tokio runtime: {e}"))?;

    rt.block_on(async move {
        let (client, frame_id) = connect_to_frame(frame).await?;
        let expression = "document.documentElement.innerHTML";
        eval_in_frame(&client, &frame_id, expression).await
    })
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Extract CDP connection info from a Frame struct and reconnect.
async fn connect_to_frame(frame: &Value) -> Result<(CdpClient, String), String> {
    let fields = match frame {
        Value::Struct { fields, .. } => fields,
        _ => return Err("Frame: expected a Frame struct".to_string()),
    };

    let ws_url = get_field_str(fields, "_ws_url")
        .ok_or_else(|| "Frame: missing _ws_url (frame not from page_frames?)".to_string())?;

    let _session_id = get_field_str(fields, "_session_id").unwrap_or_default();

    let frame_id = get_field_str(fields, "_frame_id")
        .ok_or_else(|| "Frame: missing _frame_id (frame not from page_frames?)".to_string())?;

    let client = CdpClient::connect(&ws_url)
        .await
        .map_err(|e| format!("Frame: failed to reconnect CDP: {e}"))?;

    Ok((client, frame_id))
}

/// Evaluate a JS expression in a frame's execution context.
///
/// Uses Page.createIsolatedWorld() to obtain an executionContextId for the
/// frame, then Runtime.evaluate() with that context. Returns the result
/// as a Tallow Value.
async fn eval_in_frame(
    client: &CdpClient,
    frame_id: &str,
    expression: &str,
) -> StdlibResult {
    // ── Step 1: Create an isolated world for the frame to get an executionContext ──
    let world_result = client
        .send_command(
            "Page.createIsolatedWorld",
            Some(serde_json::json!({
                "frameId": frame_id,
            })),
        )
        .await
        .map_err(|e| {
            // If createIsolatedWorld fails (cross-origin, detached frame), return empty
            if is_frame_access_error(&e) {
                return "".to_string();
            }
            format!("Frame: Page.createIsolatedWorld failed: {e}")
        })?;

    let context_id = world_result
        .get("executionContextId")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            "Frame: createIsolatedWorld returned no executionContextId".to_string()
        })?;

    // ── Step 2: Evaluate expression in the frame's context ──────────────
    let eval_result = client
        .send_command(
            "Runtime.evaluate",
            Some(serde_json::json!({
                "expression": expression,
                "contextId": context_id,
                "returnByValue": true,
                "awaitPromise": true,
            })),
        )
        .await
        .map_err(|e| {
            if is_frame_access_error(&e) {
                return "".to_string();
            }
            format!("Frame: Runtime.evaluate failed: {e}")
        })?;

    // ── Step 3: Extract value from result ───────────────────────────────
    let value = eval_result
        .get("result")
        .and_then(|r| r.get("value"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // Convert serde_json::Value to tallow Value
    Ok(json_to_tallow_value(&value))
}

/// Check if a BrowserError is a frame-access-related error (cross-origin, detached, etc.)
fn is_frame_access_error(err: &crate::browser::error::BrowserError) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("cross-origin")
        || msg.contains("detached frame")
        || msg.contains("not found")
        || msg.contains("no frame")
        || msg.contains("frame was detached")
        || msg.contains("execution context was destroyed")
        || msg.contains("execution context not found")
}

/// Convert serde_json::Value to tallow::interp::Value.
fn json_to_tallow_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i as i128)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            Value::Array(arr.iter().map(json_to_tallow_value).collect())
        }
        serde_json::Value::Object(obj) => {
            // Convert to Map of (String -> Value) pairs
            let pairs: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, v)| {
                    (Value::String(k.clone()), json_to_tallow_value(v))
                })
                .collect();
            Value::Map(pairs)
        }
    }
}

fn get_field_str(fields: &[(String, Value)], name: &str) -> Option<String> {
    fields.iter().find_map(|(f, v)| {
        if f == name {
            match v {
                Value::String(s) => Some(s.clone()),
                _ => None,
            }
        } else {
            None
        }
    })
}
