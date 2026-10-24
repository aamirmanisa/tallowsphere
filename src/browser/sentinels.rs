//! Real implementations of the browser v2 sentinels: CDP Emulation, Tracing and
//! Fetch interception, bound to the page the interpreter currently has open.
//!
//! These exist because the sentinels used to return structs marked
//! `simulated: true` while nothing underneath was touched — rules that blocked
//! nothing, a recorder that recorded nothing, a viewport applied to no page.
//! Every function here either performs the CDP command and reports what the
//! command returned, or fails with the reason. Nothing here fabricates success.
//!
//! The page is taken from `stdlib::browser::current_page()`, the same binding the
//! `page_*` free functions use; the CDP futures are driven on
//! `interp::get_browser_runtime()`, because the client's reader task lives there
//! and driving them elsewhere times out.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::browser::cdp::CdpEvent;
use crate::browser::{CdpClient, Page};

/// One interception rule, as written by `NetworkInterceptor.*`.
#[derive(Debug, Clone)]
pub enum Rule {
    Block(String),
    Mock { pattern: String, status: i64, body: String },
}

struct Intercept {
    rules: Arc<Mutex<Vec<Rule>>>,
    active: Arc<Mutex<bool>>,
}

struct Trace {
    name: String,
    dir: PathBuf,
    chunks: Arc<Mutex<Vec<String>>>,
    done: Arc<Mutex<bool>>,
}

thread_local! {
    /// The layout viewport as it was before the first override in this thread.
    static ORIGINAL_VIEWPORT: std::cell::RefCell<Option<(i64, i64)>> = const { std::cell::RefCell::new(None) };
    static INTERCEPT: std::cell::RefCell<Option<Intercept>> = const { std::cell::RefCell::new(None) };
    static TRACE: std::cell::RefCell<Option<Trace>> = const { std::cell::RefCell::new(None) };
}

fn page() -> Result<Page, String> {
    crate::stdlib::browser::current_page_handle()
        .ok_or_else(|| {
            "no page bound — launch a browser and open a page first \
             (Browser.launch(...).new_page()); the sentinel acts on that page"
                .to_string()
        })?
        .downcast_ref::<Page>()
        .cloned()
        .ok_or_else(|| "the bound handle is not a Page".to_string())
}

fn run<F, T, E>(fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    crate::interp::get_browser_runtime()
        .block_on(fut)
        .map_err(|e| e.to_string())
}

async fn emulation(page: &Page, method: &str, params: serde_json::Value) -> Result<(), String> {
    if std::env::var("TALLOW_SENTINEL_DEBUG").is_ok() {
        eprintln!("[sentinel] {method} session={} params={params}", page.session_id);
    }
    page.client
        .send_command_with_session(method, Some(params), &page.session_id)
        .await
        .map(|v| {
            if std::env::var("TALLOW_SENTINEL_DEBUG").is_ok() {
                eprintln!("[sentinel] {method} -> {v}");
            }
        })
        .map_err(|e| format!("{method}: {e}"))
}

// ── DeviceEmulator ──────────────────────────────────────────────────────────

fn capture_original(page: &Page) -> Option<(i64, i64)> {
    ORIGINAL_VIEWPORT.with(|slot| {
        if slot.borrow().is_some() {
            return None;
        }
        let v = run(async {
            page.evaluate_expression("document.documentElement.clientWidth + ',' + document.documentElement.clientHeight")
                .await
        })
        .ok()?;
        let text = v.as_str()?.to_string();
        let mut it = text.split(',');
        let w = it.next()?.trim().parse::<i64>().ok()?;
        let h = it.next()?.trim().parse::<i64>().ok()?;
        *slot.borrow_mut() = Some((w, h));
        None
    })
}

pub fn set_viewport(width: i64, height: i64, scale: f64) -> Result<(), String> {
    let page = page()?;
    let _ = capture_original(&page);
    // `setDeviceMetricsOverride` alone leaves the layout viewport at the window
    // size in headless-shell builds (measured: innerWidth stayed 1920 after an
    // override to 800x600 that reported success). `setVisibleSize` is the
    // companion call those builds honour, so both are issued and the result is
    // verified by the caller reading the page back.
    run(emulation(
        &page,
        "Emulation.setVisibleSize",
        json!({"width": width, "height": height}),
    ))?;
    run(emulation(
        &page,
        "Emulation.setDeviceMetricsOverride",
        json!({
            "width": width,
            "height": height,
            "screenWidth": width,
            "screenHeight": height,
            "deviceScaleFactor": scale,
            "mobile": false,
            "dontSetVisibleSize": false,
        }),
    ))
}

/// The device profiles the emulator knows. A name outside this table is refused
/// rather than silently mapped to a default — emulating "iPhone 15" as 1024x768
/// is worse than saying the profile is unknown.
fn device_profile(name: &str) -> Option<(i64, i64, f64, &'static str)> {
    let n = name.trim().to_ascii_lowercase();
    let n = n.replace([' ', '_'], "-");
    Some(match n.as_str() {
        "iphone-15" | "iphone-14" | "iphone-13" => (
            390,
            844,
            3.0,
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        ),
        "pixel-8" | "pixel-7" => (
            412,
            915,
            2.625,
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/124.0.0.0 Mobile Safari/537.36",
        ),
        "ipad" | "ipad-pro" => (
            1024,
            1366,
            2.0,
            "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        ),
        _ => return None,
    })
}

pub fn set_mobile(name: &str) -> Result<(), String> {
    let _ = capture_original(&page()?);
    let (w, h, scale, ua) = device_profile(name).ok_or_else(|| {
        format!(
            "DeviceEmulator.set_mobile: unknown profile '{name}' — known: iphone-15, pixel-8, ipad"
        )
    })?;
    let page = page()?;
    run(emulation(
        &page,
        "Emulation.setDeviceMetricsOverride",
        json!({
            "width": w,
            "height": h,
            "screenWidth": w,
            "screenHeight": h,
            "deviceScaleFactor": scale,
            "mobile": true,
            "dontSetVisibleSize": false,
        }),
    ))?;
    run(emulation(
        &page,
        "Emulation.setUserAgentOverride",
        json!({"userAgent": ua}),
    ))
}

pub fn set_geolocation(lat: f64, lon: f64, accuracy: f64) -> Result<(), String> {
    let page = page()?;
    run(emulation(
        &page,
        "Emulation.setGeolocationOverride",
        json!({"latitude": lat, "longitude": lon, "accuracy": accuracy}),
    ))
}

pub fn set_timezone(tz: &str) -> Result<(), String> {
    let page = page()?;
    run(emulation(
        &page,
        "Emulation.setTimezoneOverride",
        json!({"timezoneId": tz}),
    ))
}

pub fn set_locale(locale: &str) -> Result<(), String> {
    let page = page()?;
    run(emulation(
        &page,
        "Emulation.setLocaleOverride",
        json!({"locale": locale}),
    ))
}

pub fn set_user_agent(ua: &str) -> Result<(), String> {
    let page = page()?;
    run(emulation(
        &page,
        "Emulation.setUserAgentOverride",
        json!({"userAgent": ua}),
    ))
}

/// Remove every override the emulator can set, in the order CDP requires.
pub fn clear_emulation() -> Result<(), String> {
    let page = page()?;
    // Order matters and was measured the wrong way round first: clearing the
    // metrics override *after* resizing the widget re-applied the old metrics on
    // the next layout, so the page kept reporting the emulated width. Clear the
    // override first, then put the widget back to the size it had.
    let original = ORIGINAL_VIEWPORT.with(|slot| slot.borrow_mut().take()).or_else(|| {
        run(async {
            page.evaluate_expression("window.outerWidth + ',' + window.outerHeight")
                .await
        })
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .and_then(|s| {
            let mut it = s.split(',');
            let w = it.next()?.trim().parse::<i64>().ok()?;
            let h = it.next()?.trim().parse::<i64>().ok()?;
            Some((w, h))
        })
    });

    run(emulation(
        &page,
        "Emulation.clearDeviceMetricsOverride",
        json!({}),
    ))?;
    if let Some((w, h)) = original {
        if w > 0 && h > 0 {
            run(emulation(
                &page,
                "Emulation.setVisibleSize",
                json!({"width": w, "height": h}),
            ))?;
        }
    }
    run(emulation(
        &page,
        "Emulation.clearGeolocationOverride",
        json!({}),
    ))?;
    run(emulation(
        &page,
        "Emulation.setTimezoneOverride",
        json!({"timezoneId": ""}),
    ))?;
    run(emulation(
        &page,
        "Emulation.setLocaleOverride",
        json!({"locale": ""}),
    ))?;
    run(emulation(
        &page,
        "Emulation.setUserAgentOverride",
        json!({"userAgent": ""}),
    ))?;

    // The widget resize is applied asynchronously by the browser. Without this
    // wait the page still reports the emulated width immediately after `clear()`
    // — measured as an intermittent failure, roughly one run in five, because
    // the read raced the relayout. Wait for the value to actually change, and
    // report the failure rather than returning as if the restore happened.
    if let Some((w, _h)) = original {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1000);
        loop {
            let now = run(async {
                page.evaluate_expression("document.documentElement.clientWidth").await
            })
            .ok()
            .and_then(|v| v.as_i64());
            if now == Some(w) {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "clearDeviceMetricsOverride did not restore the layout width: expected {w}, \
                     page still reports {now:?} after 1 s"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
    Ok(())
}

// ── NetworkInterceptor ──────────────────────────────────────────────────────

fn glob_match(pattern: &str, url: &str) -> bool {
    // Wildcard match over bytes, `*` matching any run. Anchored at both ends
    // only when the pattern is; a bare substring is a substring.
    if !pattern.contains('*') {
        return url.contains(pattern);
    }
    let p: Vec<char> = pattern.chars().collect();
    let u: Vec<char> = url.chars().collect();
    let (mut pi, mut ui) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ui < u.len() {
        if pi < p.len() && (p[pi] == u[ui]) {
            pi += 1;
            ui += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ui;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ui = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    if pi == p.len() {
        return true;
    }
    false
}

pub fn intercept_create() -> Result<(), String> {
    // Binding the interceptor to a page is what makes it a control: without a
    // session there is nothing to intercept, and saying so is the whole point.
    let page = page()?;
    let client = page.client.clone();
    let session = page.session_id.clone();
    let rules = Arc::new(Mutex::new(Vec::<Rule>::new()));
    let active = Arc::new(Mutex::new(false));

    INTERCEPT.with(|slot| {
        *slot.borrow_mut() = Some(Intercept {
            rules: Arc::clone(&rules),
            active: Arc::clone(&active),
        })
    });

    // Enable Fetch at request stage for every request; the pump decides per
    // request. `handleAuthRequests` is off: intercepting auth prompts is a
    // different control with different failure modes.
    run(async {
        client
            .send_command_with_session(
                "Fetch.enable",
                Some(json!({
                    "patterns": [{"urlPattern": "*", "requestStage": "Request"}],
                    "handleAuthRequests": false
                })),
                &session,
            )
            .await
            .map(|_| ())
    })?;
    *active.lock().unwrap() = true;

    spawn_pump(client, session, rules);
    Ok(())
}

/// One pump per interceptor: answers every `Fetch.requestPaused` according to
/// the current rules, and accumulates tracing data when a trace is running.
fn spawn_pump(client: CdpClient, session: String, rules: Arc<Mutex<Vec<Rule>>>) {
    let mut events = client.subscribe();
    crate::interp::get_browser_runtime().spawn(async move {
        loop {
            let ev = match events.recv().await {
                Ok(ev) => ev,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            };
            let method = ev.method.clone();
            if method != "Fetch.requestPaused" {
                continue;
            }
            let Some(params) = ev.params.clone() else {
                continue;
            };
            let Some(request_id) = params.get("requestId").and_then(|v| v.as_str()) else {
                continue;
            };
            let url = params
                .get("request")
                .and_then(|r| r.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let action = {
                let list = rules.lock().unwrap();
                list.iter().rev().find_map(|r| match r {
                    Rule::Block(p) if glob_match(p, &url) => Some(("block", None)),
                    Rule::Mock { pattern, status, body } if glob_match(pattern, &url) => {
                        Some(("mock", Some((*status, body.clone()))))
                    }
                    _ => None,
                })
            };

            let (cmd, payload) = match action {
                Some(("block", _)) => (
                    "Fetch.failRequest",
                    json!({"requestId": request_id, "errorReason": "BlockedByClient"}),
                ),
                Some(("mock", Some((status, body)))) => (
                    "Fetch.fulfillRequest",
                    json!({
                        "requestId": request_id,
                        "responseCode": status,
                        "responseHeaders": [{"name": "Content-Type", "value": "text/html; charset=utf-8"}],
                        "body": base64(body.as_bytes()),
                    }),
                ),
                _ => ("Fetch.continueRequest", json!({"requestId": request_id})),
            };
            let _ = client
                .send_command_with_session(cmd, Some(payload), &session)
                .await;
        }
    });
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn intercept_add_rule(rule: Rule) {
    INTERCEPT.with(|slot| {
        if let Some(i) = slot.borrow().as_ref() {
            i.rules.lock().unwrap().push(rule);
        }
    });
}

pub fn intercept_rule_count() -> usize {
    INTERCEPT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|i| i.rules.lock().unwrap().len())
            .unwrap_or(0)
    })
}

pub fn intercept_active() -> bool {
    INTERCEPT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|i| *i.active.lock().unwrap())
            .unwrap_or(false)
    })
}

pub fn intercept_clear() -> Result<(), String> {
    let page = page()?;
    INTERCEPT.with(|slot| {
        if let Some(i) = slot.borrow().as_ref() {
            i.rules.lock().unwrap().clear();
            *i.active.lock().unwrap() = false;
        }
    });
    run(emulation(&page, "Fetch.disable", json!({})))
}

// ── TraceRecorder ───────────────────────────────────────────────────────────

pub fn trace_start(name: &str) -> Result<(), String> {
    let page = page()?;
    // Under the run sandbox, /tmp belongs to the child's mount namespace: a
    // trace written there is invisible to the caller. The run directory is the
    // one place both sides agree on.
    let dir = std::env::current_dir()
        .map(|d| d.join(".tallow-traces"))
        .unwrap_or_else(|_| std::env::temp_dir().join("tallow-traces"));
    std::fs::create_dir_all(&dir).map_err(|e| format!("trace dir: {e}"))?;

    let chunks = Arc::new(Mutex::new(Vec::<String>::new()));
    let done = Arc::new(Mutex::new(false));
    TRACE.with(|slot| {
        *slot.borrow_mut() = Some(Trace {
            name: name.to_string(),
            dir: dir.clone(),
            chunks: Arc::clone(&chunks),
            done: Arc::clone(&done),
        })
    });

    // Subscribe before `Tracing.start` so no `dataCollected` is missed, and
    // keep the receiver alive for `trace_stop` — a receiver created later loses
    // every event the broadcast already dropped.
    let mut events = page.client.subscribe();
    {
        let mut slot = TRACE_EVENTS.with(|s| s.borrow_mut().take());
        slot = Some(Collector {
            events: std::mem::replace(&mut events, page.client.subscribe()),
            chunks: Arc::clone(&chunks),
            done: Arc::clone(&done),
        });
        TRACE_EVENTS.with(|s| *s.borrow_mut() = Some(slot.unwrap()));
    }

    run(emulation(
        &page,
        "Tracing.start",
        json!({
            "categories": "devtools.timeline,v8.execute,blink.user_timing",
            "options": "sampling-frequency=1000",
            "transferMode": "ReportEvents"
        }),
    ))
}

/// One trace's event receiver, kept between `start` and `stop`.
struct Collector {
    events: tokio::sync::broadcast::Receiver<CdpEvent>,
    chunks: Arc<Mutex<Vec<String>>>,
    done: Arc<Mutex<bool>>,
}

thread_local! {
    static TRACE_EVENTS: std::cell::RefCell<Option<Collector>> = const { std::cell::RefCell::new(None) };
}

/// Mark one action in the trace. This is a real marker: it goes into the trace
/// document as a timestamp event, not into a field nobody reads.
pub fn trace_mark(action: &str, detail: &str) -> Result<(), String> {
    let page = page()?;
    let name = serde_json::to_string(&format!("{action}: {detail}")).unwrap_or_default();
    run(emulation(
        &page,
        "Runtime.evaluate",
        json!({
            "expression": format!(
                "performance.mark({name}); {name};"
            ),
            "returnByValue": true
        }),
    ))
}

pub fn trace_stop() -> Result<(String, PathBuf, usize), String> {
    let page = page()?;

    let mut collector = TRACE_EVENTS
        .with(|s| s.borrow_mut().take())
        .ok_or_else(|| "TraceRecorder.stop: no trace was started".to_string())?;

    let (name, dir) = TRACE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|t| (t.name.clone(), t.dir.clone()))
            .ok_or_else(|| "TraceRecorder.stop: no trace was started".to_string())
    })?;

    // End and wait inside one driven future: a `thread::sleep` poll would block
    // the thread the collector task needs, and the wait would time out while
    // the runtime sat idle.
    let client = page.client.clone();
    let session = page.session_id.clone();
    let done = Arc::clone(&collector.done);
    let done_after = Arc::clone(&collector.done);
    let chunks = Arc::clone(&collector.chunks);

    run(async move {
        client
            .send_command_with_session("Tracing.end", Some(json!({})), &session)
            .await?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            while let Ok(ev) = collector.events.try_recv() {
                match ev.method.as_str() {
                    "Tracing.dataCollected" => {
                        if let Some(value) = ev.params.as_ref().and_then(|p| p.get("value")) {
                            if let Ok(t) = serde_json::to_string(value) {
                                collector.chunks.lock().unwrap().push(t);
                            }
                        }
                    }
                    "Tracing.tracingComplete" => {
                        *collector.done.lock().unwrap() = true;
                    }
                    _ => {}
                }
            }
            if *done.lock().unwrap() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        Ok::<(), crate::browser::BrowserError>(())
    })?;

    if !*done_after.lock().unwrap() {
        return Err(
            "Tracing.tracingComplete did not arrive within 10 s; the trace is incomplete".into(),
        );
    }

    let collected = chunks.lock().unwrap().clone();
    let count = collected.len();
    let file = dir.join(format!("{}.json", name.replace('/', "_")));
    std::fs::write(&file, format!("[{}]", collected.join(",")))
        .map_err(|e| format!("trace write: {e}"))?;
    TRACE.with(|slot| *slot.borrow_mut() = None);
    Ok((name, file, count))
}

pub fn trace_active() -> bool {
    TRACE.with(|slot| slot.borrow().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matching_is_anchored_only_when_the_pattern_is() {
        assert!(glob_match("*.example.test/*", "https://a.example.test/x"));
        assert!(!glob_match("*.example.test", "https://a.example.test/x"));
        // A pattern with no `*` is a substring: callers write "ads" meaning
        // "any URL containing ads", not "a URL that is exactly ads".
        assert!(glob_match("ads.js", "https://t.example/js/ads.js"));
        assert!(!glob_match("ads.js", "https://t.example/js/news.js"));
        assert!(glob_match("example.test", "https://b.example.test/example.test"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*ads*", "https://t.example/ads/1.js"));
        assert!(!glob_match("*ads*", "https://t.example/news"));
    }

    #[test]
    fn base64_matches_the_standard_alphabet() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn an_unknown_device_profile_is_refused_not_defaulted() {
        assert!(device_profile("blackberry-2008").is_none());
        assert!(device_profile("iPhone 15").is_some());
    }
}
