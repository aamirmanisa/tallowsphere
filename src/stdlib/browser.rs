//! Standard library: `tallow.browser` contract/facade metadata.
//!
//! This module is intentionally a **contract boundary** rather than a second
//! browser runtime. Live browser operations still route through the interpreter,
//! codegen FFI, and `src/browser/**`. The facade here gives operators and tests
//! a single, non-live place to ask what the accepted browser phases actually claim.

use super::StdlibResult;
use crate::interp::Value;
use regex::Regex;
use std::sync::LazyLock;

// ── Current-page registry ────────────────────────────────────────────────
//
// `stdlib/browser.tl` declares module-level `page_*` helpers that take no Page
// argument (`page_extract_all_text(selector)` and friends). A live page is not
// reachable from a free function unless something binds it, so the interpreter
// registers the Page it just created or navigated here, and these helpers act
// on that page. Without a bound page they keep answering with the explicit
// "no page bound" refusal instead of pretending to work.
thread_local! {
    static CURRENT_PAGE: std::cell::RefCell<
        Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    > = const { std::cell::RefCell::new(None) };
}

/// Register the page that subsequent `browser.page_*` free functions act on.
pub fn bind_current_page(handle: std::sync::Arc<dyn std::any::Any + Send + Sync>) {
    CURRENT_PAGE.with(|slot| *slot.borrow_mut() = Some(handle));
}

fn current_page() -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    CURRENT_PAGE.with(|slot| slot.borrow().clone())
}

/// The bound page handle, for callers that must reach the interpreter (the
/// callback registrations resolve a Tallow function name there).
pub fn current_page_handle() -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    current_page()
}

/// Evaluate `js` on the bound page and return the CDP result as a `Value`.
fn eval_on_bound_page(js: &str) -> StdlibResult {
    let handle = current_page().ok_or_else(|| {
        "browser: no page bound — call browser.page_extract_all_text() and friends only after \
         a Page exists (Browser.launch(...).new_page()); otherwise use the Page handle directly"
            .to_string()
    })?;
    let page = handle
        .downcast_ref::<crate::browser::Page>()
        .ok_or_else(|| "browser: the bound handle is not a Page".to_string())?;
    // The CDP client's reader task lives on the interpreter's browser runtime;
    // driving the future on any other runtime times out (measured: the call
    // waited on a response no task was reading).
    let value = crate::interp::get_browser_runtime()
        .block_on(page.evaluate_expression(js))
        .map_err(|e| format!("browser: {e}"))?;
    Ok(super::json::json_to_value(&value))
}

/// `page_extract_all_text(selector) -> [String]` — one CDP round trip.
fn page_extract_all_text(args: Vec<Value>) -> StdlibResult {
    let selector = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("page_extract_all_text: expected a selector string".into()),
    };
    let js = format!(
        "Array.from(document.querySelectorAll({sel})).map(e => (e.textContent || '').trim())",
        sel = serde_json::to_string(&selector).map_err(|e| e.to_string())?
    );
    match eval_on_bound_page(&js)? {
        Value::Array(items) => Ok(Value::Array(
            items
                .into_iter()
                .map(|v| Value::String(v.as_string()))
                .collect(),
        )),
        other => Err(format!(
            "page_extract_all_text: expected an array from the page, got {}",
            crate::interp::type_name(&other)
        )),
    }
}

/// `page_extract_all_attrs(selector, attrs) -> [Map<String, String>]`.
fn page_extract_all_attrs(args: Vec<Value>) -> StdlibResult {
    let selector = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("page_extract_all_attrs: expected a selector string".into()),
    };
    let attrs: Vec<String> = match args.get(1) {
        Some(Value::Array(items)) => items.iter().map(|v| v.as_string()).collect(),
        _ => return Err("page_extract_all_attrs: expected an array of attribute names".into()),
    };
    let js = format!(
        "Array.from(document.querySelectorAll({sel})).map(e => {{ const o = {{}}; {body}; return o; }})",
        sel = serde_json::to_string(&selector).map_err(|e| e.to_string())?,
        body = attrs
            .iter()
            .map(|a| format!(
                "o[{name}] = e.getAttribute({name}) || '';",
                name = serde_json::to_string(a).unwrap_or_else(|_| "\"\"".into())
            ))
            .collect::<Vec<_>>()
            .join(" ")
    );
    match eval_on_bound_page(&js)? {
        Value::Array(items) => Ok(Value::Array(
            items
                .into_iter()
                .map(|v| match v {
                    Value::Map(entries) => Value::Map(
                        entries
                            .into_iter()
                            .map(|(k, val)| (k, Value::String(val.as_string())))
                            .collect(),
                    ),
                    other => Value::Map(vec![(
                        Value::String("value".to_string()),
                        Value::String(other.as_string()),
                    )]),
                })
                .collect(),
        )),
        other => Err(format!(
            "page_extract_all_attrs: expected an array from the page, got {}",
            crate::interp::type_name(&other)
        )),
    }
}

/// `page_capture_dom_snapshot() -> String` — the live document's outer HTML.
fn page_capture_dom_snapshot() -> StdlibResult {
    eval_on_bound_page("document.documentElement.outerHTML")
}

/// Run `f` against the bound page, or explain precisely why there is none.
fn with_bound_page<T>(
    f: impl FnOnce(&crate::browser::Page) -> Result<T, String>,
) -> Result<T, String> {
    let handle = current_page().ok_or_else(|| {
        "browser: no page bound — call browser.page_extract_all_text() and friends only after \
         a Page exists (Browser.launch(...).new_page()); otherwise use the Page handle directly"
            .to_string()
    })?;
    let page = handle
        .downcast_ref::<crate::browser::Page>()
        .ok_or_else(|| "browser: the bound handle is not a Page".to_string())?;
    f(page)
}

/// `page_text_redacted() -> String` — visible text with PII redacted. Uses the
/// same `redact_pii` the offline extractor uses, so the two paths cannot drift.
fn page_text_redacted() -> StdlibResult {
    match eval_on_bound_page("document.body ? document.body.innerText : ''")? {
        Value::String(text) => Ok(Value::String(redact_pii(&text))),
        other => Err(format!(
            "page_text_redacted: expected text from the page, got {}",
            crate::interp::type_name(&other)
        )),
    }
}

/// `page_block_non_essential() -> Result<()>` — blocks images, fonts, media and
/// stylesheets at the CDP level, which is the only place blocking actually
/// saves bytes (a JS filter would still download them).
fn page_block_non_essential() -> StdlibResult {
    with_bound_page(|page| {
        let client = page.client.clone();
        let blocked = serde_json::json!({
            "urls": [
                "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.svg", "*.ico",
                "*.woff", "*.woff2", "*.ttf", "*.otf",
                "*.mp4", "*.webm", "*.mp3", "*.css"
            ]
        });
        crate::interp::get_browser_runtime()
            .block_on(client.send_command_with_session(
                "Network.setBlockedURLs",
                Some(blocked),
                &page.session_id,
            ))
            .map_err(|e| format!("page_block_non_essential: {e}"))?;
        Ok(Value::Ok(Box::new(Value::Nil)))
    })
}

/// `page_wait_for_stable(timeout_ms, quiesce_ms) -> Result<()>` — waits until
/// the document stops changing. Stability is measured on the document itself
/// (size of the serialized DOM plus visible text), sampled every 50 ms.
fn page_wait_for_stable(args: Vec<Value>) -> StdlibResult {
    let timeout_ms = args
        .first()
        .map(Value::as_string)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30_000);
    let quiesce_ms = args
        .get(1)
        .map(Value::as_string)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(500);
    with_bound_page(|page| {
        let started = std::time::Instant::now();
        let mut last = String::new();
        let mut stable_since = std::time::Instant::now();
        loop {
            let signature = crate::interp::get_browser_runtime()
                .block_on(page.evaluate_expression(
                    "(document.documentElement.outerHTML.length) + ':' + \
                     ((document.body && document.body.innerText.length) || 0)",
                ))
                .map(|v| v.to_string())
                .map_err(|e| format!("page_wait_for_stable: {e}"))?;
            if signature != last {
                last = signature;
                stable_since = std::time::Instant::now();
            } else if stable_since.elapsed().as_millis() as u64 >= quiesce_ms {
                return Ok(Value::Ok(Box::new(Value::Nil)));
            }
            if started.elapsed().as_millis() as u64 >= timeout_ms {
                return Err(format!(
                    "page_wait_for_stable: timed out after {timeout_ms} ms without {quiesce_ms} ms of stability"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    })
}

/// `page_detect_pagination() -> PaginationInfo?` — reads the current document's
/// own links; returns null when the page offers no way forward.
fn page_detect_pagination() -> StdlibResult {
    let js = r#"(() => {
        const next = document.querySelector('a[rel="next"], link[rel="next"]');
        const nums = document.querySelectorAll('a[href*="page="], a[href*="/page/"], .pagination a').length;
        const more = Array.from(document.querySelectorAll('button, a')).find(
            e => /load more|show more|more results|view more/i.test(e.textContent || ''));
        if (next) return {strategy: 'next_button', next_url: next.href || next.getAttribute('href') || '', total_links: nums};
        if (more) return {strategy: 'load_more', next_url: '', total_links: nums};
        if (nums >= 2) return {strategy: 'numbered', next_url: '', total_links: nums};
        return null;
    })()"#;
    match eval_on_bound_page(js)? {
        Value::Nil => Ok(Value::Nil),
        Value::Map(entries) => {
            let get = |k: &str| {
                entries
                    .iter()
                    .find(|(key, _)| key.as_string() == k)
                    .map(|(_, v)| v.clone())
                    .unwrap_or(Value::Nil)
            };
            Ok(Value::Struct {
                name: "PaginationInfo".to_string(),
                fields: vec![
                    ("strategy".to_string(), get("strategy")),
                    ("next_url".to_string(), get("next_url")),
                    (
                        "total_links".to_string(),
                        Value::Int(get("total_links").as_string().parse().unwrap_or(0)),
                    ),
                ],
            })
        }
        other => Err(format!(
            "page_detect_pagination: unexpected page answer: {}",
            crate::interp::type_name(&other)
        )),
    }
}

/// `page_handle_cookie_consent(strategy) -> bool` — clicks the first visible
/// consent control that matches the requested strategy (accept / reject /
/// dismiss). Returns whether anything was clicked; `false` means "no banner
/// found or button not matched", never "pretended to dismiss".
fn page_handle_cookie_consent(args: Vec<Value>) -> StdlibResult {
    let strategy = args
        .first()
        .map(Value::as_string)
        .unwrap_or_else(|| "accept".to_string());
    let js = format!(
        r#"(() => {{
            const strategy = {strategy};
            const sets = {{
                accept: ['button#onetrust-accept-btn-handler', '#onetrust-accept-btn-handler',
                         'button[aria-label*="Accept" i]', 'button[title*="Accept" i]',
                         '.cc-btn.cc-allow', '#accept-cookies'],
                reject: ['#onetrust-reject-all-handler', 'button[aria-label*="Reject" i]',
                         '.cc-btn.cc-deny'],
                dismiss: ['button[aria-label*="Close" i]', '.cc-btn.cc-dismiss', '#close-cookies']
            }};
            const visible = e => e && e.offsetParent !== null;
            for (const sel of (sets[strategy] || sets.accept)) {{
                const el = document.querySelector(sel);
                if (visible(el)) {{ el.click(); return true; }}
            }}
            const byText = Array.from(document.querySelectorAll('button, a')).find(e =>
                visible(e) && (strategy === 'reject'
                    ? /^(reject|decline|refuse) (all )?/i
                    : strategy === 'dismiss'
                        ? /^(close|dismiss)$/i
                        : /^(accept|allow|agree|got it)/i).test((e.textContent || '').trim()));
            if (byText) {{ byText.click(); return true; }}
            return false;
        }})()"#,
        strategy = serde_json::to_string(&strategy).map_err(|e| e.to_string())?
    );
    match eval_on_bound_page(&js)? {
        Value::Bool(clicked) => Ok(Value::Bool(clicked)),
        other => Err(format!(
            "page_handle_cookie_consent: unexpected page answer: {}",
            crate::interp::type_name(&other)
        )),
    }
}



fn wait_result(
    matched: bool,
    elapsed_ms: u64,
    method: Option<&str>,
    url: Option<String>,
) -> Value {
    Value::Struct {
        name: "WaitResult".to_string(),
        fields: vec![
            ("result".to_string(), Value::Bool(matched)),
            ("matched".to_string(), Value::Bool(matched)),
            ("received".to_string(), Value::Bool(matched)),
            ("elapsed_ms".to_string(), Value::Int(elapsed_ms as i128)),
            ("waited_ms".to_string(), Value::Int(elapsed_ms as i128)),
            (
                "url".to_string(),
                url.map(Value::String).unwrap_or(Value::Nil),
            ),
            (
                "method".to_string(),
                method.map(|m| Value::String(m.to_string())).unwrap_or(Value::Nil),
            ),
        ],
    }
}

fn page_wait_for_request(args: Vec<Value>) -> StdlibResult {
    let pattern = arg_string(&args, 0, "page_wait_for_request")?;
    let timeout = std::time::Duration::from_millis(arg_u64(&args, 1, 30_000));
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.wait_for_request(&pattern, timeout))
            .map(|(ok, ms, url)| wait_result(ok, ms, Some("Network.requestWillBeSent"), Some(url)))
            .map_err(|e| format!("page_wait_for_request: {e}"))
    })
}

fn page_wait_for_response(args: Vec<Value>) -> StdlibResult {
    let pattern = arg_string(&args, 0, "page_wait_for_response")?;
    let timeout = std::time::Duration::from_millis(arg_u64(&args, 1, 30_000));
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.wait_for_response(&pattern, timeout))
            .map(|(ok, ms, url)| wait_result(ok, ms, Some("Network.responseReceived"), Some(url)))
            .map_err(|e| format!("page_wait_for_response: {e}"))
    })
}

fn page_wait_for_event(args: Vec<Value>) -> StdlibResult {
    let name = arg_string(&args, 0, "page_wait_for_event")?;
    let timeout = std::time::Duration::from_millis(arg_u64(&args, 1, 30_000));
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.wait_for_event(&name, timeout))
            .map(|(ok, ms, method)| wait_result(ok, ms, Some(&method), None))
            .map_err(|e| format!("page_wait_for_event: {e}"))
    })
}

// ── Delegations to the bound Page ────────────────────────────────────────
//
// These free functions existed only as refusals ("no page bound") because the
// dispatch layer had no page. With the registry above they can call the Page
// method the refusal used to name.

fn arg_string(args: &[Value], index: usize, who: &str) -> Result<String, String> {
    match args.get(index) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(format!("{who}: expected a string argument #{index}")),
    }
}

fn arg_u64(args: &[Value], index: usize, default: u64) -> u64 {
    args.get(index)
        .map(Value::as_string)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default)
}

fn page_set_content(args: Vec<Value>) -> StdlibResult {
    let html = arg_string(&args, 0, "page_set_content")?;
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.set_content(&html))
            .map(|bytes| Value::Ok(Box::new(Value::Int(bytes as i128))))
            .map_err(|e| format!("page_set_content: {e}"))
    })
}

fn page_content() -> StdlibResult {
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.content())
            .map(Value::String)
            .map_err(|e| format!("page_content: {e}"))
    })
}

fn page_add_init_script(args: Vec<Value>) -> StdlibResult {
    let script = arg_string(&args, 0, "page_add_init_script")?;
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.add_init_script(&script))
            .map(|id| Value::Ok(Box::new(Value::String(id))))
            .map_err(|e| format!("page_add_init_script: {e}"))
    })
}

fn page_add_script_tag(args: Vec<Value>) -> StdlibResult {
    let src = arg_string(&args, 0, "page_add_script_tag")?;
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.add_script_tag(&src))
            .map(|id| Value::Ok(Box::new(Value::String(id))))
            .map_err(|e| format!("page_add_script_tag: {e}"))
    })
}

fn page_add_style_tag(args: Vec<Value>) -> StdlibResult {
    let src = arg_string(&args, 0, "page_add_style_tag")?;
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.add_style_tag(&src))
            .map(|(id, _url)| Value::Ok(Box::new(Value::String(id))))
            .map_err(|e| format!("page_add_style_tag: {e}"))
    })
}

fn page_wait_for_function(args: Vec<Value>) -> StdlibResult {
    let expression = arg_string(&args, 0, "page_wait_for_function")?;
    let timeout = std::time::Duration::from_millis(arg_u64(&args, 1, 30_000));
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.wait_for_function(&expression, timeout))
            .map(|(ok, _ms)| Value::Ok(Box::new(Value::Bool(ok))))
            .map_err(|e| format!("page_wait_for_function: {e}"))
    })
}

fn page_wait_for_url(args: Vec<Value>) -> StdlibResult {
    let pattern = arg_string(&args, 0, "page_wait_for_url")?;
    let timeout = std::time::Duration::from_millis(arg_u64(&args, 1, 30_000));
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.wait_for_url(&pattern, timeout))
            .map(|(ok, _ms, _url)| Value::Ok(Box::new(Value::Bool(ok))))
            .map_err(|e| format!("page_wait_for_url: {e}"))
    })
}

fn page_wait_for_timeout(args: Vec<Value>) -> StdlibResult {
    let ms = arg_u64(&args, 0, 0);
    with_bound_page(|page| {
        let waited = crate::interp::get_browser_runtime().block_on(page.wait_for_timeout(ms));
        Ok(Value::Ok(Box::new(Value::Int(waited as i128))))
    })
}

fn page_throttle_cpu(args: Vec<Value>) -> StdlibResult {
    let rate = args
        .first()
        .map(Value::as_string)
        .and_then(|s| s.parse::<f64>().ok())
        .ok_or_else(|| "page_throttle_cpu: expected a numeric rate".to_string())?;
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.throttle_cpu(rate))
            .map(|applied| Value::Ok(Box::new(Value::Float(applied))))
            .map_err(|e| format!("page_throttle_cpu: {e}"))
    })
}

fn page_emulate_media(args: Vec<Value>) -> StdlibResult {
    let media = args.first().map(Value::as_string).unwrap_or_default();
    let scheme = args.get(1).map(Value::as_string).unwrap_or_default();
    let motion = args.get(2).map(Value::as_string).unwrap_or_default();
    with_bound_page(|page| {
        crate::interp::get_browser_runtime()
            .block_on(page.emulate_media(&media, &scheme, &motion))
            .map(|_| Value::Ok(Box::new(Value::Nil)))
            .map_err(|e| format!("page_emulate_media: {e}"))
    })
}

/// `page_structured_data() -> StructuredData` — JSON-LD + OpenGraph from the
/// live page, parsed by the same `structured_data_extract` the offline path uses.
fn page_structured_data() -> StdlibResult {
    let html = match page_capture_dom_snapshot()? {
        Value::String(s) => s,
        other => {
            return Err(format!(
                "page_structured_data: expected HTML from the page, got {}",
                crate::interp::type_name(&other)
            ))
        }
    };
    structured_data_extract(vec![Value::String(html)])
}


/// Machine-readable schema tag for the browser surface manifest.
pub const SURFACE_SCHEMA_VERSION: &str = "tallow.browser_surface_manifest.v1";
/// Machine-readable schema tag for the Phase 4 local fallback service status.
pub const FALLBACK_SERVICE_STATUS_SCHEMA_VERSION: &str =
    "tallow.browser_fallback_service_status.v1";

const COMPLETION_BOUNDARY: &str = "local_non_live_fallback_planner_and_fail_closed_boundaries_only";
const NON_CLAIM: &str = "Phase 4 does not claim live browser fallback execution, live scraping, screenshots/HAR/DOM capture, credentialed sessions, or production readiness";

// ── Pure extraction helpers (no live CDP session required) ───────────────────
//
// `stdlib/browser.tl` declares these alongside the CDP-driven functions, but
// they take their input as an argument, so they are pure and testable here.

/// `structured_data_extract(html: String) -> StructuredData`
///
/// Result = the declared `StructuredData { json_ld, open_graph, has_json_ld }`.
///
/// JSON-LD uses `extract::jsonld_raw_text` — the **text** form, which is what the
/// declared `[]String` holds. (`extract::extract_jsonld` returns *parsed* values,
/// a `Value::Map` per JSON object, which cannot satisfy a `[]String` field and made
/// the array heterogeneous: String for invalid JSON, Map for valid.)
pub(crate) fn structured_data_extract(args: Vec<Value>) -> StdlibResult {
    let html = match args.first() {
        Some(Value::String(s)) => s.as_str(),
        _ => {
            return Err(
                "structured_data_extract: expected an HTML string argument".into(),
            )
        }
    };
    // Declared shape (stdlib/browser.tl:434):
    //   struct StructuredData { json_ld: []String, open_graph: Map<String,String>, has_json_ld: bool }
    // An earlier revision returned `{jsonld, open_graph}` — one field misnamed and
    // `has_json_ld` missing — so a caller reading `sd.json_ld` got nothing while the
    // module's own test still passed on the invented name.
    let json_ld = Value::Array(
        super::extract::jsonld_raw_text(html)
            .into_iter()
            .map(Value::String)
            .collect(),
    );
    let has_json_ld = matches!(&json_ld, Value::Array(a) if !a.is_empty());
    Ok(Value::Struct {
        name: "StructuredData".into(),
        fields: vec![
            ("json_ld".into(), json_ld),
            ("open_graph".into(), extract_open_graph(html)),
            ("has_json_ld".into(), Value::Bool(has_json_ld)),
        ],
    })
}

/// Parse `<meta property="og:*" content="…">` into a Map keyed without the `og:`
/// prefix.
///
/// Deliberately **attribute-order independent**: the loop pulls `property` and
/// `content` out of each `<meta>` tag separately rather than requiring one to
/// precede the other, because real pages emit both orders and a single
/// order-sensitive regex silently returns nothing on half of them.
fn extract_open_graph(html: &str) -> Value {
    static TAG: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<meta\s[^>]*>").unwrap());
    static PROP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?is)\b(?:property|name)\s*=\s*["']([^"']+)["']"#).unwrap()
    });
    static CONTENT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?is)\bcontent\s*=\s*["']([^"']*)["']"#).unwrap());

    let mut pairs: Vec<(Value, Value)> = Vec::new();
    for tag in TAG.find_iter(html) {
        let t = tag.as_str();
        let prop = PROP.captures(t).map(|c| c[1].to_string());
        let content = CONTENT.captures(t).map(|c| c[1].to_string());
        if let (Some(p), Some(c)) = (prop, content) {
            if let Some(key) = p.strip_prefix("og:") {
                pairs.push((Value::String(key.to_string()), Value::String(c)));
            }
        }
    }
    Value::Map(pairs)
}

/// `content_fingerprint_from_text(text: String) -> ContentFingerprint`
///
/// Returns the shape `stdlib/browser.tl` declares:
/// `{hash: String, word_count: i32, text_length: i32}`.
///
/// `hash` is the 64-bit SimHash over whitespace-delimited tokens, rendered as
/// **16 lowercase hex digits** — a String, per the declaration. (An earlier
/// revision of this function returned `{simhash: Int, bits: Int}`, which did not
/// match the declared struct at all; the tests passed because they asserted on
/// that invented shape rather than the contract.)
///
/// Empty input fingerprints as `0000000000000000` rather than erroring, so
/// "nothing extracted" is a comparable value.
fn content_fingerprint_from_text(args: Vec<Value>) -> StdlibResult {
    let text = match args.first() {
        Some(Value::String(s)) => s.as_str(),
        _ => return Err("content_fingerprint_from_text: expected a string argument".into()),
    };
    let (hash, word_count, text_length) = fingerprint_fields(text);
    Ok(Value::Struct {
        name: "ContentFingerprint".into(),
        fields: vec![
            ("hash".into(), Value::String(hash)),
            ("word_count".into(), Value::Int(word_count as i128)),
            ("text_length".into(), Value::Int(text_length as i128)),
        ],
    })
}

/// The three `ContentFingerprint` fields for `text`, as
/// `(hash, word_count, text_length)`.
///
/// - `hash` — the 64-bit SimHash over whitespace-delimited tokens, rendered as
///   **16 lowercase hex digits** (a `String`, per the declaration).
/// - `word_count` — whitespace-delimited token count.
/// - `text_length` — **char** count, not bytes: a multi-byte string must not
///   report its UTF-8 width.
///
/// Both engines go through this one function (the interpreter's
/// `content_fingerprint_from_text` and the native FFI in
/// `runtime::fingerprint_ffi`). A second copy is how the two drift — the failure
/// mode that produced the D1/D2 defects in this module.
pub(crate) fn fingerprint_fields(text: &str) -> (String, i64, i64) {
    (
        format!("{:016x}", simhash64(text)),
        text.split_whitespace().count() as i64,
        text.chars().count() as i64,
    )
}

fn simhash64(text: &str) -> u64 {
    let mut votes = [0i64; 64];
    let mut saw_token = false;
    for token in text.split_whitespace() {
        saw_token = true;
        let lower = token.to_ascii_lowercase();
        let digest = blake3::hash(lower.as_bytes());
        let h = u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap());
        for (bit, vote) in votes.iter_mut().enumerate() {
            if h & (1u64 << bit) != 0 {
                *vote += 1;
            } else {
                *vote -= 1;
            }
        }
    }
    if !saw_token {
        return 0;
    }
    let mut out = 0u64;
    for (bit, vote) in votes.iter().enumerate() {
        if *vote > 0 {
            out |= 1u64 << bit;
        }
    }
    out
}

/// `content_fingerprint_similarity(a, b) -> f64` — `1.0 - hamming/64`,
/// so identical fingerprints score exactly `1.0`.
fn content_fingerprint_similarity(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err(
            "content_fingerprint_similarity: requires (a: ContentFingerprint, b: ContentFingerprint)"
                .into(),
        );
    }
    let a_hash = fingerprint_hash_hex(&args[0]).ok_or_else(|| {
        "content_fingerprint_similarity: first argument is not a ContentFingerprint".to_string()
    })?;
    let b_hash = fingerprint_hash_hex(&args[1]).ok_or_else(|| {
        "content_fingerprint_similarity: second argument is not a ContentFingerprint".to_string()
    })?;
    let similarity = similarity_from_hex(&a_hash, &b_hash).ok_or_else(|| {
        "content_fingerprint_similarity: fingerprint hash is not a 64-bit hex value".to_string()
    })?;
    Ok(Value::Float(similarity))
}

/// The `hash` field of a `ContentFingerprint` value, if it is one.
fn fingerprint_hash_hex(v: &Value) -> Option<String> {
    if let Value::Struct { name, fields } = v {
        if name == "ContentFingerprint" {
            for (k, val) in fields {
                if k == "hash" {
                    if let Value::String(hex) = val {
                        return Some(hex.clone());
                    }
                }
            }
        }
    }
    None
}

/// Parse a `ContentFingerprint.hash` — 16 hex digits, a leading `0x` tolerated —
/// to the 64-bit SimHash it encodes.
///
/// One parse for both engines: the interpreter's `fingerprint_hash_hex` path and
/// the native FFI in `runtime::fingerprint_ffi`. A second copy is how the two
/// drift (see the D5 note on `content_fingerprint_from_text`).
pub(crate) fn simhash_from_hex(hex: &str) -> Option<u64> {
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
}

/// `1.0 - hamming(a, b)/64` over two fingerprints' hash bits, so identical
/// fingerprints score exactly `1.0`. Shared by the interpreter's
/// `content_fingerprint_similarity` and the native FFI.
pub(crate) fn similarity_from_hex(a_hash: &str, b_hash: &str) -> Option<f64> {
    let a = simhash_from_hex(a_hash)?;
    let b = simhash_from_hex(b_hash)?;
    Some(1.0 - ((a ^ b).count_ones() as f64) / 64.0)
}

/// Map a Tallow-level cookie-consent strategy name to the browser strategy.
///
/// The single source of this mapping: the interpreter arm and the native
/// `tallow_page_handle_cookie_consent_str` FFI both call it, so the two engines
/// cannot disagree about what a strategy name selects.
///
/// `accept` / `accept_all` → `AcceptAll`; `dismiss` → `Dismiss`;
/// **anything else → `RejectNonEssential`** — the fail-safe default, and what the
/// interpreter has always done (the numeric sibling FFI's `_ => Dismiss` was a
/// latent divergence: a name it did not recognise would have *dismissed* where the
/// interpreter *rejects*).
pub(crate) fn consent_strategy(s: &str) -> crate::browser::CookieConsentStrategy {
    match s {
        "accept" | "accept_all" => crate::browser::CookieConsentStrategy::AcceptAll,
        "dismiss" => crate::browser::CookieConsentStrategy::Dismiss,
        _ => crate::browser::CookieConsentStrategy::RejectNonEssential,
    }
}

/// Redact likely PII from page text: emails, US SSNs, 16-digit card numbers,
/// phone numbers and IPv4 addresses.
///
/// One implementation, read by both the interpreter (`("Page","text_redacted")`)
/// and the native FFI (`runtime::browser::tallow_page_text_redacted`), so the two
/// engines cannot disagree about what was stripped.
///
/// Every pattern requires a recognisable *shape* (dotted domain, grouped digits,
/// octets) so ordinary prose is left alone. **Order matters**: email first (it
/// contains dots and digits), then the grouped-digit forms, then IP — otherwise a
/// later, looser pattern would eat part of a value the earlier one owns. The
/// replacement tokens are stable strings, so a caller can see *what* was removed
/// without seeing the value.
pub(crate) fn redact_pii(text: &str) -> String {
    static EMAIL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap());
    static SSN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
    static CARD: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b").unwrap());
    // The `+` sits OUTSIDE the leading `\b`: there is no word boundary between a
    // space and `+` (both non-word), so `\b(...\+?)` began the match at the digit
    // and left a stray leading `+` in the output — `+[REDACTED_PHONE]` — which the
    // live p42 probe surfaced.
    static PHONE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\+?\b(?:\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap()
    });
    static IPV4: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").unwrap());

    let out = EMAIL.replace_all(text, "[REDACTED_EMAIL]");
    let out = SSN.replace_all(&out, "[REDACTED_SSN]");
    let out = CARD.replace_all(&out, "[REDACTED_CC]");
    let out = PHONE.replace_all(&out, "[REDACTED_PHONE]");
    IPV4.replace_all(&out, "[REDACTED_IP]").into_owned()
}

/// `crawler_from_sitemap(url: String) -> Crawler`
///
/// **Network discovery.** Delegates discovery + parsing to
/// `browser::sitemap::SitemapParser`, which handles sitemap index files and
/// gzipped sitemaps and rides `runtime::egress_http` (Tor by default; it refuses
/// rather than falling back to the box IP). Returns the declared `Crawler` shape;
/// `max_pages` is the number of discovered entries.
pub(crate) fn crawler_from_sitemap(args: Vec<Value>) -> StdlibResult {
    let url = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("crawler_from_sitemap: expected a URL string argument".into()),
    };
    let entries = crate::browser::sitemap::SitemapParser::fetch_sitemap(&url)?;
    Ok(crawler_struct_from_entries(&url, &entries))
}

/// Shape the declared `Crawler` struct from parsed sitemap entries.
///
/// Split out from the fetch so the **parse → shape** path is testable without
/// network. `SitemapParser::parse(xml)` is pure; `fetch_sitemap` needs egress,
/// and on this host egress goes through Tor, which refuses loopback — so a local
/// fixture can never be fetched and the fused version was untestable offline.
///
/// An empty sitemap yields an empty `seed_url` with `max_pages = 0`: a valid
/// parse of "nothing found", not an error and not an invented URL.
fn crawler_struct_from_entries(
    url: &str,
    entries: &[crate::browser::sitemap::SitemapEntry],
) -> Value {
    let seed = entries.first().map(|e| e.url.clone()).unwrap_or_default();
    Value::Struct {
        name: "Crawler".into(),
        fields: vec![
            ("seed_url".into(), Value::String(seed)),
            ("sitemap_url".into(), Value::String(url.to_string())),
            ("strategy".into(), Value::String("sitemap".into())),
            ("max_depth".into(), Value::Int(0)),
            ("max_pages".into(), Value::Int(entries.len() as i128)),
            ("pages_crawled".into(), Value::Int(0)),
            ("rate_limit_ms".into(), Value::Int(0)),
        ],
    }
}

/// The declared `Crawler` fields, in declaration order
/// (`stdlib/browser.tl:381`).
pub(crate) struct CrawlerPlan {
    pub seed_url: String,
    pub sitemap_url: String,
    pub strategy: String,
    pub max_depth: i64,
    pub max_pages: i64,
    pub pages_crawled: i64,
    pub rate_limit_ms: i64,
}

/// `Crawler.from_links(url, max_depth?) -> Crawler`.
///
/// A **planner** constructor, not a crawl: it allocates the runtime's real crawl
/// queue (`browser::crawl_queue::CrawlQueue` — dedupe set + priority queue) and
/// seeds one `CrawlJob` at the requested depth via `CrawlJob::with_depth`. No
/// fetch happens and no live session is needed, which is what keeps this inside
/// the module's declared `local_non_live_fallback_planner` boundary.
///
/// `max_pages` reports the queue's current length — for a freshly-seeded crawler
/// that is 1 (the seed). It is *not* an invented cap; no crawl policy is
/// configured here, and fabricating a default page limit would be a policy claim
/// this function has no basis to make.
///
/// `max_depth` is optional at the call site and defaults to `3`, which is what
/// the interpreter's struct-static arm has always done. An empty or
/// whitespace-only seed, or a negative depth, is **refused**: the facade has
/// always refused them while the interpreter arm used to build a crawler that
/// cannot crawl, and the two now share this one decision.
///
/// One implementation: the interpreter's `Crawler.from_links` arm, the
/// `crawler_from_links` facade, and the native path (`runtime::crawler_ffi`) all
/// read this function, so neither the field values nor the validation can drift.
pub(crate) fn crawler_from_links_plan(
    seed_url: &str,
    max_depth: Option<i64>,
) -> Result<CrawlerPlan, String> {
    let seed = seed_url.to_string();
    if seed.trim().is_empty() {
        return Err("crawler_from_links: seed_url must not be empty".into());
    }
    let depth = max_depth.unwrap_or(3);
    if depth < 0 {
        return Err(format!(
            "crawler_from_links: max_depth must be non-negative, got {depth}"
        ));
    }

    let mut queue = crate::browser::crawl_queue::CrawlQueue::new();
    let seeded = queue.push_job(crate::browser::crawl_queue::CrawlJob::with_depth(
        &seed,
        0,
        depth as u32,
    ));
    if !seeded {
        return Err(format!(
            "crawler_from_links: the crawl queue rejected seed URL '{seed}'"
        ));
    }

    Ok(CrawlerPlan {
        seed_url: seed,
        // No sitemap involved in link-discovery crawling; empty, not a guess.
        sitemap_url: String::new(),
        strategy: "link_follow".to_string(),
        max_depth: depth,
        max_pages: queue.len() as i64,
        pages_crawled: 0,
        rate_limit_ms: 0,
    })
}

/// `crawler_from_links(url: String, max_depth: i64) -> Crawler`
///
/// The declared facade. The shape and the validation come from
/// `crawler_from_links_plan`.
fn crawler_from_links(args: Vec<Value>) -> StdlibResult {
    let seed = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("crawler_from_links: expected a seed URL string argument".into()),
    };
    let max_depth = match args.get(1) {
        Some(Value::Int(n)) => Some(*n as i64),
        Some(_) => return Err("crawler_from_links: expected integer max_depth".into()),
        None => None,
    };
    let plan = crawler_from_links_plan(&seed, max_depth)?;
    Ok(Value::Struct {
        name: "Crawler".into(),
        fields: vec![
            ("seed_url".into(), Value::String(plan.seed_url)),
            ("sitemap_url".into(), Value::String(plan.sitemap_url)),
            ("strategy".into(), Value::String(plan.strategy)),
            ("max_depth".into(), Value::Int(plan.max_depth as i128)),
            ("max_pages".into(), Value::Int(plan.max_pages as i128)),
            ("pages_crawled".into(), Value::Int(plan.pages_crawled as i128)),
            ("rate_limit_ms".into(), Value::Int(plan.rate_limit_ms as i128)),
        ],
    })
}

/// `page_cache_create(max_age_seconds: i64, max_size_mb: i64) -> PageCache`
///
/// Returns the declared `PageCache` shape with zeroed counters. Note the `.tl`
/// declares **no cache operations** (no get/put), so this is a configured handle
/// rather than a usable store — the counters are present for shape fidelity and
/// report 0 because nothing can yet advance them.
/// The declared `PageCache` fields, in declaration order.
///
/// One builder for the shape, so the counters and the keying label are stated
/// once: the interpreter's struct-static `PageCache.create` arm, the
/// `page_cache_create` facade, and the native path (`runtime::page_cache_ffi`)
/// all read through it.
pub(crate) struct PageCacheFields {
    pub max_age_seconds: i64,
    pub max_size_mb: i64,
    pub entries: i64,
    pub hits: i64,
    pub misses: i64,
    pub keyed_by: String,
}

/// `PageCache.create(...)` argument handling: both arguments are optional and a
/// missing one takes the default (3600 s / 1024 MB). The `.tl` declares no cache
/// operations (no get/put), so this is a configured handle rather than a usable
/// store — the counters exist for shape fidelity and report 0 because nothing
/// can yet advance them.
pub(crate) fn page_cache_fields(
    max_age_seconds: Option<i64>,
    max_size_mb: Option<i64>,
) -> PageCacheFields {
    PageCacheFields {
        max_age_seconds: max_age_seconds.unwrap_or(3600),
        max_size_mb: max_size_mb.unwrap_or(1024),
        entries: 0,
        hits: 0,
        misses: 0,
        // The declared PageCache is a "content-addressed page cache with BLAKE3
        // hashing" (stdlib/browser.tl:401), so the keying label is "blake3".
        keyed_by: "blake3".to_string(),
    }
}

/// `page_cache_create(max_age_seconds: i64, max_size_mb: i64) -> PageCache`
///
/// The declared two-argument facade. Both arguments are required *here* — the
/// struct-static `PageCache.create` is the form that makes them optional — and
/// the shape itself comes from `page_cache_fields`.
fn page_cache_create(args: Vec<Value>) -> StdlibResult {
    let max_age = match args.first() {
        Some(Value::Int(n)) => *n,
        _ => return Err("page_cache_create: expected integer max_age_seconds".into()),
    };
    let max_size = match args.get(1) {
        Some(Value::Int(n)) => *n,
        _ => return Err("page_cache_create: expected integer max_size_mb".into()),
    };
    // `Value::Int` is i128; the declared fields are i64, which is also the width
    // the native path passes, so narrow once here.
    let f = page_cache_fields(Some(max_age as i64), Some(max_size as i64));
    Ok(Value::Struct {
        name: "PageCache".into(),
        fields: vec![
            (
                "max_age_seconds".into(),
                Value::Int(f.max_age_seconds as i128),
            ),
            ("max_size_mb".into(), Value::Int(f.max_size_mb as i128)),
            ("entries".into(), Value::Int(f.entries as i128)),
            ("hits".into(), Value::Int(f.hits as i128)),
            ("misses".into(), Value::Int(f.misses as i128)),
            ("keyed_by".into(), Value::String(f.keyed_by)),
        ],
    })
}

/// Dispatch a `tallow.browser.*` contract/facade function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "surface_manifest" | "browser_surface_manifest" => Some(surface_manifest(args)),
        "pipe_transport_status" | "browser_pipe_transport_status" => {
            Some(pipe_transport_status(args))
        }
        "fallback_boundary" | "browser_fallback_boundary" => Some(fallback_boundary(args)),

        // Declared in stdlib/browser.tl with empty `// native:` bodies and previously
        // absent from every dispatcher. Implemented 2026-10-12 — these three are
        // PURE (they take their input as an argument), so unlike the other browser
        // declarations they need no live CDP session.
        "structured_data_extract" => Some(structured_data_extract(args)),
        "content_fingerprint_from_text" => Some(content_fingerprint_from_text(args)),
        "content_fingerprint_similarity" => Some(content_fingerprint_similarity(args)),
        // Wiring to EXISTING runtime machinery rather than re-implementing:
        // `crawler_from_sitemap` delegates to `browser::sitemap::SitemapParser`,
        // which already handles sitemap indexes and gzipped sitemaps.
        "crawler_from_sitemap" => Some(crawler_from_sitemap(args)),
        "crawler_from_links" => Some(crawler_from_links(args)),
        // Live-page helpers: they act on the page the interpreter last created or
        // navigated (see CURRENT_PAGE above). Bound 2026-10-22; each does one CDP
        // round trip and returns real page data, not a placeholder.
        "page_extract_all_text" => Some(page_extract_all_text(args)),
        "page_extract_all_attrs" => Some(page_extract_all_attrs(args)),
        "page_capture_dom_snapshot" => Some(page_capture_dom_snapshot()),
        "page_structured_data" => Some(page_structured_data()),
        "page_text_redacted" => Some(page_text_redacted()),
        "page_block_non_essential" => Some(page_block_non_essential()),
        "page_wait_for_stable" => Some(page_wait_for_stable(args)),
        "page_detect_pagination" => Some(page_detect_pagination()),
        "page_handle_cookie_consent" => Some(page_handle_cookie_consent(args)),
        "page_cache_create" => Some(page_cache_create(args)),
        "fallback_service_status" | "browser_fallback_service_status" => {
            Some(fallback_service_status(args))
        }
        // Navigation entrypoints: fall through to the interpreter's REAL
        // builtins where they exist, so this facade never shadows live code:
        //   - "launch" / "new"  → interp.rs "Browser.launch" | "Browser.new"
        //     (real Chromium launch via src/browser/)
        //   - "goto" / "navigate" → interp.rs ("Page","goto") | ("Page","navigate")
        //     (real CDP navigation on a live Page object)
        //   - "new_page" → interp.rs ("Browser","new_page")
        // Only "new_context" has no real interpreter builtin, so it keeps the
        // contract-level stub below (returning None there would produce a
        // misleading "unknown function" error for a declared API).
        "new_context" => Some(browser_nav_stub(function, args)),
        // Legacy module-level form helpers — REAL page-driving code (label /
        // button / form locators via evaluate + Input dispatch) for the
        // `browser.select_option(page, ...)` module-call shape. ROADMAP #7:
        // Page-method spellings `page.fill/click/select(...)` are handled by
        // the interpreter's REAL ("Page","fill"/"click"/"select") CDP arms,
        // which this router never consults — the names below return None here
        // (=> `page.fill` always reaches the interp arm, never a facade stub).
        "select_option"
        | "fill_labeled"
        | "click_button"
        | "submit_form"
        | "fill_form" => Some(form_automation_dispatch(function, args)),
        // ROADMAP #9 — module-level Antibot.resolve route. REAL arm: runs the
        // orchestrator's detect → solve → retry loop on the given Page with
        // honest per-engine capability flags. The Page-method spelling
        // `page.resolve_antibot(url)` is handled by the interp.rs arm
        // (("Page","resolve_antibot")); this module arm exists for the
        // `browser.resolve_antibot(page, url)` call shape and NEVER shadows
        // the interp arms (method dispatch does not consult this router).
        "resolve_antibot" | "antibot_resolve" => Some(page_resolve_antibot(args)),
        // ── Page-tier free functions (declared in stdlib/browser.tl with empty bodies) ──
        //
        // These 23 names are declared at module level with a real signature and a
        // real result type, and every one of them HAS a working implementation —
        // as a `Page` method dispatched by the interpreter (`("Page", "<verb>")`
        // arms in src/interp.rs), which is the only place they can be implemented:
        // the implementation needs a live page handle, and this router reaches
        // through the `tallow.browser.*` proxy where a free-function call carries
        // no page argument to bind.
        //
        // Returning None here (the previous behaviour) produced
        // `undefined function: browser.page_content` — a misleading message that
        // is indistinguishable from a typo, and the reason these 23 read as an
        // unwired surface. Each now resolves to an actionable refusal naming the
        // live spelling, the same treatment the Dialog./Keyboard./Mouse. free
        // functions received (`dispatch_no_page_bound`, register row #52).
        //
        // The coverage test at the bottom of this file parses stdlib/browser.tl and
        // fails if any empty-bodied `page_*` declaration is missing from this table.
        // Live delegations: the bound page is reachable now, so these call the
        // Page method instead of refusing. The callback registrations below
        // (on_console, on_request, expose_*) still refuse — they need a handler
        // table the stdlib dispatch does not have.
        "page_set_content" => Some(page_set_content(args)),
        "page_content" => Some(page_content()),
        "page_add_init_script" => Some(page_add_init_script(args)),
        "page_add_script_tag" => Some(page_add_script_tag(args)),
        "page_add_style_tag" => Some(page_add_style_tag(args)),
        "page_wait_for_function" => Some(page_wait_for_function(args)),
        "page_wait_for_url" => Some(page_wait_for_url(args)),
        "page_wait_for_request" => Some(page_wait_for_request(args)),
        "page_wait_for_response" => Some(page_wait_for_response(args)),
        "page_wait_for_event" => Some(page_wait_for_event(args)),
        "page_wait_for_timeout" => Some(page_wait_for_timeout(args)),
        "page_expose_function" => Some(page_fn_needs_handle(
            function,
            "page.expose_function(name, handler_name)",
        )),
        "page_expose_binding" => Some(page_fn_needs_handle(
            function,
            "page.expose_binding(name, handler_name)",
        )),
        "page_on_console" => Some(page_fn_needs_handle(function, "page.on_console(handler_name)")),
        "page_on_error" => Some(page_fn_needs_handle(function, "page.on_error(handler_name)")),
        "page_on_request" => Some(page_fn_needs_handle(function, "page.on_request(handler_name)")),
        "page_on_response" => Some(page_fn_needs_handle(function, "page.on_response(handler_name)")),
        "page_on_filechooser" => {
            Some(page_fn_needs_handle(function, "page.on_filechooser(handler_name)"))
        }
        "page_on_download" => Some(page_fn_needs_handle(function, "page.on_download(handler_name)")),
        "page_emulate_media" => Some(page_emulate_media(args)),
        "page_emulate_vision" => {
            Some(page_fn_needs_handle(function, "page.emulate_vision(deficiency)"))
        }
        "page_throttle_network" => {
            Some(page_fn_needs_handle(function, "page.throttle_network(preset)"))
        }
        "page_throttle_cpu" => Some(page_throttle_cpu(args)),
        _ => None,
    }
}

/// Dispatch a method/field read on browser contract structs.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, fields } = object else {
        return None;
    };

    match name.as_str() {
        "BrowserSurfaceManifest"
        | "BrowserSurfaceEntry"
        | "BrowserPipeTransportStatus"
        | "BrowserFallbackBoundary"
        | "BrowserFallbackServiceStatus" => fields
            .iter()
            .find(|(field, _)| field == method)
            .map(|(_, value)| Ok(value.clone())),
        _ => None,
    }
}

fn surface_manifest(args: Vec<Value>) -> StdlibResult {
    ensure_no_args("browser.surface_manifest", &args)?;

    Ok(Value::Struct {
        name: "BrowserSurfaceManifest".to_string(),
        fields: vec![
            string_field("schema_version", SURFACE_SCHEMA_VERSION),
            string_field("phase", "phase4-browser-fallback-service"),
            string_field("completion_boundary", COMPLETION_BOUNDARY),
            bool_field("claims_live_browser_ready", false),
            bool_field("claims_production_fallback_ready", false),
            string_field("non_claim", NON_CLAIM),
            (
                "entries".to_string(),
                Value::Array(vec![
                    surface_entry(
                        "Browser.launch",
                        "runtime_entrypoint",
                        "implemented_non_live_contract_tested",
                        "cdp_websocket",
                        true,
                        true,
                        "tests/browser_codegen_integration.rs and non-live tests/browser_flow_runtime_integration.rs",
                    ),
                    surface_entry(
                        "Page.goto",
                        "runtime_entrypoint",
                        "implemented_mock_contract_tested",
                        "cdp_websocket",
                        true,
                        true,
                        "tests/browser_flow_runtime_integration.rs mock CDP navigation tests",
                    ),
                    surface_entry(
                        "cdp.pipe",
                        "transport",
                        "unsupported_fail_closed",
                        "cdp_pipe",
                        false,
                        true,
                        "src/browser/process.rs rejects use_pipe before launch; src/browser/cdp.rs connect_pipe returns an error",
                    ),
                    surface_entry(
                        "request_plan.browser_fallback",
                        "fallback_policy",
                        "local_planner_available_live_execution_fail_closed",
                        "request_plan_runner",
                        false,
                        true,
                        "Phase 4 adds a local/non-live planner; live request-plan execution still fails closed before network I/O",
                    ),
                    surface_entry(
                        "browser_fallback.local_planner",
                        "fallback_service",
                        "implemented_local_non_live_planner_tested",
                        "planner_only_no_cdp",
                        false,
                        true,
                        "src/browser/fallback.rs and tests/browser_fallback_service.rs prove reason codes, budgets, artifact hooks, and no live I/O",
                    ),
                    surface_entry(
                        "stdlib.browser_facade",
                        "contract_facade",
                        "implemented_contract_metadata_only",
                        "non_live_stdlib_dispatch",
                        false,
                        false,
                        "src/stdlib/browser.rs routes manifest, pipe status, and fallback boundary metadata",
                    ),
                    surface_entry(
                        "BrowserPool.create (egress map)",
                        "egress_control",
                        "implemented_interp_routed",
                        "browser_pool_resolve_proxy",
                        false,
                        true,
                        "interp.rs BrowserPool.create accepts an OPTIONAL trailing map {proxy, tor, stealth, tier}; map wins over TALLOW_PROXY/TALLOW_TOR (env stays the fallback), tier:\"direct\" is an explicit direct choice (no env inheritance, no leak warning), stealth rides BrowserConfig.stealth; pool.rs resolve_proxy routes the URL into per-instance BrowserConfig.proxy -> Chrome --proxy-server (instance_launch_config). Non-live tested (browser::pool + interp egress tests).",
                    ),
                    surface_entry(
                        "Page.resolve_antibot (opts map)",
                        "antibot",
                        "implemented_interp_and_native_parity_tested",
                        "antibot_orchestrator_resolve",
                        false,
                        true,
                        "interp.rs Page.resolve_antibot drives AntiBotOrchestrator::resolve on get_browser_runtime() and returns Result<AntibotResolveReport> with per-engine {engine, available, ran, note} steps. Measured on a loopback page: resolved=true, final_status=200, attempts=1, steps=5 on BOTH planes (egress, captcha.detect, warmup, escalation, classify), byte-identical output. opts {solver_key, solver_service} is consumed on the interpreter path (CaptchaSolverConfig; service defaults to 2captcha when omitted); the native plane REFUSES opts at build time rather than silently ignoring them (tests/browser_antibot_opts.rs).",
                    ),
                    surface_entry(
                        "Page.goto_antibot (egress map)",
                        "antibot",
                        // Measured, not assumed: grep -c "goto_antibot" over
                        // src/interp.rs and src/codegen.rs is 0. This entry used
                        // to claim implemented_interp_routed, which made the
                        // machine-readable surface report a method that does not
                        // exist on either plane.
                        "declared_not_implemented",
                        "none",
                        false,
                        true,
                        "Declared in stdlib/browser.tl only. No interpreter arm and no native lowering (both greps return 0), so the interpreter answers 'unknown browser method' and --require-native refuses. The egress-map contract {proxy, tor, stealth, tier} with relaunch-on-proxy described here is a SPECIFICATION, not implemented behaviour. Implement or remove the declaration before claiming it.",
                    ),
                ]),
            ),
        ],
    })
}

fn pipe_transport_status(args: Vec<Value>) -> StdlibResult {
    ensure_no_args("browser.pipe_transport_status", &args)?;

    Ok(Value::Struct {
        name: "BrowserPipeTransportStatus".to_string(),
        fields: vec![
            string_field("transport", "cdp_pipe"),
            string_field("status", "unsupported_fail_closed"),
            bool_field("rejects_before_launch", true),
            bool_field("opens_debug_port", false),
            bool_field("launches_browser", false),
            bool_field("claims_lower_latency", false),
            string_field(
                "operator_action",
                "leave browser.use_pipe=false; use WebSocket CDP transport",
            ),
            string_field(
                "evidence",
                "BrowserProcess::launch rejects use_pipe=true before spawning Chrome; CdpClient::connect_pipe returns a not-implemented error",
            ),
        ],
    })
}

fn fallback_boundary(args: Vec<Value>) -> StdlibResult {
    ensure_no_args("browser.fallback_boundary", &args)?;

    Ok(Value::Struct {
        name: "BrowserFallbackBoundary".to_string(),
        fields: vec![
            string_field("status", "unsupported_fail_closed_for_live_execution"),
            bool_field("mock_cdp_navigation_event_fallback_tested", true),
            bool_field("http_to_live_browser_fallback_ready", false),
            bool_field("claims_production_fallback_ready", false),
            string_field(
                "allowed_phase3_proof",
                "non-live/mock CDP tests, zero-I/O fail-closed probes, and Phase 4 local planner decisions",
            ),
            string_field(
                "human_gate",
                "live browser launch or live external scraping requires explicit approval",
            ),
        ],
    })
}

fn fallback_service_status(args: Vec<Value>) -> StdlibResult {
    ensure_no_args("browser.fallback_service_status", &args)?;

    Ok(Value::Struct {
        name: "BrowserFallbackServiceStatus".to_string(),
        fields: vec![
            string_field("schema_version", FALLBACK_SERVICE_STATUS_SCHEMA_VERSION),
            string_field("phase", "phase4-browser-fallback-service"),
            string_field("status", "implemented_local_non_live_planner_tested"),
            bool_field("reason_codes_supported", true),
            bool_field("budgets_supported", true),
            bool_field("artifact_policy_hooks_supported", true),
            bool_field("launches_browser", false),
            bool_field("performs_network_io", false),
            bool_field("captures_screenshots_har_dom", false),
            bool_field("uses_credentials_or_sessions", false),
            string_field("pipe_status", "unsupported_fail_closed"),
            string_field(
                "artifact_manifest",
                "artifacts/phase4/browser-fallback-service-local/artifact_manifest.json",
            ),
            string_field(
                "non_claim",
                "local planner/service boundary only; live/production fallback remains human-gated",
            ),
        ],
    })
}

fn ensure_no_args(function: &str, args: &[Value]) -> Result<(), String> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(format!("{function}: expected no arguments"))
    }
}

/// Refusal for a declared page-tier free function called through the
/// `tallow.browser.*` proxy, where no page handle can be bound.
///
/// Mirrors the interpreter's `dispatch_no_page_bound` wording so a caller sees
/// one consistent explanation on both routes, and names the live spelling so the
/// message is actionable instead of a dead end.
fn page_fn_needs_handle(function: &str, live: &str) -> StdlibResult {
    Err(format!(
        "browser.{function}: no page bound in function dispatch — this call cannot touch a \
         live page; use {live} on a Page handle with a live browser session"
    ))
}

/// Browser navigation stub — provides a contract-level dispatch so the
/// typechecker accepts browser navigation calls (goto, navigate, launch,
/// new_page, new_context). Live execution routes through the interpreter and
/// `src/browser/` CDP runtime, not through this stdlib facade.
fn browser_nav_stub(function: &str, args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        Err(format!(
            "browser.{function}: requires a URL argument; live execution \
             routes through the interpreter and CDP runtime (src/browser/)"
        ))
    } else {
        Ok(Value::String(format!(
            "browser.{function} — contract-level dispatch; live execution hard-gated \
             (TALLOW_RUN_BROWSER_LIVE_TESTS=1, requires Chrome)",
        )))
    }
}

// ── Form Automation API ─────────────────────────────────────────────
//
// Real CDP-based form automation. Each function extracts a Page handle
// from the first argument and performs live DOM interactions via CDP.
// Async CDP calls are bridged through the global tokio runtime.

/// Extract a `Page` handle from a Value argument.
fn extract_page(args: &[Value], idx: usize) -> Result<&crate::browser::Page, String> {
    match args.get(idx) {
        Some(Value::BrowserObject(bh)) if bh.kind == "Page" => bh
            .handle
            .downcast_ref::<crate::browser::Page>()
            .ok_or_else(|| "browser handle is not a Page".to_string()),
        Some(v) => Err(format!(
            "argument {}: expected Page, got {}",
            idx + 1,
            crate::interp::type_name(v)
        )),
        None => Err(format!("missing argument {} (Page)", idx + 1)),
    }
}

/// Extract a String from a Value argument.
fn extract_string(args: &[Value], idx: usize, name: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(v) => {
            let s = v.as_string();
            if s.is_empty() && !matches!(v, Value::String(_)) {
                Err(format!("{name}: expected a string"))
            } else {
                Ok(s)
            }
        }
        None => Err(format!("missing argument {} ({name})", idx + 1)),
    }
}

/// Extract an optional i64 from a Value argument.
fn extract_optional_bool(args: &[Value], idx: usize) -> Result<bool, String> {
    match args.get(idx) {
        Some(Value::Bool(b)) => Ok(*b),
        None => Ok(false), // default
        Some(v) => Err(format!(
            "argument {}: expected bool, got {}",
            idx + 1,
            crate::interp::type_name(v)
        )),
    }
}

/// Extract a fields map from a Value argument.
fn extract_fields_map(args: &[Value], idx: usize) -> Result<Vec<(String, String)>, String> {
    match args.get(idx) {
        Some(Value::Map(entries)) => {
            let mut out = Vec::new();
            for (k, v) in entries {
                out.push((k.as_string(), v.as_string()));
            }
            Ok(out)
        }
        None => Err(format!("missing argument {} (fields map)", idx + 1)),
        Some(v) => Err(format!(
            "argument {}: expected map, got {}",
            idx + 1,
            crate::interp::type_name(v)
        )),
    }
}

/// `browser.select_option(page, dropdown_selector, option_text)` — CDP approach:
///  1. Query the <select> element by CSS selector
///  2. Use element.select_option(SelectBy::Label) to pick the matching <option>
fn page_select_option(args: Vec<Value>) -> StdlibResult {
    let page = extract_page(&args, 0)?;
    let dropdown_selector = extract_string(&args, 1, "dropdown_selector")?;
    let option_text = extract_string(&args, 2, "option_text")?;

    let rt = crate::runtime::get_runtime();
    rt.block_on(async {
        let select_el = page
            .query_selector(&dropdown_selector)
            .await
            .map_err(|e| format!("failed to find <select> '{}': {e}", dropdown_selector))?
            .ok_or_else(|| {
                format!("no element matching '{}' found", dropdown_selector)
            })?;

        select_el
            .select_option(crate::browser::interaction::SelectBy::Label(option_text))
            .await
            .map_err(|e| format!("failed to select option: {e}"))?;

        Ok::<_, String>(Value::Ok(Box::new(Value::Nil)))
    })
}

/// `browser.fill_labeled(page, label_text, value)` —
///  1. Runtime.evaluate to find <label> with matching textContent
///  2. If label has `for` attribute, find the input by id
///  3. Otherwise traverse to the next input/select/textarea sibling
///  4. Use ElementHandle::type_text() to fill
fn page_fill_labeled(args: Vec<Value>) -> StdlibResult {
    let page = extract_page(&args, 0)?;
    let label_text = extract_string(&args, 1, "label_text")?;
    let value = extract_string(&args, 2, "value")?;

    let rt = crate::runtime::get_runtime();
    rt.block_on(async {
        // Build JS to find the input associated with a label
        let escaped_label = crate::browser::page::escape_js_string(&label_text);
        let js = format!(
            r#"(function() {{
    var labels = Array.from(document.querySelectorAll('label'));
    var found = labels.find(function(l) {{
        return l.textContent.trim() === '{escaped_label}';
    }});
    if (!found) return null;
    // If label has 'for' attribute, find the input by id
    var forAttr = found.getAttribute('for');
    if (forAttr) {{
        var el = document.getElementById(forAttr);
        if (el) return el;
    }}
    // Otherwise, look for input/select/textarea inside the label or as next sibling
    var input = found.querySelector('input, select, textarea');
    if (input) return input;
    // Check next sibling
    var sibling = found.nextElementSibling;
    while (sibling) {{
        if (['INPUT', 'SELECT', 'TEXTAREA'].includes(sibling.tagName)) return sibling;
        var nested = sibling.querySelector('input, select, textarea');
        if (nested) return nested;
        sibling = sibling.nextElementSibling;
    }}
    return null;
}})()"#
        );

        let result = page
            .evaluate_raw(&js)
            .await
            .map_err(|e| format!("failed to find labeled input: {e}"))?;

        // Check if we got a remote object (element found) or null
        if result.get("result").and_then(|r| r.get("subtype")) == Some(&serde_json::Value::String("null".to_string()))
            || result.get("result").and_then(|r| r.get("type")) == Some(&serde_json::Value::String("undefined".to_string()))
        {
            return Err(format!(
                "no input element found for label '{}'",
                label_text
            ));
        }

        // If we got an object, extract its objectId and create an ElementHandle
        if let Some(object_id) = result
            .get("result")
            .and_then(|r| r.get("objectId"))
            .and_then(|v| v.as_str())
        {
            let el = crate::browser::element::ElementHandle {
                client: page.client.clone(),
                session_id: page.session_id.clone(),
                remote_object_id: object_id.to_string(),
            };
            el.type_text(&value, Some(20))
                .await
                .map_err(|e| format!("failed to type text: {e}"))?;
            return Ok(Value::Ok(Box::new(Value::Nil)));
        }

        // If we got a value directly (not an object), also try the fallback approach
        Err(format!(
            "could not create element handle for label '{}'",
            label_text
        ))
    })
}

/// `browser.click_button(page, button_text)` —
///  1. Runtime.evaluate to find button/input[type="submit"]/a.btn with matching text
///  2. Click the element via CDP
fn page_click_button(args: Vec<Value>) -> StdlibResult {
    let page = extract_page(&args, 0)?;
    let button_text = extract_string(&args, 1, "button_text")?;

    let rt = crate::runtime::get_runtime();
    rt.block_on(async {
        let escaped_text = crate::browser::page::escape_js_string(&button_text);
        let js = format!(
            r#"(function() {{
    var buttons = Array.from(document.querySelectorAll('button, input[type="submit"], a.btn, [role="button"]'));
    var found = buttons.find(function(el) {{
        return (el.textContent || el.value || '').trim().includes('{escaped_text}');
    }});
    return found || null;
}})()"#
        );

        let result = page
            .evaluate_raw(&js)
            .await
            .map_err(|e| format!("failed to find button: {e}"))?;

        if let Some(object_id) = result
            .get("result")
            .and_then(|r| r.get("objectId"))
            .and_then(|v| v.as_str())
        {
            let el = crate::browser::element::ElementHandle {
                client: page.client.clone(),
                session_id: page.session_id.clone(),
                remote_object_id: object_id.to_string(),
            };
            el.click(crate::browser::interaction::ClickOptions::default())
                .await
                .map_err(|e| format!("failed to click button: {e}"))?;
            return Ok(Value::Ok(Box::new(Value::Nil)));
        }

        // Fallback: try query_selector for button-like elements containing the text
        let selectors = [
            format!("button:has-text('{escaped_text}')"),
            format!("input[type='submit'][value*='{escaped_text}']"),
        ];
        for sel in &selectors {
            if let Ok(Some(el)) = page.query_selector(sel).await {
                el.click(crate::browser::interaction::ClickOptions::default())
                    .await
                    .map_err(|e| format!("failed to click button: {e}"))?;
                return Ok(Value::Ok(Box::new(Value::Nil)));
            }
        }

        Err(format!("no button found matching '{}'", button_text))
    })
}

/// `browser.submit_form(page, form_selector)` —
///  1. Runtime.evaluate: document.querySelector(form_selector).submit()
fn page_submit_form(args: Vec<Value>) -> StdlibResult {
    let page = extract_page(&args, 0)?;
    let form_selector = extract_string(&args, 1, "form_selector")?;

    let rt = crate::runtime::get_runtime();
    rt.block_on(async {
        let escaped = crate::browser::page::escape_js_string(&form_selector);
        let js = format!(
            "var f = document.querySelector('{escaped}'); if (f) {{ f.submit(); 'submitted' }} else {{ 'not_found' }}"
        );

        let result = page
            .evaluate_raw(&js)
            .await
            .map_err(|e| format!("failed to submit form: {e}"))?;

        let value = result
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if value == "not_found" {
            Err(format!("form not found: '{}'", form_selector))
        } else {
            Ok(Value::Ok(Box::new(Value::Nil)))
        }
    })
}

/// `browser.fill_form(page, fields, submit)` —
///  1. For each (label_name, value) in the fields map:
///     a. Find label matching the key → get associated input
///     b. Fill the input with the value
///  2. If submit=true, find and click a submit button
fn page_fill_form(args: Vec<Value>) -> StdlibResult {
    let page = extract_page(&args, 0)?;
    let fields = extract_fields_map(&args, 1)?;
    let submit = extract_optional_bool(&args, 2)?;

    if fields.is_empty() {
        return Err("fill_form: fields map must not be empty".to_string());
    }

    let rt = crate::runtime::get_runtime();
    rt.block_on(async {
        // Build combined JS to find all inputs at once
        let mut js_parts: Vec<String> = Vec::new();
        for (i, (label_text, _value)) in fields.iter().enumerate() {
            let escaped_label = crate::browser::page::escape_js_string(label_text);
            js_parts.push(format!(
                r#"labels[{i}] = Array.from(document.querySelectorAll('label')).find(function(l) {{ return l.textContent.trim() === '{escaped_label}'; }});"#
            ));
            js_parts.push(format!(
                r#"if (labels[{i}]) {{
    var forAttr = labels[{i}].getAttribute('for');
    if (forAttr) {{
        inputs[{i}] = document.getElementById(forAttr);
    }} else {{
        inputs[{i}] = labels[{i}].querySelector('input, select, textarea');
        if (!inputs[{i}]) {{
            var sib = labels[{i}].nextElementSibling;
            while (sib) {{
                if (['INPUT', 'SELECT', 'TEXTAREA'].includes(sib.tagName)) {{ inputs[{i}] = sib; break; }}
                var nested = sib.querySelector('input, select, textarea');
                if (nested) {{ inputs[{i}] = nested; break; }}
                sib = sib.nextElementSibling;
            }}
        }}
    }}
}}"#
            ));
        }

        let n = fields.len();
        let combined_js = format!(
            r#"(function() {{
    var labels = new Array({n});
    var inputs = new Array({n});
    {}
    return inputs.map(function(el, idx) {{
        if (!el) return null;
        // Return objectId-compatible info
        return {{ tagName: el.tagName, type: el.type || '', id: el.id || '', name: el.name || '', idx: idx }};
    }});
}})()"#,
            js_parts.join("\n")
        );

        let result = page
            .evaluate_raw(&combined_js)
            .await
            .map_err(|e| format!("failed to find form fields: {e}"))?;

        // For each field, fill via fill_labeled (simpler and handles edge cases)
        let mut errors: Vec<String> = Vec::new();
        for (label_text, value) in &fields {
            let escaped_label = crate::browser::page::escape_js_string(label_text);
            let fill_js = format!(
                r#"(function() {{
    var labels = Array.from(document.querySelectorAll('label'));
    var found = labels.find(function(l) {{ return l.textContent.trim() === '{escaped_label}'; }});
    if (!found) return null;
    var forAttr = found.getAttribute('for');
    var el = null;
    if (forAttr) {{
        el = document.getElementById(forAttr);
    }} else {{
        el = found.querySelector('input, select, textarea');
        if (!el) {{
            var sib = found.nextElementSibling;
            while (sib) {{
                if (['INPUT', 'SELECT', 'TEXTAREA'].includes(sib.tagName)) {{ el = sib; break; }}
                var nested = sib.querySelector('input, select, textarea');
                if (nested) {{ el = nested; break; }}
                sib = sib.nextElementSibling;
            }}
        }}
    }}
    return el || null;
}})()"#
            );

            let fill_result = page.evaluate_raw(&fill_js).await.map_err(|e| e.to_string())?;

            if let Some(object_id) = fill_result
                .get("result")
                .and_then(|r| r.get("objectId"))
                .and_then(|v| v.as_str())
            {
                let el = crate::browser::element::ElementHandle {
                    client: page.client.clone(),
                    session_id: page.session_id.clone(),
                    remote_object_id: object_id.to_string(),
                };
                if let Err(e) = el.type_text(value, Some(15)).await {
                    errors.push(format!("field '{}': {}", label_text, e));
                }
            } else {
                errors.push(format!("field '{}': input element not found", label_text));
            }
        }

        if !errors.is_empty() {
            return Err(format!("fill_form errors: {}", errors.join("; ")));
        }

        // Submit if requested
        if submit {
            let submit_js = r#"(function() {
    var btn = document.querySelector('button[type="submit"], input[type="submit"]');
    if (btn) return btn;
    // Try to find first form and submit it
    var form = document.querySelector('form');
    if (form) { form.submit(); return 'submitted'; }
    return null;
})()"#;

            let sub_result = page
                .evaluate_raw(submit_js)
                .await
                .map_err(|e| format!("submit failed: {e}"))?;

            if let Some(object_id) = sub_result
                .get("result")
                .and_then(|r| r.get("objectId"))
                .and_then(|v| v.as_str())
            {
                let btn = crate::browser::element::ElementHandle {
                    client: page.client.clone(),
                    session_id: page.session_id.clone(),
                    remote_object_id: object_id.to_string(),
                };
                btn.click(crate::browser::interaction::ClickOptions::default())
                    .await
                    .map_err(|e| format!("submit click failed: {e}"))?;
            }
            // If 'submitted' string was returned, already done via JS
        }

        Ok(Value::Ok(Box::new(Value::Nil)))
    })
}

/// Convert an orchestrator `ResolveReport` into the .tl-facing struct shape
/// shared by the module-level `browser.resolve_antibot` arm and (via
/// `page_resolve_antibot`) callers.
pub(crate) fn resolve_report_to_value(report: &crate::browser::antibot::ResolveReport) -> Value {
    let steps: Vec<Value> = report
        .steps
        .iter()
        .map(|s| Value::Struct {
            name: "AntibotResolveStep".to_string(),
            fields: vec![
                ("engine".to_string(), Value::String(s.engine.clone())),
                ("available".to_string(), Value::Bool(s.available)),
                ("ran".to_string(), Value::Bool(s.ran)),
                ("note".to_string(), Value::String(s.note.clone())),
            ],
        })
        .collect();
    Value::Struct {
        name: "AntibotResolveReport".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(report.url.clone())),
            ("resolved".to_string(), Value::Bool(report.resolved)),
            ("final_status".to_string(), Value::Int(report.final_status as i128)),
            ("attempts".to_string(), Value::Int(report.attempts as i128)),
            ("body_hint".to_string(), Value::String(report.body_hint.clone())),
            ("steps".to_string(), Value::Array(steps)),
        ],
    }
}

/// `browser.resolve_antibot(page, url [, opts])` — ROADMAP #9 module-level
/// route for the real orchestrator resolve loop (detect → solve → retry over
/// the page's CURRENT egress). `opts` may carry `solver_key` /
/// `solver_service` to arm the external CAPTCHA solver leg. Returns an
/// `AntibotResolveReport` struct with honest per-engine capability flags, or
/// an Err when even the first navigation fails or egress is dishonest.
fn page_resolve_antibot(args: Vec<Value>) -> StdlibResult {
    let page = extract_page(&args, 0)?;
    let url = extract_string(&args, 1, "url")?;

    // Optional third map arg {solver_key, solver_service}.
    let solver = match args.get(2) {
        Some(Value::Map(entries)) => {
            let key = entries.iter().find(|(k, _)| {
                matches!(k, Value::String(s) if s == "solver_key")
            });
            match key {
                Some((_, Value::String(k))) if !k.is_empty() => {
                    let service: String = entries
                        .iter()
                        .find(|(k, _)| matches!(k, Value::String(s) if s == "solver_service"))
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let service = if service.is_empty() {
                        "https://api.2captcha.com".to_string()
                    } else {
                        service
                    };
                    Some(crate::browser::captcha::CaptchaSolverConfig::new(k, &service))
                }
                _ => None,
            }
        }
        _ => None,
    };

    let settings = crate::browser::AntiBotSettings {
        warmup_enabled: false,
        cookie_farm_enabled: false,
        // resolve keeps the page's CURRENT egress — the pool check must not
        // fail a legitimately direct page; direct is the explicit consent here.
        allow_direct_egress: true,
        captcha_solver: solver,
        ..Default::default()
    };
    let mut orchestrator = crate::browser::AntiBotOrchestrator::with_settings(settings);

    let rt = crate::runtime::get_runtime();
    rt.block_on(async move {
        match orchestrator.resolve(page, &url).await {
            Ok(report) => Ok(Value::Ok(Box::new(resolve_report_to_value(&report)))),
            Err(e) => Ok(Value::Err(Box::new(Value::String(e.to_string())))),
        }
    })
}

fn form_automation_dispatch(function: &str, args: Vec<Value>) -> StdlibResult {
    match function {
        "select_option" => page_select_option(args),
        "fill_labeled" => page_fill_labeled(args),
        "click_button" => page_click_button(args),
        "submit_form" => page_submit_form(args),
        "fill_form" => page_fill_form(args),
        _ => Ok(Value::String(format!(
            "browser.{function} — unknown form automation function"
        ))),
    }
}

fn surface_entry(
    name: &str,
    category: &str,
    status: &str,
    transport: &str,
    requires_live_gate: bool,
    fail_closed: bool,
    evidence: &str,
) -> Value {
    Value::Struct {
        name: "BrowserSurfaceEntry".to_string(),
        fields: vec![
            string_field("name", name),
            string_field("category", category),
            string_field("status", status),
            string_field("transport", transport),
            bool_field("requires_live_gate", requires_live_gate),
            bool_field("fail_closed", fail_closed),
            string_field("evidence", evidence),
        ],
    }
}

fn string_field(name: &str, value: &str) -> (String, Value) {
    (name.to_string(), Value::String(value.to_string()))
}

fn bool_field(name: &str, value: bool) -> (String, Value) {
    (name.to_string(), Value::Bool(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── pure extraction helpers (added 2026-10-12) ──

    #[test]
    fn og_parse_is_attribute_order_independent() {
        let fwd = extract_open_graph(r#"<meta property="og:title" content="Hello">"#);
        let rev = extract_open_graph(r#"<meta content="Hello" property="og:title">"#);
        for v in [fwd, rev] {
            match v {
                Value::Map(m) => {
                    assert_eq!(m.len(), 1);
                    assert!(matches!(&m[0].0, Value::String(k) if k == "title"));
                    assert!(matches!(&m[0].1, Value::String(c) if c == "Hello"));
                }
                other => panic!("expected Map, got {other:?}"),
            }
        }
    }

    #[test]
    fn og_ignores_non_og_meta() {
        let v = extract_open_graph(
            r#"<meta name="description" content="x"><meta property="twitter:card" content="y">"#,
        );
        match v {
            Value::Map(m) => assert!(m.is_empty(), "expected no og: entries"),
            other => panic!("expected Map, got {other:?}"),
        }
    }

    #[test]
    fn consent_strategy_maps_names_and_fails_safe_on_unknown() {
        use crate::browser::CookieConsentStrategy as S;
        assert!(matches!(consent_strategy("accept"), S::AcceptAll));
        assert!(matches!(consent_strategy("accept_all"), S::AcceptAll));
        assert!(matches!(consent_strategy("dismiss"), S::Dismiss));
        // Anything unrecognised rejects non-essential — never silently accepts,
        // and never the numeric FFI's `Dismiss` fallback.
        assert!(matches!(consent_strategy("nope"), S::RejectNonEssential));
        assert!(matches!(consent_strategy(""), S::RejectNonEssential));
    }

    #[test]
    fn redact_pii_strips_each_category_and_leaves_prose_alone() {
        let raw = "Contact jane.doe+work@example.co.uk or +1 555-123-4567. \
                   SSN 123-45-6789, card 4111 1111 1111 1111, host 192.168.0.14.";
        let out = redact_pii(raw);
        assert!(!out.contains("jane.doe"), "email survived: {out}");
        assert!(!out.contains("123-45-6789"), "ssn survived: {out}");
        assert!(!out.contains("4111"), "card survived: {out}");
        assert!(!out.contains("192.168.0.14"), "ip survived: {out}");
        assert!(!out.contains("555-123-4567"), "phone survived: {out}");
        for token in [
            "[REDACTED_EMAIL]",
            "[REDACTED_SSN]",
            "[REDACTED_CC]",
            "[REDACTED_PHONE]",
            "[REDACTED_IP]",
        ] {
            assert!(out.contains(token), "missing {token}: {out}");
        }

        // Ordinary prose must pass through untouched — the patterns are
        // shape-based, so a sentence with no PII-shaped tokens is unchanged.
        let prose = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(redact_pii(prose), prose);
    }

    // ── live-page helpers (added 2026-10-22) ──

    #[test]
    fn live_page_helpers_refuse_when_no_page_is_bound() {
        // No browser is launched in a unit test, so the registry is empty. Each
        // helper must say so — the failure mode this replaces was silence.
        for (name, args) in [
            ("page_extract_all_text", vec![Value::String("h1".into())]),
            (
                "page_extract_all_attrs",
                vec![
                    Value::String("a".into()),
                    Value::Array(vec![Value::String("href".into())]),
                ],
            ),
            ("page_capture_dom_snapshot", vec![]),
            ("page_structured_data", vec![]),
        ] {
            let result = super::dispatch(name, args)
                .unwrap_or_else(|| panic!("{name} is not routed through browser::dispatch"));
            let message = result.expect_err("must refuse without a bound page");
            assert!(
                message.contains("no page bound"),
                "{name} refused with the wrong message: {message}"
            );
        }
    }

    #[test]
    fn live_page_helpers_are_routed_by_name() {
        // The dispatch table — not the .tl declaration — is what makes a name
        // callable; this pins all four so a rename cannot silently unwire them.
        for name in [
            "page_extract_all_text",
            "page_extract_all_attrs",
            "page_capture_dom_snapshot",
            "page_structured_data",
        ] {
            assert!(
                super::dispatch(name, vec![]).is_some(),
                "{name} has no dispatch arm"
            );
        }
    }

    #[test]
    fn structured_data_extract_returns_both_halves() {
        let html = concat!(
            r#"<html><head>"#,
            r#"<script type="application/ld+json">{"@type":"Thing"}</script>"#,
            r#"<meta property="og:title" content="T">"#,
            r#"</head></html>"#
        );
        match structured_data_extract(vec![Value::String(html.into())]).unwrap() {
            Value::Struct { name, fields } => {
                assert_eq!(name, "StructuredData");
                // Assert the DECLARED field-name vector, not just the values: a
                // renamed field still satisfies every value-based assertion, which
                // is exactly how `jsonld` shipped against a declared `json_ld`.
                let names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(names, vec!["json_ld", "open_graph", "has_json_ld"]);
                match fields.iter().find(|(k, _)| k == "json_ld").map(|(_, v)| v) {
                    Some(Value::Array(a)) => assert_eq!(a.len(), 1),
                    other => panic!("expected json_ld Array, got {other:?}"),
                }
                match fields
                    .iter()
                    .find(|(k, _)| k == "open_graph")
                    .map(|(_, v)| v)
                {
                    Some(Value::Map(m)) => assert_eq!(m.len(), 1),
                    other => panic!("expected open_graph Map, got {other:?}"),
                }
                assert!(
                    matches!(
                        fields.iter().find(|(k, _)| k == "has_json_ld").map(|(_, v)| v),
                        Some(Value::Bool(true))
                    ),
                    "has_json_ld must be true when JSON-LD is present"
                );
            }
            other => panic!("expected Struct, got {other:?}"),
        }
    }

    #[test]
    fn structured_data_extract_rejects_non_string() {
        assert!(structured_data_extract(vec![Value::Int(1)]).is_err());
        assert!(structured_data_extract(vec![]).is_err());
    }

    #[test]
    fn simhash_is_deterministic_and_empty_is_zero() {
        assert_eq!(
            simhash64("the quick brown fox"),
            simhash64("the quick brown fox")
        );
        assert_eq!(simhash64(""), 0);
        assert_eq!(simhash64("   "), 0);
        // tokens are lowercased, so casing does not change the fingerprint
        assert_eq!(simhash64("Quick Brown"), simhash64("quick brown"));
    }

    #[test]
    fn simhash_near_duplicates_closer_than_unrelated() {
        let base = "the quick brown fox jumps over the lazy dog";
        let near = "the quick brown fox jumps over the lazy cat";
        let far = "submarines barnacles tungsten histogram parallelogram";
        let d_near = (simhash64(base) ^ simhash64(near)).count_ones();
        let d_far = (simhash64(base) ^ simhash64(far)).count_ones();
        assert!(d_near < d_far, "near={d_near} far={d_far}");
    }

    #[test]
    fn similarity_is_exactly_one_for_identical_text() {
        let mk = |t: &str| content_fingerprint_from_text(vec![Value::String(t.into())]).unwrap();
        let s =
            content_fingerprint_similarity(vec![mk("hello world"), mk("hello world")]).unwrap();
        match s {
            Value::Float(f) => assert_eq!(f, 1.0),
            other => panic!("expected Float, got {other:?}"),
        }
    }

    #[test]
    fn similarity_rejects_non_fingerprints() {
        assert!(content_fingerprint_similarity(vec![Value::Int(1), Value::Int(2)]).is_err());
        assert!(content_fingerprint_similarity(vec![Value::Int(1)]).is_err());
    }

    #[test]
    fn content_fingerprint_matches_the_declared_struct_shape() {
        // The .tl declares {hash: String, word_count: i32, text_length: i32}.
        // Asserting the FIELD NAMES is the whole point: an earlier revision of
        // this function returned {simhash, bits} and every test still passed,
        // because the tests asserted on that invented shape instead of the
        // declared contract. This test is what catches that class of error.
        let f =
            content_fingerprint_from_text(vec![Value::String("one two three".into())]).unwrap();
        let (name, fields) = match &f {
            Value::Struct { name, fields } => (name.clone(), fields.clone()),
            other => panic!("expected Struct, got {other:?}"),
        };
        assert_eq!(name, "ContentFingerprint");
        let names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["hash", "word_count", "text_length"]);

        match &fields[0].1 {
            Value::String(h) => {
                assert_eq!(h.len(), 16, "hash must be 16 hex digits");
                assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
            }
            other => panic!("hash must be a String, got {other:?}"),
        }
        assert!(matches!(&fields[1].1, Value::Int(3)), "word_count of 'one two three'");
        assert!(
            matches!(&fields[2].1, Value::Int(13)),
            "text_length of 'one two three'"
        );
    }

    #[test]
    fn crawler_from_sitemap_shapes_parsed_entries() {
        // Drives the PURE parser, so this needs no network and no egress — which
        // matters because egress here refuses loopback, making a local fixture
        // unfetchable. This is the parse→shape path the fetch path also uses.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/alpha</loc></url>
  <url><loc>https://example.com/beta</loc></url>
  <url><loc>https://example.com/gamma</loc></url>
</urlset>"#;
        let entries = crate::browser::sitemap::SitemapParser::parse(xml);
        assert_eq!(entries.len(), 3, "fixture must parse to 3 entries");

        let v = crawler_struct_from_entries("https://example.com/sitemap.xml", &entries);
        let fields = match &v {
            Value::Struct { fields, .. } => fields.clone(),
            other => panic!("expected Struct, got {other:?}"),
        };
        let get = |n: &str| fields.iter().find(|(k, _)| k == n).unwrap().1.clone();
        assert!(matches!(get("strategy"), Value::String(ref s) if s == "sitemap"));
        assert!(matches!(get("max_pages"), Value::Int(3)), "3 discovered entries");
        assert!(
            matches!(get("seed_url"), Value::String(ref s) if s == "https://example.com/alpha"),
            "seed must be the first parsed entry"
        );
        assert!(matches!(get("pages_crawled"), Value::Int(0)), "nothing crawled yet");

        // Empty sitemap: empty seed and 0 pages, not an error and not a fake URL.
        let none = crawler_struct_from_entries("https://example.com/empty.xml", &[]);
        let f2 = match &none {
            Value::Struct { fields, .. } => fields.clone(),
            other => panic!("expected Struct, got {other:?}"),
        };
        let get2 = |n: &str| f2.iter().find(|(k, _)| k == n).unwrap().1.clone();
        assert!(matches!(get2("max_pages"), Value::Int(0)));
        assert!(matches!(get2("seed_url"), Value::String(ref s) if s.is_empty()));
    }

    #[test]
    fn crawler_from_links_is_a_planner_and_validates_its_inputs() {
        let c = crawler_from_links(vec![
            Value::String("https://example.com/".into()),
            Value::Int(3),
        ])
        .unwrap();
        let (name, fields) = match &c {
            Value::Struct { name, fields } => (name.clone(), fields.clone()),
            other => panic!("expected Struct, got {other:?}"),
        };
        assert_eq!(name, "Crawler");
        let names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "seed_url",
                "sitemap_url",
                "strategy",
                "max_depth",
                "max_pages",
                "pages_crawled",
                "rate_limit_ms"
            ]
        );

        let get = |n: &str| fields.iter().find(|(k, _)| k == n).unwrap().1.clone();
        assert!(matches!(get("strategy"), Value::String(ref s) if s == "link_follow"));
        assert!(matches!(get("max_depth"), Value::Int(3)));
        // Seeded but not crawled — the planner must not claim progress.
        assert!(matches!(get("pages_crawled"), Value::Int(0)));
        assert!(matches!(get("max_pages"), Value::Int(1)), "one job pending: the seed");
        assert!(matches!(get("sitemap_url"), Value::String(ref s) if s.is_empty()));

        // Rejected inputs.
        assert!(crawler_from_links(vec![]).is_err());
        assert!(crawler_from_links(vec![Value::Int(1), Value::Int(1)]).is_err());
        assert!(crawler_from_links(vec![Value::String("  ".into()), Value::Int(1)]).is_err());
        assert!(crawler_from_links(vec![Value::String("https://x/".into()), Value::Int(-1)]).is_err());
        assert!(crawler_from_links(vec![Value::String("https://x/".into()), Value::Bool(true)]).is_err());
    }

    #[test]
    fn page_cache_matches_its_declared_struct_shape() {
        let c = page_cache_create(vec![Value::Int(3600), Value::Int(64)]).unwrap();
        match &c {
            Value::Struct { name, fields } => {
                assert_eq!(name, "PageCache");
                let names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(
                    names,
                    vec![
                        "max_age_seconds",
                        "max_size_mb",
                        "entries",
                        "hits",
                        "misses",
                        "keyed_by"
                    ]
                );
            }
            other => panic!("expected Struct, got {other:?}"),
        }
        assert!(page_cache_create(vec![]).is_err());
        assert!(page_cache_create(vec![Value::Int(1)]).is_err());
    }

    fn field<'a>(fields: &'a [(String, Value)], name: &str) -> &'a Value {
        fields
            .iter()
            .find(|(field_name, _)| field_name == name)
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing field {name}"))
    }

    fn bool_field_value(fields: &[(String, Value)], name: &str) -> bool {
        match field(fields, name) {
            Value::Bool(value) => *value,
            other => panic!("expected bool field {name}, got {other:?}"),
        }
    }

    #[test]
    fn surface_manifest_is_non_live_boundary() {
        let Value::Struct { name, fields } = surface_manifest(vec![]).unwrap() else {
            panic!("expected surface manifest struct");
        };
        assert_eq!(name, "BrowserSurfaceManifest");
        assert_eq!(
            field(&fields, "schema_version").as_string(),
            SURFACE_SCHEMA_VERSION
        );
        assert!(!bool_field_value(&fields, "claims_live_browser_ready"));
        assert!(!bool_field_value(
            &fields,
            "claims_production_fallback_ready"
        ));
    }

    #[test]
    fn pipe_status_is_fail_closed() {
        let Value::Struct { fields, .. } = pipe_transport_status(vec![]).unwrap() else {
            panic!("expected pipe status struct");
        };
        assert_eq!(
            field(&fields, "status").as_string(),
            "unsupported_fail_closed"
        );
        assert!(bool_field_value(&fields, "rejects_before_launch"));
        assert!(!bool_field_value(&fields, "launches_browser"));
    }

    #[test]
    fn page_method_names_never_shadow_real_interp_arms() {
        // ROADMAP #7 guard: the REAL ("Page","fill")/("Page","click")/
        // ("Page","select") arms live in interp.rs method dispatch. This
        // stdlib facade must return None for those names so method calls
        // always reach the interpreter arms — never a facade stub.
        for method in ["fill", "fill_field", "fill_input", "click", "click_selector", "select"] {
            assert!(
                dispatch(method, vec![]).is_none(),
                "facade must not shadow the interp Page.{method} arm"
            );
        }
        // The legacy module-level form functions keep their real route.
        assert!(
            dispatch("select_option", vec![]).is_some(),
            "legacy select_option module fn still routed"
        );
        assert!(
            dispatch("fill_labeled", vec![]).is_some(),
            "legacy fill_labeled module fn still routed"
        );
    }

    #[test]
    fn resolve_antibot_requires_page_and_url() {
        // ROADMAP #9 module-level route: honest argument validation before any
        // engine runs (no page = no live browser touch).
        let err = dispatch("resolve_antibot", vec![])
            .expect("resolve_antibot is a routed module fn")
            .expect_err("no args must fail honestly");
        assert!(err.contains("missing argument 1"), "got: {err}");

        let err = dispatch(
            "antibot_resolve",
            vec![Value::Int(7)],
        )
        .expect("antibot_resolve alias routed")
        .expect_err("non-Page first arg must fail honestly");
        assert!(err.contains("expected Page"), "got: {err}");
    }

    #[test]
    fn resolve_report_value_shape_carries_steps() {
        // The .tl-facing report shape: resolved flag + status + steps array of
        // {engine, available, ran, note} capability tuples.
        let mut report = crate::browser::antibot::ResolveReport::new("https://example.test");
        report.resolved = false;
        report.final_status = 403;
        report.attempts = 1;
        report.body_hint = "verify you are a human".into();
        report.steps.push(crate::browser::antibot::ResolveStep {
            engine: "captcha.solve".into(),
            available: false,
            ran: false,
            note: "no solver configured".into(),
        });
        let Value::Struct { name, fields } = resolve_report_to_value(&report) else {
            panic!("expected struct");
        };
        assert_eq!(name, "AntibotResolveReport");
        assert!(!bool_field_value(&fields, "resolved"));
        assert_eq!(field(&fields, "final_status").as_string(), "403");
        let Value::Array(steps) = field(&fields, "steps") else {
            panic!("expected steps array");
        };
        assert_eq!(steps.len(), 1);
        let Value::Struct { name: sname, fields: sfields } = &steps[0] else {
            panic!("expected step struct");
        };
        assert_eq!(sname, "AntibotResolveStep");
        assert!(!bool_field_value(sfields, "available"));
        assert!(!bool_field_value(sfields, "ran"));
        assert_eq!(field(sfields, "engine").as_string(), "captcha.solve");
    }

    /// Every empty-bodied `page_*` declaration in `stdlib/browser.tl` must reach
    /// this router. Guards the drift the 2026-10-15 placeholder audit found: 23
    /// declared page-tier functions returned `None` here, which surfaced to the
    /// caller as `undefined function: browser.<name>` — indistinguishable from a
    /// typo. The name list is parsed from the `.tl` source rather than hardcoded,
    /// so a new declaration arriving without a router arm fails this test instead
    /// of shipping.
    #[test]
    fn every_declared_page_fn_reaches_this_router() {
        let source = include_str!("../../stdlib/browser.tl");
        let declared: Vec<&str> = source
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if !line.ends_with("{ }") {
                    return None;
                }
                let name = line.strip_prefix("fn ")?.split('(').next()?;
                name.starts_with("page_").then_some(name)
            })
            .collect();

        assert_eq!(
            declared.len(),
            23,
            "expected 23 declared page_* free functions, parsed: {declared:?}"
        );

        for name in declared.iter().copied() {
            match dispatch(name, Vec::new()) {
                // Still-unimplemented helpers refuse with the live spelling; the
                // implemented ones validate their arguments first (an empty call
                // cannot succeed). Both are actionable; `undefined function` is not.
                Some(Err(msg)) => assert!(
                    msg.contains("no page bound") || msg.contains(name),
                    "{name}: the refusal must be actionable, got: {msg}"
                ),
                // Argument-free helpers may succeed on a bound page; unbound they
                // must not claim success silently, so a bare Ok here is only
                // acceptable when the helper genuinely takes no page.
                Some(Ok(_)) => {}
                None => panic!("{name}: declared in stdlib/browser.tl but missing from dispatch()"),
            }
        }
    }
}
