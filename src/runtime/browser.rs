//! Browser automation runtime wrappers.
//!
//! Provides `extern "C"` functions wrapping the async browser module
//! for use by compiled Tallow binaries. Each function uses the global
//! tokio runtime via `get_runtime().block_on()` to bridge async → sync.
//!
//! Opaque handles are `Box::into_raw()` pointers. The caller must
//! free them via the corresponding `_close` / `_free` functions.

use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::browser::cdp::CdpClient;
use crate::browser::element::ElementHandle;
use crate::browser::interaction::ClickOptions;
use crate::browser::page::{CookieConsentStrategy, Page, WaitUntil};
use crate::browser::process::{BrowserConfig, BrowserProcess};

use super::{cstr_to_str, get_runtime, set_last_error, string_to_cstr};

// ── Browser Handle ──────────────────────────────────────────────────────────

/// Wraps a browser process and its CDP client as a single opaque handle.
struct BrowserHandle {
    _process: BrowserProcess,
    client: CdpClient,
}

/// Safety-net flag: register atexit only once.
static ATEXIT_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Whether the default stealth profile should be SKIPPED.
///
/// Stealth is on by default: a compiled CDP scrape otherwise presents the
/// headless-shell UA string and `navigator.webdriver === true`, which is the
/// cheapest possible bot signal. `TALLOW_NO_STEALTH=1` (or `true`/`yes`) turns
/// it off — needed when driving a backend that ships its own (Camoufox) or when
/// a program applies its own profile and wants no interference.
pub(crate) fn stealth_disabled() -> bool {
    match std::env::var("TALLOW_NO_STEALTH") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        }
        Err(_) => false,
    }
}

// ── Page-level fingerprint posture (report ag03 R-7) ────────────────────────

/// Which page-level fingerprint profile the compiled (public-scraping) path
/// applies.
///
/// The decision is a pure function of the stealth configuration so it can be
/// unit-tested without launching a browser. R-7: *public scraping defaults to
/// the honest declared-bot identity* (`TallowScraper/<v> (+contact)`); a
/// **stealth** profile (human-impersonating fingerprint) is only applied when
/// the operator explicitly opts in — those profiles are reserved for
/// legally-cleared sources. `TALLOW_NO_STEALTH=1` still disables *every*
/// profile application (unchanged contract: the explicit opt-out wins over
/// everything, and an unset env keeps the default posture on).
#[derive(Debug)]
pub(crate) enum PageProfileDecision {
    /// Explicit opt-out: apply no page-level profile at all.
    Disabled,
    /// Honest declared-bot identity — the R-7 default for public scraping.
    DeclaredBot(crate::browser::stealth::StealthProfile),
    /// A stealth profile; requires an explicit opt-in
    /// (`TALLOW_STEALTH_PROFILE` or a non-default `stealth.toml` profile).
    Stealth(crate::browser::stealth::StealthProfile),
}

/// Pure posture decision (testable without a browser or a config directory).
///
/// * `no_stealth` — the parsed `TALLOW_NO_STEALTH` opt-out (`stealth_disabled()`).
/// * `env_profile` — the raw `TALLOW_STEALTH_PROFILE` value, if set.
/// * `stealth_cfg` — the loaded `stealth.toml`; a profile that differs from the
///   built-in default counts as an explicit operator choice.
pub(crate) fn page_profile_decision_from(
    stealth_cfg: &crate::browser::config::StealthToml,
    no_stealth: bool,
    env_profile: Option<&str>,
) -> PageProfileDecision {
    if no_stealth {
        return PageProfileDecision::Disabled;
    }

    // Explicit stealth opt-in: env first, then a non-default stealth.toml
    // profile. The default profile value (`chrome_windows`) is NOT an explicit
    // choice — it is what an absent/unconfigured file resolves to.
    let requested: Option<String> = env_profile
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            let default_profile = crate::browser::config::StealthToml::default().profile;
            if stealth_cfg.profile != default_profile {
                Some(stealth_cfg.profile.trim().to_ascii_lowercase())
            } else {
                None
            }
        });

    if let Some(name) = requested {
        if name == "declared_bot" || name == "declared-bot" {
            return PageProfileDecision::DeclaredBot(
                declared_bot_page_profile(),
            );
        }
        let mut cfg = stealth_cfg.clone();
        cfg.profile = name;
        return PageProfileDecision::Stealth(cfg.to_stealth_profile());
    }

    PageProfileDecision::DeclaredBot(declared_bot_page_profile())
}

/// The declared-bot profile for compiled pages (contact/version from the
/// pool's `DeclaredBotIdentity`: `TALLOW_BOT_CONTACT` or the project contact).
fn declared_bot_page_profile() -> crate::browser::stealth::StealthProfile {
    crate::browser::pool::declared_bot_profile(
        &crate::browser::pool::DeclaredBotIdentity::default(),
    )
}

/// Posture decision using the live process state (env + loaded config).
pub(crate) fn page_profile_decision() -> PageProfileDecision {
    let stealth = crate::browser::config::BrowserFullConfig::load().stealth;
    let env_profile = std::env::var("TALLOW_STEALTH_PROFILE").ok();
    page_profile_decision_from(&stealth, stealth_disabled(), env_profile.as_deref())
}

// ── Browser Lifecycle ───────────────────────────────────────────────────────

/// Launch a browser process. Returns an opaque handle (pointer).
/// `headless`: 1 = headless, 0 = headed.
/// Returns null on error (call tallow_last_error() for details).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_browser_launch(headless: i32) -> *mut c_void {
    let rt = get_runtime();

    let config = BrowserConfig {
        headless: headless != 0,
        // Egress: honour `TALLOW_TOR=1` / `TALLOW_PROXY` here too — the same
        // contract as the HTTP runtime and the interpreter stdlib. Without this
        // a compiled CDP scrape launched a browser with no proxy at all.
        // `browser/process.rs` turns `proxy` into Chrome's `--proxy-server`
        // (normalizing `socks5h://` → `socks5://`) and clears inherited
        // `*_proxy` env vars so the child cannot be pushed onto a direct route.
        proxy: crate::runtime::fetch::egress_proxy_url(),
        // Stealth by default: a compiled CDP scrape must not be trivially
        // readable as automation at the launch-flag level. `browser/process.rs`
        // turns this on for the launch flags (`--disable-blink-features=AutomationControlled`,
        // swiftshader GL, fixed 1920x1080 window, …); the page-level identity
        // posture (declared-bot by default, stealth only on explicit opt-in —
        // report ag03 R-7) is decided in `tallow_browser_new_page`. Mirrors the
        // interpreter's `Browser.launch` (which has always set `stealth: true`)
        // and the on-disk `~/.tallow/browser/config/browser.toml` default, so
        // both runtimes agree; `TALLOW_NO_STEALTH=1` is the deliberate opt-out.
        stealth: crate::browser::config::BrowserFullConfig::load().browser.stealth
            && !stealth_disabled(),
        ..Default::default()
    };

    match rt.block_on(async {
        let process = BrowserProcess::launch(&config)?;
        let ws_url = process.ws_url.clone();
        let client = CdpClient::connect(&ws_url).await?;
        Ok::<_, crate::browser::error::BrowserError>((process, client))
    }) {
        Ok((process, client)) => {
            // Register atexit handler as safety net (once)
            if !ATEXIT_REGISTERED.swap(true, Ordering::SeqCst) {
                // Note: We can't do full cleanup in atexit since we don't
                // have the handle. The BrowserProcess Drop impl will kill
                // the child process when the handle is freed.
            }
            let handle = Box::new(BrowserHandle {
                _process: process,
                client,
            });
            Box::into_raw(handle) as *mut c_void
        }
        Err(e) => {
            set_last_error(format!("browser launch failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Close a browser and free its handle.
/// Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_browser_close(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    // Dropping the BrowserHandle drops BrowserProcess, which kills the child
    unsafe {
        drop(Box::from_raw(handle as *mut BrowserHandle));
    }
}

/// Create a new page (tab) in the browser. Returns an opaque page handle.
/// Returns null on error. Free with `tallow_page_free`, NOT `tallow_browser_close`
/// (which only frees Browser handles — calling it on a Page would corrupt memory).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_browser_new_page(handle: *mut c_void) -> *mut c_void {
    if handle.is_null() {
        set_last_error("new_page: null browser handle".to_string());
        return std::ptr::null_mut();
    }
    let browser = unsafe { &*(handle as *const BrowserHandle) };
    let rt = get_runtime();

    match rt.block_on(browser.client.create_page(None)) {
        Ok(page) => {
            // Apply the page-level fingerprint profile (UA + client-hint
            // alignment, `navigator.webdriver`, WebGL vendor/renderer,
            // permissions, canvas noise) per the R-7 posture decision:
            // public scraping defaults to the honest *declared-bot* identity,
            // stealth profiles require an explicit opt-in, and
            // `TALLOW_NO_STEALTH=1` disables all profile application. A failure
            // here is FATAL rather than a warning: this is a privacy tool, and
            // continuing with the page presenting an identity other than the
            // declared one — while the caller believes it was applied — is the
            // silent-wrong-answer class the native backend refuses everywhere
            // else. Set `TALLOW_NO_STEALTH=1` to opt out deliberately.
            let (label, profile) = match page_profile_decision() {
                PageProfileDecision::Disabled => ("", None),
                PageProfileDecision::DeclaredBot(p) => ("declared-bot profile", Some(p)),
                PageProfileDecision::Stealth(p) => ("stealth profile", Some(p)),
            };
            if let Some(profile) = profile {
                if let Err(e) = rt.block_on(page.apply_stealth(&profile)) {
                    set_last_error(format!("new_page: {label} failed: {e}"));
                    return std::ptr::null_mut();
                }
            }
            let page_handle = Box::new(page);
            Box::into_raw(page_handle) as *mut c_void
        }
        Err(e) => {
            set_last_error(format!("new_page: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Page Navigation ─────────────────────────────────────────────────────────

/// Navigate a page to a URL. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_goto(page: *mut c_void, url: *const c_char) -> i32 {
    if page.is_null() {
        set_last_error("goto: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let url_str = match unsafe { cstr_to_str(url) } {
        Some(s) => s,
        None => {
            set_last_error("goto: null or invalid URL".to_string());
            return -1;
        }
    };
    let rt = get_runtime();

    // Use DomContentLoaded — fires earlier than load, avoids timeouts on headed browsers (Gap 4).
    match rt.block_on(page_ref.navigate(url_str, WaitUntil::DomContentLoaded)) {
        Ok(_) => {
            wait_for_document_ready(rt, page_ref);
            0
        }
        Err(e) => {
            set_last_error(format!("goto: {e}"));
            -1
        }
    }
}

/// How long a navigation waits for the document to finish loading, in ms.
/// `TALLOW_GOTO_SETTLE_MS=0` disables the wait (restores the old behaviour).
fn settle_budget_ms() -> u64 {
    std::env::var("TALLOW_GOTO_SETTLE_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(5000)
}

/// Bounded wait until the navigated document reports `readyState == "complete"`.
///
/// `WaitUntil::DomContentLoaded` returns while the document is still `loading`:
/// measured on a Tor fetch of `https://www.iana.org/help/example-domains`, the
/// instant after `goto` returned, `document.readyState` was `"loading"` and
/// `document.body` was **null**. A script that navigates and immediately reads
/// the DOM therefore got an empty/nil element (native returned `""`, and the
/// same read a moment later returned ~1.3 kB of text), which is the silent-empty
/// divergence this closes. Polling beats sleeping blind, and the wait must never
/// fail the navigation: on timeout, or on a CDP error while the execution
/// context is being swapped, the caller continues with what the document has.
fn wait_for_document_ready(rt: &tokio::runtime::Runtime, page: &Page) {
    let budget = settle_budget_ms();
    if budget == 0 {
        return;
    }
    let _ = rt.block_on(async {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget);
        loop {
            let ready = match page.evaluate_expression("document.readyState").await {
                Ok(v) => v
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| v.to_string()),
                // Not fatal: during a navigation the context can be mid-swap.
                Err(_) => String::new(),
            };
            if ready.contains("complete") {
                return;
            }
            if std::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });
}

/// Interpreter-side entry point so both runtimes navigate identically.
pub(crate) fn settle_page(rt: &tokio::runtime::Runtime, page: &Page) {
    wait_for_document_ready(rt, page);
}

/// Get the page title. Returns a C string (caller must free) or null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_title(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("title: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();

    match rt.block_on(page_ref.title()) {
        Ok(title) => string_to_cstr(&title),
        Err(e) => {
            set_last_error(format!("title: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get the current page URL. Returns a C string (caller must free) or null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_url(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("url: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();

    match rt.block_on(page_ref.url()) {
        Ok(url) => string_to_cstr(&url),
        Err(e) => {
            set_last_error(format!("url: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Out-parameter shape for `throttle_network`.
///
/// Written by the callee through a pointer rather than returned by value: a
/// 40-byte struct return is lowered indirectly by the ABI, and the first
/// attempt to consume it from generated LLVM segfaulted (measured, before any
/// output of the calling program). Writing into caller memory removes the
/// ABI question entirely. `ok == 0` means unknown preset or CDP failure.
#[repr(C)]
pub struct NetworkThrottleRaw {
    pub preset: *mut c_char,
    pub latency_ms: i64,
    pub download_kbps: i64,
    pub upload_kbps: i64,
    pub ok: i64,
}

/// Apply a named network profile, writing the result into `out`. Returns 0 when
/// a profile was applied, -1 otherwise (out then carries ok = 0). The preset
/// table is `browser::network_preset`, shared with the interpreter.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_throttle_network_preset(
    page: *mut c_void,
    preset: *mut c_char,
    out: *mut NetworkThrottleRaw,
) -> i32 {
    if out.is_null() {
        set_last_error("throttle_network: null out parameter".to_string());
        return -1;
    }
    let fail = |msg: String| {
        set_last_error(msg);
        unsafe {
            *out = NetworkThrottleRaw {
                preset: std::ptr::null_mut(),
                latency_ms: 0,
                download_kbps: 0,
                upload_kbps: 0,
                ok: 0,
            }
        };
        -1
    };
    if page.is_null() || preset.is_null() {
        return fail("throttle_network: null handle or preset".to_string());
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let preset_str = unsafe { std::ffi::CStr::from_ptr(preset) }
        .to_string_lossy()
        .to_string();
    let Some((down, up, latency)) = crate::browser::network_preset(&preset_str) else {
        return fail(format!(
            "throttle_network: unknown preset '{preset_str}' (slow-3g, fast-3g, 4g, none)"
        ));
    };
    let rt = get_runtime();
    match rt.block_on(page_ref.throttle_network(down, up, latency)) {
        Ok(()) => {
            unsafe {
                *out = NetworkThrottleRaw {
                    preset: string_to_cstr(&preset_str.trim().to_ascii_lowercase()),
                    latency_ms: latency as i64,
                    download_kbps: down as i64,
                    upload_kbps: up as i64,
                    ok: 1,
                }
            };
            0
        }
        Err(e) => fail(format!("throttle_network: {e}")),
    }
}

/// `Emulation.setEmulatedVisionDeficiency`. Empty means "none", matching the
/// interpreter. Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_emulate_vision(page: *mut c_void, deficiency: *mut c_char) -> i32 {
    if page.is_null() {
        set_last_error("emulate_vision: null page handle".to_string());
        return -1;
    }
    let deficiency = if deficiency.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(deficiency) }
            .to_string_lossy()
            .to_string()
    };
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.emulate_vision(&deficiency)) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("emulate_vision: {e}"));
            -1
        }
    }
}

/// `Emulation.setEmulatedMedia`. Empty strings take the same defaults the
/// interpreter uses ("screen", "light", "no-preference"). Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_emulate_media(
    page: *mut c_void,
    media_type: *mut c_char,
    color_scheme: *mut c_char,
    reduced_motion: *mut c_char,
) -> i32 {
    if page.is_null() {
        set_last_error("emulate_media: null page handle".to_string());
        return -1;
    }
    let read = |p: *mut c_char| {
        if p.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(p) }
                .to_string_lossy()
                .to_string()
        }
    };
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.emulate_media(
        &read(media_type),
        &read(color_scheme),
        &read(reduced_motion),
    )) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("emulate_media: {e}"));
            -1
        }
    }
}

/// Out-parameter shape for `wait_for_url`; `ok == 0` carries a failure whose
/// text is in `tallow_last_error`.
#[repr(C)]
pub struct WaitUrlRaw {
    pub found: i32,
    pub elapsed_ms: i64,
    pub url: *mut c_char,
    pub ok: i32,
}

/// Wait until the page URL matches `pattern`. `timeout_ms <= 0` means 30 s, the
/// stdlib default.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_wait_for_url(
    page: *mut c_void,
    pattern: *mut c_char,
    timeout_ms: i64,
    out: *mut WaitUrlRaw,
) -> i32 {
    if out.is_null() {
        set_last_error("wait_for_url: null out parameter".to_string());
        return -1;
    }
    let fail = |msg: String| {
        set_last_error(msg);
        unsafe {
            *out = WaitUrlRaw {
                found: 0,
                elapsed_ms: 0,
                url: std::ptr::null_mut(),
                ok: 0,
            }
        };
        -1
    };
    if page.is_null() || pattern.is_null() {
        return fail("wait_for_url: null handle or pattern".to_string());
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let pattern = unsafe { std::ffi::CStr::from_ptr(pattern) }
        .to_string_lossy()
        .to_string();
    if pattern.trim().is_empty() {
        return fail("wait_for_url requires a URL or pattern".to_string());
    }
    let timeout = if timeout_ms > 0 { timeout_ms as u64 } else { 30_000 };
    let rt = get_runtime();
    match rt.block_on(page_ref.wait_for_url(&pattern, std::time::Duration::from_millis(timeout))) {
        Ok((found, elapsed, url)) => {
            unsafe {
                *out = WaitUrlRaw {
                    found: if found { 1 } else { 0 },
                    elapsed_ms: elapsed as i64,
                    url: string_to_cstr(&url),
                    ok: 1,
                }
            };
            0
        }
        Err(e) => fail(format!("wait_for_url: {e}")),
    }
}

/// Out-parameter shape for `wait_for_function`.
#[repr(C)]
pub struct WaitFnRaw {
    pub found: i32,
    pub elapsed_ms: i64,
    pub ok: i32,
}

/// Wait until `js_expression` evaluates truthy. `timeout_ms <= 0` means 30 s.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_wait_for_function(
    page: *mut c_void,
    js_expression: *mut c_char,
    timeout_ms: i64,
    out: *mut WaitFnRaw,
) -> i32 {
    if out.is_null() {
        set_last_error("wait_for_function: null out parameter".to_string());
        return -1;
    }
    let fail = |msg: String| {
        set_last_error(msg);
        unsafe {
            *out = WaitFnRaw {
                found: 0,
                elapsed_ms: 0,
                ok: 0,
            }
        };
        -1
    };
    if page.is_null() || js_expression.is_null() {
        return fail("wait_for_function: null handle or expression".to_string());
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let js = unsafe { std::ffi::CStr::from_ptr(js_expression) }
        .to_string_lossy()
        .to_string();
    if js.trim().is_empty() {
        return fail("wait_for_function requires a JS expression".to_string());
    }
    let timeout = if timeout_ms > 0 { timeout_ms as u64 } else { 30_000 };
    let rt = get_runtime();
    match rt.block_on(page_ref.wait_for_function(&js, std::time::Duration::from_millis(timeout))) {
        Ok((found, elapsed)) => {
            unsafe {
                *out = WaitFnRaw {
                    found: if found { 1 } else { 0 },
                    elapsed_ms: elapsed as i64,
                    ok: 1,
                }
            };
            0
        }
        Err(e) => fail(format!("wait_for_function: {e}")),
    }
}

/// Out-parameter shape for `wait_for_event`; `method` is owned by the caller.
#[repr(C)]
pub struct WaitEventRaw {
    pub found: i32,
    pub elapsed_ms: i64,
    pub method: *mut c_char,
    pub ok: i32,
}

/// Wait for a CDP event on this page. `timeout_ms <= 0` means 30 s.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_wait_for_event(
    page: *mut c_void,
    event_name: *mut c_char,
    timeout_ms: i64,
    out: *mut WaitEventRaw,
) -> i32 {
    if out.is_null() {
        set_last_error("wait_for_event: null out parameter".to_string());
        return -1;
    }
    let fail = |msg: String| {
        set_last_error(msg);
        unsafe {
            *out = WaitEventRaw {
                found: 0,
                elapsed_ms: 0,
                method: std::ptr::null_mut(),
                ok: 0,
            }
        };
        -1
    };
    if page.is_null() || event_name.is_null() {
        return fail("wait_for_event: null handle or event name".to_string());
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let name = unsafe { std::ffi::CStr::from_ptr(event_name) }
        .to_string_lossy()
        .to_string();
    if name.trim().is_empty() {
        return fail("wait_for_event requires an event name".to_string());
    }
    let timeout = if timeout_ms > 0 { timeout_ms as u64 } else { 30_000 };
    let rt = get_runtime();
    match rt.block_on(page_ref.wait_for_event(&name, std::time::Duration::from_millis(timeout))) {
        Ok((found, elapsed, method)) => {
            unsafe {
                *out = WaitEventRaw {
                    found: if found { 1 } else { 0 },
                    elapsed_ms: elapsed as i64,
                    method: string_to_cstr(&method),
                    ok: 1,
                }
            };
            0
        }
        Err(e) => fail(format!("wait_for_event: {e}")),
    }
}

/// Out-parameter shape for `wait_for_request` / `wait_for_response`.
#[repr(C)]
pub struct WaitNetRaw {
    pub found: i32,
    pub elapsed_ms: i64,
    pub url: *mut c_char,
    pub ok: i32,
}

fn wait_net(
    page: *mut c_void,
    pattern: *mut c_char,
    timeout_ms: i64,
    out: *mut WaitNetRaw,
    which: u8,
) -> i32 {
    if out.is_null() {
        set_last_error("wait_for_network: null out parameter".to_string());
        return -1;
    }
    let fail = |msg: String| {
        set_last_error(msg);
        unsafe {
            *out = WaitNetRaw {
                found: 0,
                elapsed_ms: 0,
                url: std::ptr::null_mut(),
                ok: 0,
            }
        };
        -1
    };
    if page.is_null() || pattern.is_null() {
        return fail("wait_for_network: null handle or pattern".to_string());
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let pat = unsafe { std::ffi::CStr::from_ptr(pattern) }
        .to_string_lossy()
        .to_string();
    let timeout = if timeout_ms > 0 { timeout_ms as u64 } else { 30_000 };
    let dur = std::time::Duration::from_millis(timeout);
    let rt = get_runtime();
    let awaited = if which == 0 {
        rt.block_on(page_ref.wait_for_request(&pat, dur))
    } else {
        rt.block_on(page_ref.wait_for_response(&pat, dur))
    };
    match awaited {
        Ok((found, elapsed, url)) => {
            unsafe {
                *out = WaitNetRaw {
                    found: if found { 1 } else { 0 },
                    elapsed_ms: elapsed as i64,
                    url: string_to_cstr(&url),
                    ok: 1,
                }
            };
            0
        }
        Err(e) => fail(format!("wait_for_network: {e}")),
    }
}

/// Wait for a request whose URL matches `pattern`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_wait_for_request(
    page: *mut c_void,
    pattern: *mut c_char,
    timeout_ms: i64,
    out: *mut WaitNetRaw,
) -> i32 {
    wait_net(page, pattern, timeout_ms, out, 0)
}

/// Wait for a response whose URL matches `pattern`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_wait_for_response(
    page: *mut c_void,
    pattern: *mut c_char,
    timeout_ms: i64,
    out: *mut WaitNetRaw,
) -> i32 {
    wait_net(page, pattern, timeout_ms, out, 1)
}

/// Opt this page into console/error capture (`Runtime.enable`). Returns 0 on
/// success. Idempotent per session.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_capture_console(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("capture_console: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.enable_runtime_events()) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("capture_console: {e}"));
            -1
        }
    }
}

/// `Emulation.setCPUThrottlingRate`. Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_throttle_cpu(page: *mut c_void, rate: f64) -> i32 {
    if page.is_null() {
        set_last_error("throttle_cpu: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.throttle_cpu(rate)) {
        Ok(_applied) => 0,
        Err(e) => {
            set_last_error(format!("throttle_cpu: {e}"));
            -1
        }
    }
}

/// Add a `<style>` (URL or inline CSS). Returns the tag id; the CSS itself is
/// not part of `StyleTag`, which carries only id and kind.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_add_style_tag(page: *mut c_void, source: *mut c_char) -> *mut c_char {
    if page.is_null() || source.is_null() {
        set_last_error("add_style_tag: null handle or argument".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let source = unsafe { std::ffi::CStr::from_ptr(source) }
        .to_string_lossy()
        .to_string();
    let rt = get_runtime();
    match rt.block_on(page_ref.add_style_tag(&source)) {
        Ok((tag, _css)) => string_to_cstr(&tag),
        Err(e) => {
            set_last_error(format!("add_style_tag: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Inject a `<script>` (URL or inline source). Returns the tag id.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_add_script_tag(page: *mut c_void, source: *mut c_char) -> *mut c_char {
    if page.is_null() || source.is_null() {
        set_last_error("add_script_tag: null handle or argument".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let source = unsafe { std::ffi::CStr::from_ptr(source) }
        .to_string_lossy()
        .to_string();
    let rt = get_runtime();
    match rt.block_on(page_ref.add_script_tag(&source)) {
        Ok(tag) => string_to_cstr(&tag),
        Err(e) => {
            set_last_error(format!("add_script_tag: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Register a script that runs before every document load. Returns its identifier.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_add_init_script(page: *mut c_void, script: *mut c_char) -> *mut c_char {
    if page.is_null() || script.is_null() {
        set_last_error("add_init_script: null handle or argument".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let script = unsafe { std::ffi::CStr::from_ptr(script) }
        .to_string_lossy()
        .to_string();
    let rt = get_runtime();
    match rt.block_on(page_ref.add_init_script(&script)) {
        Ok(id) => string_to_cstr(&id),
        Err(e) => {
            set_last_error(format!("add_init_script: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Close this page's target. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_close(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("close: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.close()) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("close: {e}"));
            -1
        }
    }
}

/// The CDP target id behind this page.
///
/// `Page.goto` returns `NavigationResult { url, frame_id, status_code }`; the
/// native lowering builds that struct from this and `tallow_page_url` rather
/// than inventing values.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_frame_id(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("frame_id: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    string_to_cstr(&page_ref.frame_id)
}

/// Reload the current page. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_reload(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("reload: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();

    match rt.block_on(page_ref.reload(WaitUntil::DomContentLoaded)) {
        Ok(()) => {
            wait_for_document_ready(rt, page_ref);
            0
        }
        Err(e) => {
            set_last_error(format!("reload: {e}"));
            -1
        }
    }
}

// ── Element Queries ─────────────────────────────────────────────────────────

/// Query a single element by CSS selector. Returns an opaque element handle.
/// Returns null if no element matches or on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_query_selector(
    page: *mut c_void,
    selector: *const c_char,
) -> *mut c_void {
    if page.is_null() {
        set_last_error("query_selector: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let sel_str = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => {
            set_last_error("query_selector: null or invalid selector".to_string());
            return std::ptr::null_mut();
        }
    };
    let rt = get_runtime();

    match rt.block_on(page_ref.query_selector(sel_str)) {
        Ok(Some(el)) => {
            let el_handle = Box::new(el);
            Box::into_raw(el_handle) as *mut c_void
        }
        Ok(None) => std::ptr::null_mut(),
        Err(e) => {
            set_last_error(format!("query_selector: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Build a NATIVE tallow array from i64 slot values.
///
/// Native arrays are `[count: i64][elem0: i64][elem1: i64]...` — the layout the
/// emitted code reads (`ExprKind::Array` / `emit_for_loop` in `codegen.rs`):
/// `.len()` loads slot 0, `arr[i]` loads slot `i + 1`, and `for x in arr` walks
/// the count. Pointers go in bitcast to i64, exactly as a native string-array
/// literal stores its elements.
///
/// Shared by this module (CDP element arrays) and `runtime::html_ffi`. The
/// buffer is intentionally leaked: emitted code never frees array buffers
/// (`.push()` mallocs a fresh one and abandons the old), so the value has to
/// stay valid for the life of the program.
pub fn native_array(items: Vec<i64>) -> *mut c_void {
    let mut slots: Vec<i64> = Vec::with_capacity(items.len() + 1);
    slots.push(items.len() as i64);
    slots.extend(items);
    let boxed: Box<[i64]> = slots.into_boxed_slice();
    Box::into_raw(boxed) as *mut c_void
}

/// Query all elements matching a CSS selector. Returns a NATIVE array of
/// element handles (`[count][handle…]`, see `native_array`).
/// Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_query_selector_all(
    page: *mut c_void,
    selector: *const c_char,
) -> *mut c_void {
    if page.is_null() {
        set_last_error("query_selector_all: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let sel_str = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => {
            set_last_error("query_selector_all: null or invalid selector".to_string());
            return std::ptr::null_mut();
        }
    };
    let rt = get_runtime();

    match rt.block_on(page_ref.query_selector_all(sel_str)) {
        Ok(elements) => {
            // Native layout, not a `Box<Vec<*mut c_void>>` handle: the handle
            // shape only supported `.len()` — indexing and `for x in arr` read
            // the Vec header words as slots and leaked raw pointers as integers.
            let items: Vec<i64> = elements
                .into_iter()
                .map(|el| Box::into_raw(Box::new(el)) as i64)
                .collect();
            native_array(items)
        }
        Err(e) => {
            set_last_error(format!("query_selector_all: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Element Interaction ─────────────────────────────────────────────────────

/// Get the text content of an element. Caller must free with tallow_free_string().
/// Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_text(el: *mut c_void) -> *mut c_char {
    if el.is_null() {
        set_last_error("text: null element handle".to_string());
        return std::ptr::null_mut();
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();

    match rt.block_on(el_ref.text()) {
        Ok(text) => string_to_cstr(&text),
        Err(e) => {
            set_last_error(format!("text: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get the inner HTML of an element. Caller must free with tallow_free_string().
/// Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_inner_html(el: *mut c_void) -> *mut c_char {
    if el.is_null() {
        set_last_error("inner_html: null element handle".to_string());
        return std::ptr::null_mut();
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();

    match rt.block_on(el_ref.inner_html()) {
        Ok(html) => string_to_cstr(&html),
        Err(e) => {
            set_last_error(format!("inner_html: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get an attribute value from an element. Caller must free with tallow_free_string().
/// Returns null if the attribute doesn't exist or on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_attribute(
    el: *mut c_void,
    name: *const c_char,
) -> *mut c_char {
    if el.is_null() {
        set_last_error("attribute: null element handle".to_string());
        return std::ptr::null_mut();
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let attr_name = match unsafe { cstr_to_str(name) } {
        Some(s) => s,
        None => {
            set_last_error("attribute: null or invalid name".to_string());
            return std::ptr::null_mut();
        }
    };
    let rt = get_runtime();

    match rt.block_on(el_ref.attribute(attr_name)) {
        Ok(Some(val)) => string_to_cstr(&val),
        Ok(None) => std::ptr::null_mut(),
        Err(e) => {
            set_last_error(format!("attribute: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Click an element. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_click(el: *mut c_void) -> i32 {
    if el.is_null() {
        set_last_error("click: null element handle".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();

    match rt.block_on(el_ref.click(ClickOptions::default())) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("click: {e}"));
            -1
        }
    }
}

/// Type text into an element character by character.
/// `delay_ms`: delay between keystrokes in milliseconds (0 = no delay).
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_type_text(
    el: *mut c_void,
    text: *const c_char,
    delay_ms: i32,
) -> i32 {
    if el.is_null() {
        set_last_error("type_text: null element handle".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let text_str = match unsafe { cstr_to_str(text) } {
        Some(s) => s,
        None => {
            set_last_error("type_text: null or invalid text".to_string());
            return -1;
        }
    };
    let rt = get_runtime();
    let delay = if delay_ms > 0 {
        Some(delay_ms as u64)
    } else {
        None
    };

    match rt.block_on(el_ref.type_text(text_str, delay)) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("type_text: {e}"));
            -1
        }
    }
}

/// Free an element handle. Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_free(el: *mut c_void) {
    if !el.is_null() {
        unsafe {
            drop(Box::from_raw(el as *mut ElementHandle));
        }
    }
}

// ── Array Helpers (legacy handle shape) ─────────────────────────────────────
// NOTE: `tallow_page_query_selector_all` and the html/extract FFI no longer
// return `Box<Vec<*mut c_void>>` handles — they return NATIVE arrays
// (`native_array` above, `[count][elem…]`), which emitted code reads directly
// with `.len`/`arr[i]`/`for x in arr`. The three helpers below still interpret
// the old handle shape, so they must only be handed a handle built as
// `Box<Vec<*mut c_void>>` — never a native array.

/// Get the length of an element array handle (`Box<Vec<*mut c_void>>`).
/// Returns -1 if the handle is null. NOT valid on native arrays.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_array_len(arr: *mut c_void) -> i32 {
    if arr.is_null() {
        return -1;
    }
    let vec = unsafe { &*(arr as *const Vec<*mut c_void>) };
    vec.len() as i32
}

/// Get an element at index from an array. Does NOT remove it.
/// Returns null if index is out of bounds or array is null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_array_get(arr: *mut c_void, index: i32) -> *mut c_void {
    if arr.is_null() || index < 0 {
        return std::ptr::null_mut();
    }
    let vec = unsafe { &*(arr as *const Vec<*mut c_void>) };
    let idx = index as usize;
    if idx >= vec.len() {
        return std::ptr::null_mut();
    }
    vec[idx]
}

/// Free an element array and all elements it contains.
/// Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_array_free(arr: *mut c_void) {
    if arr.is_null() {
        return;
    }
    let vec = unsafe { Box::from_raw(arr as *mut Vec<*mut c_void>) };
    // Free each element in the array
    for ptr in vec.iter() {
        if !ptr.is_null() {
            unsafe {
                drop(Box::from_raw(*ptr as *mut ElementHandle));
            }
        }
    }
    // Vec is dropped automatically
}

// ── Page Content ──────────────────────────────────────────────────────────

/// Get the full page HTML content. Caller must free with tallow_free_string().
/// Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_content(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("page_content: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.evaluate_expression("document.documentElement.outerHTML")) {
        Ok(val) => string_to_cstr(val.as_str().unwrap_or("")),
        Err(e) => {
            set_last_error(format!("page_content: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// PII-redacted page text: `document.body.innerText` with emails, US SSNs,
/// 16-digit card numbers, phone numbers and IPv4 addresses replaced by stable
/// tokens (`[REDACTED_EMAIL]`, …).
///
/// Caller must free with `tallow_free_string()`. Returns null on error, with the
/// reason in `tallow_last_error()`.
///
/// Shares `stdlib::browser::redact_pii` with the interpreter's
/// `("Page","text_redacted")` arm — one implementation, two engines, so the two
/// cannot disagree about what was stripped.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_text_redacted(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("text_redacted: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.evaluate_expression("document.body ? document.body.innerText : ''")) {
        Ok(val) => {
            string_to_cstr(&crate::stdlib::browser::redact_pii(val.as_str().unwrap_or("")))
        }
        Err(e) => {
            set_last_error(format!("text_redacted: {e}"));
            std::ptr::null_mut()
        }
    }
}

// NOTE: `tallow_page_wait_stable` is NOT defined here — the runtime already
// implements it further down (signature `(ptr, u64, u64) -> i32`, delegating to
// `Page::wait_for_stable`). Adding a second definition is
// `E0428: defined multiple times` (caught by `cargo build`). The codegen arm
// `("Page","wait_for_stable")` calls the pre-existing one.

// NOTE: `tallow_page_block_non_essential` is NOT defined here. It already exists
// further down this file, alongside the other page-v2 FFIs, with this exact
// signature and behaviour — re-declaring it here was `E0428: defined multiple
// times` (caught by `cargo test --lib crawler`). The codegen arm
// `("Page","block_resources") | ("Page","block_non_essential")` calls that one.

/// Capture a CDP DOM snapshot (`DOMSnapshot.captureSnapshot`) as a JSON string.
///
/// Caller must free with `tallow_free_string()`. Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_dom_snapshot(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("dom_snapshot: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.capture_dom_snapshot()) {
        Ok(snapshot) => string_to_cstr(&snapshot.to_string()),
        Err(e) => {
            set_last_error(format!("dom_snapshot: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Extract structured data (JSON-LD / microdata) from the live page as a JSON
/// string. Caller must free with `tallow_free_string()`. Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_structured_data(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("structured_data: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.extract_structured_data()) {
        Ok(data) => string_to_cstr(&data.to_string()),
        Err(e) => {
            set_last_error(format!("structured_data: {e}"));
            std::ptr::null_mut()
        }
    }
}

// NOTE: `tallow_page_extract_all_text` is NOT defined here — the runtime already
// implements it in the Batch Extraction block below, and it returns a **JSON
// array string** (`*mut c_char`), not a native array. That is why the codegen arm
// for `("Page","extract_all_text")` is deliberately ABSENT: the declared Tallow
// return is `[]String` and the interpreter hands back a `Value::Array`, so a
// native arm returning a JSON string would diverge between engines. Unlowered
// means fail-loud → interpreter, which is the correct behaviour here.

/// Set the page HTML content. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_set_content(page: *mut c_void, html: *const c_char) -> i32 {
    if page.is_null() {
        set_last_error("set_content: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let html_str = match unsafe { cstr_to_str(html) } {
        Some(s) => s,
        None => {
            set_last_error("set_content: null or invalid html".to_string());
            return -1;
        }
    };
    let rt = get_runtime();
    // S3 (audit-05 F-4): serialize as a JSON string literal — a template
    // literal let a raw backtick / `${…}` in the payload escape into
    // executed JS. JSON escaping neutralizes backticks, backslashes, and
    // interpolation by construction (crate::browser::page::js_string_literal).
    match rt.block_on(page_ref.evaluate_expression(&format!(
        "document.documentElement.innerHTML = {};",
        crate::browser::page::js_string_literal(html_str)
    ))) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("set_content: {e}"));
            -1
        }
    }
}

// ── Screenshots ───────────────────────────────────────────────────────────

/// Capture a full-page screenshot as base64-encoded PNG.
/// Caller must free with tallow_free_string(). Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_screenshot(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("screenshot: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(crate::browser::visual::capture_screenshot(
        &page_ref.client,
        &page_ref.session_id,
    )) {
        Ok(png_bytes) => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&png_bytes);
            string_to_cstr(&b64)
        }
        Err(e) => {
            set_last_error(format!("screenshot: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Generate a PDF of the page as base64-encoded data.
/// Caller must free with tallow_free_string(). Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_pdf(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("pdf: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    let opts = crate::browser::visual::PdfOptions::default();
    match rt.block_on(crate::browser::visual::print_to_pdf(
        &page_ref.client,
        &page_ref.session_id,
        &opts,
    )) {
        Ok(pdf_bytes) => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&pdf_bytes);
            string_to_cstr(&b64)
        }
        Err(e) => {
            set_last_error(format!("pdf: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Cookies ───────────────────────────────────────────────────────────────

/// Get all cookies as a JSON array string.
/// Caller must free with tallow_free_string(). Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_get_cookies(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("get_cookies: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(crate::browser::session::get_cookies(
        &page_ref.client,
        &page_ref.session_id,
    )) {
        Ok(cookies) => {
            let json = serde_json::to_string(&cookies).unwrap_or_else(|_| "[]".to_string());
            string_to_cstr(&json)
        }
        Err(e) => {
            set_last_error(format!("get_cookies: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Clear all cookies. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_clear_cookies(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("clear_cookies: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(crate::browser::session::clear_cookies(
        &page_ref.client,
        &page_ref.session_id,
    )) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("clear_cookies: {e}"));
            -1
        }
    }
}

// ── Emulation ─────────────────────────────────────────────────────────────

/// Set viewport size and device scale factor. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_set_viewport(
    page: *mut c_void,
    width: i32,
    height: i32,
    scale: f64,
) -> i32 {
    if page.is_null() {
        set_last_error("set_viewport: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(crate::browser::emulation::set_viewport(
        &page_ref.client,
        &page_ref.session_id,
        width as u32,
        height as u32,
        scale,
        false,
    )) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("set_viewport: {e}"));
            -1
        }
    }
}

/// Override user-agent string. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_set_user_agent(page: *mut c_void, ua: *const c_char) -> i32 {
    if page.is_null() {
        set_last_error("set_user_agent: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let ua_str = match unsafe { cstr_to_str(ua) } {
        Some(s) => s,
        None => {
            set_last_error("set_user_agent: null or invalid user-agent".to_string());
            return -1;
        }
    };
    let rt = get_runtime();
    match rt.block_on(crate::browser::emulation::set_user_agent(
        &page_ref.client,
        &page_ref.session_id,
        ua_str,
        "",   // platform — empty means unset
        "",   // accept-language — empty means unset
    )) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("set_user_agent: {e}"));
            -1
        }
    }
}

/// Override geolocation coordinates. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_set_geolocation(
    page: *mut c_void,
    lat: f64,
    lon: f64,
    accuracy: f64,
) -> i32 {
    if page.is_null() {
        set_last_error("set_geolocation: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(crate::browser::emulation::set_geolocation(
        &page_ref.client,
        &page_ref.session_id,
        lat,
        lon,
        accuracy,
    )) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("set_geolocation: {e}"));
            -1
        }
    }
}

// ── Element Operations ────────────────────────────────────────────────────

/// Get the outer HTML of an element. Caller must free with tallow_free_string().
/// Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_outer_html(el: *mut c_void) -> *mut c_char {
    if el.is_null() {
        set_last_error("outer_html: null element handle".to_string());
        return std::ptr::null_mut();
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.outer_html()) {
        Ok(html) => string_to_cstr(&html),
        Err(e) => {
            set_last_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Get the tag name of an element. Caller must free with tallow_free_string().
/// Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_tag_name(el: *mut c_void) -> *mut c_char {
    if el.is_null() {
        set_last_error("tag_name: null element handle".to_string());
        return std::ptr::null_mut();
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.tag_name()) {
        Ok(name) => string_to_cstr(&name),
        Err(e) => {
            set_last_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Computed style value of `property` on an element (e.g. `"display"`).
/// Caller must free with `tallow_free_string()`. Returns null on error.
///
/// Mirrors `ElementHandle::computed_style`, whose `Result<String>` yields `Ok("")`
/// for a property the browser does not report. `property()` is deliberately NOT
/// lowered alongside it: that one returns `Option<String>`, and the interpreter
/// prints the absent case as a bare `nil`, which has no `Ok`/`Err` shape.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_computed_style(
    el: *mut c_void,
    property: *const c_char,
) -> *mut c_char {
    if el.is_null() {
        set_last_error("computed_style: null element handle".to_string());
        return std::ptr::null_mut();
    }
    let Some(property) = (unsafe { cstr_to_str(property) }) else {
        set_last_error("computed_style: expected a property name string".to_string());
        return std::ptr::null_mut();
    };
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.computed_style(&property)) {
        Ok(value) => string_to_cstr(&value),
        Err(e) => {
            set_last_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Get the bounding box of an element. Writes to x, y, w, h pointers.
/// Returns 0 on success, -1 on error or if element is not visible.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_bounding_box(
    el: *mut c_void,
    x: *mut f64,
    y: *mut f64,
    w: *mut f64,
    h: *mut f64,
) -> i32 {
    if el.is_null() || x.is_null() || y.is_null() || w.is_null() || h.is_null() {
        set_last_error("bounding_box: null argument".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.bounding_box()) {
        Ok(Some(bb)) => {
            unsafe {
                *x = bb.x;
                *y = bb.y;
                *w = bb.width;
                *h = bb.height;
            }
            0
        }
        Ok(None) => {
            set_last_error("bounding_box: element not visible".to_string());
            -1
        }
        Err(e) => {
            set_last_error(format!("bounding_box: {e}"));
            -1
        }
    }
}

/// Focus an element. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_focus(el: *mut c_void) -> i32 {
    if el.is_null() {
        set_last_error("focus: null element handle".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.focus()) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Move the mouse over an element (a real hover, so hover-only CSS and menus
/// respond). Returns 0 on success, -1 on error with `tallow_last_error` set.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_hover(el: *mut c_void) -> i32 {
    if el.is_null() {
        set_last_error("hover: null element handle".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.hover()) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Wait until the element is actionable (visible, stable, enabled, receives
/// events). `timeout_ms` is passed explicitly — the default (30000) lives in both
/// callers, the interpreter arm and the codegen arm, so an omitted argument cannot
/// diverge. Returns 0 on success, -1 on error with `tallow_last_error` set.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_wait_for_actionable(el: *mut c_void, timeout_ms: i64) -> i32 {
    if el.is_null() {
        set_last_error("wait_for_actionable: null element handle".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    let budget = std::time::Duration::from_millis(timeout_ms.max(0) as u64);
    match rt.block_on(el_ref.wait_for_actionable(budget)) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Select an option by its **value** (`SelectBy::Value`), matching the
/// interpreter arm exactly. Returns 0 on success, -1 on error with
/// `tallow_last_error` set.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_select_option(el: *mut c_void, value: *const c_char) -> i32 {
    if el.is_null() {
        set_last_error("select_option: null element handle".to_string());
        return -1;
    }
    let Some(value) = (unsafe { cstr_to_str(value) }) else {
        set_last_error("select_option: expected an option value string".to_string());
        return -1;
    };
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.select_option(crate::browser::SelectBy::Value(value.to_string()))) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// `upload_files(path)` / `upload_files([p1, p2])`. `paths` is either a single C
/// string (`is_array == 0`) or a native array of C strings (`is_array != 0`, slot 0
/// = count, slots 1.. = the strings), which is the layout `native_array` builds.
/// Returns 0 on success, -1 on error with `tallow_last_error` set.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_upload_files(
    el: *mut c_void,
    paths: *mut c_void,
    is_array: i32,
) -> i32 {
    if el.is_null() {
        set_last_error("upload_files: null element handle".to_string());
        return -1;
    }
    if paths.is_null() {
        set_last_error("upload_files: expected a path or an array of paths".to_string());
        return -1;
    }
    let mut owned: Vec<String> = Vec::new();
    if is_array == 0 {
        let Some(p) = (unsafe { cstr_to_str(paths as *const c_char) }) else {
            set_last_error("upload_files: expected a path string".to_string());
            return -1;
        };
        owned.push(p.to_string());
    } else {
        let count = unsafe { *(paths as *const i64) };
        for i in 0..count.max(0) {
            let slot = unsafe { *((paths as *const i64).add(1 + i as usize)) } as *const c_char;
            let Some(p) = (unsafe { cstr_to_str(slot) }) else {
                set_last_error("upload_files: non-string entry in the path array".to_string());
                return -1;
            };
            owned.push(p.to_string());
        }
    }
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.upload_files(&refs)) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Clear an input element's value. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_clear(el: *mut c_void) -> i32 {
    if el.is_null() {
        set_last_error("clear: null element handle".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.clear()) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Scroll an element into view. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_scroll_into_view(el: *mut c_void) -> i32 {
    if el.is_null() {
        set_last_error("scroll_into_view: null element handle".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.scroll_into_view()) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Clear the CDP device-metrics override, reverting to the browser default viewport.
/// Returns 0 on success, -1 on error with `tallow_last_error` set.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_clear_device_metrics(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("clear_device_metrics: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(crate::browser::emulation::clear_device_metrics(
        &page_ref.client,
        &page_ref.session_id,
    )) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Clear the CDP geolocation override, reverting to the browser's real location.
/// Returns 0 on success, -1 on error with `tallow_last_error` set.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_clear_geolocation(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("clear_geolocation: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(crate::browser::emulation::clear_geolocation(
        &page_ref.client,
        &page_ref.session_id,
    )) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Apply the page's stealth evasions (webdriver flag, plugins, WebGL, ...).
/// Returns 0 on success, -1 on error with `tallow_last_error` set.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_apply_stealth_evasions(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("apply_stealth_evasions: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.apply_stealth_evasions()) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Build the plugin set for `block_ads` / `block_trackers` and apply it, returning the
/// interpreter's exact success message. Returns null (with `tallow_last_error`) only for
/// a null page handle: the plugin work itself ignores errors, matching the interpreter,
/// so the native value is the message whenever the handle is valid.
fn apply_page_plugins(page: *mut c_void, adblock: bool, message: &str) -> *mut c_char {
    if page.is_null() {
        set_last_error(format!("{}: null page handle", message));
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let mut plugins = crate::browser::plugins::BrowserPlugins::none();
    if adblock {
        plugins.adblock = true;
    } else {
        plugins.tracker_block = true;
    }
    let rt = get_runtime();
    // Same shipped helper the interpreter arm now uses; errors ignored for parity.
    let _ = rt.block_on(crate::browser::plugins::apply_plugins(
        &plugins,
        &page_ref.client,
        &page_ref.session_id,
    ));
    string_to_cstr(message)
}

/// `Page.block_ads()` — interpreter shape: a bare String ("AdBlock enabled").
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_block_ads(page: *mut c_void) -> *mut c_char {
    apply_page_plugins(page, true, "AdBlock enabled")
}

/// `Page.block_trackers()` — interpreter shape: a bare String ("TrackerBlock enabled").
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_block_trackers(page: *mut c_void) -> *mut c_char {
    apply_page_plugins(page, false, "TrackerBlock enabled")
}

/// `Page.disable_adblock()` — interpreter shape: a bare String. Mirrors the interpreter
/// exactly, INCLUDING its current limitation: plugin state is not persisted on the page,
/// so this cannot actually undo a previous `block_ads` (see its in-tree note in the
/// interpreter). Parity first; fixing the fake is tracked separately.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_disable_adblock(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("disable_adblock: null page handle".to_string());
        return std::ptr::null_mut();
    }
    string_to_cstr("AdBlock disabled for this page")
}

/// `Element.property(name)` — tri-state so the caller can rebuild the interpreter's
/// `Ok(String) | nil` union: returns 0 with `*out_value` set when the property exists,
/// 1 when it does not, and -1 with `tallow_last_error` set on failure. A plain status
/// return could not distinguish "absent" from "empty string".
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_property(
    el: *mut c_void,
    key: *const c_char,
    out_value: *mut *mut c_char,
) -> i32 {
    if el.is_null() || key.is_null() || out_value.is_null() {
        set_last_error("property: null handle, key or out-parameter".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let name = match unsafe { cstr_to_str(key) } {
        Some(s) => s,
        None => {
            set_last_error("property: null or invalid property name".to_string());
            return -1;
        }
    };
    let rt = get_runtime();
    match rt.block_on(el_ref.property(name)) {
        Ok(Some(val)) => {
            unsafe { *out_value = string_to_cstr(&val) };
            0
        }
        Ok(None) => 1,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// `Page.simulate_human_session()` — Result<()>, the void-family rc pair.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_simulate_human_session(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("simulate_human_session: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.simulate_human_session()) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// `Page.dom_get_title()` — Result<String>: a C string on success, null + last_error
/// on failure, which `wrap_ptr_in_result` turns into the Ok/Err pair.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_dom_get_title(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("dom_get_title: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.dom_get_title()) {
        Ok(title) => string_to_cstr(&title),
        Err(e) => {
            set_last_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// `Page.max_privacy()` — builds the max-privacy plugin set and applies it through the
/// shared helper, returning the interpreter's bare String. Errors inside the plugin
/// application are ignored for parity, exactly as in the blocker FFIs.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_max_privacy(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("max_privacy: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let plugins = crate::browser::plugins::BrowserPlugins::max_privacy();
    let rt = get_runtime();
    let _ = rt.block_on(crate::browser::plugins::apply_plugins(
        &plugins,
        &page_ref.client,
        &page_ref.session_id,
    ));
    // Same construction as the interpreter arm: `BrowserPlugins::summary()`.
    string_to_cstr(&plugins.summary())
}

/// Whether the element is visible. Returns 1 for true, 0 for false, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_is_visible(el: *mut c_void) -> i32 {
    if el.is_null() {
        set_last_error("is_visible: null element handle".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.is_visible()) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Check if an element is enabled. Returns 1 if enabled, 0 if disabled, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_element_is_enabled(el: *mut c_void) -> i32 {
    if el.is_null() {
        set_last_error("is_enabled: null element handle".to_string());
        return -1;
    }
    let el_ref = unsafe { &*(el as *const ElementHandle) };
    let rt = get_runtime();
    match rt.block_on(el_ref.is_enabled()) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            set_last_error(format!("is_enabled: {e}"));
            -1
        }
    }
}

// ── Batch Extraction ──────────────────────────────────────────────────────

/// Extract text from all elements matching a selector. Returns JSON array string.
/// Caller must free with tallow_free_string(). Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_extract_all_text(
    page: *mut c_void,
    selector: *const c_char,
) -> *mut c_char {
    if page.is_null() {
        set_last_error("extract_all_text: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let sel = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => {
            set_last_error("extract_all_text: null or invalid selector".to_string());
            return std::ptr::null_mut();
        }
    };
    let rt = get_runtime();
    match rt.block_on(page_ref.extract_all_text(sel)) {
        Ok(texts) => {
            let json = serde_json::to_string(&texts).unwrap_or_else(|_| "[]".to_string());
            string_to_cstr(&json)
        }
        Err(e) => {
            set_last_error(format!("extract_all_text: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── JavaScript Evaluation ─────────────────────────────────────────────────

/// Evaluate a JavaScript expression on the page. Returns result as string.
/// Caller must free with tallow_free_string(). Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_evaluate(
    page: *mut c_void,
    expression: *const c_char,
) -> *mut c_char {
    if page.is_null() {
        set_last_error("evaluate: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let expr = match unsafe { cstr_to_str(expression) } {
        Some(s) => s,
        None => {
            set_last_error("evaluate: null or invalid expression".to_string());
            return std::ptr::null_mut();
        }
    };
    let rt = get_runtime();
    match rt.block_on(page_ref.evaluate_expression(expr)) {
        Ok(val) => string_to_cstr(&val.to_string()),
        Err(e) => {
            set_last_error(format!("evaluate: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Accessibility ─────────────────────────────────────────────────────────

/// Get the accessibility tree as a JSON string.
/// Caller must free with tallow_free_string(). Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_accessibility_tree(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("accessibility_tree: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(crate::browser::accessibility::get_accessibility_tree(
        &page_ref.client,
        &page_ref.session_id,
    )) {
        Ok(tree) => {
            let json = serde_json::to_string(&tree).unwrap_or_else(|_| "[]".to_string());
            string_to_cstr(&json)
        }
        Err(e) => {
            set_last_error(format!("accessibility_tree: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── CAPTCHA Detection ─────────────────────────────────────────────────────

/// Detect CAPTCHA on the current page. Returns JSON object string or "null" if none.
/// Caller must free with tallow_free_string(). Returns null ptr on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_detect_captcha(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("detect_captcha: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(crate::browser::captcha::detect_captcha(
        &page_ref.client,
        &page_ref.session_id,
    )) {
        Ok(Some(info)) => {
            let json = format!(
                r#"{{"type":"{}","site_key":{},"selector":"{}"}}"#,
                info.captcha_type,
                info.site_key
                    .as_ref()
                    .map(|k| format!("\"{}\"", k.replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string()),
                info.element_selector.replace('"', "\\\""),
            );
            string_to_cstr(&json)
        }
        Ok(None) => string_to_cstr("null"),
        Err(e) => {
            set_last_error(format!("detect_captcha: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Stealth ───────────────────────────────────────────────────────────────

/// Apply a Chrome/Windows stealth profile to the page. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_apply_stealth(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("apply_stealth: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    let profile = crate::browser::stealth::StealthProfile::chrome_windows();
    match rt.block_on(page_ref.apply_stealth(&profile)) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("apply_stealth: {e}"));
            -1
        }
    }
}

// ── Frames ────────────────────────────────────────────────────────────────

/// Enter an iframe by CSS selector. Returns a new page handle scoped to the iframe.
/// Returns null on error. Free with `tallow_page_free`, NOT `tallow_browser_close`
/// (which only frees Browser handles — calling it on a Page would corrupt memory).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_enter_iframe(
    page: *mut c_void,
    selector: *const c_char,
) -> *mut c_void {
    if page.is_null() {
        set_last_error("enter_iframe: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let sel = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => {
            set_last_error("enter_iframe: null or invalid selector".to_string());
            return std::ptr::null_mut();
        }
    };
    let rt = get_runtime();
    match rt.block_on(page_ref.enter_iframe(sel)) {
        Ok(iframe_page) => Box::into_raw(Box::new(iframe_page)) as *mut c_void,
        Err(e) => {
            set_last_error(format!("enter_iframe: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Resource Blocking ─────────────────────────────────────────────────────

/// Block non-essential resources (images, fonts, media). Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_block_resources(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("block_resources: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.block_non_essential()) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("block_resources: {e}"));
            -1
        }
    }
}

// ── Cookie Consent ────────────────────────────────────────────────────────

/// Handle a cookie consent banner.
/// `strategy`: 0 = reject non-essential, 1 = accept all, 2 = dismiss.
/// Returns 1 if banner found and handled, 0 if no banner found, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_handle_cookie_consent(page: *mut c_void, strategy: i32) -> i32 {
    if page.is_null() {
        set_last_error("handle_cookie_consent: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let strat = match strategy {
        0 => CookieConsentStrategy::RejectNonEssential,
        1 => CookieConsentStrategy::AcceptAll,
        _ => CookieConsentStrategy::Dismiss,
    };
    let rt = get_runtime();
    match rt.block_on(page_ref.handle_cookie_consent(strat)) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            set_last_error(format!("handle_cookie_consent: {e}"));
            -1
        }
    }
}

/// Handle a cookie-consent banner, dispatching on the Tallow-level strategy
/// **string** (`accept`/`accept_all` → AcceptAll, `dismiss` → Dismiss, anything
/// else → RejectNonEssential).
///
/// String-parameter sibling of `tallow_page_handle_cookie_consent`, which takes
/// the numeric code: both delegate to the same `Page::handle_cookie_consent` and
/// share the one mapping in `stdlib::browser::consent_strategy`, so the two entry
/// points cannot disagree about what a strategy name means. The native codegen arm
/// calls THIS one, because the Tallow declaration takes a `String`.
///
/// Returns 1 if a banner was handled, 0 if none, -1 on error.
#[unsafe(no_mangle)]
/// Out-parameter payload for `authenticated_get` / `authenticated_request`.
#[repr(C)]
pub struct AuthenticatedRaw {
    pub status: i64,
    pub body: *mut c_char,
}

/// `Page.authenticated_request(url, method, body)`: HTTP with the browser's
/// cookies attached, egressing through the same contract as the browser zone.
/// The tuple returned by `Page::authenticated_request` is marshalled into a
/// flat out-parameter so the native plane can build `AuthenticatedResponse`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_authenticated_request(
    page: *mut c_void,
    url: *const c_char,
    method: *const c_char,
    body: *const c_char,
    out: *mut AuthenticatedRaw,
) -> i32 {
    if out.is_null() {
        set_last_error("authenticated_request: null out parameter".to_string());
        return -1;
    }
    let fail = |msg: String| {
        set_last_error(msg);
        unsafe {
            (*out).status = 0;
            (*out).body = std::ptr::null_mut();
        }
        -1
    };
    if page.is_null() {
        return fail("authenticated_request: null page handle".to_string());
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let url_str = match unsafe { cstr_to_str(url) } {
        Some(s) => s.to_string(),
        None => return fail("authenticated_request: null or invalid url".to_string()),
    };
    let method_str = unsafe { cstr_to_str(method) }.unwrap_or("GET").to_string();
    let body_str = unsafe { cstr_to_str(body) }.unwrap_or("").to_string();
    let rt = get_runtime();
    match rt.block_on(page_ref.authenticated_request(&url_str, &method_str, &body_str)) {
        Ok((status, response_body)) => {
            unsafe {
                (*out).status = status as i64;
                (*out).body = string_to_cstr(&response_body);
            }
            0
        }
        Err(e) => fail(format!("authenticated_request: {e}")),
    }
}

/// `Page.cookie_string(url)`: the Cookie header for that URL. Returns a C string
/// (caller must free) or null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_cookie_string(
    page: *mut c_void,
    url: *const c_char,
) -> *mut c_char {
    if page.is_null() {
        set_last_error("cookie_string: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let url_str = match unsafe { cstr_to_str(url) } {
        Some(s) => s.to_string(),
        None => {
            set_last_error("cookie_string: null or invalid url".to_string());
            return std::ptr::null_mut();
        }
    };
    let rt = get_runtime();
    match rt.block_on(page_ref.cookie_string(&url_str)) {
        Ok(header) => string_to_cstr(&header),
        Err(e) => {
            set_last_error(format!("cookie_string: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// `Page.set_cookies_from_header(header, domain, path)`: parse a Set-Cookie style
/// header and install each cookie for the domain.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_set_cookies_from_header(
    page: *mut c_void,
    header: *const c_char,
    domain: *const c_char,
    path: *const c_char,
) -> i32 {
    if page.is_null() {
        set_last_error("set_cookies_from_header: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let header_str = match unsafe { cstr_to_str(header) } {
        Some(s) => s.to_string(),
        None => {
            set_last_error("set_cookies_from_header: null or invalid header".to_string());
            return -1;
        }
    };
    let domain_str = match unsafe { cstr_to_str(domain) } {
        Some(s) => s.to_string(),
        None => {
            set_last_error("set_cookies_from_header: null or invalid domain".to_string());
            return -1;
        }
    };
    let path_str = unsafe { cstr_to_str(path) }.unwrap_or("/").to_string();
    let rt = get_runtime();
    match rt.block_on(page_ref.set_cookies_from_header(&header_str, &domain_str, &path_str)) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("set_cookies_from_header: {e}"));
            -1
        }
    }
}

/// `Page.select(selector, option, by)`: select an `<option>` by value, index or
/// visible label. `by` is the same three-way name the stdlib signature exposes,
/// resolved here so both planes agree on what an unknown name means (a loud
/// error, not a silent default).
pub extern "C" fn tallow_page_select(
    page: *mut c_void,
    selector: *const c_char,
    option: *const c_char,
    by: *const c_char,
) -> i32 {
    if page.is_null() {
        set_last_error("select: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let selector_str = match unsafe { cstr_to_str(selector) } {
        Some(s) => s.to_string(),
        None => {
            set_last_error("select: null or invalid selector".to_string());
            return -1;
        }
    };
    let option_str = match unsafe { cstr_to_str(option) } {
        Some(s) => s.to_string(),
        None => {
            set_last_error("select: null or invalid option".to_string());
            return -1;
        }
    };
    let by_str = unsafe { cstr_to_str(by) }
        .unwrap_or("value")
        .to_ascii_lowercase();
    let select_by = match by_str.as_str() {
        "value" => crate::browser::interaction::SelectBy::Value(option_str.clone()),
        "label" => crate::browser::interaction::SelectBy::Label(option_str.clone()),
        "index" => match option_str.trim().parse::<usize>() {
            Ok(n) => crate::browser::interaction::SelectBy::Index(n),
            Err(_) => {
                set_last_error(format!("select: index `{option_str}` is not a number"));
                return -1;
            }
        },
        other => {
            set_last_error(format!(
                "select: unknown `by` value `{other}` (expected value, label or index)"
            ));
            return -1;
        }
    };
    let rt = get_runtime();
    let outcome = rt.block_on(async {
        let el = page_ref
            .query_selector(&selector_str)
            .await
            .map_err(|e| format!("select: {e}"))?
            .ok_or_else(|| format!("select: no element matches `{selector_str}`"))?;
        el.select_option(select_by)
            .await
            .map_err(|e| format!("select: {e}"))
    });
    match outcome {
        Ok(()) => 0,
        Err(message) => {
            set_last_error(message);
            -1
        }
    }
}

/// `Page.fill(selector, value)`: query the element, clear it, then type the
/// value. Composition of existing ElementHandle operations — no new CDP code —
/// so the interpreted and native planes cannot diverge on what "fill" means.
pub extern "C" fn tallow_page_fill(
    page: *mut c_void,
    selector: *const c_char,
    text: *const c_char,
) -> i32 {
    if page.is_null() {
        set_last_error("fill: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let selector_str = match unsafe { cstr_to_str(selector) } {
        Some(s) => s.to_string(),
        None => {
            set_last_error("fill: null or invalid selector".to_string());
            return -1;
        }
    };
    let text_str = match unsafe { cstr_to_str(text) } {
        Some(s) => s.to_string(),
        None => {
            set_last_error("fill: null or invalid text".to_string());
            return -1;
        }
    };
    let rt = get_runtime();
    let outcome = rt.block_on(async {
        let el = page_ref
            .query_selector(&selector_str)
            .await
            .map_err(|e| format!("fill: {e}"))?
            .ok_or_else(|| format!("fill: no element matches `{selector_str}`"))?;
        el.clear().await.map_err(|e| format!("fill(clear): {e}"))?;
        el.type_text(&text_str, None)
            .await
            .map_err(|e| format!("fill(type): {e}"))
    });
    match outcome {
        Ok(()) => 0,
        Err(message) => {
            set_last_error(message);
            -1
        }
    }
}

pub extern "C" fn tallow_page_handle_cookie_consent_str(
    page: *mut c_void,
    strategy: *const c_char,
) -> i32 {
    if page.is_null() {
        set_last_error("handle_cookie_consent: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let strat = match unsafe { cstr_to_str(strategy) } {
        Some(s) => crate::stdlib::browser::consent_strategy(s),
        None => {
            set_last_error("handle_cookie_consent: null or invalid strategy".to_string());
            return -1;
        }
    };
    let rt = get_runtime();
    match rt.block_on(page_ref.handle_cookie_consent(strat)) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            set_last_error(format!("handle_cookie_consent: {e}"));
            -1
        }
    }
}

/// Native-array sibling of `tallow_page_extract_all_text` (which returns a JSON
/// string): builds a `[count][cstr…]` array via `native_array`, the shape the
/// declared `[]String` requires. Both call the one `Page::extract_all_text`, so
/// the extraction logic has a single implementation and the two FFIs differ only
/// in the value shape they hand back.
///
/// Each element is a C string pointer bitcast into an i64 slot — the shape a
/// native `[]String` literal has. The buffer and the element strings are leaked,
/// like every other native array this runtime hands out. Null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_extract_all_text_array(
    page: *mut c_void,
    selector: *const c_char,
) -> *mut c_void {
    if page.is_null() {
        set_last_error("extract_all_text: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let sel = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => {
            set_last_error("extract_all_text: null or invalid selector".to_string());
            return std::ptr::null_mut();
        }
    };
    let rt = get_runtime();
    match rt.block_on(page_ref.extract_all_text(sel)) {
        Ok(texts) => {
            let items: Vec<i64> = texts
                .into_iter()
                .map(|t| string_to_cstr(&t) as i64)
                .collect();
            native_array(items)
        }
        Err(e) => {
            set_last_error(format!("extract_all_text: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Write the detected pagination into caller-provided out-params. Codegen owns the
/// struct layout, so the runtime never allocates a struct whose layout it would
/// have to guess (the out-params doctrine).
///
/// Returns 1 when a pattern was found, 0 when none, -1 on error (message in
/// `tallow_last_error`). `strategy` / `next_url` are C strings (`next_url` stays
/// null when the pattern has no next link); `total_links` is written as an **i64**
/// — the native value model's int width; an i32 field does not read back as an
/// integer at display time.
///
/// Sibling of `tallow_page_detect_pagination`, which returns a JSON string: that
/// one cannot serve the declared `PaginationInfo?`. Both share the one
/// `Page::detect_pagination` call.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_detect_pagination_fields(
    page: *mut c_void,
    strategy_out: *mut *mut c_char,
    next_url_out: *mut *mut c_char,
    total_links_out: *mut i64,
) -> i32 {
    if page.is_null() {
        set_last_error("detect_pagination: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.detect_pagination()) {
        Ok(Some(info)) => {
            unsafe {
                if !strategy_out.is_null() {
                    *strategy_out = string_to_cstr(&info.strategy);
                }
                if !next_url_out.is_null() {
                    *next_url_out = match &info.next_url {
                        Some(u) => string_to_cstr(u),
                        None => std::ptr::null_mut(),
                    };
                }
                if !total_links_out.is_null() {
                    *total_links_out = info.total_links as i64;
                }
            }
            1
        }
        Ok(None) => 0,
        Err(e) => {
            set_last_error(format!("detect_pagination: {e}"));
            -1
        }
    }
}

// ── Wait Stable ───────────────────────────────────────────────────────────

/// Wait for the page to become stable (no DOM mutations).
/// `timeout_ms`: max time to wait. `quiesce_ms`: quiet period before declaring stable.
/// Returns 0 on success, -1 on timeout/error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_wait_stable(
    page: *mut c_void,
    timeout_ms: u64,
    quiesce_ms: u64,
) -> i32 {
    if page.is_null() {
        set_last_error("wait_stable: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.wait_for_stable(
        std::time::Duration::from_millis(timeout_ms),
        quiesce_ms,
    )) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("wait_stable: {e}"));
            -1
        }
    }
}

// ── Pagination Detection ──────────────────────────────────────────────────

/// Detect pagination on the current page. Returns JSON object or "null".
/// Caller must free with tallow_free_string(). Returns null ptr on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_detect_pagination(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("detect_pagination: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    match rt.block_on(page_ref.detect_pagination()) {
        Ok(Some(info)) => {
            let json = format!(
                r#"{{"strategy":"{}","next_url":{},"total_links":{}}}"#,
                info.strategy.replace('"', "\\\""),
                info.next_url
                    .as_ref()
                    .map(|u| format!("\"{}\"", u.replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string()),
                info.total_links,
            );
            string_to_cstr(&json)
        }
        Ok(None) => string_to_cstr("null"),
        Err(e) => {
            set_last_error(format!("detect_pagination: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Console Messages (Gap 1) ──────────────────────────────────────────────

/// Get all console messages as a JSON array string.
/// Each element: `{"level":"log","text":"...","timestamp":1234567.89}`.
/// Caller must free with tallow_free_string(). Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_console_messages(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("console_messages: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    let msgs = rt.block_on(page_ref.console_messages());
    let json = serde_json::to_string(
        &msgs.iter().map(|m| {
            serde_json::json!({
                "level": m.level,
                "text": m.text,
                "timestamp": m.timestamp,
            })
        }).collect::<Vec<_>>()
    ).unwrap_or_else(|_| "[]".to_string());
    string_to_cstr(&json)
}

/// Clear all captured console messages. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_clear_console(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("clear_console: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    rt.block_on(page_ref.clear_console());
    0
}

// ── 4K Video Recording ────────────────────────────────────────────────────

/// Start recording the page as a video.
///
/// Parameters:
/// - `width`  — frame width in pixels (0 = use default 3840).
/// - `height` — frame height in pixels (0 = use default 2160).
/// - `fps`    — frames per second (0 = use default 30).
/// - `quality`— JPEG quality 1–100 (0 = use default 90).
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_start_recording(
    page: *mut c_void,
    width: i32,
    height: i32,
    fps: i32,
    quality: i32,
) -> i32 {
    if page.is_null() {
        set_last_error("start_recording: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();

    let config = crate::browser::RecordingConfig {
        width:   if width  > 0 { width  as u32 } else { 3840 },
        height:  if height > 0 { height as u32 } else { 2160 },
        fps:     if fps    > 0 { fps    as u32 } else { 30 },
        quality: if quality > 0 { (quality as u32).min(100) } else { 90 },
        ..Default::default()
    };

    match rt.block_on(page_ref.start_recording(config)) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("start_recording: {e}"));
            -1
        }
    }
}

/// Stop recording and save the video.
///
/// `output_path` — path for the output file (e.g. `"out.mp4"`).
///
/// Returns an opaque `RecordingResult` handle on success (free with
/// `tallow_recording_result_free`), or null on error.
///
/// Fields are accessed via:
/// - `tallow_recording_result_frame_count`
/// - `tallow_recording_result_duration_secs`
/// - `tallow_recording_result_file_size`
/// - `tallow_recording_result_output_path`
/// - `tallow_recording_result_resolution`
/// - `tallow_recording_result_encoding`
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_stop_recording(
    page: *mut c_void,
    output_path: *const c_char,
) -> *mut c_void {
    if page.is_null() {
        set_last_error("stop_recording: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let path_str = match unsafe { cstr_to_str(output_path) } {
        Some(s) => s.to_owned(),
        None => "recording.mp4".to_string(),
    };
    let rt = get_runtime();
    let config = crate::browser::RecordingConfig::default();

    match rt.block_on(page_ref.stop_recording(&path_str, &config)) {
        Ok(result) => {
            let boxed = Box::new(result);
            Box::into_raw(boxed) as *mut c_void
        }
        Err(e) => {
            set_last_error(format!("stop_recording: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get the frame count from a RecordingResult handle.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_recording_result_frame_count(result: *const c_void) -> i64 {
    if result.is_null() {
        return -1;
    }
    let r = unsafe { &*(result as *const crate::browser::RecordingResult) };
    r.frame_count as i64
}

/// Get the duration in seconds from a RecordingResult handle.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_recording_result_duration_secs(result: *const c_void) -> f64 {
    if result.is_null() {
        return -1.0;
    }
    let r = unsafe { &*(result as *const crate::browser::RecordingResult) };
    r.duration_secs
}

/// Get the file size in bytes from a RecordingResult handle.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_recording_result_file_size(result: *const c_void) -> i64 {
    if result.is_null() {
        return -1;
    }
    let r = unsafe { &*(result as *const crate::browser::RecordingResult) };
    r.file_size as i64
}

/// Get the output path from a RecordingResult handle.
/// Caller must free with tallow_free_string(). Returns null if handle is null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_recording_result_output_path(
    result: *const c_void,
) -> *mut c_char {
    if result.is_null() {
        return std::ptr::null_mut();
    }
    let r = unsafe { &*(result as *const crate::browser::RecordingResult) };
    string_to_cstr(&r.output_path)
}

/// Get the resolution string (e.g. `"3840x2160"`) from a RecordingResult.
/// Caller must free with tallow_free_string(). Returns null if handle is null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_recording_result_resolution(
    result: *const c_void,
) -> *mut c_char {
    if result.is_null() {
        return std::ptr::null_mut();
    }
    let r = unsafe { &*(result as *const crate::browser::RecordingResult) };
    string_to_cstr(&r.resolution)
}

/// Get the encoding strategy used (e.g. `"ffmpeg"`, `"avi_mjpeg"`, `"frames"`).
/// Caller must free with tallow_free_string(). Returns null if handle is null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_recording_result_encoding(
    result: *const c_void,
) -> *mut c_char {
    if result.is_null() {
        return std::ptr::null_mut();
    }
    let r = unsafe { &*(result as *const crate::browser::RecordingResult) };
    string_to_cstr(&r.encoding)
}

/// Free a RecordingResult handle. Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_recording_result_free(result: *mut c_void) {
    if !result.is_null() {
        unsafe {
            drop(Box::from_raw(
                result as *mut crate::browser::RecordingResult,
            ));
        }
    }
}

/// Query recording status without stopping.
///
/// Writes the current status to the provided output pointers:
/// - `active_out`      — 1 if recording, 0 if not
/// - `frame_count_out` — number of frames captured so far
/// - `elapsed_out`     — elapsed seconds
///
/// Returns 0 on success, -1 if the page handle is null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_recording_status(
    page: *mut c_void,
    active_out: *mut i32,
    frame_count_out: *mut i64,
    elapsed_out: *mut f64,
) -> i32 {
    if page.is_null() {
        set_last_error("recording_status: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let rt = get_runtime();
    let (active, frame_count, elapsed) = rt.block_on(page_ref.recording_status());
    unsafe {
        if !active_out.is_null() {
            *active_out = if active { 1 } else { 0 };
        }
        if !frame_count_out.is_null() {
            *frame_count_out = frame_count as i64;
        }
        if !elapsed_out.is_null() {
            *elapsed_out = elapsed;
        }
    }
    0
}

// ── Additional Page wrappers (navigation, xpath, frames, throttling) ─────

/// Navigate back in history. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_go_back(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("go_back: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.go_back()) {
        Ok(()) => 0,
        Err(e) => { set_last_error(format!("go_back: {e}")); -1 }
    }
}

/// Navigate forward in history. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_go_forward(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("go_forward: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.go_forward()) {
        Ok(()) => 0,
        Err(e) => { set_last_error(format!("go_forward: {e}")); -1 }
    }
}

/// Wait for a selector to appear. Returns an opaque element handle, or null on timeout/error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_wait_for_selector(
    page: *mut c_void,
    selector: *const c_char,
    timeout_ms: u64,
) -> *mut c_void {
    if page.is_null() {
        set_last_error("wait_for_selector: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let sel = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => { set_last_error("wait_for_selector: invalid selector".into()); return std::ptr::null_mut(); }
    };
    let timeout = if timeout_ms == 0 { None } else { Some(std::time::Duration::from_millis(timeout_ms)) };
    match get_runtime().block_on(page_ref.wait_for_selector(sel, timeout)) {
        Ok(el) => Box::into_raw(Box::new(el)) as *mut c_void,
        Err(e) => { set_last_error(format!("wait_for_selector: {e}")); std::ptr::null_mut() }
    }
}

/// Query a single element by XPath. Returns null if not found or on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_query_xpath(
    page: *mut c_void,
    xpath: *const c_char,
) -> *mut c_void {
    if page.is_null() {
        set_last_error("query_xpath: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let xp = match unsafe { cstr_to_str(xpath) } {
        Some(s) => s,
        None => { set_last_error("query_xpath: invalid xpath".into()); return std::ptr::null_mut(); }
    };
    match get_runtime().block_on(page_ref.query_xpath(xp)) {
        Ok(Some(el)) => Box::into_raw(Box::new(el)) as *mut c_void,
        Ok(None) => std::ptr::null_mut(),
        Err(e) => { set_last_error(format!("query_xpath: {e}")); std::ptr::null_mut() }
    }
}

/// Query all elements by XPath. Returns an opaque array handle (Box<Vec<*mut c_void>>).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_query_xpath_all(
    page: *mut c_void,
    xpath: *const c_char,
) -> *mut c_void {
    if page.is_null() {
        set_last_error("query_xpath_all: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let xp = match unsafe { cstr_to_str(xpath) } {
        Some(s) => s,
        None => { set_last_error("query_xpath_all: invalid xpath".into()); return std::ptr::null_mut(); }
    };
    match get_runtime().block_on(page_ref.query_xpath_all(xp)) {
        Ok(elements) => {
            let arr: Vec<*mut c_void> = elements
                .into_iter()
                .map(|el| Box::into_raw(Box::new(el)) as *mut c_void)
                .collect();
            Box::into_raw(Box::new(arr)) as *mut c_void
        }
        Err(e) => { set_last_error(format!("query_xpath_all: {e}")); std::ptr::null_mut() }
    }
}

/// List all frames in the page. Returns a JSON-encoded C string of FrameInfo array.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_frames(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("frames: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.frames()) {
        Ok(frames) => match serde_json::to_string(&frames) {
            Ok(s) => string_to_cstr(&s),
            Err(e) => { set_last_error(format!("frames serialize: {e}")); std::ptr::null_mut() }
        },
        Err(e) => { set_last_error(format!("frames: {e}")); std::ptr::null_mut() }
    }
}

/// Extract a given attribute from all elements matching a selector.
/// Returns a JSON-encoded C string array.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_extract_all_attrs(
    page: *mut c_void,
    selector: *const c_char,
    attr: *const c_char,
) -> *mut c_char {
    if page.is_null() {
        set_last_error("extract_all_attrs: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let sel = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => { set_last_error("extract_all_attrs: invalid selector".into()); return std::ptr::null_mut(); }
    };
    let at = match unsafe { cstr_to_str(attr) } {
        Some(s) => s,
        None => { set_last_error("extract_all_attrs: invalid attr".into()); return std::ptr::null_mut(); }
    };
    let attrs_slice: &[&str] = &[at];
    match get_runtime().block_on(page_ref.extract_all_attrs(sel, attrs_slice)) {
        Ok(values) => match serde_json::to_string(&values) {
            Ok(s) => string_to_cstr(&s),
            Err(e) => { set_last_error(format!("extract_all_attrs serialize: {e}")); std::ptr::null_mut() }
        },
        Err(e) => { set_last_error(format!("extract_all_attrs: {e}")); std::ptr::null_mut() }
    }
}

/// Capture a full DOM snapshot. Returns a JSON-encoded C string.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_capture_dom_snapshot(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("capture_dom_snapshot: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.capture_dom_snapshot()) {
        Ok(v) => string_to_cstr(&v.to_string()),
        Err(e) => { set_last_error(format!("capture_dom_snapshot: {e}")); std::ptr::null_mut() }
    }
}

/// Extract structured data (JSON-LD, microdata, OpenGraph). Returns a JSON-encoded C string.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_extract_structured_data(page: *mut c_void) -> *mut c_char {
    if page.is_null() {
        set_last_error("extract_structured_data: null page handle".to_string());
        return std::ptr::null_mut();
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.extract_structured_data()) {
        Ok(v) => string_to_cstr(&v.to_string()),
        Err(e) => { set_last_error(format!("extract_structured_data: {e}")); std::ptr::null_mut() }
    }
}

/// Set the download path for the page. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_set_download_path(
    page: *mut c_void,
    path: *const c_char,
) -> i32 {
    if page.is_null() {
        set_last_error("set_download_path: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let p = match unsafe { cstr_to_str(path) } {
        Some(s) => s,
        None => { set_last_error("set_download_path: invalid path".into()); return -1; }
    };
    match get_runtime().block_on(page_ref.set_download_path(p)) {
        Ok(()) => 0,
        Err(e) => { set_last_error(format!("set_download_path: {e}")); -1 }
    }
}

/// Throttle network. download/upload in kbps, latency in ms. Returns 0/-1.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_throttle_network(
    page: *mut c_void,
    download_kbps: f64,
    upload_kbps: f64,
    latency_ms: f64,
) -> i32 {
    if page.is_null() {
        set_last_error("throttle_network: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.throttle_network(download_kbps, upload_kbps, latency_ms)) {
        Ok(()) => 0,
        Err(e) => { set_last_error(format!("throttle_network: {e}")); -1 }
    }
}

/// Disable network throttling. Returns 0/-1.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_disable_network_throttling(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("disable_network_throttling: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.disable_network_throttling()) {
        Ok(()) => 0,
        Err(e) => { set_last_error(format!("disable_network_throttling: {e}")); -1 }
    }
}

/// Send a keyboard shortcut string like "Ctrl+A" or "Ctrl+Shift+T". Returns 0/-1.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_keyboard_shortcut(
    page: *mut c_void,
    shortcut: *const c_char,
) -> i32 {
    if page.is_null() {
        set_last_error("keyboard_shortcut: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    let s = match unsafe { cstr_to_str(shortcut) } {
        Some(s) => s,
        None => { set_last_error("keyboard_shortcut: invalid shortcut".into()); return -1; }
    };
    // Parse "Ctrl+Shift+Key" -> modifiers + main key
    const CTRL: u32 = 1 << 1;
    const SHIFT: u32 = 1 << 3;
    const ALT: u32 = 1 << 0;
    const META: u32 = 1 << 2;
    let mut mods = 0u32;
    let mut main_key = "";
    for part in s.split('+') {
        match part.trim() {
            "Ctrl" | "Control" => mods |= CTRL,
            "Shift" => mods |= SHIFT,
            "Alt" => mods |= ALT,
            "Meta" | "Cmd" | "Command" | "Super" => mods |= META,
            other => main_key = other,
        }
    }
    if main_key.is_empty() {
        set_last_error("keyboard_shortcut: missing main key".into());
        return -1;
    }
    match get_runtime().block_on(page_ref.keyboard_shortcut(main_key, mods)) {
        Ok(()) => 0,
        Err(e) => { set_last_error(format!("keyboard_shortcut: {e}")); -1 }
    }
}

/// Scroll by pixel delta. Returns 0/-1.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_scroll_by(
    page: *mut c_void,
    dx: f64,
    dy: f64,
) -> i32 {
    if page.is_null() {
        set_last_error("scroll_by: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.scroll_by(dx, dy)) {
        Ok(()) => 0,
        Err(e) => { set_last_error(format!("scroll_by: {e}")); -1 }
    }
}

/// Scroll to bottom of page. Returns 0/-1.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_scroll_to_bottom(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("scroll_to_bottom: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.scroll_to_bottom()) {
        Ok(()) => 0,
        Err(e) => { set_last_error(format!("scroll_to_bottom: {e}")); -1 }
    }
}

/// Sleep for `ms` milliseconds (Page.wait_for_timeout). Returns 0/-1.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_wait_for_timeout(page: *mut c_void, ms: i64) -> i32 {
    if page.is_null() {
        set_last_error("wait_for_timeout: null page handle".to_string());
        return -1;
    }
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms as u64));
    }
    0
}

/// `Page.wait_for_timeout(ms)`: sleep and report the elapsed milliseconds so the
/// native plane can build `WaitResult` instead of returning a bare status. The
/// interpreter reads `elapsed_ms` from the runtime, so the number must come from
/// the same clock here.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_wait_for_timeout_ms(page: *mut c_void, ms: i64) -> i64 {
    if page.is_null() {
        set_last_error("wait_for_timeout: null page handle".to_string());
        return -1;
    }
    let started = std::time::Instant::now();
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms as u64));
    }
    started.elapsed().as_millis() as i64
}

/// Block all non-essential resources (images, fonts, media, ads). Returns 0/-1.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_block_non_essential(page: *mut c_void) -> i32 {
    if page.is_null() {
        set_last_error("block_non_essential: null page handle".to_string());
        return -1;
    }
    let page_ref = unsafe { &*(page as *const Page) };
    match get_runtime().block_on(page_ref.block_non_essential()) {
        Ok(()) => 0,
        Err(e) => { set_last_error(format!("block_non_essential: {e}")); -1 }
    }
}

// ── Page Close ────────────────────────────────────────────────────────────

/// Free a page handle. Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_free(page: *mut c_void) {
    if !page.is_null() {
        unsafe {
            drop(Box::from_raw(page as *mut Page));
        }
    }
}

/// Free a string returned by Tallow FFI functions (e.g. `tallow_page_title`).
/// Safe to call with null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tallow_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(s);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_content_null_page() {
        let result = tallow_page_content(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_page_set_content_null_page() {
        let html = std::ffi::CString::new("<p>test</p>").unwrap();
        assert_eq!(tallow_page_set_content(std::ptr::null_mut(), html.as_ptr()), -1);
    }

    #[test]
    fn test_screenshot_null_page() {
        let result = tallow_page_screenshot(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_pdf_null_page() {
        let result = tallow_page_pdf(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_get_cookies_null_page() {
        let result = tallow_page_get_cookies(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_clear_cookies_null_page() {
        assert_eq!(tallow_page_clear_cookies(std::ptr::null_mut()), -1);
    }

    #[test]
    fn test_set_viewport_null_page() {
        assert_eq!(tallow_page_set_viewport(std::ptr::null_mut(), 1920, 1080, 1.0), -1);
    }

    #[test]
    fn test_set_user_agent_null_page() {
        let ua = std::ffi::CString::new("Mozilla/5.0").unwrap();
        assert_eq!(tallow_page_set_user_agent(std::ptr::null_mut(), ua.as_ptr()), -1);
    }

    #[test]
    fn test_set_geolocation_null_page() {
        assert_eq!(tallow_page_set_geolocation(std::ptr::null_mut(), 40.7, -74.0, 10.0), -1);
    }

    #[test]
    fn test_element_outer_html_null() {
        let result = tallow_element_outer_html(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_element_tag_name_null() {
        let result = tallow_element_tag_name(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_element_bounding_box_null() {
        let mut x = 0.0f64;
        let mut y = 0.0f64;
        let mut w = 0.0f64;
        let mut h = 0.0f64;
        assert_eq!(
            tallow_element_bounding_box(std::ptr::null_mut(), &mut x, &mut y, &mut w, &mut h),
            -1
        );
    }

    #[test]
    fn test_element_focus_null() {
        assert_eq!(tallow_element_focus(std::ptr::null_mut()), -1);
    }

    #[test]
    fn test_element_clear_null() {
        assert_eq!(tallow_element_clear(std::ptr::null_mut()), -1);
    }

    #[test]
    fn test_element_scroll_into_view_null() {
        assert_eq!(tallow_element_scroll_into_view(std::ptr::null_mut()), -1);
    }

    #[test]
    fn test_element_is_enabled_null() {
        assert_eq!(tallow_element_is_enabled(std::ptr::null_mut()), -1);
    }

    #[test]
    fn test_page_extract_all_text_null_page() {
        let sel = std::ffi::CString::new("p").unwrap();
        let result = tallow_page_extract_all_text(std::ptr::null_mut(), sel.as_ptr());
        assert!(result.is_null());
    }

    #[test]
    fn test_page_evaluate_null_page() {
        let expr = std::ffi::CString::new("1+1").unwrap();
        let result = tallow_page_evaluate(std::ptr::null_mut(), expr.as_ptr());
        assert!(result.is_null());
    }

    #[test]
    fn test_page_accessibility_tree_null() {
        let result = tallow_page_accessibility_tree(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_page_detect_captcha_null() {
        let result = tallow_page_detect_captcha(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_page_apply_stealth_null() {
        assert_eq!(tallow_page_apply_stealth(std::ptr::null_mut()), -1);
    }

    #[test]
    fn test_page_enter_iframe_null() {
        let sel = std::ffi::CString::new("iframe").unwrap();
        let result = tallow_page_enter_iframe(std::ptr::null_mut(), sel.as_ptr());
        assert!(result.is_null());
    }

    #[test]
    fn test_page_block_resources_null() {
        assert_eq!(tallow_page_block_resources(std::ptr::null_mut()), -1);
    }

    #[test]
    fn test_page_handle_cookie_consent_null() {
        assert_eq!(tallow_page_handle_cookie_consent(std::ptr::null_mut(), 0), -1);
    }

    #[test]
    fn test_page_wait_stable_null() {
        assert_eq!(tallow_page_wait_stable(std::ptr::null_mut(), 5000, 500), -1);
    }

    #[test]
    fn test_page_detect_pagination_null() {
        let result = tallow_page_detect_pagination(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_page_free_null() {
        // Should not panic or crash
        tallow_page_free(std::ptr::null_mut());
    }

    // ── Gap 1: Console message FFI null-safety ───────────────────────────

    #[test]
    fn test_console_messages_null_page() {
        let result = tallow_page_console_messages(std::ptr::null_mut());
        assert!(result.is_null());
    }

    #[test]
    fn test_clear_console_null_page() {
        assert_eq!(tallow_page_clear_console(std::ptr::null_mut()), -1);
    }

    // ── Recording FFI null-safety ─────────────────────────────────────────

    #[test]
    fn test_start_recording_null_page() {
        assert_eq!(
            tallow_page_start_recording(std::ptr::null_mut(), 3840, 2160, 30, 90),
            -1
        );
    }

    #[test]
    fn test_stop_recording_null_page() {
        let path = std::ffi::CString::new("out.mp4").unwrap();
        let result = tallow_page_stop_recording(std::ptr::null_mut(), path.as_ptr());
        assert!(result.is_null());
    }

    #[test]
    fn test_recording_result_null_handle() {
        assert_eq!(tallow_recording_result_frame_count(std::ptr::null()), -1);
        assert!(
            (tallow_recording_result_duration_secs(std::ptr::null()) - (-1.0)).abs()
                < f64::EPSILON
        );
        assert_eq!(tallow_recording_result_file_size(std::ptr::null()), -1);
        assert!(tallow_recording_result_output_path(std::ptr::null()).is_null());
        assert!(tallow_recording_result_resolution(std::ptr::null()).is_null());
        assert!(tallow_recording_result_encoding(std::ptr::null()).is_null());
    }

    #[test]
    fn test_recording_result_free_null() {
        // Must not panic or crash
        tallow_recording_result_free(std::ptr::null_mut());
    }

    #[test]
    fn test_recording_status_null_page() {
        let mut active = 0i32;
        let mut count = 0i64;
        let mut elapsed = 0.0f64;
        assert_eq!(
            tallow_page_recording_status(
                std::ptr::null_mut(),
                &mut active,
                &mut count,
                &mut elapsed
            ),
            -1
        );
    }

    // ── NEVER N8: stealth is default-ON; the opt-out must be explicit ───

    #[test]
    fn stealth_default_on_and_optout_explicit() {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = crate::runtime::egress_http::env_lock();
        // Env hygiene: capture the prior value, restore it before returning.
        let prior = std::env::var("TALLOW_NO_STEALTH").ok();

        // Unset → stealth stays ON. An unset env must never leak by omission
        // (the same fail-closed contract as N1's egress default).
        unsafe { std::env::remove_var("TALLOW_NO_STEALTH") };
        assert!(
            !stealth_disabled(),
            "unset TALLOW_NO_STEALTH must keep stealth ON"
        );

        // Junk / false-y / empty values must NOT turn stealth off — a typo
        // fails toward stealth, never toward the cheapest bot signal.
        for junk in ["0", "false", "nope", ""] {
            unsafe { std::env::set_var("TALLOW_NO_STEALTH", junk) };
            assert!(
                !stealth_disabled(),
                "TALLOW_NO_STEALTH={junk:?} must keep stealth ON"
            );
        }

        // Only the explicit truthy spellings opt out.
        for truthy in ["1", "true", "yes"] {
            unsafe { std::env::set_var("TALLOW_NO_STEALTH", truthy) };
            assert!(
                stealth_disabled(),
                "TALLOW_NO_STEALTH={truthy:?} must disable stealth"
            );
        }

        // Matching stays case-insensitive + trim-tolerant (documented contract).
        unsafe { std::env::set_var("TALLOW_NO_STEALTH", " TRUE ") };
        assert!(stealth_disabled(), "' TRUE ' must disable stealth");

        // Restore prior state so neighbours are unaffected.
        match prior {
            Some(v) => unsafe { std::env::set_var("TALLOW_NO_STEALTH", v) },
            None => unsafe { std::env::remove_var("TALLOW_NO_STEALTH") },
        }
    }

    // ── R-7: declared-bot default for the public-scraping path ──────────────

    /// Extract the applied profile from a decision (None = no profile).
    fn applied_profile(
        decision: PageProfileDecision,
    ) -> Option<crate::browser::stealth::StealthProfile> {
        match decision {
            PageProfileDecision::Disabled => None,
            PageProfileDecision::DeclaredBot(p) | PageProfileDecision::Stealth(p) => Some(p),
        }
    }

    #[test]
    fn page_profile_decision_defaults_to_declared_bot() {
        // Unconfigured stealth.toml (the built-in default): the honest
        // declared-bot identity is the default for public scraping (R-7) —
        // NOT a human-impersonating stealth profile.
        let cfg = crate::browser::config::StealthToml::default();
        match page_profile_decision_from(&cfg, false, None) {
            PageProfileDecision::DeclaredBot(p) => {
                assert!(
                    p.user_agent.starts_with("TallowScraper/"),
                    "default public-scraping identity must declare the bot, got {}",
                    p.user_agent
                );
            }
            other => panic!("expected DeclaredBot default, got {other:?}"),
        }
    }

    #[test]
    fn page_profile_decision_no_stealth_disables_all_profiles() {
        // `TALLOW_NO_STEALTH=1` semantics stay intact: no profile is applied,
        // and the opt-out wins even over an explicit stealth opt-in.
        let cfg = crate::browser::config::StealthToml::default();
        assert!(matches!(
            page_profile_decision_from(&cfg, true, None),
            PageProfileDecision::Disabled
        ));
        assert!(matches!(
            page_profile_decision_from(&cfg, true, Some("chrome_macos")),
            PageProfileDecision::Disabled
        ));
    }

    #[test]
    fn page_profile_decision_env_optin_selects_stealth() {
        let cfg = crate::browser::config::StealthToml::default();
        match page_profile_decision_from(&cfg, false, Some("chrome_macos")) {
            PageProfileDecision::Stealth(p) => {
                assert!(p.user_agent.contains("Macintosh"));
            }
            other => panic!("expected Stealth(chrome_macos), got {other:?}"),
        }
        // `declared_bot` is an explicit spelling of the honest default.
        match page_profile_decision_from(&cfg, false, Some("declared_bot")) {
            PageProfileDecision::DeclaredBot(p) => {
                assert!(p.user_agent.starts_with("TallowScraper/"));
            }
            other => panic!("expected DeclaredBot, got {other:?}"),
        }
        // Blank / whitespace env is not an opt-in.
        assert!(matches!(
            page_profile_decision_from(&cfg, false, Some("   ")),
            PageProfileDecision::DeclaredBot(_)
        ));
    }

    #[test]
    fn page_profile_decision_non_default_toml_profile_is_stealth() {
        // An operator who names a non-default profile in stealth.toml has made
        // an explicit choice (legally-cleared source) — that becomes Steam(…)
        // rather than the declared-bot default.
        let cfg = crate::browser::config::StealthToml {
            profile: "chrome_linux".to_string(),
            ..Default::default()
        };
        match page_profile_decision_from(&cfg, false, None) {
            PageProfileDecision::Stealth(p) => {
                assert!(p.user_agent.contains("X11; Linux"));
            }
            other => panic!("expected Stealth(chrome_linux), got {other:?}"),
        }
    }

    #[test]
    fn page_profile_decision_declared_bot_is_coherent() {
        // The posture the compiled path applies must not itself be a
        // cross-vector contradiction (engine/UA/platform consistency).
        let cfg = crate::browser::config::StealthToml::default();
        let profile = applied_profile(page_profile_decision_from(&cfg, false, None))
            .expect("default posture applies a profile");
        let critical: Vec<_> = crate::browser::fingerprint_validator::FingerprintValidator::validate(
            &profile,
        )
        .into_iter()
        .filter(|w| w.severity == crate::browser::fingerprint_validator::Severity::Critical)
        .collect();
        assert!(
            critical.is_empty(),
            "declared-bot default profile has critical incoherences: {critical:?}"
        );
    }

    #[test]
    fn page_profile_decision_wrapper_follows_live_env() {
        // The live wrapper must honour the same contract as the pure decision:
        // opt-out wins, explicit opt-in selects stealth. Env hygiene + the
        // process-global lock, mirroring `stealth_default_on_and_optout_explicit`.
        let _guard = crate::runtime::egress_http::env_lock();
        let prior_no = std::env::var("TALLOW_NO_STEALTH").ok();
        let prior_p = std::env::var("TALLOW_STEALTH_PROFILE").ok();

        unsafe { std::env::remove_var("TALLOW_NO_STEALTH") };
        unsafe { std::env::remove_var("TALLOW_STEALTH_PROFILE") };

        // Default: declared bot (independent of any on-disk stealth.toml,
        // because the default contains "TallowScraper/" only when declared).
        if let PageProfileDecision::DeclaredBot(p) = page_profile_decision() {
            assert!(p.user_agent.starts_with("TallowScraper/"));
        }

        // Explicit stealth opt-in via env.
        unsafe { std::env::set_var("TALLOW_STEALTH_PROFILE", "chrome_macos") };
        match page_profile_decision() {
            PageProfileDecision::Stealth(p) => assert!(p.user_agent.contains("Macintosh")),
            other => panic!("env opt-in must select stealth, got {other:?}"),
        }

        // The opt-out wins over the env opt-in.
        unsafe { std::env::set_var("TALLOW_NO_STEALTH", "1") };
        assert!(matches!(
            page_profile_decision(),
            PageProfileDecision::Disabled
        ));

        match prior_no {
            Some(v) => unsafe { std::env::set_var("TALLOW_NO_STEALTH", v) },
            None => unsafe { std::env::remove_var("TALLOW_NO_STEALTH") },
        }
        match prior_p {
            Some(v) => unsafe { std::env::set_var("TALLOW_STEALTH_PROFILE", v) },
            None => unsafe { std::env::remove_var("TALLOW_STEALTH_PROFILE") },
        }
    }
}
