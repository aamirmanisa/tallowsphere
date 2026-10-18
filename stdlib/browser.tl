// tallow.browser — Browser automation via Chrome DevTools Protocol
//
// Browser operations require @legal annotation on the containing function.
// All operations return Result<T> and never panic.
//
// IMPORTANT: fetch() and browser.goto() are DISTINCT code paths:
//   - fetch(url) makes a raw HTTP request and returns Response (no JS rendering)
//   - page.goto(url) launches a browser, renders JavaScript, and returns NavigationResult
//
// If you need JavaScript-rendered content, use Browser.launch() + page.goto().
// If you only need HTTP responses (APIs, static HTML), use fetch().

/// Browser process handle. Created via Browser.launch().
/// Manages a headless (or visible) Chrome/Chromium instance via CDP.
struct Browser {
    // Opaque handle — managed by runtime
}

impl Browser {
    /// Launch a new browser process.
    /// headless: true for headless mode (default), false for visible window.
    /// Returns Err if Chrome is not installed or cannot be started.
    fn launch(headless: bool = true) -> Result<Browser> {
        // Runtime: spawns Chrome process, connects via CDP WebSocket
    }

    /// Create a new page (tab) in this browser.
    fn new_page(self) -> Result<Page> {
        // Runtime: creates new CDP target
    }

    /// Close the browser and terminate the process.
    fn close(self) {
        // Runtime: sends Browser.close via CDP, kills process
    }
}

/// Page handle. Represents a browser tab with navigation and DOM access.
/// This is the primary interface for interacting with web content.
struct Page {
    // Opaque handle — managed by runtime
}

impl Page {
    /// Navigate to a URL and wait for page load.
    /// This is the correct way to access JS-rendered pages.
    /// For HTTP-only requests (no JS), use fetch() instead.
    fn goto(self, url: String) -> Result<NavigationResult> {
        // Runtime: Page.navigate + Page.loadEventFired via CDP
    }

    /// Navigate to a URL (alias for goto).
    fn navigate(self, url: String) -> Result<NavigationResult> {
        self.goto(url)
    }

    /// Anti-bot-aware navigation. Routes through the AntiBotOrchestrator so
    /// proxy selection/rotation, rate limiting, cookie farming, and CAPTCHA
    /// handling actually drive egress (relaunching the browser on the chosen
    /// proxy) instead of the raw `page.navigate` used by `goto`.
    ///
    /// Optional second argument — a per-call egress/stealth map:
    ///   {proxy: String, tor: Bool, stealth: Bool, tier: String}
    ///   - proxy:    explicit proxy URL for THIS navigation ("socks5://…",
    ///               "http://…"). Wins over the orchestrator's own selection.
    ///   - tor:      true routes this navigation through Tor instances
    ///               (implies per-domain circuit isolation).
    ///   - stealth:  stealth on the relaunched browser (default true).
    ///   - tier:     "tor" | "direct" | "datacenter" | "residential" | "isp" |
    ///               "mobile". Classifies `proxy`, or "direct" pins this
    ///               navigation to direct egress (no Tor fallback attempts).
    /// With no map, historical behavior applies (default Tor fallback pool +
    /// stealth relaunch). Real arm: interp.rs Page method dispatch
    /// (goto_antibot); relaunch config.proxy carries the proxy to Chrome's
    /// --proxy-server flag.
    fn goto_antibot(self, url: String, egress: Map?) -> Result<NavigationResult> {
        // Runtime: AntiBotOrchestrator.execute_request + relaunch-on-proxy
    }

    /// Get the current page title.
    fn title(self) -> Result<String> {
        // Runtime: evaluates document.title via CDP
    }

    /// Get the current page URL.
    fn url(self) -> Result<String> {
        // Runtime: evaluates window.location.href via CDP
    }

    /// Full HTML of the current document, serialized from the live DOM
    /// (post-JS), not the bytes the server sent.
    fn content(self) -> Result<String> {
        // Runtime: document.documentElement.outerHTML via CDP
    }

    /// Replace the document with `html`. The current DOM is discarded; the
    /// page handle stays bound, so later navigation still works.
    fn set_content(self, html: String) -> Result<PageContentResult> {
        // Runtime: document.open/write/close via CDP
    }

    /// Sleep for `ms`. Explicit wait; `elapsed_ms` reports what actually
    /// elapsed rather than echoing the request.
    fn wait_for_timeout(self, ms: i64) -> Result<WaitResult> {
        // Runtime: tokio sleep, no CDP round trip
    }

    /// Poll a JS expression until it is truthy or `timeout_ms` elapses
    /// (default 30000). A timeout is `result: false`, not an error.
    fn wait_for_function(self, js_expression: String, timeout_ms: i64 = 30000) -> Result<WaitResult> {
        // Runtime: Runtime.evaluate poll at 50 ms
    }

    /// Find the first element matching a CSS selector.
    /// Returns Err if no element matches.
    fn query_selector(self, selector: String) -> Result<Element> {
        // Runtime: document.querySelector via CDP
    }

    /// Find all elements matching a CSS selector.
    /// Returns empty array if no elements match.
    fn query_selector_all(self, selector: String) -> Result<[]Element> {
        // Runtime: document.querySelectorAll via CDP
    }

    /// Wait for an element matching the selector to appear in the DOM.
    /// Returns Err on timeout.
    fn wait_for_selector(self, selector: String) -> Result<Element> {
        // Runtime: polls querySelector until found or timeout
    }

    // ── ROADMAP #7: Real CDP form automation ──
    // These methods are REAL interpreter arms ("Page","fill"/"click"/"select")
    // driving the CDP Input + DOM domains through src/browser/element.rs —
    // NOT contract stubs. Fixture-gated non-live tests cover the shape.

    /// Fill a form field by CSS selector: focus, clear, then type the value
    /// character-by-character (real CDP Input.dispatchKeyEvent).
    /// clear_first defaults to true; delay_ms paces the keystrokes.
    fn fill(self, selector: String, value: String, clear_first: Bool = true, delay_ms: i32 = 0) -> Result<()> {
        // Runtime: query_selector → focus/clear/type_text via CDP Input domain
    }

    /// Click the element matching a CSS selector (auto-waits actionability,
    /// scrolls into view, dispatches Input.dispatchMouseEvent).
    fn click(self, selector: String) -> Result<()> {
        // Runtime: query_selector → ElementHandle.click via CDP Input domain
    }

    /// Select an <option> inside the <select> matching a CSS selector.
    /// by: "value" (default) | "label" | "index"; option is the match target.
    fn select(self, selector: String, option: String, by: String = "value") -> Result<()> {
        // Runtime: query_selector → ElementHandle.select_option via CDP
    }

    /// Detect → solve → retry orchestration over the page's CURRENT egress
    /// (ROADMAP #9). Sequences captcha.detect, the external-solver solve leg
    /// (incl. Turnstile), warmup/escalation capability flags, and a bounded
    /// re-navigation, returning an AntibotResolveReport whose per-engine
    /// steps carry honest {engine, available, ran, note} capability flags.
    /// Optional opts map: {solver_key: String, solver_service: String}.
    fn resolve_antibot(self, url: String, opts: Map?) -> Result<AntibotResolveReport> {
        // Runtime: AntiBotOrchestrator.resolve (src/browser/antibot.rs) +
        // interp ("Page","resolve_antibot") arm
    }

    /// Reload the current page.
    fn reload(self) -> Result<()> {
        // Runtime: Page.reload via CDP
    }

    /// Navigate back in history.
    fn go_back(self) -> Result<()> {
        // Runtime: Page.navigateToHistoryEntry via CDP
    }

    /// Navigate forward in history.
    fn go_forward(self) -> Result<()> {
        // Runtime: Page.navigateToHistoryEntry via CDP
    }

    /// Scroll by pixel amounts.
    fn scroll_by(self, delta_x: f64, delta_y: f64) -> Result<()> {
        // Runtime: Input.dispatchMouseEvent with type=mouseWheel via CDP
    }

    /// Scroll to the bottom of the page.
    fn scroll_to_bottom(self) -> Result<()> {
        // Runtime: evaluates window.scrollTo(0, document.body.scrollHeight) via CDP
    }

    // ── Cookie Session Bridge ──

    /// Extract all browser cookies via CDP Network.getCookies.
    /// Returns an array of CdpCookie structs.
    fn get_cookies(self) -> Result<[]CdpCookie> {
        // Runtime: CDP Network.getCookies → Vec<CdpCookie>
    }

    /// Generate a Cookie header string for the given URL from the browser's cookie jar.
    /// Filters cookies by domain match, returns "name=value; name2=value2".
    fn cookie_string(self, url: String) -> Result<String> {
        // Runtime: get_cookies() → domain filter → join
    }

    /// Set cookies in the browser from a Cookie header string.
    /// domain: the domain to set cookies for (e.g. "ghraonline.com")
    /// path: the cookie path (default "/")
    fn set_cookies_from_header(self, header: String, domain: String, path: String = "/") -> Result<()> {
        // Runtime: parse header → CdpCookie → Network.setCookie
    }

    /// Make an authenticated HTTP GET request using browser cookies.
    /// Extracts cookies from the browser and sends via ureq through the runtime egress contract (proxy-aware; Tor by default) with a Cookie header.
    /// Returns {status: Int, body: String}.
    fn authenticated_get(self, url: String) -> Result<AuthenticatedResponse> {
        // Runtime: cookie_string() → ureq GET with Cookie header
    }

    /// Make an authenticated HTTP request with browser cookies.
    /// method: "GET", "POST", etc. body: request body string.
    /// Returns {status: Int, body: String}.
    fn authenticated_request(self, url: String, method: String = "GET", body: String = "") -> Result<AuthenticatedResponse> {
        // Runtime: cookie_string() → ureq with Cookie header
    }
}

/// A CDP cookie as returned by Page.get_cookies().
struct CdpCookie {
    name:      String,
    value:     String,
    domain:    String,
    path:      String,
    expires:   Float,
    http_only: Bool,
    secure:    Bool,
    same_site: String,
}

/// Response from an authenticated HTTP request.
struct AuthenticatedResponse {
    status: Int,
    body:   String,
}

// ── Wordfence Bypass ──

/// Check if the current page is a Wordfence JS challenge page ("One moment, please...").
fn page_is_wordfence_challenge(self) -> Result<Bool> {
    // Runtime: checks document.title for "One moment, please..."
}

/// Bypass the Wordfence JS challenge on the current page.
/// Executes the challenge JS and waits for auto-redirect.
/// Returns the final URL after bypass.
fn page_bypass_wordfence(self) -> Result<String> {
    // Runtime: executes WF JS challenge, waits for redirect
}

/// Navigate to a URL automatically bypassing Wordfence if encountered.
/// Combines page.goto() + wordfence detection + auto-bypass.
fn page_navigate_bypass_wordfence(self, url: String) -> Result<String> {
    // Runtime: navigate → detect WF → bypass → return final URL
}

// ── WordPress Auth Automation ──

/// Extract the WordPress REST API nonce (wp_rest) from the current page.
/// Returns nil if not found (not logged in, or not an admin page).
fn page_wp_extract_rest_nonce(self) -> Result<WpNonce?> {
    // Runtime: evaluates wpApiSettings.nonce, hidden _wpnonce fields
}

/// Check if the browser is currently logged into WordPress.
/// Detects admin bar, logged-in body class, or logout links.
fn page_wp_is_logged_in(self) -> Result<Bool> {
    // Runtime: checks for #wpadminbar, .logged-in, logout links
}

/// Attempt WordPress login via wp-login.php form.
/// Navigates to login page, fills form, submits, detects outcome.
/// Returns LoginResult with status: "success", "2fa_required", "failed", or "unknown".
fn page_wp_login(self, username: String, password: String) -> Result<LoginResult> {
    // Runtime: full wp-login.php flow → detect 2FA/success/failure
}

/// Extract ALL WordPress nonces from the current page.
/// Returns array of WpNonce structs (REST, admin, etc.).
fn page_wp_extract_all_nonces(self) -> Result<[]WpNonce> {
    // Runtime: evaluates all nonce sources on page
}

/// A WordPress nonce extracted from a page.
struct WpNonce {
    value:  String,
    source: String,
    action: String,
}

/// Result of a WordPress login attempt.
struct LoginResult {
    status: String,
    detail: String,
}

/// Navigation result returned by page.goto() and page.navigate().
/// Contains metadata about the completed navigation.
struct NavigationResult {
    url:         String,
    frame_id:    String,
    status_code: i32,
}

/// One engine step of an AntibotResolveReport — an honest capability flag:
/// available = engine could run under the current configuration, ran = it
/// executed, note = what actually happened (never a fake success token).
struct AntibotResolveStep {
    engine:    String,
    available: Bool,
    ran:       Bool,
    note:      String,
}

/// Result of page.resolve_antibot(): the detect → solve → retry loop with
/// per-engine capability flags and the final page classification.
struct AntibotResolveReport {
    url:          String,
    resolved:     Bool,
    final_status: i32,
    attempts:     i32,
    body_hint:    String,
    steps:        []AntibotResolveStep,
}

// ── ROADMAP #9: Antibot.resolve facade ──
// The orchestrator fn is `Antibot.resolve(page, url)`. Routing note: the
// `Antibot` namespace itself is not separately registered — live dispatch goes
// through the REAL interpreter arm page.resolve_antibot(url) or the module
// function browser.resolve_antibot(page, url, opts) (src/stdlib/browser.rs),
// both of which run the same AntiBotOrchestrator.resolve engine with honest
// capability flags per engine step. Never a stub.

/// Element handle. Represents a DOM element for interaction and extraction.
/// Element handles are tied to the page that created them.
struct Element {
    // Opaque handle — managed by runtime
}

impl Element {
    /// Get the text content of this element (innerText).
    fn text(self) -> Result<String> {
        // Runtime: callFunctionOn element.innerText via CDP
    }

    /// Get the inner HTML of this element.
    fn inner_html(self) -> Result<String> {
        // Runtime: callFunctionOn element.innerHTML via CDP
    }

    /// Get an attribute value by name. Returns nil if the attribute does not exist.
    fn attribute(self, name: String) -> String? {
        // Runtime: callFunctionOn element.getAttribute(name) via CDP
    }

    /// Click this element. Scrolls into view if needed.
    fn click(self) -> Result<()> {
        // Runtime: scrollIntoView + getBoxModel + Input.dispatchMouseEvent via CDP
    }

    /// Type text into this element with optional inter-keystroke delay.
    /// Focuses the element first, then dispatches keyDown/char/keyUp events.
    fn type_text(self, text: String, delay_ms: i32 = 0) -> Result<()> {
        // Runtime: focus + Input.dispatchKeyEvent per character via CDP
    }

    /// Hover over this element. Scrolls into view if needed.
    fn hover(self) -> Result<()> {
        // Runtime: scrollIntoView + getBoxModel + Input.dispatchMouseEvent(mouseMoved) via CDP
    }

    /// Check if this element is currently visible in the viewport.
    fn visible(self) -> bool {
        // Runtime: checks element bounding box and visibility via CDP
    }
}

// ── Browser v2 — Performance & Privacy Upgrade ──────────────────

/// Isolated browser context with per-proxy identity.
struct BrowserContext {
    context_id: String,
    proxy:      String,
    timezone:   String,
    locale:     String,
    isolated:   bool,
    pages_count: i32,
}

/// Create an isolated browser context.
fn browser_context_create(proxy: String, timezone: String, locale: String) -> BrowserContext {
    // native: creates CDP BrowserContext with proxy isolation
}

/// Web crawler with sitemap and link-following strategies.
struct Crawler {
    seed_url:      String,
    sitemap_url:   String,
    strategy:      String,
    max_depth:     i32,
    max_pages:     i32,
    pages_crawled: i32,
    rate_limit_ms: i32,
}

/// Create a crawler from a sitemap.
fn crawler_from_sitemap(url: String) -> Crawler {
    // native: discovers and parses sitemap.xml
}

/// Create a crawler that follows links from a seed URL.
fn crawler_from_links(url: String, max_depth: i32) -> Crawler {
    // native: BFS link-following crawler
}

/// Content-addressed page cache with BLAKE3 hashing.
struct PageCache {
    max_age_seconds: i64,
    max_size_mb:     i64,
    entries:         i32,
    hits:            i32,
    misses:          i32,
    keyed_by:        String,
}

/// Create a page cache.
fn page_cache_create(max_age_seconds: i64, max_size_mb: i64) -> PageCache {
    // native: initializes cache with content-addressed storage
}

/// Content fingerprint for deduplication and similarity detection.
struct ContentFingerprint {
    hash:        String,
    word_count:  i32,
    text_length: i32,
}

/// Create a fingerprint from text content.
fn content_fingerprint_from_text(text: String) -> ContentFingerprint {
    // native: BLAKE3-based SimHash fingerprinting
}

/// Compare two fingerprints for similarity (0.0 to 1.0).
fn content_fingerprint_similarity(a: ContentFingerprint, b: ContentFingerprint) -> f64 {
    // native: Hamming distance on hash bits
}

/// Extracted structured data from a web page.
struct StructuredData {
    json_ld:     []String,
    open_graph:  Map<String, String>,
    has_json_ld: bool,
}

/// Extract structured data (JSON-LD, OpenGraph) from HTML.
fn structured_data_extract(html: String) -> StructuredData {
    // native: parses script[type="application/ld+json"] and meta[property^="og:"]
    //
    // Which engine: the interpreter reaches this through the `stdlib::browser`
    // facade. The AOT native backend has NO lowering for this method, so
    // `tallow run` falls back to the interpreter and `--require-native` refuses
    // loudly rather than pretending. Results are correct either way; only the
    // backend differs. (Binding `tallow_structured_data_extract` is the open
    // P2.T1 item: it needs a native that builds the `%struct.StructuredData`
    // layout, including the runtime representation of `[]String` and `Map`.)
}

// ── Page v2 methods ─────────────────────────────────────────────

/// Extract all matching elements' text in ONE CDP call (batch mode).
fn page_extract_all_text(selector: String) -> []String {
    // native: single Runtime.evaluate returning all texts
}

/// Extract all matching elements with attributes in ONE CDP call.
fn page_extract_all_attrs(selector: String, attrs: []String) -> []Map<String, String> {
    // native: single Runtime.evaluate returning all attribute maps
}

/// Block non-essential resources for maximum speed.
fn page_block_non_essential() -> Result<()> {
    // native: Fetch.enable blocking images, fonts, CSS, media
}

/// Wait until DOM is stable (no mutations for quiesce_ms).
fn page_wait_for_stable(timeout_ms: i64, quiesce_ms: i64) -> Result<()> {
    // native: MutationObserver-based stability detection
}

/// Detect pagination pattern on the current page.
fn page_detect_pagination() -> PaginationInfo? {
    // native: detects numbered, next_button, load_more, infinite_scroll
}

/// Handle cookie consent banners automatically.
fn page_handle_cookie_consent(strategy: String) -> bool {
    // native: clicks accept/reject/dismiss on consent banners
}

/// Extract structured data from current page.
fn page_structured_data() -> StructuredData {
    // native: JSON-LD + OpenGraph extraction
}

/// Capture DOM snapshot (compact format for full-page extraction).
fn page_capture_dom_snapshot() -> String {
    // native: CDP DOMSnapshot.captureSnapshot
}

/// Get page text with PII automatically redacted.
fn page_text_redacted() -> String {
    // native: text extraction with email/phone/SSN/CC/IP redaction
}

/// Pagination info detected from a page.
struct PaginationInfo {
    strategy:    String,
    next_url:    String?,
    total_links: i32,
}

// ── Phase 50: Playwright Features ──────────────────────────────────────

/// Dialog handling for alert, confirm, and prompt browser dialogs.
struct Dialog {
    // Module sentinel
}

impl Dialog {
    /// Register a handler for alert() dialogs.
    fn on_alert(handler_name: String) -> DialogHandler {
        // native: Page.javascriptDialogOpening CDP event
    }

    /// Register a handler for confirm() dialogs.
    fn on_confirm(handler_name: String, auto_accept: bool = true) -> DialogHandler {
        // native: Page.javascriptDialogOpening with confirm type
    }

    /// Register a handler for prompt() dialogs.
    fn on_prompt(handler_name: String, default_value: String = "") -> DialogHandler {
        // native: Page.javascriptDialogOpening with prompt type
    }

    /// Accept a dialog, optionally providing a prompt value.
    fn accept(value: String = "") -> DialogResult {
        // native: Page.handleJavaScriptDialog accept=true
    }

    /// Dismiss (cancel) a dialog.
    fn dismiss() -> DialogResult {
        // native: Page.handleJavaScriptDialog accept=false
    }
}

struct DialogHandler {
    kind:          String,
    handler:       String,
    active:        bool,
    auto_accept:   bool?,
    default_value: String?,
}

struct DialogResult {
    accepted:  bool?,
    dismissed: bool?,
    value:     String?,
}

/// Page-level keyboard input control.
struct Keyboard {
    // Module sentinel
}

impl Keyboard {
    /// Press a key (keydown + keyup).
    fn press(key: String) -> KeyboardEvent { }

    /// Type text character by character with optional delay.
    fn type_text(text: String, delay_ms: i64 = 0) -> KeyboardEvent { }

    /// Hold a key down.
    fn down(key: String) -> KeyboardEvent { }

    /// Release a key.
    fn up(key: String) -> KeyboardEvent { }

    /// Execute a keyboard shortcut (modifier + key).
    fn shortcut(modifier: String, key: String) -> KeyboardEvent { }

    /// Insert text without key events (like clipboard paste).
    fn insert_text(text: String) -> KeyboardEvent { }
}

struct KeyboardEvent {
    key:         String?,
    text:        String?,
    pressed:     bool?,
    state:       String?,
    modifier:    String?,
    modifiers:   []String?,
    chars_typed: i64?,
    delay_ms:    i64?,
    executed:    bool?,
    inserted:    bool?,
}

/// Page-level mouse input control.
struct Mouse {
    // Module sentinel
}

impl Mouse {
    /// Click at coordinates.
    fn click(x: i64, y: i64) -> MouseEvent { }

    /// Double-click at coordinates.
    fn dblclick(x: i64, y: i64) -> MouseEvent { }

    /// Move mouse to coordinates with optional intermediate steps.
    fn move(x: i64, y: i64, steps: i64 = 1) -> MouseEvent { }

    /// Press mouse button down.
    fn down(button: String = "left") -> MouseEvent { }

    /// Release mouse button.
    fn up(button: String = "left") -> MouseEvent { }

    /// Scroll wheel.
    fn wheel(delta_x: i64, delta_y: i64) -> MouseEvent { }

    /// Drag from one point to another.
    fn drag(from_x: i64, from_y: i64, to_x: i64, to_y: i64) -> MouseEvent { }
}

struct MouseEvent {
    x:         i64?,
    y:         i64?,
    button:    String?,
    clicks:    i32?,
    steps:     i64?,
    state:     String?,
    delta_x:   i64?,
    delta_y:   i64?,
    from_x:    i64?,
    from_y:    i64?,
    to_x:      i64?,
    to_y:      i64?,
    completed: bool?,
}

// Page content methods

/// Set the page HTML content directly.
fn page_set_content(html: String) -> PageContentResult { }

/// Get the full HTML content of the page.
fn page_content() -> String { }

/// Add a script to run before page load.
fn page_add_init_script(script: String) -> ScriptTag { }

/// Inject a script tag into the page.
fn page_add_script_tag(url_or_content: String) -> ScriptTag { }

/// Inject a style tag into the page.
fn page_add_style_tag(url_or_content: String) -> StyleTag { }

struct PageContentResult {
    loaded:         bool,
    content_length: i64,
}

struct ScriptTag {
    script_hash: String?,
    tag_id:      String?,
    injected:    bool?,
    kind:        String?,
}

struct StyleTag {
    tag_id: String,
    kind:   String,
}

// Wait methods

/// Wait for a JS function/expression to return truthy.
fn page_wait_for_function(js_expression: String, timeout_ms: i64 = 30000) -> WaitResult { }

/// Wait for navigation to a URL matching pattern.
fn page_wait_for_url(url_pattern: String, timeout_ms: i64 = 30000) -> WaitResult { }

/// Wait for an outgoing request matching URL pattern.
fn page_wait_for_request(url_pattern: String, timeout_ms: i64 = 30000) -> WaitResult { }

/// Wait for a response matching URL pattern.
fn page_wait_for_response(url_pattern: String, timeout_ms: i64 = 30000) -> WaitResult { }

/// Wait for a named event.
fn page_wait_for_event(event_name: String, timeout_ms: i64 = 30000) -> WaitResult { }

/// Wait for specified milliseconds (explicit sleep).
fn page_wait_for_timeout(ms: i64) -> WaitResult { }

struct WaitResult {
    result:     bool?,
    matched:    bool?,
    received:   bool?,
    elapsed_ms: i64?,
    waited_ms:  i64?,
    url:        String?,
    method:     String?,
    status:     i32?,
    event:      String?,
}

// Expose function / binding

/// Expose a Tallow function to the page's JavaScript context.
fn page_expose_function(name: String, handler_name: String) -> ExposedFunction { }

/// Expose a binding to the page (receives caller info).
fn page_expose_binding(name: String, handler_name: String) -> ExposedBinding { }

struct ExposedFunction {
    name:    String,
    handler: String,
    exposed: bool,
}

struct ExposedBinding {
    name:    String,
    handler: String,
    bound:   bool,
}

// Event listeners

/// Listen for console messages from the page.
fn page_on_console(handler_name: String) -> EventListener { }

/// Listen for uncaught page errors.
fn page_on_error(handler_name: String) -> EventListener { }

/// Listen for outgoing network requests.
fn page_on_request(handler_name: String) -> EventListener { }

/// Listen for network responses.
fn page_on_response(handler_name: String) -> EventListener { }

/// Listen for file chooser dialogs.
fn page_on_filechooser(handler_name: String) -> EventListener { }

/// Listen for download events.
fn page_on_download(handler_name: String) -> EventListener { }

struct EventListener {
    kind:    String,
    handler: String,
    active:  bool,
}

// Media & vision emulation

/// Emulate CSS media type and preferences.
fn page_emulate_media(media_type: String = "screen", color_scheme: String = "light", reduced_motion: String = "no-preference") -> MediaEmulation { }

/// Emulate vision deficiency (color blindness, blur).
/// Valid: none, blurred, protanopia, deuteranopia, tritanopia, achromatopsia
fn page_emulate_vision(deficiency: String) -> VisionEmulation { }

struct MediaEmulation {
    media_type:     String,
    color_scheme:   String,
    reduced_motion: String,
    applied:        bool,
}

struct VisionEmulation {
    kind:    String,
    applied: bool,
}

// Network & CPU throttling

/// Throttle network to simulate connection conditions.
/// Presets: offline, slow_2g, 2g, 3g, 4g, wifi, none
fn page_throttle_network(preset: String) -> NetworkThrottle { }

/// Throttle CPU execution speed.
fn page_throttle_cpu(rate: f64) -> CpuThrottle { }

struct NetworkThrottle {
    preset:        String,
    latency_ms:    i64,
    download_kbps: i64,
    upload_kbps:   i64,
}

struct CpuThrottle {
    rate:    f64,
    applied: bool,
}

// ── Phase 51: Browser Performance Stack ─────────────────────────

/// Fast HTML parser for extracting data from raw HTML WITHOUT a browser.
/// ~100x faster than browser-based extraction for static pages.
/// For JavaScript-rendered content, use Browser.launch() + page.goto().
struct HtmlParser {
    // Static methods only — no instance state
}

impl HtmlParser {
    /// Extract text content matching a CSS selector from raw HTML.
    /// Supports tag selectors (h1, p, li), class selectors (.price),
    /// and ID selectors (#title).
    /// Returns an array of matching text strings with HTML tags stripped.
    fn parse(html: String, selector: String) -> []String {
        // native: string-based HTML parsing (no browser needed)
    }

    /// Extract all links (href attributes) from HTML.
    /// Filters out anchor-only (#) and javascript: links.
    fn links(html: String) -> []String {
        // native: extracts all href values
    }

    /// Extract meta information (title, description, keywords).
    /// Returns a struct with title, description, and keywords fields.
    fn meta(html: String) -> HtmlMeta {
        // native: extracts <title> and <meta> tags
    }
}

/// Meta information extracted from HTML <head>.
struct HtmlMeta {
    title:       String,
    description: String,
    keywords:    String,
}

/// Performance configuration presets for browser automation.
/// Controls resource blocking, wait strategies, and stealth levels.
struct PerfConfig {
    mode:              String,    // "fast" | "balanced" | "stealth"
    resource_blocking: bool,      // block images/fonts/CSS for speed
    default_wait:      String,    // "domcontentloaded" | "networkalmostidle" | "networkidle"
}

impl PerfConfig {
    /// Create a PerfConfig with a named mode.
    /// mode: "fast", "balanced", or "stealth"
    fn create(mode: String = "balanced") -> PerfConfig {
        // native: returns config struct for the specified mode
    }

    /// Fast preset: block ALL non-essential resources, DOMContentLoaded wait.
    /// Best for scraping static content where speed matters most.
    fn fast() -> PerfConfig {
        // native: { mode: "fast", resource_blocking: true, default_wait: "domcontentloaded" }
    }

    /// Balanced preset: block images/fonts, NetworkAlmostIdle wait.
    /// Good default for most scraping tasks.
    fn balanced() -> PerfConfig {
        // native: { mode: "balanced", resource_blocking: true, default_wait: "networkalmostidle" }
    }

    /// Stealth preset: allow ALL resources, NetworkIdle wait, full stealth profile.
    /// Use when the target site has bot detection.
    fn stealth() -> PerfConfig {
        // native: { mode: "stealth", resource_blocking: false, default_wait: "networkidle" }
    }
}

/// Persistent browser daemon for reusing browser instances across runs.
/// Reduces cold-start latency by keeping Chrome processes warm.
struct BrowserDaemon {
    // Static methods only — daemon runs as a background process
}

impl BrowserDaemon {
    /// Get the current daemon status.
    /// Returns running state, active instance count, and socket address.
    fn status() -> BrowserDaemonStatus {
        // native: checks if daemon process is alive
    }

    /// Get the daemon configuration.
    /// Returns max instances, tabs per instance, transport, and recycle threshold.
    fn config() -> BrowserDaemonConfig {
        // native: reads daemon config
    }
}

/// Status of the browser daemon process.
struct BrowserDaemonStatus {
    running:   bool,
    instances: i32,
    address:   String,
}

/// Configuration for the browser daemon.
struct BrowserDaemonConfig {
    max_instances:    i32,     // max Chrome processes (default: 4)
    tabs_per_instance: i32,    // tabs per Chrome process (default: 50)
    transport:        String,  // "pipe" | "websocket" (default: "pipe")
    recycle_after:    i32,     // recycle instance after N navigations (default: 100)
}

// ── Phase 49: Browser v2 — Full method wiring types ─────────────

/// Screenshot capture and comparison.
struct Screenshot {
    data_base64: String,
    width:       i64,
    height:      i64,
    format:      String,
    timestamp:   String,
    url:         String,
    selector:    String?,
}

impl Screenshot {
    /// Capture a full-page screenshot.
    fn capture(url: String, width: i64 = 1920, height: i64 = 1080) -> Screenshot { }
    /// Capture a screenshot of a specific element.
    fn capture_element(url: String, selector: String) -> Screenshot { }
    /// Compare two screenshots, returns match percentage.
    fn compare(a: Screenshot, b: Screenshot, threshold: f64 = 0.95) -> ScreenshotComparison { }
    /// Save a screenshot as a named baseline for regression testing.
    fn save_baseline(name: String, data: Screenshot) -> ScreenshotBaseline { }
}

struct ScreenshotComparison {
    match_percent:    f64,
    pixels_different: i64,
    passed:           bool,
    threshold:        f64,
}

struct ScreenshotBaseline {
    name:  String,
    hash:  String,
    saved: bool,
}

/// HAR (HTTP Archive) recorder for network traffic capture.
struct HarRecorder {
    entries:     []HarEntry,
    recording:   bool,
    format:      String,
    entry_count: i64,
}

struct HarEntry {
    method:      String,
    url:         String,
    status:      i64,
    duration_ms: i64,
}

impl HarRecorder {
    /// Create a new HAR recorder.
    fn create() -> HarRecorder { }
    /// Add a network entry to the recorder (immutable update).
    fn add_entry(recorder: HarRecorder, method: String, url: String, status: i64, duration_ms: i64) -> HarRecorder { }
    /// Export recorded entries as HAR 1.2 JSON.
    fn export(recorder: HarRecorder) -> String { }
    /// Stop recording (immutable update, sets recording: false).
    fn stop(recorder: HarRecorder) -> HarRecorder { }
}

/// Browser instance pool for parallel automation.
struct BrowserPool {
    max_size:    i64,
    max_tasks:   i64,
    active:      i64,
    idle:        i64,
    crashed:     i64,
    total_tasks: i64,
}

struct BrowserHandle {
    instance_id: String,
    session_id:  String,
    proxy:       String?,
}

struct AcquireResult {
    handle: BrowserHandle,
    pool:   BrowserPool,
}

struct PoolStats {
    max_size:    i64,
    max_tasks:   i64,
    active:      i64,
    idle:        i64,
    crashed:     i64,
    total_tasks: i64,
}

struct HealthCheckResult {
    healthy:  i64,
    crashed:  i64,
    recycled: i64,
}

impl BrowserPool {
    /// Create a browser pool with max_size instances.
    ///
    /// Optional trailing args: `headless` (default true) and an egress/stealth
    /// map `{proxy, tor, stealth, tier}`:
    ///   - proxy:   proxy URL for the pool's browsers ("socks5://…",
    ///              "http://…"). Wins over the TALLOW_PROXY env var.
    ///   - tor:     true routes pool browsers through Tor instances (3),
    ///              like TALLOW_TOR=1.
    ///   - stealth: stealth flags on each pool browser launch.
    ///   - tier:    "tor" | "direct" | "datacenter" | "residential" | "isp" |
    ///              "mobile". Classifies `proxy` explicitly; "direct" is an
    ///              explicit choice of direct egress (no env inheritance, no
    ///              leak warning).
    /// Keys omitted from the map fall back to TALLOW_PROXY / TALLOW_TOR.
    /// Without any egress the pool launches DIRECT and warns (real-IP leak
    /// risk). Real arm: interp.rs BrowserPool.create; per-instance egress is
    /// resolved in pool.rs resolve_proxy and applied to BrowserConfig.proxy
    /// (Chrome's --proxy-server flag).
    fn create(max_size: i64 = 4, max_tasks: i64 = 100, headless: bool = true, egress: Map?) -> BrowserPool { }
    /// Acquire a browser instance from the pool.
    fn acquire(pool: BrowserPool) -> AcquireResult { }
    /// Release a browser instance back to the pool.
    fn release(pool: BrowserPool, handle: BrowserHandle) -> BrowserPool { }
    /// Get current pool statistics.
    fn stats(pool: BrowserPool) -> PoolStats { }
    /// Run a health check on all pool instances.
    fn health_check(pool: BrowserPool) -> HealthCheckResult { }
}

/// Network request interceptor for blocking, mocking, and modifying requests.
struct NetworkInterceptor {
    rules:      []InterceptRule,
    active:     bool,
    rule_count: i64,
}

struct InterceptRule {
    pattern:     String,
    action:      String,
    mock_status: i64?,
    mock_body:   String?,
}

impl NetworkInterceptor {
    /// Create a new network interceptor.
    fn create() -> NetworkInterceptor { }
    /// Add a rule (pattern + action). Action: "block", "allow", "mock".
    fn add_rule(interceptor: NetworkInterceptor, pattern: String, action: String) -> NetworkInterceptor { }
    /// Block all requests matching a glob pattern.
    fn block_pattern(interceptor: NetworkInterceptor, glob: String) -> NetworkInterceptor { }
    /// Mock responses for matching requests.
    fn mock_response(interceptor: NetworkInterceptor, pattern: String, status: i64, body: String) -> NetworkInterceptor { }
    /// Clear all interception rules.
    fn clear(interceptor: NetworkInterceptor) -> NetworkInterceptor { }
}

/// Trace recorder for debugging and replay of browser sessions.
struct TraceRecorder {
    name:         String,
    actions:      []TraceAction,
    screenshots:  []Screenshot,
    network:      []HarEntry,
    recording:    bool,
    action_count: i64,
}

struct TraceAction {
    action_type: String,
    detail:      String,
    timestamp:   String,
}

impl TraceRecorder {
    /// Start recording a trace.
    fn start(name: String) -> TraceRecorder { }
    /// Record an action (click, type, navigate, etc.).
    fn record_action(trace: TraceRecorder, action_type: String, detail: String) -> TraceRecorder { }
    /// Stop recording.
    fn stop(trace: TraceRecorder) -> TraceRecorder { }
}

/// Session persistence manager for cookies and storage.
struct SessionData {
    cookies:              []String,
    local_storage_keys:   i64,
    session_storage_keys: i64,
    url:                  String,
    session_hash:         String,
}

struct SavedSession {
    name:      String,
    encrypted: bool,
    hash:      String,
}

impl SessionManager {
    /// Capture the current session state (cookies, storage).
    fn capture(url: String) -> SessionData { }
    /// Save a session to encrypted storage.
    fn save(session: SessionData, name: String) -> SavedSession { }
    /// Load a previously saved session.
    fn load(name: String) -> SessionData { }
    /// Clear all saved sessions.
    fn clear() -> SessionResult { }
}

/// Accessibility auditing tools (WCAG compliance).
struct AccessibilityReport {
    url:        String,
    violations: []String,
    passes:     i64,
    incomplete: i64,
    level:      String,
}

struct AccessibilityTree {
    url:            String,
    root_role:      String,
    children_count: i64,
    total_nodes:    i64,
}

struct ContrastResult {
    foreground: String,
    background: String,
    ratio:      f64,
    aa_pass:    bool,
    aaa_pass:   bool,
}

impl AccessibilityAudit {
    /// Run a full accessibility audit on a URL.
    fn run(url: String) -> AccessibilityReport { }
    /// Get the accessibility tree for a page.
    fn get_tree(url: String) -> AccessibilityTree { }
    /// Check color contrast ratio (WCAG AA/AAA).
    fn check_contrast(foreground: String, background: String) -> ContrastResult { }
}

/// Device emulation for viewport, mobile, geolocation, timezone, and locale.
struct ViewportConfig {
    width:   i64,
    height:  i64,
    scale:   f64,
    applied: bool,
}

struct MobileConfig {
    device:     String,
    width:      i64,
    height:     i64,
    scale:      f64,
    user_agent: String,
    applied:    bool,
}

struct GeolocationConfig {
    lat:      f64,
    lon:      f64,
    accuracy: i64,
    applied:  bool,
}

impl DeviceEmulator {
    /// Set viewport dimensions and device pixel ratio.
    fn set_viewport(width: i64, height: i64, scale: f64 = 1.0) -> ViewportConfig { }
    /// Emulate a mobile device by name (iPhone 14, Pixel 7, iPad Pro).
    fn set_mobile(device_name: String) -> MobileConfig { }
    /// Set geolocation coordinates.
    fn set_geolocation(lat: f64, lon: f64) -> GeolocationConfig { }
    /// Set timezone for the browser context.
    fn set_timezone(tz: String) -> TimezoneConfig { }
    /// Set locale for the browser context.
    fn set_locale(locale: String) -> LocaleConfig { }
    /// Set a custom user agent string.
    fn set_user_agent(ua: String) -> UserAgentConfig { }
    /// Clear all emulation settings.
    fn clear() -> EmulatorResult { }
}

/// CAPTCHA detection and classification.
struct CaptchaScanResult {
    url:          String,
    detected:     bool,
    captcha_type: String?,
    confidence:   f64,
}

impl CaptchaDetector {
    /// Scan a URL for CAPTCHA presence.
    fn scan(url: String) -> CaptchaScanResult { }
    /// List supported CAPTCHA types.
    fn types() -> []String { }
}

/// robots.txt compliance checker.
struct RobotsResult {
    url:          String,
    user_agent:   String,
    allowed:      bool,
    crawl_delay:  i64,
    sitemap_urls: []String,
}

impl RobotsChecker {
    /// Check if a URL is allowed by robots.txt for a given user agent.
    fn check(url: String, user_agent: String = "tallow/0.1") -> RobotsResult { }
    /// Find sitemap URLs for a domain.
    fn find_sitemaps(domain: String) -> []String { }
}

/// Retry policy for robust browser automation.
struct RetryPolicy {
    max_retries:  i64,
    strategy:     String,
    base_delay_ms: i64,
    max_delay_ms:  i64,
}

impl RetryPolicy {
    /// Create a retry policy.
    fn create(max_retries: i64 = 3, strategy: String = "exponential") -> RetryPolicy { }
    /// Configure backoff timing.
    fn with_backoff(policy: RetryPolicy, initial_ms: i64, max_ms: i64) -> RetryPolicy { }
}

// ── Phase 52: Device Profiles & Anti-Detection Suite ──────────────────

/// Device profile from the 163-profile registry (matching Playwright descriptors).
struct DeviceProfile {
    name:                String,
    viewport_width:      i32,
    viewport_height:     i32,
    device_scale_factor: f64,
    is_mobile:           bool,
    has_touch:           bool,
    user_agent:          String,
    default_browser:     String,
}

impl Device {
    /// Get a device profile by name (case-insensitive). Returns nil if not found.
    fn get(name: String) -> DeviceProfile? { }
    /// List all 163 device profile names.
    fn list() -> []String { }
    /// List device names filtered by category: "iphone", "ipad", "pixel", "galaxy", "desktop", "mobile", "tablet".
    fn list_category(category: String) -> []String { }
}

/// Correlated browser fingerprint profile for stealth automation.
/// All fields are internally consistent: UA matches platform, touch points match mobile flag, etc.
struct StealthProfile {
    user_agent:          String,
    platform:            String,
    vendor:              String,
    languages:           []String,
    hardware_concurrency: i32,
    device_memory:       f64,
    max_touch_points:    i32,
    viewport_width:      i32,
    viewport_height:     i32,
    device_scale_factor: f64,
    webgl_vendor:        String,
    webgl_renderer:      String,
    timezone:            String,
    locale:              String,
    canvas_noise_seed:   i64,
}

/// Stealth profile creation, randomization, and validation.
impl StealthProfile {
    /// Create a named stealth profile with correlated fingerprint data.
    /// Names: "chrome_windows", "chrome_macos", "chrome_linux", "chrome_android",
    ///        "safari_ios", "firefox_windows", "edge_windows"
    fn create(name: String) -> StealthProfile { }
    /// Generate a random consistent stealth profile from built-in presets.
    fn randomize() -> StealthProfile { }
    /// Validate that a profile's fields are internally consistent.
    /// Returns { consistent: bool, warnings: []String }.
    fn validate(profile: StealthProfile) -> ValidationResult { }
}

/// Anti-detection check result.
struct AntiDetectResult {
    bot_detected:     bool,
    detection_methods: []String,
    risk_score:       f64,
}

/// Browser fingerprint with 35 fingerprint vectors.
struct BrowserFingerprint {
    user_agent:          String,
    platform:            String,
    languages:           []String,
    color_depth:         i32,
    screen_width:        i32,
    screen_height:       i32,
    timezone_offset:     i32,
    session_storage:     bool,
    local_storage:       bool,
    indexed_db:          bool,
    open_database:       bool,
    cpu_class:           String,
    navigator_platform:  String,
    do_not_track:        String,
    plugins_count:       i32,
    canvas_hash:         String,
    webgl_vendor:        String,
    webgl_renderer:      String,
    webgl_hash:          String,
    has_lied_languages:  bool,
    has_lied_resolution: bool,
    has_lied_os:         bool,
    has_lied_browser:    bool,
    touch_support:       bool,
    max_touch_points:    i32,
    audio_context_hash:  String,
    fonts_count:         i32,
    font_list_hash:      String,
    webrtc_leak:         bool,
    hardware_concurrency: i32,
    device_memory:       f64,
    battery_charging:    bool,
    battery_level:       f64,
    media_devices_count: i32,
    speech_voices_count: i32,
    permissions_state:   String,
}

/// WebRTC leak check result.
struct WebRtcLeakResult {
    leak_detected: bool,
    local_ip:      String,
}

/// Anti-detection suite for browser automation.
impl AntiDetect {
    /// Run anti-detection checks against a URL.
    fn check(url: String) -> AntiDetectResult { }
    /// Get the full browser fingerprint (35 vectors).
    fn fingerprint() -> BrowserFingerprint { }
    /// Check for WebRTC IP leaks.
    fn webrtc_leak_check() -> WebRtcLeakResult { }
}

// ── Phase 64: Enterprise Browser Features ──────────────────────────────

/// BLAKE3-chained audit log for all browser operations.
/// Provides tamper-evident logging with cryptographic chain integrity.
/// Uses a global append-only log — all entries are linked by BLAKE3 hashes.
struct BrowserAudit {
    // Module sentinel — static methods only
}

/// Single audit log entry with chain hash.
struct AuditEntry {
    index:       i64,
    timestamp:   String,
    action:      String,
    url:         String,
    legal_basis: String,
    details:     String,
    prev_hash:   String,
    entry_hash:  String,
}

/// Result of verifying the audit chain integrity.
struct AuditVerification {
    chain_intact: bool,
    entries:      i64,
}

/// Exported audit log (JSON or text format).
struct AuditExport {
    format:  String,
    entries: []AuditEntry?,  // present for JSON format
    text:    String?,        // present for text format
    count:   i64,
}

/// Compliance report for a specific jurisdiction.
struct ComplianceReport {
    jurisdiction:   String,
    total_entries:  i64,
    status:         String,    // "compliant" | "non_compliant" | "unknown"
    recommendation: String,
}

impl BrowserAudit {
    /// Log a browser operation to the BLAKE3-chained audit log.
    /// Each entry's hash includes the previous entry's hash, forming a tamper-evident chain.
    fn log(action: String, url: String, legal_basis: String = "public_data", details: String = "") -> AuditEntry { }

    /// Verify the integrity of the entire audit chain.
    /// Returns whether all BLAKE3 hashes are consistent.
    fn verify() -> AuditVerification { }

    /// Export all audit log entries in the specified format.
    /// format: "json" (default) or "text"
    fn export(format: String = "json") -> AuditExport { }

    /// Generate a compliance report for a specific jurisdiction.
    /// jurisdiction: "eu", "us", "uk", etc.
    fn compliance_report(jurisdiction: String = "eu") -> ComplianceReport { }
}

/// Runtime rate limiting per domain.
/// Prevents overloading target servers by enforcing configurable request rates.
struct DomainRateLimiter {
    domains:      Map<String, RateConfig>,
    domain_count: i64,
}

/// Rate configuration for a single domain.
struct RateConfig {
    rate:             f64,
    last_request_ms:  i64,
}

/// Result of a rate limit check.
struct RateLimitResult {
    allowed:      bool,
    wait_ms:      i64,
    domain:       String,
    current_rate: f64,
}

/// Per-domain rate statistics.
struct DomainRateStats {
    domain:      String,
    rate:        f64,
    interval_ms: i64,
}

/// Aggregate rate limiter statistics.
struct RateLimiterStats {
    domains:      []DomainRateStats,
    domain_count: i64,
}

impl DomainRateLimiter {
    /// Create an empty rate limiter with no domain configurations.
    fn create() -> DomainRateLimiter { }

    /// Set the request rate for a specific domain.
    /// requests_per_second: maximum requests per second for this domain.
    fn set_rate(limiter: DomainRateLimiter, domain: String, requests_per_second: f64) -> DomainRateLimiter { }

    /// Check if a request to a domain is currently allowed.
    /// Returns allowed status and wait time if rate-limited.
    fn check(limiter: DomainRateLimiter, domain: String) -> RateLimitResult { }

    /// Get per-domain rate statistics.
    fn get_stats(limiter: DomainRateLimiter) -> RateLimiterStats { }
}

/// Session affinity for multi-step browser workflows.
/// Binds proxy, user-agent, and fingerprint to a single session identity.
struct StickySession {
    session_id:     String,
    proxy:          String,
    user_agent:     String,
    fingerprint_id: String,
    cookies_hash:   String,
    created_at:     String,
    requests_count: i64,
    last_used:      String,
}

/// Session validation result.
struct SessionValidation {
    valid:                  bool,
    proxy_consistent:       bool,
    ua_consistent:          bool,
    fingerprint_consistent: bool,
}

impl StickySession {
    /// Create a new sticky session binding proxy, user-agent, and fingerprint.
    fn create(proxy: String, user_agent: String = "tallow/0.1", fingerprint_id: String = "default") -> StickySession { }

    /// Validate that a session's identity parameters are all consistent.
    fn validate(session: StickySession) -> SessionValidation { }

    /// Extend a session with additional cookies (immutable update).
    fn extend(session: StickySession, extra_cookies: String) -> StickySession { }
}

/// Process isolation per job or tenant.
/// Each sandbox gets its own temp directory and simulated process boundary.
struct BrowserSandbox {
    job_id:        String,
    user_data_dir: String,
    process_id:    i64,
    isolated:      bool,
    destroyed:     bool,
}

/// Result of destroying a sandbox.
struct SandboxDestroyed {
    destroyed:      bool,
    data_wiped:     bool,
    process_killed: bool,
}

/// Result of checking sandbox isolation.
struct IsolationCheck {
    isolated:          bool,
    no_cookie_leakage: bool,
    separate_process:  bool,
}

impl BrowserIsolation {
    /// Create an isolated sandbox for a browser job.
    fn create_sandbox(job_id: String = "job-0") -> BrowserSandbox { }

    /// Destroy a sandbox, wiping all data and killing the process.
    fn destroy_sandbox(sandbox: BrowserSandbox) -> SandboxDestroyed { }

    /// Check that a sandbox is properly isolated.
    fn check_isolation(sandbox: BrowserSandbox) -> IsolationCheck { }
}

/// Webhook notifications for browser automation events.
struct BrowserWebhook {
    // Module sentinel — static methods only
}

/// Webhook configuration.
struct WebhookConfig {
    url:    String,
    events: []String,
    secret: String,
    active: bool,
}

/// Result of firing a webhook.
struct WebhookFired {
    fired:     bool,
    event:     String,
    timestamp: String,
    signature: String,   // HMAC-BLAKE3 signature
}

/// Result of testing a webhook endpoint.
struct WebhookTestResult {
    success:     bool,
    url:         String,
    status_code: i64,
    latency_ms:  i64,
}

impl BrowserWebhook {
    /// Configure a webhook endpoint for browser events.
    /// events: "job_started", "job_completed", "job_failed", "rate_limited",
    ///         "pii_detected", "tos_changed", "screenshot_captured"
    fn config(url: String, events: []String = ["job_completed"], secret: String = "webhook-secret") -> WebhookConfig { }

    /// Fire a webhook notification for a specific event.
    /// Returns the fired status and HMAC-BLAKE3 signature.
    fn fire(config: WebhookConfig, event: String, payload: String = "") -> WebhookFired { }

    /// Send a test ping to the webhook endpoint.
    fn test(config: WebhookConfig) -> WebhookTestResult { }
}

/// Screenshot storage with content-addressed paths and retention policies.
struct ScreenshotArchive {
    base_dir:       String,
    retention_days: i64,
    entries:        []ScreenshotEntry,
    total_size:     i64,
}

/// Metadata for a stored screenshot.
struct ScreenshotEntry {
    url:        String,
    path:       String,
    hash:       String,
    size:       i64,
    timestamp:  String,
    expires_at: String,
}

/// Result of storing a screenshot.
struct ScreenshotStored {
    stored:     bool,
    path:       String,
    hash:       String,
    size:       i64,
    expires_at: String,
}

/// Result of purging expired screenshots.
struct PurgeResult {
    purged_count: i64,
    bytes_freed:  i64,
}

impl ScreenshotArchive {
    /// Create a screenshot archive with a base directory and retention period.
    fn create(base_dir: String = "/tmp/tallow-screenshots", retention_days: i64 = 30) -> ScreenshotArchive { }

    /// Store a screenshot (base64-encoded) for a URL.
    /// Path: {base_dir}/{BLAKE3(url)[0:8]}/{timestamp}.png
    fn store(archive: ScreenshotArchive, url: String, screenshot_data_b64: String) -> ScreenshotStored { }

    /// Purge all expired screenshots from the archive.
    fn purge(archive: ScreenshotArchive) -> PurgeResult { }

    /// List all stored screenshots with metadata.
    fn list(archive: ScreenshotArchive) -> []ScreenshotEntry { }
}

/// Jurisdiction-aware robots.txt compliance auditing.
/// Provides both technical robots.txt parsing and legal analysis per jurisdiction.
struct RobotsTxtAudit {
    // Module sentinel — static methods only
}

/// robots.txt check result.
struct RobotsTxtResult {
    url:           String,
    user_agent:    String,
    allowed:       bool,
    crawl_delay_s: i64,
    sitemap_urls:  []String,
}

/// Jurisdiction-specific robots.txt legal analysis.
struct JurisdictionReport {
    url:                String,
    jurisdiction:       String,
    robots_respected:   bool,
    legal_status:       String,   // "advisory" | "non_binding" | "unknown"
    recommendation:     String,
    case_law_reference: String,
}

impl RobotsTxtAudit {
    /// Check if a URL is allowed by robots.txt for a given user agent.
    fn check(url: String, user_agent: String = "tallow/0.1") -> RobotsTxtResult { }

    /// Generate a jurisdiction-specific legal analysis of robots.txt compliance.
    /// Includes case law references:
    ///   "eu": "CNIL treats robots.txt as LIA evidence (2023)"
    ///   "us": "hiQ v. LinkedIn — robots.txt not binding under CFAA (9th Cir. 2022)"
    ///   "uk": "No specific case law — follow EU guidance"
    ///   "au": "Privacy Act 1988 — treat as EU equivalent"
    fn jurisdiction_report(url: String, jurisdiction: String = "eu") -> JurisdictionReport { }
}

/// BLAKE3-based content deduplication registry.
/// Tracks content hashes to detect and count duplicate content.
struct ContentDedup {
    hashes:          Map<String, String>,
    total_checked:   i64,
    unique_count:    i64,
    duplicate_count: i64,
}

/// Result of checking content for duplication.
struct DedupResult {
    is_duplicate: bool,
    hash:         String,
    first_seen:   String,
}

/// Deduplication statistics.
struct DedupStats {
    total_checked:   i64,
    unique_count:    i64,
    duplicate_count: i64,
    dedup_rate:      f64,
}

impl ContentDedup {
    /// Create an empty deduplication registry.
    fn create() -> ContentDedup { }

    /// Check if content already exists in the registry (does NOT add it).
    fn check(registry: ContentDedup, content: String) -> DedupResult { }

    /// Add content to the registry (immutable update). Tracks duplicates.
    fn add(registry: ContentDedup, content: String) -> ContentDedup { }

    /// Get deduplication statistics.
    fn stats(registry: ContentDedup) -> DedupStats { }
}

/// Memory scrubbing after sensitive page visits.
/// Ensures no residual data remains in browser state after processing sensitive content.
struct MemoryScrub {
    // Module sentinel — static methods only
}

/// Result of scrubbing a page.
struct ScrubResult {
    scrubbed:           bool,
    page_url:           String,
    navigated_to_blank: bool,
    cookies_cleared:    bool,
    storage_cleared:    bool,
}

/// Result of scrubbing an entire session.
struct SessionScrubResult {
    scrubbed:       bool,
    session_id:     String,
    process_killed: bool,
}

/// Scrub policy based on sensitivity level.
struct ScrubPolicy {
    level:   String,
    actions: []String,
}

impl MemoryScrub {
    /// Scrub all browser state after visiting a page.
    /// Navigates to about:blank, clears cookies, clears storage.
    fn scrub_page(page_url: String) -> ScrubResult { }

    /// Scrub an entire browser session, killing the process.
    fn scrub_session(session_id: String) -> SessionScrubResult { }

    /// Get the scrub policy for a given sensitivity level.
    /// "standard": clear cookies + local storage
    /// "sensitive": navigate blank + clear all storage + clear cache
    /// "critical": all of sensitive + kill process + wipe user data dir
    fn policy(sensitivity_level: String = "standard") -> ScrubPolicy { }
}

// ── Phase 65: Enterprise Browser Features Batch 2 ──────────────────────

/// PII tier classification following GDPR Art.9 categories.
/// Classifies text into 5 tiers:
///   T1 (Special category Art.9): health, religion, political, biometric, sexual orientation, ethnicity
///   T2 (Sensitive PII): SSN, passport, financial accounts, tax IDs
///   T3 (Standard PII): email, phone, name, physical address
///   T4 (Pseudonymous): UUID, hex hashes, device IDs
///   T5 (Non-PII): everything else
struct PiiClassifier {
    // Module sentinel — static methods only
}

struct PiiClassification {
    tier:               String,    // "T1" .. "T5"
    categories:         []String,  // detected PII categories
    pii_count:          i32,       // number of PII elements found
    highest_risk:       String,    // "critical" | "high" | "medium" | "low" | "none"
    requires_art9_basis: bool,     // true if Art.9 legal basis needed
}

struct PiiScanResult {
    tier:          String,
    redacted_text: String,
    detections:    []PiiDetection,
}

struct PiiDetection {
    detection_type: String,
    value_preview:  String,
    position:       i32,
    tier:           String,
}

struct PiiPolicy {
    allowed_bases:        []String,
    requires_dpa:         bool,
    requires_art9_consent: bool,
    max_retention_days:   i32,
}

impl PiiClassifier {
    /// Classify text into a PII tier (T1-T5).
    fn classify(text: String) -> PiiClassification { }

    /// Scan text, classify PII, and return redacted version with detections.
    fn scan_and_classify(text: String) -> PiiScanResult { }

    /// Get the GDPR policy requirements for a given tier.
    fn policy(tier: String) -> PiiPolicy { }
}

/// Terms of Service change detection and monitoring.
/// Snapshots ToS content, detects changes, and flags significant modifications
/// (e.g., new restrictions on scraping or automated access).
struct TosMonitor {
    // Module sentinel — static methods only
}

struct TosSnapshot {
    url:          String,
    content_hash: String,   // BLAKE3 hash
    word_count:   i32,
    snapshot_at:  String,   // ISO 8601 timestamp
}

struct TosComparison {
    changed:            bool,
    hash_changed:       bool,
    word_count_delta:   i32,
    significant_change: bool,   // >5% word change OR restrictive keywords added
}

struct TosWatch {
    url:              String,
    legal_basis_ref:  String,
    monitoring:       bool,
    check_interval:   String,
}

impl TosMonitor {
    /// Take a snapshot of ToS content for later comparison.
    fn snapshot(url: String, content: String) -> TosSnapshot { }

    /// Compare a previous snapshot with new content.
    /// Detects significant changes: >5% word delta or restrictive keywords
    /// ("prohibit", "restrict", "automated", "scraping", "crawling", "bot", "data collection").
    fn compare(old_snapshot: TosSnapshot, new_content: String) -> TosComparison { }

    /// Start monitoring a ToS URL for changes.
    fn watch(url: String, legal_basis_ref: String = "public_data") -> TosWatch { }
}

/// Data Processing Agreement generator.
/// Creates structured DPA documents from @legal metadata.
/// Output is GDPR-compliant and includes standard security measures.
struct DpaGenerator {
    // Module sentinel — static methods only
}

struct DataProcessingAgreement {
    version:             String,
    parties:             DpaParties,
    data_categories:     []String,
    processing_purposes: []String,
    legal_basis:         String,
    retention:           String,
    jurisdiction:        []String,
    sub_processors:      []String,
    security_measures:   []String,
    data_subject_rights: DataSubjectRights,
    generated_at:        String,
    tallow_version:        String,
}

struct DpaParties {
    controller: String,
    processor:  String,
}

struct DataSubjectRights {
    access:      bool,
    erasure:     bool,
    portability: bool,
}

struct DpaValidation {
    valid:          bool,
    missing_fields: []String,
    gdpr_compliant: bool,
}

impl DpaGenerator {
    /// Generate a DPA from data categories, purposes, retention, jurisdictions, and sub-processors.
    fn generate(data_categories: []String, purposes: []String, retention_days: i32, jurisdictions: []String, sub_processors: []String) -> DataProcessingAgreement { }

    /// Convert a DPA to human-readable text.
    fn to_text(dpa: DataProcessingAgreement) -> String { }

    /// Validate a DPA has all required fields.
    fn validate(dpa: DataProcessingAgreement) -> DpaValidation { }
}

/// Data quality scoring for extracted data.
/// Measures completeness, confidence, and overall quality.
struct DataQuality {
    // Module sentinel — static methods only
}

struct DataQualityScore {
    completeness:    f64,    // 0.0 to 1.0 — ratio of non-empty fields
    freshness_hours: f64,
    confidence:      String, // "high" | "medium" | "low"
    overall:         f64,    // weighted: completeness*0.6 + confidence*0.4
}

struct SchemaValidation {
    valid:           bool,
    missing_fields:  []String,
    extra_fields:    []String,
    type_mismatches: []TypeMismatch,
}

struct TypeMismatch {
    field:    String,
    expected: String,
    actual:   String,
}

impl DataQuality {
    /// Score data quality against expected fields.
    fn score(data: Map<String, String>, expected_fields: []String) -> DataQualityScore { }

    /// Validate data against a schema (field names and types).
    fn validate_schema(data: Map<String, String>, schema: Map<String, String>) -> SchemaValidation { }
}

/// Secure credential management with in-memory encryption.
/// Passwords are AES-256-GCM encrypted and zero-wiped on delete.
/// NEVER logged, NEVER in audit trails.
struct CredentialVault {
    // Module sentinel — static methods only
}

struct CredentialStoreResult {
    stored:    bool,
    name:      String,
    encrypted: bool,
}

struct Credential {
    name:     String,
    username: String,
    password: String,
}

struct CredentialDeleteResult {
    deleted:     bool,
    zero_wiped:  bool,
}

struct CredentialRotateResult {
    rotated:    bool,
    old_wiped:  bool,
}

impl CredentialVault {
    /// Store a credential (encrypted in memory, never logged).
    fn store(name: String, username: String, password: String) -> CredentialStoreResult { }

    /// Retrieve a credential (decrypted on access).
    fn get(name: String) -> Credential { }

    /// Delete a credential (zero-wipes memory before removal).
    fn delete(name: String) -> CredentialDeleteResult { }

    /// List credential names only (NO passwords, NO usernames).
    fn list() -> []String { }

    /// Rotate a credential's password (zero-wipes old, encrypts new).
    fn rotate(name: String, new_password: String) -> CredentialRotateResult { }
}

/// Geographic proxy routing.
/// Routes requests through proxies matching the target jurisdiction.
struct GeoProxy {
    // Module sentinel — static methods only
}

struct GeoProxyPool {
    proxies: []GeoProxyEntry,
    count:   i32,
    active:  bool,
}

struct GeoProxyEntry {
    url:     String,
    country: String,
}

struct GeoProxyRoute {
    selected_proxy:     String,
    country:            String,
    latency_estimate_ms: i32,
}

struct GeoProxyStat {
    country: String,
    count:   i32,
    healthy: bool,
}

impl GeoProxy {
    /// Create a proxy pool from an array of {url, country} entries.
    fn create(proxies_with_geo: []GeoProxyEntry) -> GeoProxyPool { }

    /// Route a request through a proxy matching the jurisdiction.
    fn route(pool: GeoProxyPool, target_url: String, jurisdiction: String = "any") -> GeoProxyRoute { }

    /// Add a proxy to an existing pool.
    fn add(pool: GeoProxyPool, proxy_url: String, country: String) -> GeoProxyPool { }

    /// Get per-country proxy statistics.
    fn stats(pool: GeoProxyPool) -> []GeoProxyStat { }
}

/// Priority job queue with retry and dead letter queue (DLQ).
/// In-memory, suitable for single-process deployment.
/// Priority: critical=0, high=1, normal=2, low=3. Dequeue returns lowest first.
struct BrowserJobQueue {
    // Module sentinel — static methods only
}

struct BrowserJob {
    id:          i32,
    name:        String,
    priority:    i32,
    url:         String,
    retry_count: i32,
    status:      String,
}

struct DequeueResult {
    job:   BrowserJob?,
    queue: BrowserJobQueue,
}

struct QueueStatus {
    pending:           i32,
    active:            i32,
    completed:         i32,
    failed:            i32,
    dead_letter_count: i32,
}

impl BrowserJobQueue {
    /// Create an empty job queue.
    fn create() -> BrowserJobQueue { }

    /// Enqueue a job with name, priority, URL, and optional config.
    fn enqueue(queue: BrowserJobQueue, job_name: String, priority: String, url: String, config: String?) -> BrowserJobQueue { }

    /// Dequeue the highest-priority job.
    fn dequeue(queue: BrowserJobQueue) -> DequeueResult { }

    /// Re-enqueue a job by ID with incremented retry count.
    fn retry(queue: BrowserJobQueue, job_id: i32) -> BrowserJobQueue { }

    /// Move a job to the dead letter queue with a reason.
    fn dead_letter(queue: BrowserJobQueue, job_id: i32, reason: String) -> BrowserJobQueue { }

    /// Get queue status (pending, active, completed, failed, DLQ counts).
    fn status(queue: BrowserJobQueue) -> QueueStatus { }
}

/// Health monitoring for browser pool operations.
/// Records events, computes summaries, and exports Prometheus metrics.
struct BrowserHealthMetrics {
    // Module sentinel — static methods only
}

struct HealthEvent {
    event_type:  String,
    domain:      String,
    duration_ms: i32,
    success:     bool,
}

struct HealthSummary {
    total_requests:   i32,
    success_rate:     f64,
    avg_duration_ms:  f64,
    p95_duration_ms:  f64,
    errors_by_type:   Map<String, i32>,
    domains_accessed: []String,
}

impl BrowserHealthMetrics {
    /// Create an empty metrics store.
    fn create() -> BrowserHealthMetrics { }

    /// Record a health event (event type, domain, duration, success).
    fn record(metrics: BrowserHealthMetrics, event_type: String, domain: String, duration_ms: i32, success: bool) -> BrowserHealthMetrics { }

    /// Compute summary statistics from recorded events.
    fn summary(metrics: BrowserHealthMetrics) -> HealthSummary { }

    /// Export metrics in Prometheus exposition format.
    fn prometheus(metrics: BrowserHealthMetrics) -> String { }
}


// ── Browser contract facade (Phase 3/4 metadata) ─────────────────────

/// Machine-readable manifest of the browser automation surface.
/// Non-live: reports contract status for Browser.launch, Page.goto, cdp.pipe, etc.
fn browser_surface_manifest() -> BrowserSurfaceManifest {
    // native: returns contract metadata for the browser surface
}

/// Status of the CDP pipe transport (--remote-debugging-pipe).
/// Reports fail-closed: pipe transport is not yet implemented.
fn browser_pipe_transport_status() -> BrowserPipeTransportStatus {
    // native: returns pipe transport contract status
}

/// Boundary of the Phase 4 local/non-live browser fallback service.
fn browser_fallback_boundary() -> BrowserFallbackBoundary {
    // native: returns fallback boundary contract metadata
}

/// Status of the Phase 4 browser fallback service (local, non-live planner).
fn browser_fallback_service_status() -> BrowserFallbackServiceStatus {
    // native: returns fallback service status metadata
}

/// Browser surface manifest struct.
struct BrowserSurfaceManifest {
    schema_version: String,
    phase: String,
    completion_boundary: String,
    claims_live_browser_ready: bool,
    claims_production_fallback_ready: bool,
    non_claim: String,
    entries: []BrowserSurfaceEntry,
}

/// A single entry in the browser surface manifest.
struct BrowserSurfaceEntry {
    name: String,
    kind: String,
    status: String,
    transport: String,
    implemented: bool,
    fail_closed: bool,
    evidence: String,
}

/// CDP pipe transport status struct.
struct BrowserPipeTransportStatus {
    transport: String,
    status: String,
    rejects_before_launch: bool,
    opens_debug_port: bool,
    launches_browser: bool,
    claims_lower_latency: bool,
    operator_action: String,
    evidence: String,
}

/// Browser fallback boundary struct.
struct BrowserFallbackBoundary {
    status: String,
    mock_cdp_navigation_event_fallback_tested: bool,
    http_to_live_browser_fallback_ready: bool,
    claims_production_fallback_ready: bool,
    allowed_phase3_proof: String,
    human_gate: String,
}

/// Browser fallback service status struct.
struct BrowserFallbackServiceStatus {
    schema_version: String,
    phase: String,
    status: String,
    reason_codes_supported: bool,
    budgets_supported: bool,
    artifact_policy_hooks_supported: bool,
    launches_browser: bool,
    performs_network_io: bool,
    captures_screenshots_har_dom: bool,
    uses_credentials_or_sessions: bool,
    pipe_status: String,
    artifact_manifest: String,
    non_claim: String,
}
