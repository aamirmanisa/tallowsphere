# Tallow Browser System — Complete Specification

> **Version:** 0.4.0  
> **Modules:** 138 source files / 101,790 LOC / 1,609 test fns (re-measured in this tree 2026-10-15;
> the previous figures were 132 / 95,778 / 1,505 as verified 2026-09-12). `Config Files: 15` and
> `Device Profiles: 163` were re-checked the same day and are accurate — `tallow browser config list`
> enumerates all 15 by name, and `tallow browser devices` reports 163 total.  
> **Config Files:** 15  
> **Device Profiles:** 163  
> **Evasion Vectors:** 20+  
> **Search Engines:** 8  
> **CAPTCHA Types:** 8  

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Browser Process & Transport](#2-browser-process--transport)
3. [CDP Client](#3-cdp-client)
4. [Page & Navigation](#4-page--navigation)
5. [Element Querying & Interaction](#5-element-querying--interaction)
6. [Stealth V1 — Classic Anti-Detection](#6-stealth-v1--classic-anti-detection)
7. [Stealth V2 — Advanced Evasion](#7-stealth-v2--advanced-evasion)
8. [Tor Integration](#8-tor-integration)
9. [Plugin System (10 Built-In)](#9-plugin-system-10-built-in)
10. [Privacy & PII Protection](#10-privacy--pii-protection)
11. [Network Interception](#11-network-interception)
12. [Session Management](#12-session-management)
13. [Authentication (OAuth + TOTP)](#13-authentication-oauth--totp)
14. [CAPTCHA Detection & Solving](#14-captcha-detection--solving)
15. [Search Engine Cascade](#15-search-engine-cascade)
16. [Device Emulation](#16-device-emulation)
17. [Recording & Video Capture](#17-recording--video-capture)
18. [Visual Testing & Screenshots](#18-visual-testing--screenshots)
19. [Accessibility & WCAG Auditing](#19-accessibility--wcag-auditing)
20. [Trace Recording & Replay](#20-trace-recording--replay)
21. [HTML Parser](#21-html-parser)
22. [Browser Pool](#22-browser-pool)
23. [Distributed Pool](#23-distributed-pool)
24. [Scheduler](#24-scheduler)
25. [Retry & Rate Limiting](#25-retry--rate-limiting)
26. [robots.txt Compliance](#26-robotstxt-compliance)
27. [Browser Download & Management](#27-browser-download--management)
28. [IPPool & Kernel Tuning](#28-ippool--kernel-tuning)
29. [Configuration System](#29-configuration-system)
30. [CLI Reference](#30-cli-reference)
31. [Error Types](#31-error-types)
32. [Integration Map](#32-integration-map)

---

## 1. Architecture Overview

The Tallow browser system is a CDP-based (Chrome DevTools Protocol) browser automation engine built in Rust. It controls real Chrome/Chromium binaries — no patched browsers, no custom engines. This means authentic TLS fingerprints (JA3/JA4), real rendering, and genuine browser behavior.

```
┌─────────────────────────────────────────────────────────┐
│                    Tallow Browser System                  │
├─────────────┬───────────────┬───────────────────────────┤
│  Process    │  CDP Client   │  Page / Element / Frame   │
│  Lifecycle  │  WebSocket    │  Navigation & DOM         │
│  Chrome     │  Pipe (opt)   │  Querying & Interaction   │
├─────────────┼───────────────┼───────────────────────────┤
│  Stealth V1 │  Stealth V2   │  Tor Stealth              │
│  6 vectors  │  13 vectors   │  Firefox ESR profile      │
├─────────────┼───────────────┼───────────────────────────┤
│  Plugins    │  Privacy/PII  │  Network Interception     │
│  10 toggles │  8 PII types  │  HAR / WebSocket          │
├─────────────┼───────────────┼───────────────────────────┤
│  Sessions   │  Auth/TOTP    │  CAPTCHA (8 types)        │
│  PQC crypto │  OAuth flows  │  5 solver backends        │
├─────────────┼───────────────┼───────────────────────────┤
│  Search     │  Emulation    │  Recording                │
│  8 engines  │  163 devices  │  4K, 3 codecs             │
├─────────────┼───────────────┼───────────────────────────┤
│  Pool       │  Distributed  │  Scheduler                │
│  Semaphore  │  Gossip/QUIC  │  Cron/Interval            │
├─────────────┼───────────────┼───────────────────────────┤
│  Retry      │  Robots.txt   │  Config (15 TOML files)   │
│  Backoff    │  Rate limit   │  Full customization       │
└─────────────┴───────────────┴───────────────────────────┘
```

### Key Design Principles

- **Real Chrome, not patched** — authentic JA3/JA4 TLS fingerprints
- **CDP protocol** — standard Chrome DevTools Protocol, no custom extensions
- **Stealth by default** — 20+ JS-vector evasion toggles injected before page load (design targets, not a guarantee against anti-bot systems; main-world injection is inspectable)
- **Privacy first** — PII scanning, auto-redaction, data retention tracking
- **Legal compliance** — robots.txt, rate limiting, audit-ready
- **Session crypto today** — AES-256-GCM + HKDF (code comment: "not PQC"); ML-KEM-768 session encryption is a design target
- **Zero external dependencies at runtime** — all plugins are built-in
- **Cross-platform** — Windows, macOS, Linux (x86-64, ARM64)

---

## 2. Browser Process & Transport

### BrowserConfig

Controls Chrome launch parameters.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `chrome_path` | PathBuf | auto-detect | Path to Chrome/Chromium binary |
| `headless` | bool | `true` | Run headless (no visible window) |
| `port` | Option\<u16\> | `None` | Debug port (None = auto-find) |
| `args` | Vec\<String\> | `[]` | Additional Chrome CLI flags |
| `user_data_dir` | Option\<PathBuf\> | `None` | Custom profile (None = temp dir) |
| `timeout` | Duration | 30s | Browser startup timeout |
| `stealth` | bool | `false` | Add `--disable-blink-features=AutomationControlled` |
| `proxy` | Option\<String\> | `None` | socks5://, http://, https:// proxy |
| `use_pipe` | bool | `false` | Pipe transport (~1.5x lower latency) |

### Performance Flags

22 optimization flags for headless scraping:
- `--disable-gpu`, `--disable-extensions`, `--disable-background-networking`
- `--disable-sync`, `--disable-translate`, `--no-first-run`
- `--disable-component-update`, `--disable-domain-reliability`
- `--disable-client-side-phishing-detection` ... and more

**Max performance mode** adds: `--disable-site-isolation-trials`, `--renderer-process-limit=2`

### Transport Modes

| Mode | Flag | Latency | Notes |
|------|------|---------|-------|
| WebSocket | `--remote-debugging-port` | ~2ms | Default, most compatible |
| Pipe | `--remote-debugging-pipe` | ~1.3ms | Lower latency, fd 3/4 on Unix |

### CdpWriter Abstraction

```rust
pub enum CdpWriter {
    WebSocket(WsSink),
    #[cfg(unix)]
    Pipe(BufWriter<File>),
}
```

Both variants implement `send_message(msg: String)` for transparent transport switching.

### Config File: `browser.toml`

```toml
chrome_path = "auto"
headless = true
port = 0
timeout_secs = 30
stealth = true
proxy = ""
use_pipe = false
performance = "normal"    # "normal" | "fast" | "max"
extra_args = []
user_data_dir = ""
```

---

## 3. CDP Client

The `CdpClient` is the low-level Chrome DevTools Protocol client.

### Connection

```rust
let client = CdpClient::connect("ws://127.0.0.1:9222/devtools/browser/...").await?;
```

Spawns a background read loop that:
- Routes responses to pending command futures
- Broadcasts events to all subscribers
- Captures console messages from `Runtime.consoleAPICalled`
- Stores screencast frames for recording

### Core API

| Method | Description |
|--------|-------------|
| `connect(ws_url)` | Connect WebSocket, spawn read loop, enable Runtime |
| `send_command(method, params)` | Send CDP command, await response |
| `send_command_with_session(method, params, session_id)` | Session-scoped command |
| `subscribe()` | Get broadcast receiver for CDP events |
| `create_page(url)` | Create new tab in default context |
| `create_browser_context()` | Isolated browser context (separate cookies/storage) |
| `create_page_in_context(context_id, url)` | Tab in specific context |
| `close_page(page)` | Close tab/target |
| `get_console_messages()` | Captured console.log/warn/error messages |

### Browser Context Isolation

```rust
let ctx = client.create_browser_context().await?;
let page = client.create_page_in_context(&ctx, None).await?;
// Isolated cookies, storage, cache
client.dispose_browser_context(&ctx).await?;
```

Supports per-context proxy:
```rust
let ctx = client.create_browser_context_with_proxy(Some("socks5://127.0.0.1:9050")).await?;
```

---

## 4. Page & Navigation

### Navigation

```rust
let result = page.navigate("https://example.com", WaitUntil::NetworkIdle).await?;
```

**WaitUntil strategies:**

| Strategy | CDP Event | Use Case |
|----------|-----------|----------|
| `Load` | `load` | Fast, basic pages |
| `DomContentLoaded` | `DOMContentLoaded` | Fastest, HTML-only |
| `NetworkIdle` | `networkIdle` | SPAs, JS-heavy pages |
| `NetworkAlmostIdle` | `networkAlmostIdle` | Pages with long-polling |

### NavigationResult

```rust
pub struct NavigationResult {
    pub url: String,
    pub frame_id: String,
    pub status_code: Option<u16>,
}
```

### Page Methods

**Navigation & History:**
- `navigate(url, wait_until)` — Navigate to URL
- `reload(wait_until)` — Reload current page
- `go_back()` / `go_forward()` — History navigation

**Properties:**
- `url()` — Current URL
- `title()` — Current page title

**DOM Querying (CSS):**
- `query_selector(selector)` — First match
- `query_selector_all(selector)` — All matches
- `wait_for_selector(selector, timeout)` — Wait for element to appear (50ms poll)

**DOM Querying (XPath):**
- `query_xpath(expression)` — First match
- `query_xpath_all(expression)` — All matches

**Batch Extraction (single CDP call):**
- `extract_all_text(selector)` — All text content matching selector
- `extract_all_attrs(selector, attrs)` — Multiple attributes per element
- `capture_dom_snapshot()` — Full DOM snapshot
- `extract_structured_data()` — JSON-LD, OpenGraph, Microdata

**JavaScript:**
- `evaluate_expression(js)` — Evaluate and return result

**Interaction:**
- `keyboard_shortcut(key, modifiers)` — e.g., Ctrl+A
- `scroll_by(dx, dy)` / `scroll_to_bottom()` — Scrolling

**Frames:**
- `frames()` — List all frames in tree
- `enter_iframe(selector)` — Returns scoped `Page` for iframe

**Waiting:**
- `wait_for_stable(timeout, quiesce_ms)` — DOM stability + network quiet

**Resource Blocking:**
- `block_resources(types)` — Block specific resource types
- `block_non_essential()` — Block images, fonts, stylesheets, media

**Pagination:**
- `detect_pagination()` — Detect numbered/next_button/load_more/infinite_scroll
- Returns `PaginationInfo { strategy, next_url, total_links }`

**Cookie Consent:**
- `handle_cookie_consent(strategy)` — Auto-handle banners
- Strategies: `RejectNonEssential`, `AcceptAll`, `Dismiss`

**Recording:**
- `start_recording(config)` — Begin screen recording
- `stop_recording(path, config)` — Stop and encode
- `recording_status()` — Check without stopping

---

## 5. Element Querying & Interaction

### ElementHandle

Represents a DOM element with full interaction capabilities.

**Content Extraction:**
- `text()` — Text content
- `inner_html()` / `outer_html()` — HTML content
- `tag_name()` — Element tag (lowercase)
- `attribute(name)` — HTML attribute value
- `property(name)` — DOM property (`.value`, `.checked`)

**Styling:**
- `computed_style(property)` — Single CSS property
- `computed_styles(properties)` — Multiple CSS properties (one call)

**Visibility & State:**
- `bounding_box()` — Position and size; `None` if hidden
- `is_visible()` — Non-zero bbox + CSS visibility
- `is_enabled()` — Not disabled
- `wait_for_actionable(timeout)` — Playwright-style: visible + stable + enabled

**Scoped Querying:**
- `query_selector(selector)` — Child elements
- `query_selector_all(selector)` — All child matches

**Interaction:**
- `click(options)` — Auto-waits, scrolls into view, dispatches events
- `type_text(text, delay_ms)` — Character-by-character typing
- `select_option(by)` — Dropdown: `Value(s)`, `Index(n)`, `Label(s)`
- `upload_files(paths)` — File input upload
- `clear()` — Clear input value
- `hover()` — Mouse hover
- `drag_to(target)` — Drag and drop
- `focus()` — Focus element
- `scroll_into_view()` — Scroll into viewport

**Shadow DOM:**
- `shadow_root()` — Access shadow DOM (open or closed via CDP)

### ElementChain — Batch Extraction

Extract data from multiple elements in a single CDP call:

```rust
let data = ElementChain::new(client, session_id, ".product")
    .extract(".title", &["textContent"])
    .extract(".price", &["textContent"])
    .extract("img", &["src", "alt"])
    .execute()
    .await?;
```

### Click Options

```rust
pub struct ClickOptions {
    pub button: MouseButton,   // Left, Right, Middle
    pub click_count: u32,      // 1=single, 2=double, 3=triple
    pub modifiers: u32,        // MODIFIER_ALT|CTRL|META|SHIFT
}
```

### Human-Like Input

- `bezier_mouse_path(from, to, steps)` — Cubic Bezier with randomized control points (±30%)
- `gaussian_keystroke_delay(mean_ms, stddev_ms)` — Gaussian-distributed typing delay

---

## 6. Stealth V1 — Classic Anti-Detection

6 core evasion scripts injected via `Page.addScriptToEvaluateOnNewDocument` (before any page JS runs).

### Evasion Vectors

| Vector | What It Does |
|--------|-------------|
| **Webdriver** | Hides `navigator.webdriver`, adds `chrome.csi/loadTimes`, fixes `permissions.query` |
| **Chrome Runtime** | Reconstructs `window.chrome.runtime` object |
| **Plugins** | Sets `navigator.plugins` to realistic Chrome PDF plugin array |
| **Languages** | Overrides `navigator.languages` to match profile |
| **Canvas** | Adds pixel-level noise to canvas reads (seeded PRNG) |
| **Navigator** | Overrides `navigator.*` properties (UA, platform, vendor, memory, concurrency) |

### StealthProfile

Correlated fingerprint — all values match a real browser:

```rust
pub struct StealthProfile {
    pub user_agent: String,
    pub platform: String,           // "Win32", "MacIntel", "Linux x86_64"
    pub vendor: String,
    pub languages: Vec<String>,
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    pub max_touch_points: u32,
    pub viewport: (u32, u32),
    pub device_scale_factor: f64,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    pub timezone: String,
    pub locale: String,
    pub canvas_noise_seed: u64,
}
```

### Presets

| Preset | UA | Platform | Touch | Viewport |
|--------|----|----------|-------|----------|
| `chrome_windows()` | Chrome 131 Win10 | Win32 | 0 | 1920x1080 |
| `chrome_macos()` | Chrome 131 macOS | MacIntel | 0 | 1440x900 |
| `chrome_linux()` | Chrome 131 Linux | Linux x86_64 | 0 | 1920x1080 |
| `mobile_android()` | Chrome 131 Android | Linux armv81 | 5 | 412x915 |
| `mobile_ios()` | Safari 17 iOS | iPhone | 5 | 390x844 |

### Config File: `stealth.toml`

```toml
profile = "chrome_windows"
v1_enabled = true
v2_enabled = true

[evasions]
webdriver = true
chrome_runtime = true
plugins_spoof = true
languages = true
canvas = true
webgl = true
navigator = true
# ... 13 more V2 vectors
```

---

## 7. Stealth V2 — Advanced Evasion

13 additional evasion vectors targeting modern bot detection (Google, Cloudflare, PerimeterX, DataDome).

### Evasion Vectors

| # | Vector | Target Detection |
|---|--------|-----------------|
| 1 | **Connection** | `navigator.connection` (Network Information API) |
| 2 | **Screen Dimensions** | `outerWidth/outerHeight` mismatch with viewport |
| 3 | **Performance Memory** | `performance.memory` (Chrome-only, absent = headless) |
| 4 | **Performance Timing** | `performance.now()` microsecond noise |
| 5 | **Chrome Extended** | `chrome.app` + `chrome.webstore` properties |
| 6 | **Permissions** | Full `Permissions.prototype.query` coverage |
| 7 | **Speech Synthesis** | `speechSynthesis.getVoices()` returns real voices |
| 8 | **Media Devices** | `MediaDevices.enumerateDevices()` returns realistic set |
| 9 | **WebRTC** | Forces relay-only ICE (prevents real IP leak) |
| 10 | **Battery** | `navigator.getBattery()` returns realistic values |
| 11 | **Iframe** | `contentWindow` detection bypass |
| 12 | **Client Hints** | `navigator.userAgentData` (Sec-CH-UA headers) |
| 13 | **Timezone** | `Intl.DateTimeFormat` + `Date.getTimezoneOffset` consistency |

### Combined Script

```rust
pub fn stealth_v2_script(profile: &StealthProfile) -> String
```

Returns a single JS string combining all 13 evasions with profile-specific values.

---

## 8. Tor Integration

### Architecture

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│ Chrome   │────▶│ SOCKS5   │────▶│ Tor      │────▶ Internet
│ Browser  │     │ Proxy    │     │ Daemon   │     (exit node)
└──────────┘     └──────────┘     └──────────┘
                  127.0.0.1:9050   Control:9051
```

### TorManager

Manages multiple Tor daemon instances:

- `start(count)` — Start N instances (sequential ports: 9050/9051, 9052/9053, ...)
- `stop()` — Stop all instances
- `instances()` — List running instances
- Auto-detects system Tor or bundled binary

### TorPool

Circuit rotation and stream isolation:

| Policy | Description |
|--------|-------------|
| `PerRequest` | New circuit for every request |
| `PerBatch(n)` | New circuit every N requests |
| `PerDuration` | Periodic rotation (default: 600s) |
| `Manual` | Rotate only on explicit call |

**Stream Isolation:** Unique SOCKS auth per request (`IsolateSOCKSAuth` directive).

### TorControlPort

Async control port client (TCP):
- `authenticate()` — Cookie/password/null auth
- `signal_newnym()` — New circuit (10s rate limit enforced)
- `get_info(key)` — Query Tor state
- `get_exit_ip()` — Current exit node IP

### Tor Browser Fingerprint

When Tor is detected, stealth profile auto-adjusts to match Tor Browser Bundle:
- Firefox ESR 128.0 User-Agent
- 1000x900 viewport
- UTC timezone
- Empty WebGL renderer
- `navigator.maxTouchPoints = 0`

### Config File: `tor.toml`

```toml
enabled = false
instances = 1
auto_start = false

[circuit]
rotation_secs = 600
rotation_policy = "periodic"
batch_size = 10

[isolation]
stream_isolation = true
isolate_by_domain = false

[ports]
socks_base = 9050
control_base = 9051

[fingerprint]
use_tor_profile = true
auto_adjust = true
```

---

## 9. Plugin System (10 Built-In)

All plugins are built-in — no browser extensions to install. They inject JS via CDP and intercept network requests.

### Available Plugins

| Plugin | Default | Description |
|--------|---------|-------------|
| `adblock` | ON | Block ads (uBlock Origin patterns) |
| `tracker_block` | ON | Block known tracking domains |
| `https_everywhere` | ON | Force HTTPS on all navigations |
| `noscript` | OFF | Block all JavaScript (breaks most sites) |
| `clear_urls` | ON | Strip tracking parameters (utm_*, fbclid, etc.) |
| `cookie_autoblock` | OFF | Auto-block third-party cookies |
| `fingerprint_protect` | ON | Canvas/navigator fingerprint randomization |
| `popup_block` | ON | Block popup windows |
| `miner_block` | ON | Block cryptocurrency miners |
| `social_block` | ON | Block social media widgets/trackers |

### Presets

| Preset | Plugins Enabled |
|--------|----------------|
| `balanced` | All except noscript + cookie_autoblock |
| `max` | All 10 enabled |
| `none` | All disabled |
| `custom` | Per-plugin TOML configuration |

### Three-Layer Protection

1. **CSS cosmetic hiding** — Fast visual ad removal
2. **MutationObserver** — Element removal before resource loading
3. **Fetch/XHR override** — Network-level blocking at JS API

### URL Cleaning

Strips tracking parameters: `utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, `utm_content`, `fbclid`, `gclid`, `mc_eid`, `yclid`, `_ga`, `_gl`, `ref`, `ref_src`, `ref_url`

### Config File: `plugins.toml`

```toml
preset = "balanced"
adblock = true
tracker_block = true
https_everywhere = true
noscript = false
clear_urls = true
cookie_autoblock = false
fingerprint_protect = true
popup_block = true
miner_block = true
social_block = true
```

---

## 10. Privacy & PII Protection

### PII Detection

8 types of personally identifiable information detected via regex + heuristics:

| Type | Detection Method |
|------|-----------------|
| Email | RFC 5322 pattern |
| Phone | International patterns (+1, +44, etc.) |
| SSN | XXX-XX-XXXX pattern |
| Credit Card | 13-19 digit patterns with Luhn check |
| IP Address | IPv4 dotted-quad |
| Name | Capitalized multi-word sequences near keywords |
| Address | Street patterns + ZIP codes |
| Date of Birth | ISO/slash/dash dates near "born"/"dob" keywords |

### Redaction

```rust
let result = scan_and_redact("Contact john@example.com or 555-1234");
// result.redacted_text = "Contact [EMAIL] or [PHONE]"
// result.count = 2
// result.types_found = {Email, Phone}
```

Redaction styles: `mask` (***), `hash` (SHA-256), `remove` (delete entirely).

### Content Fingerprinting

SimHash-based deduplication:
```rust
let fp = ContentFingerprint::from_text(page_text);
let similarity = fp.similarity(&other_fp); // 0.0 - 1.0
```

### Data Retention Registry

Track what data was collected, when, and when it expires:
```rust
registry.register(url, content_hash, "public_data", 30); // 30-day retention
let expired = registry.expired_entries(); // Auto-cleanup
```

### Config File: `privacy.toml`

```toml
pii_scan_enabled = true
redaction_enabled = true
fingerprint_dedup = true
retention_days = 30

[pii_types]
email = true
phone = true
ssn = true
credit_card = true
ip_address = true
name = false
address = false
date_of_birth = true

[redaction]
style = "mask"
mask_char = "*"
```

---

## 11. Network Interception

### InterceptRule

```rust
pub struct InterceptRule {
    pub url_pattern: Option<String>,          // Glob pattern
    pub resource_type: Option<ResourceType>,  // Document, Script, Image, etc.
    pub method: Option<String>,               // GET, POST, etc.
    pub request_stage: RequestStage,          // Request or Response
    pub action: InterceptAction,              // Block, Continue, Mock, Modify
}
```

### Actions

| Action | Description |
|--------|-------------|
| `Block` | Silently drop the request |
| `Continue` | Pass through unmodified |
| `ContinueModified { url, method, headers, post_data }` | Modify and forward |
| `Mock(MockResponse)` | Return fake response |

### Resource Types

`Document`, `Stylesheet`, `Image`, `Media`, `Font`, `Script`, `TextTrack`, `XHR`, `Fetch`, `Prefetch`, `EventSource`, `WebSocket`, `Manifest`, `Other`

### WebSocket Monitoring

- `WebSocketMonitor` — Capture WebSocket frames
- `WebSocketInterceptor` — Intercept/modify WebSocket messages
- Frame direction tracking (sent vs received)

### HAR Recording

Record all network traffic as HAR (HTTP Archive) format for replay and analysis.

### Config File: `network.toml`

```toml
intercept_enabled = false
har_recording = false
har_output_dir = "har/"
websocket_monitor = false

[blocked_resources]
images = false
stylesheets = false
fonts = false
media = false
scripts = false

[[rules]]
url_pattern = "*.doubleclick.net/*"
action = "block"

[[rules]]
url_pattern = "*/api/config"
action = "mock"
mock_status = 200
mock_body = '{"feature_flags": {}}'
```

---

## 12. Session Management

### Cookie Operations

- `get_cookies(client, session_id)` — Get all cookies
- `set_cookies(client, session_id, cookies)` — Set cookies
- `clear_cookies(client, session_id)` — Clear all cookies

### Storage Operations

- `get_local_storage(client, session_id, origin)` — Get localStorage
- `get_session_storage(client, session_id, origin)` — Get sessionStorage
- `set_local_storage_item(...)` / `set_session_storage_item(...)` — Set items
- `clear_local_storage(...)` / `clear_session_storage(...)` — Clear

### Full Session Capture

```rust
let session = capture_session(&client, &session_id, "my-session", &["https://example.com"]).await?;
save_session(&db, &session, &shared_secret)?;  // AES-256-GCM-encrypted SQLite (PQC is a design target)

// Later...
let session = load_session(&db, "my-session", &shared_secret)?;
restore_session(&client, &session_id, &session).await?;
```

### CdpCookie

```rust
pub struct CdpCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expires: f64,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: String,
    pub size: Option<i32>,
}
```

### Config File: `session.toml`

```toml
persist_cookies = false
persist_local_storage = false
persist_session_storage = false
encrypt_sessions = true
session_dir = ""

[cookies]
block_third_party = false
clear_on_exit = false
allowed_domains = []
blocked_domains = []

[storage]
max_size_mb = 50
quota_per_origin_mb = 10
```

---

## 13. Authentication (OAuth + TOTP)

### Login Sessions

- `save_login_session(...)` — Capture cookies + storage, encrypt to SQLite (AES-256-GCM; PQC is a design target)
- `restore_login_session(...)` — Restore session from encrypted storage
- `is_logged_in(client, session_id, check_selector)` — Check DOM element for login state

### TOTP (RFC 6238)

```rust
let secret = decode_totp_secret("JBSWY3DPEHPK3PXP")?;  // Base32
let code = generate_totp_default(&secret);                // 6-digit, 30s
let code = generate_totp(&secret, 30, 6);                 // Custom step/digits
let code = generate_totp_at(&secret, 30, 6, unix_secs);   // Specific time
```

### OAuth

```rust
let result = capture_oauth_redirect(&client, &session_id, "https://myapp.com/callback", timeout).await?;
// result.access_token, result.refresh_token, result.code, result.state
```

Parses both query string parameters and URL fragment (`#access_token=...`).

---

## 14. CAPTCHA Detection & Solving

### Supported CAPTCHA Types

| Type | Detection Method |
|------|-----------------|
| reCAPTCHA v2 | `iframe[src*="recaptcha"]`, `.g-recaptcha` |
| reCAPTCHA v3 | `script[src*="recaptcha/api.js"]` |
| hCaptcha | `iframe[src*="hcaptcha"]`, `.h-captcha` |
| Cloudflare Turnstile | `iframe[src*="challenges.cloudflare"]`, `.cf-turnstile` |
| AWS WAF | `#captcha-container`, `awswaf` in page |
| Arkose Labs | `iframe[src*="arkoselabs"]` |
| DataDome | `iframe[src*="datadome"]`, `dd.js` script |
| FunCaptcha | Legacy Arkose `#FunCaptcha` |

### Solver Backends

| Backend | URL |
|---------|-----|
| 2Captcha | `https://2captcha.com` |
| Anti-Captcha | `https://api.anti-captcha.com` |
| CapSolver | `https://api.capsolver.com` |
| CapMonster | `https://api.capmonster.cloud` |
| Custom | Any URL |

### Workflow

1. `detect_captcha(client, session_id)` — DOM inspection → `CaptchaInfo`
2. `solve_captcha(client, session_id, config)` — Submit to solver, poll for solution
3. `inject_captcha_solution(...)` — Inject solution token
4. `wait_for_manual_solve(...)` — Fallback: pause for human

### Config File: `captcha.toml`

```toml
auto_detect = true
auto_solve = false
manual_fallback = true

[solver]
backend = ""
api_key = ""
timeout_secs = 120
poll_interval_secs = 5

[supported_types]
recaptcha_v2 = true
recaptcha_v3 = true
hcaptcha = true
turnstile = true
aws_waf = true
arkose_labs = true
datadome = true
funcaptcha = true
```

---

## 15. Search Engine Cascade

Multi-engine search with automatic failover — all free.

### Cascade Order (Default)

1. **Bing** — Rarely blocks, good results
2. **Brave Search** — Privacy-friendly, no bot detection
3. **DuckDuckGo** — HTML version, good fallback
4. **Yahoo** — Uses Bing's index, backup
5. **Google Trends** — Always works, even via Tor

### Additional Engines

6. **Google CSE** — 100 free queries/day (API key required)
7. **Google Profile** — Persistent cookie pool (advanced)
8. **Startpage** — Privacy proxy for Google results

### Block Detection

```rust
pub fn is_blocked_page(page_text: &str) -> bool
```

Detects: "unusual traffic", "are you a robot", "captcha", "verify you are a human", "access denied", "bot blocked"

### Profile Pool

For Google Search with persistent cookies:

```rust
pub struct ProfilePool {
    pub profiles_dir: PathBuf,
    pub count: usize,
    pub usage: HashMap<usize, u32>,
    pub max_per_profile: u32,  // 100/day default
}
```

Round-robin rotation, daily usage tracking, auto-reset.

### Config File: `search.toml`

```toml
merge_results = true
max_results = 20
timeout_secs = 10
engine_delay_ms = 500
engines = ["bing", "brave", "duckduckgo", "yahoo", "google_trends"]

[google_cse]
enabled = false
api_key = ""
cx = ""

[profile_pool]
enabled = false
profiles_dir = ""
count = 5
max_per_profile = 100
```

---

## 16. Device Emulation

### 163 Device Profiles

Full registry of real device fingerprints:

| Category | Devices | Examples |
|----------|---------|---------|
| iPhone | 15+ | iPhone 12, 13, 14, 15 Pro, SE |
| iPad | 8+ | iPad Air, Pro 11", Pro 12.9" |
| Pixel | 10+ | Pixel 5, 6, 7, 8 Pro |
| Galaxy | 12+ | Galaxy S20-S24, Z Fold, A series |
| Desktop | 6+ | 1080p, 1440p, 4K, macOS, Windows |
| Chromebook | 4+ | Chromebook, Chromebook HD |

### DeviceDescriptor

```rust
pub struct DeviceDescriptor {
    pub name: &'static str,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub device_scale_factor: f64,
    pub is_mobile: bool,
    pub has_touch: bool,
    pub user_agent: &'static str,
    pub default_browser: &'static str,
}
```

### Emulation API

- `set_viewport(client, session_id, width, height, mobile, scale)` — Viewport override
- `set_user_agent(client, session_id, ua)` — User-Agent override
- `set_touch_emulation(client, session_id, enabled, max_points)` — Touch events
- `set_timezone(client, session_id, tz)` — IANA timezone
- `set_locale(client, session_id, locale)` — BCP-47 locale
- `set_geolocation(client, session_id, lat, lon, accuracy)` — GPS spoofing

### Config File: `emulation.toml`

```toml
device = ""

[viewport]
width = 0
height = 0
device_scale_factor = 0.0
mobile = false

[locale]
timezone = ""
language = ""

[geolocation]
enabled = false
latitude = 0.0
longitude = 0.0
accuracy = 100.0

[touch]
enabled = false
max_touch_points = 0
```

---

## 17. Recording & Video Capture

### Codecs

| Codec | Extension | CRF Range | Notes |
|-------|-----------|-----------|-------|
| H.264 | .mp4 | 0-51 | Most compatible, default |
| VP9 | .webm | 0-63 | Better compression, slower |
| AV1 | .mp4 | 0-63 | Best compression, slowest |

### Output Formats

| Format | Method | Notes |
|--------|--------|-------|
| MP4 | ffmpeg | Requires ffmpeg in PATH |
| WebM | ffmpeg | VP9/AV1 only |
| AVI | Built-in MJPEG | No ffmpeg needed, larger files |
| Frames | JPEG files | Individual frame export |

### RecordingConfig

| Field | Default | Description |
|-------|---------|-------------|
| `width` | 1920 | Frame width |
| `height` | 1080 | Frame height |
| `fps` | 30 | Frames per second |
| `quality` | 90 | JPEG quality (1-100) |
| `format` | "mp4" | Output format |
| `codec` | "h264" | Video codec |
| `crf` | 18 | Quality factor (lower = better) |
| `capture_audio` | false | System audio capture |
| `max_frames_in_memory` | 1800 | ~60s at 30fps |

### Resolution Presets

`"4k"` (3840x2160), `"2k"` (2560x1440), `"1080p"` (1920x1080), `"720p"` (1280x720), `"480p"` (854x480)

### Config File: `recording.toml`

```toml
width = 1920
height = 1080
fps = 30
quality = 90
format = "mp4"
codec = "h264"
crf = 18
capture_audio = false
max_frames_in_memory = 1800
output_dir = "recordings/"
```

---

## 18. Visual Testing & Screenshots

### Screenshot Capture

- `capture_screenshot(client, session_id)` — Full-page PNG (beyond viewport)
- `capture_viewport_screenshot(client, session_id)` — Viewport-only PNG
- `capture_element_screenshot(client, session_id, object_id)` — Single element

### PDF Generation

```rust
pub struct PdfOptions {
    pub landscape: bool,          // false
    pub print_background: bool,   // true
    pub paper_width: f64,         // 8.5 (US Letter)
    pub paper_height: f64,        // 11.0
    pub margin_top: f64,          // 0.4"
    pub margin_bottom: f64,
    pub margin_left: f64,
    pub margin_right: f64,
    pub scale: f64,               // 1.0
}
```

### Pixel Diff Comparison

```rust
let diff = compare_screenshots(&baseline_png, &current_png, threshold)?;
// diff.diff_percentage, diff.different_pixels, diff.dimensions_match
```

Per-channel threshold (R, G, B, A independently compared).

### Baseline Management

```rust
save_baseline("./baselines", "homepage", &png_data)?;
let diff = compare_with_baseline("./baselines", "homepage", &current_png, 5)?;
let baselines = list_baselines("./baselines")?;
```

Baselines stored with manifest (`baselines.json`) tracking name, hash, dimensions, timestamps.

---

## 19. Accessibility & WCAG Auditing

### WCAG Levels

| Level | Tags | Coverage |
|-------|------|----------|
| A | `wcag2a`, `wcag21a` | Basic accessibility |
| AA | + `wcag2aa`, `wcag21aa`, `wcag22aa` | Standard (legal requirement in many jurisdictions) |
| AAA | + `wcag2aaa` | Enhanced accessibility |

### axe-core Integration

Production axe-core v4.10.2 (553KB) embedded for WCAG auditing.

```rust
let result = run_wcag_audit(&client, &session_id, WcagLevel::AA).await?;
// result.violations: Vec<WcagViolation>
// result.passes_count, result.incomplete_count
```

### WcagViolation

```rust
pub struct WcagViolation {
    pub id: String,          // "color-contrast"
    pub impact: String,      // "critical", "serious", "moderate", "minor"
    pub description: String,
    pub help_url: String,
    pub nodes_count: usize,
}
```

Impact weights: critical=4, serious=3, moderate=2, minor=1.

### Consent Banner Detection

```rust
let banner = detect_consent_banner(&client, &session_id).await?;
// banner.found, banner.accept_selector, banner.reject_selector
accept_consent(&client, &session_id).await?;
reject_tracking_cookies(&client, &session_id).await?;
```

### Accessibility Tree

```rust
let tree = get_accessibility_tree(&client, &session_id).await?;
let node = query_accessibility_node(&client, &session_id, "button", "Submit").await?;
```

### Config File: `accessibility.toml`

```toml
wcag_level = "AA"
auto_audit = false
fail_on_violations = false

[consent]
auto_handle = true
strategy = "accept"
reject_tracking = true
```

---

## 20. Trace Recording & Replay

### TraceRecorder

Records all browser actions with timestamps for debugging and replay.

**Recorded Data:**
- Actions: navigate, click, type, screenshot, wait (with selectors and values)
- Network events: request/response URLs, methods, status codes, sizes, durations
- Screenshots: PNG snapshots at key moments

### Output Format

ZIP archive containing:
```
trace.zip/
  actions.jsonl       — One action per line
  network.jsonl       — One network event per line
  screenshots/
    0.png, 1.png...   — Indexed screenshots
  metadata.json       — Summary stats
```

### Built-In Viewer

```rust
open_trace_viewer(&trace_path)?;  // Opens HTML viewer in default browser
```

Embedded HTML viewer with timeline, screenshot gallery, and network waterfall.

---

## 21. HTML Parser

Fast string-based HTML extraction (~100x faster than browser DOM).

### HtmlParser

- `extract_text(html, selector)` — Extract text by tag/class/ID selector
- `extract_links(html)` — All `<a href>` values (excludes `#`, `javascript:`)
- `extract_meta(html)` — Title, description, keywords, author, viewport, robots

### Utility

- `strip_html_tags(html)` — Remove all `<tag>` markup, preserve text content

---

## 22. Browser Pool

### PoolConfig

| Field | Default | Description |
|-------|---------|-------------|
| `max_size` | 4 | Max concurrent browser instances |
| `max_tasks_per_instance` | 100 | Recycle after N tasks |
| `recycle_on_release` | true | Clear cookies/storage between tasks |
| `proxies` | `[]` | Round-robin proxy list |
| `tor_enabled` | false | Route through Tor |
| `tor_instances` | 1 | Number of Tor daemons |

### Pool States

| State | Description |
|-------|-------------|
| `Idle` | Available for new tasks |
| `Active` | Currently executing a task |
| `Crashed` | Process died, needs restart |

### PoolStats

Atomic counters: `active`, `idle`, `crashed`, `total_tasks`, `total_created`, `total_recycled`

### Semaphore Gating

Pool uses `tokio::sync::Semaphore` for backpressure — callers await a permit before acquiring a browser.

### Config File: `pool.toml`

```toml
max_size = 4
max_tasks_per_instance = 100
recycle_on_release = true
proxies = []

[distributed]
enabled = false
nodes = []
discovery = "manual"
coordination = "gossip"
```

---

## 23. Distributed Pool

Multi-node browser pool with automatic coordination.

### Components

| Component | Description |
|-----------|-------------|
| `SessionRegistry` | Session entry storage with TTL + GC |
| `NodeCoordinator` | Cluster state via gossip heartbeat |
| `PoolDiscovery` | mDNS auto + WAN manual + hybrid |
| `CdpRelay` | CDP command routing to remote sessions |
| `WorkDistributor` | Proportional URL sharding across nodes |

### Discovery Modes

| Mode | Use Case |
|------|----------|
| `manual` | Static node list |
| `mdns` | LAN auto-discovery |
| `hybrid` | mDNS + manual nodes |

### Wire Protocol

QUIC-based relay with 7 message types:
- `PoolAcquireRequest` / `PoolAcquireResponse`
- `PoolReleaseRequest`
- `DistributedCdpCommand` / `DistributedCdpResponse`
- `PoolHealthReport`
- `SessionExpired`

---

## 24. Scheduler

### ScheduledJob

Run `.tl` scripts on cron/interval schedules.

**Frequency types:**
- `Cron("0 8 * * *")` — Cron expression
- `Interval(3600)` — Every N seconds
- `Once(1712345678)` — Single execution at epoch
- `Daily("08:00")` — Daily at HH:MM

**Missed Policy:**
- `Skip` — Skip missed executions
- `RunOnce` — Run once to catch up
- `RunAll` — Run all missed executions

### Job Fields

Script, frequency, enabled, headless, plugins, device, tor, proxy, created_at, last_run, next_run, run_count, max_runs, timeout_secs, retry_count, retry_delay_secs, retry_backoff, allow_overlap, missed_policy, tz_offset_secs, work_dir, env_vars, args

### SchedulerDaemon

Persistent daemon that polls for due jobs and executes them as subprocesses.

### Config File: `scheduler.toml`

```toml
max_concurrent_jobs = 4
default_timeout_secs = 300
default_headless = true
default_plugins = "balanced"

[retry]
max_retries = 3
delay_secs = 60
backoff = true

[missed]
policy = "run_once"

[persistence]
store_path = ""
```

---

## 25. Retry & Rate Limiting

### BackoffStrategy

| Strategy | Formula |
|----------|---------|
| Exponential | `delay = initial * multiplier^attempt` (capped at max) |
| Linear | `delay = interval` (constant) |
| Fixed | `delay = interval` (same as linear) |

### RetryConfig

```rust
pub struct RetryConfig {
    pub max_retries: u32,         // 3
    pub backoff: BackoffStrategy, // Exponential(100ms, 2.0x, 5000ms)
}
```

### Error Classification

`is_retryable()` classifies errors as transient (retry) vs permanent (fail immediately):
- **Retryable:** timeout, connection reset, 429/500/502/503/504
- **Permanent:** 400/401/403/404, parsing errors, permission denied

### Config File: `retry.toml`

```toml
max_retries = 3
strategy = "exponential"

[exponential]
initial_ms = 100
multiplier = 2.0
max_ms = 5000

[linear]
interval_ms = 1000

[fixed]
interval_ms = 2000

[robots]
respect = true
policy = "permissive"
user_agent = "TallowBot/0.4"
cache_ttl_secs = 3600

[rate_limit]
enabled = true
default_rps = 2.0
respect_crawl_delay = true
```

---

## 26. robots.txt Compliance

### RobotsCache

Caches parsed robots.txt with configurable TTL:
```rust
let cache = RobotsCache::new(Duration::from_secs(3600), "TallowBot/0.4");
let allowed = cache.is_allowed("https://example.com/path").await?;
```

### RobotsPolicy

| Policy | Behavior |
|--------|----------|
| `Permissive` | Allow if robots.txt missing |
| `Strict` | Block if robots.txt missing |

### Rate Limiting

Token-bucket per domain with support for `Crawl-delay` directives.

```rust
let limiter = RateLimiter::new(2.0); // 2 req/sec default
limiter.acquire_async("example.com").await; // Blocks until token available
```

---

## 27. Browser Download & Management

### Chrome for Testing API

Downloads official Chrome/Chromium binaries from Google's CfT (Chrome for Testing) infrastructure.

### Supported Platforms

| Platform | Binary | Notes |
|----------|--------|-------|
| Linux x86-64 | chrome-headless-shell | Primary target |
| Linux ARM64 | chrome-headless-shell | Apple Silicon Linux |
| macOS ARM64 | chrome-headless-shell | Apple Silicon |
| macOS x86-64 | chrome-headless-shell | Intel Mac |
| Windows x64 | chrome-headless-shell | Windows 10+ |
| Windows x86 | chrome-headless-shell | 32-bit Windows |
| Linux RISC-V | Not available | Helpful error message |

### Verification

- **SHA-256** after download, before extraction
- **BLAKE3** integrity check stored as `checksum.blake3`

### Auto-Detection Priority

1. Managed installs (newest version first)
2. System Chrome (platform-specific paths)
3. Auto-download headless-shell if nothing found

---

## 28. IPPool & Kernel Tuning

### IpPoolBackend Trait

```rust
pub trait IpPoolBackend: Send + Sync {
    fn acquire(&self) -> Result<(), String>;
    fn release(&self) -> Result<(), String>;
    fn active_connections(&self) -> u64;
    fn capacity(&self) -> u64;
    fn backend_name(&self) -> &'static str;
}
```

### Backends

| Backend | Scale | Notes |
|---------|-------|-------|
| `EpollBackend` | 10K-100K | Standard, atomic counters |
| `IoUringBackend` | 100K-1M | Linux 5.6+, feature-gated (off by default; single-op; file I/O only) |
| `StubDpdkBackend` | 1M-10M+ | Stub only (no implementation; does not fabricate a connection) |

*Scale figures are design capacities, not measured values; only the epoll backend is enabled by default.*

### IPPool Auto-Selection

```rust
let pool = IPPool::new(100_000); // Auto-selects best backend
```

### Kernel Tuning (Linux)

`KernelTuner` sets high-scale `/proc/sys` parameters:
- `fs.file-max = 20000000`
- `net.ipv4.ip_local_port_range = 1024 65535`
- `net.ipv4.tcp_tw_reuse = 1`
- `net.core.somaxconn = 65535`
- `net.ipv4.tcp_max_syn_backlog = 65535`

**Auto-rollback on Drop** — all changes reversed when pool exits.

### DPDK Configuration

```rust
pub struct DpdkConfig {
    pub hugepages: u32,           // 1024
    pub pci_device: String,       // "0000:01:00.0"
    pub queue_count: u32,         // 4
    pub memory_channels: u32,     // 4
}
```

### Connection Scaling

| Pool Size | RAM | Backend | Use Case |
|-----------|-----|---------|----------|
| 10K | 20MB | epoll | Standard |
| 100K | 200MB | io_uring (off by default) | High-throughput |
| 1M | 2GB | io_uring + tuned | Enterprise |
| 10M+ | 20GB | DPDK (stub — not implemented) | Maximum (target) |
| Unlimited | Distributed | Multi-node (dormant — target-only) | No ceiling |

---

## 29. Configuration System

### Config Directory

```
~/.tallow/browser/config/          (Linux/macOS)
%LOCALAPPDATA%\tallow\browser\config\  (Windows)
```

### 15 Config Files

| File | Domain | Key Settings |
|------|--------|-------------|
| `browser.toml` | Chrome launch | chrome_path, headless, stealth, proxy, pipe, performance |
| `plugins.toml` | 10 plugins | preset, per-plugin on/off |
| `stealth.toml` | Anti-detection | profile, V1/V2 enable, 20 evasion toggles |
| `privacy.toml` | PII protection | scan types, redaction style, retention |
| `network.toml` | Interception | HAR, blocked resources, custom rules |
| `recording.toml` | Video capture | codec, resolution, fps, crf, format |
| `search.toml` | Search engines | engine order, CSE keys, profile pool |
| `emulation.toml` | Device emulation | device, viewport, timezone, geolocation |
| `accessibility.toml` | WCAG auditing | level, consent banner strategy |
| `session.toml` | Persistence | cookies, storage, PQC encryption |
| `captcha.toml` | CAPTCHA solving | backend, API keys, type support |
| `pool.toml` | Browser pool | max_size, proxies, distributed mode |
| `tor.toml` | Tor integration | circuit rotation, isolation, ports |
| `scheduler.toml` | Job scheduling | missed policy, retry, concurrency |
| `retry.toml` | Retry/rate limit | backoff, robots.txt, rate limiting |

### Design Principles

- **`#[serde(default)]` on every field** — partial files work, specify only what you change
- **Config file as base, CLI flags override** — layered configuration
- **No breaking changes** — existing code works unchanged without config files
- **Cross-platform paths** — Windows LOCALAPPDATA, Unix ~/.tallow

---

## 30. CLI Reference

### Browser Management

```bash
tallow browser install [--full]     # Download Chrome for Testing
tallow browser list                 # List installed versions
tallow browser remove <version>     # Remove installed version
tallow browser path                 # Show Chrome binary path
tallow browser pool                 # Show pool status
tallow browser devices [--category] # List 163 device profiles
```

### Browser Launch

```bash
tallow browser open [url]           # Launch Chrome with all features
  --headless                        # Headless mode
  --plugins <balanced|max|none|config>  # Plugin preset
  --device <name>                   # Device emulation
  --no-plugins                      # Disable all plugins
  --tor                             # Route through Tor
  --proxy <url>                     # Custom proxy
```

### Configuration

```bash
tallow browser config init          # Create all 15 default TOML files
tallow browser config show          # Display all config
tallow browser config show --file <name>  # Display single file
tallow browser config edit <name>   # Open in $EDITOR
tallow browser config set <key> <value>   # Set individual value
tallow browser config reset         # Reset all to defaults
tallow browser config reset --file <name> # Reset single file
tallow browser config path          # Show config directory
tallow browser config list          # List all files with descriptions
```

### Scheduling

```bash
tallow browser schedule add --name <n> --script <path> --cron "0 8 * * *"
tallow browser schedule add --name <n> --script <path> --every 30m
tallow browser schedule add --name <n> --script <path> --daily 08:00
tallow browser schedule list
tallow browser schedule remove --name <n>
tallow browser schedule pause --name <n>
tallow browser schedule resume --name <n>
tallow browser schedule run --name <n>
tallow browser schedule start [--poll <secs>]
tallow browser schedule info --name <n>
```

### Tor

```bash
tallow tor start [--instances N]    # Start Tor daemons
tallow tor stop                     # Stop all instances
tallow tor status                   # Show running instances
```

---

## 31. Error Types

### BrowserError

| Variant | Description |
|---------|-------------|
| `ConnectionFailed(String)` | WebSocket/pipe connection failure |
| `CommandFailed { method, code, message }` | CDP command error |
| `CommandTimeout(String)` | CDP command timeout |
| `NavigationFailed(String)` | Page navigation error |
| `ElementNotFound(String)` | CSS/XPath selector not found |
| `JavaScriptError(String)` | JS evaluation error |
| `ProtocolError(String)` | CDP protocol violation |
| `ProcessError(String)` | Chrome process failure |
| `DownloadError(String)` | Browser binary download failure |
| `ChecksumMismatch { expected, actual }` | SHA-256 verification failure |

### NavigationError

| Variant | Description |
|---------|-------------|
| `Timeout` | Navigation timed out |
| `NetError(String)` | Network error (DNS, connection) |
| `HttpError(u16)` | HTTP error status |
| `Aborted` | Navigation aborted |

---

## 32. Integration Map

How modules connect:

```
BrowserConfig ──▶ BrowserProcess ──▶ CdpClient ──▶ Page
                                         │
                    ┌────────────────────┤
                    ▼                    ▼
              StealthProfile      NetworkInterceptor
              (V1 + V2 + Tor)     (Rules + HAR + WS)
                    │
                    ▼
              BrowserPlugins ──▶ injection_script()
                    │
                    ▼
              Page.evaluate() ──▶ Chrome DevTools Protocol
                    │
          ┌────────┼────────┬────────────────┐
          ▼        ▼        ▼                ▼
      ElementHandle  SessionMgr   RecordingConfig  TraceRecorder
      (query/click)  (cookies)    (screencast)     (ZIP output)
          │
          ▼
      ElementChain ──▶ Batch extraction (single CDP call)

BrowserPool ──▶ [BrowserProcess₁, BrowserProcess₂, ...]
    │               │
    ▼               ▼
PoolConfig     Semaphore gating + crash recovery
    │
    ▼
TorPool ──▶ TorManager ──▶ [TorInstance₁, TorInstance₂, ...]
    │
    ▼
DistributedPool ──▶ NodeCoordinator ──▶ CdpRelay (QUIC)

SearchConfig ──▶ [Bing, Brave, Yahoo, DuckDuckGo, Google Trends]
    │                    │
    ▼                    ▼
ProfilePool         is_blocked_page() → next engine

BrowserFullConfig (15 TOML files) ──▶ All of the above
```

---

## Appendix A: Module Index

| # | Module | File | LOC | Purpose |
|---|--------|------|-----|---------|
| 1 | accessibility | `src/browser/accessibility.rs` | ~300 | WCAG auditing, AX tree, consent banners |
| 2 | auth | `src/browser/auth.rs` | ~250 | OAuth, TOTP, login sessions |
| 3 | captcha | `src/browser/captcha.rs` | ~350 | CAPTCHA detection + 5 solver backends |
| 4 | cdp | `src/browser/cdp.rs` | ~900 | CDP WebSocket/Pipe client |
| 5 | config | `src/browser/config/` | ~2200 | 15 TOML config files + loader |
| 6 | devices | `src/browser/devices.rs` | ~800 | 163 device profiles |
| 7 | distributed | `src/browser/distributed/` | ~630 | Multi-node pool (registry, gossip, QUIC) |
| 8 | download | `src/browser/download.rs` | ~900 | Chrome download, SHA-256, management |
| 9 | element | `src/browser/element.rs` | ~900 | DOM elements, shadow DOM, batch extraction |
| 10 | emulation | `src/browser/emulation.rs` | ~200 | Viewport, timezone, locale, geolocation |
| 11 | error | `src/browser/error.rs` | ~100 | BrowserError, NavigationError |
| 12 | frame | `src/browser/frame.rs` | ~80 | Frame tree parsing |
| 13 | html_parser | `src/browser/html_parser.rs` | ~200 | Fast string-based HTML extraction |
| 14 | interaction | `src/browser/interaction.rs` | ~470 | Click, type, mouse paths, keystroke delay |
| 15 | network | `src/browser/network.rs` | ~500 | Request interception, HAR, WebSocket |
| 16 | page | `src/browser/page.rs` | ~1500 | Page navigation, DOM, recording |
| 17 | plugins | `src/browser/plugins.rs` | ~400 | 10 built-in plugins |
| 18 | pool | `src/browser/pool.rs` | ~400 | Browser pool with semaphore gating |
| 19 | privacy | `src/browser/privacy.rs` | ~350 | PII scanning, redaction, retention |
| 20 | process | `src/browser/process.rs` | ~340 | Chrome process lifecycle |
| 21 | recording | `src/browser/recording.rs` | ~400 | Video capture (3 codecs, 4 formats) |
| 22 | retry | `src/browser/retry.rs` | ~130 | Retry logic + backoff strategies |
| 23 | robots | `src/browser/robots.rs` | ~200 | robots.txt cache + rate limiting |
| 24 | scheduler | `src/browser/scheduler.rs` | ~600 | Cron scheduling + daemon |
| 25 | search_engine | `src/browser/search_engine.rs` | ~380 | Multi-engine search cascade |
| 26 | session | `src/browser/session.rs` | ~500 | Cookie/storage persistence; AES-256-GCM + HKDF (PQC is a design target) |
| 27 | stealth | `src/browser/stealth.rs` | ~350 | Stealth V1 (6 evasion vectors) |
| 28 | stealth_v2 | `src/browser/stealth_v2.rs` | ~550 | Stealth V2 (13 evasion vectors) |
| 29 | tor_stealth | `src/browser/tor_stealth.rs` | ~90 | Tor Browser fingerprint matching |
| 30 | trace | `src/browser/trace.rs` | ~350 | Action/network recording + viewer |
| 31 | visual | `src/browser/visual.rs` | ~400 | Screenshots, PDF, pixel diff, baselines |

**Total: 95,778 lines across 132 source files, 1,505 tests (verified 2026-09-12); the table above lists 31 logical module groups + 15 config files**

---

## Appendix B: Feature Matrix vs Competitors

| Feature | Tallow | Playwright | Puppeteer | Selenium | Crawlee |
|---------|--------|-----------|-----------|----------|---------|
| Real Chrome (authentic TLS) | Yes | Yes | Yes | Yes | Yes |
| Built-in stealth (20+ JS-vector toggles; design targets, no evasion guarantee) | Yes | No | No | No | Partial |
| Built-in plugins (no extensions) | Yes (10) | No | No | No | No |
| PII auto-redaction | Yes (8 types) | No | No | No | No |
| Post-quantum encryption | Design target (session crypto today: AES-256-GCM + HKDF) | No | No | No | No |
| CAPTCHA solving (8 types) | Yes | No | No | No | Partial |
| Multi-engine search | Yes (8) | No | No | No | No |
| Tor integration | Yes (native) | Manual | Manual | Manual | No |
| 163 device profiles | Yes | Yes (~50) | No | No | No |
| Video recording (3 codecs) | Yes | Yes (1) | No | No | No |
| WCAG auditing (axe-core) | Yes | No | No | No | No |
| Distributed pool (QUIC) | Yes | No | No | Grid | No |
| robots.txt compliance | Yes | No | No | No | Yes |
| TOML config system (15 files) | Yes | JSON | JSON | Properties | JSON |
| Trace recording + viewer | Yes | Yes | No | No | No |
| Pixel diff baselines | Yes | Yes | No | No | No |
| Pipe transport | Yes | Yes | No | No | No |
| io_uring backend | Yes | No | No | No | No |
| Kernel auto-tuning | Yes | No | No | No | No |

---

*End of Tallow Browser System Specification*  
*Version: 0.4.0 — April 2026*
