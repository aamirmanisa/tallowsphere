//! Browser stealth evasions for Tallow — design-target JS-vector spoofing.
//!
//! Provides `StealthProfile` with correlated fingerprint properties and
//! JavaScript evasion scripts injectable via CDP `Page.addScriptToEvaluateOnNewDocument`.
//! The scripts override navigator properties, canvas/WebGL fingerprints,
//! `chrome.runtime`, and plugins to reduce obvious headless-Chrome tells.
//!
//! Reality check (audit-05 F-12; cycle-01 §2.4 item 2) — **no evasion
//! guarantees**: these overrides are injected into the page's **main world**
//! (see `inject_stealth_scripts_with_config`), where page scripts and page
//! fingerprinters can both observe and detect them; nothing here defeats
//! every anti-bot system, and no such claim should be made. Vector
//! coherence is checked by `fingerprint_validator`, which is consistency
//! testing, not real-world evasion evidence.
//!
//! Stealth scripts MUST be applied BEFORE any navigation to ensure overrides
//! are in place for all JS execution.

use serde_json::json;

use super::cdp::CdpClient;
use super::error::BrowserError;

// ---------------------------------------------------------------------------
// Stealth Profile
// ---------------------------------------------------------------------------

/// A correlated browser fingerprint profile for stealth automation.
///
/// All fields are internally consistent: user_agent, platform, vendor,
/// hardware_concurrency, etc. must match what the real browser would report.
/// Use factory methods (`chrome_windows()`, etc.) for pre-validated presets.
#[derive(Debug, Clone)]
pub struct StealthProfile {
    pub user_agent: String,
    pub platform: String,
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
    /// When `true`, Chrome-specific evasions (window.chrome, chrome.runtime,
    /// Chrome PDF plugins, Client Hints, etc.) are skipped and Firefox-appropriate
    /// values are injected instead.  Set automatically by Tor/Firefox profiles.
    pub is_firefox_profile: bool,
}

impl StealthProfile {
    /// Chrome 151 on Windows 10/11.
    pub fn chrome_windows() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36".to_string(),
            platform: "Win32".to_string(),
            vendor: "Google Inc.".to_string(),
            languages: vec!["en-US".to_string(), "en".to_string()],
            hardware_concurrency: 8,
            device_memory: 8.0,
            max_touch_points: 0,
            viewport: (1920, 1080),
            device_scale_factor: 1.0,
            webgl_vendor: "Google Inc. (NVIDIA)".to_string(),
            webgl_renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)".to_string(),
            timezone: "America/New_York".to_string(),
            locale: "en-US".to_string(),
            canvas_noise_seed: 0x4e69_7865_5769_6e64, // "TallowWin" in hex
            is_firefox_profile: false,
        }
    }

    /// Chrome 151 on macOS Sonoma (Apple Silicon).
    pub fn chrome_macos() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36".to_string(),
            platform: "MacIntel".to_string(),
            vendor: "Google Inc.".to_string(),
            languages: vec!["en-US".to_string(), "en".to_string()],
            hardware_concurrency: 10,
            device_memory: 8.0,
            max_touch_points: 0,
            viewport: (1440, 900),
            device_scale_factor: 2.0,
            webgl_vendor: "Google Inc. (Apple)".to_string(),
            webgl_renderer: "ANGLE (Apple, Apple M2, OpenGL 4.1)".to_string(),
            timezone: "America/Los_Angeles".to_string(),
            locale: "en-US".to_string(),
            canvas_noise_seed: 0x4e69_7865_4d61_634f, // "TallowMac" in hex
            is_firefox_profile: false,
        }
    }

    /// Chrome 151 on Linux (X11).
    pub fn chrome_linux() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36".to_string(),
            platform: "Linux x86_64".to_string(),
            vendor: "Google Inc.".to_string(),
            languages: vec!["en-US".to_string(), "en".to_string()],
            hardware_concurrency: 8,
            device_memory: 8.0,
            max_touch_points: 0,
            viewport: (1920, 1080),
            device_scale_factor: 1.0,
            webgl_vendor: "Google Inc. (Intel)".to_string(),
            webgl_renderer: "ANGLE (Intel, Mesa Intel(R) UHD Graphics 630, OpenGL 4.6)".to_string(),
            timezone: "America/Chicago".to_string(),
            locale: "en-US".to_string(),
            canvas_noise_seed: 0x4e69_7865_4c69_6e78, // "TallowLin" in hex
            is_firefox_profile: false,
        }
    }

    /// Chrome 151 on Android (Pixel 8).
    pub fn mobile_android() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36".to_string(),
            platform: "Linux armv81".to_string(),
            vendor: "Google Inc.".to_string(),
            languages: vec!["en-US".to_string(), "en".to_string()],
            hardware_concurrency: 8,
            device_memory: 8.0,
            max_touch_points: 5,
            viewport: (412, 915),
            device_scale_factor: 2.625,
            webgl_vendor: "Qualcomm".to_string(),
            webgl_renderer: "Adreno (TM) 740".to_string(),
            timezone: "America/New_York".to_string(),
            locale: "en-US".to_string(),
            canvas_noise_seed: 0x4e69_7865_416e_6472, // "TallowAnd" in hex
            is_firefox_profile: false,
        }
    }

    /// Chrome 151 on iOS (iPhone 15 Pro).
    pub fn mobile_ios() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/151.0.6945.0 Mobile/15E148 Safari/604.1".to_string(),
            platform: "iPhone".to_string(),
            vendor: "Apple Computer, Inc.".to_string(),
            languages: vec!["en-US".to_string(), "en".to_string()],
            hardware_concurrency: 6,
            device_memory: 6.0,
            max_touch_points: 5,
            viewport: (393, 852),
            device_scale_factor: 3.0,
            webgl_vendor: "Apple Inc.".to_string(),
            webgl_renderer: "Apple GPU".to_string(),
            timezone: "America/New_York".to_string(),
            locale: "en-US".to_string(),
            canvas_noise_seed: 0x4e69_7865_694f_5331, // "TalloiOS1" in hex
            is_firefox_profile: false,
        }
    }

    /// Randomize the per-session "identity" fields so each fresh browser launch
    /// presents a different, non-correlatable fingerprint — while keeping the
    /// engine-consistent fields (UA, platform, vendor, WebGL, viewport,
    /// `is_firefox_profile`) untouched so we don't reintroduce a JS/engine
    /// fingerprint contradiction.
    ///
    /// Rotated: `timezone`, `canvas_noise_seed`, `hardware_concurrency`,
    /// `device_memory`, `languages`, `locale`, `device_scale_factor`.
    pub fn randomize(&mut self) {
        use rand::Rng;
        let mut rng = rand::rng();

        let timezones: &[&str] = &[
            "America/New_York",
            "America/Chicago",
            "America/Denver",
            "America/Los_Angeles",
            "America/Phoenix",
            "America/Detroit",
            "America/Boise",
            "America/Anchorage",
            "America/Indianapolis",
            "Pacific/Honolulu",
        ];
        self.timezone = timezones[rng.random_range(0..timezones.len())].to_string();

        let conc: &[u32] = &[2, 4, 6, 8, 10, 12, 16];
        self.hardware_concurrency = conc[rng.random_range(0..conc.len())];

        let mem: &[f64] = &[2.0, 4.0, 8.0, 16.0];
        self.device_memory = mem[rng.random_range(0..mem.len())];

        let scale: &[f64] = &[1.0, 1.25, 1.5, 2.0];
        self.device_scale_factor = scale[rng.random_range(0..scale.len())];

        let lang_sets: &[&[&str]] = &[
            &["en-US", "en"],
            &["en-GB", "en"],
            &["en-CA", "en"],
            &["en-US", "en", "es"],
            &["en-AU", "en"],
            &["en-US", "en", "fr"],
            &["en", "en-US"],
        ];
        let chosen = lang_sets[rng.random_range(0..lang_sets.len())];
        self.languages = chosen.iter().map(|s| s.to_string()).collect();
        if !self.languages.is_empty() {
            self.locale = self.languages[0].clone();
        }

        self.canvas_noise_seed = rng.random();
    }
}

// ---------------------------------------------------------------------------
// JS Evasion Script Constants
// ---------------------------------------------------------------------------

/// Hides `navigator.webdriver`, adds `chrome.csi`/`chrome.loadTimes` stubs,
/// and fixes `permissions.query` to not leak "denied" for notifications.
pub const WEBDRIVER_EVASION: &str = r#"
(() => {
    // Hide navigator.webdriver
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
        configurable: true
    });
    // Delete the property from the prototype chain too
    const proto = Object.getPrototypeOf(navigator);
    if (proto && Object.getOwnPropertyDescriptor(proto, 'webdriver')) {
        Object.defineProperty(proto, 'webdriver', {
            get: () => undefined,
            configurable: true
        });
    }
    // Stub chrome.csi (present in real Chrome)
    if (!window.chrome) window.chrome = {};
    window.chrome.csi = function() {
        return {
            onloadT: Date.now(),
            startE: Date.now(),
            pageT: performance.now(),
            tpidr: 0
        };
    };
    // Stub chrome.loadTimes (present in real Chrome)
    window.chrome.loadTimes = function() {
        return {
            commitLoadTime: Date.now() / 1000,
            connectionInfo: 'h2',
            finishDocumentLoadTime: Date.now() / 1000,
            finishLoadTime: Date.now() / 1000,
            firstPaintAfterLoadTime: 0,
            firstPaintTime: Date.now() / 1000,
            navigationType: 'Other',
            npnNegotiatedProtocol: 'h2',
            requestTime: Date.now() / 1000,
            startLoadTime: Date.now() / 1000,
            wasAlternateProtocolAvailable: false,
            wasFetchedViaSpdy: true,
            wasNpnNegotiated: true
        };
    };
    // Fix permissions.query to return "prompt" for notifications
    const origQuery = window.Notification
        ? window.Permissions.prototype.query
        : null;
    if (origQuery) {
        Permissions.prototype.query = function(parameters) {
            if (parameters.name === 'notifications') {
                return Promise.resolve({ state: Notification.permission });
            }
            return origQuery.call(this, parameters);
        };
    }
})();
"#;

/// Fix `window.chrome.runtime` to return a proper object (detection signal
/// when missing or when it has an empty object).
pub const CHROME_RUNTIME_EVASION: &str = r#"
(() => {
    if (!window.chrome) window.chrome = {};
    if (!window.chrome.runtime) {
        window.chrome.runtime = {
            OnInstalledReason: {
                CHROME_UPDATE: 'chrome_update',
                INSTALL: 'install',
                SHARED_MODULE_UPDATE: 'shared_module_update',
                UPDATE: 'update'
            },
            OnRestartRequiredReason: {
                APP_UPDATE: 'app_update',
                OS_UPDATE: 'os_update',
                PERIODIC: 'periodic'
            },
            PlatformArch: {
                ARM: 'arm',
                ARM64: 'arm64',
                MIPS: 'mips',
                MIPS64: 'mips64',
                X86_32: 'x86-32',
                X86_64: 'x86-64'
            },
            PlatformOs: {
                ANDROID: 'android',
                CROS: 'cros',
                LINUX: 'linux',
                MAC: 'mac',
                OPENBSD: 'openbsd',
                WIN: 'win'
            },
            RequestUpdateCheckStatus: {
                NO_UPDATE: 'no_update',
                THROTTLED: 'throttled',
                UPDATE_AVAILABLE: 'update_available'
            },
            connect: function() { return { onDisconnect: { addListener: function() {} }, onMessage: { addListener: function() {} }, postMessage: function() {} }; },
            sendMessage: function() {}
        };
    }
})();
"#;

/// Set `navigator.plugins` to a realistic Chrome PDF plugin array.
pub const PLUGINS_EVASION: &str = r#"
(() => {
    const pdfPlugin = {
        name: 'Chrome PDF Viewer',
        description: 'Portable Document Format',
        filename: 'internal-pdf-viewer',
        length: 1,
        0: { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' }
    };
    const pdfPlugin2 = {
        name: 'Chromium PDF Viewer',
        description: 'Portable Document Format',
        filename: 'internal-pdf-viewer',
        length: 1,
        0: { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' }
    };
    const nativePdfPlugin = {
        name: 'Native Client',
        description: '',
        filename: 'internal-nacl-plugin',
        length: 2,
        0: { type: 'application/x-nacl', suffixes: '', description: 'Native Client Executable' },
        1: { type: 'application/x-pnacl', suffixes: '', description: 'Portable Native Client Executable' }
    };
    const pluginArr = [pdfPlugin, pdfPlugin2, nativePdfPlugin];
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            const p = pluginArr;
            p.item = (i) => p[i] || null;
            p.namedItem = (n) => p.find(x => x.name === n) || null;
            p.refresh = () => {};
            return p;
        },
        configurable: true
    });
    Object.defineProperty(navigator, 'mimeTypes', {
        get: () => {
            const m = [
                { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: pdfPlugin }
            ];
            m.item = (i) => m[i] || null;
            m.namedItem = (n) => m.find(x => x.type === n) || null;
            return m;
        },
        configurable: true
    });
})();
"#;

/// Firefox-appropriate empty plugins/mimeTypes (Firefox reports empty arrays).
/// Used instead of `PLUGINS_EVASION` when `is_firefox_profile` is true.
pub const FIREFOX_PLUGINS_EVASION: &str = r#"
(() => {
    // Firefox reports empty plugin and mimeType arrays
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            const p = [];
            p.item = (i) => p[i] || null;
            p.namedItem = (n) => null;
            p.refresh = () => {};
            return p;
        },
        configurable: true
    });
    Object.defineProperty(navigator, 'mimeTypes', {
        get: () => {
            const m = [];
            m.item = (i) => m[i] || null;
            m.namedItem = (n) => null;
            return m;
        },
        configurable: true
    });
})();
"#;

/// Firefox-appropriate webdriver evasion: hides navigator.webdriver and
/// fixes permissions, but does NOT inject window.chrome, chrome.csi,
/// or chrome.loadTimes (which do not exist in Firefox).
pub const FIREFOX_WEBDRIVER_EVASION: &str = r#"
(() => {
    // Hide navigator.webdriver
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
        configurable: true
    });
    const proto = Object.getPrototypeOf(navigator);
    if (proto && Object.getOwnPropertyDescriptor(proto, 'webdriver')) {
        Object.defineProperty(proto, 'webdriver', {
            get: () => undefined,
            configurable: true
        });
    }
    // Fix permissions.query to return "prompt" for notifications
    const origQuery = window.Notification
        ? window.Permissions.prototype.query
        : null;
    if (origQuery) {
        Permissions.prototype.query = function(parameters) {
            if (parameters.name === 'notifications') {
                return Promise.resolve({ state: Notification.permission });
            }
            return origQuery.call(this, parameters);
        };
    }
})();
"#;

/// Override `navigator.languages` getter. Parameterized by the profile's language list.
pub const LANGUAGES_EVASION_TEMPLATE: &str = r#"
(() => {
    Object.defineProperty(navigator, 'languages', {
        get: () => __LANGUAGES__,
        configurable: true
    });
})();
"#;

// ---------------------------------------------------------------------------
// Dynamic JS Script Generators
// ---------------------------------------------------------------------------

/// Generate canvas noise injection JS using a deterministic PRNG seeded per context.
///
/// Overrides `HTMLCanvasElement.prototype.toDataURL` to add imperceptible noise
/// and `WebGLRenderingContext.getParameter` for VENDOR/RENDERER spoofing.
pub fn canvas_evasion_script(profile: &StealthProfile) -> String {
    format!(
        r#"
(() => {{
    // STABLE-PER-READ noise: the PRNG is never advanced across calls. Instead,
    // noise is a PURE function of (canvas content hash, per-profile seed), so
    // two toDataURL() reads of an unchanged canvas return IDENTICAL bytes
    // (a stateful PRNG that changes the image on every read is a detector tell).
    const TALLOW_SEED = {seed}n;

    // FNV-1a hash of the sampled content -> 32-bit. Deterministic.
    function __tallowHash(buf) {{
        let h = 0x811c9dc5;
        for (let i = 0; i < buf.length; i++) {{
            h ^= buf[i];
            h = Math.imul(h, 0x01000193);
        }}
        return h >>> 0;
    }}

    // Pure PRNG seeded from a 32-bit value; same seed -> same stream.
    function __tallowRng(a) {{
        return function() {{
            a |= 0; a = a + 0x6D2B79F5 | 0;
            let t = Math.imul(a ^ a >>> 15, 1 | a);
            t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
            return ((t ^ t >>> 14) >>> 0) / 4294967296;
        }};
    }}

    // Override toDataURL to add imperceptible, content-keyed noise
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type, quality) {{
        try {{
            const ctx = this.getContext('2d');
            if (ctx) {{
                const w = this.width, h = this.height;
                if (w > 0 && h > 0) {{
                    const imgData = ctx.getImageData(0, 0, Math.min(w, 16), Math.min(h, 16));
                    // Content-hash XOR per-profile seed -> SAME noise on every read.
                    const key = (__tallowHash(imgData.data) ^ Number(TALLOW_SEED)) >>> 0;
                    const rng = __tallowRng(key);
                    for (let i = 0; i < imgData.data.length; i += 4) {{
                        imgData.data[i] = (imgData.data[i] + (rng() > 0.5 ? 1 : -1)) & 0xFF;
                    }}
                    ctx.putImageData(imgData, 0, 0);
                }}
            }}
        }} catch(e) {{}}
        return origToDataURL.call(this, type, quality);
    }};

    // Override WebGL VENDOR/RENDERER
    const getParam = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {{
        if (param === 0x1F00) return '{webgl_vendor}';   // VENDOR
        if (param === 0x1F01) return '{webgl_renderer}'; // RENDERER
        if (param === 0x9245) return '{webgl_vendor}';   // UNMASKED_VENDOR
        if (param === 0x9246) return '{webgl_renderer}'; // UNMASKED_RENDERER
        return getParam.call(this, param);
    }};
    // WebGL2 as well
    if (typeof WebGL2RenderingContext !== 'undefined') {{
        const getParam2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(param) {{
            if (param === 0x1F00) return '{webgl_vendor}';
            if (param === 0x1F01) return '{webgl_renderer}';
            if (param === 0x9245) return '{webgl_vendor}';
            if (param === 0x9246) return '{webgl_renderer}';
            return getParam2.call(this, param);
        }};
    }}
}})();
"#,
        seed = profile.canvas_noise_seed,
        webgl_vendor = profile.webgl_vendor.replace('\'', "\\'"),
        webgl_renderer = profile.webgl_renderer.replace('\'', "\\'"),
    )
}

/// Generate JS that overrides navigator properties to match the stealth profile.
pub fn navigator_overrides_script(profile: &StealthProfile) -> String {
    let languages_json = serde_json::to_string(&profile.languages).unwrap_or_else(|_| "[\"en-US\"]".to_string());
    format!(
        r#"
(() => {{
    const overrides = {{
        platform: '{platform}',
        vendor: '{vendor}',
        hardwareConcurrency: {hw_concurrency},
        deviceMemory: {device_memory},
        maxTouchPoints: {max_touch_points},
        languages: {languages}
    }};
    for (const [key, value] of Object.entries(overrides)) {{
        Object.defineProperty(navigator, key, {{
            get: () => value,
            configurable: true
        }});
    }}
}})();
"#,
        platform = profile.platform.replace('\'', "\\'"),
        vendor = profile.vendor.replace('\'', "\\'"),
        hw_concurrency = profile.hardware_concurrency,
        device_memory = profile.device_memory,
        max_touch_points = profile.max_touch_points,
        languages = languages_json,
    )
}

// ---------------------------------------------------------------------------
// CDP Injection Functions
// ---------------------------------------------------------------------------

/// Inject all stealth evasion scripts into a page via `Page.addScriptToEvaluateOnNewDocument`.
///
/// Order: webdriver evasion first, then navigator overrides, then canvas,
/// then plugins, then chrome runtime.
///
/// This function MUST be called BEFORE any navigation to ensure overrides
/// are in place before any JS on the page executes.
///
/// Honors the process-wide stealth config (see `StealthToml::global_or_load`)
/// loaded from `stealth.toml`: `v1_enabled` / `v2_enabled` / `v3_enabled`
/// gate the three script layers and the `[evasions]` toggles filter the
/// per-vector scripts. When no config file exists the defaults are
/// all-enabled, so behavior is unchanged from the historical full-set
/// injection.
pub async fn inject_stealth_scripts(
    client: &CdpClient,
    session_id: &str,
    profile: &StealthProfile,
) -> Result<(), BrowserError> {
    inject_stealth_scripts_with_config(
        client,
        session_id,
        profile,
        Some(super::config::stealth_conf::StealthToml::global_or_load()),
    )
    .await
}

/// Like [`inject_stealth_scripts`], but with an explicit stealth config.
///
/// Pass `None` (or an all-default config) to inject the full script set —
/// the historical behavior. Pass a [`StealthToml`] to disable whole layers
/// (`v1_enabled` / `v2_enabled` / `v3_enabled`) or individual vectors via
/// `[evasions]` toggles.
pub async fn inject_stealth_scripts_with_config(
    client: &CdpClient,
    session_id: &str,
    profile: &StealthProfile,
    config: Option<&super::config::stealth_conf::StealthToml>,
) -> Result<(), BrowserError> {
    let is_ff = profile.is_firefox_profile;

    // Layer gates. With no config these default to enabled → full set.
    let v1_enabled = config.map_or(true, |c| c.v1_enabled);
    let v2_enabled = config.map_or(true, |c| c.v2_enabled);
    let v3_enabled = config.map_or(true, |c| c.v3_enabled);
    // Per-vector gates. Default = every vector enabled.
    let ev = config
        .map(|c| c.evasions.clone())
        .unwrap_or_default();

    // Build script list — choose browser-appropriate evasions.
    // Firefox profiles skip window.chrome, chrome.runtime, and Chrome PDF plugins.
    let mut scripts: Vec<(&str, String)> = Vec::new();

    if v1_enabled {
        // Webdriver evasion: Firefox variant omits chrome.csi / chrome.loadTimes
        if ev.webdriver {
            if is_ff {
                scripts.push(("webdriver_evasion", FIREFOX_WEBDRIVER_EVASION.to_string()));
            } else {
                scripts.push(("webdriver_evasion", WEBDRIVER_EVASION.to_string()));
            }
        }

        // Navigator overrides (shared — works for both browsers)
        if ev.navigator {
            scripts.push(("navigator_overrides", navigator_overrides_script(profile)));
        }

        // Canvas/WebGL evasion (shared — works for both browsers).
        // The script patches canvas noise AND WebGL getParameter, so it is
        // gated by either toggle; only both-off disables it.
        if ev.canvas || ev.webgl {
            scripts.push(("canvas_evasion", canvas_evasion_script(profile)));
        }

        // Plugins: Chrome gets Chrome PDF plugins; Firefox gets empty arrays
        if ev.plugins_spoof {
            if is_ff {
                scripts.push(("plugins_evasion", FIREFOX_PLUGINS_EVASION.to_string()));
            } else {
                scripts.push(("plugins_evasion", PLUGINS_EVASION.to_string()));
            }
        }

        // chrome.runtime — Chrome only (Firefox has no window.chrome)
        if ev.chrome_runtime && !is_ff {
            scripts.push(("chrome_runtime_evasion", CHROME_RUNTIME_EVASION.to_string()));
        }

        // Languages (shared)
        if ev.languages {
            scripts.push((
                "languages_evasion",
                LANGUAGES_EVASION_TEMPLATE.replace(
                    "__LANGUAGES__",
                    &serde_json::to_string(&profile.languages)
                        .unwrap_or_else(|_| "[\"en-US\"]".to_string()),
                ),
            ));
        }
    }

    for (name, source) in &scripts {
        client
            .send_command_with_session(
                "Page.addScriptToEvaluateOnNewDocument",
                // Inject into the MAIN world (omit `worldName`) so that
                // page fingerprinters (FingerprintJS, DataDome, PX, Akamai)
                // actually observe the overrides. Isolated-world injection
                // leaves main-world probes unpatched.
                Some(json!({
                    "source": source,
                })),
                session_id,
            )
            .await
            .map_err(|e| BrowserError::CdpError {
                code: -1,
                message: format!("failed to inject stealth script '{}': {}", name, e),
            })?;
    }

    // ── Stealth V2: patch remaining detection vectors ──
    // The V2 script is internally gated per-vector by the same [evasions]
    // toggles (see stealth_v2::stealth_v2_script).
    if v2_enabled {
        let v2_script = super::stealth_v2::stealth_v2_script(profile, Some(&ev));
        client
            .send_command_with_session(
                "Page.addScriptToEvaluateOnNewDocument",
                Some(json!({
                    "source": v2_script,
                })),
                session_id,
            )
            .await
            .map_err(|e| BrowserError::CdpError {
                code: -1,
                message: format!("failed to inject stealth v2 script: {}", e),
            })?;
    }

    // ── Stealth V3: advanced anti-detection (toString cloaking, Error.stack
    //    sanitization, $cdc_/CDP leak cleanup, perf-entry filtering, hasFocus,
    //    Notification permission) — targets DataDome/CreepJS/FingerprintJS ──
    if v3_enabled {
        let v3_script = super::stealth_v3::stealth_v3_script(profile);
        client
            .send_command_with_session(
                "Page.addScriptToEvaluateOnNewDocument",
                Some(json!({
                    "source": v3_script,
                })),
                session_id,
            )
            .await
            .map_err(|e| BrowserError::CdpError {
                code: -1,
                message: format!("failed to inject stealth v3 script: {}", e),
            })?;
    }

    Ok(())
}

/// Set the HTTP-level User-Agent override via `Network.setUserAgentOverride`.
///
/// This overrides the User-Agent header sent in HTTP requests **and** the
/// `Sec-CH-UA`, `Sec-CH-UA-Platform`, and `Sec-CH-UA-Mobile` headers via the
/// `userAgentMetadata` parameter.  Without `userAgentMetadata`, Chrome sends
/// its real Client Hints headers even though JS `navigator.userAgentData` is
/// spoofed by the V2 evasion scripts — creating a detectable mismatch.
///
/// The JS-level `navigator.userAgent` is handled by the evasion scripts.
pub async fn apply_stealth_ua(
    client: &CdpClient,
    session_id: &str,
    profile: &StealthProfile,
) -> Result<(), BrowserError> {
    let accept_language = profile.languages.join(", ");

    // Extract Chrome major version from the UA string for Client Hints.
    let chrome_ver = profile
        .user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|s| s.split('.').next())
        .unwrap_or("151");

    // Full version string (e.g. "151.0.0.0")
    let full_version = profile
        .user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or("151.0.0.0");

    // Map StealthProfile.platform to the Sec-CH-UA-Platform value.
    let ch_platform = if profile.platform.contains("Win") {
        "Windows"
    } else if profile.platform.contains("Mac") || profile.platform == "iPhone" {
        "macOS"
    } else if profile.platform.contains("Linux") || profile.platform.contains("Android") {
        "Linux"
    } else {
        "Windows"
    };

    let mobile = profile.max_touch_points > 0;

    // Platform version — approximate, used by high-entropy Client Hints.
    let platform_version = if ch_platform == "Windows" {
        "10.0.0"
    } else if ch_platform == "macOS" {
        "14.0.0"
    } else {
        "6.5.0"
    };

    // Build the userAgentMetadata object that CDP uses to populate
    // Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform HTTP headers.
    let ua_metadata = json!({
        "brands": [
            { "brand": "Google Chrome", "version": chrome_ver },
            { "brand": "Chromium", "version": chrome_ver },
            { "brand": "Not_A Brand", "version": "24" }
        ],
        "fullVersionList": [
            { "brand": "Google Chrome", "version": full_version },
            { "brand": "Chromium", "version": full_version },
            { "brand": "Not_A Brand", "version": "24.0.0.0" }
        ],
        "fullVersion": full_version,
        "platform": ch_platform,
        "platformVersion": platform_version,
        "architecture": if mobile { "arm" } else { "x86" },
        "model": if mobile { "Pixel 8" } else { "" },
        "mobile": mobile,
        "bitness": if mobile { "64" } else { "64" },
        "wow64": false,
    });

    client
        .send_command_with_session(
            "Network.setUserAgentOverride",
            Some(json!({
                "userAgent": profile.user_agent,
                "platform": profile.platform,
                "acceptLanguage": accept_language,
                "userAgentMetadata": ua_metadata,
            })),
            session_id,
        )
        .await?;

    Ok(())
}

/// Detect the real Chrome version via `Browser.getVersion` and return the
/// version string (e.g. `"133.0.6943.98"`).
///
/// This is a browser-level command (no session ID needed).
pub async fn detect_chrome_version(
    client: &CdpClient,
) -> Result<String, BrowserError> {
    let result = client
        .send_command("Browser.getVersion", None)
        .await?;

    // The response has: { "product": "Chrome/152.0.6943.98", "userAgent": "...", ... }
    let product = result
        .get("product")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract version after "Chrome/" or "HeadlessChrome/"
    let version = product
        .split("Chrome/")
        .nth(1)
        .unwrap_or(product)
        .to_string();

    if version.is_empty() {
        return Err(BrowserError::CdpError {
            code: -1,
            message: format!(
                "could not parse Chrome version from Browser.getVersion product: {:?}",
                product
            ),
        });
    }

    Ok(version)
}

impl StealthProfile {
    /// Update the user agent string to match the actual installed Chrome version.
    ///
    /// Replaces the Chrome version in the UA string (e.g. `Chrome/151.0.0.0` ->
    /// `Chrome/152.0.6943.98`) and similarly for CriOS on iOS profiles.
    /// This prevents JA4 fingerprint mismatches where the TLS handshake
    /// identifies Chrome 152 but the UA string claims Chrome 151.
    pub fn update_chrome_version(&mut self, actual_version: &str) {
        // Extract just the major version for CriOS replacement
        let actual_major = actual_version.split('.').next().unwrap_or(actual_version);

        // Replace "Chrome/OLD_VERSION" with "Chrome/ACTUAL_VERSION" in the UA
        if let Some(start) = self.user_agent.find("Chrome/") {
            let prefix = &self.user_agent[..start + 7]; // "...Chrome/"
            let rest = &self.user_agent[start + 7..];
            // Find end of old version (next space or end of string)
            let end = rest.find(' ').unwrap_or(rest.len());
            self.user_agent = format!("{}{}{}", prefix, actual_version, &rest[end..]);
        }

        // Also handle CriOS (Chrome on iOS) — e.g. "CriOS/151.0.6945.0"
        if let Some(start) = self.user_agent.find("CriOS/") {
            let prefix = &self.user_agent[..start + 6]; // "...CriOS/"
            let rest = &self.user_agent[start + 6..];
            let end = rest.find(' ').unwrap_or(rest.len());
            self.user_agent = format!("{}{}{}", prefix, actual_version, &rest[end..]);
        }

        // For HeadlessChrome profiles (unlikely but handle gracefully)
        if let Some(start) = self.user_agent.find("HeadlessChrome/") {
            let prefix = &self.user_agent[..start + 15];
            let rest = &self.user_agent[start + 15..];
            let end = rest.find(' ').unwrap_or(rest.len());
            self.user_agent = format!("{}{}{}", prefix, actual_version, &rest[end..]);
        }

        let _ = actual_major; // suppress unused warning if CriOS branch not taken
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- StealthProfile factory method tests --

    #[test]
    fn chrome_windows_profile_is_valid() {
        let p = StealthProfile::chrome_windows();
        assert!(p.user_agent.contains("Chrome/151"));
        assert!(p.user_agent.contains("Windows NT 10.0"));
        assert_eq!(p.platform, "Win32");
        assert_eq!(p.vendor, "Google Inc.");
        assert!(!p.languages.is_empty());
        assert!(p.hardware_concurrency > 0);
        assert!(p.device_memory > 0.0);
        assert_eq!(p.max_touch_points, 0); // Desktop: no touch
        assert!(p.viewport.0 > 0 && p.viewport.1 > 0);
        assert!(!p.webgl_vendor.is_empty());
        assert!(!p.webgl_renderer.is_empty());
    }

    #[test]
    fn chrome_macos_profile_is_valid() {
        let p = StealthProfile::chrome_macos();
        assert!(p.user_agent.contains("Chrome/151"));
        assert!(p.user_agent.contains("Macintosh"));
        assert_eq!(p.platform, "MacIntel");
        assert_eq!(p.device_scale_factor, 2.0); // Retina
        assert_eq!(p.max_touch_points, 0);
    }

    #[test]
    fn chrome_linux_profile_is_valid() {
        let p = StealthProfile::chrome_linux();
        assert!(p.user_agent.contains("Chrome/151"));
        assert!(p.user_agent.contains("X11; Linux x86_64"));
        assert_eq!(p.platform, "Linux x86_64");
    }

    #[test]
    fn mobile_android_profile_is_valid() {
        let p = StealthProfile::mobile_android();
        assert!(p.user_agent.contains("Chrome/151"));
        assert!(p.user_agent.contains("Android 14"));
        assert!(p.user_agent.contains("Mobile"));
        assert_eq!(p.platform, "Linux armv81");
        assert!(p.max_touch_points > 0); // Mobile has touch
        assert!(p.device_scale_factor > 1.0);
    }

    #[test]
    fn mobile_ios_profile_is_valid() {
        let p = StealthProfile::mobile_ios();
        assert!(p.user_agent.contains("iPhone"));
        assert!(p.user_agent.contains("CriOS/151"));
        assert_eq!(p.platform, "iPhone");
        assert_eq!(p.vendor, "Apple Computer, Inc.");
        assert!(p.max_touch_points > 0);
        assert_eq!(p.device_scale_factor, 3.0);
    }

    #[test]
    fn all_presets_have_unique_canvas_seeds() {
        let seeds = [
            StealthProfile::chrome_windows().canvas_noise_seed,
            StealthProfile::chrome_macos().canvas_noise_seed,
            StealthProfile::chrome_linux().canvas_noise_seed,
            StealthProfile::mobile_android().canvas_noise_seed,
            StealthProfile::mobile_ios().canvas_noise_seed,
        ];
        // All seeds should be unique
        for i in 0..seeds.len() {
            for j in (i + 1)..seeds.len() {
                assert_ne!(seeds[i], seeds[j], "seeds at indices {} and {} should differ", i, j);
            }
        }
    }

    // -- JS evasion script tests --

    #[test]
    fn canvas_evasion_different_seeds_different_scripts() {
        let p1 = StealthProfile::chrome_windows();
        let p2 = StealthProfile::chrome_macos();
        let s1 = canvas_evasion_script(&p1);
        let s2 = canvas_evasion_script(&p2);
        // Different seeds produce different scripts
        assert_ne!(s1, s2);
    }

    #[test]
    fn canvas_evasion_contains_content_keyed_rng_and_webgl() {
        let p = StealthProfile::chrome_windows();
        let script = canvas_evasion_script(&p);
        // Noise must be keyed on a content hash + profile seed, NOT a stateful
        // PRNG that advances per call (stateful noise is a detector tell).
        assert!(script.contains("__tallowHash"), "should hash canvas content");
        assert!(script.contains("__tallowRng"), "should contain pure PRNG");
        assert!(script.contains("toDataURL"), "should override toDataURL");
        assert!(script.contains("NVIDIA"), "should contain WebGL renderer");
        assert!(script.contains("0x1F00"), "should check WebGL VENDOR param");
        assert!(script.contains("0x9246"), "should check UNMASKED_RENDERER param");
    }

    #[test]
    fn canvas_noise_is_stable_per_read() {
        // Two toDataURL() calls on the same canvas must produce identical bytes.
        // Because noise is a pure function of (content hash, per-profile seed),
        // the emitted override re-derives the SAME key on every read instead of
        // advancing a shared RNG. Assert the script derives its PRNG seed from a
        // content hash XOR the profile seed (stable), not from a mutable counter.
        let p = StealthProfile::chrome_windows();
        let script = canvas_evasion_script(&p);
        // The key is recomputed from the sampled content each call -> identical
        // noise on every read of an unchanged canvas.
        assert!(
            script.contains("__tallowHash(imgData.data)"),
            "noise key must be a pure function of canvas content"
        );
        assert!(
            script.contains("__tallowHash(imgData.data) ^ Number(TALLOW_SEED)"),
            "noise key must fold in the per-profile seed"
        );
        // Reject the old stateful design: a mutable seed advanced on every call.
        assert!(
            !script.contains("seed ^= seed << 13n"),
            "must not use a stateful xorshift advanced per read"
        );
    }

    #[test]
    fn navigator_overrides_includes_all_profile_fields() {
        let p = StealthProfile::chrome_windows();
        let script = navigator_overrides_script(&p);
        assert!(script.contains("Win32"), "should include platform");
        assert!(script.contains("Google Inc."), "should include vendor");
        assert!(script.contains("hardwareConcurrency"), "should include hw_concurrency");
        assert!(script.contains("deviceMemory"), "should include device_memory");
        assert!(script.contains("maxTouchPoints"), "should include max_touch_points");
        assert!(script.contains("languages"), "should include languages");
        assert!(script.contains("en-US"), "should include language value");
    }

    #[test]
    fn randomize_rotates_identity_keeps_engine() {
        let mut p = StealthProfile::chrome_windows();
        let engine_ua = p.user_agent.clone();
        let engine_platform = p.platform.clone();
        let engine_ff = p.is_firefox_profile;
        let mut seen_timezones = std::collections::HashSet::new();
        for _ in 0..8 {
            p.randomize();
            seen_timezones.insert(p.timezone.clone());
            // Engine-consistent fields must NOT change.
            assert_eq!(p.user_agent, engine_ua, "UA must stay engine-consistent");
            assert_eq!(p.platform, engine_platform, "platform must stay fixed");
            assert_eq!(p.is_firefox_profile, engine_ff);
            // Identity fields should be realistic after rotation.
            assert!(p.hardware_concurrency >= 2 && p.hardware_concurrency <= 16);
            assert!(p.device_memory >= 2.0 && p.device_memory <= 16.0);
            assert!(!p.languages.is_empty());
            assert!(!p.timezone.is_empty());
        }
        // Over 8 draws we should have seen more than one timezone (the rotation
        // actually varies the identity), unless the RNG was pathologically
        // unlucky — accept >=2 distinct zones as proof of rotation.
        assert!(seen_timezones.len() >= 2, "expected timezone rotation");
    }

    #[test]
    fn webdriver_evasion_hides_navigator_webdriver() {
        assert!(WEBDRIVER_EVASION.contains("navigator, 'webdriver'"));
        assert!(WEBDRIVER_EVASION.contains("undefined"));
        assert!(WEBDRIVER_EVASION.contains("chrome.csi"));
        assert!(WEBDRIVER_EVASION.contains("chrome.loadTimes"));
        assert!(WEBDRIVER_EVASION.contains("notifications"));
    }

    #[test]
    fn chrome_runtime_evasion_has_runtime_object() {
        assert!(CHROME_RUNTIME_EVASION.contains("chrome.runtime"));
        assert!(CHROME_RUNTIME_EVASION.contains("OnInstalledReason"));
        assert!(CHROME_RUNTIME_EVASION.contains("connect"));
        assert!(CHROME_RUNTIME_EVASION.contains("sendMessage"));
    }

    #[test]
    fn plugins_evasion_has_pdf_plugins() {
        assert!(PLUGINS_EVASION.contains("Chrome PDF Viewer"));
        assert!(PLUGINS_EVASION.contains("Chromium PDF Viewer"));
        assert!(PLUGINS_EVASION.contains("application/pdf"));
        assert!(PLUGINS_EVASION.contains("navigator, 'plugins'"));
        assert!(PLUGINS_EVASION.contains("navigator, 'mimeTypes'"));
    }

    #[test]
    fn languages_evasion_template_has_placeholder() {
        assert!(LANGUAGES_EVASION_TEMPLATE.contains("__LANGUAGES__"));
        assert!(LANGUAGES_EVASION_TEMPLATE.contains("navigator, 'languages'"));
    }

    #[test]
    fn chrome_profiles_not_firefox() {
        assert!(!StealthProfile::chrome_windows().is_firefox_profile);
        assert!(!StealthProfile::chrome_macos().is_firefox_profile);
        assert!(!StealthProfile::chrome_linux().is_firefox_profile);
        assert!(!StealthProfile::mobile_android().is_firefox_profile);
        assert!(!StealthProfile::mobile_ios().is_firefox_profile);
    }

    #[test]
    fn firefox_plugins_evasion_has_empty_arrays() {
        assert!(FIREFOX_PLUGINS_EVASION.contains("navigator, 'plugins'"));
        assert!(FIREFOX_PLUGINS_EVASION.contains("navigator, 'mimeTypes'"));
        assert!(FIREFOX_PLUGINS_EVASION.contains("const p = []"));
        assert!(!FIREFOX_PLUGINS_EVASION.contains("Chrome PDF Viewer"));
    }

    #[test]
    fn firefox_webdriver_evasion_no_chrome_objects() {
        assert!(FIREFOX_WEBDRIVER_EVASION.contains("navigator, 'webdriver'"));
        assert!(!FIREFOX_WEBDRIVER_EVASION.contains("chrome.csi"));
        assert!(!FIREFOX_WEBDRIVER_EVASION.contains("chrome.loadTimes"));
        assert!(!FIREFOX_WEBDRIVER_EVASION.contains("window.chrome"));
    }

    // -- update_chrome_version tests --

    #[test]
    fn update_chrome_version_windows() {
        let mut p = StealthProfile::chrome_windows();
        assert!(p.user_agent.contains("Chrome/151.0.0.0"));
        p.update_chrome_version("152.0.6943.98");
        assert!(p.user_agent.contains("Chrome/152.0.6943.98"));
        assert!(!p.user_agent.contains("Chrome/151"));
        // Rest of UA should be intact
        assert!(p.user_agent.contains("Windows NT 10.0"));
        assert!(p.user_agent.contains("Safari/537.36"));
    }

    #[test]
    fn update_chrome_version_macos() {
        let mut p = StealthProfile::chrome_macos();
        p.update_chrome_version("152.0.7000.1");
        assert!(p.user_agent.contains("Chrome/152.0.7000.1"));
        assert!(p.user_agent.contains("Macintosh"));
    }

    #[test]
    fn update_chrome_version_ios_crios() {
        let mut p = StealthProfile::mobile_ios();
        assert!(p.user_agent.contains("CriOS/151"));
        p.update_chrome_version("152.0.6943.98");
        assert!(p.user_agent.contains("CriOS/152.0.6943.98"));
        assert!(!p.user_agent.contains("CriOS/151"));
    }

    #[test]
    fn update_chrome_version_preserves_ua_structure() {
        let mut p = StealthProfile::chrome_windows();
        let original = p.user_agent.clone();
        p.update_chrome_version("133.0.6943.98");
        // Should still have the same structure — only version number changed
        assert!(p.user_agent.starts_with("Mozilla/5.0"));
        assert!(p.user_agent.ends_with("Safari/537.36"));
        assert_ne!(original, p.user_agent);
    }

    #[test]
    fn update_chrome_version_no_chrome_in_ua_is_noop() {
        let mut p = StealthProfile::chrome_windows();
        // Manually set a Firefox-style UA
        p.user_agent = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0".to_string();
        let before = p.user_agent.clone();
        p.update_chrome_version("133.0.6943.98");
        // No "Chrome/" in UA, so it should be unchanged
        assert_eq!(p.user_agent, before);
    }
}
