//! Stealth V2 — comprehensive anti-detection evasion scripts.
//!
//! Addresses 20 detection vectors used by Google, Cloudflare, PerimeterX,
//! DataDome, and Akamai bot detection systems. Injected via
//! `Page.addScriptToEvaluateOnNewDocument` before any navigation.
//!
//! These scripts supplement the V1 evasions in `stealth.rs` — they are
//! injected AFTER V1 scripts to patch remaining gaps.

use super::config::stealth_conf::StealthEvasions;
use super::stealth::StealthProfile;

// ─────────────────────────────────────────────────────────────────────────────
// 1. navigator.connection (Network Information API)
// Detection: headless Chrome returns undefined; real Chrome always has it.
// ─────────────────────────────────────────────────────────────────────────────

pub const CONNECTION_EVASION: &str = r#"
(() => {
    if (!navigator.connection) {
        const conn = {
            downlink: 10,
            effectiveType: '4g',
            onchange: null,
            rtt: 50,
            saveData: false,
            addEventListener: function() {},
            removeEventListener: function() {},
            dispatchEvent: function() { return true; }
        };
        Object.defineProperty(navigator, 'connection', {
            get: () => conn,
            configurable: true
        });
        Object.defineProperty(navigator, 'networkInformation', {
            get: () => conn,
            configurable: true
        });
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 2. window.outerWidth / outerHeight (headless reports 0)
// Detection: if (outerWidth === 0 || outerHeight === 0) → bot
// ─────────────────────────────────────────────────────────────────────────────

pub fn screen_dimensions_script(profile: &StealthProfile) -> String {
    let (vw, vh) = profile.viewport;
    // outerWidth/Height should be slightly larger than viewport (chrome frame)
    let ow = vw + 16;  // window border
    let oh = vh + 88;  // chrome + toolbar
    let avail_h = vh + 48; // taskbar offset
    format!(
        r#"
(() => {{
    Object.defineProperty(window, 'outerWidth', {{ get: () => {ow}, configurable: true }});
    Object.defineProperty(window, 'outerHeight', {{ get: () => {oh}, configurable: true }});
    Object.defineProperty(window, 'innerWidth', {{ get: () => {vw}, configurable: true }});
    Object.defineProperty(window, 'innerHeight', {{ get: () => {vh}, configurable: true }});
    Object.defineProperty(screen, 'width', {{ get: () => {vw}, configurable: true }});
    Object.defineProperty(screen, 'height', {{ get: () => {vh}, configurable: true }});
    Object.defineProperty(screen, 'availWidth', {{ get: () => {vw}, configurable: true }});
    Object.defineProperty(screen, 'availHeight', {{ get: () => {avail_h}, configurable: true }});
    Object.defineProperty(screen, 'pixelDepth', {{ get: () => 24, configurable: true }});
    Object.defineProperty(screen, 'colorDepth', {{ get: () => 24, configurable: true }});
    Object.defineProperty(screen, 'orientation', {{
        get: () => ({{ angle: 0, type: 'landscape-primary', onchange: null }}),
        configurable: true
    }});
}})();
"#
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. performance.memory (missing in headless)
// Detection: if (!performance.memory) → bot
// ─────────────────────────────────────────────────────────────────────────────

pub const PERFORMANCE_MEMORY_EVASION: &str = r#"
(() => {
    if (!performance.memory) {
        const mem = {
            jsHeapSizeLimit: 2197815296,
            totalJSHeapSize: 35731968 + Math.floor(Math.random() * 10000000),
            usedJSHeapSize: 22123456 + Math.floor(Math.random() * 5000000)
        };
        Object.defineProperty(performance, 'memory', {
            get: () => mem,
            configurable: true,
            enumerable: true
        });
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 4. performance.now() timing noise
// Detection: perfectly linear time increments = headless
// ─────────────────────────────────────────────────────────────────────────────

pub const PERFORMANCE_TIMING_EVASION: &str = r#"
(() => {
    const origNow = performance.now.bind(performance);
    let offset = Math.random() * 0.05;
    performance.now = function() {
        offset += (Math.random() - 0.5) * 0.02;
        return origNow() + offset;
    };
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 5. window.chrome extended properties (.app, .webstore)
// Detection: Object.keys(chrome).length < 4 → bot
// ─────────────────────────────────────────────────────────────────────────────

pub const CHROME_EXTENDED_EVASION: &str = r#"
(() => {
    if (!window.chrome) window.chrome = {};
    if (!window.chrome.app) {
        window.chrome.app = {
            isInstalled: false,
            InstallState: {
                DISABLED: 'disabled',
                INSTALLED: 'installed',
                NOT_INSTALLED: 'not_installed'
            },
            RunningState: {
                CANNOT_RUN: 'cannot_run',
                READY_TO_RUN: 'ready_to_run',
                RUNNING: 'running'
            },
            getDetails: function() { return null; },
            getIsInstalled: function() { return false; },
            installState: function(cb) { if (cb) cb('not_installed'); },
            runningState: function() { return 'cannot_run'; }
        };
    }
    if (!window.chrome.webstore) {
        window.chrome.webstore = {
            onInstallStageChanged: { addListener: function() {} },
            onDownloadProgress: { addListener: function() {} }
        };
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 6. Permissions API (full coverage, not just notifications)
// Detection: query('camera') etc. returns different in headless
// ─────────────────────────────────────────────────────────────────────────────

pub const PERMISSIONS_FULL_EVASION: &str = r#"
(() => {
    const origQuery = Permissions.prototype.query;
    Permissions.prototype.query = function(descriptor) {
        const name = descriptor.name || '';
        const promptPermissions = [
            'notifications', 'geolocation', 'camera', 'microphone',
            'clipboard-read', 'clipboard-write', 'payment-handler',
            'persistent-storage', 'midi', 'background-sync'
        ];
        if (promptPermissions.includes(name)) {
            return Promise.resolve({
                state: 'prompt',
                onchange: null,
                addEventListener: function() {},
                removeEventListener: function() {},
                dispatchEvent: function() { return true; }
            });
        }
        return origQuery.call(this, descriptor);
    };
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 7. speechSynthesis.getVoices() (empty in headless)
// Detection: if (getVoices().length === 0) → headless
// ─────────────────────────────────────────────────────────────────────────────

pub const SPEECH_SYNTHESIS_EVASION: &str = r#"
(() => {
    if (window.speechSynthesis) {
        const origGetVoices = speechSynthesis.getVoices.bind(speechSynthesis);
        speechSynthesis.getVoices = function() {
            const voices = origGetVoices();
            if (voices.length > 0) return voices;
            return [{
                default: true,
                lang: 'en-US',
                localService: true,
                name: 'Microsoft David - English (United States)',
                voiceURI: 'Microsoft David - English (United States)'
            }, {
                default: false,
                lang: 'en-US',
                localService: true,
                name: 'Microsoft Zira - English (United States)',
                voiceURI: 'Microsoft Zira - English (United States)'
            }];
        };
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 8. MediaDevices.enumerateDevices() (empty in headless)
// Detection: if (devices.length === 0) → headless
// ─────────────────────────────────────────────────────────────────────────────

pub const MEDIA_DEVICES_EVASION: &str = r#"
(() => {
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        const origEnum = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
        navigator.mediaDevices.enumerateDevices = function() {
            return origEnum().then(devices => {
                if (devices.length > 0) return devices;
                return [
                    { deviceId: 'default', groupId: 'g1', kind: 'audioinput', label: '' },
                    { deviceId: 'comms', groupId: 'g2', kind: 'audiooutput', label: '' },
                    { deviceId: 'default', groupId: 'g3', kind: 'videoinput', label: '' }
                ];
            });
        };
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 9. WebRTC leak prevention (critical for Tor)
// Detection: create RTCPeerConnection, harvest ICE candidates → real IP
// ─────────────────────────────────────────────────────────────────────────────

pub const WEBRTC_LEAK_PREVENTION: &str = r#"
(() => {
    // Block WebRTC from leaking real IP
    const origRTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (origRTC) {
        const handler = {
            construct(target, args) {
                const config = args[0] || {};
                // Force all ICE traffic through proxy by removing STUN servers
                config.iceServers = [];
                config.iceTransportPolicy = 'relay';
                return new target(config);
            }
        };
        window.RTCPeerConnection = new Proxy(origRTC, handler);
        if (window.webkitRTCPeerConnection) {
            window.webkitRTCPeerConnection = window.RTCPeerConnection;
        }
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 10. Battery API (spoof instead of delete)
// Detection: navigator.getBattery returning undefined looks suspicious
// ─────────────────────────────────────────────────────────────────────────────

pub const BATTERY_SPOOF_EVASION: &str = r#"
(() => {
    navigator.getBattery = function() {
        return Promise.resolve({
            charging: true,
            chargingTime: 0,
            dischargingTime: Infinity,
            level: 0.85 + Math.random() * 0.15,
            addEventListener: function() {},
            removeEventListener: function() {},
            dispatchEvent: function() { return true; },
            onchargingchange: null,
            onchargingtimechange: null,
            ondischargingtimechange: null,
            onlevelchange: null
        });
    };
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 11. Iframe contentWindow detection bypass
// Detection: checking if iframe.contentWindow.chrome exists
// ─────────────────────────────────────────────────────────────────────────────

pub const IFRAME_EVASION: &str = r#"
(() => {
    const origCreate = document.createElement.bind(document);
    document.createElement = function(tag) {
        const el = origCreate(tag);
        if (tag.toLowerCase() === 'iframe') {
            const origAppend = Element.prototype.appendChild;
            const origGet = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
            // Ensure chrome object exists in iframes too
            el.addEventListener('load', () => {
                try {
                    if (el.contentWindow && !el.contentWindow.chrome) {
                        el.contentWindow.chrome = window.chrome;
                    }
                } catch(e) {}
            }, { once: false });
        }
        return el;
    };
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 12. Client Hints generation (Sec-CH-UA headers)
// These must match the User-Agent for consistency
// ─────────────────────────────────────────────────────────────────────────────

pub fn client_hints_script(profile: &StealthProfile) -> String {
    // Extract Chrome version from UA
    let chrome_ver = profile.user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|s| s.split('.').next())
        .unwrap_or("151");

    let platform = if profile.platform.contains("Mac") {
        "macOS"
    } else if profile.platform.contains("Linux") {
        "Linux"
    } else {
        "Windows"
    };

    let mobile = if profile.max_touch_points > 0 { "true" } else { "false" };

    format!(
        r#"
(() => {{
    // Override navigator.userAgentData (Client Hints JS API)
    if (!navigator.userAgentData || navigator.userAgentData.brands.length === 0) {{
        const uaData = {{
            brands: [
                {{ brand: "Google Chrome", version: "{chrome_ver}" }},
                {{ brand: "Chromium", version: "{chrome_ver}" }},
                {{ brand: "Not_A Brand", version: "24" }}
            ],
            mobile: {mobile},
            platform: "{platform}",
            getHighEntropyValues: function(hints) {{
                return Promise.resolve({{
                    architecture: "x86",
                    bitness: "64",
                    brands: this.brands,
                    fullVersionList: [
                        {{ brand: "Google Chrome", version: "{chrome_ver}.0.0.0" }},
                        {{ brand: "Chromium", version: "{chrome_ver}.0.0.0" }},
                        {{ brand: "Not_A Brand", version: "24.0.0.0" }}
                    ],
                    mobile: this.mobile,
                    model: "",
                    platform: this.platform,
                    platformVersion: "10.0.0",
                    uaFullVersion: "{chrome_ver}.0.0.0",
                    wow64: false
                }});
            }},
            toJSON: function() {{
                return {{ brands: this.brands, mobile: this.mobile, platform: this.platform }};
            }}
        }};
        Object.defineProperty(navigator, 'userAgentData', {{
            get: () => uaData,
            configurable: true
        }});
    }}
}})();
"#
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. Intl.DateTimeFormat timezone consistency
// Detection: Intl timezone must match Emulation.setTimezoneOverride
// ─────────────────────────────────────────────────────────────────────────────

pub fn timezone_consistency_script(profile: &StealthProfile) -> String {
    let tz = &profile.timezone;
    format!(
        r#"
(() => {{
    // Ensure Intl.DateTimeFormat resolves to the correct timezone
    const origDTF = Intl.DateTimeFormat;
    Intl.DateTimeFormat = function(locale, options) {{
        if (!options || !options.timeZone) {{
            options = Object.assign({{}}, options, {{ timeZone: '{tz}' }});
        }}
        return new origDTF(locale, options);
    }};
    Intl.DateTimeFormat.prototype = origDTF.prototype;
    Intl.DateTimeFormat.supportedLocalesOf = origDTF.supportedLocalesOf;

    // Also patch Date.prototype.getTimezoneOffset for consistency
    // This is the offset in minutes from UTC
    const tzOffsets = {{
        'America/New_York': 300,    // UTC-5 (EST) / 240 (EDT)
        'America/Chicago': 360,      // UTC-6 (CST)
        'America/Los_Angeles': 480,  // UTC-8 (PST)
        'UTC': 0,
        'Europe/London': 0,
        'Europe/Berlin': -60,
        'Asia/Tokyo': -540,
    }};
    const expectedOffset = tzOffsets['{tz}'];
    if (expectedOffset !== undefined) {{
        Date.prototype.getTimezoneOffset = function() {{ return expectedOffset; }};
    }}
}})();
"#
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. AudioContext fingerprint spoofing
// Detection: create OfflineAudioContext, run oscillator through compressor,
// read back float samples — the output uniquely identifies hardware/driver.
// Used by 10K+ sites (FingerprintJS, CreepJS, etc.)
// ─────────────────────────────────────────────────────────────────────────────

pub fn audio_context_evasion_script(profile: &StealthProfile) -> String {
    let seed = profile.canvas_noise_seed;
    format!(
        r#"
(() => {{
    // STABLE-PER-READ noise: every noise value is a PURE function of the
    // (per-profile seed, input index/value) — never drawn from a shared RNG
    // that advances across renders. Rendering an equivalent context twice
    // therefore yields IDENTICAL perturbed samples (a stateful stream that
    // changes the output on every read is a detector tell).
    const __tallowAudioSeed = {seed};

    // FNV-1a-style mix of the seed + positional keys -> 32-bit. Deterministic.
    function __tallowHash(seed, a, b) {{
        let h = ((seed >>> 0) ^ 0x811c9dc5);
        h = Math.imul(h ^ a, 0x01000193);
        if (b !== undefined) h = Math.imul(h ^ b, 0x01000193);
        return h >>> 0;
    }}

    // Pure PRNG seeded from a 32-bit value; same seed -> same stream.
    function __tallowMulberry32(a) {{
        return function() {{
            a |= 0; a = a + 0x6D2B79F5 | 0;
            let t = Math.imul(a ^ a >>> 15, 1 | a);
            t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
            return ((t ^ t >>> 14) >>> 0) / 4294967296;
        }};
    }}

    // Magnitude ~1e-7 so it alters the fingerprint hash but is inaudible.
    function __tallowNoiseFor(seed, a, b) {{
        return (__tallowMulberry32(__tallowHash(seed, a, b))() - 0.5) * 1e-7;
    }}

    // --- 14a. OfflineAudioContext.startRendering ---
    // Intercept the rendered AudioBuffer and perturb its samples. Each sample
    // is keyed on (seed, channel, index) so re-rendering is byte-identical.
    const origStartRendering = OfflineAudioContext.prototype.startRendering;
    OfflineAudioContext.prototype.startRendering = function() {{
        return origStartRendering.call(this).then(function(buffer) {{
            for (let ch = 0; ch < buffer.numberOfChannels; ch++) {{
                const data = buffer.getChannelData(ch);
                for (let i = 0; i < data.length; i++) {{
                    data[i] += __tallowNoiseFor(__tallowAudioSeed, ch, i);
                }}
            }}
            return buffer;
        }});
    }};

    // --- 14b. AudioContext.createOscillator frequency jitter ---
    const origCreateOscillator = BaseAudioContext.prototype.createOscillator;
    BaseAudioContext.prototype.createOscillator = function() {{
        const osc = origCreateOscillator.call(this);
        const origFreqValue = Object.getOwnPropertyDescriptor(
            AudioParam.prototype, 'value'
        );
        if (origFreqValue && origFreqValue.set) {{
            const origSet = origFreqValue.set;
            // Patch only this oscillator's frequency param
            Object.defineProperty(osc.frequency, 'value', {{
                get: origFreqValue.get,
                set: function(v) {{
                    // Deterministic jitter keyed on the requested value: ~0.001%.
                    // Re-setting the SAME frequency yields the SAME jitter.
                    const jitter = (__tallowMulberry32(
                        __tallowHash(__tallowAudioSeed, 0, Math.round(v * 1000))
                    )() - 0.5) * v * 1e-5;
                    origSet.call(this, v + jitter);
                }},
                configurable: true
            }});
        }}
        return osc;
    }};

    // --- 14c. AnalyserNode data noise ---
    const origGetFloat = AnalyserNode.prototype.getFloatFrequencyData;
    AnalyserNode.prototype.getFloatFrequencyData = function(array) {{
        origGetFloat.call(this, array);
        for (let i = 0; i < array.length; i++) {{
            array[i] += __tallowNoiseFor(__tallowAudioSeed, 1, i);
        }}
    }};

    const origGetByte = AnalyserNode.prototype.getByteFrequencyData;
    AnalyserNode.prototype.getByteFrequencyData = function(array) {{
        origGetByte.call(this, array);
        for (let i = 0; i < array.length; i++) {{
            // Byte data is 0-255; jitter by +/-1 occasionally. Keyed on
            // (seed, index) so repeated reads of the same data are identical.
            const r = __tallowMulberry32(__tallowHash(__tallowAudioSeed, 2, i))();
            const jitter = (r < 0.15) ? ((__tallowMulberry32(
                __tallowHash(__tallowAudioSeed, 3, i)
            )() < 0.5) ? -1 : 1) : 0;
            array[i] = Math.max(0, Math.min(255, array[i] + jitter));
        }}
    }};
}})();
"#
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. WebGPU fingerprint spoofing
// Detection: WebGPU adapter info leaks real GPU; inconsistency with WebGL = bot
// ─────────────────────────────────────────────────────────────────────────────

pub fn webgpu_evasion_script(profile: &StealthProfile) -> String {
    // Derive WebGPU vendor/architecture from the WebGL renderer for consistency.
    // WebGL renderer examples:
    //   "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"
    //   "ANGLE (Apple, Apple M2, OpenGL 4.1)"
    //   "ANGLE (Intel, Mesa Intel(R) UHD Graphics 630, OpenGL 4.6)"
    //   "Apple GPU"
    //   "Adreno (TM) 740"
    let renderer = &profile.webgl_renderer;

    let (gpu_vendor, gpu_arch, gpu_device, gpu_desc) =
        if renderer.contains("NVIDIA") {
            ("nvidia", "ampere", "NVIDIA GeForce RTX 3060", renderer.as_str())
        } else if renderer.contains("Apple") {
            ("apple", "common-3", "Apple M2 GPU", renderer.as_str())
        } else if renderer.contains("Intel") {
            ("intel", "gen-12lp", "Intel UHD Graphics 630", renderer.as_str())
        } else if renderer.contains("Adreno") {
            ("qualcomm", "adreno-7xx", "Adreno (TM) 740", renderer.as_str())
        } else {
            ("unknown", "unknown", "Generic GPU", renderer.as_str())
        };

    format!(
        r#"
(() => {{
    // If WebGPU is not natively available, leave navigator.gpu undefined
    // to avoid leaking a half-spoofed API surface.
    if (typeof navigator.gpu === 'undefined') return;

    const realRequestAdapter = navigator.gpu.requestAdapter.bind(navigator.gpu);

    navigator.gpu.requestAdapter = function(options) {{
        return realRequestAdapter(options).then(adapter => {{
            if (!adapter) return adapter;

            // Spoof requestAdapterInfo to match WebGL renderer
            const origRequestAdapterInfo = adapter.requestAdapterInfo
                ? adapter.requestAdapterInfo.bind(adapter)
                : null;

            const spoofedInfo = {{
                vendor: '{gpu_vendor}',
                architecture: '{gpu_arch}',
                device: '{gpu_device}',
                description: '{gpu_desc}'
            }};

            // Override requestAdapterInfo()
            if (origRequestAdapterInfo) {{
                adapter.requestAdapterInfo = function() {{
                    return Promise.resolve(spoofedInfo);
                }};
            }}

            // Also spoof the info property (newer Chrome exposes GPUAdapterInfo directly)
            try {{
                Object.defineProperty(adapter, 'info', {{
                    get: () => spoofedInfo,
                    configurable: true
                }});
            }} catch(e) {{}}

            return adapter;
        }});
    }};
}})();
"#,
        gpu_vendor = gpu_vendor.replace('\'', "\\'"),
        gpu_arch = gpu_arch.replace('\'', "\\'"),
        gpu_device = gpu_device.replace('\'', "\\'"),
        gpu_desc = gpu_desc.replace('\'', "\\'"),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. Font enumeration fingerprint spoofing
// Detection: measure many fonts via offsetWidth/getBoundingClientRect to
//            identify installed fonts — unique set = unique fingerprint
// ─────────────────────────────────────────────────────────────────────────────

pub fn font_enumeration_evasion_script(profile: &StealthProfile) -> String {
    // OS-appropriate font list. Fingerprinters check for the presence/absence
    // of OS-specific fonts. We return a consistent, plausible set.
    let font_list = if profile.platform.contains("Win") {
        r#"[
            'Arial', 'Arial Black', 'Calibri', 'Cambria', 'Cambria Math',
            'Candara', 'Comic Sans MS', 'Consolas', 'Constantia', 'Corbel',
            'Courier New', 'Georgia', 'Impact', 'Lucida Console',
            'Lucida Sans Unicode', 'Microsoft Sans Serif', 'Palatino Linotype',
            'Segoe Print', 'Segoe Script', 'Segoe UI', 'Segoe UI Symbol',
            'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana', 'Wingdings',
            'Webdings', 'Symbol', 'MS Gothic', 'MS PGothic', 'MS UI Gothic',
            'Malgun Gothic', 'Yu Gothic', 'Meiryo'
        ]"#
    } else if profile.platform.contains("Mac") || profile.platform.contains("iPhone") {
        r#"[
            'Arial', 'Arial Black', 'Avenir', 'Avenir Next', 'Baskerville',
            'Cochin', 'Courier New', 'Didot', 'Futura', 'Geneva',
            'Georgia', 'Gill Sans', 'Helvetica', 'Helvetica Neue',
            'Hoefler Text', 'Impact', 'Lucida Grande', 'Menlo', 'Monaco',
            'Optima', 'Palatino', 'SF Pro Display', 'SF Pro Text',
            'San Francisco', 'Times New Roman', 'Trebuchet MS', 'Verdana',
            'Apple Color Emoji', 'Apple SD Gothic Neo', 'Hiragino Sans',
            'Hiragino Kaku Gothic ProN'
        ]"#
    } else {
        // Linux / Android
        r#"[
            'Arial', 'Courier New', 'DejaVu Sans', 'DejaVu Sans Mono',
            'DejaVu Serif', 'Droid Sans', 'Droid Sans Mono', 'FreeMono',
            'FreeSans', 'FreeSerif', 'Georgia', 'Liberation Mono',
            'Liberation Sans', 'Liberation Serif', 'Noto Sans',
            'Noto Serif', 'Roboto', 'Times New Roman', 'Ubuntu',
            'Ubuntu Mono', 'Verdana', 'Noto Color Emoji',
            'Noto Sans CJK JP', 'Noto Sans CJK SC'
        ]"#
    };

    format!(
        r#"
(() => {{
    const ALLOWED_FONTS = new Set({font_list});

    // --- 16a. Intercept document.fonts.check() ---
    // Fingerprinters call check('12px FontName') for hundreds of fonts.
    // We return true only for our allowed set.
    if (document.fonts && document.fonts.check) {{
        const origCheck = document.fonts.check.bind(document.fonts);
        document.fonts.check = function(font, text) {{
            // Extract font family from CSS font shorthand like "12px Arial"
            // or "bold 16px 'Comic Sans MS'"
            const match = font.match(/(?:^|\s)['"]?([^'",]+)['"]?\s*$/);
            if (match) {{
                const family = match[1].trim();
                if (!ALLOWED_FONTS.has(family)) {{
                    return false;
                }}
            }}
            return origCheck(font, text);
        }};
    }}

    // --- 16b. Noise on text measurement APIs for font detection patterns ---
    // Fingerprinters rapidly measure many fonts. We detect this pattern
    // (high call frequency) and add sub-pixel noise to defeat comparison.
    let measureCallCount = 0;
    let measureWindowStart = performance.now();
    const RAPID_THRESHOLD = 20; // calls within 100ms = fingerprinting
    const NOISE_WINDOW_MS = 100;

    function isRapidMeasurement() {{
        const now = performance.now();
        if (now - measureWindowStart > NOISE_WINDOW_MS) {{
            measureCallCount = 0;
            measureWindowStart = now;
        }}
        measureCallCount++;
        return measureCallCount > RAPID_THRESHOLD;
    }}

    // Deterministic noise from a seed so measurements are stable within a page
    // load but differ across sessions. Uses a simple xorshift.
    let noiseSeed = (Date.now() ^ 0x5DEECE66D) & 0xFFFFFFFF;
    function nextNoise() {{
        noiseSeed ^= noiseSeed << 13;
        noiseSeed ^= noiseSeed >> 17;
        noiseSeed ^= noiseSeed << 5;
        noiseSeed = noiseSeed & 0xFFFFFFFF;
        // Return noise in range [-0.25, +0.25] pixels — sub-pixel, unnoticeable
        return ((noiseSeed & 0xFFFF) / 0xFFFF - 0.5) * 0.5;
    }}

    // --- offsetWidth / offsetHeight ---
    const origOffsetWidthDesc = Object.getOwnPropertyDescriptor(
        HTMLElement.prototype, 'offsetWidth'
    );
    const origOffsetHeightDesc = Object.getOwnPropertyDescriptor(
        HTMLElement.prototype, 'offsetHeight'
    );

    if (origOffsetWidthDesc && origOffsetWidthDesc.get) {{
        Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {{
            get: function() {{
                const val = origOffsetWidthDesc.get.call(this);
                if (isRapidMeasurement()) {{
                    return val + Math.round(nextNoise());
                }}
                return val;
            }},
            configurable: true
        }});
    }}

    if (origOffsetHeightDesc && origOffsetHeightDesc.get) {{
        Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {{
            get: function() {{
                const val = origOffsetHeightDesc.get.call(this);
                if (isRapidMeasurement()) {{
                    return val + Math.round(nextNoise());
                }}
                return val;
            }},
            configurable: true
        }});
    }}

    // --- getBoundingClientRect ---
    const origGetBCR = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = function() {{
        const rect = origGetBCR.call(this);
        if (isRapidMeasurement()) {{
            const n = nextNoise();
            return new DOMRect(rect.x, rect.y, rect.width + n, rect.height + n);
        }}
        return rect;
    }};
}})();
"#,
        font_list = font_list,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Combined V2 injection — all 16 evasions as one script
// ─────────────────────────────────────────────────────────────────────────────

/// Generate the combined V2 stealth script for a given profile.
/// Should be injected AFTER V1 stealth scripts.
///
/// When `evasions` is `Some`, each vector section is gated by the matching
/// `StealthEvasions` toggle. `None` (or an all-default config) includes every
/// vector — the historical behavior.
pub fn stealth_v2_script(
    profile: &StealthProfile,
    evasions: Option<&StealthEvasions>,
) -> String {
    let is_ff = profile.is_firefox_profile;
    // Per-vector gates; default = every vector enabled.
    let ev = evasions.cloned().unwrap_or_default();
    let mut script = String::with_capacity(16384);
    script.push_str("// ═══ Tallow Stealth V2 — Anti-Detection Engine ═══\n");
    script.push_str("(function() { 'use strict';\n");

    // 1. navigator.connection — Chrome-only API (Firefox does not expose it)
    if !is_ff && ev.connection {
        script.push_str(CONNECTION_EVASION);
    }
    // 2. Screen dimensions + outerWidth/Height (shared)
    if ev.screen_dimensions {
        script.push_str(&screen_dimensions_script(profile));
    }
    // 3. performance.memory — Chrome-only API (Firefox never has it)
    if !is_ff && ev.performance_memory {
        script.push_str(PERFORMANCE_MEMORY_EVASION);
    }
    // 4. performance.now() timing noise (shared)
    if ev.performance_timing {
        script.push_str(PERFORMANCE_TIMING_EVASION);
    }
    // 5. chrome.app + chrome.webstore — Chrome only (window.chrome absent in Firefox)
    if !is_ff && ev.chrome_extended {
        script.push_str(CHROME_EXTENDED_EVASION);
    }
    // 6. Permissions API full coverage (shared)
    if ev.permissions {
        script.push_str(PERMISSIONS_FULL_EVASION);
    }
    // 7. speechSynthesis voices (shared)
    if ev.speech_synthesis {
        script.push_str(SPEECH_SYNTHESIS_EVASION);
    }
    // 8. MediaDevices (shared)
    if ev.media_devices {
        script.push_str(MEDIA_DEVICES_EVASION);
    }
    // 9. WebRTC leak prevention (shared — critical for Tor)
    if ev.webrtc {
        script.push_str(WEBRTC_LEAK_PREVENTION);
    }
    // 10. Battery API spoof (shared)
    if ev.battery {
        script.push_str(BATTERY_SPOOF_EVASION);
    }
    // 11. Iframe contentWindow — Chrome only (injects window.chrome into iframes)
    if !is_ff && ev.iframe {
        script.push_str(IFRAME_EVASION);
    }
    // 12. Client Hints (Sec-CH-UA) — Chrome only (Firefox does not support CH)
    if !is_ff && ev.client_hints {
        script.push_str(&client_hints_script(profile));
    }
    // 13. Timezone consistency (shared)
    if ev.timezone {
        script.push_str(&timezone_consistency_script(profile));
    }
    // 14. AudioContext fingerprint spoofing (shared)
    if ev.audio_context {
        script.push_str(&audio_context_evasion_script(profile));
    }
    // 15. WebGPU fingerprint spoofing (shared — guards on navigator.gpu existence)
    if ev.webgpu {
        script.push_str(&webgpu_evasion_script(profile));
    }
    // 16. Font enumeration fingerprint spoofing (shared)
    if ev.fonts {
        script.push_str(&font_enumeration_evasion_script(profile));
    }

    script.push_str("})();\n");
    script
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stealth_v2_contains_all_evasions() {
        let p = StealthProfile::chrome_windows();
        let script = stealth_v2_script(&p, None);
        assert!(script.contains("navigator.connection"));
        assert!(script.contains("outerWidth"));
        assert!(script.contains("outerHeight"));
        assert!(script.contains("performance.memory"));
        assert!(script.contains("performance.now"));
        assert!(script.contains("chrome.app"));
        assert!(script.contains("chrome.webstore"));
        assert!(script.contains("Permissions.prototype.query"));
        assert!(script.contains("speechSynthesis"));
        assert!(script.contains("enumerateDevices"));
        assert!(script.contains("RTCPeerConnection"));
        assert!(script.contains("getBattery"));
        assert!(script.contains("userAgentData"));
        assert!(script.contains("getTimezoneOffset"));
        assert!(script.contains("OfflineAudioContext"));
        assert!(script.contains("getFloatFrequencyData"));
        assert!(script.contains("navigator.gpu"));
        assert!(script.contains("requestAdapter"));
        assert!(script.contains("requestAdapterInfo"));
        assert!(script.contains("document.fonts"));
        assert!(script.contains("ALLOWED_FONTS"));
        assert!(script.contains("offsetWidth"));
        assert!(script.contains("getBoundingClientRect"));
    }

    #[test]
    fn stealth_v2_evasions_gate_respected() {
        use super::super::config::stealth_conf::StealthEvasions;
        let p = StealthProfile::chrome_windows();

        // All disabled → no vector sections present (just the wrapper).
        let mut all_off = StealthEvasions::default();
        all_off.webdriver = false;
        all_off.chrome_runtime = false;
        all_off.plugins_spoof = false;
        all_off.languages = false;
        all_off.canvas = false;
        all_off.webgl = false;
        all_off.navigator = false;
        all_off.connection = false;
        all_off.screen_dimensions = false;
        all_off.performance_memory = false;
        all_off.performance_timing = false;
        all_off.chrome_extended = false;
        all_off.permissions = false;
        all_off.speech_synthesis = false;
        all_off.media_devices = false;
        all_off.webrtc = false;
        all_off.battery = false;
        all_off.iframe = false;
        all_off.client_hints = false;
        all_off.timezone = false;
        all_off.audio_context = false;
        all_off.webgpu = false;
        all_off.fonts = false;
        let empty_script = stealth_v2_script(&p, Some(&all_off));
        assert!(!empty_script.contains("navigator.connection"));
        assert!(!empty_script.contains("outerWidth"));
        assert!(!empty_script.contains("performance.memory"));
        assert!(!empty_script.contains("RTCPeerConnection"));
        assert!(!empty_script.contains("getBattery"));
        assert!(!empty_script.contains("OfflineAudioContext"));
        assert!(!empty_script.contains("navigator.gpu"));
        assert!(!empty_script.contains("document.fonts"));

        // Selectively disable one vector → only that section disappears.
        let mut no_webrtc = StealthEvasions::default();
        no_webrtc.webrtc = false;
        let script = stealth_v2_script(&p, Some(&no_webrtc));
        assert!(!script.contains("RTCPeerConnection"), "webrtc=off must drop WebRTC patch");
        assert!(script.contains("navigator.connection"), "other vectors stay");
        assert!(script.contains("getBattery"), "other vectors stay");
    }

    #[test]
    fn stealth_v2_default_config_matches_none() {
        let p = StealthProfile::chrome_windows();
        let default_evasions = StealthEvasions::default();
        let with_default = stealth_v2_script(&p, Some(&default_evasions));
        let with_none = stealth_v2_script(&p, None);
        assert_eq!(with_default, with_none);
    }

    #[test]
    fn screen_dimensions_match_viewport() {
        let p = StealthProfile::chrome_windows();
        let script = screen_dimensions_script(&p);
        assert!(script.contains("1920")); // viewport width
        assert!(script.contains("1080")); // viewport height
        assert!(script.contains("1936")); // outerWidth = 1920 + 16
    }

    #[test]
    fn client_hints_extracts_chrome_version() {
        let p = StealthProfile::chrome_windows();
        let script = client_hints_script(&p);
        assert!(script.contains("151")); // Chrome version from UA (FIX11 updated profiles to Chrome 151)
        assert!(script.contains("Windows")); // Platform
    }

    #[test]
    fn timezone_consistency_has_offset() {
        let p = StealthProfile::chrome_windows();
        let script = timezone_consistency_script(&p);
        assert!(script.contains("America/New_York"));
        assert!(script.contains("getTimezoneOffset"));
    }

    #[test]
    fn webrtc_forces_relay_only() {
        assert!(WEBRTC_LEAK_PREVENTION.contains("iceTransportPolicy"));
        assert!(WEBRTC_LEAK_PREVENTION.contains("relay"));
        assert!(WEBRTC_LEAK_PREVENTION.contains("iceServers"));
    }

    #[test]
    fn battery_returns_promise_not_undefined() {
        assert!(BATTERY_SPOOF_EVASION.contains("Promise.resolve"));
        assert!(BATTERY_SPOOF_EVASION.contains("charging: true"));
        assert!(BATTERY_SPOOF_EVASION.contains("level:"));
    }

    #[test]
    fn audio_context_evasion_has_all_overrides() {
        let p = StealthProfile::chrome_windows();
        let script = audio_context_evasion_script(&p);
        // Uses canvas_noise_seed as the deterministic seed
        assert!(script.contains(&p.canvas_noise_seed.to_string()));
        // Overrides OfflineAudioContext.startRendering
        assert!(script.contains("OfflineAudioContext.prototype.startRendering"));
        // Overrides createOscillator with frequency jitter
        assert!(script.contains("createOscillator"));
        assert!(script.contains("osc.frequency"));
        // Overrides AnalyserNode data methods
        assert!(script.contains("getFloatFrequencyData"));
        assert!(script.contains("getByteFrequencyData"));
        // Uses deterministic PRNG
        assert!(script.contains("__tallowMulberry32"));
    }

    #[test]
    fn audio_context_seed_differs_per_profile() {
        let p1 = StealthProfile::chrome_windows();
        let mut p2 = StealthProfile::chrome_windows();
        p2.canvas_noise_seed = 999_999;
        let s1 = audio_context_evasion_script(&p1);
        let s2 = audio_context_evasion_script(&p2);
        assert_ne!(s1, s2);
        assert!(s2.contains("999999"));
    }

    #[test]
    fn audio_noise_is_stable_per_read() {
        // Rendering an equivalent context twice must produce IDENTICAL samples.
        // Every noise value is a pure function of (per-profile seed, index/value)
        // via __tallowHash + __tallowMulberry32 — never drawn from a shared RNG
        // that advances across renders. Assert the script keys noise on the seed
        // and a positional key (channel/index/value), and no longer keeps a
        // single stateful `__tallowRng` stream advanced per call.
        let p = StealthProfile::chrome_windows();
        let script = audio_context_evasion_script(&p);
        assert!(
            script.contains("__tallowNoiseFor(__tallowAudioSeed, ch, i)"),
            "audio samples must be keyed on (seed, channel, index)"
        );
        assert!(
            script.contains("__tallowNoiseFor(__tallowAudioSeed, 1, i)"),
            "getFloatFrequencyData noise must be keyed on (seed, index)"
        );
        assert!(
            !script.contains("const __tallowRng"),
            "must not keep a single stateful RNG stream advanced per read"
        );
    }

    #[test]
    fn webgpu_evasion_matches_webgl_renderer() {
        // Windows/NVIDIA profile
        let p = StealthProfile::chrome_windows();
        let script = webgpu_evasion_script(&p);
        assert!(script.contains("navigator.gpu"), "should guard on navigator.gpu existence");
        assert!(script.contains("requestAdapter"));
        assert!(script.contains("requestAdapterInfo"));
        assert!(script.contains("nvidia"), "vendor should match NVIDIA WebGL renderer");
        assert!(script.contains("ampere"), "architecture should match NVIDIA Ampere");
        assert!(script.contains("NVIDIA GeForce RTX 3060"));
        // Adapter info property spoof
        assert!(script.contains("adapter, 'info'"));

        // macOS/Apple profile
        let p_mac = StealthProfile::chrome_macos();
        let script_mac = webgpu_evasion_script(&p_mac);
        assert!(script_mac.contains("apple"), "vendor should match Apple WebGL renderer");
        assert!(script_mac.contains("common-3"), "architecture should match Apple GPU family");
        assert!(script_mac.contains("Apple M2 GPU"));

        // Linux/Intel profile
        let p_linux = StealthProfile::chrome_linux();
        let script_linux = webgpu_evasion_script(&p_linux);
        assert!(script_linux.contains("intel"));
        assert!(script_linux.contains("gen-12lp"));
    }

    #[test]
    fn webgpu_evasion_skips_when_gpu_undefined() {
        let p = StealthProfile::chrome_windows();
        let script = webgpu_evasion_script(&p);
        // Must bail early if navigator.gpu is undefined — never inject a half-spoofed API
        assert!(script.contains("typeof navigator.gpu === 'undefined'"));
        assert!(script.contains("return"));
    }

    #[test]
    fn font_evasion_windows_fonts() {
        let p = StealthProfile::chrome_windows();
        let script = font_enumeration_evasion_script(&p);
        assert!(script.contains("Segoe UI"), "Windows profile should have Segoe UI");
        assert!(script.contains("Calibri"), "Windows profile should have Calibri");
        assert!(script.contains("Consolas"), "Windows profile should have Consolas");
        assert!(!script.contains("Helvetica Neue"), "Windows profile should NOT have macOS fonts");
        assert!(!script.contains("DejaVu Sans"), "Windows profile should NOT have Linux fonts");
    }

    #[test]
    fn font_evasion_macos_fonts() {
        let p = StealthProfile::chrome_macos();
        let script = font_enumeration_evasion_script(&p);
        assert!(script.contains("Helvetica Neue"), "macOS profile should have Helvetica Neue");
        assert!(script.contains("SF Pro Display"), "macOS profile should have SF Pro");
        assert!(script.contains("Menlo"), "macOS profile should have Menlo");
        assert!(!script.contains("Segoe UI"), "macOS profile should NOT have Windows fonts");
    }

    #[test]
    fn font_evasion_linux_fonts() {
        let p = StealthProfile::chrome_linux();
        let script = font_enumeration_evasion_script(&p);
        assert!(script.contains("DejaVu Sans"), "Linux profile should have DejaVu Sans");
        assert!(script.contains("Liberation Sans"), "Linux profile should have Liberation Sans");
        assert!(script.contains("Noto Sans"), "Linux profile should have Noto Sans");
        assert!(!script.contains("Segoe UI"), "Linux profile should NOT have Windows fonts");
    }

    #[test]
    fn font_evasion_has_measurement_noise() {
        let p = StealthProfile::chrome_windows();
        let script = font_enumeration_evasion_script(&p);
        assert!(script.contains("document.fonts.check"), "should intercept fonts.check");
        assert!(script.contains("ALLOWED_FONTS"), "should use allowlist");
        assert!(script.contains("isRapidMeasurement"), "should detect rapid measurement pattern");
        assert!(script.contains("offsetWidth"), "should add noise to offsetWidth");
        assert!(script.contains("offsetHeight"), "should add noise to offsetHeight");
        assert!(script.contains("getBoundingClientRect"), "should add noise to getBCR");
        assert!(script.contains("DOMRect"), "should return noised DOMRect");
    }

    #[test]
    fn font_evasion_ios_uses_mac_fonts() {
        let p = StealthProfile::mobile_ios();
        let script = font_enumeration_evasion_script(&p);
        // iPhone platform should use macOS font list (Apple ecosystem)
        assert!(script.contains("Helvetica Neue"), "iOS should use macOS font list");
        assert!(script.contains("SF Pro Display"));
    }

    #[test]
    fn connection_has_4g() {
        assert!(CONNECTION_EVASION.contains("effectiveType"));
        assert!(CONNECTION_EVASION.contains("4g"));
        assert!(CONNECTION_EVASION.contains("downlink"));
    }

    #[test]
    fn firefox_profile_skips_chrome_evasions() {
        let p = crate::browser::tor_stealth::tor_browser_profile();
        assert!(p.is_firefox_profile);
        let script = stealth_v2_script(&p, None);
        // Chrome-only evasions should be absent
        assert!(!script.contains("chrome.app"), "Firefox profile must not inject chrome.app");
        assert!(!script.contains("chrome.webstore"), "Firefox profile must not inject chrome.webstore");
        assert!(!script.contains("navigator.connection"), "Firefox profile must not inject navigator.connection");
        assert!(!script.contains("performance.memory"), "Firefox profile must not inject performance.memory");
        assert!(!script.contains("userAgentData"), "Firefox profile must not inject Client Hints");
        assert!(!script.contains("contentWindow.chrome"), "Firefox profile must not inject chrome into iframes");
        // Shared evasions should still be present
        assert!(script.contains("outerWidth"), "Firefox profile should have screen dimensions");
        assert!(script.contains("RTCPeerConnection"), "Firefox profile should have WebRTC prevention");
        assert!(script.contains("getBattery"), "Firefox profile should have battery spoof");
        assert!(script.contains("getTimezoneOffset"), "Firefox profile should have timezone consistency");
        assert!(script.contains("OfflineAudioContext"), "Firefox profile should have audio evasion");
    }
}
