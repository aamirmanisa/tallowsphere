//! Stealth V3 — advanced anti-detection evasions for DataDome, FingerprintJS, and CreepJS.
//!
//! Addresses detection vectors that V1 and V2 miss:
//! 1. Function.prototype.toString cloaking (all patched functions look native)
//! 2. document.hasFocus() override (headless returns false)
//! 3. Error.stack leak prevention (sanitize CDP/puppeteer frames)
//! 4. performance.getEntries() filtering (hide injected script resources)
//! 5. Proxy/Reflect detection bypass (Symbol.toStringTag, getOwnPropertyDescriptor)
//! 6. SharedArrayBuffer timing defense (add noise to timing channels)
//! 7. Notification.permission override (headless returns "denied")
//! 8. Chrome CDP leak patches ($cdc_ properties, $chrome_asyncScriptInfo)
//!
//! Injected AFTER V1 and V2 scripts via `Page.addScriptToEvaluateOnNewDocument`.

use super::stealth::StealthProfile;

/// A named stealth patch: name for diagnostics, JS code to inject.
#[derive(Debug, Clone)]
pub struct StealthPatch {
    pub name: &'static str,
    pub js: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Function.prototype.toString Cloaking
// Detection: fingerprinters call toString() on patched functions; if the
// result is not "function name() { [native code] }" the override is detected.
// This MUST be injected first so all subsequent patches can use makeNative().
// ─────────────────────────────────────────────────────────────────────────────

pub const FUNCTION_TOSTRING_CLOAKING: &str = r#"
(() => {
    // Store the real toString before we touch anything.
    const _realToString = Function.prototype.toString;
    // WeakMap: patched function -> name to report as native.
    const _nativeNames = new WeakMap();

    // The replacement toString: if the function was registered via
    // makeNative(), return the faked native string; otherwise delegate
    // to the real toString.
    const _patchedToString = function toString() {
        if (_nativeNames.has(this)) {
            return 'function ' + _nativeNames.get(this) + '() { [native code] }';
        }
        return _realToString.call(this);
    };

    // Make toString itself look native.
    _nativeNames.set(_patchedToString, 'toString');

    // Apply the override.
    Function.prototype.toString = _patchedToString;

    // Also handle Reflect.apply(Function.prototype.toString, fn, [])
    // Since we replaced Function.prototype.toString, Reflect.apply will
    // naturally call our version. No extra patching needed.

    // Expose makeNative on the window so subsequent stealth scripts can use it.
    // We hide it from enumeration so fingerprinters cannot discover it.
    Object.defineProperty(window, '__tallowMakeNative', {
        value: function(fn, name) {
            _nativeNames.set(fn, name || fn.name || '');
        },
        writable: false,
        enumerable: false,
        configurable: false
    });

    // Retroactively cloak toString itself.
    window.__tallowMakeNative(Function.prototype.toString, 'toString');
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 2. document.hasFocus() Override
// Detection: headless Chrome returns false for document.hasFocus().
// Real browsers with the tab focused return true.
// ─────────────────────────────────────────────────────────────────────────────

pub const DOCUMENT_HAS_FOCUS_EVASION: &str = r#"
(() => {
    const origHasFocus = Document.prototype.hasFocus;
    Document.prototype.hasFocus = function() {
        return true;
    };
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Document.prototype.hasFocus, 'hasFocus');
    }

    // Also patch document.visibilityState and document.hidden for consistency.
    Object.defineProperty(document, 'visibilityState', {
        get: () => 'visible',
        configurable: true
    });
    Object.defineProperty(document, 'hidden', {
        get: () => false,
        configurable: true
    });
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 3. Error.stack Leak Prevention
// Detection: throw an error and inspect the stack trace for telltale
// injected script filenames like "__puppeteer_evaluation_script__",
// "pptr:evaluate", CDP evaluate contexts, or "tallow-stealth".
// ─────────────────────────────────────────────────────────────────────────────

pub const ERROR_STACK_SANITIZATION: &str = r#"
(() => {
    // Patterns that indicate injected/automated scripts.
    const SUSPICIOUS_PATTERNS = [
        '__puppeteer_evaluation_script__',
        'pptr:evaluate',
        'puppeteer',
        '__playwright',
        'playwright',
        'tallow-stealth',
        '__selenium_evaluate',
        'selenium',
        '__driver_evaluate',
        '__webdriver_evaluate',
        '__fxdriver_evaluate',
        'cdp_evaluation',
        'Runtime.evaluate',
        'debugger eval code',
        'injectedScript',
        'chrome-extension://',
        'moz-extension://'
    ];

    const SUSPICIOUS_RE = new RegExp(
        SUSPICIOUS_PATTERNS.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
        'i'
    );

    function sanitizeStack(stack) {
        if (typeof stack !== 'string') return stack;
        return stack
            .split('\n')
            .filter(line => !SUSPICIOUS_RE.test(line))
            .join('\n');
    }

    // Override the stack getter on Error.prototype.
    const origStackDesc = Object.getOwnPropertyDescriptor(Error.prototype, 'stack');
    if (origStackDesc) {
        Object.defineProperty(Error.prototype, 'stack', {
            get: function() {
                const val = origStackDesc.get ? origStackDesc.get.call(this) : this.__rawStack;
                return sanitizeStack(val);
            },
            set: function(v) {
                if (origStackDesc.set) {
                    origStackDesc.set.call(this, v);
                } else {
                    this.__rawStack = v;
                }
            },
            configurable: true
        });
    }

    // Also patch Error.captureStackTrace if available (V8).
    if (Error.captureStackTrace) {
        const origCapture = Error.captureStackTrace;
        Error.captureStackTrace = function(target, constructorOpt) {
            origCapture.call(this, target, constructorOpt);
            // The getter above intercepts reads via Error.prototype.stack,
            // but some code accesses the raw __rawStack or reads stack
            // before the getter is hit. Eagerly sanitize here.
            if (typeof target.stack === 'string') {
                const origDesc2 = Object.getOwnPropertyDescriptor(target, 'stack');
                if (origDesc2 && origDesc2.value) {
                    Object.defineProperty(target, 'stack', {
                        value: sanitizeStack(origDesc2.value),
                        writable: true,
                        configurable: true
                    });
                }
            }
        };
        if (typeof window.__tallowMakeNative === 'function') {
            window.__tallowMakeNative(Error.captureStackTrace, 'captureStackTrace');
        }
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 4. performance.getEntries() Filtering
// Detection: performance.getEntries() and getEntriesByType('resource')
// can reveal injected stealth scripts by their resource timing entries.
// ─────────────────────────────────────────────────────────────────────────────

pub const PERFORMANCE_ENTRIES_FILTERING: &str = r#"
(() => {
    const SUSPICIOUS_ENTRY_PATTERNS = [
        '__puppeteer',
        'pptr:',
        'playwright',
        'tallow-stealth',
        'cdp',
        'devtools',
        'injectedScript',
        'chrome-extension://',
        'moz-extension://',
        '__selenium',
        '__driver'
    ];

    const SUSPICIOUS_ENTRY_RE = new RegExp(
        SUSPICIOUS_ENTRY_PATTERNS.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
        'i'
    );

    function filterEntries(entries) {
        return entries.filter(entry => {
            const name = entry.name || '';
            return !SUSPICIOUS_ENTRY_RE.test(name);
        });
    }

    // Override getEntries
    const origGetEntries = Performance.prototype.getEntries;
    Performance.prototype.getEntries = function() {
        return filterEntries(origGetEntries.call(this));
    };
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Performance.prototype.getEntries, 'getEntries');
    }

    // Override getEntriesByType
    const origGetEntriesByType = Performance.prototype.getEntriesByType;
    Performance.prototype.getEntriesByType = function(type) {
        return filterEntries(origGetEntriesByType.call(this, type));
    };
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Performance.prototype.getEntriesByType, 'getEntriesByType');
    }

    // Override getEntriesByName
    const origGetEntriesByName = Performance.prototype.getEntriesByName;
    Performance.prototype.getEntriesByName = function(name, type) {
        return filterEntries(origGetEntriesByName.call(this, name, type));
    };
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Performance.prototype.getEntriesByName, 'getEntriesByName');
    }

    // Override PerformanceObserver to filter entries in callbacks
    if (typeof PerformanceObserver !== 'undefined') {
        const OrigObserver = PerformanceObserver;
        window.PerformanceObserver = function(callback) {
            const wrappedCallback = function(list, observer) {
                const filteredEntries = filterEntries(list.getEntries());
                // Create a proxy that returns filtered entries
                const filteredList = {
                    getEntries: () => filteredEntries,
                    getEntriesByType: (type) => filteredEntries.filter(e => e.entryType === type),
                    getEntriesByName: (name, type) => filteredEntries.filter(e => {
                        return e.name === name && (!type || e.entryType === type);
                    })
                };
                callback(filteredList, observer);
            };
            return new OrigObserver(wrappedCallback);
        };
        window.PerformanceObserver.prototype = OrigObserver.prototype;
        window.PerformanceObserver.supportedEntryTypes = OrigObserver.supportedEntryTypes;
        if (typeof window.__tallowMakeNative === 'function') {
            window.__tallowMakeNative(window.PerformanceObserver, 'PerformanceObserver');
        }
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 5. Proxy/Reflect Detection Bypass
// Detection: fingerprinters detect JS Proxy wrappers by:
//   - Checking Symbol.toStringTag on proxied objects
//   - Testing Object.getOwnPropertyDescriptor behavior differences
//   - Detecting Proxy.revocable patterns
//   - Checking toString() output of proxied functions
// ─────────────────────────────────────────────────────────────────────────────

pub const PROXY_REFLECT_BYPASS: &str = r#"
(() => {
    // Patch Proxy to be undetectable. The real Proxy constructor is saved
    // and wrapped so that proxied objects pass common detection checks.
    const OrigProxy = window.Proxy;
    if (!OrigProxy) return;

    // WeakSet of all proxy instances we have created, so we can
    // recognize them in detection checks.
    const __proxyInstances = new WeakSet();

    // Wrap Proxy constructor to auto-add protections.
    window.Proxy = function(target, handler) {
        // Ensure toString returns the target's toString, not "[object Object]"
        const origGet = handler.get;
        handler.get = function(t, prop, receiver) {
            // Symbol.toStringTag: return what the target would return
            if (prop === Symbol.toStringTag) {
                return target[Symbol.toStringTag] || (typeof target === 'function' ? undefined : undefined);
            }
            // toString: delegate to target
            if (prop === 'toString') {
                const targetToString = target.toString;
                if (typeof targetToString === 'function') {
                    return targetToString.bind(target);
                }
            }
            if (origGet) {
                return origGet.call(this, t, prop, receiver);
            }
            return Reflect.get(t, prop, receiver);
        };

        // Ensure getOwnPropertyDescriptor returns consistent results
        if (!handler.getOwnPropertyDescriptor) {
            handler.getOwnPropertyDescriptor = function(t, prop) {
                return Object.getOwnPropertyDescriptor(t, prop);
            };
        }

        const proxy = new OrigProxy(target, handler);
        __proxyInstances.add(proxy);
        return proxy;
    };

    // Preserve Proxy.revocable
    window.Proxy.revocable = function(target, handler) {
        const result = OrigProxy.revocable(target, handler);
        __proxyInstances.add(result.proxy);
        return result;
    };

    // Make our Proxy wrapper look native
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(window.Proxy, 'Proxy');
        window.__tallowMakeNative(window.Proxy.revocable, 'revocable');
    }

    // Harden Object.getOwnPropertyDescriptor to not leak proxy internals.
    // Some fingerprinters call Object.getOwnPropertyDescriptor(navigator, 'webdriver')
    // and check if the descriptor looks "synthetic" (writable + configurable + value
    // instead of a getter). We patch it to return descriptors that look natural.
    const origGetOwnPropDesc = Object.getOwnPropertyDescriptor;

    // Properties on navigator that stealth scripts override with defineProperty.
    // If a fingerprinter inspects the descriptor, they may see a configurable
    // data descriptor where native code would show a non-configurable getter.
    // We fix these descriptors to look like the browser originals.
    const NAVIGATOR_NATIVE_GETTERS = new Set([
        'webdriver', 'languages', 'plugins', 'mimeTypes', 'platform',
        'hardwareConcurrency', 'userAgent', 'appVersion', 'vendor',
        'maxTouchPoints', 'connection', 'deviceMemory',
        'pdfViewerEnabled', 'scheduling', 'userAgentData'
    ]);

    Object.getOwnPropertyDescriptor = function(obj, prop) {
        const desc = origGetOwnPropDesc.call(this, obj, prop);
        if (!desc) return desc;

        // If it's a navigator property we override, ensure the descriptor
        // looks like a native getter (accessor, not writable data property).
        if ((obj === navigator || obj === Navigator.prototype) &&
            NAVIGATOR_NATIVE_GETTERS.has(prop) && desc.value !== undefined) {
            // Convert data descriptor to accessor descriptor that looks native.
            const val = desc.value;
            return {
                get: function() { return val; },
                set: undefined,
                enumerable: desc.enumerable !== false,
                configurable: true
            };
        }

        // If it's on navigator proto and has both value + configurable,
        // match native Chrome behavior: configurable: true, enumerable: true.
        if (obj === Navigator.prototype && desc.value !== undefined &&
            typeof desc.value === 'function') {
            desc.enumerable = true;
            desc.configurable = true;
        }

        return desc;
    };
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Object.getOwnPropertyDescriptor, 'getOwnPropertyDescriptor');
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 6. SharedArrayBuffer Timing Defense
// Detection: SharedArrayBuffer + Atomics can be used as a high-precision
// timer to detect automation timing patterns (e.g., measuring how long
// operations take with sub-microsecond precision).
// We add noise to the counter thread to defeat timing-based detection.
// ─────────────────────────────────────────────────────────────────────────────

pub const SHARED_ARRAY_BUFFER_DEFENSE: &str = r#"
(() => {
    // Only patch if SharedArrayBuffer exists (requires cross-origin isolation headers).
    if (typeof SharedArrayBuffer === 'undefined') return;

    const OrigSAB = SharedArrayBuffer;

    // Wrap SharedArrayBuffer to intercept any SAB-based timers.
    // Anti-bot systems create a SAB, spawn a worker that increments a counter
    // in a tight loop, then read the counter from the main thread as a
    // high-precision timer. We interpose on Atomics to add noise.
    const origAtomicsLoad = Atomics.load;
    const origAtomicsStore = Atomics.store;

    // Add noise to Atomics.load reads — jitter by +/-2 counter ticks.
    Atomics.load = function(typedArray, index) {
        const val = origAtomicsLoad.call(this, typedArray, index);
        // Only add noise to Int32Array/Uint32Array (timer pattern uses these).
        if (typedArray instanceof Int32Array || typedArray instanceof Uint32Array) {
            const noise = Math.floor(Math.random() * 5) - 2;
            return val + noise;
        }
        return val;
    };

    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Atomics.load, 'load');
        window.__tallowMakeNative(Atomics.store, 'store');
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 7. Notification Permission Override
// Detection: Notification.permission returns "denied" in headless Chrome.
// Real browsers that have never been asked return "default".
// ─────────────────────────────────────────────────────────────────────────────

pub const NOTIFICATION_PERMISSION_EVASION: &str = r#"
(() => {
    if (typeof Notification === 'undefined') return;

    // Override the permission property to return "default" instead of "denied".
    try {
        const origDesc = Object.getOwnPropertyDescriptor(Notification, 'permission');
        Object.defineProperty(Notification, 'permission', {
            get: function() {
                const real = origDesc && origDesc.get ? origDesc.get.call(this) : 'denied';
                // "denied" is the headless giveaway; return "default" instead.
                return real === 'denied' ? 'default' : real;
            },
            configurable: true
        });
    } catch(e) {
        // Fallback: define directly if the above fails.
        try {
            Object.defineProperty(Notification, 'permission', {
                get: () => 'default',
                configurable: true
            });
        } catch(e2) {}
    }

    // Also override Notification.requestPermission to behave like a real browser.
    const origRequestPermission = Notification.requestPermission;
    Notification.requestPermission = function(callback) {
        const promise = Promise.resolve('default');
        if (typeof callback === 'function') {
            promise.then(callback);
        }
        return promise;
    };
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Notification.requestPermission, 'requestPermission');
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// 8. Chrome CDP Leak Patches
// Detection: ChromeDriver injects properties like:
//   - window.cdc_adoQpoasnfa76pfcZLmcfl_Array
//   - window.cdc_adoQpoasnfa76pfcZLmcfl_Promise
//   - Any property starting with $cdc_
//   - document.$chrome_asyncScriptInfo
//   - window.__$webdriverAsyncExecutor
//   - navigator.__proto__ has webdriver-injected properties
// These must be cleaned up before any page JS runs.
// ─────────────────────────────────────────────────────────────────────────────

pub const CDP_LEAK_PATCHES: &str = r#"
(() => {
    // --- 8a. Delete known ChromeDriver leak properties ---
    const cdcPatterns = /^cdc_|^\$cdc_|^__\$webdriver/;

    // Clean window
    for (const prop of Object.getOwnPropertyNames(window)) {
        if (cdcPatterns.test(prop)) {
            try { delete window[prop]; } catch(e) {}
        }
    }

    // Clean document
    try { delete document.$chrome_asyncScriptInfo; } catch(e) {}
    try { delete document.$cdc_asdjflasutopfhvcZLmcfl_; } catch(e) {}

    // --- 8b. MutationObserver to catch dynamically added CDC properties ---
    // ChromeDriver may inject these after page load too.
    const cdcObserver = new MutationObserver((mutations) => {
        for (const prop of Object.getOwnPropertyNames(window)) {
            if (cdcPatterns.test(prop)) {
                try { delete window[prop]; } catch(e) {}
            }
        }
    });

    // Observe attribute changes on document.documentElement (ChromeDriver
    // sometimes adds attributes there).
    if (document.documentElement) {
        cdcObserver.observe(document.documentElement, {
            attributes: true,
            childList: true,
            subtree: false
        });
    }

    // --- 8c. Clean navigator prototype chain ---
    // Some drivers add properties to Navigator.prototype.
    const navProto = Object.getPrototypeOf(navigator);
    if (navProto) {
        for (const prop of Object.getOwnPropertyNames(navProto)) {
            if (cdcPatterns.test(prop) || prop === '__webdriver_evaluate' ||
                prop === '__selenium_evaluate' || prop === '__fxdriver_evaluate' ||
                prop === '__driver_unwrapped' || prop === '__webdriver_unwrapped' ||
                prop === '__driver_evaluate' || prop === '__selenium_unwrapped' ||
                prop === '__fxdriver_unwrapped') {
                try { delete navProto[prop]; } catch(e) {}
            }
        }
    }

    // --- 8d. Hide CDP Runtime.enable artifacts ---
    // Chrome DevTools Protocol leaves traces in some global objects.
    // Clean up common ones.
    try { delete window.__commandLineAPI; } catch(e) {}
    try { delete window.__cdp; } catch(e) {}

    // --- 8e. Prevent detection via Object.keys/getOwnPropertyNames of window ---
    // Some fingerprinters enumerate window properties looking for CDC patterns.
    const origGetOwnPropertyNames = Object.getOwnPropertyNames;
    Object.getOwnPropertyNames = function(obj) {
        const names = origGetOwnPropertyNames.call(this, obj);
        if (obj === window || obj === document || obj === navigator) {
            return names.filter(name => !cdcPatterns.test(name) &&
                name !== '$chrome_asyncScriptInfo' &&
                name !== '__commandLineAPI' &&
                name !== '__tallowMakeNative');
        }
        return names;
    };
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Object.getOwnPropertyNames, 'getOwnPropertyNames');
    }

    // Also filter Reflect.ownKeys to hide internal properties.
    const origReflectOwnKeys = Reflect.ownKeys;
    Reflect.ownKeys = function(obj) {
        const keys = origReflectOwnKeys.call(this, obj);
        if (obj === window || obj === document || obj === navigator) {
            return keys.filter(name => {
                if (typeof name === 'symbol') return true;
                return !cdcPatterns.test(name) &&
                    name !== '$chrome_asyncScriptInfo' &&
                    name !== '__commandLineAPI' &&
                    name !== '__tallowMakeNative';
            });
        }
        return keys;
    };
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Reflect.ownKeys, 'ownKeys');
    }

    // Also filter Object.keys for the same objects.
    const origKeys = Object.keys;
    Object.keys = function(obj) {
        const keys = origKeys.call(this, obj);
        if (obj === window) {
            return keys.filter(name => !cdcPatterns.test(name) &&
                name !== '$chrome_asyncScriptInfo' &&
                name !== '__commandLineAPI' &&
                name !== '__tallowMakeNative');
        }
        return keys;
    };
    if (typeof window.__tallowMakeNative === 'function') {
        window.__tallowMakeNative(Object.keys, 'keys');
    }
})();
"#;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Return individual stealth patches with names for diagnostics.
/// Each patch is a self-contained IIFE that can be injected independently.
pub fn get_stealth_v3_patches() -> Vec<StealthPatch> {
    vec![
        StealthPatch {
            name: "function_tostring_cloaking",
            js: FUNCTION_TOSTRING_CLOAKING.to_string(),
        },
        StealthPatch {
            name: "document_has_focus",
            js: DOCUMENT_HAS_FOCUS_EVASION.to_string(),
        },
        StealthPatch {
            name: "error_stack_sanitization",
            js: ERROR_STACK_SANITIZATION.to_string(),
        },
        StealthPatch {
            name: "performance_entries_filtering",
            js: PERFORMANCE_ENTRIES_FILTERING.to_string(),
        },
        StealthPatch {
            name: "proxy_reflect_bypass",
            js: PROXY_REFLECT_BYPASS.to_string(),
        },
        StealthPatch {
            name: "shared_array_buffer_defense",
            js: SHARED_ARRAY_BUFFER_DEFENSE.to_string(),
        },
        StealthPatch {
            name: "notification_permission",
            js: NOTIFICATION_PERMISSION_EVASION.to_string(),
        },
        StealthPatch {
            name: "cdp_leak_patches",
            js: CDP_LEAK_PATCHES.to_string(),
        },
    ]
}

/// Generate the combined V3 stealth script.
/// Should be injected AFTER V1 and V2 stealth scripts.
/// The `_profile` parameter is accepted for API consistency with V2
/// (future patches may need profile-specific behavior).
pub fn stealth_v3_script(_profile: &StealthProfile) -> String {
    let mut script = String::with_capacity(32768);
    script.push_str("// ═══ Tallow Stealth V3 — Advanced Anti-Detection Engine ═══\n");
    script.push_str("// Targets: DataDome Picasso, FingerprintJS, CreepJS\n");
    script.push_str("(function() { 'use strict';\n");

    // 1. Function.prototype.toString cloaking MUST be first — all other
    //    patches depend on __tallowMakeNative being available.
    script.push_str(FUNCTION_TOSTRING_CLOAKING);

    // 2. document.hasFocus()
    script.push_str(DOCUMENT_HAS_FOCUS_EVASION);

    // 3. Error.stack sanitization
    script.push_str(ERROR_STACK_SANITIZATION);

    // 4. performance.getEntries() filtering
    script.push_str(PERFORMANCE_ENTRIES_FILTERING);

    // 5. Proxy/Reflect detection bypass
    script.push_str(PROXY_REFLECT_BYPASS);

    // 6. SharedArrayBuffer timing defense
    script.push_str(SHARED_ARRAY_BUFFER_DEFENSE);

    // 7. Notification.permission override
    script.push_str(NOTIFICATION_PERMISSION_EVASION);

    // 8. Chrome CDP leak patches
    script.push_str(CDP_LEAK_PATCHES);

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
    fn stealth_v3_contains_all_evasions() {
        let p = StealthProfile::chrome_windows();
        let script = stealth_v3_script(&p);
        // 1. Function.prototype.toString cloaking
        assert!(
            script.contains("Function.prototype.toString"),
            "should cloak toString"
        );
        assert!(
            script.contains("__tallowMakeNative"),
            "should expose makeNative helper"
        );
        assert!(
            script.contains("[native code]"),
            "should fake native code output"
        );
        // 2. document.hasFocus()
        assert!(
            script.contains("Document.prototype.hasFocus"),
            "should override hasFocus"
        );
        assert!(
            script.contains("visibilityState"),
            "should patch visibilityState"
        );
        // 3. Error.stack
        assert!(
            script.contains("Error.prototype"),
            "should patch Error.prototype stack"
        );
        assert!(
            script.contains("__puppeteer_evaluation_script__"),
            "should filter puppeteer frames"
        );
        assert!(
            script.contains("pptr:evaluate"),
            "should filter pptr frames"
        );
        assert!(
            script.contains("__selenium_evaluate"),
            "should filter selenium frames"
        );
        // 4. performance.getEntries()
        assert!(
            script.contains("Performance.prototype.getEntries"),
            "should override getEntries"
        );
        assert!(
            script.contains("getEntriesByType"),
            "should override getEntriesByType"
        );
        assert!(
            script.contains("getEntriesByName"),
            "should override getEntriesByName"
        );
        assert!(
            script.contains("PerformanceObserver"),
            "should wrap PerformanceObserver"
        );
        // 5. Proxy/Reflect
        assert!(
            script.contains("Symbol.toStringTag"),
            "should handle toStringTag"
        );
        assert!(
            script.contains("Proxy.revocable"),
            "should preserve Proxy.revocable"
        );
        // 6. SharedArrayBuffer
        assert!(
            script.contains("SharedArrayBuffer"),
            "should patch SharedArrayBuffer"
        );
        assert!(
            script.contains("Atomics.load"),
            "should add noise to Atomics.load"
        );
        // 7. Notification.permission
        assert!(
            script.contains("Notification, 'permission'"),
            "should override Notification.permission"
        );
        assert!(
            script.contains("requestPermission"),
            "should override requestPermission"
        );
        // 8. CDP leaks
        assert!(script.contains("$cdc_"), "should match cdc patterns");
        assert!(
            script.contains("$chrome_asyncScriptInfo"),
            "should clean chrome async info"
        );
        assert!(
            script.contains("__webdriver_evaluate"),
            "should clean webdriver props"
        );
        assert!(
            script.contains("__commandLineAPI"),
            "should clean command line API"
        );
    }

    #[test]
    fn tostring_cloaking_is_first_patch() {
        let p = StealthProfile::chrome_windows();
        let script = stealth_v3_script(&p);
        // Function.prototype.toString cloaking must appear before any
        // __tallowMakeNative usage.
        let tostring_pos = script.find("Function.prototype.toString").unwrap();
        let make_native_usage = script.find("window.__tallowMakeNative(Document").unwrap();
        assert!(
            tostring_pos < make_native_usage,
            "toString cloaking must come before hasFocus patch that uses makeNative"
        );
    }

    #[test]
    fn get_patches_returns_all_eight() {
        let patches = get_stealth_v3_patches();
        assert_eq!(patches.len(), 8, "should return exactly 8 patches");

        let names: Vec<&str> = patches.iter().map(|p| p.name).collect();
        assert!(names.contains(&"function_tostring_cloaking"));
        assert!(names.contains(&"document_has_focus"));
        assert!(names.contains(&"error_stack_sanitization"));
        assert!(names.contains(&"performance_entries_filtering"));
        assert!(names.contains(&"proxy_reflect_bypass"));
        assert!(names.contains(&"shared_array_buffer_defense"));
        assert!(names.contains(&"notification_permission"));
        assert!(names.contains(&"cdp_leak_patches"));
    }

    #[test]
    fn patches_are_nonempty() {
        for patch in get_stealth_v3_patches() {
            assert!(
                !patch.js.is_empty(),
                "patch '{}' should not be empty",
                patch.name
            );
            assert!(
                patch.js.len() > 50,
                "patch '{}' seems too short: {} bytes",
                patch.name,
                patch.js.len()
            );
        }
    }

    #[test]
    fn error_stack_filters_puppeteer_and_selenium() {
        assert!(ERROR_STACK_SANITIZATION.contains("__puppeteer_evaluation_script__"));
        assert!(ERROR_STACK_SANITIZATION.contains("pptr:evaluate"));
        assert!(ERROR_STACK_SANITIZATION.contains("__selenium_evaluate"));
        assert!(ERROR_STACK_SANITIZATION.contains("__driver_evaluate"));
        assert!(ERROR_STACK_SANITIZATION.contains("Runtime.evaluate"));
        assert!(ERROR_STACK_SANITIZATION.contains("tallow-stealth"));
    }

    #[test]
    fn cdp_leaks_cleans_all_known_patterns() {
        assert!(CDP_LEAK_PATCHES.contains("cdc_"));
        assert!(CDP_LEAK_PATCHES.contains("$chrome_asyncScriptInfo"));
        assert!(CDP_LEAK_PATCHES.contains("__webdriver_evaluate"));
        assert!(CDP_LEAK_PATCHES.contains("__selenium_evaluate"));
        assert!(CDP_LEAK_PATCHES.contains("__fxdriver_evaluate"));
        assert!(CDP_LEAK_PATCHES.contains("__driver_unwrapped"));
        assert!(CDP_LEAK_PATCHES.contains("MutationObserver"));
    }

    #[test]
    fn notification_returns_default_not_denied() {
        assert!(NOTIFICATION_PERMISSION_EVASION.contains("'default'"));
        assert!(NOTIFICATION_PERMISSION_EVASION.contains("'denied'"));
        // Must convert denied -> default
        assert!(NOTIFICATION_PERMISSION_EVASION.contains("=== 'denied' ? 'default'"));
    }

    #[test]
    fn document_has_focus_returns_true() {
        assert!(DOCUMENT_HAS_FOCUS_EVASION.contains("return true"));
        assert!(DOCUMENT_HAS_FOCUS_EVASION.contains("'visible'"));
        assert!(DOCUMENT_HAS_FOCUS_EVASION.contains("false"));
    }

    #[test]
    fn shared_array_buffer_guards_existence() {
        assert!(SHARED_ARRAY_BUFFER_DEFENSE.contains("typeof SharedArrayBuffer === 'undefined'"));
        assert!(SHARED_ARRAY_BUFFER_DEFENSE.contains("return;"));
    }

    #[test]
    fn performance_entries_filters_observer() {
        assert!(PERFORMANCE_ENTRIES_FILTERING.contains("PerformanceObserver"));
        assert!(PERFORMANCE_ENTRIES_FILTERING.contains("supportedEntryTypes"));
        assert!(PERFORMANCE_ENTRIES_FILTERING.contains("filterEntries"));
    }

    #[test]
    fn tostring_cloaking_handles_reflect_apply() {
        // Our approach replaces Function.prototype.toString directly,
        // so Reflect.apply(Function.prototype.toString, fn, []) naturally
        // calls our replacement. Verify the script documents this.
        assert!(FUNCTION_TOSTRING_CLOAKING.contains("Reflect.apply"));
    }

    #[test]
    fn tostring_cloaking_cloaks_itself() {
        // toString itself must look native
        assert!(
            FUNCTION_TOSTRING_CLOAKING.contains("_nativeNames.set(_patchedToString, 'toString')")
        );
    }

    #[test]
    fn proxy_bypass_preserves_revocable() {
        assert!(PROXY_REFLECT_BYPASS.contains("Proxy.revocable"));
        assert!(PROXY_REFLECT_BYPASS.contains("OrigProxy.revocable"));
    }
}
