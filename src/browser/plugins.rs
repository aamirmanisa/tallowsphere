//! Built-in browser plugins — ad blocking, tracker blocking, privacy protection.
//!
//! Equivalent to: uBlock Origin + Privacy Badger + HTTPS Everywhere + NoScript +
//!                ClearURLs + Cookie AutoDelete + Decentraleyes
//!
//! All plugins are built-in and activate automatically. No extensions to install.

use std::collections::HashSet;

use serde_json::json;

use super::cdp::CdpClient;
use super::error::BrowserError;

// ─────────────────────────────────────────────────────────────────────────────
// CDP enforcement — apply plugin blocklists via Network.setBlockedURLs
// ─────────────────────────────────────────────────────────────────────────────

/// Apply browser plugin blocklists via the CDP `Network.setBlockedURLs` command.
///
/// Combines all enabled blocklist URL patterns (ads, trackers, miners, social
/// widgets) into a single `Network.setBlockedURLs` call. This is a lightweight
/// approach that does not require `Fetch.enable` and avoids deadlock risks.
///
/// Also injects the plugin JS bundle (fingerprint protection, popup blocking,
/// cookie blocking, cosmetic hiding, element removal, network-level blocking)
/// via `Page.addScriptToEvaluateOnNewDocument` so it runs before every page load.
pub async fn apply_plugins(
    plugins: &BrowserPlugins,
    cdp: &CdpClient,
    session_id: &str,
) -> Result<(), BrowserError> {
    // ── 1. Collect URL patterns from all enabled blocklists ──────────────
    let mut blocked_urls: Vec<String> = Vec::new();

    if plugins.adblock {
        blocked_urls.extend(AD_PATTERNS.iter().map(|p| p.to_string()));
    }
    if plugins.tracker_block {
        blocked_urls.extend(TRACKER_PATTERNS.iter().map(|p| p.to_string()));
    }
    if plugins.miner_block {
        blocked_urls.extend(MINER_PATTERNS.iter().map(|p| p.to_string()));
    }
    if plugins.social_block {
        blocked_urls.extend(SOCIAL_PATTERNS.iter().map(|p| p.to_string()));
    }
    // Analytics / session-replay kill layer — always applied. Stops MS Clarity,
    // Sentry, GTM/GA4, and reCAPTCHA from reaching their servers, so the site
    // operator gets no behavioral telemetry from the session.
    blocked_urls.extend(ANALYTICS_URLS.iter().map(|p| p.to_string()));

    // ── 2. Enable Network domain (required for setBlockedURLs) ──────────
    cdp.send_command_with_session("Network.enable", None, session_id)
        .await?;

    // ── 3. Send the combined blocklist in one call ──────────────────────
    if !blocked_urls.is_empty() {
        cdp.send_command_with_session(
            "Network.setBlockedURLs",
            Some(json!({ "urls": blocked_urls })),
            session_id,
        )
        .await?;
    }

    // ── 4. Inject the JS plugin bundle for layers that need runtime JS ──
    let js = plugins.injection_script();
    if !js.is_empty() {
        cdp.send_command_with_session(
            "Page.addScriptToEvaluateOnNewDocument",
            Some(json!({ "source": js })),
            session_id,
        )
        .await?;
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in browser plugin set. Enable/disable individual protections.
#[derive(Debug, Clone)]
pub struct BrowserPlugins {
    pub adblock: bool,
    pub tracker_block: bool,
    pub https_everywhere: bool,
    pub noscript: bool,
    pub clear_urls: bool,
    pub cookie_autoblock: bool,
    pub fingerprint_protect: bool,
    pub popup_block: bool,
    pub miner_block: bool,
    pub social_block: bool,
}

impl Default for BrowserPlugins {
    fn default() -> Self {
        Self {
            adblock: true,
            tracker_block: true,
            https_everywhere: true,
            noscript: false,       // off by default (breaks many sites)
            clear_urls: true,
            cookie_autoblock: false, // off by default
            fingerprint_protect: true,
            popup_block: true,
            miner_block: true,
            social_block: true,
        }
    }
}

/// The single pre-navigation URL rewrite: strip tracking parameters
/// (ClearURLs) and upgrade plain HTTP to HTTPS where it is safe (#108).
///
/// Both engines call this through `Page::navigate`, so a change here cannot
/// make the interpreter and the native FFI disagree.
pub fn normalize_navigation_url(raw: &str) -> String {
    let plugins = BrowserPlugins::default();
    plugins.force_https(&plugins.clean_url(raw))
}

impl BrowserPlugins {
    /// All plugins enabled (maximum privacy).
    pub fn max_privacy() -> Self {
        Self {
            adblock: true,
            tracker_block: true,
            https_everywhere: true,
            noscript: true,
            clear_urls: true,
            cookie_autoblock: true,
            fingerprint_protect: true,
            popup_block: true,
            miner_block: true,
            social_block: true,
        }
    }

    /// All plugins disabled (no blocking).
    pub fn none() -> Self {
        Self {
            adblock: false,
            tracker_block: false,
            https_everywhere: false,
            noscript: false,
            clear_urls: false,
            cookie_autoblock: false,
            fingerprint_protect: false,
            popup_block: false,
            miner_block: false,
            social_block: false,
        }
    }

    /// Balanced — ads + trackers blocked, scripts allowed.
    pub fn balanced() -> Self {
        Self::default()
    }

    /// Get all URL patterns to block.
    pub fn blocked_patterns(&self) -> Vec<&'static str> {
        let mut patterns = Vec::new();
        if self.adblock {
            patterns.extend_from_slice(&AD_PATTERNS);
        }
        if self.tracker_block {
            patterns.extend_from_slice(&TRACKER_PATTERNS);
        }
        if self.miner_block {
            patterns.extend_from_slice(&MINER_PATTERNS);
        }
        if self.social_block {
            patterns.extend_from_slice(&SOCIAL_PATTERNS);
        }
        patterns
    }

    /// Get domains to block (for DNS-level blocking).
    pub fn blocked_domains(&self) -> HashSet<&'static str> {
        let mut domains = HashSet::new();
        if self.adblock {
            for d in AD_DOMAINS { domains.insert(*d); }
        }
        if self.tracker_block {
            for d in TRACKER_DOMAINS { domains.insert(*d); }
        }
        if self.miner_block {
            for d in MINER_DOMAINS { domains.insert(*d); }
        }
        if self.social_block {
            for d in SOCIAL_DOMAINS { domains.insert(*d); }
        }
        domains
    }

    /// Get tracking URL parameters to strip (ClearURLs).
    pub fn tracking_params(&self) -> &'static [&'static str] {
        if self.clear_urls { &TRACKING_PARAMS } else { &[] }
    }

    /// Generate the JavaScript to inject for fingerprint protection.
    pub fn fingerprint_protection_js(&self) -> &'static str {
        if self.fingerprint_protect { FINGERPRINT_PROTECT_JS } else { "" }
    }

    /// Generate the JavaScript to inject for popup blocking.
    pub fn popup_block_js(&self) -> &'static str {
        if self.popup_block { POPUP_BLOCK_JS } else { "" }
    }

    /// Generate the JavaScript to inject for cookie auto-blocking.
    pub fn cookie_block_js(&self) -> &'static str {
        if self.cookie_autoblock { COOKIE_BLOCK_JS } else { "" }
    }

    /// Should a URL be blocked?
    pub fn should_block_url(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();
        for pattern in self.blocked_patterns() {
            if glob_match(pattern, &url_lower) {
                return true;
            }
        }
        // Check domain blocking
        if let Some(domain) = extract_domain(&url_lower) {
            if self.blocked_domains().contains(domain) {
                return true;
            }
        }
        false
    }

    /// Clean tracking parameters from a URL (ClearURLs).
    pub fn clean_url(&self, url: &str) -> String {
        if !self.clear_urls { return url.to_string(); }
        let params = self.tracking_params();
        if params.is_empty() { return url.to_string(); }

        if let Some(pos) = url.find('?') {
            let base = &url[..pos];
            let query = &url[pos + 1..];
            let cleaned: Vec<&str> = query.split('&')
                .filter(|pair| {
                    let key = pair.split('=').next().unwrap_or("");
                    !params.contains(&key)
                })
                .collect();
            if cleaned.is_empty() {
                base.to_string()
            } else {
                format!("{}?{}", base, cleaned.join("&"))
            }
        } else {
            url.to_string()
        }
    }

    /// Force HTTPS on a URL (HTTPS Everywhere).
    pub fn force_https(&self, url: &str) -> String {
        if !self.https_everywhere { return url.to_string(); }
        if let Some(rest) = url.strip_prefix("http://") {
            // Loopback and private-range hosts are not "upgradeable": they
            // usually serve plain HTTP on purpose, and rewriting them to
            // https:// produces a TLS error page instead of the target
            // (chrome-error://chromewebdata/), which reads like a network
            // failure rather than a policy decision. Local test pages,
            // sidecars and LAN services must stay reachable.
            if !is_local_or_private_host(rest) {
                return format!("https://{rest}");
            }
        }
        url.to_string()
    }

    /// Get a combined JS injection script for all active plugins.
    ///
    /// The script now performs three layers of blocking when adblock/tracker_block
    /// are enabled:
    /// 1. CSS cosmetic hiding of ad/tracker containers (fast, visual)
    /// 2. MutationObserver element removal — removes script/iframe/img nodes whose
    ///    src/href matches ad/tracker patterns before they execute
    /// 3. fetch() + XMLHttpRequest prototype override — blocks network requests to
    ///    ad/tracker domains at the JS API level
    pub fn injection_script(&self) -> String {
        let mut script = String::new();
        script.push_str("(function() { 'use strict';\n");

        if self.fingerprint_protect {
            script.push_str(FINGERPRINT_PROTECT_JS);
            script.push('\n');
        }
        if self.popup_block {
            script.push_str(POPUP_BLOCK_JS);
            script.push('\n');
        }
        if self.cookie_autoblock {
            script.push_str(COOKIE_BLOCK_JS);
            script.push('\n');
        }
        if self.adblock || self.tracker_block || self.miner_block || self.social_block {
            // Layer 1: CSS cosmetic hiding
            if self.adblock {
                script.push_str(AD_COSMETIC_JS);
                script.push('\n');
            }
            // Layer 2: Element removal via MutationObserver
            script.push_str(&self.element_removal_js());
            script.push('\n');
            // Layer 3: Network request blocking (fetch + XHR)
            script.push_str(&self.network_block_js());
            script.push('\n');
        }

        // Analytics / session-replay kill (Clarity, Sentry, GTM/GA4, reCAPTCHA)
        script.push_str(&analytics_kill_js());
        script.push('\n');

        script.push_str("})();\n");
        script
    }

    /// Generate JavaScript that uses MutationObserver to remove script, iframe,
    /// and img elements whose src/href matches known ad/tracker domain patterns.
    /// This is more effective than CSS hiding because the resources never load.
    fn element_removal_js(&self) -> String {
        // Collect all blocked domains for JS injection
        let domains: Vec<String> = self
            .blocked_domains()
            .into_iter()
            .map(|d| d.to_string())
            .collect();

        if domains.is_empty() {
            return String::new();
        }

        // Build the JS domain list
        let domain_list = domains
            .iter()
            .map(|d| format!("'{d}'"))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            r#"
// Tallow: element removal for ad/tracker domains
(function() {{
    var BLOCKED_DOMAINS = [{domain_list}];
    function isDomainBlocked(url) {{
        if (!url) return false;
        try {{
            var hostname = new URL(url, location.href).hostname;
            for (var i = 0; i < BLOCKED_DOMAINS.length; i++) {{
                if (hostname === BLOCKED_DOMAINS[i] || hostname.endsWith('.' + BLOCKED_DOMAINS[i])) {{
                    return true;
                }}
            }}
        }} catch(e) {{ return false; }}
        return false;
    }}
    function removeIfBlocked(el) {{
        var url = el.src || el.href || el.getAttribute('data-src') || '';
        if (isDomainBlocked(url)) {{
            console.log('[Tallow] Removed element:', el.tagName, url);
            el.remove();
            return true;
        }}
        return false;
    }}
    function scanAndRemove(root) {{
        var tags = root.querySelectorAll ? root.querySelectorAll('script[src], iframe[src], img[src], link[href]') : [];
        Array.from(tags).forEach(removeIfBlocked);
    }}
    // Scan existing DOM
    scanAndRemove(document);
    // Watch for new nodes being inserted
    var observer = new MutationObserver(function(mutations) {{
        mutations.forEach(function(mutation) {{
            mutation.addedNodes.forEach(function(node) {{
                if (node.nodeType !== 1) return; // Element nodes only
                removeIfBlocked(node);
                scanAndRemove(node);
            }});
        }});
    }});
    // At document_start there is no documentElement yet; observing null throws
    // and kills the rest of this script.
    var root = document.documentElement;
    if (root) {{
        observer.observe(root, {{ childList: true, subtree: true }});
    }} else {{
        document.addEventListener('readystatechange', function once() {{
            document.removeEventListener('readystatechange', once);
            if (document.documentElement) {{
                observer.observe(document.documentElement, {{ childList: true, subtree: true }});
            }}
        }});
    }}
}})();
"#,
            domain_list = domain_list
        )
    }

    /// Generate JavaScript that overrides the `fetch()` and `XMLHttpRequest`
    /// prototypes to block network requests to ad/tracker domains.
    /// Requests to blocked domains are silently dropped (fetch returns a 204,
    /// XHR aborts) to avoid breaking site error-handling code.
    fn network_block_js(&self) -> String {
        let domains: Vec<String> = self
            .blocked_domains()
            .into_iter()
            .map(|d| d.to_string())
            .collect();

        if domains.is_empty() {
            return String::new();
        }

        let domain_list = domains
            .iter()
            .map(|d| format!("'{d}'"))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            r#"
// Tallow: network request blocking (fetch + XHR)
(function() {{
    var BLOCKED_DOMAINS = [{domain_list}];
    function isBlocked(url) {{
        if (!url) return false;
        try {{
            var hostname = new URL(url, location.href).hostname;
            for (var i = 0; i < BLOCKED_DOMAINS.length; i++) {{
                if (hostname === BLOCKED_DOMAINS[i] || hostname.endsWith('.' + BLOCKED_DOMAINS[i])) {{
                    return true;
                }}
            }}
        }} catch(e) {{ return false; }}
        return false;
    }}

    // Override fetch()
    var origFetch = window.fetch;
    if (origFetch) {{
        window.fetch = function(input, init) {{
            var url = (typeof input === 'string') ? input : (input && input.url) || '';
            if (isBlocked(url)) {{
                console.log('[Tallow] Blocked fetch:', url);
                return Promise.resolve(new Response(null, {{ status: 204, statusText: 'Blocked by Tallow' }}));
            }}
            return origFetch.apply(this, arguments);
        }};
    }}

    // Override XMLHttpRequest
    var origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {{
        this._tallowUrl = url;
        if (isBlocked(url)) {{
            console.log('[Tallow] Blocked XHR:', url);
            this._tallowBlocked = true;
        }}
        return origOpen.apply(this, arguments);
    }};
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {{
        if (this._tallowBlocked) {{
            // Simulate an aborted request — fire readyState 4 with status 0
            Object.defineProperty(this, 'readyState', {{ get: function() {{ return 4; }} }});
            Object.defineProperty(this, 'status', {{ get: function() {{ return 0; }} }});
            var evt = new Event('loadend');
            this.dispatchEvent(evt);
            return;
        }}
        return origSend.apply(this, arguments);
    }};
}})();
"#,
            domain_list = domain_list
        )
    }

    /// Summary of active plugins for display.
    pub fn summary(&self) -> String {
        let mut active = Vec::new();
        if self.adblock { active.push("AdBlock"); }
        if self.tracker_block { active.push("TrackerBlock"); }
        if self.https_everywhere { active.push("HTTPS-Everywhere"); }
        if self.noscript { active.push("NoScript"); }
        if self.clear_urls { active.push("ClearURLs"); }
        if self.cookie_autoblock { active.push("CookieBlock"); }
        if self.fingerprint_protect { active.push("FingerprintProtect"); }
        if self.popup_block { active.push("PopupBlock"); }
        if self.miner_block { active.push("MinerBlock"); }
        if self.social_block { active.push("SocialBlock"); }
        format!("{}/{} plugins active: {}", active.len(), 10, active.join(", "))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ad network patterns (uBlock Origin equivalent)
// ─────────────────────────────────────────────────────────────────────────────

static AD_PATTERNS: &[&str] = &[
    "*googlesyndication.com*",
    "*googleadservices.com*",
    "*doubleclick.net*",
    "*googleads.g.doubleclick.net*",
    "*adservice.google.com*",
    "*pagead2.googlesyndication.com*",
    "*tpc.googlesyndication.com*",
    "*adsense*",
    "*adnxs.com*",
    "*advertising.com*",
    "*outbrain.com*",
    "*taboola.com*",
    "*criteo.com*",
    "*criteo.net*",
    "*moatads.com*",
    "*amazon-adsystem.com*",
    "*media.net*",
    "*pubmatic.com*",
    "*openx.net*",
    "*rubiconproject.com*",
    "*casalemedia.com*",
    "*indexexchange.com*",
    "*33across.com*",
    "*sharethrough.com*",
    "*spotxchange.com*",
    "*smartadserver.com*",
    "*adcolony.com*",
    "*admob*",
    "*unity3d.com/ads*",
    "*applovin.com*",
    "*mopub.com*",
    "*inmobi.com*",
    "*vungle.com*",
    "*chartboost.com*",
    "*bidswitch.net*",
    "*adobedtm.com*",
    "*demdex.net*",
    "*everesttech.net*",
    "*adform.net*",
    "*adsrvr.org*",
    "*serving-sys.com*",
    "*flashtalking.com*",
    "*sizmek.com*",
    "*/ad/*",
    "*/ads/*",
    "*/adserver/*",
    "*banner*ad*",
    "*popup*ad*",
];

static AD_DOMAINS: &[&str] = &[
    "googlesyndication.com",
    "googleadservices.com",
    "doubleclick.net",
    "adnxs.com",
    "advertising.com",
    "outbrain.com",
    "taboola.com",
    "criteo.com",
    "criteo.net",
    "moatads.com",
    "amazon-adsystem.com",
    "media.net",
    "pubmatic.com",
    "openx.net",
    "rubiconproject.com",
    "casalemedia.com",
    "indexexchange.com",
    "bidswitch.net",
    "adform.net",
    "adsrvr.org",
    "serving-sys.com",
    "flashtalking.com",
    "sizmek.com",
    "2mdn.net",
    "adtechus.com",
    "yieldmanager.com",
];

// ─────────────────────────────────────────────────────────────────────────────
// Tracker patterns (Privacy Badger equivalent)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Analytics / session-replay kill layer
// ─────────────────────────────────────────────────────────────────────────────
/// URL patterns for client-side analytics that leak the session's on-site
/// behavior (search terms, mouse/scroll, page views) to the site operator.
/// Blocking these at the network layer stops MS Clarity session-replay, Sentry
/// breadcrumbs, GTM/GA4 pageview beacons, and reCAPTCHA fingerprint challenges
/// from ever reaching their servers — so the operator gets no telemetry about
/// what the (anonymous, Tor-routed) session did on their site.
pub const ANALYTICS_URLS: &[&str] = &[
    "*clarity.ms*",
    "*ingest.sentry.io*",
    "*sentry.io/api*",
    "*googletagmanager.com*",
    "*www.googletagmanager.com*",
    "*google-analytics.com*",
    "*www.google-analytics.com*",
    "*connect.facebook.net*",
    "*site-09.example/tr*",
    "*snap.licdn.com*",
    "*site-32.example*",
    "*cdn.amplitude.com*",
    "*static.hotjar.com*",
    "*in.hotjar.com*",
    "*cdn.mxpnl.com*",
    "*www.google.com/recaptcha*",
    "*recaptcha/api*",
    "*gstatic.com/recaptcha*",
    "*google.com/recaptcha/*",
];

/// Clean hostnames of the dedicated analytics/session-replay providers, used by
/// the proxy-layer PAC block (`analytics_blocking_pac`). These are the domains
/// a site operator uses to capture the session's on-site behavior (MS Clarity
/// session-replay, Sentry, GTM/GA4 beacons, ad pixels). Google's reCAPTCHA is
/// intentionally excluded here (blocking `www.google.com` wholesale would break
/// too much); the JS kill handles its script tags instead.
pub const ANALYTICS_DOMAINS: &[&str] = &[
    "clarity.ms",
    "sentry.io",
    "googletagmanager.com",
    "google-analytics.com",
    "connect.facebook.net",
    "snap.licdn.com",
    "site-32.example",
    "cdn.amplitude.com",
    "static.hotjar.com",
    "in.hotjar.com",
    "hotjar.com",
    "cdn.mxpnl.com",
];

/// Generate a PAC (proxy auto-config) script that blocks the analytics domains
/// at the proxy layer — **before any page content or frame-1 beacon loads** —
/// by returning a dead proxy for them, and routes everything else through
/// `egress` (e.g. `"SOCKS5 127.0.0.1:9050"` for Tor). This is the network-level
/// equivalent of `analytics_kill_js()`, but it stops the very first analytics
/// request from ever being transmitted (the JS kill runs after load).
pub fn analytics_blocking_pac(egress: &str) -> String {
    let conds: Vec<String> = ANALYTICS_DOMAINS
        .iter()
        .map(|d| format!("dnsDomainIs(host, \"{d}\")"))
        .collect();
    format!(
        "function FindProxyForURL(url, host) {{\n\
         \x20   // Tallow: block analytics/session-replay at the proxy layer.\n\
         \x20   if ({}) {{\n\
         \x20       return \"PROXY 127.0.0.1:9\"; // dead port -> refused -> blocked\n\
         \x20   }}\n\
         \x20   return \"{}\";\n\
         }}",
        conds.join(" || "),
        egress
    )
}

/// JS that stubs the most common client-side analytics/session-replay APIs so
/// that even if a script loads (or the network block misses a domain) it cannot
/// collect or exfiltrate session behavior. Neutralizes `window.clarity`
/// (MS Clarity), `window.Sentry`, GTM/GA4 (`dataLayer`/`gtag`/`ga`), and
/// `sendBeacon`, and removes analytics script tags.
pub fn analytics_kill_js() -> String {
    r#"
// Tallow: client-side analytics / session-replay kill
(function() {
    'use strict';
    window.__tallow_analytics_killed = true;
    var URLS=["clarity.ms","sentry.io","googletagmanager.com","google-analytics.com","connect.facebook.net","site-09.example/tr","snap.licdn.com","site-32.example","cdn.amplitude.com","static.hotjar.com","in.hotjar.com","cdn.mxpnl.com","google.com/recaptcha","gstatic.com/recaptcha","recaptcha"];
    function isAnalytics(u){ if(!u) return false; try{ var h=new URL(u,location.href).hostname; for(var i=0;i<URLS.length;i++){ if(h===URLS[i]||h.endsWith('.'+URLS[i])) return true; } }catch(e){} return false; }
    try{ window.clarity=function(){}; delete window.clarity; Object.defineProperty(window,'clarity',{value:function(){},writable:true}); }catch(e){}
    try{
        var noop={captureException:function(){},captureMessage:function(){},captureBreadcrumb:function(){},init:function(){},withScope:function(){return this;},setUser:function(){},configureScope:function(){},addBreadcrumb:function(){},setContext:function(){}};
        window.Sentry=noop; if(window.__SENTRY__&&window.__SENTRY__.hub){ window.__SENTRY__.hub.getClient=function(){return null;}; }
    }catch(e){}
    try{ window.dataLayer=window.dataLayer||[]; window.dataLayer.push=function(){return 0;}; window.gtag=function(){}; window.ga=function(){}; }catch(e){}
    try{ var sb=navigator.sendBeacon.bind(navigator); navigator.sendBeacon=function(url,data){ if(isAnalytics(url)) return false; return sb(url,data); }; }catch(e){}
    var tags=document.querySelectorAll('script[src],iframe[src],img[src],link[href]');
    for(var i=0;i<tags.length;i++){ if(isAnalytics(tags[i].src||tags[i].href)){ try{ tags[i].remove(); }catch(e){} } }
    var mo=new MutationObserver(function(muts){ muts.forEach(function(m){ for(var j=0;j<m.addedNodes.length;j++){ var n=m.addedNodes[j]; if(n.src&&isAnalytics(n.src)){ try{ n.remove(); }catch(e){} } } }); });
    try{ mo.observe(document,{subtree:true,childList:true}); }catch(e){}
})();
"#
    .to_string()
}

static TRACKER_PATTERNS: &[&str] = &[
    "*google-analytics.com*",
    "*googletagmanager.com*",
    "*facebook.net/tr*",
    "*site-09.example/tr*",
    "*connect.facebook.net*",
    "*site-09.example*",
    "*hotjar.com*",
    "*fullstory.com*",
    "*mouseflow.com*",
    "*luckyorange.com*",
    "*crazyegg.com*",
    "*mixpanel.com*",
    "*amplitude.com*",
    "*segment.com*",
    "*segment.io*",
    "*heap.io*",
    "*heapanalytics.com*",
    "*kissmetrics.com*",
    "*optimizely.com*",
    "*quantserve.com*",
    "*scorecardresearch.com*",
    "*newrelic.com*",
    "*nr-data.net*",
    "*bugsnag.com*",
    "*sentry.io/api*",
    "*clarity.ms*",
    "*matomo.*piwik*",
    "*plausible.io*",
    "*intercom.io*",
    "*drift.com*",
    "*hubspot.com/analytics*",
    "*pardot.com*",
    "*marketo.com*",
    "*eloqua.com*",
    "*omtrdc.net*",
    "*demdex.net*",
    "*2o7.net*",
    "*bluekai.com*",
    "*exelator.com*",
    "*krxd.net*",
    "*rlcdn.com*",
    "*tapad.com*",
    "*agkn.com*",
    "*adsymptotic.com*",
    "*branch.io*",
    "*adjust.com*",
    "*appsflyer.com*",
    "*kochava.com*",
    "*singular.net*",
];

static TRACKER_DOMAINS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "hotjar.com",
    "fullstory.com",
    "mouseflow.com",
    "crazyegg.com",
    "mixpanel.com",
    "amplitude.com",
    "segment.com",
    "heapanalytics.com",
    "kissmetrics.com",
    "optimizely.com",
    "quantserve.com",
    "scorecardresearch.com",
    "newrelic.com",
    "nr-data.net",
    "clarity.ms",
    "intercom.io",
    "drift.com",
    "bluekai.com",
    "exelator.com",
    "krxd.net",
    "rlcdn.com",
    "tapad.com",
    "branch.io",
    "adjust.com",
    "appsflyer.com",
];

// ─────────────────────────────────────────────────────────────────────────────
// Crypto miner patterns
// ─────────────────────────────────────────────────────────────────────────────

static MINER_PATTERNS: &[&str] = &[
    "*coinhive.com*",
    "*coin-hive.com*",
    "*cryptoloot.pro*",
    "*crypto-loot.com*",
    "*jsecoin.com*",
    "*authedmine.com*",
    "*minero.cc*",
    "*coinimp.com*",
    "*ppoi.org*",
    "*coinlab.biz*",
    "*webminepool.com*",
    "*monerominer.rocks*",
    "*2giga.link/hive*",
    "*hashforcash.us*",
];

static MINER_DOMAINS: &[&str] = &[
    "coinhive.com",
    "coin-hive.com",
    "cryptoloot.pro",
    "crypto-loot.com",
    "jsecoin.com",
    "authedmine.com",
    "minero.cc",
    "coinimp.com",
    "webminepool.com",
];

// ─────────────────────────────────────────────────────────────────────────────
// Social media tracking (Facebook, Twitter, LinkedIn widgets)
// ─────────────────────────────────────────────────────────────────────────────

static SOCIAL_PATTERNS: &[&str] = &[
    "*site-32.example/widgets*",
    "*site-16.example*",
    "*connect.facebook.net*",
    "*site-13.example*",
    "*apis.google.com/js/plusone*",
    "*static.addtoany.com*",
    "*s7.addthis.com*",
    "*sharethis.com*",
    "*site-22.example/js/pinit*",
    "*snap.licdn.com*",
    "*site-31.example/embed*",
    "*site-24.example/buttons*",
    "*disqus.com/embed*",
    "*disquscdn.com*",
];

static SOCIAL_DOMAINS: &[&str] = &[
    "addtoany.com",
    "addthis.com",
    "sharethis.com",
    "disqus.com",
    "disquscdn.com",
];

// ─────────────────────────────────────────────────────────────────────────────
// ClearURLs — tracking parameters to strip
// ─────────────────────────────────────────────────────────────────────────────

static TRACKING_PARAMS: &[&str] = &[
    // Google
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_source_platform", "utm_creative_format", "utm_marketing_tactic",
    "gclid", "gclsrc", "dclid", "gbraid", "wbraid",
    // Facebook
    "fbclid", "fb_action_ids", "fb_action_types", "fb_ref", "fb_source",
    // Microsoft
    "msclkid",
    // HubSpot
    "hsa_cam", "hsa_grp", "hsa_mt", "hsa_src", "hsa_ad", "hsa_acc",
    "hsa_net", "hsa_ver", "hsa_la", "hsa_ol", "hsa_kw",
    // Mailchimp
    "mc_cid", "mc_eid",
    // Adobe
    "s_cid", "ef_id",
    // General
    "ref", "_ref", "ref_", "referrer",
    "source", "click_id", "campaign_id",
    "zanpid", "irclickid", "irgwc",
    // Yandex
    "yclid", "ymclid", "_openstat",
    // TikTok
    "ttclid",
    // Twitter/X
    "twclid",
    // Snapchat
    "ScCid", "sccid",
    // Pinterest
    "epik",
    // Wicked Reports
    "wickedid",
];

// ─────────────────────────────────────────────────────────────────────────────
// Fingerprint protection JavaScript (inject before page load)
// ─────────────────────────────────────────────────────────────────────────────

static FINGERPRINT_PROTECT_JS: &str = r#"
// Canvas fingerprint protection — add noise to canvas readback
const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    const ctx = this.getContext('2d');
    if (ctx) {
        const imageData = ctx.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] ^= 1;     // R: flip LSB
        }
        ctx.putImageData(imageData, 0, 0);
    }
    return origToDataURL.apply(this, arguments);
};

// WebGL fingerprint protection — randomize renderer/vendor
const origGetParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 0x1F00) return 'Tallow WebGL';    // VENDOR
    if (param === 0x1F01) return 'Tallow Renderer';  // RENDERER
    if (param === 0x9246) return 'Tallow';           // UNMASKED_VENDOR
    if (param === 0x9247) return 'Tallow GPU';       // UNMASKED_RENDERER
    return origGetParameter.apply(this, arguments);
};

// AudioContext fingerprint protection
const origCreateOscillator = AudioContext.prototype.createOscillator;
if (origCreateOscillator) {
    AudioContext.prototype.createOscillator = function() {
        const osc = origCreateOscillator.apply(this, arguments);
        osc.frequency.value += (Math.random() - 0.5) * 0.01;
        return osc;
    };
}

// Battery API — hide
if (navigator.getBattery) {
    navigator.getBattery = undefined;
}

// Normalizers. Each redefines a property the browser may have made
// non-configurable; a throw here aborts the whole init script, so the
// evasions after it never run and `on_error` reports an exception the page
// never caused. Swallow the failure instead: the property keeps its real
// (already plausible) value, which is the correct outcome.
function __tallowNormalize(target, prop, value) {
    try {
        Object.defineProperty(target, prop, { get: () => value, configurable: true });
    } catch (e) {
        // non-configurable — leave the real value in place
    }
}

__tallowNormalize(navigator, 'hardwareConcurrency', 4);
__tallowNormalize(navigator, 'deviceMemory', 8);
__tallowNormalize(screen, 'colorDepth', 24);
"#;

// ─────────────────────────────────────────────────────────────────────────────
// Popup blocker JavaScript
// ─────────────────────────────────────────────────────────────────────────────

static POPUP_BLOCK_JS: &str = r#"
// Block window.open popups not triggered by user action
const origOpen = window.open;
window.open = function() {
    if (!window._tallowUserAction) {
        console.log('[Tallow] Popup blocked');
        return null;
    }
    return origOpen.apply(this, arguments);
};
document.addEventListener('click', () => { window._tallowUserAction = true; setTimeout(() => { window._tallowUserAction = false; }, 1000); });
document.addEventListener('submit', () => { window._tallowUserAction = true; setTimeout(() => { window._tallowUserAction = false; }, 1000); });
"#;

// ─────────────────────────────────────────────────────────────────────────────
// Cookie auto-block JavaScript
// ─────────────────────────────────────────────────────────────────────────────

static COOKIE_BLOCK_JS: &str = r#"
// Block third-party cookies and tracking cookies
const origSetCookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
Object.defineProperty(document, 'cookie', {
    set: function(val) {
        const name = val.split('=')[0].trim().toLowerCase();
        const blocked = ['_ga','_gid','_gat','_fbp','_fbc','_gcl_au','_uetsid','_uetvid','fr','xs','sb','datr','c_user','_pin_unauth','IDE','DSID','FLC','AID','TAID','exchange_uid','personalization_id'];
        if (blocked.some(b => name.startsWith(b))) {
            console.log('[Tallow] Cookie blocked: ' + name);
            return;
        }
        origSetCookie.set.call(this, val);
    },
    get: function() { return origSetCookie.get.call(this); }
});
"#;

// ─────────────────────────────────────────────────────────────────────────────
// Cosmetic ad hiding CSS (inject into pages)
// ─────────────────────────────────────────────────────────────────────────────

static AD_COSMETIC_JS: &str = r#"
// Cosmetic ad hiding — hide common ad containers via CSS
const style = document.createElement('style');
style.textContent = `
    [id*="google_ads"], [id*="ad-container"], [id*="ad_container"],
    [class*="ad-banner"], [class*="ad_banner"], [class*="adsbygoogle"],
    [class*="ad-slot"], [class*="ad_slot"], [class*="sponsored"],
    [data-ad], [data-ad-slot], [data-google-query-id],
    iframe[src*="doubleclick"], iframe[src*="googlesyndication"],
    ins.adsbygoogle, .ad-wrapper, .ad-unit, .ad-zone, .ad-block,
    .advertisement, #advertisement, .ad-placeholder, .ad-leaderboard,
    .ad-sidebar, .ad-footer, .ad-header, .ad-top, .ad-bottom,
    div[aria-label="advertisement"], div[aria-label="Advertisement"],
    .dfp-ad, .gpt-ad, .outbrain-widget, .taboola-widget,
    #taboola-below-article, #outbrain-widget, .promoted-content,
    .sponsored-content, .native-ad, .partner-content
    { display: none !important; visibility: hidden !important; height: 0 !important; overflow: hidden !important; }
`;
if (document.head) document.head.appendChild(style);
else document.addEventListener('DOMContentLoaded', () => document.head.appendChild(style));
"#;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 { return text == pattern; }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() { continue; }
        if let Some(found) = text[pos..].find(part) {
            if i == 0 && found != 0 { return false; }
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}

fn extract_domain(url: &str) -> Option<&str> {
    let after_scheme = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let domain = after_scheme.split('/').next()?;
    let domain = domain.split(':').next()?;
    Some(domain)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// True when the authority part of a URL points at loopback, a private
/// network, or a `.local` name — hosts HTTPS Everywhere must not rewrite.
///
/// `authority` is everything after `http://`: `host[:port][/path…]`, possibly
/// with `user:pass@`. IPv6 literals keep their brackets.
fn is_local_or_private_host(authority: &str) -> bool {
    // Drop path/query/fragment, then userinfo, then the port.
    let host_port = authority.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = host_port.rsplit('@').next().unwrap_or(host_port);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest) // [::1]:8080
    } else if host_port.matches(':').count() == 1 {
        host_port.split(':').next().unwrap_or(host_port)
    } else {
        host_port
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
        return true;
    }
    // Parse, do not pattern-match octets: "127.0.0.1.example.com" has four
    // numeric-looking labels and is not an address.
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback() || v4.is_private() || v4.is_link_local();
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        let first = v6.segments()[0];
        return v6.is_loopback()
            || (first & 0xfe00) == 0xfc00 // fc00::/7 unique-local
            || (first & 0xffc0) == 0xfe80; // fe80::/10 link-local
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_plugins() {
        let p = BrowserPlugins::default();
        assert!(p.adblock);
        assert!(p.tracker_block);
        assert!(p.https_everywhere);
        assert!(!p.noscript);
        assert!(p.clear_urls);
        assert!(p.fingerprint_protect);
        assert!(p.popup_block);
        assert!(p.miner_block);
        assert!(p.social_block);
    }

    #[test]
    fn block_ad_urls() {
        let p = BrowserPlugins::default();
        assert!(p.should_block_url("https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"));
        assert!(p.should_block_url("https://www.googleadservices.com/pagead/conversion/"));
        assert!(p.should_block_url("https://ad.doubleclick.net/ddm/"));
        assert!(p.should_block_url("https://cdn.taboola.com/libtrc/"));
        assert!(p.should_block_url("https://outbrain.com/widget/"));
    }

    #[test]
    fn block_tracker_urls() {
        let p = BrowserPlugins::default();
        assert!(p.should_block_url("https://www.google-analytics.com/analytics.js"));
        assert!(p.should_block_url("https://www.googletagmanager.com/gtm.js"));
        assert!(p.should_block_url("https://connect.facebook.net/en_US/fbevents.js"));
        assert!(p.should_block_url("https://static.hotjar.com/c/hotjar.js"));
        assert!(p.should_block_url("https://cdn.segment.com/analytics.js"));
    }

    #[test]
    fn block_miner_urls() {
        let p = BrowserPlugins::default();
        assert!(p.should_block_url("https://coinhive.com/lib/coinhive.min.js"));
        assert!(p.should_block_url("https://authedmine.com/miner.js"));
    }

    #[test]
    fn allow_normal_urls() {
        let p = BrowserPlugins::default();
        assert!(!p.should_block_url("https://www.google.com/search?q=test"));
        assert!(!p.should_block_url("https://example.com/index.html"));
        assert!(!p.should_block_url("https://cdn.jsdelivr.net/npm/lodash@4/lodash.min.js"));
        assert!(!p.should_block_url("https://api.github.com/repos"));
    }

    #[test]
    fn clean_tracking_params() {
        let p = BrowserPlugins::default();
        assert_eq!(
            p.clean_url("https://example.com/page?utm_source=google&utm_medium=cpc&id=123"),
            "https://example.com/page?id=123"
        );
        assert_eq!(
            p.clean_url("https://example.com/page?fbclid=abc123"),
            "https://example.com/page"
        );
        assert_eq!(
            p.clean_url("https://example.com/page?gclid=xyz&q=search&msclkid=abc"),
            "https://example.com/page?q=search"
        );
        // No tracking params — unchanged
        assert_eq!(
            p.clean_url("https://example.com/page?q=test&page=2"),
            "https://example.com/page?q=test&page=2"
        );
    }

    #[test]
    fn force_https() {
        let p = BrowserPlugins::default();
        assert_eq!(p.force_https("http://example.com"), "https://example.com");
        assert_eq!(p.force_https("https://example.com"), "https://example.com");
    }

    #[test]
    fn force_https_leaves_loopback_and_private_hosts_alone() {
        let p = BrowserPlugins::default();
        for url in [
            "http://127.0.0.1:18101/",
            "http://localhost:8080/x?y=1",
            "http://[::1]:9000/",
            "http://10.1.2.3/",
            "http://192.168.1.10/",
            "http://172.16.0.5/",
            "http://172.31.255.1/",
            "http://169.254.1.1/",
            "http://printer.local/",
            "http://user:pass@127.0.0.1:3000/",
        ] {
            assert_eq!(p.force_https(url), url, "{url} must not be upgraded");
        }
        // Public hosts still upgrade, including ones that merely look close.
        assert_eq!(p.force_https("http://172.32.0.1/"), "https://172.32.0.1/");
        assert_eq!(p.force_https("http://127.0.0.1.example.com/"), "https://127.0.0.1.example.com/");
    }

    #[test]
    fn no_plugins() {
        let p = BrowserPlugins::none();
        assert!(!p.should_block_url("https://googlesyndication.com/ad.js"));
        assert_eq!(p.clean_url("https://example.com?utm_source=test"), "https://example.com?utm_source=test");
        assert_eq!(p.force_https("http://example.com"), "http://example.com");
    }

    #[test]
    fn max_privacy_blocks_everything() {
        let p = BrowserPlugins::max_privacy();
        assert!(p.noscript);
        assert!(p.cookie_autoblock);
        let patterns = p.blocked_patterns();
        assert!(patterns.len() > 100);
        let domains = p.blocked_domains();
        assert!(domains.len() > 50);
    }

    #[test]
    fn summary() {
        let p = BrowserPlugins::default();
        let s = p.summary();
        assert!(s.contains("AdBlock"));
        assert!(s.contains("TrackerBlock"));
        assert!(s.contains("HTTPS-Everywhere"));
        assert!(!s.contains("NoScript")); // off by default
    }

    #[test]
    fn injection_script_non_empty() {
        let p = BrowserPlugins::default();
        let js = p.injection_script();
        assert!(js.contains("Canvas fingerprint"));
        assert!(js.contains("Popup blocked"));
        assert!(js.contains("display: none"));
        // Layer 2: element removal
        assert!(js.contains("MutationObserver"));
        assert!(js.contains("Tallow: element removal"));
        // Layer 3: network blocking
        assert!(js.contains("Tallow: network request blocking"));
        assert!(js.contains("window.fetch"));
        assert!(js.contains("XMLHttpRequest.prototype.open"));
    }

    #[test]
    fn injection_script_network_blocking_includes_blocked_domains() {
        let p = BrowserPlugins::default();
        let js = p.injection_script();
        // Known blocked domains must appear in the network block script
        assert!(js.contains("google-analytics.com"));
        assert!(js.contains("googlesyndication.com"));
        assert!(js.contains("hotjar.com"));
    }

    #[test]
    fn analytics_pac_blocks_analytics_routes_egress() {
        let pac = analytics_blocking_pac("SOCKS5 127.0.0.1:9050");
        // PAC entry point + dead-proxy block for the analytics domains.
        assert!(pac.contains("FindProxyForURL"));
        assert!(pac.contains("dnsDomainIs(host, \"clarity.ms\")"));
        assert!(pac.contains("dnsDomainIs(host, \"sentry.io\")"));
        assert!(pac.contains("dnsDomainIs(host, \"googletagmanager.com\")"));
        assert!(pac.contains("PROXY 127.0.0.1:9"));
        // Everything else routes through the given egress (Tor SOCKS5).
        assert!(pac.contains("SOCKS5 127.0.0.1:9050"));
        // Google reCAPTCHA host is intentionally NOT PAC-blocked (would break too much).
        assert!(!pac.contains("dnsDomainIs(host, \"google.com\")"));
    }

    #[test]
    fn injection_script_none_has_no_blocking() {
        let p = BrowserPlugins::none();
        let js = p.injection_script();
        // No plugin blocking layers active — but the analytics/session-replay
        // kill layer (MS Clarity/Sentry/GTM stubs + its MutationObserver) is
        // always applied as a baseline privacy layer, so a MutationObserver IS
        // present. What must NOT be present is the plugin-level ad/tracker
        // network blocking (fetch/XHR overrides) and element removal.
        assert!(js.contains("MutationObserver"));
        assert!(js.contains("window.clarity"));
        assert!(!js.contains("window.fetch"));
        assert!(!js.contains("XMLHttpRequest.prototype.open"));
        assert!(!js.contains("BLOCKED_DOMAINS"));
    }

    #[test]
    fn element_removal_js_contains_observer_and_domains() {
        let p = BrowserPlugins::default();
        let js = p.element_removal_js();
        assert!(js.contains("MutationObserver"));
        assert!(js.contains("isDomainBlocked"));
        assert!(js.contains("removeIfBlocked"));
        // At least one domain from the blocked set
        assert!(js.contains("doubleclick.net") || js.contains("googlesyndication.com"));
    }

    #[test]
    fn network_block_js_overrides_fetch_and_xhr() {
        let p = BrowserPlugins::default();
        let js = p.network_block_js();
        assert!(js.contains("window.fetch"));
        assert!(js.contains("origFetch"));
        assert!(js.contains("XMLHttpRequest.prototype.open"));
        assert!(js.contains("XMLHttpRequest.prototype.send"));
        assert!(js.contains("_tallowBlocked"));
    }

    #[test]
    fn element_removal_js_empty_when_all_blocked_domains_empty() {
        let p = BrowserPlugins::none();
        let js = p.element_removal_js();
        // None active means no blocked domains, so JS should be empty
        assert!(js.is_empty());
    }

    #[test]
    fn social_blocking() {
        let p = BrowserPlugins::default();
        assert!(p.should_block_url("https://site-32.example/widgets.js"));
        assert!(p.should_block_url("https://connect.facebook.net/en_US/sdk.js"));
        assert!(p.should_block_url("https://disqus.com/embed/comments/"));
    }
}
