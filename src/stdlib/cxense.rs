//! Standard library: `tallow.cxense` — Cxense-metered paywall bypass client.
//!
//! Cxense (Piano) meters news paywalls (WSJ, Barron's, MarketWatch, The Atlantic,
//! The New Yorker, Foreign Policy, etc.) with a CLIENT-SIDE meter: the full
//! article is already in the served HTML, but Cxense JS (cdn.cxense.com) gates it
//! with a CSS overlay after a free-article quota.
//!
//! ## Bypass Vectors (researched Aug 2026)
//!
//! 1. **Meter-cookie reset** — clear `cX_P`/`cX_C`/`_cX_`/`cX_G`/`cX_S` cookies to
//!    reset the free-article counter (the meter is keyed to cookies the client
//!    controls).
//! 2. **Referrer whitelist** — send a heavy-traffic referrer (drudgereport.com for
//!    WSJ/Dow Jones; site-28.example for social; news.google.com) so the server serves the
//!    full body ungated.
//! 3. **Block Cxense JS** — strip `cdn.cxense.com` + `cdn.ampproject.org` scripts
//!    so the meter overlay never runs.
//! 4. **JSON-LD articleBody leak** — many Cxense sites (WSJ included) embed the
//!    FULL article body in `NewsArticle.articleBody` / `@graph` for SEO even when
//!    the rendered DOM is blurred/gated.
//!
//! NOTE: WSJ also has DataDome at the edge — from datacenter IPs it returns a
//! CAPTCHA before origin. Use `stealth_http` / the tallow-reader daemon for that;
//! this module handles the METER once origin is reached.

use super::StdlibResult;
use crate::interp::Value;

use std::sync::LazyLock;
use std::time::Duration;

// ─── Shared HTTP agent ───────────────────────────────────────────

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    crate::runtime::egress_http::agent_with_timeouts(Some(Duration::from_secs(60)), Some(Duration::from_secs(30)))
});

const DESKTOP_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
const GOOGLEBOT_UA: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

// Whitelisted heavy-traffic referrers (server-side meter bypass).
const REFERRERS: &[(&str, &str)] = &[
    ("drudge", "https://www.drudgereport.com/"),
    ("social", "https://site-28.example/reader"),
    ("google", "https://news.google.com/"),
    ("google_web", "https://www.google.com/"),
    ("facebook", "https://site-09.example/"),
    ("hn", "https://site-20.example/"),
];

fn referrer_for(style: &str) -> &'static str {
    REFERRERS
        .iter()
        .find(|(k, _)| *k == style)
        .map(|(_, v)| *v)
        .unwrap_or("https://www.google.com/")
}

// Cxense meter-cookie name fragments to strip before fetching.
const METER_COOKIE_FRAGS: &[&str] = &["cX_P", "cX_C", "cX_G", "cX_S", "_cX_", "cX_"];

fn is_dowjones(url: &str) -> bool {
    ["site-34.example", "marketwatch.com", "barrons.com", "dowjones.com"]
        .iter()
        .any(|d| url.contains(d))
}

fn is_cxense_site(url: &str) -> bool {
    [
        "theatlantic.com",
        "newyorker.com",
        "foreignpolicy.com",
        "foreignaffairs.com",
        "courant.com",
        "chicagotribune.com",
        "nypost.com",
        "theglobeandmail.com",
    ]
    .iter()
    .any(|d| url.contains(d))
}

fn default_style(url: &str) -> &'static str {
    if is_dowjones(url) {
        "drudge"
    } else {
        "google"
    }
}

fn should_use_googlebot(url: &str) -> bool {
    !is_dowjones(url) && is_cxense_site(url)
}

// ─── Dispatch ────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "get_article" => Some(cxense_get_article(args)),
        "get_with_referrer" => Some(cxense_get_with_referrer(args)),
        "extract_jsonld" => Some(cxense_extract_jsonld(args)),
        "reset_meter" => Some(cxense_reset_meter(args)),
        "referrer_map" => Some(cxense_referrer_map(args)),
        _ => None,
    }
}

pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

// ─── Helpers ─────────────────────────────────────────────────────

fn arg_str(args: &[Value], idx: usize, name: &str) -> Result<String, String> {
    args.get(idx)
        .map(|v| v.as_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("cxense.{name}: argument {idx} must be a non-empty string"))
}

fn build_result_map(fields: Vec<(&str, String)>) -> Value {
    let map: Vec<(Value, Value)> = fields
        .into_iter()
        .map(|(k, v)| (Value::String(k.to_string()), Value::String(v)))
        .collect();
    Value::Map(map)
}

fn fetch(url: &str, referer: &str, ua: &str, cookie_header: &str) -> Result<String, String> {
    let mut req = AGENT.get(url).header("User-Agent", ua).header("Referer", referer);
    if !cookie_header.is_empty() {
        req = req.header("Cookie", cookie_header);
    }
    let resp = req.call().map_err(|e| format!("HTTP GET {url}: {e}"))?;
    resp.into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read body: {e}"))
}

/// Reset Cxense meter cookies from a Cookie header (strip cX_* counters).
fn reset_meter_cookies(cookie_header: &str) -> String {
    if cookie_header.is_empty() {
        return String::new();
    }
    cookie_header
        .split(';')
        .map(str::trim)
        .filter(|p| {
            let name = p.split('=').next().unwrap_or("").trim();
            !METER_COOKIE_FRAGS.iter().any(|f| name.starts_with(f))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Extract the full article body from JSON-LD (`NewsArticle.articleBody` or
/// `@graph[]`). Returns (title, body).
fn extract_jsonld_body(html: &str) -> (String, String) {
    let mut best = String::new();
    let mut title = String::new();
    let mut pos = 0usize;
    while let Some(rel) = html[pos..].find("<script type=\"application/ld+json\">") {
        let start = pos + rel + "<script type=\"application/ld+json\">".len();
        let end = match html[start..].find("</script>") {
            Some(i) => start + i,
            None => break,
        };
        let raw = &html[start..end];
        if let Ok(serde_json::Value::Object(root)) = serde_json::from_str::<serde_json::Value>(raw) {
            // flatten @graph + single object
            let mut nodes: Vec<&serde_json::Map<String, serde_json::Value>> = Vec::new();
            if let Some(graph) = root.get("@graph").and_then(|g| g.as_array()) {
                for g in graph {
                    if let Some(o) = g.as_object() {
                        nodes.push(o);
                    }
                }
            }
            nodes.push(&root);
            for node in nodes {
                let body = node
                    .get("articleBody")
                    .or_else(|| node.get("articleBodyPlainText"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let body = body.trim();
                if body.len() >= 300 && body.len() > best.len() {
                    best = body.to_string();
                    if let Some(t) = node.get("headline").and_then(|v| v.as_str()) {
                        title = t.to_string();
                    } else if let Some(t) = node.get("name").and_then(|v| v.as_str()) {
                        title = t.to_string();
                    }
                }
            }
        }
        pos = end + "</script>".len();
    }
    (title, best)
}

// ─── API Functions ───────────────────────────────────────────────

/// cxense.get_article(url: str, cookie_header?: str) -> Map
///
/// Extract a Cxense-metered article. Tries every whitelisted referrer in order
/// (drudge/social/google/facebook/hn), with a JSON-LD articleBody check first
/// (the strongest vector) then a full-HTML body grab. Returns the best result.
fn cxense_get_article(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_article")?;
    let incoming_cookies = args.get(1).map(|v| v.as_string()).unwrap_or_default();
    let style = default_style(&url);
    // order referrers: primary style first, then the rest
    let mut order = vec![style.to_string()];
    for (k, _) in REFERRERS {
        if *k != style && !order.iter().any(|o| o == k) {
            order.push(k.to_string());
        }
    }

    let ua = if should_use_googlebot(&url) { GOOGLEBOT_UA } else { DESKTOP_UA };
    let mut best_fields: Option<Value> = None;
    let mut best_len = 0usize;
    let mut tried: Vec<String> = Vec::new();

    for st in &order {
        let refr = referrer_for(st).to_string();
        let cookie_header = reset_meter_cookies(&incoming_cookies);
        tried.push(st.clone());
        let html = match fetch(&url, &refr, ua, &cookie_header) {
            Ok(h) => h,
            Err(_) => continue,
        };
        // 1) JSON-LD articleBody leak
        let (jl_title, jl_body) = extract_jsonld_body(&html);
        if jl_body.len() >= 300 && jl_body.len() > best_len {
            best_len = jl_body.len();
            let mut f: Vec<(&str, String)> = Vec::new();
            f.push(("title", jl_title));
            f.push(("full_text", jl_body));
            f.push(("method", format!("jsonld-articlebody ({st})")));
            f.push(("referrer_used", refr.clone()));
            f.push(("has_paywall", "false".to_string()));
            best_fields = Some(build_result_map(f));
        }
        // 2) strip paywall scripts/nodes then grab body text
        let stripped = strip_paywall_scripts(&html);
        let body = extract_body_text(&stripped);
        if body.len() >= 300 && body.len() > best_len {
            best_len = body.len();
            let title = extract_meta(&html, "title").unwrap_or_default();
            let mut f: Vec<(&str, String)> = Vec::new();
            f.push(("title", title));
            f.push(("full_text", body.clone()));
            f.push(("method", format!("meter-strip ({st})")));
            f.push(("referrer_used", refr));
            f.push(("has_paywall", (body.contains("Subscribe") && body.len() < 500).to_string()));
            best_fields = Some(build_result_map(f));
        }
    }

    if let Some(v) = best_fields {
        let mut out = fields_to_map(vec![
            ("url", url),
            ("wordcount", best_len.to_string()),
            ("referrers_tried", tried.join(",")),
        ]);
        if let Value::Map(ref mut m) = out {
            m.push((Value::String("result".into()), v));
        }
        return Ok(out);
    }

    let mut f: Vec<(&str, String)> = Vec::new();
    f.push(("error", "all referrers blocked or no readable content".to_string()));
    f.push(("url", url));
    f.push(("referrers_tried", tried.join(",")));
    Ok(build_result_map(f))
}

/// cxense.get_with_referrer(url: str, referrer_style: str) -> Map
///
/// Fetch with one explicit referrer style ("drudge"|"social"|"google"|"facebook"|"hn").
fn cxense_get_with_referrer(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_with_referrer")?;
    let style = arg_str(&args, 1, "get_with_referrer").unwrap_or_else(|_| default_style(&url).to_string());
    let refr = referrer_for(&style).to_string();
    let ua = if should_use_googlebot(&url) { GOOGLEBOT_UA } else { DESKTOP_UA };
    match fetch(&url, &refr, ua, "") {
        Ok(html) => {
            let (jl_title, jl_body) = extract_jsonld_body(&html);
            let body = if jl_body.len() >= 300 { jl_body } else { extract_body_text(&strip_paywall_scripts(&html)) };
            let mut f: Vec<(&str, String)> = Vec::new();
            f.push(("title", if jl_title.is_empty() { extract_meta(&html, "title").unwrap_or_default() } else { jl_title }));
            f.push(("full_text", body));
            f.push(("method", format!("referrer-{style}")));
            f.push(("referrer_used", refr));
            Ok(build_result_map(f))
        }
        Err(e) => {
            let mut f: Vec<(&str, String)> = Vec::new();
            f.push(("error", e));
            f.push(("url", url));
            f.push(("referrer_used", refr));
            Ok(build_result_map(f))
        }
    }
}

/// cxense.extract_jsonld(url: str) -> Map
///
/// Pure JSON-LD `articleBody` extraction for a URL (no referrer tricks).
fn cxense_extract_jsonld(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "extract_jsonld")?;
    let ua = if should_use_googlebot(&url) { GOOGLEBOT_UA } else { DESKTOP_UA };
    match fetch(&url, referrer_for(default_style(&url)), ua, "") {
        Ok(html) => {
            let (title, body) = extract_jsonld_body(&html);
            let found = !body.is_empty();
            let mut f: Vec<(&str, String)> = Vec::new();
            f.push(("title", title));
            f.push(("full_text", body));
            f.push(("found", found.to_string()));
            Ok(build_result_map(f))
        }
        Err(e) => {
            let mut f: Vec<(&str, String)> = Vec::new();
            f.push(("error", e));
            Ok(build_result_map(f))
        }
    }
}

/// cxense.reset_meter() -> Map
///
/// Instructions for clearing the Cxense meter-cookie quota.
fn cxense_reset_meter(_args: Vec<Value>) -> StdlibResult {
    let mut f: Vec<(&str, String)> = Vec::new();
    f.push(("method", "cookie_reset".to_string()));
    f.push(("cookies_to_clear", "cX_P, cX_C, cX_G, cX_S, _cX_*".to_string()));
    f.push(("instruction", "Clear Cxense cookies (cX_P/cX_C/_cX_*) for the publisher domain, then reload. Meter resets to a fresh free-article quota.".to_string()));
    f.push(("alternative_1", "Open in private/incognito window".to_string()));
    f.push(("alternative_2", "Use drudgereport/site-28.example/news.google.com referrer".to_string()));
    f.push(("note", "WSJ + Dow Jones family: desktop Chrome UA + drudgereport referrer; Googlebot does NOT bypass site-34.example. DataDome at the edge needs stealth_http / tallow-reader.".to_string()));
    Ok(build_result_map(f))
}

/// cxense.referrer_map() -> Map
///
/// The whitelisted referrer styles available to `get_with_referrer`.
fn cxense_referrer_map(_args: Vec<Value>) -> StdlibResult {
    let mut f: Vec<(&str, String)> = Vec::new();
    for (k, v) in REFERRERS {
        f.push((k, v.to_string()));
    }
    Ok(build_result_map(f))
}

// ─── HTML helpers ────────────────────────────────────────────────

fn fields_to_map(fields: Vec<(&str, String)>) -> Value {
    build_result_map(fields)
}

fn extract_meta(html: &str, property: &str) -> Option<String> {
    for pat in &[
        format!("property=\"{property}\" content=\""),
        format!("name=\"{property}\" content=\""),
    ] {
        if let Some(start) = html.find(pat) {
            let after = &html[start + pat.len()..];
            if let Some(end) = after.find('"') {
                return Some(unescape_html(&after[..end]));
            }
        }
    }
    None
}

fn strip_paywall_scripts(html: &str) -> String {
    // Remove <script ... cdn.cxense.com ...>, AMP-subscription, and paywall-meter scripts.
    let frags = [
        "cdn.cxense.com", "cdn.ampproject.org", "tinypass.com", "zephr.com",
        "piano.io", "metering", "paywall", "snippet-promotion",
    ];
    let mut out = html.to_string();
    for frag in frags {
        let mut pos = 0usize;
        while let Some(rel) = out[pos..].find(frag) {
            // find enclosing <script ...>...</script>
            let mid = pos + rel;
            let open_start = out[..mid].rfind("<script").unwrap_or(0);
            let open_end = match out[open_start..].find('>') {
                Some(i) => open_start + i + 1,
                None => break,
            };
            let close = match out[open_end..].find("</script>") {
                Some(i) => open_end + i,
                None => break,
            };
            out.replace_range(open_start..close + "</script>".len(), "");
            pos = open_start;
        }
    }
    out
}

fn extract_body_text(html: &str) -> String {
    // Crude but robust: strip script/style, take <p> paragraphs.
    let mut cleaned = html.to_string();
    let mut pos = 0usize;
    // strip <script...>...</script>
    loop {
        let s = cleaned[pos..].find("<script");
        let Some(s) = s else { break };
        let s = pos + s;
        let e = match cleaned[s..].find("</script>") {
            Some(i) => s + i + "</script>".len(),
            None => break,
        };
        cleaned.replace_range(s..e, "");
        pos = s;
    }
    pos = 0;
    loop {
        let s = cleaned[pos..].find("<style");
        let Some(s) = s else { break };
        let s = pos + s;
        let e = match cleaned[s..].find("</style>") {
            Some(i) => s + i + "</style>".len(),
            None => break,
        };
        cleaned.replace_range(s..e, "");
        pos = s;
    }
    let mut paragraphs = Vec::new();
    pos = 0;
    while let Some(rel) = cleaned[pos..].find("<p") {
        let start = pos + rel;
        let tag_end = match cleaned[start..].find('>') {
            Some(i) => start + i + 1,
            None => break,
        };
        let close = match cleaned[tag_end..].find("</p>") {
            Some(i) => tag_end + i,
            None => break,
        };
        let text = strip_tags(&cleaned[tag_end..close]);
        if text.len() > 20 {
            paragraphs.push(text);
        }
        pos = close + 4;
    }
    paragraphs.join("\n")
}

fn strip_tags(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => { in_tag = false; result.push(' '); }
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    result.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn unescape_html(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}
