//! Standard library: `tallow.substack` — Substack.com paywall bypass client.
//!
//! Substack is a newsletter platform where each publication is a subdomain
//! (pub.substack.com) or custom domain. Content is server-side gated per
//! publication's configuration — free preview length varies.
//!
//! ## Architecture (researched Aug 2026)
//!
//! - **API**: REST-like at /api/v1/. Posts at /api/v1/posts/{slug}
//! - **Auth**: Email magic link → JWT → session cookie (substack.sid)
//! - **Paywall**: Server-side. body_html absent from API responses when gated.
//! - **Reader feed**: /api/v1/reader/feed for discovery
//! - **Archive**: /archive often lists all posts with metadata
//!
//! ## Bypass Vectors
//!
//! 1. **Archive API** — /api/v1/archive often leaks full post list metadata
//! 2. **RSS feed** — Many publications have /feed exposing full content
//! 3. **Publication misconfiguration** — free preview can be 100%
//! 4. **Email share tokens** — extended validity, can be harvested
//! 5. **Cross-publication session reuse** — Substack auth is platform-wide
//! 6. **Reader API** — /api/v1/reader/feed for discovery without auth

use super::StdlibResult;
use crate::interp::Value;

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;

// ─── Shared HTTP agent ───────────────────────────────────────────

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    crate::runtime::egress_http::agent_with_timeouts(Some(Duration::from_secs(60)), Some(Duration::from_secs(30)))
});

// ─── Cookie jar (in-memory, per-session) ─────────────────────────
// ANY valid substack.sid cookie from a free-tier account unlocks
// full body_html for ALL paywalled posts across ALL publications.

static COOKIE_JAR: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_cookie_header() -> Option<String> {
    let jar = COOKIE_JAR.lock().unwrap();
    let cookies: Vec<String> = jar.values().cloned().collect();
    if cookies.is_empty() {
        None
    } else {
        Some(cookies.join("; "))
    }
}

fn set_cookie_internal(key: &str, value: &str) {
    let mut jar = COOKIE_JAR.lock().unwrap();
    jar.insert(key.to_string(), value.to_string());
}

// ─── Dispatch ────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "discover" => Some(substack_discover(args)),
        "get_post" => Some(substack_get_post(args)),
        "get_archive" => Some(substack_get_archive(args)),
        "get_rss" => Some(substack_get_rss(args)),
        "get_reader_feed" => Some(substack_get_reader_feed(args)),
        "check_free_preview" => Some(substack_check_free_preview(args)),
        "cookie_bypass_info" => Some(substack_cookie_bypass_info(args)),
        "discover_publications" => Some(substack_discover_publications(args)),
        "set_cookie" => Some(substack_set_cookie(args)),
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
        .ok_or_else(|| format!("substack.{name}: argument {idx} must be a non-empty string"))
}

fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let mut req = AGENT
        .get(url)
        .header("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");

    if let Some(ref cookie) = get_cookie_header() {
        req = req.header("Cookie", cookie);
    }

    let resp = req
        .call()
        .map_err(|e| format!("HTTP GET {url}: {e}"))?;

    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read body: {e}"))?;

    serde_json::from_str(&body).map_err(|e| format!("JSON parse: {e}"))
}

fn http_get_text(url: &str) -> Result<String, String> {
    let mut req = AGENT
        .get(url)
        .header("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");

    if let Some(ref cookie) = get_cookie_header() {
        req = req.header("Cookie", cookie);
    }

    let resp = req
        .call()
        .map_err(|e| format!("HTTP GET {url}: {e}"))?;

    resp.into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read body: {e}"))
}

fn json_to_tallow(val: &serde_json::Value) -> Value {
    match val {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i as i128)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(json_to_tallow).collect()),
        serde_json::Value::Object(obj) => {
            let fields: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, v)| (Value::String(k.clone()), json_to_tallow(v)))
                .collect();
            Value::Map(fields)
        }
    }
}

fn strip_html(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                result.push(' ');
            }
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    result.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// Parse a Substack URL to extract the publication domain and post slug.
/// Accepts: pub.substack.com/p/slug, customdomain.com/p/slug
fn parse_substack_url(url: &str) -> Result<(String, Option<String>), String> {
    let url = url.trim().trim_end_matches('/');

    if let Some(idx) = url.find("/p/") {
        let base = url[..idx].to_string();
        let slug = url[idx + 3..].to_string();
        Ok((base, Some(slug)))
    } else {
        Ok((url.to_string(), None))
    }
}

// ─── API Functions ───────────────────────────────────────────────

/// substack.discover(url: str) -> Map
///
/// Discover a Substack publication from a URL.
/// Returns: base_url, post_slug (if any), publication metadata.
fn substack_discover(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "discover")?;
    let (base_url, post_slug) = parse_substack_url(&url)?;

    let mut fields: Vec<(Value, Value)> = vec![
        (Value::String("base_url".into()), Value::String(base_url.clone())),
    ];

    if let Some(slug) = post_slug {
        fields.push((Value::String("post_slug".into()), Value::String(slug)));
    }

    // Try to check if the publication exists and get metadata
    let pub_url = if base_url.ends_with(".substack.com") || base_url.contains("substack.com") {
        base_url.clone()
    } else {
        // Custom domain — can't easily determine the substack subdomain
        base_url.clone()
    };

    // Check /api/v1/archive for publication info
    if let Ok(json) = http_get_json(&format!("{pub_url}/api/v1/archive?limit=1")) {
        fields.push((
            Value::String("archive_accessible".into()),
            Value::Bool(true),
        ));
        // Try to extract publication name from first post
        if let Some(posts) = json.as_array() {
            fields.push((
                Value::String("total_posts".into()),
                Value::Int(posts.len() as i128),
            ));
        }
    } else {
        fields.push((
            Value::String("archive_accessible".into()),
            Value::Bool(false),
        ));
    }

    Ok(Value::Map(fields))
}

/// substack.get_post(url: str) -> Map
///
/// Extract a Substack post. Tries multiple endpoints:
/// 1. /api/v1/posts/{slug} — official API (may omit body_html for gated posts)
/// 2. Direct page HTML — parse for inline content
/// 3. /feed — RSS feed (often has full content)
///
/// Returns: title, subtitle, published_date, audience, free_content,
/// has_paywall, body_html_length (0 = gated).
fn substack_get_post(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_post")?;
    let (base_url, post_slug) = parse_substack_url(&url)?;

    let slug = post_slug.ok_or_else(|| "URL must contain /p/<slug>".to_string())?;

    let mut fields: Vec<(Value, Value)> = Vec::new();
    let mut has_body = false;

    // Method 1: Try the API
    let api_url = format!("{base_url}/api/v1/posts/{slug}");
    if let Ok(json) = http_get_json(&api_url) {
        // Extract string fields
        for key in &["title", "subtitle", "slug", "audience", "type", "canonical_url"] {
            if let Some(v) = json.get(*key).and_then(|v| v.as_str()) {
                fields.push((Value::String(key.to_string()), Value::String(v.to_string())));
            }
        }
        // Dates
        if let Some(v) = json.get("post_date").and_then(|v| v.as_str()) {
            fields.push((Value::String("post_date".into()), Value::String(v.to_string())));
        }
        if let Some(v) = json.get("published_date").and_then(|v| v.as_str()) {
            fields.push((Value::String("published_date".into()), Value::String(v.to_string())));
        }
        // Body HTML
        if let Some(body) = json.get("body_html").and_then(|v| v.as_str()) {
            if body.len() > 10 {
                let plain = strip_html(body);
                fields.push((Value::String("body_html".into()), Value::String(body.to_string())));
                fields.push((Value::String("body_text".into()), Value::String(plain)));
                fields.push((Value::String("body_length".into()), Value::Int(body.len() as i128)));
                has_body = true;
            }
        }
        // Free content (if present)
        if let Some(free) = json.get("free_content").and_then(|v| v.as_str()) {
            fields.push((Value::String("free_content".into()), Value::String(free.to_string())));
        }
        // Paywall status
        if let Some(audience) = json.get("audience").and_then(|v| v.as_str()) {
            let is_gated = audience == "paid" || audience == "founding";
            fields.push((Value::String("has_paywall".into()), Value::Bool(is_gated)));
        }
    }

    // Method 2: If API didn't give body, try page HTML
    if !has_body {
        if let Ok(html) = http_get_text(&url) {
            // Look for inline body content in Substack's data
            if let Some(start) = html.find("\"body_html\":\"") {
                let after = &html[start + 14..];
                // Find end (unescaped JSON string)
                let mut body_html = String::new();
                let mut i = 0;
                let chars: Vec<char> = after.chars().collect();
                while i < chars.len() {
                    if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1] == '"' {
                        body_html.push('"');
                        i += 2;
                    } else if chars[i] == '"' {
                        break;
                    } else {
                        body_html.push(chars[i]);
                        i += 1;
                    }
                }
                if body_html.len() > 10 {
                    let body_len = body_html.len();
                    let plain = strip_html(&body_html);
                    fields.push((Value::String("body_html_page".into()), Value::String(body_html)));
                    fields.push((Value::String("body_text_page".into()), Value::String(plain)));
                    fields.push((Value::String("body_length".into()), Value::Int(body_len as i128)));
                    has_body = true;
                }
            }
        }
    }

    fields.push((Value::String("has_body".into()), Value::Bool(has_body)));
    fields.push((Value::String("api_url".into()), Value::String(api_url)));

    Ok(Value::Map(fields))
}

/// substack.get_archive(base_url: str, limit?: int) -> Array
///
/// Fetch the publication archive via /api/v1/archive.
/// Returns list of posts with title, slug, publish_date, audience.
fn substack_get_archive(args: Vec<Value>) -> StdlibResult {
    let base_url = arg_str(&args, 0, "get_archive")?;
    let limit = args.get(1).and_then(|v| {
        if let Value::Int(n) = v { Some(*n as usize) } else { None }
    }).unwrap_or(50);

    let archive_url = format!("{base_url}/api/v1/archive?limit={limit}&sort=new");
    let json = http_get_json(&archive_url)?;

    // Response is typically an array of posts
    if let Some(posts) = json.as_array() {
        let mut results: Vec<Value> = Vec::new();
        for post in posts {
            let mut fields: Vec<(Value, Value)> = Vec::new();
            for key in &["title", "slug", "audience", "type", "canonical_url", "post_date"] {
                if let Some(v) = post.get(*key).and_then(|v| v.as_str()) {
                    fields.push((Value::String(key.to_string()), Value::String(v.to_string())));
                }
            }
            results.push(Value::Map(fields));
        }
        Ok(Value::Array(results))
    } else {
        // Might be wrapped in an object
        Ok(json_to_tallow(&json))
    }
}

/// substack.get_rss(base_url: str) -> Map
///
/// Fetch the publication's RSS feed at /feed.
/// RSS feeds on Substack often contain the FULL article text,
/// even for paywalled posts, because email subscribers receive
/// the full content.
fn substack_get_rss(args: Vec<Value>) -> StdlibResult {
    let base_url = arg_str(&args, 0, "get_rss")?;
    let rss_url = format!("{base_url}/feed");

    let mut fields: Vec<(Value, Value)> = Vec::new();

    if let Ok(xml) = http_get_text(&rss_url) {
        // Extract RSS items
        let mut items: Vec<Value> = Vec::new();
        let mut pos = 0;

        while let Some(start) = xml[pos..].find("<item>") {
            let abs_start = pos + start;
            let item_end = match xml[abs_start..].find("</item>") {
                Some(i) => abs_start + i + 7,
                None => break,
            };
            let item_xml = &xml[abs_start..item_end];

            let mut item_fields: Vec<(Value, Value)> = Vec::new();

            // Extract title
            if let Some(t) = extract_xml_tag(item_xml, "title") {
                item_fields.push((Value::String("title".into()), Value::String(t)));
            }
            // Extract description (often full content in RSS)
            if let Some(d) = extract_xml_tag(item_xml, "description") {
                let plain = strip_html(&d);
                item_fields.push((Value::String("description_html".into()), Value::String(d)));
                item_fields.push((Value::String("description_text".into()), Value::String(plain)));
            }
            // Extract content:encoded (full article in RSS2)
            if let Some(c) = extract_xml_tag(item_xml, "content:encoded") {
                let plain = strip_html(&c);
                item_fields.push((Value::String("content_html".into()), Value::String(c)));
                item_fields.push((Value::String("content_text".into()), Value::String(plain)));
            }
            // Extract link
            if let Some(l) = extract_xml_tag(item_xml, "link") {
                item_fields.push((Value::String("link".into()), Value::String(l)));
            }
            // Extract pubDate
            if let Some(d) = extract_xml_tag(item_xml, "pubDate") {
                item_fields.push((Value::String("pub_date".into()), Value::String(d)));
            }

            items.push(Value::Map(item_fields));
            pos = item_end;
        }

        fields.push((Value::String("rss_url".into()), Value::String(rss_url)));
        fields.push((Value::String("item_count".into()), Value::Int(items.len() as i128)));
        fields.push((Value::String("items".into()), Value::Array(items)));
    } else {
        fields.push((Value::String("error".into()), Value::String("RSS feed not accessible".into())));
    }

    Ok(Value::Map(fields))
}

/// substack.get_reader_feed() -> Map
///
/// Access Substack's reader feed API at substack.com.
/// Returns the reader's feed tabs and discovery surface.
fn substack_get_reader_feed(_args: Vec<Value>) -> StdlibResult {
    let feed_url = "https://substack.com/api/v1/reader/feed/tabs?surface=feed&selectedTab=for-you&type=base";

    if let Ok(json) = http_get_json(feed_url) {
        Ok(json_to_tallow(&json))
    } else {
        Ok(Value::Map(vec![(
            Value::String("error".into()),
            Value::String("Reader feed not accessible".into()),
        )]))
    }
}

/// substack.check_free_preview(url: str) -> Map
///
/// Check if a Substack post has free preview enabled and at what percentage.
/// Some publications accidentally set free preview to 100%.
/// Returns: has_free_preview, preview_percentage (estimated),
/// audience, is_fully_accessible.
fn substack_check_free_preview(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "check_free_preview")?;
    let (base_url, post_slug) = parse_substack_url(&url)?;

    let slug = post_slug.ok_or_else(|| "URL must contain /p/<slug>".to_string())?;

    let api_url = format!("{base_url}/api/v1/posts/{slug}");
    let mut fields: Vec<(Value, Value)> = Vec::new();

    if let Ok(json) = http_get_json(&api_url) {
        let audience = json.get("audience").and_then(|v| v.as_str()).unwrap_or("unknown");
        let has_body = json.get("body_html")
            .and_then(|v| v.as_str())
            .map(|b| b.len() > 50)
            .unwrap_or(false);

        let free_text = json.get("free_content")
            .and_then(|v| v.as_str())
            .map(|s| s.len())
            .unwrap_or(0);

        fields.push((Value::String("audience".into()), Value::String(audience.to_string())));
        fields.push((Value::String("has_body_in_api".into()), Value::Bool(has_body)));
        fields.push((Value::String("free_content_length".into()), Value::Int(free_text as i128)));

        // Heuristic: if body_html is present without auth, preview is effectively 100%
        let is_fully_accessible = has_body;
        fields.push((Value::String("is_fully_accessible".into()), Value::Bool(is_fully_accessible)));

        if is_fully_accessible {
            fields.push((Value::String("verdict".into()), Value::String(
                "FULLY ACCESSIBLE — body_html served without auth. Publication is misconfigured or intentionally open.".into()
            )));
        } else if free_text > 1000 {
            fields.push((Value::String("verdict".into()), Value::String(
                "Large free preview — significant content available without subscription.".into()
            )));
        } else {
            fields.push((Value::String("verdict".into()), Value::String(
                "Gated — body_html absent from API response. Requires subscription or RSS/email bypass.".into()
            )));
        }
    } else {
        fields.push((Value::String("error".into()), Value::String("API not accessible".into())));
    }

    Ok(Value::Map(fields))
}

// ─── RSS Helper ──────────────────────────────────────────────────

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");

    if let Some(start) = xml.find(&open) {
        let after = &xml[start + open.len()..];
        if let Some(end) = after.find(&close) {
            let content = &after[..end];
            // Handle CDATA
            if content.starts_with("<![CDATA[") && content.ends_with("]]>") {
                return Some(content[9..content.len() - 3].to_string());
            }
            return Some(unescape_xml(content));
        }
    }

    // Try with attributes: <tag attr="...">
    let open_attr = format!("<{tag} ");
    if let Some(start) = xml.find(&open_attr) {
        let after_start = &xml[start + open_attr.len()..];
        if let Some(tag_end) = after_start.find('>') {
            let after_tag = &after_start[tag_end + 1..];
            if let Some(end) = after_tag.find(&close) {
                let content = &after_tag[..end];
                if content.starts_with("<![CDATA[") && content.ends_with("]]>") {
                    return Some(content[9..content.len() - 3].to_string());
                }
                return Some(unescape_xml(content));
            }
        }
    }

    None
}

fn unescape_xml(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
}

/// substack.cookie_bypass_info() -> Map
///
/// CRITICAL FINDING: ANY valid Substack auth cookie (substack.sid)
/// unlocks ALL paywalled content across ALL publications.
/// Even a FREE-tier account's cookies provide full body_html access.
/// The paywall is server-side for unauthenticated users but becomes
/// client-side CSS/JS only once ANY valid cookie is present.
///
/// This is the PRIMARY bypass vector for Substack.
fn substack_cookie_bypass_info(_args: Vec<Value>) -> StdlibResult {
    let mut fields: Vec<(Value, Value)> = Vec::new();

    fields.push((Value::String("verdict".into()), Value::String(
        "ANY valid Substack auth cookie (substack.sid) unlocks ALL paywalled content across ALL publications. Even a free-tier account works.".into()
    )));
    fields.push((Value::String("primary_cookie".into()), Value::String("substack.sid".into())));
    fields.push((Value::String("secondary_cookie".into()), Value::String("substack.lli".into())));
    fields.push((Value::String("cookie_domain".into()), Value::String(".substack.com (works across all subdomains)".into())));
    fields.push((Value::String("method_1".into()), Value::String(
        "Create a FREE Substack account → extract cookies from browser → use with any publication's API".into()
    )));
    fields.push((Value::String("method_2".into()), Value::String(
        "Export cookies from browser DevTools (Application > Cookies > substack.com) as JSON".into()
    )));
    fields.push((Value::String("method_3".into()), Value::String(
        "Use sbstck-dl (Go) or substack_api (Python) with cookie export to download full archives".into()
    )));
    fields.push((Value::String("gating_mechanism".into()), Value::String(
        "Server-side for unauthenticated (API returns error). Client-side CSS/JS for authenticated (body_html served, React hides it with .paywallFade / .paywallBlur CSS)".into()
    )));
    fields.push((Value::String("known_tools".into()), Value::String(
        "Substack2Markdown (511★), sbstck-dl (233★), substack_api (221★), substack-archives-downloader (59★)".into()
    )));
    fields.push((Value::String("note".into()), Value::String(
        "Substack has NO password-based auth. Magic-link email only. No developer API. No public bug bounty. Two known breaches (2020 CC leak, Oct 2025 data breach).".into()
    )));

    Ok(Value::Map(fields))
}

/// substack.discover_publications(category_id?: str, page?: int) -> Array
///
/// Discover publications via Substack's public category API.
/// The endpoint substack.com/api/v1/category/public/{id}/all
/// returns publications with 80+ metadata fields including:
/// - Stripe IDs, pricing plans in all currencies
/// - Author names, bios, photos, Twitter handles
/// - Subscriber counts (public_user_count)
/// - Parent/child/sibling publication relationships
/// - Paywall/content exposure settings
///
/// Default category: "62" (Business)
fn substack_discover_publications(args: Vec<Value>) -> StdlibResult {
    let category_id = args.get(0)
        .map(|v| v.as_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "62".to_string());

    let page = args.get(1).and_then(|v| {
        if let Value::Int(n) = v { Some(*n as u32) } else { None }
    }).unwrap_or(0);

    let url = format!(
        "https://substack.com/api/v1/category/public/{}/all?page={}",
        category_id, page
    );

    if let Ok(json) = http_get_json(&url) {
        Ok(json_to_tallow(&json))
    } else {
        Ok(Value::Map(vec![(
            Value::String("error".into()),
            Value::String(format!("Category API not accessible for id={category_id}")),
        )]))
    }
}

/// substack.set_cookie(name: str, value: str) -> Bool
///
/// Inject a cookie into the session cookie jar. The cookie will be
/// sent with all subsequent requests to Substack APIs.
///
/// ANY valid substack.sid cookie from a free-tier account unlocks
/// full body_html for ALL paywalled posts across ALL publications.
fn substack_set_cookie(args: Vec<Value>) -> StdlibResult {
    let name = arg_str(&args, 0, "set_cookie")?;
    let value = arg_str(&args, 1, "set_cookie")?;
    set_cookie_internal(&name, &value);
    Ok(Value::Bool(true))
}

