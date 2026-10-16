//! Standard library: `tallow.ghost` — Ghost CMS paywall interface.
//!
//! Ghost is the #1 open-source publishing CMS with memberships. It powers
//! 404 Media, Platformer, The Browser, The Pragmatic Engineer, and ~10K+
//! active publications. Ghost 6.x has the strongest paywall defense of
//! any surveyed platform — true server-side content stripping with no
//! Googlebot UA bypass or API leak vectors for paid content.
//!
//! ## Architecture (researched Aug 2026)
//!
//! - **Backend**: Node.js + openresty (Nginx+Lua) on Fastly CDN
//! - **Content API**: `/ghost/api/v3/content/` — requires per-pub API key
//! - **Members API**: `/ghost/api/v3/members/` — requires JWT session
//! - **RSS**: `/rss/` — always accessible, descriptions only
//! - **Anti-bot**: Fastly Client Challenge (`_fs-ch-`) — JS-based bot detection
//!
//! ## Known Bypass Vectors
//!
//! 1. **Content API key leak** — many Ghost themes embed the Content API
//!    key in page source for client-side rendering. Key is 26 hex chars.
//!    404 Media uses Fastly challenge but Platformer's key was found.
//!
//! 2. **RSS feed** — always accessible, provides metadata + descriptions.
//!    Proven working on 404 Media even through Fastly.
//!
//! 3. **Googlebot UA** — does NOT work. Content is stripped server-side.
//!    Confirmed: same 45,554 chars for Googlebot vs normal UA.
//!
//! 4. **Browser CDP** — Fastly challenges are JS-based. A real browser
//!    (Chrome via CDP) can pass the challenge, extract rendered content,
//!    and capture Content API keys. Requires Tor/proxy for exit node rotation.
//!
//! 5. **Members API JWT** — if a subscriber session can be obtained,
//!    the Members API serves full paid content via `/ghost/api/v3/members/`.

use super::StdlibResult;
use crate::interp::Value;

use std::sync::LazyLock;
use std::time::Duration;

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    crate::runtime::egress_http::agent_with_timeouts(Some(Duration::from_secs(60)), Some(Duration::from_secs(30)))
});

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "discover" => Some(ghost_discover(args)),
        "extract_content_key" => Some(ghost_extract_content_key(args)),
        "get_posts_api" => Some(ghost_get_posts_api(args)),
        "get_rss" => Some(ghost_get_rss(args)),
        "get_post_by_slug" => Some(ghost_get_post_by_slug(args)),
        _ => None,
    }
}

pub fn dispatch_method(_o: &Value, _m: &str, _a: Vec<Value>) -> Option<StdlibResult> {
    None
}

fn arg_str(args: &[Value], i: usize, n: &str) -> Result<String, String> {
    args.get(i).map(|v| v.as_string()).filter(|s| !s.is_empty())
        .ok_or_else(|| format!("ghost.{n}: arg {i} required"))
}

fn arg_str_opt(args: &[Value], i: usize) -> Option<String> {
    args.get(i).map(|v| v.as_string()).filter(|s| !s.is_empty())
}

fn http_get_text(url: &str) -> Result<String, String> {
    let resp = AGENT.get(url)
        .header("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
        .call().map_err(|e| format!("GET {url}: {e}"))?;
    resp.into_body().read_to_string().map_err(|e| format!("Body: {e}"))
}

fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let resp = AGENT.get(url)
        .header("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
        .call().map_err(|e| format!("GET {url}: {e}"))?;
    let body = resp.into_body().read_to_string().map_err(|e| format!("Body: {e}"))?;
    serde_json::from_str(&body).map_err(|e| format!("JSON: {e}"))
}

fn json_to_tallow(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() { Value::Int(i as i128) }
            else if let Some(f) = n.as_f64() { Value::Float(f) }
            else { Value::String(n.to_string()) }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(json_to_tallow).collect()),
        serde_json::Value::Object(o) => {
            let f: Vec<(Value, Value)> = o.iter()
                .map(|(k, v)| (Value::String(k.clone()), json_to_tallow(v)))
                .collect();
            Value::Map(f)
        }
    }
}

fn strip_html(h: &str) -> String {
    let mut r = String::new(); let mut t = false;
    for c in h.chars() {
        match c { '<' => { t = true; } '>' => { t = false; r.push(' '); }
            _ if !t => { r.push(c); } _ => {} }
    }
    r.split_whitespace().collect::<Vec<&str>>().join(" ")
}

// ─── Discovery ───────────────────────────────────────────────────

/// ghost.discover(url: str) -> Map
///
/// Probe a site for Ghost infrastructure: version, API endpoints,
/// Fastly challenge status, RSS availability.
fn ghost_discover(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "discover")?;
    let base = url.trim_end_matches('/');
    let mut fields: Vec<(Value, Value)> = Vec::new();

    // Try RSS feed — Ghost always exposes this
    let rss_url = format!("{base}/rss/");
    let mut has_rss = false;
    if let Ok(xml) = http_get_text(&rss_url) {
        if xml.contains("<generator>Ghost") {
            has_rss = true;
            // Extract Ghost version from RSS
            if let Some(ver) = extract_xml_tag(&xml, "generator") {
                fields.push((Value::String("ghost_version".into()), Value::String(ver)));
            }
            // Extract site info
            if let Some(title) = extract_xml_tag(&xml, "title") {
                fields.push((Value::String("title".into()), Value::String(title)));
            }
            if let Some(desc) = extract_xml_tag(&xml, "description") {
                fields.push((Value::String("description".into()), Value::String(desc)));
            }
            // Count items
            let item_count = xml.matches("<item>").count();
            fields.push((Value::String("rss_item_count".into()), Value::Int(item_count as i128)));
        }
    }
    fields.push((Value::String("rss_accessible".into()), Value::Bool(has_rss)));
    fields.push((Value::String("rss_url".into()), Value::String(rss_url)));

    // Try Content API directly
    let api_url = format!("{base}/ghost/api/v3/content/settings/");
    let has_api = if let Ok(json) = http_get_json(&api_url) {
        if let Some(site) = json.get("settings") {
            if let Some(title) = site.get("title").and_then(|v| v.as_str()) {
                fields.push((Value::String("api_site_title".into()), Value::String(title.to_string())));
            }
        }
        true
    } else {
        false
    };
    fields.push((Value::String("content_api_accessible".into()), Value::Bool(has_api)));
    fields.push((Value::String("content_api_url".into()), Value::String(format!("{base}/ghost/api/v3/content/"))));
    fields.push((Value::String("members_api_url".into()), Value::String(format!("{base}/ghost/api/v3/members/"))));
    fields.push((Value::String("base_url".into()), Value::String(base.to_string())));
    fields.push((Value::String("is_ghost".into()), Value::Bool(has_rss || has_api)));

    Ok(Value::Map(fields))
}

// ─── Content Key Extraction ──────────────────────────────────────

/// ghost.extract_content_key(url: str) -> String?
///
/// Extract Ghost Content API key from page source.
/// Many themes embed the 26-char hex key for client-side rendering.
/// Found in Platformer, The Browser, and other Ghost pubs.
fn ghost_extract_content_key(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "extract_content_key")?;
    let html = http_get_text(&url)?;

    // Ghost Content API keys are 26 hex characters
    // Usually embedded as: /ghost/api/content/ or content_api_key
    let pattern = regex_find_hex26(&html);

    Ok(match pattern {
        Some(key) => Value::String(key),
        None => Value::Nil,
    })
}

/// ghost.get_posts_api(url: str, key: str, limit?: int) -> Array
///
/// Access Ghost Content API with a valid content key.
/// Returns ONLY public posts — paid posts require Members API JWT.
fn ghost_get_posts_api(args: Vec<Value>) -> StdlibResult {
    let base = arg_str(&args, 0, "get_posts_api")?;
    let key = arg_str(&args, 1, "get_posts_api.key")?;
    let limit = args.get(2).and_then(|v| {
        if let Value::Int(n) = v { Some(*n as u32) } else { None }
    }).unwrap_or(10);

    let url = format!("{}/ghost/api/v3/content/posts/?key={key}&limit={limit}&include=authors,tags",
        base.trim_end_matches('/'));

    match http_get_json(&url) {
        Ok(json) => {
            if let Some(errors) = json.get("errors") {
                let msg = errors.get(0).and_then(|e| e.get("message")).and_then(|m| m.as_str())
                    .unwrap_or("Unknown API error");
                Err(format!("Content API error: {msg}"))
            } else if let Some(posts) = json.get("posts").and_then(|p| p.as_array()) {
                let results: Vec<Value> = posts.iter().map(|p| {
                    let mut f: Vec<(Value, Value)> = Vec::new();
                    for key in &["title", "slug", "visibility", "published_at", "url"] {
                        if let Some(v) = p.get(*key).and_then(|v| v.as_str()) {
                            f.push((Value::String(key.to_string()), Value::String(v.to_string())));
                        }
                    }
                    if let Some(html) = p.get("html").and_then(|v| v.as_str()) {
                        f.push((Value::String("html_length".into()), Value::Int(html.len() as i128)));
                        f.push((Value::String("html".into()), Value::String(html.to_string())));
                    }
                    if let Some(exc) = p.get("excerpt").and_then(|v| v.as_str()) {
                        f.push((Value::String("excerpt".into()), Value::String(exc.to_string())));
                    }
                    Value::Map(f)
                }).collect();
                Ok(Value::Array(results))
            } else {
                Ok(json_to_tallow(&json))
            }
        }
        Err(e) => Err(e),
    }
}

/// ghost.get_rss(url: str) -> Map
///
/// Extract posts from Ghost RSS feed. Always accessible, even through
/// Fastly challenges. Contains descriptions + metadata.
fn ghost_get_rss(args: Vec<Value>) -> StdlibResult {
    let base = arg_str(&args, 0, "get_rss")?;
    let rss_url = format!("{}/rss/", base.trim_end_matches('/'));
    let mut fields: Vec<(Value, Value)> = Vec::new();
    fields.push((Value::String("rss_url".into()), Value::String(rss_url.clone())));

    if let Ok(xml) = http_get_text(&rss_url) {
        let mut items: Vec<Value> = Vec::new();
        let mut pos = 0;
        while let Some(start) = xml[pos..].find("<item>") {
            let abs_start = pos + start;
            let item_end = match xml[abs_start..].find("</item>") {
                Some(i) => abs_start + i + 7, None => break,
            };
            let item = &xml[abs_start..item_end];
            let mut ifields: Vec<(Value, Value)> = Vec::new();
            for (tag, key) in &[
                ("title", "title"), ("link", "link"), ("pubDate", "pub_date"),
                ("dc:creator", "author"), ("description", "description"),
                ("content:encoded", "content"),
            ] {
                if let Some(v) = extract_xml_tag(item, tag) {
                    let clean = if *key == "description" || *key == "content" {
                        strip_html(&v)
                    } else { v };
                    ifields.push((Value::String(key.to_string()), Value::String(clean)));
                }
            }
            items.push(Value::Map(ifields));
            pos = item_end;
        }
        fields.push((Value::String("item_count".into()), Value::Int(items.len() as i128)));
        fields.push((Value::String("items".into()), Value::Array(items)));
    } else {
        fields.push((Value::String("error".into()), Value::String("RSS not accessible (Fastly challenge?)".into())));
    }

    Ok(Value::Map(fields))
}

/// ghost.get_post_by_slug(url: str, key: str, slug: str) -> Map
///
/// Get a single post via Content API by slug.
fn ghost_get_post_by_slug(args: Vec<Value>) -> StdlibResult {
    let base = arg_str(&args, 0, "get_post_by_slug")?;
    let key = arg_str(&args, 1, "get_post_by_slug.key")?;
    let slug = arg_str(&args, 2, "get_post_by_slug.slug")?;

    let url = format!("{}/ghost/api/v3/content/posts/slug/{slug}/?key={key}",
        base.trim_end_matches('/'));

    match http_get_json(&url) {
        Ok(json) => {
            if let Some(errors) = json.get("errors") {
                Err(format!("API error: {:?}", errors))
            } else if let Some(posts) = json.get("posts").and_then(|p| p.as_array()) {
                if let Some(post) = posts.first() {
                    let mut f: Vec<(Value, Value)> = Vec::new();
                    for key in &["title", "slug", "visibility", "published_at", "url"] {
                        if let Some(v) = post.get(*key).and_then(|v| v.as_str()) {
                            f.push((Value::String(key.to_string()), Value::String(v.to_string())));
                        }
                    }
                    if let Some(html) = post.get("html").and_then(|v| v.as_str()) {
                        f.push((Value::String("html_length".into()), Value::Int(html.len() as i128)));
                        f.push((Value::String("html".into()), Value::String(html.to_string())));
                    }
                    Ok(Value::Map(f))
                } else {
                    Err("Post not found".into())
                }
            } else {
                Ok(json_to_tallow(&json))
            }
        }
        Err(e) => Err(e),
    }
}

// ─── Helpers ─────────────────────────────────────────────────────

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let Some(start) = xml.find(&open) {
        let after = &xml[start + open.len()..];
        if let Some(end) = after.find(&close) {
            let content = &after[..end];
            if content.starts_with("<![CDATA[") && content.ends_with("]]>") {
                return Some(content[9..content.len()-3].to_string());
            }
            return Some(content.to_string());
        }
    }
    // Try with CDATA-style
    let open_cdata = format!("<{tag}><![CDATA[");
    if let Some(start) = xml.find(&open_cdata) {
        let after = &xml[start + open_cdata.len()..];
        if let Some(end) = after.find("]]></") {
            return Some(after[..end].to_string());
        }
    }
    None
}

fn regex_find_hex26(html: &str) -> Option<String> {
    // Ghost Content API keys are exactly 26 lowercase hex chars
    // Search for patterns like: key=XXXX, "XXXX", /api/content/ with XXXX nearby
    let mut chars = html.chars().peekable();
    let mut buf = String::new();

    for ch in html.chars() {
        if ch.is_ascii_hexdigit() {
            buf.push(ch);
            if buf.len() == 26 {
                // Found a candidate — verify it's a Ghost key by checking context
                let idx = html.find(&buf).unwrap_or(0);
                let context_start = if idx > 80 { idx - 80 } else { 0 };
                let context = &html[context_start..std::cmp::min(context_start + 120, html.len())];
                if context.contains("ghost") || context.contains("content") || context.contains("api") {
                    return Some(buf.clone());
                }
                buf.clear();
            }
        } else {
            buf.clear();
        }
    }
    None
}
