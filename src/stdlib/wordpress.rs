//! Standard library: `tallow.wordpress` — WordPress membership paywall bypass.
//!
//! WordPress powers 43% of the web. Membership plugins (MemberPress, RCP,
//! Paid Memberships Pro, WooCommerce Memberships) gate content at the PHP
//! template level — but the REST API at /wp-json/wp/v2/posts often serves
//! full content because plugin authors forget to filter REST responses.
//!
//! ## Architecture (researched Aug 2026)
//!
//! - **REST API**: /wp-json/wp/v2/posts — often leaks protected content
//! - **RSS Feeds**: /feed/ — may contain full text even for gated posts
//! - **Sitemaps**: /wp-sitemap.xml — enumerates all URLs including protected
//! - **JSON-LD**: schema.org structured data in page source
//! - **Plugins**: MemberPress, RCP, PMPro, WooCommerce Memberships
//!
//! ## Bypass Vectors
//!
//! 1. **REST API leak** — primary vector. Many plugins don't filter /wp-json
//! 2. **RSS feed extraction** — /feed/ often has full content
//! 3. **Googlebot UA** — some hosts whitelist crawlers for SEO
//! 4. **Sitemap enumeration** — discover all post URLs + metadata
//! 5. **JSON-LD extraction** — structured data in <script type="ld+json">

use super::StdlibResult;
use crate::interp::Value;

use std::sync::LazyLock;
use std::time::Duration;

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    crate::runtime::egress_http::agent_with_timeouts(Some(Duration::from_secs(60)), Some(Duration::from_secs(30)))
});

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "discover" => Some(wp_discover(args)),
        "get_posts" => Some(wp_get_posts(args)),
        "get_post" => Some(wp_get_post(args)),
        "get_rss" => Some(wp_get_rss(args)),
        "detect_plugins" => Some(wp_detect_plugins(args)),
        "get_sitemap" => Some(wp_get_sitemap(args)),
        _ => None,
    }
}

pub fn dispatch_method(_o: &Value, _m: &str, _a: Vec<Value>) -> Option<StdlibResult> {
    None
}

fn arg_str(args: &[Value], i: usize, n: &str) -> Result<String, String> {
    args.get(i).map(|v| v.as_string()).filter(|s| !s.is_empty())
        .ok_or_else(|| format!("wordpress.{n}: arg {i} required"))
}

fn arg_str_opt(args: &[Value], i: usize) -> Option<String> {
    args.get(i).map(|v| v.as_string()).filter(|s| !s.is_empty())
}

fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let resp = AGENT.get(url)
        .header("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
        .call().map_err(|e| format!("GET {url}: {e}"))?;
    let body = resp.into_body().read_to_string()
        .map_err(|e| format!("Body read: {e}"))?;
    serde_json::from_str(&body).map_err(|e| format!("JSON: {e}"))
}

fn http_get_text(url: &str) -> Result<String, String> {
    let resp = AGENT.get(url)
        .header("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
        .call().map_err(|e| format!("GET {url}: {e}"))?;
    resp.into_body().read_to_string().map_err(|e| format!("Body: {e}"))
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
        match c { '<' => t = true, '>' => { t = false; r.push(' '); }
            _ if !t => r.push(c), _ => {} }
    }
    r.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
     .replace("&quot;", "\"").replace("&#39;", "'").replace("&nbsp;", " ")
}

// ─── Discovery ───────────────────────────────────────────────────

/// wordpress.discover(url: str) -> Map
///
/// Probe a site for WordPress + membership infrastructure.
/// Returns: is_wordpress, wp_version, theme, active_plugins,
/// rest_api_accessible, has_membership_plugin, sitemap_url,
/// feed_url, rest_url.
fn wp_discover(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "discover")?;
    let base = url.trim_end_matches('/');

    let mut fields: Vec<(Value, Value)> = Vec::new();
    let mut is_wp = false;

    // Check REST API
    let rest_url = format!("{base}/wp-json/wp/v2/posts?per_page=1");
    if let Ok(json) = http_get_json(&rest_url) {
        is_wp = true;
        fields.push((Value::String("rest_api_accessible".into()), Value::Bool(true)));
        // Get total post count from headers (available via X-WP-Total)
        if let Some(headers) = json.as_array().map(|a| a.len()) {
            fields.push((Value::String("posts_sample".into()), Value::Int(headers as i128)));
        }
    } else {
        fields.push((Value::String("rest_api_accessible".into()), Value::Bool(false)));
    }

    // Check WP-JSON index for site info
    let index_url = format!("{base}/wp-json");
    if let Ok(json) = http_get_json(&index_url) {
        is_wp = true;
        if let Some(name) = json.get("name").and_then(|v| v.as_str()) {
            fields.push((Value::String("site_name".into()), Value::String(name.to_string())));
        }
        if let Some(desc) = json.get("description").and_then(|v| v.as_str()) {
            fields.push((Value::String("description".into()), Value::String(desc.to_string())));
        }
        if let Some(url_s) = json.get("url").and_then(|v| v.as_str()) {
            fields.push((Value::String("site_url".into()), Value::String(url_s.to_string())));
        }
        // Check available namespaces for plugin detection
        if let Some(ns) = json.get("namespaces").and_then(|v| v.as_array()) {
            let ns_list: Vec<String> = ns.iter()
                .filter_map(|n| n.as_str().map(|s| s.to_string()))
                .collect();
            let has_membership = ns_list.iter().any(|n|
                n.contains("memberpress") || n.contains("rcp") ||
                n.contains("pmpro") || n.contains("woocommerce") ||
                n.contains("memberships") || n.contains("restrict-content")
            );
            fields.push((Value::String("has_membership_namespace".into()), Value::Bool(has_membership)));
        }
    }

    // Try to get HTML for plugin detection
    if let Ok(html) = http_get_text(base) {
        // Detect WP version from generator meta
        if let Some(r#gen) = extract_meta(&html, "generator") {
            let generator = r#gen;
            if generator.contains("WordPress") {
                is_wp = true;
                fields.push((Value::String("generator".into()), Value::String(generator)));
            }
        }
        // Detect membership plugins from HTML
        let plugins = detect_plugins_from_html(&html);
        if !plugins.is_empty() {
            fields.push((Value::String("detected_plugins".into()),
                Value::Array(plugins.into_iter().map(Value::String).collect())));
        }
    }

    fields.push((Value::String("is_wordpress".into()), Value::Bool(is_wp)));
    fields.push((Value::String("base_url".into()), Value::String(base.to_string())));
    fields.push((Value::String("rest_url".into()), Value::String(format!("{base}/wp-json/wp/v2"))));
    fields.push((Value::String("feed_url".into()), Value::String(format!("{base}/feed/"))));
    fields.push((Value::String("sitemap_url".into()), Value::String(format!("{base}/wp-sitemap.xml"))));

    Ok(Value::Map(fields))
}

// ─── Content Extraction ──────────────────────────────────────────

/// wordpress.get_posts(url: str, per_page?: int, page?: int) -> Array
///
/// Extract posts via WordPress REST API. This is the PRIMARY bypass
/// vector — many membership plugins don't filter REST responses.
fn wp_get_posts(args: Vec<Value>) -> StdlibResult {
    let base = arg_str(&args, 0, "get_posts")?;
    let per_page = args.get(1).and_then(|v| if let Value::Int(n) = v { Some(*n as u32) } else { None }).unwrap_or(20);
    let page = args.get(2).and_then(|v| if let Value::Int(n) = v { Some(*n as u32) } else { None }).unwrap_or(1);

    let url = format!("{}/wp-json/wp/v2/posts?per_page={per_page}&page={page}&_embed", base.trim_end_matches('/'));

    match http_get_json(&url) {
        Ok(serde_json::Value::Array(posts)) => {
            let results: Vec<Value> = posts.iter().map(|post| {
                let mut f: Vec<(Value, Value)> = Vec::new();
                for key in &["id", "date", "modified", "slug", "status", "type", "link", "title"] {
                    if let Some(v) = post.get(*key) {
                        match key {
                            &"title" => {
                                if let Some(t) = v.get("rendered").and_then(|r| r.as_str()) {
                                    f.push((Value::String("title".into()), Value::String(unescape(&strip_html(t)))));
                                }
                            }
                            &"link" => {
                                if let Some(l) = v.as_str() {
                                    f.push((Value::String("link".into()), Value::String(l.to_string())));
                                }
                            }
                            _ => {
                                if let Some(s) = v.as_str() {
                                    f.push((Value::String(key.to_string()), Value::String(s.to_string())));
                                }
                            }
                        }
                    }
                }
                // Content — THE LEAK
                if let Some(content) = post.get("content").and_then(|c| c.get("rendered")).and_then(|r| r.as_str()) {
                    let plain = unescape(&strip_html(content));
                    f.push((Value::String("content_html".into()), Value::String(content.to_string())));
                    f.push((Value::String("content_text".into()), Value::String(plain)));
                    f.push((Value::String("content_length".into()), Value::Int(content.len() as i128)));
                }
                // Excerpt
                if let Some(excerpt) = post.get("excerpt").and_then(|e| e.get("rendered")).and_then(|r| r.as_str()) {
                    f.push((Value::String("excerpt".into()), Value::String(unescape(&strip_html(excerpt)))));
                }
                // Check if protected
                if let Some(prot) = post.get("protected").and_then(|p| p.as_bool()) {
                    f.push((Value::String("protected".into()), Value::Bool(prot)));
                }
                Value::Map(f)
            }).collect();
            Ok(Value::Array(results))
        }
        Ok(other) => Ok(json_to_tallow(&other)),
        Err(e) => Err(e),
    }
}

/// wordpress.get_post(url: str, slug: str) -> Map
///
/// Get a single post by slug via REST API.
fn wp_get_post(args: Vec<Value>) -> StdlibResult {
    let base = arg_str(&args, 0, "get_post")?;
    let slug = arg_str(&args, 1, "get_post.slug")?;
    let url = format!("{}/wp-json/wp/v2/posts?slug={}&_embed", base.trim_end_matches('/'), slug);

    match http_get_json(&url) {
        Ok(serde_json::Value::Array(posts)) => {
            if let Some(post) = posts.first() {
                let mut f: Vec<(Value, Value)> = Vec::new();
                if let Some(title) = post.get("title").and_then(|t| t.get("rendered")).and_then(|r| r.as_str()) {
                    f.push((Value::String("title".into()), Value::String(unescape(&strip_html(title)))));
                }
                if let Some(content) = post.get("content").and_then(|c| c.get("rendered")).and_then(|r| r.as_str()) {
                    let plain = unescape(&strip_html(content));
                    f.push((Value::String("content_html".into()), Value::String(content.to_string())));
                    f.push((Value::String("content_text".into()), Value::String(plain)));
                    f.push((Value::String("content_length".into()), Value::Int(content.len() as i128)));
                }
                if let Some(prot) = post.get("protected").and_then(|p| p.as_bool()) {
                    f.push((Value::String("protected".into()), Value::Bool(prot)));
                }
                f.push((Value::String("slug".into()), Value::String(slug)));
                Ok(Value::Map(f))
            } else {
                Err(format!("Post not found: {slug}"))
            }
        }
        Ok(_) => Err("Unexpected API response".into()),
        Err(e) => Err(e),
    }
}

// ─── RSS Feed ────────────────────────────────────────────────────

/// wordpress.get_rss(url: str) -> Map
///
/// Extract posts via RSS feed. WordPress RSS feeds at /feed/ often
/// contain full content even for membership-protected posts because
/// plugins may not filter the feed.
fn wp_get_rss(args: Vec<Value>) -> StdlibResult {
    let base = arg_str(&args, 0, "get_rss")?;
    let feed_url = format!("{}/feed/", base.trim_end_matches('/'));

    let mut fields: Vec<(Value, Value)> = Vec::new();
    fields.push((Value::String("feed_url".into()), Value::String(feed_url.clone())));

    if let Ok(xml) = http_get_text(&feed_url) {
        let mut items: Vec<Value> = Vec::new();
        let mut pos = 0;

        while let Some(start) = xml[pos..].find("<item>") {
            let abs_start = pos + start;
            let item_end = match xml[abs_start..].find("</item>") {
                Some(i) => abs_start + i + 7,
                None => break,
            };
            let item_xml = &xml[abs_start..item_end];
            let mut ifields: Vec<(Value, Value)> = Vec::new();

            for (tag, key) in &[("title","title"), ("link","link"), ("pubDate","pub_date"),
                ("description","description"), ("content:encoded","content")] {
                if let Some(v) = extract_xml(item_xml, tag) {
                    let clean = if *key == "description" || *key == "content" {
                        strip_html(&unescape(&v))
                    } else {
                        unescape(&v)
                    };
                    ifields.push((Value::String(key.to_string()), Value::String(clean)));
                }
            }
            items.push(Value::Map(ifields));
            pos = item_end;
        }

        fields.push((Value::String("item_count".into()), Value::Int(items.len() as i128)));
        fields.push((Value::String("items".into()), Value::Array(items)));
    } else {
        fields.push((Value::String("error".into()), Value::String("RSS feed not accessible".into())));
    }

    Ok(Value::Map(fields))
}

// ─── Plugin Detection ────────────────────────────────────────────

/// wordpress.detect_plugins(url: str) -> Array
///
/// Detect membership plugins installed on a WordPress site.
/// Checks for: MemberPress, Restrict Content Pro, Paid Memberships Pro,
/// WooCommerce Memberships, Ultimate Member, and others.
fn wp_detect_plugins(args: Vec<Value>) -> StdlibResult {
    let base = arg_str(&args, 0, "detect_plugins")?;
    let html = http_get_text(&base)?;
    let plugins = detect_plugins_from_html(&html);
    Ok(Value::Array(plugins.into_iter().map(Value::String).collect()))
}

/// wordpress.get_sitemap(url: str) -> Array
///
/// Extract all post URLs from WordPress sitemap.
fn wp_get_sitemap(args: Vec<Value>) -> StdlibResult {
    let base = arg_str(&args, 0, "get_sitemap")?;

    // Try wp-sitemap.xml (WP 5.5+)
    let sitemap_url = format!("{}/wp-sitemap.xml", base.trim_end_matches('/'));
    let mut urls: Vec<Value> = Vec::new();

    if let Ok(xml) = http_get_text(&sitemap_url) {
        // WP sitemap index — extract sub-sitemaps
        let mut pos = 0;
        while let Some(start) = xml[pos..].find("<loc>") {
            let abs = pos + start + 5;
            if let Some(end) = xml[abs..].find("</loc>") {
                let loc = &xml[abs..abs + end];
                if loc.contains("post") || loc.contains("wp-sitemap-posts") {
                    urls.push(Value::String(loc.to_string()));
                }
                pos = abs + end + 6;
            } else { break; }
        }
    }

    Ok(Value::Array(urls))
}

// ─── Helpers ─────────────────────────────────────────────────────

fn extract_meta(html: &str, name: &str) -> Option<String> {
    let pattern = format!("name=\"{name}\" content=\"");
    if let Some(start) = html.find(&pattern) {
        let after = &html[start + pattern.len()..];
        if let Some(end) = after.find('"') {
            return Some(unescape(&after[..end]));
        }
    }
    None
}

fn extract_xml(xml: &str, tag: &str) -> Option<String> {
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
    // Try with attributes
    let open_attr = format!("<{tag} ");
    if let Some(start) = xml.find(&open_attr) {
        let after = &xml[start + open_attr.len()..];
        if let Some(gt) = after.find('>') {
            let content_start = gt + 1;
            if let Some(end) = after[content_start..].find(&close) {
                let content = &after[content_start..content_start + end];
                if content.starts_with("<![CDATA[") && content.ends_with("]]>") {
                    return Some(content[9..content.len()-3].to_string());
                }
                return Some(content.to_string());
            }
        }
    }
    None
}

fn detect_plugins_from_html(html: &str) -> Vec<String> {
    let mut found = Vec::new();
    let signatures: Vec<(&str, &str)> = vec![
        ("memberpress", "MemberPress"),
        ("rcp-", "Restrict Content Pro"),
        ("pmpro-", "Paid Memberships Pro"),
        ("woocommerce-memberships", "WooCommerce Memberships"),
        ("woocommerce-subscriptions", "WooCommerce Subscriptions"),
        ("ultimate-member", "Ultimate Member"),
        ("membermouse", "MemberMouse"),
        ("s2member", "s2Member"),
        ("aam-", "Advanced Access Manager"),
        ("wp-members", "WP-Members"),
        ("restrict-content", "Restrict Content"),
        ("paid-memberships", "Paid Memberships"),
        ("learndash", "LearnDash"),
        ("tutor-lms", "Tutor LMS"),
    ];
    let lower = html.to_lowercase();
    for (sig, name) in &signatures {
        if lower.contains(sig) {
            found.push(name.to_string());
        }
    }
    found
}
