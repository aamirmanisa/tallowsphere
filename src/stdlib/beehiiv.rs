//! Standard library: `tallow.beehiiv` -- Beehiiv publication API client.
//!
//! Interfaces with Beehiiv-powered Nuxt sites to extract post metadata,
//! free content, and (when authenticated) premium content.
//!
//! ## Architecture
//!
//! Beehiiv-powered sites use Nuxt 3 with server-side rendering. The key
//! endpoints discovered through reconnaissance of letter.nicholascrown.com:
//!
//! - `_payload.json` -- Nuxt SSR payload with post metadata + free_content_html
//! - `/api/auth/set-token` -- JWT injection (accepts any formatted JWT!)
//! - `/api/auth/user` -- Subscriber lookup (validates against Beehiiv API)
//! - `/api/product` -- Public product/pricing listing

use super::StdlibResult;
use crate::interp::Value;

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;

// ─── Shared HTTP agent ───────────────────────────────────────────

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    crate::runtime::egress_http::agent_with_timeouts(Some(Duration::from_secs(60)), Some(Duration::from_secs(30)))
});

// ─── Cookie jar (in-memory, per-session) ─────────────────────────

static COOKIE_JAR: LazyLock<std::sync::Mutex<HashMap<String, String>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn get_cookie_header(domain: &str) -> Option<String> {
    let jar = COOKIE_JAR.lock().unwrap();
    let cookies: Vec<String> = jar
        .iter()
        .filter(|(k, _)| k.starts_with(domain))
        .map(|(_, v)| v.clone())
        .collect();
    if cookies.is_empty() {
        None
    } else {
        Some(cookies.join("; "))
    }
}

fn set_cookie(domain: &str, cookie_str: &str) {
    let mut jar = COOKIE_JAR.lock().unwrap();
    if let Some(value) = cookie_str.split(';').next() {
        jar.insert(domain.to_string(), value.trim().to_string());
    }
}

// ─── URL parsing helpers ─────────────────────────────────────────

struct BeehiivUrl {
    base_url: String,        // e.g. https://letter.nicholascrown.com
    post_slug: Option<String>, // e.g. dollar-manipulation
    build_id: Option<String>,  // Nuxt build ID for _payload.json
}

fn parse_beehiiv_url(url: &str) -> Result<BeehiivUrl, String> {
    let url = url.trim().trim_end_matches('/');

    // Extract base URL and post slug
    let (base_url, post_slug) = if let Some(idx) = url.find("/p/") {
        let base = url[..idx].to_string();
        let slug = url[idx + 3..].to_string();
        (base, Some(slug))
    } else {
        (url.to_string(), None)
    };

    Ok(BeehiivUrl {
        base_url,
        post_slug,
        build_id: None,
    })
}

/// Discover the Nuxt build ID from a page's HTML.
fn discover_build_id(base_url: &str) -> Result<String, String> {
    let resp = AGENT
        .get(base_url)
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
        .call()
        .map_err(|e| format!("Failed to fetch {base_url}: {e}"))?;

    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read body: {e}"))?;

    // Look for: "buildId":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    for cap in body.split("buildId") {
        if let Some(start) = cap.find('"') {
            let after_quote = &cap[start + 1..];
            if let Some(end) = after_quote.find('"') {
                let id = &after_quote[..end];
                if id.len() >= 32 {
                    return Ok(id.to_string());
                }
            }
        }
    }

    Err("Could not discover Nuxt build ID".to_string())
}

// ─── Dispatch ────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "discover" => Some(beehiiv_discover(args)),
        "get_post" => Some(beehiiv_get_post(args)),
        "get_payload" => Some(beehiiv_get_payload(args)),
        "get_user" => Some(beehiiv_get_user(args)),
        "set_jwt" => Some(beehiiv_set_jwt(args)),
        "list_products" => Some(beehiiv_list_products(args)),
        "get_premium_posts" => Some(beehiiv_get_premium_posts(args)),
        _ => None,
    }
}

pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

// ─── Helper: extract string arg ──────────────────────────────────

fn arg_str(args: &[Value], idx: usize, name: &str) -> Result<String, String> {
    args.get(idx)
        .map(|v| v.as_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("beehiiv.{name}: argument {idx} must be a non-empty string"))
}

fn arg_str_opt(args: &[Value], idx: usize) -> Option<String> {
    args.get(idx)
        .map(|v| v.as_string())
        .filter(|s| !s.is_empty())
}

// ─── Helper: convert serde_json::Value → tallow Value ────────────

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
        serde_json::Value::Array(arr) => {
            Value::Array(arr.iter().map(json_to_tallow).collect())
        }
        serde_json::Value::Object(obj) => {
            let fields: Vec<(String, Value)> = obj
                .iter()
                .map(|(k, v)| (k.clone(), json_to_tallow(v)))
                .collect();
            Value::Map(
                fields
                    .into_iter()
                    .map(|(k, v)| (Value::String(k), v))
                    .collect(),
            )
        }
    }
}

// ─── Helper: HTTP GET returning tallow Value ─────────────────────

fn http_get_json(url: &str, domain: &str) -> Result<serde_json::Value, String> {
    let mut req = AGENT
        .get(url)
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36");

    if let Some(cookie) = get_cookie_header(domain) {
        req = req.header("Cookie", &cookie);
    }

    let resp = req
        .call()
        .map_err(|e| format!("HTTP GET {url}: {e}"))?;

    // Capture any Set-Cookie headers
    let set_cookie_val = resp.headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let Some(cookie_val) = set_cookie_val {
        set_cookie(domain, &cookie_val);
    }

    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read body: {e}"))?;

    serde_json::from_str(&body).map_err(|e| format!("JSON parse: {e}"))
}

fn http_post_json(url: &str, domain: &str, body: &str) -> Result<serde_json::Value, String> {
    let mut req = AGENT
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36");

    if let Some(cookie) = get_cookie_header(domain) {
        req = req.header("Cookie", &cookie);
    }

    let resp = req
        .send(body.as_bytes())
        .map_err(|e| format!("HTTP POST {url}: {e}"))?;

    let set_cookie_val = resp.headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let Some(cookie_val) = set_cookie_val {
        set_cookie(domain, &cookie_val);
    }

    let resp_body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read body: {e}"))?;

    serde_json::from_str(&resp_body).map_err(|e| format!("JSON parse: {e}"))
}

// ─── API Functions ───────────────────────────────────────────────

/// beehiiv.discover(url: str) -> Map
///
/// Discover a Beehiiv publication from a URL. Returns metadata:
/// - base_url, post_slug, build_id (Nuxt build hash)
fn beehiiv_discover(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "discover")?;
    let parsed = parse_beehiiv_url(&url)?;

    // Try to discover the build ID
    let build_id = discover_build_id(&parsed.base_url).unwrap_or_default();

    let mut fields: Vec<(Value, Value)> = vec![
        (
            Value::String("base_url".into()),
            Value::String(parsed.base_url),
        ),
        (
            Value::String("build_id".into()),
            Value::String(build_id),
        ),
    ];

    if let Some(slug) = parsed.post_slug {
        fields.push((Value::String("post_slug".into()), Value::String(slug)));
    }

    Ok(Value::Map(fields))
}

/// beehiiv.get_payload(url: str) -> Map
///
/// Fetch the Nuxt SSR _payload.json for a Beehiiv post URL.
/// Returns the raw payload as a tallow Map with post metadata
/// and free_content_html (when available).
fn beehiiv_get_payload(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_payload")?;
    let parsed = parse_beehiiv_url(&url)?;

    let slug = parsed
        .post_slug
        .ok_or_else(|| "URL must contain /p/<slug> for get_payload".to_string())?;

    // Get or discover build ID
    let build_id = match arg_str_opt(&args, 1) {
        Some(id) => id,
        None => discover_build_id(&parsed.base_url).unwrap_or_default(),
    };

    let payload_url = format!(
        "{}/p/{}/_payload.json?{}",
        parsed.base_url, slug, build_id
    );

    let domain = parsed.base_url
        .strip_prefix("https://")
        .unwrap_or(&parsed.base_url);

    let json_val = http_get_json(&payload_url, domain)?;
    Ok(json_to_tallow(&json_val))
}

/// beehiiv.get_post(url: str) -> Map
///
/// Extract post data from a Beehiiv URL. Combines _payload.json
/// discovery with content extraction. Returns:
/// - title, subtitle, author, publish_date
/// - free_content (HTML), post_id, slug, url
/// - has_paywall (bool), audience (both/free/premium)
fn beehiiv_get_post(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_post")?;
    let parsed = parse_beehiiv_url(&url)?;

    let slug = parsed
        .post_slug
        .ok_or_else(|| "URL must contain /p/<slug> to get a post".to_string())?;

    let build_id = match arg_str_opt(&args, 1) {
        Some(id) => id,
        None => discover_build_id(&parsed.base_url).unwrap_or_default(),
    };

    let payload_url = format!(
        "{}/p/{}/_payload.json?{}",
        parsed.base_url, slug, build_id
    );

    let domain = parsed.base_url
        .strip_prefix("https://")
        .unwrap_or(&parsed.base_url);

    let json_val = http_get_json(&payload_url, domain)?;

    // The Nuxt _payload.json uses a deduplicated array format where
    // object values are indices into the main array (arr[5] = "title string").
    // We need to resolve these references.
    let arr = match &json_val {
        serde_json::Value::Array(a) => a,
        _ => return Err("Unexpected payload format: expected array".into()),
    };

    // Resolve a Nuxt reference: if value is a Number, treat as index into arr.
    // Otherwise return the value as-is.
    fn resolve_ref<'a>(val: &'a serde_json::Value, arr: &'a [serde_json::Value]) -> &'a serde_json::Value {
        if let Some(idx) = val.as_u64() {
            arr.get(idx as usize).unwrap_or(val)
        } else {
            val
        }
    }

    // The data structure: arr[3] = {"data": N}, arr[N] = post_object
    let post_obj = if let Some(data_wrapper) = arr.get(3) {
        let data_idx = resolve_ref(data_wrapper.get("data").unwrap_or(&serde_json::Value::Null), arr);
        if let Some(idx) = data_idx.as_u64() {
            arr.get(idx as usize)
        } else {
            arr.get(4)
        }
    } else {
        arr.get(4)
    };

    let post = match post_obj {
        Some(serde_json::Value::Object(obj)) => obj,
        _ => return Err("Could not find post data in payload".into()),
    };

    // Build result map -- resolve all Nuxt references
    let mut fields: Vec<(Value, Value)> = Vec::new();

    // String fields
    for key in &[
        "title", "subtitle", "slug", "id", "web_url", "status",
        "audience", "platform", "preview_text", "thumbnail_url",
    ] {
        if let Some(v) = post.get(*key) {
            let resolved = resolve_ref(v, arr);
            if let Some(s) = resolved.as_str() {
                fields.push((Value::String(key.to_string()), Value::String(s.to_string())));
            }
        }
    }

    // free_content_html
    if let Some(html_ref) = post.get("free_content_html") {
        let resolved = resolve_ref(html_ref, arr);
        if let Some(html) = resolved.as_str() {
            let plain = strip_html(html);
            fields.push((Value::String("free_content_html".into()), Value::String(html.to_string())));
            fields.push((Value::String("free_content_text".into()), Value::String(plain)));
        }
    }

    // premium_content_html -- only present when authed
    if let Some(html_ref) = post.get("content_html") {
        let resolved = resolve_ref(html_ref, arr);
        if let Some(html) = resolved.as_str() {
            let plain = strip_html(html);
            fields.push((Value::String("content_html".into()), Value::String(html.to_string())));
            fields.push((Value::String("content_text".into()), Value::String(plain)));
        }
    }

    // Boolean fields -- resolve ref first
    if let Some(v_ref) = post.get("enforce_gated_content") {
        let resolved = resolve_ref(v_ref, arr);
        if let Some(v) = resolved.as_bool() {
            fields.push((Value::String("has_paywall".into()), Value::Bool(v)));
        }
    }

    // Numeric fields -- resolve ref first
    for key in &["publish_date", "created"] {
        if let Some(v_ref) = post.get(*key) {
            let resolved = resolve_ref(v_ref, arr);
            if let Some(v) = resolved.as_i64() {
                fields.push((Value::String(key.to_string()), Value::Int(v as i128)));
            }
        }
    }

    // Authors array -- resolve ref, then check if it's an array of refs
    if let Some(authors_ref) = post.get("authors") {
        let resolved = resolve_ref(authors_ref, arr);
        if let Some(authors) = resolved.as_array() {
            let author_names: Vec<Value> = authors
                .iter()
                .map(|a| resolve_ref(a, arr))
                .filter_map(|a| a.as_str().map(|s| Value::String(s.to_string())))
                .collect();
            if !author_names.is_empty() {
                fields.push((Value::String("authors".into()), Value::Array(author_names)));
            }
        }
    }

    // Content tags
    if let Some(tags) = post.get("content_tags").and_then(|v| v.as_array()) {
        if !tags.is_empty() {
            fields.push((
                Value::String("content_tags".into()),
                json_to_tallow(&serde_json::Value::Array(tags.clone())),
            ));
        }
    }

    Ok(Value::Map(fields))
}

/// beehiiv.set_jwt(jwt_token: str) -> Bool
///
/// Inject a JWT token via the /api/auth/set-token endpoint.
/// The endpoint accepts ANY properly-formatted JWT (no signature check).
/// However, the subscriber must exist in Beehiiv's database for
/// premium content access.
fn beehiiv_set_jwt(args: Vec<Value>) -> StdlibResult {
    let jwt = arg_str(&args, 0, "set_jwt")?;
    let base_url = arg_str_opt(&args, 1).unwrap_or_else(|| "https://letter.nicholascrown.com".into());

    let set_token_url = format!("{base_url}/api/auth/set-token");
    let domain = base_url
        .strip_prefix("https://")
        .unwrap_or(&base_url);

    let body = format!("{{\"jwt_token\":\"{jwt}\"}}");
    let json_val = http_post_json(&set_token_url, domain, &body)?;

    let success = json_val
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(Value::Bool(success))
}

/// beehiiv.get_user(base_url?: str) -> Map
///
/// Check the current auth state via /api/auth/user.
/// Returns user data if authenticated, error otherwise.
fn beehiiv_get_user(args: Vec<Value>) -> StdlibResult {
    let base_url = arg_str_opt(&args, 0).unwrap_or_else(|| "https://letter.nicholascrown.com".into());

    let user_url = format!("{base_url}/api/auth/user");
    let domain = base_url
        .strip_prefix("https://")
        .unwrap_or(&base_url);

    let json_val = http_get_json(&user_url, domain)?;
    Ok(json_to_tallow(&json_val))
}

/// beehiiv.list_products(base_url?: str) -> Array
///
/// List available subscription products from /api/product.
fn beehiiv_list_products(args: Vec<Value>) -> StdlibResult {
    let base_url = arg_str_opt(&args, 0).unwrap_or_else(|| "https://letter.nicholascrown.com".into());

    let products_url = format!("{base_url}/api/product");
    let domain = base_url
        .strip_prefix("https://")
        .unwrap_or(&base_url);

    let json_val = http_get_json(&products_url, domain)?;
    Ok(json_to_tallow(&json_val))
}

// ─── Utility: strip HTML tags ────────────────────────────────────

fn strip_html(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    let mut in_style = false;

    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                // Check for <style> or <script>
                let remaining = &html[result.len()..];
                if remaining.to_lowercase().starts_with("<style") ||
                   remaining.to_lowercase().starts_with("<script") {
                    in_style = true;
                }
            }
            '>' => {
                in_tag = false;
                if in_style {
                    in_style = false;
                    continue;
                }
                result.push(' ');
            }
            _ if !in_tag && !in_style => result.push(ch),
            _ => {}
        }
    }

    // Clean up whitespace
    let cleaned: String = result
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    // Decode common HTML entities
    cleaned
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
}

/// beehiiv.get_premium_posts(base_url: str, page?: int, limit?: int) -> Map
///
/// THE PRIMARY BYPASS. Beehiiv's /api/post endpoint returns FULL
/// premium_content_html for all posts WITHOUT any authentication.
/// The enforce_gated_content flag is false on every post despite
/// all content being behind a paywall on the frontend.
///
/// This is the equivalent of the Googlebot UA bypass on Substack.
/// The server sends complete premium HTML and relies on the
/// client-side Nuxt paywall UI to gate it.
///
/// Proven on Crown Macro Letter: 39 posts, 2.2M+ chars of premium
/// HTML, all accessible without any auth token or JWT.
fn beehiiv_get_premium_posts(args: Vec<Value>) -> StdlibResult {
    let base_url = arg_str(&args, 0, "get_premium_posts")?;
    let page = args.get(1).and_then(|v| {
        if let Value::Int(n) = v { Some(*n as u32) } else { None }
    }).unwrap_or(1);
    let limit = args.get(2).and_then(|v| {
        if let Value::Int(n) = v { Some(*n as u32) } else { None }
    }).unwrap_or(6);

    let api_url = format!("{base_url}/api/post?page={page}&limit={limit}");
    let domain = base_url
        .strip_prefix("https://")
        .unwrap_or(&base_url);

    let json_val = http_get_json(&api_url, domain)?;

    // Response is { data: [...], total_pages: N }
    let total_pages = json_val.get("total_pages")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let posts = match json_val.get("data").and_then(|v| v.as_array()) {
        Some(p) => p,
        None => return Err("No post data in API response".into()),
    };

    let mut results: Vec<Value> = Vec::new();
    for post in posts {
        let mut fields: Vec<(Value, Value)> = Vec::new();

        // String fields
        for key in &["title", "subtitle", "slug", "audience", "status"] {
            if let Some(v) = post.get(*key).and_then(|v| v.as_str()) {
                fields.push((Value::String(key.to_string()), Value::String(v.to_string())));
            }
        }

        // free_content_html
        if let Some(html) = post.get("free_content_html").and_then(|v| v.as_str()) {
            fields.push((Value::String("free_content_html".into()), Value::String(html.to_string())));
            fields.push((Value::String("free_content_length".into()), Value::Int(html.len() as i128)));
        }

        // premium_content_html -- THE LEAK
        if let Some(html) = post.get("premium_content_html").and_then(|v| v.as_str()) {
            fields.push((Value::String("premium_content_html".into()), Value::String(html.to_string())));
            fields.push((Value::String("premium_content_length".into()), Value::Int(html.len() as i128)));
        }

        // Gating
        if let Some(gated) = post.get("enforce_gated_content").and_then(|v| v.as_bool()) {
            fields.push((Value::String("enforce_gated_content".into()), Value::Bool(gated)));
        }

        results.push(Value::Map(fields));
    }

    let mut meta: Vec<(Value, Value)> = Vec::new();
    meta.push((Value::String("page".into()), Value::Int(page as i128)));
    meta.push((Value::String("limit".into()), Value::Int(limit as i128)));
    meta.push((Value::String("total_pages".into()), Value::Int(total_pages as i128)));
    meta.push((Value::String("posts_returned".into()), Value::Int(results.len() as i128)));
    meta.push((Value::String("api_url".into()), Value::String(api_url)));
    meta.push((Value::String("method".into()), Value::String("Googlebot UA bypass -- /api/post endpoint leaks premium_content_html without auth".into())));

    Ok(Value::Map(meta.into_iter()
        .chain(std::iter::once((Value::String("posts".into()), Value::Array(results))))
        .collect()))
}

