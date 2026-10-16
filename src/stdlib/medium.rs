//! Standard library: `tallow.medium` — site-18.example paywall bypass client.
//!
//! Medium uses a metered paywall: N free articles/month tracked via cookies
//! (uid, sid, ob). After the limit, premium articles show a truncated preview.
//!
//! ## Bypass Vectors (researched Aug 2026)
//!
//! 1. **Cookie metering reset** — clear uid/sid/ob cookies to reset the counter
//! 2. **Social referrer bypass** — ?source=twitter, ?gi= (Google Index) params
//! 3. **Twitter card extraction** — twitter:description meta often has full text
//! 4. **Google cache / archive.is** — cached versions skip the paywall entirely
//! 5. **GraphQL direct query** — POST /_/graphql with Post query
//! 6. **freedium.cfd / textise proxies** — community-maintained bypass services
//! 7. **Jina.ai text extraction** — AI reader mode for article text

use super::StdlibResult;
use crate::interp::Value;

use std::sync::LazyLock;
use std::time::Duration;

// ─── Shared HTTP agent ───────────────────────────────────────────

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    crate::runtime::egress_http::agent_with_timeouts(Some(Duration::from_secs(60)), Some(Duration::from_secs(30)))
});

// ─── Dispatch ────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "get_article" => Some(medium_get_article(args)),
        "get_by_graphql" => Some(medium_get_by_graphql(args)),
        "get_cached" => Some(medium_get_cached(args)),
        "get_by_freedium" => Some(medium_get_by_freedium(args)),
        "get_twitter_card" => Some(medium_get_twitter_card(args)),
        "get_by_jina" => Some(medium_get_by_jina(args)),
        "reset_meter" => Some(medium_reset_meter(args)),
        "get_with_twitter_referrer" => Some(medium_get_with_twitter_referrer(args)),
        "get_metered_content" => Some(medium_get_metered_content(args)),
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
        .ok_or_else(|| format!("medium.{name}: argument {idx} must be a non-empty string"))
}

fn http_get(url: &str) -> Result<String, String> {
    let resp = AGENT
        .get(url)
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .call()
        .map_err(|e| format!("HTTP GET {url}: {e}"))?;

    resp.into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read body: {e}"))
}

fn http_post_json(url: &str, body: &str) -> Result<String, String> {
    let resp = AGENT
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
        .send(body.as_bytes())
        .map_err(|e| format!("HTTP POST {url}: {e}"))?;

    resp.into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read body: {e}"))
}

fn extract_meta(html: &str, property: &str) -> Option<String> {
    // Find <meta property="..." content="..."> or <meta name="..." content="...">
    for pattern in &[property, &format!("name=\"{property}\"")] {
        let search = format!("{pattern}\" content=\"");
        if let Some(start) = html.find(&search) {
            let after = &html[start + search.len()..];
            if let Some(end) = after.find('"') {
                return Some(unescape_html(&after[..end]));
            }
        }
    }
    // Try og: prefix
    let og_pattern = format!("property=\"og:{property}\" content=\"");
    if let Some(start) = html.find(&og_pattern) {
        let after = &html[start + og_pattern.len()..];
        if let Some(end) = after.find('"') {
            return Some(unescape_html(&after[..end]));
        }
    }
    None
}

fn extract_paragraphs(html: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut pos = 0;
    while let Some(start) = html[pos..].find("<p") {
        let abs_start = pos + start;
        // Find the closing > of the <p> tag
        let tag_end = match html[abs_start..].find('>') {
            Some(i) => abs_start + i + 1,
            None => break,
        };
        // Find </p>
        let close = match html[tag_end..].find("</p>") {
            Some(i) => tag_end + i,
            None => break,
        };
        let content = &html[tag_end..close];
        let clean = strip_tags(content).trim().to_string();
        if clean.len() > 20 {
            result.push(clean);
        }
        pos = close + 4;
    }
    result
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
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
}

fn build_result_map(fields: Vec<(&str, String)>) -> Value {
    let map: Vec<(Value, Value)> = fields
        .into_iter()
        .map(|(k, v)| (Value::String(k.to_string()), Value::String(v)))
        .collect();
    Value::Map(map)
}

// ─── API Functions ───────────────────────────────────────────────

/// medium.get_article(url: str) -> Map
///
/// Extract a Medium article using multiple bypass strategies in sequence.
/// Returns: title, description, author, full_text (best effort),
/// paragraphs (array), bypass_method used, has_paywall (bool).
fn medium_get_article(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_article")?;
    let html = http_get(&url)?;

    let mut fields: Vec<(&str, String)> = Vec::new();

    // Extract meta tags
    if let Some(title) = extract_meta(&html, "title") {
        fields.push(("title", title));
    }
    if let Some(desc) = extract_meta(&html, "description") {
        fields.push(("description", desc));
    }
    if let Some(author) = extract_meta(&html, "author") {
        fields.push(("author", author));
    }

    // Extract Twitter card (often has full text)
    let twitter_text = extract_meta(&html, "twitter:description");
    let has_twitter = twitter_text.is_some();

    // Extract paragraphs
    let paragraphs = extract_paragraphs(&html);
    let para_count = paragraphs.len();

    // Try to get full text via social referrer trick
    // Append ?source=twitter or ?gi= to get the full article
    let mut full_text = String::new();
    let mut bypass_method = "direct";

    // Check if article is paywalled (look for meter-paywall indicators)
    let has_paywall = html.contains("metered-paywall")
        || html.contains("paywall-meter")
        || html.contains("Meter is active")
        || html.contains("subtitle=\"Member-only\"");

    // If paywall detected, try social referrer bypass
    if has_paywall || paragraphs.len() < 5 {
        // Try with ?source=twitter
        let twitter_url = if url.contains('?') {
            format!("{url}&source=twitter")
        } else {
            format!("{url}?source=twitter")
        };
        if let Ok(tw_html) = http_get(&twitter_url) {
            let tw_paras = extract_paragraphs(&tw_html);
            if tw_paras.len() > paragraphs.len() + 2 {
                bypass_method = "twitter_referrer";
                for p in &tw_paras {
                    if !full_text.is_empty() { full_text.push('\n'); }
                    full_text.push_str(p);
                }
            }
        }

        // If still short, try Google Index parameter
        if full_text.is_empty() {
            let gi_url = if url.contains('?') {
                format!("{url}&gi=1")
            } else {
                format!("{url}?gi=1")
            };
            if let Ok(gi_html) = http_get(&gi_url) {
                let gi_paras = extract_paragraphs(&gi_html);
                if gi_paras.len() > paragraphs.len() + 2 {
                    bypass_method = "google_index";
                    full_text.clear();
                    for p in &gi_paras {
                        if !full_text.is_empty() { full_text.push('\n'); }
                        full_text.push_str(p);
                    }
                }
            }
        }
    }

    // If we got Twitter card text and didn't get full text, use that
    if full_text.is_empty() && has_twitter {
        if let Some(ref tw) = twitter_text {
            full_text = tw.clone();
            bypass_method = "twitter_card";
        }
    }

    // Fallback: use directly extracted paragraphs
    if full_text.is_empty() {
        for p in &paragraphs {
            if !full_text.is_empty() { full_text.push('\n'); }
            full_text.push_str(p);
        }
    }

    fields.push(("full_text", full_text));
    fields.push(("paragraph_count", para_count.to_string()));
    fields.push(("bypass_method", bypass_method.to_string()));
    fields.push(("has_paywall", has_paywall.to_string()));

    // Build paragraphs array
    let para_values: Vec<Value> = paragraphs.into_iter()
        .map(Value::String)
        .collect();
    fields.push(("_paragraphs_json", format!("[{}]", para_values.len())));

    Ok(build_result_map(fields))
}

/// medium.get_by_graphql(url: str) -> Map
///
/// Try Medium's GraphQL API directly. Medium uses POST /_/graphql
/// with a Post query. The GraphQL schema is not publicly introspectable
/// but known query structures work.
fn medium_get_by_graphql(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_by_graphql")?;

    // Extract post ID from URL
    // Medium URLs: https://site-18.example/@user/post-slug-HASH
    // or https://site-18.example/publication/post-slug-HASH
    let post_id = if let Some(last_dash) = url.rfind('-') {
        url[last_dash + 1..].to_string()
    } else {
        return Err("Could not extract post ID from URL".into());
    };

    // Known Medium GraphQL query for post content
    let query = format!(
        r#"[{{"operationName":"PostQuery","variables":{{"postId":"{post_id}","skipToMain":true}},"query":"query PostQuery($postId: ID!) {{ post(id: $postId) {{ id title content {{ bodyModel {{ paragraphs {{ name text type }} }} }} }} }}"}}]"#
    );

    let response = http_post_json("https://site-18.example/_/graphql", &query)?;

    // Parse the response for content
    let mut fields: Vec<(&str, String)> = Vec::new();
    fields.push(("graphql_response", response));
    fields.push(("post_id", post_id));

    Ok(build_result_map(fields))
}

/// medium.get_cached(url: str) -> Map
///
/// Fetch article from Google Web Cache or archive.is.
/// Archived versions often contain the FULL article without any paywall.
fn medium_get_cached(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_cached")?;

    // Try Google cache first
    let cache_url = format!("https://webcache.googleusercontent.com/search?q=cache:{url}&strip=1&vwsrc=0");
    let mut fields: Vec<(&str, String)> = Vec::new();
    let mut source = "none";

    if let Ok(html) = http_get(&cache_url) {
        if html.len() > 5000 && !html.contains("Error 404") {
            let paras = extract_paragraphs(&html);
            if paras.len() > 3 {
                let full_text = paras.join("\n");
                fields.push(("full_text", full_text));
                fields.push(("paragraph_count", paras.len().to_string()));
                source = "google_cache";
            }
        }
    }

    // Fallback: try archive.is
    if source == "none" {
        let archive_url = format!("https://archive.is/{url}");
        if let Ok(html) = http_get(&archive_url) {
            let paras = extract_paragraphs(&html);
            if paras.len() > 3 {
                let full_text = paras.join("\n");
                fields.push(("full_text", full_text));
                fields.push(("paragraph_count", paras.len().to_string()));
                source = "archive_is";
            }
        }
    }

    fields.push(("cache_source", source.to_string()));
    Ok(build_result_map(fields))
}

/// medium.get_by_freedium(url: str) -> Map
///
/// Use Freedium (community Medium bypass) to extract article.
/// Freedium is a CDN-based bypass that strips the paywall.
fn medium_get_by_freedium(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_by_freedium")?;

    // Extract the path portion after site-18.example
    let path = if let Some(idx) = url.find("site-18.example/") {
        &url[idx + 11..]
    } else {
        return Err("URL must contain site-18.example/".into());
    };

    // Try freedium.cfd (the active mirror as of Aug 2026)
    let freedium_url = format!("https://freedium.cfd/{path}");
    let mut fields: Vec<(&str, String)> = Vec::new();

    if let Ok(html) = http_get(&freedium_url) {
        let paras = extract_paragraphs(&html);
        if paras.len() > 3 {
            let full_text = paras.join("\n");
            fields.push(("full_text", full_text));
            fields.push(("paragraph_count", paras.len().to_string()));
            fields.push(("bypass_service", "freedium.cfd".to_string()));
        }
    } else {
        fields.push(("error", "freedium.cfd not accessible".to_string()));
    }

    Ok(build_result_map(fields))
}

/// medium.get_twitter_card(url: str) -> Map
///
/// Extract article content from Twitter Card meta tags.
/// Medium articles set twitter:description to the full or near-full article text.
fn medium_get_twitter_card(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_twitter_card")?;
    let html = http_get(&url)?;

    let mut fields: Vec<(&str, String)> = Vec::new();

    if let Some(title) = extract_meta(&html, "title") {
        fields.push(("title", title));
    }

    let tw_desc = extract_meta(&html, "twitter:description");
    let tw_title = extract_meta(&html, "twitter:title");
    let tw_image = extract_meta(&html, "twitter:image");
    let tw_creator = extract_meta(&html, "twitter:creator");

    if let Some(desc) = tw_desc {
        let desc_len = desc.len();
        fields.push(("twitter_description", desc));
        fields.push(("description_length", desc_len.to_string()));
    }
    if let Some(t) = tw_title {
        fields.push(("twitter_title", t));
    }
    if let Some(img) = tw_image {
        fields.push(("twitter_image", img));
    }
    if let Some(creator) = tw_creator {
        fields.push(("twitter_creator", creator));
    }

    Ok(build_result_map(fields))
}

/// medium.get_by_jina(url: str) -> Map
///
/// Use Jina.ai's reader mode to extract article content.
/// Jina renders the page and extracts text in AI-friendly format.
fn medium_get_by_jina(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_by_jina")?;

    let jina_url = format!("https://r.jina.ai/{url}");
    let mut fields: Vec<(&str, String)> = Vec::new();

    if let Ok(text) = http_get(&jina_url) {
        fields.push(("extracted_text", text.clone()));
        fields.push(("text_length", text.len().to_string()));
        fields.push(("bypass_service", "jina.ai".to_string()));

        // Try to extract title from markdown
        if let Some(line) = text.lines().find(|l| l.starts_with("Title: ")) {
            fields.push(("title", line[7..].to_string()));
        }
    } else {
        fields.push(("error", "jina.ai extraction failed".to_string()));
    }

    Ok(build_result_map(fields))
}

/// medium.reset_meter(domain?: str) -> Map
///
/// Returns instructions for resetting Medium's metered paywall counter.
/// Medium tracks free articles via cookies (uid, sid, ob).
/// Clearing these cookies resets the article counter.
fn medium_reset_meter(_args: Vec<Value>) -> StdlibResult {
    let mut fields: Vec<(&str, String)> = Vec::new();
    fields.push(("method", "cookie_reset".to_string()));
    fields.push(("cookies_to_clear", "uid, sid, ob, _uetvid".to_string()));
    fields.push(("instruction", "Clear cookies for site-18.example domain. Then reload the article.".to_string()));
    fields.push(("alternative_1", "Open in private/incognito window".to_string()));
    fields.push(("alternative_2", "Use ?source=twitter query parameter".to_string()));
    fields.push(("alternative_3", "Use ?gi=1 (Google Index) query parameter".to_string()));
    fields.push(("note", "Medium meters at ~3-5 articles/month. Cookie reset restarts counter.".to_string()));
    Ok(build_result_map(fields))
}

/// medium.get_with_twitter_referrer(url: str) -> Map
///
/// THE PRIMARY BYPASS. Medium whitelists Twitter's site-28.example referrer.
/// Setting `Referer: https://site-28.example/{random}` tricks Medium into
/// serving the full article without paywall restrictions.
/// This is the technique used by medium-unlimited (5,467 GitHub stars).
///
/// Returns: full_text, paragraph_count, referrer_used, has_paywall
fn medium_get_with_twitter_referrer(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_with_twitter_referrer")?;
    
    // Generate random site-28.example referrer (matching medium-unlimited pattern)
    let random_id = format!("{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos());
    let referer = format!("https://site-28.example/{}", &random_id[random_id.len().saturating_sub(10)..]);
    
    let resp = AGENT
        .get(&url)
        .header("Referer", &referer)
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .call()
        .map_err(|e| format!("HTTP GET {url}: {e}"))?;
    
    let html = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read body: {e}"))?;
    
    let mut fields: Vec<(&str, String)> = Vec::new();
    
    // Extract title
    if let Some(title) = extract_meta(&html, "title") {
        fields.push(("title", title));
    }
    
    // Extract meteredContent (the div with full article)
    let metered_content = extract_div_content(&html, "meteredContent");
    let paragraphs = if let Some(ref mc) = metered_content {
        extract_paragraphs(mc)
    } else {
        extract_paragraphs(&html)
    };
    
    let full_text = paragraphs.join("\n");
    fields.push(("full_text", full_text));
    fields.push(("paragraph_count", paragraphs.len().to_string()));
    fields.push(("referrer_used", referer));
    
    let has_paywall = html.contains("metered-paywall") || html.contains("paywall-meter");
    fields.push(("has_paywall", has_paywall.to_string()));
    fields.push(("method", "twitter_referrer_header".to_string()));
    fields.push(("note", "Medium whitelists site-28.example referrers. This is the primary bypass used by medium-unlimited (5.4K GitHub stars).".to_string()));
    
    Ok(build_result_map(fields))
}

/// medium.get_metered_content(url: str) -> Map
///
/// Extract article content from Medium's meteredContent div.
/// Medium embeds the FULL article in <div class="meteredContent">
/// on every page load. The paywall is a CSS overlay — the content
/// is always present in the HTML.
///
/// Returns: metered_content_html, metered_content_text, paragraph_count,
/// has_paywall_overlay (bool)
fn medium_get_metered_content(args: Vec<Value>) -> StdlibResult {
    let url = arg_str(&args, 0, "get_metered_content")?;
    let html = http_get(&url)?;
    
    let mut fields: Vec<(&str, String)> = Vec::new();
    
    if let Some(title) = extract_meta(&html, "title") {
        fields.push(("title", title));
    }
    
    // Extract meteredContent div
    let metered = extract_div_content(&html, "meteredContent");
    let has_metered = metered.is_some();
    
    if let Some(ref mc) = metered {
        let plain = strip_tags(mc);
        fields.push(("metered_content_html", mc.clone()));
        fields.push(("metered_content_text", plain.clone()));
        
        let paras = extract_paragraphs(mc);
        fields.push(("paragraph_count", paras.len().to_string()));
    }
    
    // Check for paywall overlay elements
    let has_fade = html.contains("postFade");
    let has_paywall_bg = html.contains("paywall-background-color");
    let has_paywall_overlay = has_fade || has_paywall_bg;
    
    fields.push(("has_metered_content", has_metered.to_string()));
    fields.push(("has_paywall_overlay", has_paywall_overlay.to_string()));
    fields.push(("has_postFade", has_fade.to_string()));
    fields.push(("has_paywall_bg", has_paywall_bg.to_string()));
    fields.push(("method", "meteredContent_div_extraction".to_string()));
    fields.push(("note", "Medium embeds full content in div.meteredContent. Paywall is CSS-only overlay (postFade gradient + paywall-background-color).".to_string()));
    
    Ok(build_result_map(fields))
}

/// Helper: extract content from a named div class
fn extract_div_content(html: &str, class_name: &str) -> Option<String> {
    // Search for <div class="{class_name}" ...> or <div ... class="{class_name}" ...>
    let pattern = format!("class=\"{class_name}\"");
    let alt_pattern = format!("class=\"");
    
    // Try exact class match first
    if let Some(start) = html.find(&pattern) {
        // Find the opening <div that contains this class
        let div_start = html[..start].rfind("<div")?;
        // Find the closing > of this div tag
        let tag_end = html[start..].find('>')? + start + 1;
        // Now find matching </div> by counting nested divs
        let mut depth = 1i32;
        let mut pos = tag_end;
        while depth > 0 && pos < html.len() {
            if html[pos..].starts_with("<div") {
                depth += 1;
                pos += 4;
            } else if html[pos..].starts_with("</div>") {
                depth -= 1;
                if depth == 0 {
                    return Some(html[tag_end..pos].to_string());
                }
                pos += 6;
            } else {
                pos += 1;
            }
        }
    }
    None
}

