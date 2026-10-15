//! AI-powered extraction pipeline for Tallow's browser system.
//!
//! Converts raw HTML into clean LLM-friendly text and provides schema-based
//! extraction for common page types (products, articles, recipes) using a
//! layered strategy: JSON-LD → OpenGraph → Microdata → CSS heuristics.

use regex::Regex;
use serde_json::Value as JsonValue;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Structured product data extracted from a page.
#[derive(Debug, Clone, Default)]
pub struct ProductData {
    pub name: Option<String>,
    pub price: Option<f64>,
    pub currency: Option<String>,
    pub availability: Option<String>,
    pub rating: Option<f64>,
    pub image_url: Option<String>,
    pub brand: Option<String>,
    pub sku: Option<String>,
}

/// Structured article data extracted from a page.
#[derive(Debug, Clone, Default)]
pub struct ArticleData {
    pub title: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub body: String,
}

/// Structured recipe data extracted from a page.
#[derive(Debug, Clone, Default)]
pub struct RecipeData {
    pub name: Option<String>,
    pub ingredients: Vec<String>,
    pub instructions: Vec<String>,
    pub prep_time: Option<String>,
    pub cook_time: Option<String>,
}

// ---------------------------------------------------------------------------
// html_to_clean_text
// ---------------------------------------------------------------------------

/// Convert raw HTML into clean, LLM-friendly plain text.
///
/// 1. Strips `<script>`, `<style>`, `<nav>`, `<header>`, `<footer>`, `<aside>` blocks.
/// 2. Removes all HTML attributes except `href` and `src`.
/// 3. Converts remaining markup to structured plain text.
/// 4. Collapses whitespace.
/// 5. Truncates to ~4 000 words.
pub fn html_to_clean_text(html: &str) -> String {
    let mut text = html.to_string();

    // Step 1 — remove noisy block-level elements (case-insensitive).
    for tag in &["script", "style", "nav", "header", "footer", "aside", "noscript", "svg"] {
        let re = Regex::new(&format!(r"(?is)<{tag}\b[^>]*>.*?</{tag}>")).unwrap();
        text = re.replace_all(&text, "").to_string();
    }

    // Also strip HTML comments.
    let comment_re = Regex::new(r"(?s)<!--.*?-->").unwrap();
    text = comment_re.replace_all(&text, "").to_string();

    // Step 2 — strip attributes except href and src.
    // The `regex` crate does not support look-ahead, so we match all attributes
    // then selectively keep href and src by replacing in a closure.
    let attr_re = Regex::new(r#"(?i)\s+([a-z][a-z0-9\-]*)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)"#).unwrap();
    text = attr_re.replace_all(&text, |caps: &regex::Captures| {
        let name = caps.get(1).map_or("", |m| m.as_str()).to_lowercase();
        if name == "href" || name == "src" {
            caps.get(0).map_or("", |m| m.as_str()).to_string()
        } else {
            String::new()
        }
    }).to_string();

    // Step 3 — convert structural tags to text markers.
    // Headings → newline + text + newline.
    for level in 1..=6 {
        let re = Regex::new(&format!(r"(?is)<h{level}\b[^>]*>(.*?)</h{level}>")).unwrap();
        text = re.replace_all(&text, |caps: &regex::Captures| {
            format!("\n\n{}\n", caps[1].trim())
        }).to_string();
    }

    // Paragraphs, divs, sections, articles → double newline.
    for tag in &["p", "div", "section", "article", "main", "blockquote", "figcaption"] {
        let re = Regex::new(&format!(r"(?is)<{tag}\b[^>]*>(.*?)</{tag}>")).unwrap();
        text = re.replace_all(&text, |caps: &regex::Captures| {
            format!("\n\n{}\n\n", caps[1].trim())
        }).to_string();
    }

    // List items → bullet.
    let li_re = Regex::new(r"(?is)<li\b[^>]*>(.*?)</li>").unwrap();
    text = li_re.replace_all(&text, |caps: &regex::Captures| {
        format!("\n- {}", caps[1].trim())
    }).to_string();

    // Line breaks.
    let br_re = Regex::new(r"(?i)<br\s*/?>").unwrap();
    text = br_re.replace_all(&text, "\n").to_string();

    // Links → text (url).
    let link_re = Regex::new(r#"(?is)<a\b[^>]*href\s*=\s*"([^"]*)"[^>]*>(.*?)</a>"#).unwrap();
    text = link_re.replace_all(&text, |caps: &regex::Captures| {
        let href = caps[1].trim();
        let label = strip_all_tags(caps[2].trim());
        if href.is_empty() || href.starts_with('#') || href.starts_with("javascript:") {
            label
        } else {
            format!("{label} ({href})")
        }
    }).to_string();

    // Images → [image: src].
    let img_re = Regex::new(r#"(?i)<img\b[^>]*src\s*=\s*"([^"]*)"[^>]*/?\s*>"#).unwrap();
    text = img_re.replace_all(&text, "[image: $1]").to_string();

    // Strip all remaining tags.
    text = strip_all_tags(&text);

    // Decode common HTML entities.
    text = text
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ");

    // Decode numeric entities.
    let num_entity = Regex::new(r"&#(\d+);").unwrap();
    text = num_entity.replace_all(&text, |caps: &regex::Captures| {
        let code: u32 = caps[1].parse().unwrap_or(0);
        char::from_u32(code).map(|c| c.to_string()).unwrap_or_default()
    }).to_string();

    let hex_entity = Regex::new(r"(?i)&#x([0-9a-f]+);").unwrap();
    text = hex_entity.replace_all(&text, |caps: &regex::Captures| {
        let code = u32::from_str_radix(&caps[1], 16).unwrap_or(0);
        char::from_u32(code).map(|c| c.to_string()).unwrap_or_default()
    }).to_string();

    // Step 4 — collapse whitespace.
    // Collapse runs of spaces/tabs within lines.
    let space_re = Regex::new(r"[^\S\n]+").unwrap();
    text = space_re.replace_all(&text, " ").to_string();
    // Collapse 3+ newlines → 2.
    let nl_re = Regex::new(r"\n{3,}").unwrap();
    text = nl_re.replace_all(&text, "\n\n").to_string();
    // Trim each line.
    text = text
        .lines()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join("\n");
    text = text.trim().to_string();

    // Step 5 — truncate to ~4000 words.
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() > 4000 {
        text = words[..4000].join(" ");
        text.push_str("\n\n[... truncated to 4000 words ...]");
    }

    text
}

/// Strip all HTML tags from a string, leaving only text content.
fn strip_all_tags(s: &str) -> String {
    let re = Regex::new(r"<[^>]*>").unwrap();
    re.replace_all(s, "").to_string()
}

// ---------------------------------------------------------------------------
// SchemaExtractor
// ---------------------------------------------------------------------------

/// Rule-based structured data extractor.
///
/// No external LLM required. Uses a layered strategy for each schema:
/// JSON-LD → OpenGraph/meta → Microdata → CSS heuristics.
pub struct SchemaExtractor;

impl SchemaExtractor {
    // -----------------------------------------------------------------------
    // Product
    // -----------------------------------------------------------------------

    /// Extract product data from HTML.
    pub fn extract_product(html: &str) -> Option<ProductData> {
        // Layer 1: JSON-LD
        if let Some(p) = Self::product_from_jsonld(html) {
            if p.name.is_some() {
                return Some(p);
            }
        }
        // Layer 2: OpenGraph + meta
        if let Some(p) = Self::product_from_meta(html) {
            if p.name.is_some() {
                return Some(p);
            }
        }
        // Layer 3: Microdata
        if let Some(p) = Self::product_from_microdata(html) {
            if p.name.is_some() {
                return Some(p);
            }
        }
        // Layer 4: CSS heuristics
        Self::product_from_css(html)
    }

    fn product_from_jsonld(html: &str) -> Option<ProductData> {
        for block in extract_jsonld_blocks(html) {
            let val: JsonValue = serde_json::from_str(&block).ok()?;
            // Handle @graph arrays
            let items = jsonld_items_of_type(&val, "Product");
            for item in items {
                let mut p = ProductData::default();
                p.name = json_str(&item, "name");
                p.brand = item.get("brand")
                    .and_then(|b| {
                        if b.is_string() { b.as_str().map(String::from) }
                        else { json_str(b, "name") }
                    });
                p.sku = json_str(&item, "sku");
                p.image_url = json_str(&item, "image")
                    .or_else(|| item.get("image").and_then(|v| v.as_array())
                        .and_then(|a| a.first()).and_then(|v| v.as_str().map(String::from)));

                // Offers
                if let Some(offers) = item.get("offers") {
                    let offer = if offers.is_array() {
                        offers.as_array().and_then(|a| a.first())
                    } else {
                        Some(offers)
                    };
                    if let Some(o) = offer {
                        p.price = json_f64(o, "price")
                            .or_else(|| json_str(o, "price").and_then(|s| parse_price_str(&s)));
                        p.currency = json_str(o, "priceCurrency");
                        p.availability = json_str(o, "availability")
                            .map(|a| a.replace("https://schema.org/", "").replace("http://schema.org/", ""));
                    }
                }

                // Rating
                if let Some(rating) = item.get("aggregateRating") {
                    p.rating = json_f64(rating, "ratingValue")
                        .or_else(|| json_str(rating, "ratingValue").and_then(|s| s.parse().ok()));
                }

                if p.name.is_some() {
                    return Some(p);
                }
            }
        }
        None
    }

    fn product_from_meta(html: &str) -> Option<ProductData> {
        let mut p = ProductData::default();
        p.name = extract_meta(html, "og:title")
            .or_else(|| extract_meta(html, "twitter:title"));
        p.image_url = extract_meta(html, "og:image");
        p.price = extract_meta(html, "product:price:amount")
            .and_then(|s| parse_price_str(&s));
        p.currency = extract_meta(html, "product:price:currency")
            .or_else(|| extract_meta(html, "og:price:currency"));
        p.availability = extract_meta(html, "product:availability");

        if p.name.is_some() && (p.price.is_some() || p.image_url.is_some()) {
            Some(p)
        } else {
            None
        }
    }

    fn product_from_microdata(html: &str) -> Option<ProductData> {
        let mut p = ProductData::default();
        p.name = extract_itemprop_text(html, "name");
        p.price = extract_itemprop_content(html, "price")
            .and_then(|s| parse_price_str(&s));
        p.currency = extract_itemprop_content(html, "priceCurrency");
        p.availability = extract_itemprop_content(html, "availability");
        p.brand = extract_itemprop_text(html, "brand");
        p.sku = extract_itemprop_content(html, "sku");
        p.image_url = extract_itemprop_attr(html, "image", "src")
            .or_else(|| extract_itemprop_content(html, "image"));
        p.rating = extract_itemprop_content(html, "ratingValue")
            .and_then(|s| s.parse().ok());

        if p.name.is_some() { Some(p) } else { None }
    }

    fn product_from_css(html: &str) -> Option<ProductData> {
        let mut p = ProductData::default();
        let lower = html.to_lowercase();

        // Title: look for common product title selectors.
        p.name = extract_first_by_class(html, &lower, &[
            "product-title", "product-name", "product_title", "product_name",
            "pdp-title", "item-title", "item-name",
        ]).or_else(|| extract_first_by_attr(html, "data-product-name"))
          .or_else(|| {
              // Fallback: <h1> on the page
              let re = Regex::new(r"(?is)<h1\b[^>]*>(.*?)</h1>").ok()?;
              re.captures(html).map(|c| strip_all_tags(c[1].trim()).trim().to_string())
          });

        // Price: class or data-attribute.
        let price_text = extract_first_by_class(html, &lower, &[
            "price", "product-price", "offer-price", "sale-price",
            "price-current", "price-now", "priceblock_ourprice",
        ]).or_else(|| extract_first_by_attr(html, "data-price"));
        p.price = price_text.as_deref().and_then(parse_price_str);

        // Currency from price text.
        if let Some(ref pt) = price_text {
            p.currency = detect_currency(pt);
        }

        // Image: first large product image.
        let img_re = Regex::new(r#"(?i)<img\b[^>]*class\s*=\s*"[^"]*product[^"]*"[^>]*src\s*=\s*"([^"]+)"#).ok();
        if let Some(re) = img_re {
            p.image_url = re.captures(html).map(|c| c[1].to_string());
        }
        if p.image_url.is_none() {
            let img_re2 = Regex::new(r#"(?i)<img\b[^>]*src\s*=\s*"([^"]+)"[^>]*class\s*=\s*"[^"]*product[^"]*""#).ok();
            if let Some(re) = img_re2 {
                p.image_url = re.captures(html).map(|c| c[1].to_string());
            }
        }

        if p.name.is_some() || p.price.is_some() { Some(p) } else { None }
    }

    // -----------------------------------------------------------------------
    // Article
    // -----------------------------------------------------------------------

    /// Extract article data from HTML.
    pub fn extract_article(html: &str) -> Option<ArticleData> {
        if let Some(a) = Self::article_from_jsonld(html) {
            if a.title.is_some() {
                return Some(a);
            }
        }
        if let Some(a) = Self::article_from_meta(html) {
            if a.title.is_some() {
                return Some(a);
            }
        }
        Self::article_from_heuristics(html)
    }

    fn article_from_jsonld(html: &str) -> Option<ArticleData> {
        for block in extract_jsonld_blocks(html) {
            let val: JsonValue = serde_json::from_str(&block).ok()?;
            let types = ["Article", "NewsArticle", "BlogPosting", "WebPage", "TechArticle", "ScholarlyArticle"];
            for ty in &types {
                let items = jsonld_items_of_type(&val, ty);
                for item in items {
                    let mut a = ArticleData::default();
                    a.title = json_str(&item, "headline").or_else(|| json_str(&item, "name"));
                    a.author = item.get("author")
                        .and_then(|au| {
                            if au.is_string() { au.as_str().map(String::from) }
                            else if au.is_array() {
                                au.as_array().and_then(|arr| arr.first())
                                    .and_then(|v| json_str(v, "name"))
                            } else { json_str(au, "name") }
                        });
                    a.date = json_str(&item, "datePublished")
                        .or_else(|| json_str(&item, "dateCreated"));
                    a.body = json_str(&item, "articleBody").unwrap_or_default();
                    if a.title.is_some() {
                        // If body is empty, fill from page text.
                        if a.body.is_empty() {
                            a.body = extract_article_body(html);
                        }
                        return Some(a);
                    }
                }
            }
        }
        None
    }

    fn article_from_meta(html: &str) -> Option<ArticleData> {
        let mut a = ArticleData::default();
        a.title = extract_meta(html, "og:title")
            .or_else(|| extract_meta(html, "twitter:title"));
        a.author = extract_meta(html, "author")
            .or_else(|| extract_meta(html, "article:author"));
        a.date = extract_meta(html, "article:published_time")
            .or_else(|| extract_meta(html, "date"))
            .or_else(|| extract_meta(html, "publish_date"));
        a.body = extract_article_body(html);

        if a.title.is_some() { Some(a) } else { None }
    }

    fn article_from_heuristics(html: &str) -> Option<ArticleData> {
        let mut a = ArticleData::default();

        // Title from <h1> or <title>.
        let h1_re = Regex::new(r"(?is)<h1\b[^>]*>(.*?)</h1>").ok()?;
        a.title = h1_re.captures(html)
            .map(|c| strip_all_tags(c[1].trim()).trim().to_string())
            .or_else(|| {
                let title_re = Regex::new(r"(?is)<title\b[^>]*>(.*?)</title>").ok()?;
                title_re.captures(html).map(|c| c[1].trim().to_string())
            });

        // Author from rel="author" or class="author".
        let author_re = Regex::new(r#"(?is)<[^>]*(?:rel\s*=\s*"author"|class\s*=\s*"[^"]*author[^"]*")[^>]*>(.*?)</[^>]+>"#).ok()?;
        a.author = author_re.captures(html).map(|c| strip_all_tags(c[1].trim()).trim().to_string());

        // Date from <time>.
        let time_re = Regex::new(r#"(?is)<time\b[^>]*datetime\s*=\s*"([^"]+)"[^>]*>"#).ok()?;
        a.date = time_re.captures(html).map(|c| c[1].to_string());

        a.body = extract_article_body(html);

        if a.title.is_some() { Some(a) } else { None }
    }

    // -----------------------------------------------------------------------
    // Recipe
    // -----------------------------------------------------------------------

    /// Extract recipe data from HTML.
    pub fn extract_recipe(html: &str) -> Option<RecipeData> {
        if let Some(r) = Self::recipe_from_jsonld(html) {
            if r.name.is_some() {
                return Some(r);
            }
        }
        Self::recipe_from_microdata(html)
    }

    fn recipe_from_jsonld(html: &str) -> Option<RecipeData> {
        for block in extract_jsonld_blocks(html) {
            let val: JsonValue = serde_json::from_str(&block).ok()?;
            let items = jsonld_items_of_type(&val, "Recipe");
            for item in items {
                let mut r = RecipeData::default();
                r.name = json_str(&item, "name");

                // Ingredients.
                if let Some(arr) = item.get("recipeIngredient").and_then(|v| v.as_array()) {
                    r.ingredients = arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                        .collect();
                }

                // Instructions — can be string, array of strings, or array of HowToStep.
                if let Some(inst) = item.get("recipeInstructions") {
                    if let Some(s) = inst.as_str() {
                        r.instructions = s.split('\n')
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect();
                    } else if let Some(arr) = inst.as_array() {
                        for entry in arr {
                            if let Some(s) = entry.as_str() {
                                r.instructions.push(s.trim().to_string());
                            } else if let Some(text) = json_str(entry, "text") {
                                r.instructions.push(text);
                            }
                        }
                    }
                }

                r.prep_time = json_str(&item, "prepTime").map(|s| iso_duration_to_human(&s));
                r.cook_time = json_str(&item, "cookTime").map(|s| iso_duration_to_human(&s));

                if r.name.is_some() {
                    return Some(r);
                }
            }
        }
        None
    }

    fn recipe_from_microdata(html: &str) -> Option<RecipeData> {
        let mut r = RecipeData::default();
        r.name = extract_itemprop_text(html, "name");
        r.prep_time = extract_itemprop_content(html, "prepTime").map(|s| iso_duration_to_human(&s));
        r.cook_time = extract_itemprop_content(html, "cookTime").map(|s| iso_duration_to_human(&s));

        // Ingredients: multiple itemprop="recipeIngredient" elements.
        let re = Regex::new(r#"(?is)<[^>]*itemprop\s*=\s*"recipeIngredient"[^>]*>(.*?)</[^>]+>"#).ok()?;
        for cap in re.captures_iter(html) {
            let text = strip_all_tags(cap[1].trim()).trim().to_string();
            if !text.is_empty() {
                r.ingredients.push(text);
            }
        }

        // Instructions.
        let inst_re = Regex::new(r#"(?is)<[^>]*itemprop\s*=\s*"recipeInstructions"[^>]*>(.*?)</[^>]+>"#).ok()?;
        for cap in inst_re.captures_iter(html) {
            let text = strip_all_tags(cap[1].trim()).trim().to_string();
            if !text.is_empty() {
                r.instructions.push(text);
            }
        }

        if r.name.is_some() && (!r.ingredients.is_empty() || !r.instructions.is_empty()) {
            Some(r)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract all JSON-LD script blocks from HTML.
fn extract_jsonld_blocks(html: &str) -> Vec<String> {
    let re = Regex::new(r#"(?is)<script\b[^>]*type\s*=\s*["']application/ld\+json["'][^>]*>(.*?)</script>"#).unwrap();
    re.captures_iter(html)
        .map(|c| c[1].trim().to_string())
        .collect()
}

/// Given a JSON-LD value, find all items matching a given `@type`.
/// Handles top-level objects, `@graph` arrays, and nested arrays.
fn jsonld_items_of_type<'a>(val: &'a JsonValue, type_name: &str) -> Vec<&'a JsonValue> {
    let mut results = Vec::new();
    jsonld_walk(val, type_name, &mut results);
    results
}

fn jsonld_walk<'a>(val: &'a JsonValue, type_name: &str, out: &mut Vec<&'a JsonValue>) {
    match val {
        JsonValue::Object(map) => {
            if let Some(t) = map.get("@type") {
                let matches = if let Some(s) = t.as_str() {
                    s.eq_ignore_ascii_case(type_name)
                        || s.eq_ignore_ascii_case(&format!("schema.org/{type_name}"))
                        || s.eq_ignore_ascii_case(&format!("https://schema.org/{type_name}"))
                        || s.eq_ignore_ascii_case(&format!("http://schema.org/{type_name}"))
                } else if let Some(arr) = t.as_array() {
                    arr.iter().any(|v| v.as_str().map(|s|
                        s.eq_ignore_ascii_case(type_name)
                    ).unwrap_or(false))
                } else {
                    false
                };
                if matches {
                    out.push(val);
                }
            }
            // Walk @graph
            if let Some(graph) = map.get("@graph") {
                jsonld_walk(graph, type_name, out);
            }
        }
        JsonValue::Array(arr) => {
            for item in arr {
                jsonld_walk(item, type_name, out);
            }
        }
        _ => {}
    }
}

/// Get a string field from a JSON object.
fn json_str(val: &JsonValue, key: &str) -> Option<String> {
    val.get(key).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Get an f64 field from a JSON object.
fn json_f64(val: &JsonValue, key: &str) -> Option<f64> {
    val.get(key).and_then(|v| {
        v.as_f64().or_else(|| v.as_i64().map(|i| i as f64))
    })
}

/// Extract `<meta>` tag content by property or name.
fn extract_meta(html: &str, name: &str) -> Option<String> {
    // property="..." content="..."
    let re1 = Regex::new(&format!(
        r#"(?is)<meta\b[^>]*(?:property|name)\s*=\s*["']{name}["'][^>]*content\s*=\s*["']([^"']*)["'][^>]*/?\s*>"#
    )).ok()?;
    if let Some(cap) = re1.captures(html) {
        let val = cap[1].trim().to_string();
        if !val.is_empty() { return Some(val); }
    }
    // content="..." property="..." (reversed order)
    let re2 = Regex::new(&format!(
        r#"(?is)<meta\b[^>]*content\s*=\s*["']([^"']*)["'][^>]*(?:property|name)\s*=\s*["']{name}["'][^>]*/?\s*>"#
    )).ok()?;
    if let Some(cap) = re2.captures(html) {
        let val = cap[1].trim().to_string();
        if !val.is_empty() { return Some(val); }
    }
    None
}

/// Extract text content of an element with a given `itemprop`.
fn extract_itemprop_text(html: &str, prop: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"(?is)<[^>]*itemprop\s*=\s*["']{prop}["'][^>]*>(.*?)</[^>]+>"#
    )).ok()?;
    re.captures(html).map(|c| strip_all_tags(c[1].trim()).trim().to_string()).filter(|s| !s.is_empty())
}

/// Extract the `content` attribute of an element with a given `itemprop`.
fn extract_itemprop_content(html: &str, prop: &str) -> Option<String> {
    // content="..." itemprop="..."
    let re1 = Regex::new(&format!(
        r#"(?is)<[^>]*itemprop\s*=\s*["']{prop}["'][^>]*content\s*=\s*["']([^"']*)["'][^>]*/?\s*>"#
    )).ok()?;
    if let Some(cap) = re1.captures(html) {
        let v = cap[1].trim().to_string();
        if !v.is_empty() { return Some(v); }
    }
    let re2 = Regex::new(&format!(
        r#"(?is)<[^>]*content\s*=\s*["']([^"']*)["'][^>]*itemprop\s*=\s*["']{prop}["'][^>]*/?\s*>"#
    )).ok()?;
    if let Some(cap) = re2.captures(html) {
        let v = cap[1].trim().to_string();
        if !v.is_empty() { return Some(v); }
    }
    // Fallback to text content.
    extract_itemprop_text(html, prop)
}

/// Extract a specific attribute from an element with a given `itemprop`.
fn extract_itemprop_attr(html: &str, prop: &str, attr: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"(?is)<[^>]*itemprop\s*=\s*["']{prop}["'][^>]*{attr}\s*=\s*["']([^"']*)["'][^>]*/?\s*>"#
    )).ok()?;
    re.captures(html).map(|c| c[1].trim().to_string()).filter(|s| !s.is_empty())
}

/// Extract text from the first element matching any of the given class names.
fn extract_first_by_class(html: &str, html_lower: &str, classes: &[&str]) -> Option<String> {
    for class in classes {
        let class_lower = class.to_lowercase();
        // Check if class appears at all (fast reject).
        if !html_lower.contains(&class_lower) {
            continue;
        }
        let re = Regex::new(&format!(
            r#"(?is)<[^>]*class\s*=\s*["'][^"']*\b{}\b[^"']*["'][^>]*>(.*?)</[^>]+>"#,
            regex::escape(class)
        )).ok()?;
        if let Some(cap) = re.captures(html) {
            let text = strip_all_tags(cap[1].trim()).trim().to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

/// Extract text from first element with a given data-attribute.
fn extract_first_by_attr(html: &str, attr: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"(?is)<[^>]*{}\s*=\s*["']([^"']*)["'][^>]*>"#,
        regex::escape(attr)
    )).ok()?;
    re.captures(html).map(|c| c[1].trim().to_string()).filter(|s| !s.is_empty())
}

/// Extract the main body text from an article page.
fn extract_article_body(html: &str) -> String {
    // Try <article> tag first.
    let article_re = Regex::new(r"(?is)<article\b[^>]*>(.*?)</article>").ok();
    if let Some(ref re) = article_re {
        if let Some(cap) = re.captures(html) {
            let body = html_to_clean_text(&cap[1]);
            if body.split_whitespace().count() > 50 {
                return body;
            }
        }
    }

    // Try role="main" or id="content".
    let main_re = Regex::new(r#"(?is)<[^>]*(?:role\s*=\s*["']main["']|id\s*=\s*["']content["'])[^>]*>(.*?)</(?:div|main|section)>"#).ok();
    if let Some(ref re) = main_re {
        if let Some(cap) = re.captures(html) {
            let body = html_to_clean_text(&cap[1]);
            if body.split_whitespace().count() > 50 {
                return body;
            }
        }
    }

    // Fallback: concatenate all <p> tags.
    let p_re = Regex::new(r"(?is)<p\b[^>]*>(.*?)</p>").unwrap();
    let paragraphs: Vec<String> = p_re.captures_iter(html)
        .map(|c| strip_all_tags(c[1].trim()).trim().to_string())
        .filter(|s| s.split_whitespace().count() > 5)
        .collect();
    paragraphs.join("\n\n")
}

/// Parse a price string like "$29.99", "29,99 EUR", "USD 100.00" into f64.
fn parse_price_str(s: &str) -> Option<f64> {
    let re = Regex::new(r"[\d]+[.,]?\d*").ok()?;
    let m = re.find(s)?;
    let num_str = m.as_str().replace(',', ".");
    num_str.parse::<f64>().ok()
}

/// Detect currency symbol/code from a price string.
fn detect_currency(s: &str) -> Option<String> {
    let s = s.trim();
    if s.contains('$') || s.contains("USD") { return Some("USD".to_string()); }
    if s.contains('\u{20AC}') || s.contains("EUR") { return Some("EUR".to_string()); }
    if s.contains('\u{00A3}') || s.contains("GBP") { return Some("GBP".to_string()); }
    if s.contains('\u{00A5}') || s.contains("JPY") || s.contains("CNY") { return Some("JPY".to_string()); }
    if s.contains("CAD") || s.contains("CA$") { return Some("CAD".to_string()); }
    if s.contains("AUD") || s.contains("A$") { return Some("AUD".to_string()); }
    None
}

/// Convert ISO 8601 duration (PT1H30M) to human-readable form.
fn iso_duration_to_human(s: &str) -> String {
    let s = s.trim();
    if !s.starts_with("PT") && !s.starts_with("P") {
        return s.to_string();
    }
    let mut result = String::new();
    let re = Regex::new(r"(\d+)([HDMS])").unwrap();
    for cap in re.captures_iter(s) {
        let val = &cap[1];
        let unit = match &cap[2] {
            "H" => "hours",
            "D" => "days",
            "M" => "minutes",
            "S" => "seconds",
            _ => "?",
        };
        if !result.is_empty() { result.push(' '); }
        result.push_str(&format!("{val} {unit}"));
    }
    if result.is_empty() { s.to_string() } else { result }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_to_clean_text_strips_scripts() {
        let html = r#"<html><body><script>alert('x')</script><p>Hello world</p></body></html>"#;
        let text = html_to_clean_text(html);
        assert!(text.contains("Hello world"));
        assert!(!text.contains("alert"));
    }

    #[test]
    fn test_html_to_clean_text_collapses_whitespace() {
        let html = "<p>  lots   of    spaces  </p>";
        let text = html_to_clean_text(html);
        assert_eq!(text, "lots of spaces");
    }

    #[test]
    fn test_html_to_clean_text_truncates() {
        let long = (0..5000).map(|i| format!("word{i}")).collect::<Vec<_>>().join(" ");
        let html = format!("<p>{long}</p>");
        let text = html_to_clean_text(&html);
        assert!(text.contains("[... truncated to 4000 words ...]"));
    }

    #[test]
    fn test_product_from_jsonld() {
        let html = r#"
        <html><head>
        <script type="application/ld+json">
        {
            "@type": "Product",
            "name": "Widget Pro",
            "offers": { "price": 29.99, "priceCurrency": "USD", "availability": "InStock" },
            "aggregateRating": { "ratingValue": 4.5 },
            "brand": { "name": "Acme" },
            "sku": "WP-100"
        }
        </script></head><body></body></html>"#;
        let p = SchemaExtractor::extract_product(html).unwrap();
        assert_eq!(p.name.as_deref(), Some("Widget Pro"));
        assert_eq!(p.price, Some(29.99));
        assert_eq!(p.currency.as_deref(), Some("USD"));
        assert_eq!(p.brand.as_deref(), Some("Acme"));
        assert_eq!(p.sku.as_deref(), Some("WP-100"));
        assert_eq!(p.rating, Some(4.5));
    }

    #[test]
    fn test_product_from_meta() {
        let html = r#"
        <html><head>
        <meta property="og:title" content="Cool Gadget" />
        <meta property="product:price:amount" content="49.95" />
        <meta property="product:price:currency" content="EUR" />
        </head><body></body></html>"#;
        let p = SchemaExtractor::extract_product(html).unwrap();
        assert_eq!(p.name.as_deref(), Some("Cool Gadget"));
        assert_eq!(p.price, Some(49.95));
        assert_eq!(p.currency.as_deref(), Some("EUR"));
    }

    #[test]
    fn test_article_from_jsonld() {
        let html = r#"
        <html><head>
        <script type="application/ld+json">
        {
            "@type": "NewsArticle",
            "headline": "Big News Today",
            "author": { "name": "Jane Doe" },
            "datePublished": "2026-03-15"
        }
        </script></head><body><p>Some article body text that is long enough to count.</p></body></html>"#;
        let a = SchemaExtractor::extract_article(html).unwrap();
        assert_eq!(a.title.as_deref(), Some("Big News Today"));
        assert_eq!(a.author.as_deref(), Some("Jane Doe"));
        assert_eq!(a.date.as_deref(), Some("2026-03-15"));
    }

    #[test]
    fn test_recipe_from_jsonld() {
        let html = r#"
        <html><head>
        <script type="application/ld+json">
        {
            "@type": "Recipe",
            "name": "Chocolate Cake",
            "recipeIngredient": ["2 cups flour", "1 cup sugar", "3 eggs"],
            "recipeInstructions": [
                {"@type": "HowToStep", "text": "Preheat oven to 350F"},
                {"@type": "HowToStep", "text": "Mix dry ingredients"}
            ],
            "prepTime": "PT15M",
            "cookTime": "PT1H30M"
        }
        </script></head><body></body></html>"#;
        let r = SchemaExtractor::extract_recipe(html).unwrap();
        assert_eq!(r.name.as_deref(), Some("Chocolate Cake"));
        assert_eq!(r.ingredients.len(), 3);
        assert_eq!(r.instructions.len(), 2);
        assert_eq!(r.prep_time.as_deref(), Some("15 minutes"));
        assert_eq!(r.cook_time.as_deref(), Some("1 hours 30 minutes"));
    }

    #[test]
    fn test_parse_price_str() {
        assert_eq!(parse_price_str("$29.99"), Some(29.99));
        assert_eq!(parse_price_str("EUR 1.299,00"), Some(1.299)); // first match
        assert_eq!(parse_price_str("free"), None);
    }

    #[test]
    fn test_detect_currency() {
        assert_eq!(detect_currency("$29.99"), Some("USD".to_string()));
        assert_eq!(detect_currency("\u{20AC}10"), Some("EUR".to_string()));
        assert_eq!(detect_currency("\u{00A3}5"), Some("GBP".to_string()));
    }

    #[test]
    fn test_iso_duration_to_human() {
        assert_eq!(iso_duration_to_human("PT15M"), "15 minutes");
        assert_eq!(iso_duration_to_human("PT1H30M"), "1 hours 30 minutes");
        assert_eq!(iso_duration_to_human("PT45S"), "45 seconds");
    }
}
