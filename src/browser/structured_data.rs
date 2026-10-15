//! JSON-LD, microdata, and structured data extraction from HTML.
//!
//! Extracts structured data embedded in web pages: JSON-LD (`<script type="application/ld+json">`),
//! product information (price, name, availability), and HTML microdata attributes.

use serde_json::Value;

/// Extracted product data from structured markup or common HTML patterns.
#[derive(Debug, Clone)]
pub struct ProductData {
    /// Product name.
    pub name: Option<String>,
    /// Price as a string (preserving currency formatting).
    pub price: Option<String>,
    /// Numeric price value, if parseable.
    pub price_value: Option<f64>,
    /// Currency code (USD, EUR, etc.).
    pub currency: Option<String>,
    /// Availability status (InStock, OutOfStock, etc.).
    pub availability: Option<String>,
    /// Aggregate rating value (e.g. 4.5).
    pub rating: Option<f64>,
    /// Number of reviews.
    pub review_count: Option<u32>,
    /// Product image URL.
    pub image: Option<String>,
    /// Product description.
    pub description: Option<String>,
    /// Brand name.
    pub brand: Option<String>,
    /// SKU or product identifier.
    pub sku: Option<String>,
}

/// A single microdata item extracted from HTML.
#[derive(Debug, Clone)]
pub struct MicrodataItem {
    /// The `itemtype` URL (e.g., "https://schema.org/Product").
    pub item_type: Option<String>,
    /// Key-value properties from `itemprop` attributes.
    pub properties: Vec<(String, String)>,
    /// Nested microdata items.
    pub children: Vec<MicrodataItem>,
}

/// Extractor for structured data embedded in HTML pages.
pub struct StructuredDataExtractor;

impl StructuredDataExtractor {
    /// Extract all JSON-LD blocks from page HTML.
    ///
    /// Finds all `<script type="application/ld+json">` elements and parses
    /// their contents as JSON. Invalid JSON blocks are silently skipped.
    pub fn extract_json_ld(html: &str) -> Vec<Value> {
        let mut results = Vec::new();
        let lower = html.to_lowercase();
        let target = "application/ld+json";
        let mut search_from = 0;

        while search_from < lower.len() {
            // Find script tag with ld+json type
            let type_pos = match lower[search_from..].find(target) {
                Some(p) => search_from + p,
                None => break,
            };

            // Find the opening > of this script tag
            let script_start = match lower[..type_pos].rfind("<script") {
                Some(p) => p,
                None => {
                    search_from = type_pos + target.len();
                    continue;
                }
            };

            let content_start = match html[script_start..].find('>') {
                Some(p) => script_start + p + 1,
                None => {
                    search_from = type_pos + target.len();
                    continue;
                }
            };

            // Find closing </script>
            let content_end = match lower[content_start..].find("</script>") {
                Some(p) => content_start + p,
                None => {
                    search_from = type_pos + target.len();
                    continue;
                }
            };

            let json_text = html[content_start..content_end].trim();

            if !json_text.is_empty() {
                // Try parsing as a single value or array
                if let Ok(val) = serde_json::from_str::<Value>(json_text) {
                    match val {
                        Value::Array(arr) => results.extend(arr),
                        other => results.push(other),
                    }
                }
            }

            search_from = content_end + 9; // past "</script>"
        }

        results
    }

    /// Extract product data from HTML using JSON-LD, microdata, and common patterns.
    ///
    /// Tries JSON-LD first (most reliable), then falls back to microdata and
    /// common CSS class patterns.
    pub fn extract_product(html: &str) -> Option<ProductData> {
        // Try JSON-LD first
        if let Some(product) = Self::extract_product_from_json_ld(html) {
            return Some(product);
        }

        // Try microdata
        if let Some(product) = Self::extract_product_from_microdata(html) {
            return Some(product);
        }

        // Try common HTML patterns as last resort
        Self::extract_product_from_html_patterns(html)
    }

    /// Extract all microdata items from HTML.
    ///
    /// Finds elements with `itemscope` and `itemtype` attributes and extracts
    /// their `itemprop` properties.
    pub fn extract_microdata(html: &str) -> Vec<MicrodataItem> {
        let mut items = Vec::new();
        let lower = html.to_lowercase();
        let mut search_from = 0;

        while let Some(scope_pos) = lower[search_from..].find("itemscope") {
            let abs_pos = search_from + scope_pos;

            // Find the tag that contains this itemscope
            let tag_start = match lower[..abs_pos].rfind('<') {
                Some(p) => p,
                None => {
                    search_from = abs_pos + 9;
                    continue;
                }
            };

            // Extract itemtype
            let tag_end = match html[tag_start..].find('>') {
                Some(p) => tag_start + p,
                None => {
                    search_from = abs_pos + 9;
                    continue;
                }
            };

            let tag_content = &html[tag_start..tag_end + 1];
            let item_type = extract_attribute(tag_content, "itemtype");

            // Find the tag name to locate the closing tag
            let tag_name = extract_tag_name(&html[tag_start..]);

            // Find matching closing tag (approximate — doesn't handle nested same-name tags perfectly)
            let close_tag = format!("</{}>", tag_name);
            let block_end = lower[tag_end..]
                .find(&close_tag.to_lowercase())
                .map(|p| tag_end + p)
                .unwrap_or(html.len());

            let block = &html[tag_end + 1..block_end];

            // Extract itemprop values from this block
            let properties = extract_itemprops(block);

            items.push(MicrodataItem {
                item_type,
                properties,
                children: Vec::new(), // Simplified: no recursive nesting
            });

            search_from = block_end + close_tag.len().min(html.len() - block_end);
        }

        items
    }

    /// Extract product data from JSON-LD blocks.
    fn extract_product_from_json_ld(html: &str) -> Option<ProductData> {
        let ld_blocks = Self::extract_json_ld(html);

        for block in &ld_blocks {
            // Check @type for Product or similar
            let block_type = block
                .get("@type")
                .and_then(|t| t.as_str())
                .unwrap_or("");

            if !matches!(
                block_type,
                "Product" | "IndividualProduct" | "ProductModel"
            ) {
                // Check @graph for nested products
                if let Some(graph) = block.get("@graph").and_then(|g| g.as_array()) {
                    for item in graph {
                        if let Some(t) = item.get("@type").and_then(|t| t.as_str()) {
                            if matches!(t, "Product" | "IndividualProduct" | "ProductModel") {
                                return Self::json_ld_to_product(item);
                            }
                        }
                    }
                }
                continue;
            }

            return Self::json_ld_to_product(block);
        }

        None
    }

    /// Convert a JSON-LD Product object to ProductData.
    fn json_ld_to_product(obj: &Value) -> Option<ProductData> {
        let name = obj.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());

        // Price from offers
        let offers = obj.get("offers").or_else(|| obj.get("Offers"));
        let (price, price_value, currency, availability) = if let Some(offers) = offers {
            let offer = if offers.is_array() {
                offers.as_array().and_then(|a| a.first())
            } else {
                Some(offers)
            };

            if let Some(offer) = offer {
                let price_str = offer
                    .get("price")
                    .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| {
                        v.as_f64().map(|f| format!("{f:.2}"))
                    }));
                let price_val = offer
                    .get("price")
                    .and_then(|v| {
                        v.as_f64().or_else(|| v.as_str().and_then(|s| s.replace(',', "").parse().ok()))
                    });
                let curr = offer
                    .get("priceCurrency")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let avail = offer
                    .get("availability")
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        // Normalize schema.org URLs to short form
                        s.replace("https://schema.org/", "")
                            .replace("http://schema.org/", "")
                    });
                (price_str, price_val, curr, avail)
            } else {
                (None, None, None, None)
            }
        } else {
            (None, None, None, None)
        };

        // Rating
        let rating_obj = obj.get("aggregateRating");
        let (rating, review_count) = if let Some(r) = rating_obj {
            let rv = r.get("ratingValue").and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            });
            let rc = r.get("reviewCount").and_then(|v| {
                v.as_u64()
                    .map(|n| n as u32)
                    .or_else(|| v.as_str().and_then(|s| s.replace(',', "").parse().ok()))
            });
            (rv, rc)
        } else {
            (None, None)
        };

        let image = obj
            .get("image")
            .and_then(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v.as_array().and_then(|a| a.first()).and_then(|v| v.as_str().map(|s| s.to_string())))
                    .or_else(|| v.get("url").and_then(|u| u.as_str()).map(|s| s.to_string()))
            });

        let description = obj
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let brand = obj
            .get("brand")
            .and_then(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
            });

        let sku = obj
            .get("sku")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if name.is_some() || price.is_some() {
            Some(ProductData {
                name,
                price,
                price_value,
                currency,
                availability,
                rating,
                review_count,
                image,
                description,
                brand,
                sku,
            })
        } else {
            None
        }
    }

    /// Extract product data from microdata attributes.
    fn extract_product_from_microdata(html: &str) -> Option<ProductData> {
        let items = Self::extract_microdata(html);

        for item in &items {
            let is_product = item
                .item_type
                .as_deref()
                .map(|t| t.contains("Product"))
                .unwrap_or(false);

            if !is_product {
                continue;
            }

            let mut product = ProductData {
                name: None,
                price: None,
                price_value: None,
                currency: None,
                availability: None,
                rating: None,
                review_count: None,
                image: None,
                description: None,
                brand: None,
                sku: None,
            };

            for (prop, value) in &item.properties {
                match prop.as_str() {
                    "name" => product.name = Some(value.clone()),
                    "price" => {
                        product.price = Some(value.clone());
                        product.price_value = value.replace(',', "").parse().ok();
                    }
                    "priceCurrency" => product.currency = Some(value.clone()),
                    "availability" => {
                        product.availability = Some(
                            value
                                .replace("https://schema.org/", "")
                                .replace("http://schema.org/", ""),
                        );
                    }
                    "ratingValue" => product.rating = value.parse().ok(),
                    "reviewCount" => {
                        product.review_count = value.replace(',', "").parse().ok();
                    }
                    "image" => product.image = Some(value.clone()),
                    "description" => product.description = Some(value.clone()),
                    "brand" => product.brand = Some(value.clone()),
                    "sku" => product.sku = Some(value.clone()),
                    _ => {}
                }
            }

            if product.name.is_some() || product.price.is_some() {
                return Some(product);
            }
        }

        None
    }

    /// Last-resort extraction using common HTML class/id patterns.
    fn extract_product_from_html_patterns(html: &str) -> Option<ProductData> {
        let lower = html.to_lowercase();

        // Try to find a product name from common selectors
        let name = find_meta_content(html, "og:title")
            .or_else(|| find_meta_content(html, "twitter:title"))
            .or_else(|| extract_first_tag_content(html, "h1"));

        // Try to find price from common patterns
        let price = find_by_class_content(html, &lower, "price")
            .or_else(|| find_by_class_content(html, &lower, "product-price"))
            .or_else(|| find_by_class_content(html, &lower, "offer-price"));

        let price_value = price
            .as_ref()
            .and_then(|p| extract_numeric_price(p));

        if name.is_some() || price.is_some() {
            Some(ProductData {
                name,
                price,
                price_value,
                currency: None,
                availability: None,
                rating: None,
                review_count: None,
                image: find_meta_content(html, "og:image"),
                description: find_meta_content(html, "og:description")
                    .or_else(|| find_meta_content(html, "description")),
                brand: None,
                sku: None,
            })
        } else {
            None
        }
    }
}

/// Extract an HTML attribute value from a tag string.
fn extract_attribute(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let attr_lower = attr.to_lowercase();

    // Try attr="value"
    for quote in ['"', '\''] {
        let pattern = format!("{}={}", attr_lower, quote);
        if let Some(start) = lower.find(&pattern) {
            let val_start = start + pattern.len();
            if let Some(val_end) = tag[val_start..].find(quote) {
                return Some(tag[val_start..val_start + val_end].to_string());
            }
        }
    }

    None
}

/// Extract the tag name from an opening tag.
fn extract_tag_name(tag: &str) -> String {
    let without_bracket = tag.trim_start_matches('<');
    let end = without_bracket
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .unwrap_or(without_bracket.len());
    without_bracket[..end].to_lowercase()
}

/// Extract itemprop values from an HTML block.
fn extract_itemprops(html: &str) -> Vec<(String, String)> {
    let mut props = Vec::new();
    let lower = html.to_lowercase();
    let mut search_from = 0;

    while let Some(pos) = lower[search_from..].find("itemprop") {
        let abs_pos = search_from + pos;

        // Find the enclosing tag
        let tag_start = match lower[..abs_pos].rfind('<') {
            Some(p) => p,
            None => {
                search_from = abs_pos + 8;
                continue;
            }
        };

        let tag_end = match html[tag_start..].find('>') {
            Some(p) => tag_start + p,
            None => {
                search_from = abs_pos + 8;
                continue;
            }
        };

        let tag = &html[tag_start..tag_end + 1];

        if let Some(prop_name) = extract_attribute(tag, "itemprop") {
            // Get value from: content attr, href attr, src attr, or text content
            let value = extract_attribute(tag, "content")
                .or_else(|| extract_attribute(tag, "href"))
                .or_else(|| extract_attribute(tag, "src"))
                .or_else(|| {
                    // Get text content until closing tag
                    let tag_name = extract_tag_name(&html[tag_start..]);
                    let close = format!("</{}>", tag_name);
                    lower[tag_end + 1..]
                        .find(&close.to_lowercase())
                        .map(|end| {
                            let text = &html[tag_end + 1..tag_end + 1 + end];
                            strip_tags(text).trim().to_string()
                        })
                });

            if let Some(val) = value {
                if !val.is_empty() {
                    props.push((prop_name, val));
                }
            }
        }

        search_from = tag_end + 1;
    }

    props
}

/// Strip HTML tags from a string, returning only text content.
fn strip_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(ch);
        }
    }
    result
}

/// Find a <meta> tag's content by property or name attribute.
fn find_meta_content(html: &str, name: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let name_lower = name.to_lowercase();

    // Search for property="name" or name="name"
    for attr_name in &["property", "name"] {
        for quote in ['"', '\''] {
            let pattern = format!("{attr_name}={quote}{name_lower}{quote}");
            if let Some(pos) = lower.find(&pattern) {
                // Find the enclosing <meta tag
                let tag_start = lower[..pos].rfind("<meta")?;
                let tag_end = html[tag_start..].find('>')? + tag_start;
                let tag = &html[tag_start..tag_end + 1];
                return extract_attribute(tag, "content");
            }
        }
    }
    None
}

/// Extract text content of the first occurrence of a tag.
fn extract_first_tag_content(html: &str, tag: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start = lower.find(&open)?;
    let content_start = html[start..].find('>')? + start + 1;
    let end = lower[content_start..].find(&close)? + content_start;

    let text = strip_tags(&html[content_start..end]).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Find element text by class name.
fn find_by_class_content(html: &str, lower: &str, class: &str) -> Option<String> {
    let class_lower = class.to_lowercase();

    // Look for class="...class_name..."
    for quote in ['"', '\''] {
        let class_attr = format!("class={quote}");
        let mut search_from = 0;

        while let Some(pos) = lower[search_from..].find(&class_attr) {
            let abs_pos = search_from + pos;
            let val_start = abs_pos + class_attr.len();
            let val_end = match lower[val_start..].find(quote) {
                Some(e) => val_start + e,
                None => {
                    search_from = val_start;
                    continue;
                }
            };

            let classes = &lower[val_start..val_end];
            if classes.split_whitespace().any(|c| c == class_lower) {
                // Found a matching element — extract its text
                let tag_start = lower[..abs_pos].rfind('<')?;
                let tag_end = html[tag_start..].find('>')? + tag_start;
                let tag_name = extract_tag_name(&html[tag_start..]);
                let close = format!("</{}>", tag_name);

                if let Some(end) = lower[tag_end + 1..].find(&close) {
                    let text = strip_tags(&html[tag_end + 1..tag_end + 1 + end])
                        .trim()
                        .to_string();
                    if !text.is_empty() {
                        return Some(text);
                    }
                }
            }

            search_from = val_end + 1;
        }
    }

    None
}

/// Extract a numeric price from a price string like "$19.99" or "EUR 1,234.56".
fn extract_numeric_price(price_str: &str) -> Option<f64> {
    // Remove currency symbols and whitespace, keep digits, dots, commas
    let cleaned: String = price_str
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
        .collect();

    if cleaned.is_empty() {
        return None;
    }

    // Handle European format (1.234,56) vs US format (1,234.56)
    let last_dot = cleaned.rfind('.');
    let last_comma = cleaned.rfind(',');

    let normalized = match (last_dot, last_comma) {
        (Some(d), Some(c)) if c > d => {
            // European: 1.234,56 -> 1234.56
            cleaned.replace('.', "").replace(',', ".")
        }
        (Some(_d), Some(_c)) => {
            // US: 1,234.56 -> 1234.56
            cleaned.replace(',', "")
        }
        (None, Some(_)) => {
            // Could be European decimal or US thousands
            // If comma is followed by exactly 2 digits at end, treat as decimal
            if cleaned.ends_with(|_: char| true) {
                let parts: Vec<&str> = cleaned.split(',').collect();
                if parts.len() == 2 && parts[1].len() == 2 {
                    cleaned.replace(',', ".")
                } else {
                    cleaned.replace(',', "")
                }
            } else {
                cleaned.replace(',', "")
            }
        }
        _ => cleaned,
    };

    normalized.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_ld() {
        let html = r#"<html><head>
<script type="application/ld+json">
{"@type":"Product","name":"Widget","offers":{"price":"19.99","priceCurrency":"USD"}}
</script>
</head><body></body></html>"#;

        let ld = StructuredDataExtractor::extract_json_ld(html);
        assert_eq!(ld.len(), 1);
        assert_eq!(ld[0]["@type"], "Product");
        assert_eq!(ld[0]["name"], "Widget");
    }

    #[test]
    fn test_extract_multiple_json_ld() {
        let html = r#"<html>
<script type="application/ld+json">{"@type":"Organization","name":"Acme"}</script>
<script type="application/ld+json">{"@type":"Product","name":"Gizmo"}</script>
</html>"#;

        let ld = StructuredDataExtractor::extract_json_ld(html);
        assert_eq!(ld.len(), 2);
    }

    #[test]
    fn test_extract_json_ld_array() {
        let html = r#"<script type="application/ld+json">
[{"@type":"BreadcrumbList"},{"@type":"Product","name":"Foo"}]
</script>"#;

        let ld = StructuredDataExtractor::extract_json_ld(html);
        assert_eq!(ld.len(), 2);
    }

    #[test]
    fn test_extract_product_from_json_ld() {
        let html = r#"<script type="application/ld+json">
{
  "@type": "Product",
  "name": "Super Widget",
  "offers": {
    "price": "29.99",
    "priceCurrency": "USD",
    "availability": "https://schema.org/InStock"
  },
  "aggregateRating": {
    "ratingValue": "4.5",
    "reviewCount": "128"
  },
  "brand": {"name": "WidgetCo"},
  "sku": "WDG-001"
}
</script>"#;

        let product = StructuredDataExtractor::extract_product(html).unwrap();
        assert_eq!(product.name.as_deref(), Some("Super Widget"));
        assert_eq!(product.price.as_deref(), Some("29.99"));
        assert_eq!(product.price_value, Some(29.99));
        assert_eq!(product.currency.as_deref(), Some("USD"));
        assert_eq!(product.availability.as_deref(), Some("InStock"));
        assert_eq!(product.rating, Some(4.5));
        assert_eq!(product.review_count, Some(128));
        assert_eq!(product.brand.as_deref(), Some("WidgetCo"));
        assert_eq!(product.sku.as_deref(), Some("WDG-001"));
    }

    #[test]
    fn test_extract_microdata() {
        let html = r#"<div itemscope itemtype="https://schema.org/Product">
  <span itemprop="name">Cool Gadget</span>
  <span itemprop="price" content="49.99">$49.99</span>
</div>"#;

        let items = StructuredDataExtractor::extract_microdata(html);
        assert!(!items.is_empty());
        assert!(items[0]
            .item_type
            .as_ref()
            .unwrap()
            .contains("Product"));

        let name_prop = items[0].properties.iter().find(|(k, _)| k == "name");
        assert!(name_prop.is_some());
    }

    #[test]
    fn test_extract_numeric_price() {
        assert_eq!(extract_numeric_price("$19.99"), Some(19.99));
        assert_eq!(extract_numeric_price("EUR 1,234.56"), Some(1234.56));
        assert_eq!(extract_numeric_price("1.234,56 €"), Some(1234.56));
        assert_eq!(extract_numeric_price("$0.99"), Some(0.99));
        assert!(extract_numeric_price("free").is_none());
    }

    #[test]
    fn test_find_meta_content() {
        let html = r#"<html><head>
<meta property="og:title" content="My Product">
<meta name="description" content="A great product">
</head></html>"#;

        assert_eq!(
            find_meta_content(html, "og:title"),
            Some("My Product".to_string())
        );
        assert_eq!(
            find_meta_content(html, "description"),
            Some("A great product".to_string())
        );
    }

    #[test]
    fn test_empty_json_ld() {
        let html = "<html><body>No structured data here</body></html>";
        let ld = StructuredDataExtractor::extract_json_ld(html);
        assert!(ld.is_empty());
    }

    #[test]
    fn test_strip_tags() {
        assert_eq!(strip_tags("<b>bold</b> text"), "bold text");
        assert_eq!(strip_tags("no tags"), "no tags");
    }
}
