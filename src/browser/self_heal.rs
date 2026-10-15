//! Self-healing CSS selectors for Tallow's browser system.
//!
//! When a CSS selector fails to match any elements on a page, this module
//! analyses the page HTML and proposes fuzzy alternatives ranked by
//! similarity confidence.

use regex::Regex;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A candidate replacement selector with confidence score.
#[derive(Debug, Clone)]
pub struct SelectorCandidate {
    /// The proposed CSS selector.
    pub selector: String,
    /// Confidence that this selector matches the original intent (0.0 - 1.0).
    pub confidence: f64,
    /// Human-readable reason this candidate was proposed.
    pub reason: String,
    /// Sample text content this selector would extract.
    pub sample_text: String,
}

// ---------------------------------------------------------------------------
// SelfHealingSelector
// ---------------------------------------------------------------------------

/// Provides fuzzy recovery when a CSS selector fails to match.
pub struct SelfHealingSelector;

impl SelfHealingSelector {
    /// Given a page's HTML and a failed CSS selector, return up to 5 alternative
    /// selectors ranked by confidence.
    pub fn heal(page_html: &str, failed_selector: &str) -> Vec<SelectorCandidate> {
        let intent = SelectorIntent::parse(failed_selector);
        let elements = ElementIndex::build(page_html);

        let mut candidates: Vec<SelectorCandidate> = Vec::new();

        // Strategy 1: fuzzy class name matching.
        if let Some(ref class) = intent.class {
            Self::heal_by_class(class, &elements, &mut candidates);
        }

        // Strategy 2: fuzzy ID matching.
        if let Some(ref id) = intent.id {
            Self::heal_by_id(id, &elements, &mut candidates);
        }

        // Strategy 3: attribute-based matching (data-* attributes).
        if let Some(ref attr) = intent.attribute {
            Self::heal_by_attribute(attr, &elements, &mut candidates);
        }

        // Strategy 4: tag + semantic matching.
        if let Some(ref tag) = intent.tag {
            Self::heal_by_tag(tag, &intent, &elements, &mut candidates);
        }

        // Strategy 5: text content pattern matching.
        Self::heal_by_text_pattern(&intent, &elements, &mut candidates);

        // Deduplicate by selector string, keeping highest confidence.
        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut deduped: Vec<SelectorCandidate> = Vec::new();
        candidates.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        for c in candidates {
            if let Some(&idx) = seen.get(&c.selector) {
                if c.confidence > deduped[idx].confidence {
                    deduped[idx] = c;
                }
            } else {
                seen.insert(c.selector.clone(), deduped.len());
                deduped.push(c);
            }
        }

        deduped.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        deduped.truncate(5);
        deduped
    }

    // -----------------------------------------------------------------------
    // Healing strategies
    // -----------------------------------------------------------------------

    fn heal_by_class(target_class: &str, elements: &ElementIndex, out: &mut Vec<SelectorCandidate>) {
        let target_norm = normalize_identifier(target_class);
        let target_words = split_identifier_words(target_class);

        for (class_name, els) in &elements.by_class {
            if class_name == target_class { continue; }
            let cand_norm = normalize_identifier(class_name);
            let cand_words = split_identifier_words(class_name);

            // Exact normalized match (e.g. product-price vs productPrice).
            if cand_norm == target_norm {
                let sample = els.first().map(|e| e.text.clone()).unwrap_or_default();
                out.push(SelectorCandidate {
                    selector: format!(".{class_name}"),
                    confidence: 0.95,
                    reason: format!("equivalent naming convention: '{target_class}' -> '{class_name}'"),
                    sample_text: truncate_sample(&sample),
                });
                continue;
            }

            // Word overlap score.
            let overlap = word_overlap_score(&target_words, &cand_words);
            if overlap >= 0.5 {
                let sample = els.first().map(|e| e.text.clone()).unwrap_or_default();
                out.push(SelectorCandidate {
                    selector: format!(".{class_name}"),
                    confidence: (overlap * 0.85).min(0.9),
                    reason: format!("similar class name: '{target_class}' ~ '{class_name}'"),
                    sample_text: truncate_sample(&sample),
                });
                continue;
            }

            // Substring containment.
            if cand_norm.contains(&target_norm) || target_norm.contains(&cand_norm) {
                let sample = els.first().map(|e| e.text.clone()).unwrap_or_default();
                let ratio = target_norm.len().min(cand_norm.len()) as f64
                    / target_norm.len().max(cand_norm.len()) as f64;
                out.push(SelectorCandidate {
                    selector: format!(".{class_name}"),
                    confidence: ratio * 0.7,
                    reason: format!("class name contains similar substring: '{class_name}'"),
                    sample_text: truncate_sample(&sample),
                });
            }
        }
    }

    fn heal_by_id(target_id: &str, elements: &ElementIndex, out: &mut Vec<SelectorCandidate>) {
        let target_norm = normalize_identifier(target_id);
        let target_words = split_identifier_words(target_id);

        for (id, el) in &elements.by_id {
            if id == target_id { continue; }
            let cand_norm = normalize_identifier(id);
            let cand_words = split_identifier_words(id);

            if cand_norm == target_norm {
                out.push(SelectorCandidate {
                    selector: format!("#{id}"),
                    confidence: 0.95,
                    reason: format!("equivalent ID naming: '{target_id}' -> '{id}'"),
                    sample_text: truncate_sample(&el.text),
                });
                continue;
            }

            let overlap = word_overlap_score(&target_words, &cand_words);
            if overlap >= 0.5 {
                out.push(SelectorCandidate {
                    selector: format!("#{id}"),
                    confidence: (overlap * 0.8).min(0.85),
                    reason: format!("similar ID: '{target_id}' ~ '{id}'"),
                    sample_text: truncate_sample(&el.text),
                });
            }
        }
    }

    fn heal_by_attribute(target_attr: &str, elements: &ElementIndex, out: &mut Vec<SelectorCandidate>) {
        let target_norm = normalize_identifier(target_attr);
        let synonyms = attribute_synonyms(target_attr);

        for (attr_name, els) in &elements.by_data_attr {
            if attr_name == target_attr { continue; }
            let cand_norm = normalize_identifier(attr_name);

            let score = if cand_norm == target_norm {
                0.9
            } else if synonyms.iter().any(|s| normalize_identifier(s) == cand_norm) {
                0.8
            } else if cand_norm.contains(&target_norm) || target_norm.contains(&cand_norm) {
                0.6
            } else {
                continue;
            };

            let sample = els.first().map(|e| e.text.clone()).unwrap_or_default();
            out.push(SelectorCandidate {
                selector: format!("[{attr_name}]"),
                confidence: score,
                reason: format!("similar data attribute: '{target_attr}' ~ '{attr_name}'"),
                sample_text: truncate_sample(&sample),
            });
        }
    }

    fn heal_by_tag(target_tag: &str, intent: &SelectorIntent, elements: &ElementIndex, out: &mut Vec<SelectorCandidate>) {
        // If the selector was e.g. `span.price`, try other tags with similar classes.
        if let Some(ref class) = intent.class {
            let class_norm = normalize_identifier(class);
            for (tag, els) in &elements.by_tag {
                if tag == target_tag { continue; }
                for el in els {
                    for c in &el.classes {
                        if normalize_identifier(c) == class_norm {
                            out.push(SelectorCandidate {
                                selector: format!("{tag}.{c}"),
                                confidence: 0.7,
                                reason: format!("same class on different tag: '{target_tag}' -> '{tag}'"),
                                sample_text: truncate_sample(&el.text),
                            });
                            break;
                        }
                    }
                }
            }
        }

        // Suggest same tag with common semantic classes if no class was specified.
        if intent.class.is_none() && intent.id.is_none() {
            if let Some(els) = elements.by_tag.get(target_tag) {
                for el in els.iter().take(3) {
                    if !el.classes.is_empty() {
                        let cls = &el.classes[0];
                        out.push(SelectorCandidate {
                            selector: format!("{target_tag}.{cls}"),
                            confidence: 0.4,
                            reason: format!("tag '{target_tag}' with class '{cls}'"),
                            sample_text: truncate_sample(&el.text),
                        });
                    }
                }
            }
        }
    }

    fn heal_by_text_pattern(intent: &SelectorIntent, elements: &ElementIndex, out: &mut Vec<SelectorCandidate>) {
        // Infer what kind of content was being targeted from the selector name.
        let keywords = extract_semantic_keywords(&intent.raw);
        if keywords.is_empty() { return; }

        // Price pattern: $ followed by digits.
        let is_price = keywords.iter().any(|k| matches!(k.as_str(), "price" | "cost" | "amount" | "total"));
        if is_price {
            let price_re = Regex::new(r"[$\u{20AC}\u{00A3}\u{00A5}]\s*\d+[.,]?\d*|\d+[.,]\d+\s*(?:USD|EUR|GBP)").unwrap();
            for el in &elements.all {
                if price_re.is_match(&el.text) {
                    let selector = best_selector_for(el);
                    out.push(SelectorCandidate {
                        selector,
                        confidence: 0.65,
                        reason: "text matches price pattern (currency + digits)".to_string(),
                        sample_text: truncate_sample(&el.text),
                    });
                }
            }
        }

        // Date pattern.
        let is_date = keywords.iter().any(|k| matches!(k.as_str(), "date" | "time" | "published" | "posted"));
        if is_date {
            let date_re = Regex::new(r"\d{4}[-/]\d{2}[-/]\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+\d{1,2},?\s+\d{4}").unwrap();
            for el in &elements.all {
                if date_re.is_match(&el.text) {
                    let selector = best_selector_for(el);
                    out.push(SelectorCandidate {
                        selector,
                        confidence: 0.6,
                        reason: "text matches date pattern".to_string(),
                        sample_text: truncate_sample(&el.text),
                    });
                }
            }
        }

        // Email pattern.
        let is_email = keywords.iter().any(|k| matches!(k.as_str(), "email" | "mail" | "contact"));
        if is_email {
            let email_re = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
            for el in &elements.all {
                if email_re.is_match(&el.text) {
                    let selector = best_selector_for(el);
                    out.push(SelectorCandidate {
                        selector,
                        confidence: 0.6,
                        reason: "text matches email pattern".to_string(),
                        sample_text: truncate_sample(&el.text),
                    });
                }
            }
        }

        // Generic keyword match in class/id names of elements.
        for keyword in &keywords {
            for el in &elements.all {
                let kw_lower = keyword.to_lowercase();
                let matched_class = el.classes.iter().any(|c| c.to_lowercase().contains(&kw_lower));
                let matched_id = el.id.as_ref().map(|id| id.to_lowercase().contains(&kw_lower)).unwrap_or(false);
                if matched_class || matched_id {
                    let selector = best_selector_for(el);
                    // Avoid duplicating selectors we already proposed.
                    if !out.iter().any(|c| c.selector == selector) {
                        out.push(SelectorCandidate {
                            selector,
                            confidence: 0.45,
                            reason: format!("element class/id contains keyword '{keyword}'"),
                            sample_text: truncate_sample(&el.text),
                        });
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Selector intent parsing
// ---------------------------------------------------------------------------

/// Parsed understanding of what a CSS selector is trying to match.
struct SelectorIntent {
    raw: String,
    tag: Option<String>,
    class: Option<String>,
    id: Option<String>,
    attribute: Option<String>,
}

impl SelectorIntent {
    fn parse(selector: &str) -> Self {
        let raw = selector.trim().to_string();
        let mut tag = None;
        let mut class = None;
        let mut id = None;
        let mut attribute = None;

        // Extract attribute selector [attr] or [attr=value].
        let attr_re = Regex::new(r"\[([a-zA-Z0-9\-_]+)(?:=[^\]]+)?\]").unwrap();
        let mut remaining = raw.clone();
        if let Some(cap) = attr_re.captures(&remaining) {
            attribute = Some(cap[1].to_string());
            remaining = attr_re.replace(&remaining, "").to_string();
        }

        // Extract ID.
        let id_re = Regex::new(r"#([a-zA-Z0-9\-_]+)").unwrap();
        if let Some(cap) = id_re.captures(&remaining) {
            id = Some(cap[1].to_string());
            remaining = id_re.replace(&remaining, "").to_string();
        }

        // Extract class (first one).
        let class_re = Regex::new(r"\.([a-zA-Z0-9\-_]+)").unwrap();
        if let Some(cap) = class_re.captures(&remaining) {
            class = Some(cap[1].to_string());
            remaining = class_re.replace(&remaining, "").to_string();
        }

        // Remaining should be the tag (take last segment after space/combinator).
        let remaining = remaining.trim();
        if !remaining.is_empty() {
            // Take the last simple selector's tag portion.
            let parts: Vec<&str> = remaining.split_whitespace().collect();
            let last = parts.last().unwrap_or(&remaining);
            let tag_re = Regex::new(r"^([a-zA-Z][a-zA-Z0-9]*)").unwrap();
            if let Some(cap) = tag_re.captures(last) {
                tag = Some(cap[1].to_lowercase());
            }
        }

        SelectorIntent { raw, tag, class, id, attribute }
    }
}

// ---------------------------------------------------------------------------
// Element index — lightweight page analysis
// ---------------------------------------------------------------------------

/// A lightweight representation of an HTML element.
#[derive(Debug, Clone)]
struct ParsedElement {
    tag: String,
    id: Option<String>,
    classes: Vec<String>,
    data_attrs: Vec<String>,
    text: String,
}

/// Index of all elements on a page, organized for fast lookup.
struct ElementIndex {
    all: Vec<ParsedElement>,
    by_class: HashMap<String, Vec<ParsedElement>>,
    by_id: HashMap<String, ParsedElement>,
    by_tag: HashMap<String, Vec<ParsedElement>>,
    by_data_attr: HashMap<String, Vec<ParsedElement>>,
}

impl ElementIndex {
    fn build(html: &str) -> Self {
        let mut all = Vec::new();
        let mut by_class: HashMap<String, Vec<ParsedElement>> = HashMap::new();
        let mut by_id: HashMap<String, ParsedElement> = HashMap::new();
        let mut by_tag: HashMap<String, Vec<ParsedElement>> = HashMap::new();
        let mut by_data_attr: HashMap<String, Vec<ParsedElement>> = HashMap::new();

        // Match opening tags with their content.
        // We use a simple regex approach: find each opening tag and extract
        // the text until the next tag or closing tag.
        let tag_re = Regex::new(r"(?is)<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>([^<]*)").unwrap();

        for cap in tag_re.captures_iter(html) {
            let tag_name = cap[1].to_lowercase();
            let attrs_str = &cap[2];
            let immediate_text = cap[3].trim().to_string();

            // Skip non-content tags.
            if matches!(tag_name.as_str(), "script" | "style" | "meta" | "link" | "br" | "hr" | "img" | "input") {
                continue;
            }

            // For elements with child tags, try to get the full text content.
            let text = if immediate_text.is_empty() {
                // Try to find the closing tag and get all text in between.
                let open_pos = cap.get(0).map(|m| m.end()).unwrap_or(0);
                let close_pattern = format!("</{tag_name}>");
                let close_lower = html[open_pos..].to_lowercase();
                if let Some(close_offset) = close_lower.find(&close_pattern) {
                    let inner = &html[open_pos..open_pos + close_offset];
                    let strip_re = Regex::new(r"<[^>]*>").unwrap();
                    strip_re.replace_all(inner, " ").trim().to_string()
                } else {
                    String::new()
                }
            } else {
                immediate_text
            };

            // Parse attributes.
            let id = extract_attr_value(attrs_str, "id");
            let classes = extract_attr_value(attrs_str, "class")
                .map(|c| c.split_whitespace().map(String::from).collect::<Vec<_>>())
                .unwrap_or_default();
            let data_attrs = extract_data_attrs(attrs_str);

            let el = ParsedElement {
                tag: tag_name.clone(),
                id: id.clone(),
                classes: classes.clone(),
                data_attrs: data_attrs.clone(),
                text: text.clone(),
            };

            // Skip elements with empty text unless they have identifying attributes.
            if text.is_empty() && id.is_none() && classes.is_empty() && data_attrs.is_empty() {
                continue;
            }

            for class in &classes {
                by_class.entry(class.clone()).or_default().push(el.clone());
            }
            if let Some(ref id_val) = id {
                by_id.entry(id_val.clone()).or_insert_with(|| el.clone());
            }
            by_tag.entry(tag_name).or_default().push(el.clone());
            for attr in &data_attrs {
                by_data_attr.entry(attr.clone()).or_default().push(el.clone());
            }
            all.push(el);
        }

        ElementIndex { all, by_class, by_id, by_tag, by_data_attr }
    }
}

// ---------------------------------------------------------------------------
// String similarity and utilities
// ---------------------------------------------------------------------------

/// Normalize an identifier by lowercasing and removing separators.
/// "product-price" and "productPrice" both become "productprice".
fn normalize_identifier(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == '-' || ch == '_' {
            continue;
        }
        result.push(ch.to_ascii_lowercase());
    }
    result
}

/// Split an identifier into semantic words.
/// "productPrice" -> ["product", "price"]
/// "product-price" -> ["product", "price"]
/// "product_price_tag" -> ["product", "price", "tag"]
fn split_identifier_words(s: &str) -> Vec<String> {
    // First split on - and _.
    let parts: Vec<&str> = s.split(|c: char| c == '-' || c == '_').collect();
    let mut words = Vec::new();
    for part in parts {
        // Split camelCase.
        let mut current = String::new();
        for ch in part.chars() {
            if ch.is_uppercase() && !current.is_empty() {
                words.push(current.to_lowercase());
                current = String::new();
            }
            current.push(ch);
        }
        if !current.is_empty() {
            words.push(current.to_lowercase());
        }
    }
    words.into_iter().filter(|w| !w.is_empty()).collect()
}

/// Compute word overlap score between two sets of identifier words.
fn word_overlap_score(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() || b.is_empty() { return 0.0; }
    let matches = a.iter().filter(|w| b.contains(w)).count();
    let total = a.len().max(b.len());
    matches as f64 / total as f64
}

/// Extract the value of an HTML attribute from an attribute string.
fn extract_attr_value(attrs: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"(?i)\b{}\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))"#,
        regex::escape(name)
    )).ok()?;
    re.captures(attrs).map(|c| {
        c.get(1).or(c.get(2)).or(c.get(3)).map(|m| m.as_str().to_string()).unwrap_or_default()
    })
}

/// Extract all data-* attribute names from an attribute string.
fn extract_data_attrs(attrs: &str) -> Vec<String> {
    let re = Regex::new(r#"(?i)\b(data-[a-zA-Z0-9\-_]+)\s*="#).unwrap();
    re.captures_iter(attrs).map(|c| c[1].to_string()).collect()
}

/// Generate synonyms for common data attribute names.
fn attribute_synonyms(attr: &str) -> Vec<String> {
    let base = attr.replace("data-", "");
    let synonyms_map: &[(&[&str],)] = &[
        (&["price", "cost", "amount", "total", "value"],),
        (&["name", "title", "label", "heading"],),
        (&["image", "img", "photo", "picture", "thumbnail", "thumb"],),
        (&["date", "time", "datetime", "timestamp", "published"],),
        (&["id", "sku", "product-id", "item-id", "pid"],),
        (&["rating", "score", "stars", "review-score"],),
    ];
    let base_lower = base.to_lowercase();
    for (group,) in synonyms_map {
        if group.iter().any(|s| normalize_identifier(s) == normalize_identifier(&base_lower)) {
            return group.iter()
                .map(|s| format!("data-{s}"))
                .filter(|s| s != attr)
                .collect();
        }
    }
    Vec::new()
}

/// Build the best CSS selector for a parsed element.
fn best_selector_for(el: &ParsedElement) -> String {
    if let Some(ref id) = el.id {
        return format!("#{id}");
    }
    if !el.classes.is_empty() {
        return format!("{}.{}", el.tag, el.classes.join("."));
    }
    if !el.data_attrs.is_empty() {
        return format!("{}[{}]", el.tag, el.data_attrs[0]);
    }
    el.tag.clone()
}

/// Extract semantic keywords from a selector string.
fn extract_semantic_keywords(selector: &str) -> Vec<String> {
    // Remove CSS syntax characters and split into words.
    let cleaned = selector.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', " ");
    split_identifier_words(&cleaned)
        .into_iter()
        .filter(|w| w.len() > 2) // Skip tiny words like "a", "li"
        .collect()
}

/// Truncate a sample text string for display.
fn truncate_sample(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() <= 80 {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..77])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_identifier() {
        assert_eq!(normalize_identifier("product-price"), "productprice");
        assert_eq!(normalize_identifier("productPrice"), "productprice");
        assert_eq!(normalize_identifier("product_price"), "productprice");
        assert_eq!(normalize_identifier("PRODUCT-PRICE"), "productprice");
    }

    #[test]
    fn test_split_identifier_words() {
        assert_eq!(split_identifier_words("product-price"), vec!["product", "price"]);
        assert_eq!(split_identifier_words("productPrice"), vec!["product", "price"]);
        assert_eq!(split_identifier_words("product_price_tag"), vec!["product", "price", "tag"]);
    }

    #[test]
    fn test_word_overlap_score() {
        let a = vec!["product".into(), "price".into()];
        let b = vec!["product".into(), "cost".into()];
        assert_eq!(word_overlap_score(&a, &b), 0.5);

        let c = vec!["product".into(), "price".into()];
        assert_eq!(word_overlap_score(&a, &c), 1.0);
    }

    #[test]
    fn test_selector_intent_parse() {
        let intent = SelectorIntent::parse("div.product-price");
        assert_eq!(intent.tag.as_deref(), Some("div"));
        assert_eq!(intent.class.as_deref(), Some("product-price"));

        let intent2 = SelectorIntent::parse("#main-title");
        assert_eq!(intent2.id.as_deref(), Some("main-title"));

        let intent3 = SelectorIntent::parse("[data-price]");
        assert_eq!(intent3.attribute.as_deref(), Some("data-price"));
    }

    #[test]
    fn test_heal_finds_similar_class() {
        let html = r#"
        <html><body>
            <span class="productPrice">$29.99</span>
            <div class="item-cost">$19.99</div>
            <p class="unrelated">Hello</p>
        </body></html>"#;

        let candidates = SelfHealingSelector::heal(html, ".product-price");
        assert!(!candidates.is_empty(), "should find at least one candidate");

        // Should find productPrice as a high-confidence match.
        let top = &candidates[0];
        assert!(
            top.selector.contains("productPrice") || top.selector.contains("item-cost"),
            "top candidate should be a price-related selector, got: {}",
            top.selector
        );
        assert!(top.confidence > 0.5);
    }

    #[test]
    fn test_heal_finds_similar_id() {
        let html = r#"
        <html><body>
            <h1 id="mainTitle">Welcome</h1>
            <h2 id="sub-title">Subtitle</h2>
        </body></html>"#;

        let candidates = SelfHealingSelector::heal(html, "#main-title");
        let found_main_title = candidates.iter().any(|c| c.selector == "#mainTitle");
        assert!(found_main_title, "should find #mainTitle as alternative");
    }

    #[test]
    fn test_heal_by_text_pattern_price() {
        let html = r#"
        <html><body>
            <span class="cost-display">$49.99</span>
            <span class="other">hello</span>
        </body></html>"#;

        let candidates = SelfHealingSelector::heal(html, ".product-price");
        let has_price = candidates.iter().any(|c| c.sample_text.contains("49.99"));
        assert!(has_price, "should find element with price text pattern");
    }

    #[test]
    fn test_heal_returns_at_most_5() {
        let mut html = String::from("<html><body>");
        for i in 0..20 {
            html.push_str(&format!(r#"<div class="price-variant-{i}">${i}.99</div>"#));
        }
        html.push_str("</body></html>");

        let candidates = SelfHealingSelector::heal(&html, ".price");
        assert!(candidates.len() <= 5, "should return at most 5 candidates");
    }

    #[test]
    fn test_extract_attr_value() {
        assert_eq!(extract_attr_value(r#"class="foo bar" id="baz""#, "id"), Some("baz".into()));
        assert_eq!(extract_attr_value(r#"class="foo bar""#, "class"), Some("foo bar".into()));
        assert_eq!(extract_attr_value(r#"data-price="29.99""#, "data-price"), Some("29.99".into()));
    }

    #[test]
    fn test_extract_data_attrs() {
        let attrs = r#"class="x" data-price="29" data-sku="ABC" id="y""#;
        let result = extract_data_attrs(attrs);
        assert!(result.contains(&"data-price".to_string()));
        assert!(result.contains(&"data-sku".to_string()));
    }

    #[test]
    fn test_attribute_synonyms() {
        let syns = attribute_synonyms("data-price");
        assert!(syns.contains(&"data-cost".to_string()));
        assert!(syns.contains(&"data-amount".to_string()));
    }
}
