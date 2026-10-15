//! Selector fallback chains for resilient extraction (T3.16).
//!
//! Tries primary selectors first, falls back to alternatives, and tracks
//! per-selector success rates so degradation can be alerted on.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorType {
    Css,
    XPath,
    TextRegex,
    JsonPath,
    JsVariable,
    AttributeValue,
}

#[derive(Debug, Clone)]
pub struct SelectorEntry {
    pub selector: String,
    pub selector_type: SelectorType,
    pub priority: u8,
    pub confidence_base: f64,
}

#[derive(Debug, Clone)]
pub struct ExtractionResult {
    pub value: Option<String>,
    pub selector_used: Option<SelectorEntry>,
    pub selector_index: usize,
    pub degraded: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ChainStats {
    pub total_extractions: u64,
    pub primary_success_count: u64,
    pub fallback_success_count: u64,
    pub total_failures: u64,
    pub per_selector_usage: Vec<u64>,
    pub degradation_rate: f64,
}

#[derive(Debug, Clone)]
pub struct SelectorChain {
    pub field_name: String,
    pub selectors: Vec<SelectorEntry>,
    stats: ChainStats,
}

impl SelectorChain {
    pub fn new(field_name: &str) -> Self {
        Self {
            field_name: field_name.to_string(),
            selectors: Vec::new(),
            stats: ChainStats::default(),
        }
    }

    pub fn add(&mut self, selector: &str, sel_type: SelectorType, priority: u8) {
        self.selectors.push(SelectorEntry {
            selector: selector.to_string(),
            selector_type: sel_type,
            priority,
            confidence_base: 1.0 - (priority as f64 * 0.1).min(0.9),
        });
        self.selectors.sort_by_key(|e| e.priority);
        self.stats.per_selector_usage.resize(self.selectors.len(), 0);
    }

    /// Try each selector in priority order. Uses lightweight matchers — CSS
    /// and XPath use simple tag/class/id probing; full DOM queries should be
    /// layered on top via [`crate::browser::html_parser`].
    pub fn try_extract(&self, html: &str) -> ExtractionResult {
        for (idx, entry) in self.selectors.iter().enumerate() {
            if let Some(value) = extract_with(entry, html) {
                return ExtractionResult {
                    value: Some(value),
                    selector_used: Some(entry.clone()),
                    selector_index: idx,
                    degraded: idx > 0,
                };
            }
        }
        ExtractionResult {
            value: None,
            selector_used: None,
            selector_index: usize::MAX,
            degraded: false,
        }
    }

    /// Record an extraction outcome against the chain's rolling stats.
    pub fn record(&mut self, result: &ExtractionResult) {
        self.stats.total_extractions += 1;
        match result.value {
            Some(_) => {
                if result.selector_index < self.stats.per_selector_usage.len() {
                    self.stats.per_selector_usage[result.selector_index] += 1;
                }
                if result.degraded {
                    self.stats.fallback_success_count += 1;
                } else {
                    self.stats.primary_success_count += 1;
                }
            }
            None => self.stats.total_failures += 1,
        }
        let successes =
            self.stats.primary_success_count + self.stats.fallback_success_count;
        self.stats.degradation_rate = if successes == 0 {
            0.0
        } else {
            self.stats.fallback_success_count as f64 / successes as f64
        };
    }

    pub fn stats(&self) -> ChainStats {
        self.stats.clone()
    }
}

fn extract_with(entry: &SelectorEntry, html: &str) -> Option<String> {
    match entry.selector_type {
        SelectorType::Css => extract_css(&entry.selector, html),
        SelectorType::XPath => extract_xpath(&entry.selector, html),
        SelectorType::TextRegex => extract_regex(&entry.selector, html),
        SelectorType::JsonPath => extract_jsonpath(&entry.selector, html),
        SelectorType::JsVariable => extract_js_var(&entry.selector, html),
        SelectorType::AttributeValue => extract_attribute(&entry.selector, html),
    }
}

/// Very small CSS selector matcher: supports `.class`, `#id`, and `tag`.
/// Returns the inner text of the first match.
fn extract_css(selector: &str, html: &str) -> Option<String> {
    let sel = selector.trim();
    let needle: String = if let Some(class) = sel.strip_prefix('.') {
        format!("class=\"{class}\"")
    } else if let Some(id) = sel.strip_prefix('#') {
        format!("id=\"{id}\"")
    } else {
        format!("<{sel}")
    };
    let idx = html.find(&needle)?;
    let after = &html[idx..];
    let gt = after.find('>')?;
    let rest = &after[gt + 1..];
    let end = rest.find('<')?;
    let text = rest[..end].trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn extract_xpath(selector: &str, html: &str) -> Option<String> {
    // Minimal: "//tag" → first tag's text.
    let tag = selector.trim_start_matches('/').trim();
    let needle = format!("<{tag}");
    let idx = html.find(&needle)?;
    let after = &html[idx..];
    let gt = after.find('>')?;
    let rest = &after[gt + 1..];
    let end = rest.find('<')?;
    Some(rest[..end].trim().to_string()).filter(|s| !s.is_empty())
}

fn extract_regex(pattern: &str, html: &str) -> Option<String> {
    // Simple literal contains — avoids regex dep.
    let idx = html.find(pattern)?;
    let slice = &html[idx..];
    let end = slice.find(['\n', '<']).unwrap_or(slice.len().min(200));
    Some(slice[..end].trim().to_string()).filter(|s| !s.is_empty())
}

fn extract_jsonpath(path: &str, html: &str) -> Option<String> {
    // JSON-LD block lookup: find <script type="application/ld+json"> then
    // locate "key": pattern matching the last segment of the path.
    let block_start = html.find("application/ld+json")?;
    let open = html[block_start..].find('>')? + block_start + 1;
    let close = html[open..].find("</script>")? + open;
    let json = &html[open..close];
    let key = path.rsplit('.').next()?;
    let needle = format!("\"{key}\"");
    let i = json.find(&needle)?;
    let after = &json[i + needle.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = rest.find([',', '}', '\n']).unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

fn extract_js_var(name: &str, html: &str) -> Option<String> {
    let needle = format!("{name}=");
    let i = html.find(&needle).or_else(|| html.find(&format!("{name} =")))?;
    let after = &html[i + needle.len()..];
    let end = after.find([';', '\n']).unwrap_or(after.len().min(500));
    Some(after[..end].trim().trim_matches('"').to_string())
}

fn extract_attribute(spec: &str, html: &str) -> Option<String> {
    // spec like `meta[property=og:price:amount]/content`
    let (locator, attr) = spec.split_once('/').unwrap_or((spec, "content"));
    let i = html.find(locator)?;
    let tag_start = html[..i].rfind('<')?;
    let tag_end = html[tag_start..].find('>')? + tag_start;
    let tag = &html[tag_start..=tag_end];
    let key = format!("{attr}=\"");
    let k = tag.find(&key)?;
    let v = &tag[k + key.len()..];
    let end = v.find('"')?;
    Some(v[..end].to_string())
}

/// Registry tracking chains per `(target, field)` and alerting on degradation.
#[derive(Debug, Default)]
pub struct ChainRegistry {
    chains: HashMap<(String, String), SelectorChain>,
    pub alert_threshold: f64,
}

impl ChainRegistry {
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
            alert_threshold: 0.10,
        }
    }

    pub fn register(&mut self, target: &str, chain: SelectorChain) {
        let key = (target.to_string(), chain.field_name.clone());
        self.chains.insert(key, chain);
    }

    pub fn get_mut(&mut self, target: &str, field: &str) -> Option<&mut SelectorChain> {
        self.chains.get_mut(&(target.to_string(), field.to_string()))
    }

    /// Returns `(target, field)` pairs whose degradation rate exceeds the
    /// configured alert threshold.
    pub fn alerts(&self) -> Vec<(String, String, f64)> {
        self.chains
            .iter()
            .filter_map(|((t, f), chain)| {
                let rate = chain.stats.degradation_rate;
                if rate > self.alert_threshold && chain.stats.total_extractions >= 10 {
                    Some((t.clone(), f.clone(), rate))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn css_primary_matches() {
        let mut chain = SelectorChain::new("price");
        chain.add(".price", SelectorType::Css, 0);
        chain.add(".cost", SelectorType::Css, 1);
        let html = r#"<div class="price">$9.99</div>"#;
        let r = chain.try_extract(html);
        assert_eq!(r.value.as_deref(), Some("$9.99"));
        assert!(!r.degraded);
        assert_eq!(r.selector_index, 0);
    }

    #[test]
    fn fallback_used_when_primary_missing() {
        let mut chain = SelectorChain::new("price");
        chain.add(".price", SelectorType::Css, 0);
        chain.add(".cost", SelectorType::Css, 1);
        let html = r#"<span class="cost">$4.50</span>"#;
        let r = chain.try_extract(html);
        assert_eq!(r.value.as_deref(), Some("$4.50"));
        assert!(r.degraded);
        assert_eq!(r.selector_index, 1);
    }

    #[test]
    fn stats_track_degradation() {
        let mut chain = SelectorChain::new("p");
        chain.add(".a", SelectorType::Css, 0);
        chain.add(".b", SelectorType::Css, 1);
        let r1 = chain.try_extract(r#"<div class="a">1</div>"#);
        chain.record(&r1);
        let r2 = chain.try_extract(r#"<div class="b">2</div>"#);
        chain.record(&r2);
        let s = chain.stats();
        assert_eq!(s.total_extractions, 2);
        assert_eq!(s.primary_success_count, 1);
        assert_eq!(s.fallback_success_count, 1);
        assert!((s.degradation_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn jsonld_price_extract() {
        let mut chain = SelectorChain::new("price");
        chain.add("offers.price", SelectorType::JsonPath, 0);
        let html = r#"<script type="application/ld+json">{"offers":{"price":"19.99"}}</script>"#;
        let r = chain.try_extract(html);
        assert_eq!(r.value.as_deref(), Some("19.99"));
    }

    #[test]
    fn attribute_extract() {
        let mut chain = SelectorChain::new("price");
        chain.add("og:price:amount\"/content", SelectorType::AttributeValue, 0);
        let html = r#"<meta property="og:price:amount" content="42.00" />"#;
        let r = chain.try_extract(html);
        assert_eq!(r.value.as_deref(), Some("42.00"));
    }

    #[test]
    fn registry_alerts_over_threshold() {
        let mut reg = ChainRegistry::new();
        let mut chain = SelectorChain::new("price");
        chain.add(".a", SelectorType::Css, 0);
        chain.add(".b", SelectorType::Css, 1);
        reg.register("heb.com", chain);
        for _ in 0..15 {
            let chain = reg.get_mut("heb.com", "price").unwrap();
            let r = chain.try_extract(r#"<div class="b">x</div>"#);
            chain.record(&r);
        }
        assert!(!reg.alerts().is_empty());
    }
}
