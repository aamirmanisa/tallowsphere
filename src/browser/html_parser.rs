//! Fast HTML parser for extracting data from raw HTML without a browser.
//!
//! This module provides string-based HTML parsing for static pages.
//! For JavaScript-rendered content, use the full browser automation via CDP.
//! This is ~100x faster than launching a browser for simple extraction tasks.

/// Fast HTML parser using string-based extraction.
/// Handles tag selectors, class selectors, ID selectors, and common patterns.
pub struct HtmlParser;

impl HtmlParser {
    /// Extract text content matching a CSS selector from raw HTML.
    /// Supports simple tag selectors (`p`, `h1`), class selectors (`.price`),
    /// and ID selectors (`#title`).
    pub fn extract_text(html: &str, selector: &str) -> Vec<String> {
        let mut results = Vec::new();
        let selector_lower = selector.to_lowercase();

        // Handle ID selectors (#id)
        if selector.starts_with('#') {
            let id_name = &selector[1..];
            Self::extract_by_attribute(html, "id", id_name, &mut results);
            return results;
        }

        // Handle class selectors (.classname)
        if selector.starts_with('.') {
            let class_name = &selector[1..];
            Self::extract_by_class(html, class_name, &mut results);
            return results;
        }

        // Handle simple tag selectors (no . # or [)
        if !selector.contains('.') && !selector.contains('#') && !selector.contains('[') {
            let tag = selector_lower.trim();
            Self::extract_by_tag(html, tag, &mut results);
        }

        results
    }

    /// Extract elements by tag name.
    fn extract_by_tag(html: &str, tag: &str, results: &mut Vec<String>) {
        let open_tag = format!("<{}", tag);
        let close_tag = format!("</{}>", tag);
        let mut search_from = 0;

        while search_from < html.len() {
            let hay = &html[search_from..];
            let hay_lower = hay.to_lowercase();
            if let Some(start) = hay_lower.find(&open_tag) {
                let abs_start = search_from + start;
                if let Some(content_start) = html[abs_start..].find('>') {
                    let content_begin = abs_start + content_start + 1;
                    if content_begin < html.len() {
                        let remaining_lower = html[content_begin..].to_lowercase();
                        if let Some(end) = remaining_lower.find(&close_tag) {
                            let text = &html[content_begin..content_begin + end];
                            let stripped = strip_html_tags(text);
                            if !stripped.trim().is_empty() {
                                results.push(stripped.trim().to_string());
                            }
                        }
                    }
                }
                search_from = abs_start + 1;
            } else {
                break;
            }
        }
    }

    /// Extract elements by class attribute.
    fn extract_by_class(html: &str, class_name: &str, results: &mut Vec<String>) {
        let class_lower = class_name.to_lowercase();
        let mut search_from = 0;

        while search_from < html.len() {
            let hay_lower = html[search_from..].to_lowercase();
            // Look for class="classname" or class='classname' or class="... classname ..."
            let found = Self::find_class_attr(&hay_lower, &class_lower);

            if let Some(pos) = found {
                let abs_pos = search_from + pos;
                // Walk back to find the opening <
                let mut tag_start = abs_pos;
                while tag_start > 0 && html.as_bytes()[tag_start] != b'<' {
                    tag_start -= 1;
                }
                // Find the end of the opening tag >
                if let Some(gt_offset) = html[abs_pos..].find('>') {
                    let begin = abs_pos + gt_offset + 1;
                    if begin < html.len() {
                        // Find closing tag — look for the next </
                        if let Some(end) = html[begin..].find("</") {
                            let text = &html[begin..begin + end];
                            let stripped = strip_html_tags(text);
                            if !stripped.trim().is_empty() {
                                results.push(stripped.trim().to_string());
                            }
                        }
                    }
                }
                search_from = abs_pos + 1;
            } else {
                break;
            }
        }
    }

    /// Find a class attribute containing the given class name.
    fn find_class_attr(html_lower: &str, class_lower: &str) -> Option<usize> {
        let patterns = [
            format!("class=\"{}\"", class_lower),
            format!("class='{}'", class_lower),
            format!("class=\"{} ", class_lower),
            format!("class='{} ", class_lower),
            format!(" {} ", class_lower),   // space-delimited in class list
            format!(" {}\"", class_lower),  // last in class list
            format!(" {}'", class_lower),   // last in class list (single quotes)
        ];

        // Try exact class match first
        for pattern in &patterns[..4] {
            if let Some(pos) = html_lower.find(pattern.as_str()) {
                return Some(pos);
            }
        }

        // Try class within a class list
        let class_attr_pattern = "class=";
        let mut offset = 0;
        while let Some(pos) = html_lower[offset..].find(class_attr_pattern) {
            let abs = offset + pos;
            let after_eq = abs + class_attr_pattern.len();
            if after_eq >= html_lower.len() {
                break;
            }
            let quote = html_lower.as_bytes()[after_eq];
            let end_quote = if quote == b'"' { '"' } else if quote == b'\'' { '\'' } else { '"' };
            let val_start = after_eq + 1;
            if let Some(val_end) = html_lower[val_start..].find(end_quote) {
                let class_value = &html_lower[val_start..val_start + val_end];
                // Check if any class in the space-separated list matches
                for cls in class_value.split_whitespace() {
                    if cls == class_lower {
                        return Some(abs);
                    }
                }
            }
            offset = abs + 1;
        }

        None
    }

    /// Extract elements by a specific attribute (id, data-*, etc.).
    fn extract_by_attribute(html: &str, attr: &str, value: &str, results: &mut Vec<String>) {
        let pattern_dq = format!("{}=\"{}\"", attr, value);
        let pattern_sq = format!("{}='{}'", attr, value);
        let mut search_from = 0;

        while search_from < html.len() {
            let hay_lower = html[search_from..].to_lowercase();
            let found = hay_lower
                .find(&pattern_dq.to_lowercase())
                .or_else(|| hay_lower.find(&pattern_sq.to_lowercase()));

            if let Some(pos) = found {
                let abs_pos = search_from + pos;
                if let Some(gt_offset) = html[abs_pos..].find('>') {
                    let begin = abs_pos + gt_offset + 1;
                    if begin < html.len() {
                        if let Some(end) = html[begin..].find("</") {
                            let text = &html[begin..begin + end];
                            let stripped = strip_html_tags(text);
                            if !stripped.trim().is_empty() {
                                results.push(stripped.trim().to_string());
                            }
                        }
                    }
                }
                search_from = abs_pos + 1;
            } else {
                break;
            }
        }
    }

    /// Extract all links (href attributes) from HTML.
    pub fn extract_links(html: &str) -> Vec<String> {
        let mut links = Vec::new();
        let mut search_from = 0;
        let lower = html.to_lowercase();

        while search_from < lower.len() {
            if let Some(pos) = lower[search_from..].find("href=") {
                let abs_pos = search_from + pos + 5;
                if abs_pos >= html.len() {
                    break;
                }
                let quote = html.as_bytes()[abs_pos];
                if quote == b'"' || quote == b'\'' {
                    let val_start = abs_pos + 1;
                    let end_char = quote as char;
                    if let Some(end) = html[val_start..].find(end_char) {
                        let url = &html[val_start..val_start + end];
                        if !url.is_empty()
                            && !url.starts_with('#')
                            && !url.starts_with("javascript:")
                        {
                            links.push(url.to_string());
                        }
                    }
                    search_from = abs_pos + 1;
                } else {
                    search_from = abs_pos + 1;
                }
            } else {
                break;
            }
        }
        links
    }

    /// Extract meta tags (title, description, keywords, author, viewport, robots).
    pub fn extract_meta(html: &str) -> Vec<(String, String)> {
        let mut meta = Vec::new();
        let lower = html.to_lowercase();

        // Title tag
        if let Some(start) = lower.find("<title>") {
            if let Some(end) = lower[start + 7..].find("</title>") {
                let title = html[start + 7..start + 7 + end].trim().to_string();
                if !title.is_empty() {
                    meta.push(("title".to_string(), title));
                }
            }
        }

        // Meta name="..." content="..."
        for name in &[
            "description",
            "keywords",
            "author",
            "viewport",
            "robots",
        ] {
            let pattern = format!("name=\"{}\"", name);
            if let Some(pos) = lower.find(&pattern) {
                Self::extract_content_attr(html, pos, name, &mut meta);
            } else {
                // Also try single quotes
                let pattern_sq = format!("name='{}'", name);
                if let Some(pos) = lower.find(&pattern_sq) {
                    Self::extract_content_attr(html, pos, name, &mut meta);
                }
            }
        }

        meta
    }

    /// Helper to extract the content="..." attribute near a given position.
    fn extract_content_attr(
        html: &str,
        pos: usize,
        name: &str,
        meta: &mut Vec<(String, String)>,
    ) {
        // Look within a reasonable range of the name attribute for content=
        let search_range = html.len().min(pos + 200);
        let region = &html[pos..search_range];
        let region_lower = region.to_lowercase();

        if let Some(content_pos) = region_lower.find("content=") {
            let after_eq = content_pos + 8;
            if after_eq < region.len() {
                let quote = region.as_bytes()[after_eq];
                if quote == b'"' || quote == b'\'' {
                    let val_start = after_eq + 1;
                    let end_char = quote as char;
                    if let Some(end) = region[val_start..].find(end_char) {
                        let value = region[val_start..val_start + end].to_string();
                        meta.push((name.to_string(), value));
                    }
                }
            }
        }
    }
}

/// Strip HTML tags from a string, returning only text content.
pub fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        if ch == '<' {
            in_tag = true;
            continue;
        }
        if ch == '>' {
            in_tag = false;
            continue;
        }
        if !in_tag {
            result.push(ch);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_text_tag() {
        let html = "<html><body><h1>Hello World</h1><p>Some text</p></body></html>";
        let results = HtmlParser::extract_text(html, "h1");
        assert_eq!(results, vec!["Hello World"]);

        let results = HtmlParser::extract_text(html, "p");
        assert_eq!(results, vec!["Some text"]);
    }

    #[test]
    fn test_extract_text_multiple_tags() {
        let html = "<ul><li>First</li><li>Second</li><li>Third</li></ul>";
        let results = HtmlParser::extract_text(html, "li");
        assert_eq!(results, vec!["First", "Second", "Third"]);
    }

    #[test]
    fn test_extract_text_class() {
        let html = r#"<div class="price">$19.99</div><div class="title">Product A</div><div class="price">$29.99</div>"#;
        let results = HtmlParser::extract_text(html, ".price");
        assert_eq!(results, vec!["$19.99", "$29.99"]);
    }

    #[test]
    fn test_extract_text_id() {
        let html = r#"<div id="main-title">Welcome</div><div id="subtitle">Subtitle</div>"#;
        let results = HtmlParser::extract_text(html, "#main-title");
        assert_eq!(results, vec!["Welcome"]);
    }

    #[test]
    fn test_extract_text_nested_tags() {
        let html = "<div class=\"item\"><span>Bold <b>text</b></span></div>";
        let results = HtmlParser::extract_text(html, ".item");
        assert_eq!(results, vec!["Bold text"]);
    }

    #[test]
    fn test_extract_text_empty() {
        let html = "<html><body></body></html>";
        let results = HtmlParser::extract_text(html, "h1");
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_links() {
        let html = r##"
            <a href="https://example.com">Example</a>
            <a href="/about">About</a>
            <a href="#section">Section</a>
            <a href="javascript:void(0)">JS</a>
            <a href="https://other.com/page">Other</a>
        "##;
        let links = HtmlParser::extract_links(html);
        assert_eq!(
            links,
            vec![
                "https://example.com",
                "/about",
                "https://other.com/page",
            ]
        );
    }

    #[test]
    fn test_extract_links_single_quotes() {
        let html = "<a href='https://example.com'>Link</a>";
        let links = HtmlParser::extract_links(html);
        assert_eq!(links, vec!["https://example.com"]);
    }

    #[test]
    fn test_extract_meta() {
        let html = r#"
            <html>
            <head>
                <title>My Page</title>
                <meta name="description" content="A great page">
                <meta name="keywords" content="rust, html, parser">
                <meta name="author" content="Tallow Team">
            </head>
            <body></body>
            </html>
        "#;
        let meta = HtmlParser::extract_meta(html);
        assert!(meta.contains(&("title".to_string(), "My Page".to_string())));
        assert!(meta.contains(&("description".to_string(), "A great page".to_string())));
        assert!(meta.contains(&("keywords".to_string(), "rust, html, parser".to_string())));
        assert!(meta.contains(&("author".to_string(), "Tallow Team".to_string())));
    }

    #[test]
    fn test_extract_meta_no_title() {
        let html = "<html><head><meta name=\"description\" content=\"test\"></head></html>";
        let meta = HtmlParser::extract_meta(html);
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[0], ("description".to_string(), "test".to_string()));
    }

    #[test]
    fn test_strip_html_tags() {
        assert_eq!(strip_html_tags("<b>bold</b>"), "bold");
        assert_eq!(strip_html_tags("no tags"), "no tags");
        assert_eq!(
            strip_html_tags("<div><span>nested</span></div>"),
            "nested"
        );
        assert_eq!(strip_html_tags("<a href=\"url\">link text</a>"), "link text");
    }

    #[test]
    fn test_case_insensitive_tags() {
        let html = "<H1>Title</H1><P>Paragraph</P>";
        let results = HtmlParser::extract_text(html, "h1");
        assert_eq!(results, vec!["Title"]);
        let results = HtmlParser::extract_text(html, "p");
        assert_eq!(results, vec!["Paragraph"]);
    }
}
