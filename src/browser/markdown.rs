//! HTML-to-Markdown converter optimized for LLM consumption.
//!
//! Strips navigation, ads, sidebars, footers, and boilerplate, then converts
//! the remaining content to clean Markdown. Uses heuristics to identify the
//! main content area and preserve semantic structure.

/// Convert HTML to clean Markdown, stripping boilerplate.
///
/// Removes nav, header, footer, sidebar, ad, and cookie-banner elements.
/// Converts headings, links, images, lists, tables, code blocks, bold,
/// italic, and blockquotes to their Markdown equivalents.
pub fn html_to_markdown(html: &str) -> String {
    // Step 1: Remove boilerplate elements
    let cleaned = remove_boilerplate(html);

    // Step 2: Extract the main content area if possible
    let content = extract_main_content(&cleaned).unwrap_or(cleaned);

    // Step 3: Convert HTML to Markdown
    let md = convert_to_markdown(&content);

    // Step 4: Clean up whitespace
    clean_whitespace(&md)
}

/// Remove boilerplate elements: nav, header, footer, sidebar, ads, etc.
fn remove_boilerplate(html: &str) -> String {
    let mut result = html.to_string();

    // Remove script and style tags with their content
    result = remove_tag_with_content(&result, "script");
    result = remove_tag_with_content(&result, "style");
    result = remove_tag_with_content(&result, "noscript");
    result = remove_tag_with_content(&result, "svg");
    result = remove_tag_with_content(&result, "iframe");

    // Remove common boilerplate elements
    let boilerplate_tags = ["nav", "header", "footer"];
    for tag in &boilerplate_tags {
        result = remove_tag_with_content(&result, tag);
    }

    // Remove elements by class/id patterns (ads, sidebars, cookie banners)
    let boilerplate_patterns = [
        "sidebar",
        "side-bar",
        "advertisement",
        "ad-container",
        "ad-wrapper",
        "cookie-banner",
        "cookie-consent",
        "cookie-notice",
        "gdpr",
        "newsletter-signup",
        "newsletter-popup",
        "popup-overlay",
        "social-share",
        "social-buttons",
        "breadcrumb",
        "skip-to-content",
        "sr-only",
        "visually-hidden",
        "comments-section",
        "related-posts",
        "recommended",
    ];

    for pattern in &boilerplate_patterns {
        result = remove_elements_by_class_or_id(&result, pattern);
    }

    // Remove elements with role attributes for nav-like sections
    let boilerplate_roles = ["navigation", "banner", "contentinfo", "complementary"];
    for role in &boilerplate_roles {
        result = remove_elements_by_attribute(&result, "role", role);
    }

    result
}

/// Try to extract the main content area (<main>, <article>, or role="main").
fn extract_main_content(html: &str) -> Option<String> {
    let lower = html.to_lowercase();

    // Try <main> tag first
    if let Some(content) = extract_tag_content_block(html, &lower, "main") {
        return Some(content);
    }

    // Try <article> tag
    if let Some(content) = extract_tag_content_block(html, &lower, "article") {
        return Some(content);
    }

    // Try role="main"
    if let Some(pos) = lower.find("role=\"main\"") {
        let tag_start = lower[..pos].rfind('<')?;
        let tag_name = extract_tag_name_at(&html[tag_start..]);
        let close = format!("</{}>", tag_name);
        let tag_end = html[tag_start..].find('>')? + tag_start;
        let content_end = lower[tag_end + 1..].find(&close.to_lowercase())? + tag_end + 1;
        return Some(html[tag_end + 1..content_end].to_string());
    }

    // Try common content div IDs/classes
    for id in &["content", "main-content", "page-content", "post-content", "entry-content"] {
        if let Some(content) = extract_element_by_id(html, &lower, id) {
            return Some(content);
        }
    }

    None
}

/// Convert cleaned HTML to Markdown.
fn convert_to_markdown(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let chars: Vec<char> = html.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '<' {
            // Parse the tag
            let tag_start = i;
            let mut tag_end = i + 1;
            while tag_end < len && chars[tag_end] != '>' {
                tag_end += 1;
            }
            if tag_end >= len {
                i += 1;
                continue;
            }

            let tag_str: String = chars[tag_start..=tag_end].iter().collect();
            let tag_lower = tag_str.to_lowercase();

            if tag_lower.starts_with("</") {
                // Closing tag — handle block element spacing
                let tag_name = extract_closing_tag_name(&tag_lower);
                match tag_name.as_str() {
                    "p" | "div" | "section" | "article" | "main" => {
                        result.push_str("\n\n");
                    }
                    "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                        result.push('\n');
                    }
                    "li" => {
                        result.push('\n');
                    }
                    "tr" => {
                        result.push_str("|\n");
                    }
                    "blockquote" => {
                        result.push('\n');
                    }
                    "pre" => {
                        result.push_str("\n```\n");
                    }
                    "code" => {
                        // Only add backtick if not inside a pre block
                        if !is_inside_pre(html, tag_start) {
                            result.push('`');
                        }
                    }
                    "strong" | "b" => result.push_str("**"),
                    "em" | "i" => result.push('*'),
                    "del" | "s" | "strike" => result.push_str("~~"),
                    "a" => {
                        // Close link: find the href from the opening tag
                        // Already handled inline in opening tag processing
                    }
                    "table" => result.push('\n'),
                    _ => {}
                }
                i = tag_end + 1;
                continue;
            }

            // Opening tag
            let tag_name = extract_opening_tag_name(&tag_lower);
            match tag_name.as_str() {
                "h1" => result.push_str("\n\n# "),
                "h2" => result.push_str("\n\n## "),
                "h3" => result.push_str("\n\n### "),
                "h4" => result.push_str("\n\n#### "),
                "h5" => result.push_str("\n\n##### "),
                "h6" => result.push_str("\n\n###### "),
                "p" => result.push_str("\n\n"),
                "br" => result.push('\n'),
                "hr" => result.push_str("\n\n---\n\n"),
                "li" => result.push_str("\n- "),
                "blockquote" => result.push_str("\n> "),
                "pre" => result.push_str("\n```\n"),
                "code" => {
                    if !is_inside_pre(html, tag_start) {
                        result.push('`');
                    }
                }
                "strong" | "b" => result.push_str("**"),
                "em" | "i" => result.push('*'),
                "del" | "s" | "strike" => result.push_str("~~"),
                "a" => {
                    // Extract href and queue it for the closing tag
                    if let Some(href) = extract_attr_from_tag(&tag_str, "href") {
                        // Output as [text](url) — push opening bracket
                        result.push('[');
                        // Find closing </a> and the text between
                        let close_pos = find_closing_tag(&chars, tag_end + 1, "a");
                        if let Some(close) = close_pos {
                            let text: String = extract_text_from_chars(&chars, tag_end + 1, close);
                            let text = text.trim().to_string();
                            if text.is_empty() {
                                result.push_str(&href);
                            } else {
                                result.push_str(&text);
                            }
                            result.push_str("](");
                            result.push_str(&href);
                            result.push(')');
                            i = close; // skip past the </a>
                            // Advance past the closing tag
                            while i < len && chars[i] != '>' {
                                i += 1;
                            }
                            i += 1;
                            continue;
                        } else {
                            result.push_str(&href);
                            result.push_str("](");
                            result.push_str(&href);
                            result.push(')');
                        }
                    }
                }
                "img" => {
                    let alt = extract_attr_from_tag(&tag_str, "alt").unwrap_or_default();
                    if let Some(src) = extract_attr_from_tag(&tag_str, "src") {
                        result.push_str(&format!("![{alt}]({src})"));
                    }
                }
                "th" => result.push_str("| **"),
                "td" => result.push_str("| "),
                "div" | "section" | "article" | "main" => {
                    // Block elements: just add spacing
                }
                _ => {}
            }

            // Handle self-closing tags
            if tag_str.ends_with("/>") || matches!(tag_name.as_str(), "br" | "hr" | "img") {
                i = tag_end + 1;
                continue;
            }

            i = tag_end + 1;
        } else {
            // Regular text character
            let ch = chars[i];
            // Decode HTML entities inline
            if ch == '&' {
                let entity_end = chars[i..]
                    .iter()
                    .position(|&c| c == ';')
                    .map(|p| i + p + 1);

                if let Some(end) = entity_end {
                    if end - i <= 10 {
                        let entity: String = chars[i..end].iter().collect();
                        match entity.as_str() {
                            "&amp;" => result.push('&'),
                            "&lt;" => result.push('<'),
                            "&gt;" => result.push('>'),
                            "&quot;" => result.push('"'),
                            "&apos;" => result.push('\''),
                            "&nbsp;" => result.push(' '),
                            "&mdash;" | "&emdash;" => result.push_str(" -- "),
                            "&ndash;" => result.push_str(" - "),
                            "&hellip;" => result.push_str("..."),
                            "&copy;" => result.push_str("(c)"),
                            "&reg;" => result.push_str("(R)"),
                            "&trade;" => result.push_str("(TM)"),
                            _ => {
                                // Try numeric entities
                                if entity.starts_with("&#") {
                                    let num_str = entity
                                        .trim_start_matches("&#")
                                        .trim_start_matches('x')
                                        .trim_end_matches(';');
                                    let code = if entity.contains('x') || entity.contains('X') {
                                        u32::from_str_radix(num_str, 16).ok()
                                    } else {
                                        num_str.parse::<u32>().ok()
                                    };
                                    if let Some(c) = code.and_then(char::from_u32) {
                                        result.push(c);
                                    } else {
                                        result.push_str(&entity);
                                    }
                                } else {
                                    result.push_str(&entity);
                                }
                            }
                        }
                        i = end;
                        continue;
                    }
                }
            }
            result.push(ch);
            i += 1;
        }
    }

    result
}

/// Clean up excessive whitespace in the final Markdown.
fn clean_whitespace(md: &str) -> String {
    let mut lines: Vec<&str> = md.lines().collect();

    // Trim each line
    let trimmed: Vec<String> = lines.iter().map(|l| l.trim().to_string()).collect();
    lines = trimmed.iter().map(|s| s.as_str()).collect();

    // Collapse multiple blank lines into at most two
    let mut result = String::with_capacity(md.len());
    let mut consecutive_blank = 0;

    for line in &lines {
        if line.is_empty() {
            consecutive_blank += 1;
            if consecutive_blank <= 2 {
                result.push('\n');
            }
        } else {
            consecutive_blank = 0;
            result.push_str(line);
            result.push('\n');
        }
    }

    // Trim leading/trailing whitespace
    result.trim().to_string()
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Remove a tag and all its content from HTML (case-insensitive).
fn remove_tag_with_content(html: &str, tag: &str) -> String {
    let mut result = html.to_string();
    let lower_tag = tag.to_lowercase();

    loop {
        let lower = result.to_lowercase();
        let open = format!("<{}", lower_tag);
        let close = format!("</{}>", lower_tag);

        let start = match lower.find(&open) {
            Some(p) => p,
            None => break,
        };

        // Verify it's actually a tag (followed by space, >, or /)
        let after_tag = start + open.len();
        if after_tag < lower.len() {
            let next_char = lower.as_bytes()[after_tag];
            if next_char != b' '
                && next_char != b'>'
                && next_char != b'/'
                && next_char != b'\t'
                && next_char != b'\n'
                && next_char != b'\r'
            {
                // Not actually the tag we're looking for (e.g., "navigate" when looking for "nav")
                // Replace the found portion with a marker to avoid infinite loop
                result = format!(
                    "{}{}",
                    &result[..start + open.len()],
                    &result[start + open.len()..]
                );
                continue;
            }
        }

        let end = match lower[start..].find(&close) {
            Some(p) => start + p + close.len(),
            None => {
                // Self-closing or unclosed — remove just the opening tag
                match result[start..].find('>') {
                    Some(p) => start + p + 1,
                    None => break,
                }
            }
        };

        result = format!("{}{}", &result[..start], &result[end..]);
    }

    result
}

/// Remove elements that have a matching class or id.
fn remove_elements_by_class_or_id(html: &str, pattern: &str) -> String {
    let mut result = html.to_string();
    let pat_lower = pattern.to_lowercase();

    loop {
        let lower = result.to_lowercase();
        // Look for the pattern in a class or id attribute
        let pos = lower
            .find(&format!("class=\"{}", pat_lower))
            .or_else(|| lower.find(&format!("class='{}", pat_lower)))
            .or_else(|| lower.find(&format!("id=\"{}", pat_lower)))
            .or_else(|| lower.find(&format!("id='{}", pat_lower)))
            // Also match when pattern appears within a class list
            .or_else(|| {
                // Search for the pattern within class attribute values
                let mut search_from = 0;
                loop {
                    if let Some(p) = lower[search_from..].find(&pat_lower) {
                        let abs_p = search_from + p;
                        // Check if it's within a class or id attribute
                        let before = &lower[..abs_p];
                        let last_class = before.rfind("class=");
                        let last_id = before.rfind("id=");
                        let last_tag = before.rfind('<');

                        let in_attr = match (last_class, last_id, last_tag) {
                            (Some(c), _, Some(t)) if c > t => true,
                            (_, Some(id), Some(t)) if id > t => true,
                            _ => false,
                        };

                        if in_attr {
                            return Some(abs_p);
                        }
                        search_from = abs_p + 1;
                    } else {
                        return None;
                    }
                }
            });

        let pos = match pos {
            Some(p) => p,
            None => break,
        };

        // Find the enclosing tag start
        let tag_start = match lower[..pos].rfind('<') {
            Some(p) => p,
            None => break,
        };

        let tag_name = extract_tag_name_at(&result[tag_start..]);
        let close_tag = format!("</{}>", tag_name);
        let tag_end = match result[tag_start..].find('>') {
            Some(p) => tag_start + p + 1,
            None => break,
        };

        // Find the matching closing tag
        let block_end = match lower[tag_end..].find(&close_tag.to_lowercase()) {
            Some(p) => tag_end + p + close_tag.len(),
            None => tag_end, // no closing tag, just remove the opening
        };

        result = format!("{}{}", &result[..tag_start], &result[block_end..]);
    }

    result
}

/// Remove elements with a specific attribute value.
fn remove_elements_by_attribute(html: &str, attr: &str, value: &str) -> String {
    let mut result = html.to_string();
    let search = format!("{}=\"{}\"", attr.to_lowercase(), value.to_lowercase());

    loop {
        let lower = result.to_lowercase();
        let pos = match lower.find(&search) {
            Some(p) => p,
            None => break,
        };

        let tag_start = match lower[..pos].rfind('<') {
            Some(p) => p,
            None => break,
        };

        let tag_name = extract_tag_name_at(&result[tag_start..]);
        let close_tag = format!("</{}>", tag_name);
        let tag_end = match result[tag_start..].find('>') {
            Some(p) => tag_start + p + 1,
            None => break,
        };

        let block_end = match lower[tag_end..].find(&close_tag.to_lowercase()) {
            Some(p) => tag_end + p + close_tag.len(),
            None => tag_end,
        };

        result = format!("{}{}", &result[..tag_start], &result[block_end..]);
    }

    result
}

/// Extract tag content block (inner HTML of first matching tag).
fn extract_tag_content_block(html: &str, lower: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start = lower.find(&open)?;
    let content_start = html[start..].find('>')? + start + 1;
    let content_end = lower[content_start..].find(&close)? + content_start;

    Some(html[content_start..content_end].to_string())
}

/// Extract element inner HTML by id attribute.
fn extract_element_by_id(html: &str, lower: &str, id: &str) -> Option<String> {
    let id_pattern = format!("id=\"{}\"", id);
    let pos = lower.find(&id_pattern)?;

    let tag_start = lower[..pos].rfind('<')?;
    let tag_name = extract_tag_name_at(&html[tag_start..]);
    let close = format!("</{}>", tag_name);
    let tag_end = html[tag_start..].find('>')? + tag_start + 1;
    let content_end = lower[tag_end..].find(&close.to_lowercase())? + tag_end;

    Some(html[tag_end..content_end].to_string())
}

/// Get the tag name from an opening tag at the start of a string.
fn extract_tag_name_at(tag: &str) -> String {
    let without_bracket = tag.trim_start_matches('<');
    let end = without_bracket
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .unwrap_or(without_bracket.len());
    without_bracket[..end].to_lowercase()
}

/// Extract opening tag name from lowercase tag string like "<h1 class=...>".
fn extract_opening_tag_name(tag_lower: &str) -> String {
    let s = tag_lower.trim_start_matches('<');
    let end = s
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .unwrap_or(s.len());
    s[..end].to_string()
}

/// Extract closing tag name from "</tagname>".
fn extract_closing_tag_name(tag_lower: &str) -> String {
    let s = tag_lower.trim_start_matches("</");
    let end = s
        .find(|c: char| c.is_whitespace() || c == '>')
        .unwrap_or(s.len());
    s[..end].to_string()
}

/// Extract an attribute value from a tag string.
fn extract_attr_from_tag(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let attr_lower = attr.to_lowercase();

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

/// Find the position of a closing tag in a char slice.
fn find_closing_tag(chars: &[char], from: usize, tag: &str) -> Option<usize> {
    let close: Vec<char> = format!("</{}>", tag).chars().collect();
    let close_upper: Vec<char> = format!("</{}>", tag.to_uppercase()).chars().collect();
    let close_len = close.len();

    let mut i = from;
    while i + close_len <= chars.len() {
        let slice: Vec<char> = chars[i..i + close_len]
            .iter()
            .map(|c| c.to_lowercase().next().unwrap_or(*c))
            .collect();
        let target: Vec<char> = close.iter().map(|c| c.to_lowercase().next().unwrap_or(*c)).collect();
        if slice == target {
            return Some(i);
        }
        let _ = close_upper; // suppress unused warning
        i += 1;
    }
    None
}

/// Extract visible text from a char range, stripping any nested tags.
fn extract_text_from_chars(chars: &[char], from: usize, to: usize) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for i in from..to.min(chars.len()) {
        if chars[i] == '<' {
            in_tag = true;
        } else if chars[i] == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(chars[i]);
        }
    }
    result
}

/// Check if a position is inside a <pre> block.
fn is_inside_pre(html: &str, pos: usize) -> bool {
    let before = &html[..pos].to_lowercase();
    let last_pre_open = before.rfind("<pre");
    let last_pre_close = before.rfind("</pre>");

    match (last_pre_open, last_pre_close) {
        (Some(open), Some(close)) => open > close,
        (Some(_), None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_conversion() {
        let html = "<html><body><h1>Title</h1><p>Hello world</p></body></html>";
        let md = html_to_markdown(html);
        assert!(md.contains("# Title"));
        assert!(md.contains("Hello world"));
    }

    #[test]
    fn test_links() {
        let html = r#"<p>Visit <a href="https://example.com">Example</a> today</p>"#;
        let md = html_to_markdown(html);
        assert!(md.contains("[Example](https://example.com)"));
    }

    #[test]
    fn test_bold_italic() {
        let html = "<p><strong>bold</strong> and <em>italic</em></p>";
        let md = html_to_markdown(html);
        assert!(md.contains("**bold**"));
        assert!(md.contains("*italic*"));
    }

    #[test]
    fn test_headings() {
        let html = "<h1>One</h1><h2>Two</h2><h3>Three</h3>";
        let md = html_to_markdown(html);
        assert!(md.contains("# One"));
        assert!(md.contains("## Two"));
        assert!(md.contains("### Three"));
    }

    #[test]
    fn test_list() {
        let html = "<ul><li>Apple</li><li>Banana</li><li>Cherry</li></ul>";
        let md = html_to_markdown(html);
        assert!(md.contains("- Apple"));
        assert!(md.contains("- Banana"));
        assert!(md.contains("- Cherry"));
    }

    #[test]
    fn test_code_inline() {
        let html = "<p>Use <code>println!</code> to print</p>";
        let md = html_to_markdown(html);
        assert!(md.contains("`println!`"));
    }

    #[test]
    fn test_images() {
        let html = r#"<img src="pic.jpg" alt="A photo">"#;
        let md = html_to_markdown(html);
        assert!(md.contains("![A photo](pic.jpg)"));
    }

    #[test]
    fn test_strips_nav() {
        let html = r#"<html><body>
<nav><a href="/">Home</a><a href="/about">About</a></nav>
<main><h1>Content</h1><p>Real text here</p></main>
<footer>Copyright 2026</footer>
</body></html>"#;
        let md = html_to_markdown(html);
        assert!(md.contains("Content"));
        assert!(md.contains("Real text here"));
        assert!(!md.contains("About"));
        assert!(!md.contains("Copyright"));
    }

    #[test]
    fn test_strips_scripts() {
        let html = r#"<p>Hello</p><script>alert('xss')</script><p>World</p>"#;
        let md = html_to_markdown(html);
        assert!(md.contains("Hello"));
        assert!(md.contains("World"));
        assert!(!md.contains("alert"));
    }

    #[test]
    fn test_html_entities() {
        let html = "<p>A &amp; B &lt; C &gt; D</p>";
        let md = html_to_markdown(html);
        assert!(md.contains("A & B < C > D"));
    }

    #[test]
    fn test_horizontal_rule() {
        let html = "<p>Above</p><hr><p>Below</p>";
        let md = html_to_markdown(html);
        assert!(md.contains("---"));
    }

    #[test]
    fn test_empty_html() {
        let md = html_to_markdown("");
        assert!(md.is_empty());
    }

    #[test]
    fn test_whitespace_cleanup() {
        let html = "<p>Hello</p>\n\n\n\n\n<p>World</p>";
        let md = html_to_markdown(html);
        // Should not have more than 2 consecutive newlines
        assert!(!md.contains("\n\n\n\n"));
    }

    #[test]
    fn test_blockquote() {
        let html = "<blockquote>A wise quote</blockquote>";
        let md = html_to_markdown(html);
        assert!(md.contains("> A wise quote"));
    }
}
