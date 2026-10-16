//! Standard library: `tallow.markdown` — HTML to clean Markdown conversion.
//!
//! Converts HTML to clean, LLM-optimized Markdown suitable for AI extraction,
//! summarization, and structured data parsing. Uses regex-based conversion
//! that strips noise elements and preserves content structure.
//!
//! # API
//! - `Markdown.convert(html)` — convert HTML to Markdown (strips noise)
//! - `Markdown.strip_noise(html)` — strip non-content elements, return clean HTML
//! - `Markdown.extract_main(html)` — extract main content, convert to Markdown

use super::StdlibResult;
use crate::interp::{type_name, Value};

use regex::Regex;

fn html_to_markdown(html: &str, strip_noise: bool, main_only: bool) -> String {
    let mut html = html.to_string();

    // Strip noise elements first
    if strip_noise || main_only {
        // Remove script and style blocks
        let re_script = Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap();
        let re_style = Regex::new(r"(?is)<style[^>]*>.*?</style>").unwrap();
        let re_noscript = Regex::new(r"(?is)<noscript[^>]*>.*?</noscript>").unwrap();
        html = re_script.replace_all(&html, "").to_string();
        html = re_style.replace_all(&html, "").to_string();
        html = re_noscript.replace_all(&html, "").to_string();

        // Remove nav, footer, iframe, svg, aside elements
        for tag in &["nav", "footer", "iframe", "svg", "aside", "form", "input", "select"] {
            let re = Regex::new(&format!(r"(?is)<{}[^>]*>.*?</{}>", tag, tag)).unwrap();
            html = re.replace_all(&html, "").to_string();
        }

        // Remove common ad/sidebar classes
        for cls in &["sidebar", "advertisement", "cookie-banner", "modal", "popup", "overlay"] {
            let re = Regex::new(&format!(r#"(?is)<(div|section|aside)[^>]*class="[^"]*{}[^"]*"[^>]*>.*?</\1>"#, cls)).unwrap();
            html = re.replace_all(&html, "").to_string();
        }
    }

    // Try to extract main content
    if main_only {
        let re_main = Regex::new(r"(?is)<(main|article)[^>]*>(.*?)</\1>").unwrap();
        if let Some(caps) = re_main.captures(&html) {
            html = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or(html);
        }
    }

    // Convert HTML to Markdown
    let mut md = html;

    // Headings
    let re_h = Regex::new(r"(?i)<h([1-6])[^>]*>(.*?)</h\1>").unwrap();
    md = re_h.replace_all(&md, |caps: &regex::Captures| {
        let level: usize = caps[1].parse().unwrap();
        let content = strip_tags(&caps[2]);
        format!("\n{} {}\n", "#".repeat(level), content.trim())
    }).to_string();

    // Bold/strong
    let re_b = Regex::new(r"(?is)<(strong|b)[^>]*>(.*?)</\1>").unwrap();
    md = re_b.replace_all(&md, "**${2}**").to_string();

    // Italic/em
    let re_i = Regex::new(r"(?is)<(em|i)[^>]*>(.*?)</\1>").unwrap();
    md = re_i.replace_all(&md, "*${2}*").to_string();

    // Links
    let re_a = Regex::new(r#"(?is)<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>"#).unwrap();
    md = re_a.replace_all(&md, "[$2]($1)").to_string();

    // Images
    let re_img = Regex::new(r#"(?is)<img[^>]*src="([^"]*)"[^>]*alt="([^"]*)"[^>]*/?>"#).unwrap();
    md = re_img.replace_all(&md, "![$2]($1)").to_string();

    // Inline code
    let re_code = Regex::new(r"(?is)<code[^>]*>(.*?)</code>").unwrap();
    md = re_code.replace_all(&md, "`$1`").to_string();

    // Pre/code blocks
    let re_pre = Regex::new(r"(?is)<pre[^>]*><code[^>]*>(.*?)</code></pre>").unwrap();
    md = re_pre.replace_all(&md, "\n```\n$1\n```\n").to_string();

    // Blockquotes
    let re_bq = Regex::new(r"(?is)<blockquote[^>]*>(.*?)</blockquote>").unwrap();
    md = re_bq.replace_all(&md, "\n> $1\n").to_string();

    // Horizontal rules
    let re_hr = Regex::new(r"(?i)<hr[^>]*/?>").unwrap();
    md = re_hr.replace_all(&md, "\n---\n").to_string();

    // Line breaks
    let re_br = Regex::new(r"(?i)<br[^>]*/?>").unwrap();
    md = re_br.replace_all(&md, "\n").to_string();

    // List items
    let re_li = Regex::new(r"(?is)<li[^>]*>(.*?)</li>").unwrap();
    md = re_li.replace_all(&md, "- $1\n").to_string();

    // Paragraphs
    let re_p = Regex::new(r"(?is)<p[^>]*>(.*?)</p>").unwrap();
    md = re_p.replace_all(&md, "\n$1\n").to_string();

    // Divs — add newlines
    let re_div = Regex::new(r"(?is)<div[^>]*>(.*?)</div>").unwrap();
    md = re_div.replace_all(&md, "\n$1\n").to_string();

    // Remove remaining HTML tags
    let re_tag = Regex::new(r"<[^>]+>").unwrap();
    md = re_tag.replace_all(&md, "").to_string();

    // Decode HTML entities
    md = md.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
           .replace("&quot;", "\"").replace("&#39;", "'").replace("&apos;", "'")
           .replace("&#x27;", "'").replace("&nbsp;", " ");

    // Normalize whitespace
    md = md.lines().map(|l| l.trim()).collect::<Vec<_>>().join("\n");
    // Collapse multiple blank lines
    let mut result = String::new();
    let mut blank_count = 0;
    for line in md.lines() {
        if line.is_empty() {
            if blank_count < 1 { result.push('\n'); }
            blank_count += 1;
        } else {
            result.push_str(line);
            result.push('\n');
            blank_count = 0;
        }
    }
    result.trim().to_string()
}

fn strip_tags(html: &str) -> String {
    let re = Regex::new(r"<[^>]+>").unwrap();
    re.replace_all(html, "").to_string()
}

fn clean_html_only(html: &str, main_only: bool) -> String {
    let mut h = html.to_string();

    // Strip scripts, styles
    for pat in &[r"(?is)<script[^>]*>.*?</script>", r"(?is)<style[^>]*>.*?</style>"] {
        if let Ok(re) = Regex::new(pat) {
            h = re.replace_all(&h, "").to_string();
        }
    }

    // Try main extraction
    if main_only {
        if let Ok(re) = Regex::new(r"(?is)<(main|article)[^>]*>(.*?)</\1>") {
            if let Some(caps) = re.captures(&h) {
                h = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or(h);
            }
        }
    }

    // Remove nav, footer, etc.
    for tag in &["nav", "footer", "script", "style", "noscript", "iframe", "svg"] {
        if let Ok(re) = Regex::new(&format!(r"(?is)<{}[^>]*>.*?</{}>", tag, tag)) {
            h = re.replace_all(&h, "").to_string();
        }
    }

    h
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "convert" => Some(md_convert(args)),
        "strip_noise" => Some(md_strip_noise(args)),
        "extract_main" => Some(md_extract_main(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "convert" | "strip_noise" | "extract_main")
}

fn md_convert(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    Ok(Value::String(html_to_markdown(html, true, false)))
}

fn md_strip_noise(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    Ok(Value::String(clean_html_only(html, false)))
}

fn md_extract_main(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    Ok(Value::String(html_to_markdown(html, true, true)))
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}
