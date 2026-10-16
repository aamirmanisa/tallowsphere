// tallow.markdown — HTML to clean, LLM-optimized Markdown conversion.
//
// Strips noise elements (ads, scripts, nav, footer, sidebars) and
// converts HTML structure to clean Markdown suitable for AI extraction.

// Convert HTML to clean Markdown (strips noise by default)
fn Markdown.convert(html: String) -> String

// Strip non-content elements, return clean HTML
fn Markdown.strip_noise(html: String) -> String

// Extract main content area only, convert to Markdown
fn Markdown.extract_main(html: String) -> String
