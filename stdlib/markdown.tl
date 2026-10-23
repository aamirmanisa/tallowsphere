// tallow.markdown — HTML to clean, LLM-optimized Markdown conversion.
//
// Strips noise elements (ads, scripts, nav, footer, sidebars) and
// converts HTML structure to clean Markdown suitable for AI extraction.

// Convert HTML to clean Markdown (strips noise by default)
native fn Markdown.convert(html: String) -> String

// Strip non-content elements, return clean HTML
native fn Markdown.strip_noise(html: String) -> String

// Extract main content area only, convert to Markdown
native fn Markdown.extract_main(html: String) -> String
