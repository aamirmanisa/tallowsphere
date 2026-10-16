// tallow.html — HTML parsing, CSS selectors
//
// High-performance HTML parsing with CSS selector support
// for structured data extraction.

/// Parsed HTML document
struct Document {
    // internal: parsed DOM tree
}

/// HTML element node
struct Element {
    tag:     String,
    attrs:   Map<String, String>,
}

/// Parse HTML string into document
fn parse(input: String) -> Document {
    // native: parses HTML into DOM tree
}

/// Parse HTML bytes into document
fn parse_bytes(input: Bytes) -> Document {
    // native: parses HTML bytes (auto-detects encoding)
}

impl Document {
    /// Select elements matching CSS selector
    fn select(self, selector: String) -> []Element {
        // native: CSS selector query, returns matching elements
    }

    /// Select first element matching CSS selector
    fn select_one(self, selector: String) -> Element? {
        // native: returns first match or nil
    }

    /// Get document title
    fn title(self) -> String? {
        let el = self.select_one("title")
        if el != nil { el.text() } else { nil }
    }

    /// Get all links
    fn links(self) -> []String {
        self.select("a[href]").map { el -> el.attr("href") }
    }

    /// Get document text content (no tags)
    fn text(self) -> String {
        // native: extracts all text nodes
    }
}

impl Element {
    /// Get element text content
    fn text(self) -> String {
        // native: text content of element and children
    }

    /// Get attribute value
    fn attr(self, name: String) -> String? {
        self.attrs[name]
    }

    /// Check if attribute exists
    fn has_attr(self, name: String) -> bool {
        self.attrs.contains(name)
    }

    /// Get inner HTML
    fn inner_html(self) -> String {
        // native: HTML content inside this element
    }

    /// Get outer HTML (including this element's tag)
    fn outer_html(self) -> String {
        // native: HTML including this element
    }

    /// Select children matching CSS selector
    fn select(self, selector: String) -> []Element {
        // native: CSS selector within this element's subtree
    }

    /// Get parent element
    fn parent(self) -> Element? {
        // native: parent node
    }

    /// Get child elements
    fn children(self) -> []Element {
        // native: direct child elements
    }

    /// Get element class list
    fn classes(self) -> []String {
        let cls = self.attr("class")
        if cls != nil { cls.split(" ") } else { [] }
    }

    /// Get element ID
    fn id(self) -> String? {
        self.attr("id")
    }
}
