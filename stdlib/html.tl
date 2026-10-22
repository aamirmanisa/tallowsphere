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
// native: parses HTML into DOM tree
native fn parse(input: String) -> Document

/// Parse HTML bytes into document
// native: parses HTML bytes (auto-detects encoding)
native fn parse_bytes(input: Bytes) -> Document

impl Document {
    /// Select elements matching CSS selector
    // native: CSS selector query, returns matching elements
    native fn select(self, selector: String) -> []Element

    /// Select first element matching CSS selector
    // native: returns first match or nil
    native fn select_one(self, selector: String) -> Element?

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
    // native: extracts all text nodes
    native fn text(self) -> String
}

impl Element {
    /// Get element text content
    // native: text content of element and children
    native fn text(self) -> String

    /// Get attribute value
    fn attr(self, name: String) -> String? {
        self.attrs[name]
    }

    /// Check if attribute exists
    fn has_attr(self, name: String) -> bool {
        self.attrs.contains(name)
    }

    /// Get inner HTML
    // native: HTML content inside this element
    native fn inner_html(self) -> String

    /// Get outer HTML (including this element's tag)
    // native: HTML including this element
    native fn outer_html(self) -> String

    /// Select children matching CSS selector
    // native: CSS selector within this element's subtree
    native fn select(self, selector: String) -> []Element

    /// Get parent element
    // native: parent node
    native fn parent(self) -> Element?

    /// Get child elements
    // native: direct child elements
    native fn children(self) -> []Element

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
