// tallow.frame — iFrame traversal and interaction
//
// Frames represent nested browsing contexts within a page.
// The page_frames() function discovers all frames in the current page,
// including cross-origin iframes (which provide only url and name).
//
// Frame operations are tied to the active browser page.

struct Frame {
    url:  String,
    name: String,
}

impl Frame {
    /// Get the full HTML content of this frame.
    fn content(self) -> String {
        // native: evaluates document.documentElement.outerHTML
    }

    /// Find the first element matching a CSS selector within this frame.
    /// Returns nil if no element matches or frame is cross-origin.
    fn query_selector(self, selector: String) -> Element? {
        // native: frame.contentDocument.querySelector(selector)
    }

    /// Find all elements matching a CSS selector within this frame.
    /// Returns empty array if no elements match or frame is cross-origin.
    fn query_selector_all(self, selector: String) -> []Element {
        // native: frame.contentDocument.querySelectorAll(selector)
    }

    /// Get the inner HTML of the frame's body element.
    fn inner_html(self) -> String {
        // native: evaluates frame.contentDocument.body.innerHTML
    }
}

/// Get all frames in the current page.
/// Cross-origin iframes return just url + name; same-origin frames
/// support full interaction (content, query_selector, etc.).
fn page_frames() -> []Frame {
    // native: CDP Page.getFrameTree → parse_frame_tree
}
