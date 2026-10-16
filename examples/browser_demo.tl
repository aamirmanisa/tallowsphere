// Tallow Browser Automation Demo (v0.2)
// CDP-powered browser control with anti-detection
//
// NOTE: Requires Chromium/Chrome installed.
// Run: tallow run examples/browser_demo.tl

@legal(
    basis:         .public_data,
    purpose:       "demonstrate browser automation",
    personal_data: false,
    robots_txt:    .respect,
    rate_limit:    1.per_second
)
fn scrape_title(url: String) -> Result<String> {
    // Launch headless browser
    let browser = Browser.launch(true) match {
        Ok(b)  -> b
        Err(e) -> { bail "launch failed: {e}" }
    }

    // Open page and navigate
    let page = browser.new_page() match {
        Ok(p)  -> p
        Err(e) -> { browser.close(); bail "new_page failed: {e}" }
    }

    let nav = page.goto(url) match {
        Ok(n)  -> n
        Err(e) -> { browser.close(); bail "navigate failed: {e}" }
    }

    print("Navigated to: {nav.url}")
    print("Status: {nav.status_code}")

    // Extract page title
    let title = page.title() match {
        Ok(t)  -> t
        Err(e) -> { browser.close(); bail "title failed: {e}" }
    }

    browser.close()
    Ok(title)
}

fn main() {
    print("=== Tallow Browser Automation ===")
    print("")

    let title = scrape_title("https://example.com") match {
        Ok(t)  -> t
        Err(e) -> {
            print("Error: {e}")
            "unknown"
        }
    }

    print("")
    print("Page title: {title}")
    print("")
    print("Browser automation complete!")
}
