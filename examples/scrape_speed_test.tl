// Tallow Scraping Speed Test
// Measures: page load, element extraction, multi-page scraping

@legal(basis: .research, purpose: "scraping speed benchmark", retain_for: 1.days)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TALLOW SCRAPING SPEED TEST ===")
    print("")

    let browser = Browser.launch(true)
    let page = browser.new_page()

    // Test 1: Page load speed
    let t1 = time.now()
    page.goto("https://example.com")
    let t2 = time.now()
    let load_ms = t2 - t1
    print("[1] Page load (example.com):  {load_ms}ms")

    // Test 2: Element extraction speed
    let t3 = time.now()
    let title = page.title()
    let url = page.url()
    let h1 = page.query_selector("h1")
    let h1_text = h1.text()
    let links = page.query_selector_all("a")
    let link_count = links.len()
    let paragraphs = page.query_selector_all("p")
    let p_count = paragraphs.len()
    let t4 = time.now()
    let extract_ms = t4 - t3
    print("[2] Extract 5 elements:      {extract_ms}ms")
    print("    Title: {title}")
    print("    H1: {h1_text}")
    print("    Links: {link_count}, Paragraphs: {p_count}")

    // Test 3: JavaScript evaluation speed
    let t5 = time.now()
    var i = 0
    while i < 10 {
        page.evaluate("document.title")
        i = i + 1
    }
    let t6 = time.now()
    let js_ms = t6 - t5
    let js_per = js_ms / 10
    print("[3] 10x JS evaluate:         {js_ms}ms ({js_per}ms/eval)")

    // Test 4: Multi-page navigation speed
    let urls = [
        "https://example.com",
        "https://www.iana.org",
        "https://www.iana.org/domains",
        "https://www.iana.org/protocols",
        "https://www.iana.org/numbers"
    ]
    let t7 = time.now()
    var pages_loaded = 0
    var j = 0
    while j < urls.len() {
        page.goto(urls[j])
        let t = page.title()
        pages_loaded = pages_loaded + 1
        j = j + 1
    }
    let t8 = time.now()
    let multi_ms = t8 - t7
    let per_page = multi_ms / pages_loaded
    print("[4] {pages_loaded} pages navigated:       {multi_ms}ms ({per_page}ms/page)")

    // Test 5: Screenshot speed
    let t9 = time.now()
    page.screenshot()
    let t10 = time.now()
    let screenshot_ms = t10 - t9
    print("[5] Screenshot capture:      {screenshot_ms}ms")

    // Test 6: Cookie extraction speed
    let t11 = time.now()
    let cookies = page.get_cookies()
    let t12 = time.now()
    let cookie_ms = t12 - t11
    print("[6] Cookie extraction:       {cookie_ms}ms")

    // Test 7: Full page data extraction
    let t13 = time.now()
    let content = page.content()
    let all_links = page.query_selector_all("a")
    var k = 0
    while k < all_links.len() {
        let link = all_links[k]
        let href = link.attribute("href")
        let text = link.text()
        k = k + 1
    }
    let t14 = time.now()
    let full_ms = t14 - t13
    print("[7] Full page extraction:    {full_ms}ms ({all_links.len()} links with text+href)")

    print("")
    print("=== RESULTS ===")
    print("  Page load:          {load_ms}ms")
    print("  Element extract:    {extract_ms}ms")
    print("  JS eval:            {js_per}ms per call")
    print("  Navigation:         {per_page}ms per page")
    print("  Screenshot:         {screenshot_ms}ms")
    print("  Cookie extract:     {cookie_ms}ms")
    print("  Full extraction:    {full_ms}ms")

    browser.close()
    print("")
    print("Done.")
}
