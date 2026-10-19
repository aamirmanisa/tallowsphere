// Tallow Browser — Full Feature Demo
// Launches Chrome with all Tallow browser specs

@legal(basis: .research, purpose: "browser feature demonstration", retain_for: 7.days)
@stealth(profile: .chrome_windows, evasions: .all)
@cra_class(.default)
@persona(id: "browser-full-demo", cover_class: .researcher, compartment: "browser-full-demo", fingerprint_seed: "browser-full-demo-1020")
@burn_plan(persona: "browser-full-demo", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowDemo/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {

print("=== TALLOW BROWSER DEMO ===")
print("")

// 1. Launch headed browser
let browser = Browser.launch(false)
print("[1] Browser launched (headed mode)")

// 2. Create page
let page = browser.new_page()
print("[2] New page created")

// 3. Set viewport
page.set_viewport(1920, 1080)
print("[3] Viewport: 1920x1080")

// 4. Set user agent
page.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
print("[4] User agent: Chrome 120 Windows")

// 5. Navigate to Google
page.goto("https://www.google.com")
print("[5] Navigated to Google")

// 6. Get title
let title = page.title()
print("[6] Page title: {title}")

// 7. Get URL
let url = page.url()
print("[7] Page URL: {url}")

// 8. Screenshot
let screenshot = page.screenshot()
print("[8] Screenshot captured")

// 9. Get cookies
let cookies = page.get_cookies()
print("[9] Cookies: {cookies}")

// 10. JavaScript evaluation
let js = page.evaluate("document.title")
print("[10] JS eval (document.title): {js}")

let js2 = page.evaluate("navigator.userAgent")
print("[11] JS eval (navigator.userAgent): {js2}")

let js3 = page.evaluate("window.innerWidth + 'x' + window.innerHeight")
print("[12] JS eval (viewport): {js3}")

// 13. Console messages
let console = page.console_messages()
print("[13] Console messages captured: {console.len()} messages")

// 14. Navigate to example.com
page.goto("https://example.com")
let title2 = page.title()
print("[14] Example.com title: {title2}")

// 15. Query single element
let h1 = page.query_selector("h1")
let h1_text = h1.text()
print("[15] H1 element text: {h1_text}")

// 16. Query multiple elements
let paragraphs = page.query_selector_all("p")
print("[16] Found {paragraphs.len()} <p> elements")

// 17. Get element attribute
let link = page.query_selector("a")
let href = link.attribute("href")
print("[17] First link href: {href}")

// 18. Click element
link.click()
print("[18] Clicked first link")

// 19. Get new URL after click
let url2 = page.url()
print("[19] URL after click: {url2}")

// 20. Go back
page.goto("https://example.com")
print("[20] Navigated back to example.com")

// 21. Get page content (HTML)
let content = page.content()
print("[21] Page HTML: {content.len()} chars")

// 22. Check WebDriver detection (should be hidden by stealth)
let webdriver = page.evaluate("navigator.webdriver")
print("[22] navigator.webdriver: {webdriver} (should be false/undefined with stealth)")

// 23. Check Chrome detection
let chrome = page.evaluate("typeof window.chrome !== 'undefined'")
print("[23] window.chrome exists: {chrome}")

// 24. Accessibility tree
let a11y = page.accessibility_tree()
print("[24] Accessibility tree: {a11y}")

// 25. PDF export
let pdf = page.pdf()
print("[25] PDF exported")

print("")
print("=== CONSOLE LOG DUMP ===")
let final_console = page.console_messages()
var i = 0
while i < final_console.len() {
    let msg = final_console[i]
    print("  [{msg.level}] {msg.text}")
    i = i + 1
}
if final_console.len() == 0 {
    print("  (no console messages)")
}

print("")
print("=== TALLOW BROWSER SPECS ===")
print("  Modules:        25 (CDP, stealth, recording, pool, etc.)")
print("  Device profiles: 163 (iPhone, iPad, Pixel, Galaxy, Desktop)")
print("  Stealth profiles: 7 (headless bypass, WebDriver hide, etc.)")
print("  Recording:       4K video at 60fps via ffmpeg")
print("  Protocol:        Chrome DevTools Protocol (WebSocket)")
print("  Crypto:          42+ real algorithms (ML-KEM, AES-256, BLAKE3)")
print("  Compliance:      @legal + @stealth enforced at compile time")
print("  Binary:          20.5 MB, <1ms startup, zero dependencies")

// Close
browser.close()
print("")
print("Browser closed. Demo complete.")

}
