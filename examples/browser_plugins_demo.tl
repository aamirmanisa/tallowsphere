// Tallow Browser — Built-in Plugins Demo
// All privacy plugins activate automatically. No extensions needed.

@legal(basis: .research, purpose: "plugin demo", retain_for: 1.days)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    let browser = Browser.launch(false)
    let page = browser.new_page()

    // Enable ALL built-in plugins with one call
    let status = page.enable_plugins("balanced")
    print("Plugins: {status}")
    print("")

    // Navigate to a site — ads, trackers, and fingerprinting are auto-blocked
    page.goto("https://example.com")
    let title = page.title()
    print("Page: {title}")

    // Clean a URL with tracking params
    let dirty = "https://example.com/page?utm_source=google&utm_medium=cpc&fbclid=abc123&id=42"
    let clean = page.clean_url(dirty)
    print("")
    print("Dirty URL: {dirty}")
    print("Clean URL: {clean}")

    // Check console for blocked requests
    let console = page.console_messages()
    print("")
    print("Console messages ({console.len()}):")
    var i = 0
    while i < console.len() {
        let msg = console[i]
        print("  [{msg.level}] {msg.text}")
        i = i + 1
    }

    print("")
    print("=== BUILT-IN PLUGINS ===")
    print("  AdBlock          — 47 ad network patterns + 26 ad domains + CSS cosmetic hiding")
    print("  TrackerBlock     — 49 tracker patterns + 27 tracker domains")
    print("  HTTPS-Everywhere — Auto-upgrade http:// to https://")
    print("  ClearURLs        — Strip 50+ tracking params (utm_*, fbclid, gclid, etc.)")
    print("  FingerprintBlock — Canvas/WebGL/Audio/Battery/HW randomization")
    print("  PopupBlock       — Block non-user-initiated window.open()")
    print("  MinerBlock       — 14 crypto miner patterns + 9 miner domains")
    print("  SocialBlock      — 14 social widget patterns (Facebook, Twitter, Disqus)")
    print("  CookieBlock      — Block 20+ tracking cookies (_ga, _fbp, IDE, etc.)")
    print("  NoScript         — Disable all JavaScript (opt-in)")
    print("")
    print("Usage:")
    print("  page.enable_plugins()         // balanced (default)")
    print("  page.enable_plugins(\"max\")    // maximum privacy")
    print("  page.block_ads()              // ads only")
    print("  page.block_trackers()         // trackers only")
    print("  page.block_scripts()          // disable JavaScript")
    print("  page.privacy_mode()           // everything on")
    print("  page.clean_url(url)           // strip tracking params")

    browser.close()
    print("")
    print("Done.")
}
