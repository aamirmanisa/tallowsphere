// expected: E5004 (plus existing E0100/E0400/W1900)
// context: collection program with zero plan annotations — no @legal/@cra_class/@stealth/@burn_plan anywhere; the new program-level gate must refuse the build.
// Acceptance fixture for A5.2.1 (§2 E5004). Not expected to pass current gates.

fn main() {
    let r = fetch("https://example.org/list")
    let browser = Browser.launch(true).unwrap()
    let page = browser.new_page().unwrap()
    page.goto("https://example.org/list")
    print(r.text())
    browser.close()
}
