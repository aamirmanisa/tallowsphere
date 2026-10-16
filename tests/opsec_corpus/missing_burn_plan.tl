// expected: E5004
// context: all legacy gates satisfied (@legal + @cra_class + @stealth present) but the collection program ships no burn plan — proves E5004 is additive.
// Acceptance fixture for A5.2.1 (§2 E5004). Not expected to pass current gates.

@legal(basis: .public_data, purpose: "opsec corpus: missing burn plan fixture", personal_data: false)
@cra_class(.default)
@stealth(profile: .chrome_windows, evasions: .all)
@persona(id: "burnless-01", cover_class: .engineer, compartment: "lab-d", fingerprint_seed: "seed-77c1")
fn main() {
    let browser = Browser.launch(true).unwrap()
    let page = browser.new_page().unwrap()
    page.goto("https://example.org/report")
    browser.close()
}
