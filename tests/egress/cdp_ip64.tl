@legal(basis: .research, purpose: "egress check: which IP family the interpreted browser (CDP) sees (G13)")
@cra_class(.class_i)
@stealth(profile: .chrome_windows, evasions: .all)
@persona(id: "egress-cdp64", cover_class: .researcher, compartment: "egress-4", fingerprint_seed: "egress-cdp64-seed-4e17")
@burn_plan(persona: "egress-cdp64", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .cohort_uniform, bot_identity: .browser)
fn main() {
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("https://api64.ipify.org")
    let body = page.query_selector("body")
    print("cdp_ip64=" + body.text())
    browser.close()
}
