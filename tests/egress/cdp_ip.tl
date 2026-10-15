@legal(basis: .research, purpose: "egress check: what IP does the compiled browser (CDP) see")
@cra_class(.class_i)
@stealth(profile: .chrome_windows, evasions: .all)
@persona(id: "egress-cdp", cover_class: .researcher, compartment: "egress-2", fingerprint_seed: "egress-cdp-seed-5b39")
@burn_plan(persona: "egress-cdp", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .cohort_uniform, bot_identity: .browser)
fn main() {
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("https://api.ipify.org")
    let body = page.query_selector("body")
    print("cdp_ip=" + body.text())
    browser.close()
}
