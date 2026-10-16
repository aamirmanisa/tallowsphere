// zabalist_dump.tl — dump rendered auth/login HTML over Tor for offline selector analysis
// Run: TALLOW_TOR=1 ./target/debug/tallow run examples/zabalist_dump.tl > artifacts/zabalist/auth_rendered.html 2>auth_run.log

fn from_ok(res: String) -> String { "" + res }

@legal(basis: .public_data, purpose: "recon of public login form", personal_data: false,
       robots_txt: .respect, rate_limit: 1.per_second)
@cra_class(.default)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    let browser = match Browser.launch(true) {
        Ok(b) -> b
        Err(e) -> { print("FATAL launch: " + e.to_string()); return }
    }
    let page = match browser.new_page() {
        Ok(p) -> p
        Err(e) -> { print("FATAL new_page: " + e.to_string()); return }
    }
    page.set_viewport(1366, 900)
    page.apply_stealth_evasions() match { Ok(_) -> {} Err(e) -> {} }

    page.goto("https://www.zabalist.com/auth/login?signup=true")
    page.wait_for_timeout(12000)

    let html = from_ok(page.content())
    print(html)

    print("\n===MARKER_END===\n")
    browser.close()
}
