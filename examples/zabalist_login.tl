// zabalist_login.tl — Tor-routed Tallow automation of zabalist magic-link signup
// Steps: render /auth/login, fill email (React-safe), agree terms, wait Turnstile,
//        submit, report result. Email passed as first arg after --.
// Run: TALLOW_TOR=1 ./target/debug/tallow run examples/zabalist_login.tl -- user@example.com

fn from_ok(res: String) -> String { "" + res }

@legal(basis: .public_data, purpose: "automated signup flow analysis", personal_data: false,
       robots_txt: .respect, rate_limit: 1.per_second)
@cra_class(.default)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    let args = cli.args()
    var email = "test@example.com"
    if args.len() > 3 { email = args[3] }
    print("EMAIL_ARG: " + email)

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

    // 1. Set email via native value setter + input event (React-safe, no braces)
    let set1 = from_ok(page.evaluate("document.querySelector('input[type=email]')?document.querySelector('input[type=email]').value='" + email + "':'NOINPUT'"))
    print("SET_EMAIL: " + set1)
    let ev1 = from_ok(page.evaluate("document.querySelector('input[type=email]')?document.querySelector('input[type=email]').dispatchEvent(new Event('input')):'nope'"))
    print("DISPATCH: " + ev1)

    // 2. Check the terms checkbox via click
    let cb = from_ok(page.evaluate("document.querySelector('input[type=checkbox]')?document.querySelector('input[type=checkbox]').click()||'clicked':'NOCB'"))
    print("CHECKBOX: " + cb)

    page.wait_for_timeout(4000)

    // 3. State check: input value, button disabled state, turnstile token
    let val = from_ok(page.evaluate("document.querySelector('input[type=email]')?document.querySelector('input[type=email]').value:'?'"))
    print("INPUT_VALUE: " + val)
    let btn = from_ok(page.evaluate("document.querySelector('form button[type=submit]')?document.querySelector('form button[type=submit]').disabled:'NOBTN'"))
    print("SUBMIT_DISABLED: " + btn)
    let ts = from_ok(page.evaluate("document.querySelector('[name=cf-turnstile-response]')?document.querySelector('[name=cf-turnstile-response]').value.substring(0,40):'NOTS'"))
    print("TURNSTILE_TOKEN: " + ts)

    // 4. Click submit if enabled
    let click = from_ok(page.evaluate("document.querySelector('form button[type=submit]')?document.querySelector('form button[type=submit]').click()||'ok':'nobtn'"))
    print("SUBMIT_CLICK: " + click)

    page.wait_for_timeout(6000)

    let body2 = from_ok(page.evaluate("document.body?document.body.innerText.substring(0,800):'NO BODY'"))
    print("AFTER_SUBMIT: " + body2)

    // 5. Dump cookies for downstream use
    let cookies = from_ok(page.cookie_string("https://www.zabalist.com"))
    print("COOKIES: " + cookies)

    print("DONE")
    browser.close()
}
