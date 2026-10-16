// zabalist_login2.tl — Tor-routed Tallow automation of zabalist magic-link signup (v2)
// Fixes: React-native value setter via comma-operator (brace-free), bubbling input event,
//        long Turnstile poll, submit click, post-state dump.
// Run: TALLOW_TOR=1 ./target/debug/tallow run examples/zabalist_login2.tl -- user@example.com

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

    // React-safe value set: native setter + bubbling input event (createEvent, no braces)
    let js_set = "window.setr=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set," +
                 "window.evt=document.createEvent('Event'),window.evt.initEvent('input',true,false)," +
                 "window.setr.call(document.querySelector('input[type=email]'),'" + email + "')," +
                 "document.querySelector('input[type=email]').dispatchEvent(window.evt),'set-ok'"
    let set1 = from_ok(page.evaluate(js_set))
    print("SET_EMAIL: " + set1)

    // Check terms checkbox
    let cb = from_ok(page.evaluate("document.querySelector('input[type=checkbox]')?document.querySelector('input[type=checkbox]').click()||'clicked':'NOCB'"))
    print("CHECKBOX: " + cb)

    // Poll Turnstile token up to 75s
    var tok = ""
    var n = 0
    while n < 15 {
        page.wait_for_timeout(5000)
        tok = from_ok(page.evaluate("document.querySelector('[name=cf-turnstile-response]')?document.querySelector('[name=cf-turnstile-response]').value:'NOTS'"))
        n = n + 1
        print("POLL " + n.to_string() + " token_len=" + tok.len().to_string())
        if tok.len() > 20 { break }
    }

    // State before submit
    let val = from_ok(page.evaluate("document.querySelector('input[type=email]')?document.querySelector('input[type=email]').value:'?'"))
    print("INPUT_VALUE: " + val)
    let btn = from_ok(page.evaluate("document.querySelector('form button[type=submit]')?document.querySelector('form button[type=submit]').disabled:'NOBTN'"))
    print("SUBMIT_DISABLED: " + btn)

    // Click submit
    let click = from_ok(page.evaluate("document.querySelector('form button[type=submit]')?document.querySelector('form button[type=submit]').click()||'ok':'nobtn'"))
    print("SUBMIT_CLICK: " + click)

    page.wait_for_timeout(8000)

    let body2 = from_ok(page.evaluate("document.body?document.body.innerText.substring(0,900):'NO BODY'"))
    print("AFTER_SUBMIT: " + body2)

    let cookies = from_ok(page.cookie_string("https://www.zabalist.com"))
    print("COOKIES: " + cookies)

    print("DONE")
    browser.close()
}
