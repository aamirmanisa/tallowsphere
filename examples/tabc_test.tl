// Minimal postback test
const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"

fn ev(page: String, js: String) -> String {
    let res = page.evaluate(js)
    "" + res
}

fn save(page: String, name: String) {
    let h = page.content()
    let s = "" + h
    fs.write(OUT + "/" + name, s)
}

@legal(basis: .public_data, purpose: "test", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)

    page.goto("https://apps.tabc.texas.gov/publicinquiry/")
    page.wait_for_selector("input")
    save(page, "test_00_initial.html")

    // Test 1: Can we evaluate JS at all?
    let t1 = ev(page, "'hello from JS'")
    print("Test 1 (JS eval): " + t1)

    // Test 2: Does __doPostBack exist?
    let t2 = ev(page, "typeof __doPostBack")
    print("Test 2 (typeof __doPostBack): " + t2)

    // Test 3: Does WebForm_DoPostBackWithOptions exist?
    let t3 = ev(page, "typeof WebForm_DoPostBackWithOptions")
    print("Test 3 (typeof WebForm_DoPostBackWithOptions): " + t3)

    // Test 4: Does MainContent_btnLocation exist?
    let t4 = ev(page, "document.getElementById('MainContent_btnLocation')?'YES':'NO'")
    print("Test 4 (btnLocation exists): " + t4)

    // Test 5: What's the button's onclick?
    let t5 = ev(page, "var b=document.getElementById('MainContent_btnLocation');b?b.getAttribute('onclick'):'NO BTN'")
    print("Test 5 (onclick): " + t5)

    // Test 6: Click via __doPostBack
    ev(page, "__doPostBack('ctl00$MainContent$btnLocation','')")
    page.wait_for_stable(3000, 500)
    save(page, "test_06_after_postback.html")
    let t6 = ev(page, "document.body?document.body.innerText.substring(0,300):'no body'")
    print("Test 6 (after __doPostBack): " + t6)

    // Test 7: Check if location panel opened (ddlCounty exists)
    let t7 = ev(page, "document.querySelector('select[name$=ddlCounty]')?'OPEN':'CLOSED'")
    print("Test 7 (location panel): " + t7)

    browser.close()
}
