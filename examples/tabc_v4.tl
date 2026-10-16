// TABC Roster Downloader v4 — page.evaluate() for all interactions
// click_button and select_option are stubs; must use raw JS via evaluate()

const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"

fn save(page: String, filename: String) {
    let html = page.content()
    let s = "" + html
    fs.write(OUT + "/" + filename, s)
}

fn eval_js(page: String, js: String) -> String {
    let res = page.evaluate(js)
    "" + res
}

// JS helpers — simple functions with single quotes to avoid Tallow interpolation
const CLICK_LINK = "var as=document.querySelectorAll('a');for(var i=0;i<as.length;i++){if(as[i].textContent.indexOf('ARG')>-1){as[i].click();break}}"

const CLICK_BTN = "var bs=document.querySelectorAll('input[type=submit],button');for(var i=0;i<bs.length;i++){var v=bs[i].value||'';if(v.indexOf('ARG')>-1){bs[i].click();break}}"

const SELECT_OPT = "(function(){var s=document.querySelector('select[name$=ddlCounty]');if(s){s.value='ARG';s.dispatchEvent(new Event('change'))}})()"

@legal(basis: .public_data, purpose: "TABC public records download", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC ROSTER v4 ===")

    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)

    // Navigate to TABC Public Inquiry  
    page.goto("https://www.tabc.texas.gov/public-information/tabc-public-inquiry/")
    page.wait_for_selector("a")
    print("At TABC page")

    // Click Public Inquiry System link
    eval_js(page, CLICK_LINK.replace("ARG", "Public Inquiry System"))
    page.wait_for_stable(3000, 500)
    save(page, "01_agreement.html")
    print("At agreement")

    // Acknowledge
    eval_js(page, CLICK_BTN.replace("ARG", "Acknowledge"))
    page.wait_for_stable(3000, 500)
    save(page, "02_welcome.html")
    print("At welcome")

    // Click Create a list of Licenses: Old Layout
    eval_js(page, CLICK_LINK.replace("ARG", "Old Layout"))
    page.wait_for_stable(3000, 500)
    save(page, "03_roster.html")
    print("At roster")

    // Click Add/Edit for location
    eval_js(page, CLICK_BTN.replace("ARG", "Add/Edit"))
    page.wait_for_selector("select")
    save(page, "04_location_form.html")
    print("Location form open")

    // Select Travis county
    eval_js(page, SELECT_OPT.replace("ARG", "TRAVIS"))
    page.wait_for_stable(500, 200)

    // Submit Entry
    eval_js(page, CLICK_BTN.replace("ARG", "Submit Entry"))
    page.wait_for_stable(3000, 500)
    save(page, "05_county_added.html")
    print("County submitted")

    // Go To Summary Page
    eval_js(page, CLICK_BTN.replace("ARG", "Summary"))
    page.wait_for_stable(5000, 1000)
    save(page, "06_summary.html")
    print("At summary")

    // Try to find download link
    let links = eval_js(page, "JSON.stringify(Array.from(document.querySelectorAll('a')).map(function(a){return a.href||''}))")
    fs.write(OUT + "/07_links.json", links)
    print("Links saved")

    browser.close()
    print("DONE — check " + OUT + "/")
}
