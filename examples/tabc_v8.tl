// TABC Roster v8 — use __doPostBack for all ASP.NET postbacks
// dispatchEvent/click don't trigger javascript: hrefs on <a> links
// __doPostBack IS the standard ASP.NET mechanism and IS a function (test confirmed)

const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"

fn ev(page: String, js: String) -> String {
    let res = page.evaluate(js)
    "" + res
}

fn postback(page: String, target: String) {
    ev(page, "__doPostBack('" + target + "','')")
}

fn save(page: String, name: String) {
    let h = page.content()
    let s = "" + h
    fs.write(OUT + "/" + name, s)
}

@legal(basis: .public_data, purpose: "TABC public records", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC ROSTER v8 ===")

    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)

    // Navigate directly to apps — no agreement gate
    page.goto("https://apps.tabc.texas.gov/publicinquiry/")
    page.wait_for_selector("a")
    save(page, "00_welcome.html")
    print("At welcome page")

    // Step 1: Click Roster Old Layout via __doPostBack
    postback(page, "ctl00$MainContent$lnkbtnRoster")
    page.wait_for_stable(3000, 500)
    save(page, "01_roster.html")
    print("At roster form")
    
    let check1 = ev(page, "document.body?document.body.innerText.substring(0,200):'?'")
    print("Page: " + check1)

    // Step 2: Open Location panel via __doPostBack
    postback(page, "ctl00$MainContent$btnLocation")
    page.wait_for_stable(3000, 500)
    save(page, "02_location_form.html")
    
    // Debug: check what's on the page
    let dbg2 = ev(page, "document.body?document.body.innerText.substring(0,400):'?'")
    print("After btnLocation: " + dbg2)
    
    // Check for county dropdown specifically
    let has_county = ev(page, "document.querySelector('select[name$=ddlCounty]')?'YES':'NO'")
    let has_roster_loc = ev(page, "document.getElementById('MainContent_RosterSelectLocation_ddlCounty')?'YES':'NO'")
    print("County dropdown (ends-with): " + has_county)
    print("County dropdown (full ID): " + has_roster_loc)

    // Step 3: Select TRAVIS
    ev(page, "var s=document.querySelector('select[name$=ddlCounty]');if(s) s.value='TRAVIS'")
    page.wait_for_stable(500, 200)
    print("Selected TRAVIS")

    // Step 4: Submit Entry — adds county to list, stays on location panel
    postback(page, "ctl00$MainContent$btnSubmit")
    page.wait_for_stable(3000, 500)
    save(page, "03_county_submitted.html")
    print("County submitted")
    
    // Step 4.5: Return to roster — click "Return To Prior Page" (btnExit)
    postback(page, "ctl00$MainContent$btnExit")
    page.wait_for_stable(3000, 500)
    save(page, "03b_back_to_roster.html")
    print("Back to roster form")
    
    let check2 = ev(page, "document.body?document.body.innerText.substring(0,300):'?'")
    print("After return: " + check2)

    // Step 5: Go To Summary Page — now btnSubmit shows "Go To Summary Page"
    postback(page, "ctl00$MainContent$btnSubmit")
    page.wait_for_stable(5000, 1000)
    save(page, "04_summary.html")
    
    let check3 = ev(page, "document.body?document.body.innerText.substring(0,500):'?'")
    print("Summary: " + check3)

    // Get links
    let links = ev(page, "JSON.stringify(Array.from(document.querySelectorAll('a')).map(function(a) a.href))")
    fs.write(OUT + "/summary_links.json", links)

    browser.close()
    print("DONE")
}
