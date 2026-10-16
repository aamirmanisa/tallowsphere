// TABC Roster Downloader v7 — getElementById + click() for every button
// ASP.NET __doPostBack not triggering. Native click() on elements works.

const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"

fn ev(page: String, js: String) -> String {
    let res = page.evaluate(js)
    "" + res
}

fn click_id(page: String, id: String) {
    ev(page, "var b=document.getElementById('" + id + "');if(b) b.dispatchEvent(new Event('click'))")
}

fn save(page: String, name: String) {
    let h = page.content()
    let s = "" + h
    fs.write(OUT + "/" + name, s)
}

@legal(basis: .public_data, purpose: "TABC public records download", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC ROSTER v7 ===")

    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)

    // Navigate to apps.tabc.texas.gov
    page.goto("https://apps.tabc.texas.gov/publicinquiry/")
    page.wait_for_selector("input[type=submit]")
    save(page, "00_start.html")
    print("At apps")

    // Acknowledge if needed
    click_id(page, "MainContent_btnAcknowledge")
    page.wait_for_stable(3000, 500)
    save(page, "01_welcome.html")
    print("At welcome")

    // Click Roster Old Layout: MainContent_lnkbtnRoster
    click_id(page, "MainContent_lnkbtnRoster")
    page.wait_for_stable(3000, 500)
    save(page, "02_roster.html")
    print("At roster form")
    
    // Verify we're on the roster
    let check = ev(page, "document.body?document.body.innerText.substring(0,200):'no body'")
    print("Page: " + check)

    // Click Add/Edit for Location: MainContent_btnLocation
    click_id(page, "MainContent_btnLocation")
    // Wait for the full county dropdown name — avoids matching DataTable dropdowns
    page.wait_for_selector("select[name$='RosterSelectLocation$ddlCounty']")
    // Double check — also try without quotes
    ev(page, "0")  // no-op to ensure page is stable
    save(page, "03_location_form.html")
    print("Location panel open")

    // Select TRAVIS county
    ev(page, "var s=document.querySelector('select[name$=ddlCounty]');if(s) s.value='TRAVIS'")
    page.wait_for_stable(500, 200)
    print("Selected TRAVIS")

    // Submit Entry — button is MainContent_btnSubmit with value "Submit Entry"
    click_id(page, "MainContent_btnSubmit")
    page.wait_for_stable(3000, 500)
    save(page, "04_county_submitted.html")
    print("County submitted")
    
    // Check if county was added
    let check2 = ev(page, "document.body?document.body.innerText.substring(0,500):'no body'")
    print("After submit: " + check2)

    // Go To Summary Page — same button now shows "Go To Summary Page"
    click_id(page, "MainContent_btnSubmit")
    page.wait_for_stable(5000, 1000)
    save(page, "05_summary.html")
    print("At summary")

    // Get page content and links
    let summary_text = ev(page, "document.body?document.body.innerText.substring(0,1000):'no body'")
    print("Summary: " + summary_text)

    let links = ev(page, "JSON.stringify(Array.from(document.querySelectorAll('a')).map(function(a) a.href))")
    fs.write(OUT + "/summary_links.json", links)

    browser.close()
    print("DONE")
}
