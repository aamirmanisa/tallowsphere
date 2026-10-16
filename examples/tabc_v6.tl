// TABC Roster Downloader v6 — navigate directly to apps.tabc.texas.gov
// The "Public Inquiry System" link goes to external apps subdomain.
// Navigate directly there and handle agreement/welcome/roster flow.

const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"

fn ev(page: String, js: String) -> String {
    let res = page.evaluate(js)
    "" + res
}

// Click first submit button whose value contains text
fn click_btn(page: String, text: String) {
    ev(page, "var bs=document.querySelectorAll('input[type=submit]');for(var i=0;i<bs.length;i++) " +
             "if(bs[i].value.indexOf('" + text + "')>-1) bs[i].click()")
}

// Click first link whose text contains substring
fn click_link(page: String, text: String) {
    ev(page, "var as=document.querySelectorAll('a');for(var i=0;i<as.length;i++) " +
             "if(as[i].textContent.indexOf('" + text + "')>-1) as[i].click()")
}

fn save(page: String, name: String) {
    let h = page.content()
    let s = "" + h
    fs.write(OUT + "/" + name, s)
}

@legal(basis: .public_data, purpose: "TABC public records download", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC ROSTER v6 ===")

    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)

    // Navigate DIRECTLY to apps.tabc.texas.gov
    page.goto("https://apps.tabc.texas.gov/publicinquiry/")
    page.wait_for_selector("input[type=submit]")
    save(page, "00_start.html")
    print("At apps.tabc.texas.gov")

    // Check if at agreement page - acknowledge if needed
    click_btn(page, "Acknowledge")
    page.wait_for_stable(3000, 500)
    save(page, "01_post_ack.html")
    print("Acknowledged agreement (if present)")

    // We should now be at the welcome page with links like:
    // "Verify the status and other information on License(s): Old Layout | New Layout"
    // "Create a list of Licenses: Old Layout | New Layout"
    
    // Look for "Create a list of Licenses" and click its "Old Layout"
    // The welcome page has text like "Create a list of Licenses: Old Layout | New Layout"
    // We need to click the "Old Layout" link that follows "Create a list of Licenses"
    
    // Click the Roster "Old Layout" link by its ID: MainContent_lnkbtnRoster
    ev(page, "var a=document.getElementById('MainContent_lnkbtnRoster');if(a) a.click()")
    page.wait_for_stable(3000, 500)
    save(page, "02_roster_form.html")
    print("At roster form")

    // Click Add/Edit for Location using proper ASP.NET postback
    // Must set __EVENTTARGET before calling __doPostBack
    ev(page, "document.getElementById('__EVENTTARGET')?document.getElementById('__EVENTTARGET').value='ctl00$MainContent$btnLocation':0;__doPostBack('ctl00$MainContent$btnLocation','')")
    page.wait_for_selector("select")
    save(page, "03_location_form.html")
    print("Location form open")

    // Select TRAVIS county
    ev(page, "var s=document.querySelector('select[name$=ddlCounty]');if(s) s.value='TRAVIS'")
    page.wait_for_stable(500, 200)

    // Submit Entry — use __doPostBack
    ev(page, "__doPostBack('ctl00$MainContent$btnSubmit','')")
    page.wait_for_stable(3000, 500)
    save(page, "04_county_submitted.html")
    print("County submitted")

    // Go To Summary Page — button value is "Go To Summary Page"
    click_btn(page, "Summary")
    page.wait_for_stable(5000, 1000)
    save(page, "05_summary.html")
    print("At summary")

    // Check page content for success indicators
    let content = ev(page, "document.body?document.body.innerText.substring(0,500):'no body'")
    print("Page text: " + content)

    // Look for download links
    let links = ev(page, "JSON.stringify(Array.from(document.querySelectorAll('a')).map(function(a) " +
                   "a.href))")
    fs.write(OUT + "/06_links.json", links)

    browser.close()
    print("DONE")
}
