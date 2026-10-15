// TABC Roster Downloader v5 — brace-free JavaScript via page.evaluate()
// Tallow's string parser interprets { } as interpolation even in strings.
// All JS must use single-statement bodies, no braces.

const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"

fn save(page: String, filename: String) {
    let html = page.content()
    let s = "" + html
    fs.write(OUT + "/" + filename, s)
}

fn ev(page: String, js: String) -> String {
    let res = page.evaluate(js)
    "" + res
}

@legal(basis: .public_data, purpose: "TABC public records download", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC ROSTER v5 ===")

    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)

    // Navigate to TABC
    page.goto("https://www.tabc.texas.gov/public-information/tabc-public-inquiry/")
    page.wait_for_selector("a")
    print("At TABC page")

    // Click "Public Inquiry System" link — single-statement loop, no braces
    ev(page, "var as=document.querySelectorAll('a');for(var i=0;i<as.length;i++) " +
             "if(as[i].textContent.indexOf('Public Inquiry System')>-1) as[i].click()")
    page.wait_for_stable(3000, 500)
    save(page, "01_agreement.html")
    print("At agreement")

    // Acknowledge
    ev(page, "var bs=document.querySelectorAll('input[type=submit]');for(var i=0;i<bs.length;i++) " +
             "if(bs[i].value.indexOf('Acknowledge')>-1) bs[i].click()")
    page.wait_for_stable(3000, 500)
    save(page, "02_welcome.html")
    print("At welcome")

    // Click Create a list of Licenses: Old Layout
    ev(page, "var as=document.querySelectorAll('a');for(var i=0;i<as.length;i++) " +
             "if(as[i].textContent.indexOf('Old Layout')>-1) as[i].click()")
    page.wait_for_stable(3000, 500)
    save(page, "03_roster.html")
    print("At roster")

    // Add/Edit for Location
    ev(page, "var bs=document.querySelectorAll('input[type=submit]');for(var i=0;i<bs.length;i++) " +
             "if(bs[i].value.indexOf('Add/Edit')>-1) bs[i].click()")
    page.wait_for_selector("select")
    save(page, "04_location_form.html")
    print("Location form open")

    // Select TRAVIS county
    ev(page, "var s=document.querySelector('select[name$=ddlCounty]');if(s) s.value='TRAVIS'")
    page.wait_for_stable(500, 200)

    // Submit Entry
    ev(page, "var bs=document.querySelectorAll('input[type=submit]');for(var i=0;i<bs.length;i++) " +
             "if(bs[i].value.indexOf('Submit Entry')>-1) bs[i].click()")
    page.wait_for_stable(3000, 500)
    save(page, "05_county_added.html")
    print("County submitted")

    // Go To Summary Page
    ev(page, "var bs=document.querySelectorAll('input[type=submit]');for(var i=0;i<bs.length;i++) " +
             "if(bs[i].value.indexOf('Summary')>-1) bs[i].click()")
    page.wait_for_stable(5000, 1000)
    save(page, "06_summary.html")
    print("At summary")

    // Get all links
    let links = ev(page, "JSON.stringify(Array.from(document.querySelectorAll('a')).map(function(a) " + 
                   "a.href||''))")
    fs.write(OUT + "/07_links.json", links)
    print("Links saved")

    browser.close()
    print("DONE — check " + OUT + "/")
}
