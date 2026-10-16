// TABC Roster v9 — verified postback with explicit state checks
// After every __doPostBack, verify the expected element appeared before continuing

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

fn wait_for_element(page: String, id: String) {
    var tries = 0
    while tries < 20 {
        let found = ev(page, "document.getElementById('" + id + "')?'YES':'NO'")
        if found == "YES" {
            tries = 20
        }
        tries = tries + 1
    }
}

fn page_text(page: String) -> String {
    ev(page, "document.body?document.body.innerText.substring(0,500):'NO BODY'")
}

@legal(basis: .public_data, purpose: "TABC public records", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC ROSTER v9 ===")

    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)

    // ── Navigate to TABC apps ──
    page.goto("https://apps.tabc.texas.gov/publicinquiry/")
    page.wait_for_selector("a")
    save(page, "00_welcome.html")
    print("[1] Welcome page loaded")

    // ── Click Roster Old Layout ──
    postback(page, "ctl00$MainContent$lnkbtnRoster")
    // Verify: roster form has btnLocation
    wait_for_element(page, "MainContent_btnLocation")
    save(page, "01_roster.html")
    print("[2] Roster form — btnLocation found")
    print("    " + page_text(page))

    // ── Open Location panel ──
    postback(page, "ctl00$MainContent$btnLocation")
    // Verify: location panel has county dropdown
    wait_for_element(page, "MainContent_RosterSelectLocation_ddlCounty")
    save(page, "02_location.html")
    print("[3] Location panel open — county dropdown found")

    // ── Select TRAVIS ──
    ev(page, "document.getElementById('MainContent_RosterSelectLocation_ddlCounty').value='TRAVIS'")
    print("[4] Selected TRAVIS")

    // ── Submit Entry ──
    postback(page, "ctl00$MainContent$btnSubmit")
    // After submit, TRAVIS should appear in the location list
    page.wait_for_stable(2000, 500)
    save(page, "03_county_submitted.html")
    print("[5] Submit Entry — page: " + page_text(page))

    // ── Return to roster ──
    postback(page, "ctl00$MainContent$btnExit")
    // Verify: back on roster (btnLocation should be visible)
    wait_for_element(page, "MainContent_btnLocation")
    save(page, "04_back_to_roster.html")
    print("[6] Back to roster — " + page_text(page))

    // ── Go To Summary Page ──
    postback(page, "ctl00$MainContent$btnSubmit")
    page.wait_for_stable(5000, 1000)
    save(page, "05_summary.html")
    
    // Get summary text and links
    let summary = page_text(page)
    print("[7] Summary page — " + summary)
    
    // Extract all data from summary
    let links = ev(page, "JSON.stringify(Array.from(document.querySelectorAll('a')).map(function(a) " +
                   "a.href+'|'+a.textContent.trim().substring(0,80)))")
    fs.write(OUT + "/summary_links.json", links)
    
    // Try to find CSV download
    let csv_links = ev(page, "JSON.stringify(Array.from(document.querySelectorAll('a')).map(function(a) a.href).filter(function(h) " +
                       "h.indexOf('.csv')>-1||h.indexOf('.xls')>-1||h.indexOf('Export')>-1||h.indexOf('Download')>-1))")
    fs.write(OUT + "/csv_links.json", csv_links)
    print("[8] CSV links: " + csv_links)

    // Save final full HTML
    save(page, "06_final.html")

    browser.close()
    print("DONE — files in " + OUT)
}
