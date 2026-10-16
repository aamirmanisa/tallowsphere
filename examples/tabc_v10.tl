// TABC Roster v10 — eval button onclick strings directly
// __doPostBack doesn't carry form field values (county dropdown)
// Must execute the actual onclick handler which includes validation

const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"

fn ev(page: String, js: String) -> String {
    let res = page.evaluate(js)
    "" + res
}

// Execute a button's onclick handler by reading its attribute and eval-ing it
fn click_onclick(page: String, id: String) {
    // Read onclick attr and eval it — single expression, no braces
    ev(page, "var b=document.getElementById('" + id + "');" +
             "b&&b.getAttribute('onclick')&&eval(b.getAttribute('onclick').replace('javascript:',''))")
}

fn save(page: String, name: String) {
    let h = page.content()
    let s = "" + h
    fs.write(OUT + "/" + name, s)
}

fn wait_for_id(page: String, id: String) {
    var tries = 0
    while tries < 20 {
        let found = ev(page, "document.getElementById('" + id + "')?'YES':'NO'")
        if found == "YES" { tries = 20 }
        tries = tries + 1
    }
}

fn page_text(page: String) -> String {
    ev(page, "document.body?document.body.innerText.substring(0,400):'NO BODY'")
}

@legal(basis: .public_data, purpose: "TABC public records", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC ROSTER v10 ===")
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)

    // [1] Welcome
    page.goto("https://apps.tabc.texas.gov/publicinquiry/")
    page.wait_for_selector("a")
    print("[1] Welcome")

    // [2] Click Roster via onclick eval
    click_onclick(page, "MainContent_lnkbtnRoster")
    wait_for_id(page, "MainContent_btnLocation")
    print("[2] Roster: " + page_text(page))

    // [3] Open Location panel via onclick eval
    click_onclick(page, "MainContent_btnLocation")
    wait_for_id(page, "MainContent_RosterSelectLocation_ddlCounty")
    print("[3] Location panel open")

    // [4] Select TRAVIS
    ev(page, "document.getElementById('MainContent_RosterSelectLocation_ddlCounty').value='TRAVIS'")
    print("[4] Selected TRAVIS")

    // [5] Submit Entry via onclick eval — includes form data!
    click_onclick(page, "MainContent_btnSubmit")
    page.wait_for_stable(3000, 500)
    print("[5] Submit: " + page_text(page))

    // [6] Return to roster
    click_onclick(page, "MainContent_btnExit")
    wait_for_id(page, "MainContent_btnLocation")
    print("[6] Return: " + page_text(page))

    // [7] Go To Summary
    click_onclick(page, "MainContent_btnSubmit")
    page.wait_for_stable(5000, 1000)
    save(page, "07_summary.html")
    print("[7] Summary: " + page_text(page))

    // [8] Get download links
    let csv = ev(page, "JSON.stringify(Array.from(document.querySelectorAll('a')).filter(function(a) " +
                 "a.href.indexOf('.csv')>-1||a.href.indexOf('.xls')>-1).map(function(a) a.href))")
    print("[8] CSV: " + csv)
    fs.write(OUT + "/csv_links.json", csv)

    save(page, "99_final.html")
    browser.close()
    print("DONE")
}
