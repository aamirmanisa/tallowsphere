// TABC Roster v11 — hybrid: __doPostBack for links, onclick eval for form submits
// Links don't need form data, __doPostBack works fine for them
// Submit buttons need form data (county dropdown), use onclick eval for those

const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"

fn ev(page: String, js: String) -> String {
    let res = page.evaluate(js)
    "" + res
}

fn postback(page: String, target: String) {
    ev(page, "__doPostBack('" + target + "','')")
}

fn submit_form(page: String, target: String) {
    // Full form submit with event target set — use only when target IS rendered on page
    // Sets __EVENTTARGET to the control name, then submits the form
    ev(page, "document.getElementById('__EVENTTARGET').value='" + target + "';" +
             "document.forms[0].submit()")
}

fn save(page: String, name: String) {
    let h = page.content()
    fs.write(OUT + "/" + name, "" + h)
}

fn wait_id(page: String, id: String) {
    var tries = 0
    while tries < 15 {
        let found = ev(page, "document.getElementById('" + id + "')?'YES':'NO'")
        if found == "YES" { tries = 15 }
        tries = tries + 1
    }
}

fn text(page: String) -> String {
    ev(page, "document.body?document.body.innerText.substring(0,300):'NO BODY'")
}

@legal(basis: .public_data, purpose: "TABC", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC v11 ===")
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)

    page.goto("https://apps.tabc.texas.gov/publicinquiry/")
    page.wait_for_selector("a")
    print("1 Welcome")

    // Roster link via __doPostBack (proven working)
    postback(page, "ctl00$MainContent$lnkbtnRoster")
    wait_id(page, "MainContent_btnLocation")
    save(page, "01_roster.html")
    print("2 Roster: " + text(page))

    // Location panel via __doPostBack (proven working in v8)
    postback(page, "ctl00$MainContent$btnLocation")
    wait_id(page, "MainContent_RosterSelectLocation_ddlCounty")
    save(page, "02_location.html")
    print("3 Location panel open")

    // Select TRAVIS
    ev(page, "document.getElementById('MainContent_RosterSelectLocation_ddlCounty').value='TRAVIS'")
    print("4 TRAVIS selected")

    // Submit Entry via full form submit — carries dropdown data
    submit_form(page, "ctl00$MainContent$btnSubmit")
    page.wait_for_stable(3000, 500)
    save(page, "03_submitted.html")
    print("5 Submit: " + text(page))

    // Return to roster
    postback(page, "ctl00$MainContent$btnExit")
    wait_id(page, "MainContent_btnLicense")
    save(page, "04_back.html")
    print("6 Return: " + text(page))

    // ── Add License Type ──
    postback(page, "ctl00$MainContent$btnLicense")
    wait_id(page, "MainContent_RosterSelectLicense")  // will timeout, but try
    page.wait_for_stable(2000, 500)
    save(page, "05_license_form.html")
    print("6b License form: " + text(page))

    // Go To Summary — see if just Location is enough if we select "All" license types
    postback(page, "ctl00$MainContent$btnSubmit")
    page.wait_for_stable(5000, 1000)
    save(page, "06_summary.html")
    print("7 Summary: " + text(page))

    // Get CSV links
    let csv = ev(page, "JSON.stringify(Array.from(document.querySelectorAll('a'))." +
                 "filter(function(a) a.href.indexOf('.csv')>-1||a.href.indexOf('.xls')>-1)." +
                 "map(function(a) a.href))")
    print("8 CSV: " + csv)
    fs.write(OUT + "/csv_links.json", csv)

    save(page, "99_final.html")
    browser.close()
    print("DONE")
}
