// TABC License Roster Downloader v2 — Revenue Stream Solutions
// Downloads county-level TABC license rosters via CDP browser
// Parses for Songwriters Texas LLC ownership patterns

const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"
const TABC = "https://www.tabc.texas.gov/public-information/tabc-public-inquiry/"

fn ev(page: String, js: String) -> String {
    let res = page.evaluate(js)
    "" + res
}

fn click_link_containing(page: String, text: String) {
    let js = "var as=document.querySelectorAll('a');for(var i=0;i<as.length;i++)" +
             "{if(as[i].textContent.indexOf('" + text + "')>-1){as[i].click();break}}"
    ev(page, js)
}

fn click_button_containing(page: String, text: String) {
    let js = "var bs=document.querySelectorAll('input[type=submit],button');for(var i=0;i<bs.length;i++)" +
             "{var v=bs[i].value||'';if(v.indexOf('" + text + "')>-1){bs[i].click();break}}"
    ev(page, js)
}

fn select_county(page: String, county: String) {
    let js = "(function()" +
             "{var s=document.querySelector('select[name*=ddlCounty]');" +
             "if(s){s.value='" + county + "'}}" +
             ")()"
    ev(page, js)
}

fn get_all_links(page: String) -> String {
    ev(page, "JSON.stringify(Array.from(document.querySelectorAll('a')).map(function(a){return {href:a.href||'',text:(a.textContent||'').trim().substring(0,100)}}))")
}

@legal(basis: .public_data, purpose: "TABC public records license roster download", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC ROSTER DOWNLOADER v2 ===")
    print("")

    let counties = ["TRAVIS", "WILLIAMSON", "BASTROP", "BELL", "NUECES", "LEE", "CALDWELL", "HAYS"]

    var i = 0
    while i < counties.len() {
        let county = counties[i]
        print("[" + (i + 1).to_string() + "/8] " + county + " County")

        let browser = Browser.launch(true)
        let page = browser.new_page()
        page.set_viewport(1280, 900)

        // Navigate to TABC Public Inquiry
        page.goto(TABC)
        page.wait_for_selector("a")

        // Click "Public Inquiry System" link
        click_link_containing(page, "Public Inquiry System")
        page.wait_for_stable(3000, 500)
        print("  At agreement page")

        // Acknowledge
        click_button_containing(page, "Acknowledge")
        page.wait_for_stable(3000, 500)
        print("  At welcome page")

        // Create list of licenses - Old Layout
        click_link_containing(page, "Old Layout")
        page.wait_for_stable(3000, 500)
        print("  At roster form")

        // Click Add/Edit for Location
        click_button_containing(page, "Add/Edit")
        page.wait_for_selector("select")
        print("  Location form open")

        // Select county
        select_county(page, county)
        page.wait_for_stable(1000, 500)

        // Submit Entry
        click_button_containing(page, "Submit Entry")
        page.wait_for_stable(3000, 500)
        print("  County added")

        // Go To Summary Page
        click_button_containing(page, "Summary")
        page.wait_for_stable(5000, 1000)
        print("  At summary page")

        // Get HTML and links
        let html = page.content()
        let html_str = "" + html
        
        let out_html = OUT + "/" + county + "_summary.html"
        fs.write(out_html, html_str)

        let links = get_all_links(page)
        let out_links = OUT + "/" + county + "_links.json"
        fs.write(out_links, links)
        print("  Saved: " + out_html + " (" + html_str.len().to_string() + " bytes)")
        print("  Links: " + out_links)

        browser.close()
        print("")
        i = i + 1
    }

    print("=== COMPLETE ===")
    print("Files in: " + OUT + "/")
}
