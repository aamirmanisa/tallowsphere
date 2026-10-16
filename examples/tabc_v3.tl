// TABC Roster Downloader v3 — using Tallow built-in browser functions
// click_button() and select_option() are declared in stdlib/browser.tl
// page.goto(), page.content(), page.evaluate() proven working in mbs_browser_recon.tl

const OUT = "/mnt/Personal/Nixe/artifacts/rss_research/tabc_rosters"

@legal(basis: .public_data, purpose: "TABC public records download", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    print("=== TABC ROSTER v3 ===")
    
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.set_viewport(1280, 900)
    
    // Navigate to TABC Public Inquiry
    page.goto("https://www.tabc.texas.gov/public-information/tabc-public-inquiry/")
    print("At TABC page")
    
    // Click the Public Inquiry System link
    page.click_button("Public Inquiry System")
    page.wait_for_stable(3000, 500)
    print("At agreement")
    
    // Acknowledge
    page.click_button("Acknowledge and Proceed")
    page.wait_for_stable(3000, 500)
    print("At welcome")
    
    // Get page content to verify
    let html = page.content()
    let html_str = "" + html
    print("Page size: " + html_str.len().to_string())
    
    // Save welcome page
    fs.write(OUT + "/welcome.html", html_str)
    
    // Now try to navigate the roster
    // Click "Create a list of Licenses: Old Layout" link 
    page.click_button("Old Layout")
    page.wait_for_stable(3000, 500)
    print("Clicked Old Layout")
    
    // Get content
    let html2 = page.content()
    let html2_str = "" + html2
    fs.write(OUT + "/roster.html", html2_str)
    print("Roster page size: " + html2_str.len().to_string())
    
    // Click Add/Edit for location
    page.click_button("Add/Edit")
    page.wait_for_stable(3000, 500)
    print("Location form open")
    
    let html3 = page.content()
    let html3_str = "" + html3
    fs.write(OUT + "/location_form.html", html3_str)
    
    // Select Travis county
    page.select_option("select[name$='ddlCounty']", "TRAVIS")
    page.wait_for_stable(1000, 500)
    print("Selected TRAVIS")
    
    // Submit Entry
    page.click_button("Submit Entry")
    page.wait_for_stable(3000, 500)
    print("Submitted county")
    
    let html4 = page.content()
    let html4_str = "" + html4
    fs.write(OUT + "/after_county.html", html4_str)
    
    // Go To Summary Page
    page.click_button("Go To Summary Page")
    page.wait_for_stable(5000, 1000)
    print("At summary")
    
    let html5 = page.content()
    let html5_str = "" + html5
    fs.write(OUT + "/summary.html", html5_str)
    print("Summary size: " + html5_str.len().to_string())
    
    browser.close()
    print("DONE")
}
