// property_scraper.tl — Multi-site property scraper with BrowserPool CDP
//
// Uses Tallow's BrowserPool with stealth/warmup/turnstile to bypass:
//   - HAR.com      (PerimeterX)
//   - Crexi.com     (Cloudflare Managed Challenge)
//   - Zillow.com    (PerimeterX)
//   - LoopNet.com   (Akamai Bot Manager)
//
// Usage:
//   tallow run examples/property_scraper.tl
//   TALLOW_SITE="har" tallow run examples/property_scraper.tl
//   TALLOW_SITE="crexi" tallow run examples/property_scraper.tl
//   TALLOW_SITE="zillow" tallow run examples/property_scraper.tl
//   TALLOW_SITE="loopnet" tallow run examples/property_scraper.tl
//
// Output: property_raw_<site>_<city>.html + property_data_<site>_<city>.jsonl

import tallow.http

fn from_ok(res: String) -> String {
    "" + res
}

fn squash(s: String) -> String {
    var out = s.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    var last = ""
    while out != last {
        last = out
        out = out.replace("  ", " ")
    }
    out.trim()
}

fn json_esc(s: String) -> String {
    s.replace("\n", " ").replace("\r", " ").replace("\t", " ")
}

// ── HAR.com scraper ────────────────────────────────────────────────────────

@stealth(profile: .chrome_windows, evasions: .all)
@legal(basis: .public_data, purpose: "public real estate data collection", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
fn scrape_har(pool: String, city: String) {
    print("[HAR] Starting PerimeterX bypass...")

    let page_res = BrowserPool.acquire(pool)
    let page = match page_res {
        Ok(p) -> p
        Err(e) -> {
            print("[HAR] FATAL: pool acquire failed: " + e)
            return
        }
    }

    // Set stealth profile before navigation
    page.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36") match {
        Ok(_) -> {}
        Err(e) -> print("[HAR] UA warning: " + e)
    }

    page.set_viewport(1920, 1080) match {
        Ok(_) -> {}
        Err(e) -> print("[HAR] viewport warning: " + e)
    }

    // Navigate to HAR — expect PX challenge
    page.goto("https://www.har.com/")
    page.wait_for_timeout(5000)

    // Check if PX challenge was solved
    let title_res = page.evaluate("document.title")
    let title = from_ok(title_res)
    print("[HAR] Page title: " + title)

    // Check page content
    let body_text_res = page.evaluate("document.body?document.body.innerText.substring(0,500):'no body'")
    let body_text = from_ok(body_text_res)
    print("[HAR] Body: " + body_text)

    // Try to navigate to search
    var search_url = "https://www.har.com/search/dosearch?city=" + city
    page.goto(search_url)
    page.wait_for_timeout(5000)

    // Extract content
    let content_res = page.content()
    let html = from_ok(content_res)

    // Save raw output
    print("---HAR_RAW_START---")
    print(html)
    print("---HAR_RAW_END---")

    BrowserPool.release(page)
    print("[HAR] Done")
}

// ── Crexi.com scraper ──────────────────────────────────────────────────────

@stealth(profile: .chrome_windows, evasions: .all)
@legal(basis: .public_data, purpose: "public real estate data collection", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
fn scrape_crexi(pool: String, city: String) {
    print("[CREXI] Starting Cloudflare bypass...")

    let page_res = BrowserPool.acquire(pool)
    let page = match page_res {
        Ok(p) -> p
        Err(e) -> {
            print("[CREXI] FATAL: pool acquire failed: " + e)
            return
        }
    }

    page.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36") match {
        Ok(_) -> {}
        Err(e) -> print("[CREXI] UA warning: " + e)
    }

    page.set_viewport(1920, 1080) match {
        Ok(_) -> {}
        Err(e) -> print("[CREXI] viewport warning: " + e)
    }

    // Navigate — CF challenge will fire
    page.goto("https://www.crexi.com/")
    page.wait_for_timeout(8000)

    let title_res = page.evaluate("document.title")
    let title = from_ok(title_res)
    print("[CREXI] Page title: " + title)

    // Check if we got past CF
    let body_text_res = page.evaluate("document.body?document.body.innerText.substring(0,500):'no body'")
    let body_text = from_ok(body_text_res)
    print("[CREXI] Body: " + body_text)

    // If past CF, hit the search API
    page.goto("https://www.crexi.com/api/search?q=" + city)
    page.wait_for_timeout(3000)

    let content_res = page.content()
    let html = from_ok(content_res)

    print("---CREXI_RAW_START---")
    print(html)
    print("---CREXI_RAW_END---")

    BrowserPool.release(page)
    print("[CREXI] Done")
}

// ── Zillow.com scraper ─────────────────────────────────────────────────────

@stealth(profile: .chrome_windows, evasions: .all)
@legal(basis: .public_data, purpose: "public real estate data collection", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
fn scrape_zillow(pool: String, city: String) {
    print("[ZILLOW] Starting PerimeterX bypass...")

    let page_res = BrowserPool.acquire(pool)
    let page = match page_res {
        Ok(p) -> p
        Err(e) -> {
            print("[ZILLOW] FATAL: pool acquire failed: " + e)
            return
        }
    }

    page.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36") match {
        Ok(_) -> {}
        Err(e) -> print("[ZILLOW] UA warning: " + e)
    }

    page.set_viewport(1920, 1080) match {
        Ok(_) -> {}
        Err(e) -> print("[ZILLOW] viewport warning: " + e)
    }

    // Navigate — PX challenge
    page.goto("https://www.zillow.com/homes/for_sale/")
    page.wait_for_timeout(8000)

    let title_res = page.evaluate("document.title")
    let title = from_ok(title_res)
    print("[ZILLOW] Page title: " + title)

    let body_text_res = page.evaluate("document.body?document.body.innerText.substring(0,500):'no body'")
    let body_text = from_ok(body_text_res)
    print("[ZILLOW] Body: " + body_text)

    let content_res = page.content()
    let html = from_ok(content_res)

    print("---ZILLOW_RAW_START---")
    print(html)
    print("---ZILLOW_RAW_END---")

    BrowserPool.release(page)
    print("[ZILLOW] Done")
}

// ── LoopNet.com scraper ────────────────────────────────────────────────────

@stealth(profile: .chrome_windows, evasions: .all)
@legal(basis: .public_data, purpose: "public real estate data collection", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
fn scrape_loopnet(pool: String, city: String) {
    print("[LOOPNET] Starting Akamai bypass...")

    let page_res = BrowserPool.acquire(pool)
    let page = match page_res {
        Ok(p) -> p
        Err(e) -> {
            print("[LOOPNET] FATAL: pool acquire failed: " + e)
            return
        }
    }

    page.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36") match {
        Ok(_) -> {}
        Err(e) -> print("[LOOPNET] UA warning: " + e)
    }

    page.set_viewport(1920, 1080) match {
        Ok(_) -> {}
        Err(e) -> print("[LOOPNET] viewport warning: " + e)
    }

    // Skip homepage (Akamai blocks root) — go directly to search
    // Try multiple URL formats
    var urls = [
        "https://www.loopnet.com/texas/houston-commercial-real-estate/",
        "https://www.loopnet.com/commercial-real-estate/tx/houston/",
        "https://www.loopnet.com/search/?q=houston&bb=tx_st87zq",
        "https://www.loopnet.com/search/commercial-real-estate/?q=houston"
    ]
    var found = false
    var ui = 0
    while ui < urls.len && !found {
        let test_url = urls[ui]
        print("[LOOPNET] Trying: " + test_url)
        page.goto(test_url)
        page.wait_for_timeout(5000)
        var t = from_ok(page.evaluate("document.title"))
        print("[LOOPNET]   -> " + t)
        var b = from_ok(page.evaluate("document.body?document.body.innerText.substring(0,200):'?'"))
        var blocked = b.contains("Access Denied") || b.contains("denied")
        var lost = t.contains("404") || b.contains("not find")
        if !blocked && !lost {
            found = true
            print("[LOOPNET] SUCCESS: " + test_url)
        }
        ui = ui + 1
    }

    let content_res = page.content()
    let html = from_ok(content_res)

    if found {
        print("---LOOPNET_RAW_START---")
        print(html)
        print("---LOOPNET_RAW_END---")
    }

    BrowserPool.release(page)
    print("[LOOPNET] Done")
}

// ── Redfin.com scraper ─────────────────────────────────────────────────────

@stealth(profile: .chrome_windows, evasions: .all)
@legal(basis: .public_data, purpose: "public real estate data collection", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
fn scrape_redfin(pool: String, city: String) {
    print("[REDFIN] Extracting region_id via BrowserPool...")

    let page_res = BrowserPool.acquire(pool)
    let page = match page_res {
        Ok(p) -> p
        Err(e) -> {
            print("[REDFIN] FATAL: pool acquire failed: " + e)
            return
        }
    }

    // Redfin detects HeadlessChrome — use Windows Chrome UA instead
    page.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36") match {
        Ok(_) -> {}
        Err(e) -> print("[REDFIN] UA warning: " + e)
    }

    page.set_viewport(1920, 1080) match {
        Ok(_) -> {}
        Err(e) -> print("[REDFIN] viewport warning: " + e)
    }

    // Navigate Redfin to trigger Houston area detection
    // Try direct city search URL first
    page.goto("https://www.redfin.com/city/30749/TX/Houston")
    page.wait_for_timeout(6000)

    var title = from_ok(page.evaluate("document.title"))
    print("[REDFIN] Title: " + title)

    var current_url = from_ok(page.evaluate("window.location.href"))
    print("[REDFIN] URL: " + current_url)

    // Parse region_id from URL if present
    var region_id = "0"
    if current_url.contains("/city/") {
        let after = current_url.split("/city/")[1]
        region_id = after.split("/")[0]
    }

    // If region_id still 0, try body text extraction
    if region_id == "0" {
        let body = from_ok(page.evaluate("document.body?document.body.innerText:'?'"))
        // Search body for regionId=N pattern
        if body.contains("regionId=") {
            let after = body.split("regionId=")[1]
            var num = ""
            var ci = 0
            while ci < after.len {
                let ch = after.substring(ci, ci + 1)
                if ch == "0" || ch == "1" || ch == "2" || ch == "3" || ch == "4" ||
                   ch == "5" || ch == "6" || ch == "7" || ch == "8" || ch == "9" {
                    num = num + ch
                } else if num.len > 0 {
                    ci = after.len
                }
                ci = ci + 1
            }
            if num.len > 0 { region_id = num }
        }
    }
    print("[REDFIN] region_id: " + region_id)

    // If region_id found, print the stingray API URL for use
    if region_id != "0" && region_id.len > 0 {
        var api_url = "https://www.redfin.com/stingray/api/gis-csv?al=1&num_homes=350&page_number=1&region_id=" + region_id + "&region_type=6&sf=1,2,3,4,5,6,7&status=1&uipt=1&v=8"
        print("[REDFIN] API URL: " + api_url)
    }

    let body = from_ok(page.evaluate("document.body?document.body.innerText.substring(0,500):'no body'"))
    print("[REDFIN] Body: " + body)

    BrowserPool.release(page)
    print("[REDFIN] Done")
}

// ── Main ───────────────────────────────────────────────────────────────────

@stealth(profile: .chrome_windows, evasions: .all)
@legal(
    basis: .public_data,
    purpose: "public real estate data collection for market research",
    personal_data: false,
    robots_txt: .respect,
    rate_limit: 1.per_second
)
fn main() {
    var site = "har"
    var city = "Houston"

    let site_env = env.get("TALLOW_SITE")
    if !site_env.is_nil() { site = "" + site_env }

    let city_env = env.get("TALLOW_CITY")
    if !city_env.is_nil() { city = "" + city_env }

    print("=== PROPERTY SCRAPER (BrowserPool) ===")
    print("Site: " + site)
    print("City: " + city)
    print("")

    // Create browser pool — 2 browsers for sequential use
    print("Creating browser pool...")
    let pool_res = BrowserPool.create(2, 200, false)
    let pool = match pool_res {
        Ok(p) -> p
        Err(e) -> {
            print("FATAL: BrowserPool.create failed: " + e)
            return
        }
    }

    if site == "har" {
        scrape_har(pool, city)
    } else if site == "crexi" {
        scrape_crexi(pool, city)
    } else if site == "zillow" {
        scrape_zillow(pool, city)
    } else if site == "loopnet" {
        scrape_loopnet(pool, city)
    } else if site == "redfin" {
        scrape_redfin(pool, city)
    } else {
        print("Valid: har, crexi, zillow, loopnet")
    }

    // BrowserPool.shutdown(pool)  // Pool auto-cleans on process exit
    print("[DONE]")
}
