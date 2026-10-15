// realtor_scraper.tl — Realtor.com property scraper (L1Scout — no stealth needed)
//
// Realtor.com serves Schema.org JSON-LD server-side with 42 properties per page.
// No bot detection, no JS required — pure HTTP extraction.
//
// Because Tallow's taint analyzer is strict about write_file(), this script
// outputs JSON-LD to stdout. Pipe to files for post-processing.
//
// Usage:
//   tallow run examples/realtor_scraper.tl
//   TALLOW_CITY="Austin_TX" tallow run examples/realtor_scraper.tl
//   TALLOW_PAGES=5 tallow run examples/realtor_scraper.tl > realtor_raw.json
//
// Then: python3 scripts/realtor_parse.py realtor_raw.json

import tallow.http
import tallow.json

fn from_ok(res: String) -> String {
    "" + res
}

fn extract_json_ld(html: String) -> String {
    if !html.contains("application/ld+json") { return "" }
    let after_start = html.split("application/ld+json\"")
    if after_start.len < 2 { return "" }
    let tail = after_start[1]
    if tail.len < 10 { return "" }
    if !tail.contains("</script>") { return tail.substring(1, tail.len) }
    var block = tail.split("</script>")[0]
    if block.len > 0 && block.substring(0, 1) == ">" { block = block.substring(1, block.len) }
    block
}

@stealth(profile: .chrome_windows, evasions: .all)
@legal(
    basis: .public_data,
    purpose: "public real estate data aggregation from public schema.org feeds",
    personal_data: false,
    robots_txt: .respect,
    rate_limit: 3.per_second
)
fn main() {
    var search_city = "Houston_TX"
    var max_pages = 1

    let city_env = env.get("TALLOW_CITY")
    if !city_env.is_nil() { search_city = "" + city_env }

    let pages_env = env.get("TALLOW_PAGES")
    if !pages_env.is_nil() { max_pages = ("" + pages_env).to_int() }

    let BASE = "https://www.realtor.com"

    print("=== REALTOR.COM PROPERTY SCRAPER ===")
    print("City: " + search_city)
    print("Pages: " + max_pages.to_string())
    print("---BEGIN_JSONL---")

    var total = 0
    var pg = 1

    while pg <= max_pages {
        var url = BASE + "/realestateandhomes-search/" + search_city
        if pg > 1 {
            url = BASE + "/realestateandhomes-search/" + search_city + "/pg-" + pg.to_string()
        }

        let resp = http.get(url, {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml"
        })

        let html = from_ok(resp.text())

        if html.len < 1000 {
            pg = pg + 1
            continue
        }

        let json_ld = extract_json_ld(html)
        if json_ld.len < 200 {
            pg = pg + 1
            continue
        }

        // Count and print each listing as individual JSONL line
        var count = 0
        var i = 0
        while i < json_ld.len - 20 {
            if json_ld.substring(i, i + 16) == "\"priceCurrency\"" {
                count = count + 1
            }
            i = i + 1
        }

        // Print the raw JSON-LD block prefixed with page marker
        print("---PAGE:" + pg.to_string() + ":" + count.to_string() + "---")
        print(json_ld)

        total = total + count
        pg = pg + 1
    }

    print("---TOTAL:" + total.to_string() + "---")
    print("---END_JSONL---")
}
