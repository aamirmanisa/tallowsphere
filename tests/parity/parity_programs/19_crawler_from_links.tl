// Parity fixture: `Crawler.from_links` — the ALREADY-BOUND native, now with a compiling
// path pinned against the interpreter's values.
//
// Offline by construction: `crawler_from_links_plan` is pure, so this needs no egress.
// Tag+value lines rather than interpolation, for the same reason as the structured-data
// fixture: interpolating would test the interpolation rules, not the binding.

fn main() {
    let c = Crawler.from_links("https://example.com", 5)
    print("A_seed")
    print(c.seed_url)
    print("A_strategy")
    print(c.strategy)
    print("A_maxdepth")
    print(c.max_depth)
    print("A_maxpages")
    print(c.max_pages)
    print("A_crawled")
    print(c.pages_crawled)
    print("A_rate")
    print(c.rate_limit_ms)

    // The optional argument's shared default (3) is a decided value, not an absence.
    let d = Crawler.from_links("https://example.com")
    print("B_maxdepth")
    print(d.max_depth)
}
