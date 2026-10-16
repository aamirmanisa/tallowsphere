// parity: expect-refusal
// Refusal-parity fixture: a non-string sitemap URL.
//
// Offline by construction, which matters here: `Crawler.from_sitemap` fetches. A non-string
// argument is refused BEFORE any egress, so this test can never touch the network. The
// happy path (a real fetch) is deliberately NOT covered — see tests/crawler_parity.rs.

fn main() {
    let c = Crawler.from_sitemap(42)
    print(c.strategy)
}
