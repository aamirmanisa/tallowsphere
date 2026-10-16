// parity: expect-refusal
// Refusal-parity fixture: a non-string seed URL.
//
// The interpreter used to COERCE this (`v.as_string()` → "42") and plan a crawler from it;
// the compiled leg refused. Both now refuse, naming the same cause.

fn main() {
    let c = Crawler.from_links(42)
    print(c.strategy)
}
