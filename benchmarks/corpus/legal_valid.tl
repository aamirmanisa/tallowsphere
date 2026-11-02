// @legal annotation examples.
//
// Every function that touches the network or stores data must carry a @legal
// annotation recording the lawful basis and the purpose; personal data also
// needs a retention window. tests/fixtures/legal_invalid.tl is the failing
// counterpart (a network call with no @legal), legal_valid.tl the passing one.
//
// Run: tallow run examples/legal_valid.tl

// Public data: no personal data, so no retention window is required.
@legal(basis: .public_data, purpose: "aggregate public catalogue statistics")
fn catalogue_stats(rows: i64) -> String {
    "rows processed: {rows}"
}

// Research basis over public listings.
@legal(basis: .research, purpose: "market research over public listings")
fn research_note(topic: String) -> String {
    "research note: {topic}"
}

// A network-touching function must be annotated. This one is declared but
// never called here: examples never perform live network I/O. The annotation
// also carries politeness fields that the audit trail records.
@legal(
    basis: .public_data,
    purpose: "mirror the public product index",
    robots_txt: "/robots.txt",
    rate_limit: "1 rps"
)
fn mirror_public_index(url: URL) -> Result<String> {
    let resp = fetch(url)?
    Ok(resp.text())
}

fn main() {
    print("=== @legal annotation examples ===")

    print(catalogue_stats(1200))
    print(research_note("public store listings"))

    print("Every function above declares basis + purpose.")
    print("Network/browser access without @legal is a compile error: see")
    print("tests/fixtures/legal_invalid.tl.")
}
