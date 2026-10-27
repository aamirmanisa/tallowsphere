// End-to-end run for the tallow.api bundle surface (N16).
//
// Offline by construction: both inputs are local fixtures under
// tests/fixtures/intel_api/, and the scanner only ever reads text — no
// network, no browser, no evaluation of the JavaScript.
//
// Run from the repository root:
//   cargo run -- run tests/fixtures/intel_api/bundle_routes.tl
fn main() {
    let bundle = fs.read_file("tests/fixtures/intel_api/bundle.min.js")
    let url = "https://fixture.test/static/bundle.min.js"

    // ── N16: the bundle text itself ─────────────────────────────────────
    // Seven constructs are in the fixture (a literal, a fetch literal, a fetch
    // template, a concatenation, an axios call, a $.ajax url field, and an
    // asset path that must not be reported).
    let plain = api.bundle_routes(bundle, url)
    print("n16: mode=" + plain.map_mode + " count=" + plain.count + " unlocated=" + plain.skipped_unlocated + " non_route=" + plain.skipped_non_route)
    for r in plain.routes {
        print("n16: route=" + r.route + " from=" + r.recovered_from + " offset=" + r.offset + " line=" + r.line + " interpolated=" + r.interpolated + " partial=" + r.partial)
    }

}
