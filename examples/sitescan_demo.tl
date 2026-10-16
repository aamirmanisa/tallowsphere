// examples/sitescan_demo.tl — comprehensive website + infrastructure scan (D5).
//
// Owner-authorized, READ-ONLY scan of an own asset (myvapeisland.com, which
// is hosted on this same machine). Demonstrates the full depth ladder:
//   D1 surface -> D2 pages -> D3 assets & endpoints -> D4 infra -> D5 network
// with the network stage gated by an explicit owner authorization CIDR
// (this box's own public address).
//
// Run: ./target/debug/tallow run examples/sitescan_demo.tl

@legal(
    basis: .public_data,
    purpose: "owner-authorized read-only website + infrastructure scan of an own asset",
    personal_data: false,
    rate_limit: 2.per_second
)
fn main() {
    print("== sitescan: comprehensive website + infrastructure scan ==")

    // 0. Egress posture (fail-closed contract; Tor-first).
    let eg = sitescan.probe_egress().parse_json().unwrap()
    print("egress: " + eg.to_string())

    // 1. Depth ladder (step 3 of the spec: adjustable penetration depth).
    let di = sitescan.depth_info().parse_json().unwrap()
    print("depth ladder: " + di.get("levels").len().to_string() + " levels, 1..5")

    // 2. Full-scope scan at D5. Owner authorization CIDR = this box's public IP.
    let target = "https://myvapeisland.com"
    let opts = '{"max_pages": 6, "link_depth": 2, "max_js": 8, "max_css": 4, "authorized_cidr": "203.0.113.1/32", "port_timeout_ms": 1200}'
    print("scanning " + target + " @ depth 5 ...")
    let raw = sitescan.scan(target, 5, opts).unwrap()
    let env = raw.parse_json().unwrap()

    // 3. Headline findings.
    let st = env.get("stages")
    print("ok=" + env.get("ok").to_string()
        + " depth=" + env.get("depth").get("level").to_string()
        + " (" + env.get("depth").get("label").to_string() + ")"
        + " stages=" + env.get("stage_order").len().to_string())
    print("surface: HTTP " + st.get("surface").get("http").get("status").to_string()
        + " title=" + st.get("surface").get("homepage").get("title").to_string()
        + " tech=" + st.get("surface").get("tech").len().to_string())
    print("pages: " + st.get("pages").get("count").to_string()
        + " crawled (capped=" + st.get("pages").get("capped").to_string() + ")")
    print("assets: " + st.get("assets").get("inventory").get("unique").to_string()
        + " unique assets · endpoints=" + st.get("assets").get("endpoints").len().to_string()
        + " · sourcemaps=" + st.get("assets").get("sourcemaps").len().to_string())
    print("infra: subdomains=" + st.get("infra").get("subdomains").get("count").to_string()
        + " certRows=" + st.get("infra").get("certs").get("cert_rows").to_string()
        + " ips=" + st.get("infra").get("ips").len().to_string())
    print("network: open=" + st.get("network").get("open").len().to_string()
        + " / " + st.get("network").get("ports_requested").len().to_string() + " ports on "
        + st.get("network").get("targets_scanned").to_string() + " host(s)")
    print("errors/notes: " + env.get("errors").len().to_string())

    // 4. Aggregate findings: raw envelope + rendered report.
    fs.write_file("artifacts/sitescan_2026-09-12/myvapeisland_d5_scan.json", raw)
    let md = sitescan.report(raw).unwrap()
    fs.write_file("artifacts/sitescan_2026-09-12/myvapeisland_d5_report.md", md)
    print('wrote artifacts/sitescan_2026-09-12/{myvapeisland_d5_scan.json,myvapeisland_d5_report.md}')
    print("DONE")
}
