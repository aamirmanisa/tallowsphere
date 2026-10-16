// tallow.sitescan — comprehensive website + infrastructure scanning module.
// READ-ONLY · PUBLIC-DATA · GET-ONLY · FAIL-CLOSED EGRESS (TOR-FIRST).
//
// One call returns a depth-labelled picture of a target website and the
// infrastructure underneath it — no component silently dropped:
//
//   D1 surface  homepage fetch (redirect chain, ALL headers, security-header
//               matrix, cookies, link-graph rollup, tech fingerprint, forms
//               + inputs), robots.txt (parsed rules + sitemaps),
//               sitemap.xml (url count / index children), third-party hosts
//   D2 pages    robotted same-site crawl to link_depth (default 3): per page
//               url/final_url/status/content-type/bytes/title/depth, links
//               in+out, assets, forms; separate documents rollup
//   D3 assets   inventory by kind + host: images/media/fonts/scripts/styles/
//               iframes; CSS fetched & mined (url(), @import → fonts/images);
//               JS fetched & mined for endpoints — absolute URLs,
//               fetch/axios/XHR call targets, api-shaped literal paths,
//               websocket endpoints, sourceMappingURL refs — with per-finding
//               source provenance; inline scripts mined too
//   D4 infra    DNS via DoH (A/AAAA/CNAME/MX/TXT/NS/SOA/CAA), subdomains via
//               certificate transparency (crt.sh: cert rows, issuers, latest
//               expiry + days remaining); optional DNS brute + Wayback CDX;
//               rdap for the domain and resolved IPs (+ netblock rollup)
//   D5 network  TCP port sweep on resolved IPs — STRICTLY gated: every target
//               must be inside an explicit owner-authorized CIDR
//               (opts.authorized_cidr), re-checked per IP against the scope
//               authorizer; out-of-scope targets are refused, never scanned
//
// Depth parameter: scan(target, depth, opts)
//   1 | "surface" · 2 | "pages" · 3 | "assets" · 4 | "infra" · 5 | "network"
//   | "full"  (Int is the typed contract; stage names also accepted at runtime)
//
// opts (JSON string, all optional):
//   max_pages (default 25) · link_depth (3) · max_js (10) · max_css (5) ·
//   include_subdomains (false) · brute (false) · wayback (false) ·
//   only: ["surface"|"pages"|"assets"|"infra"|"network"] · ports: [..] (D5) ·
//   authorized_cidr ("x.x.x.x/nn" — required for any D5 result) ·
//   port_timeout_ms (1500)
//
// Aggregation: every stage carries counts + timing; the envelope carries
// module/version/target/host/apex/depth/stage_order/limits/errors/ok;
// report() renders the full Markdown findings document — the scope, depth &
// limits block and each stage's findings, plus a plainly-labelled errors &
// notes section (nothing silently dropped).
//
// Error contract (match on prefixes):
//   sitescan:param:  bad argument (type/value)
//   sitescan:net:    transport failure (only genuine transport errors)
//   sitescan:http:   non-2xx after retries (API stages)
//   sitescan:shape:  upstream body malformed
//   sitescan:fatal:  primary document fetch failed
//
// Egress: all HTTP rides the process-wide fail-closed egress contract
// (Tor-first); DNS via Cloudflare DoH (no plain :53); pacing via GOV_SITESCAN
// (env TALLOW_SITESCAN_RPS, default 2 rps).
//
// Read-only guarantee: GET-only forever — no POST/PUT/DELETE, no credentials,
// no login submission, no writes to the target, no exploitation. The network
// stage refuses anything outside the operator-provided authorization scope.
//
// Composition: ureq + egress_http proxy contract + RateGovernor + governed
// retry/backoff (http::governed_get) + scraper (HTML) + regex + url +
// osint Scanner/ScanScope + osint match_signatures + osint WebArchive
// (optional) + DoH + crt.sh + RDAP.

// Full scan. depth: 1..5 Int (see ladder above; stage names accepted at
// runtime). opts: JSON string (see above) or Nil for defaults. Returns the
// scan envelope as a JSON String. Stage caps are enforced (see depth_info()).
fn scan(target: String, depth: Int?, opts: String?) -> String

// Render a scan envelope (scan() output) into a Markdown findings report:
// scope, depth & limits block first, then one section per stage, then the
// errors & notes section.
fn report(scan_json: String) -> String

// The depth ladder + per-stage caps as JSON:
// {levels: [{level, label, includes, caps}]}.
fn depth_info() -> String

// Egress posture: {proxy_configured, proxy, pacing_rps, user_agent} — proves
// the fail-closed contract before scanning.
fn probe_egress() -> String

// Module version string.
fn version() -> String
