// msales_surface.tl — status-level surface probe of Modisoft's internal-API candidates.
//
// Question: does Modisoft run an internal per-store SALES API that is separate from cartzie?
// This does GET-only status/health checks on publicly-resolving hosts; NO data routes are
// called, no store identifiers are used, nothing is enumerated beyond the two
// self-published spec files' meta head.
//
// Run: ./target/debug/tallow run examples/msales_surface.tl

@legal(
    basis: .public_data,
    purpose: "status-level surface probe of public API hosts (health/spec meta only)",
    personal_data: false,
    rate_limit: 2.per_second
)
fn main() {
    let urls = [
        "https://io-df-api-prod.modisoft.com/health",
        "https://io-df-api-dev.modisoft.com/health",
        "https://io-df-api-prod.modisoft.com/openapi.json",
        "https://insights.modisoft.com/health",
        "https://insights1.modisoft.com/",
        "https://insights2.modisoft.com/",
        "https://insights1n.modisoft.com/health",
        "https://clsapiprodback1n.modisoft.com/health",
        "https://mposapiprodback1n.modisoft.com/health",
        "https://365.modisoft.com/"
    ]
    for u in urls {
        let r = http.get(u)
        print("URL " + u)
        print("STATUS " + r.status.to_string() + " LEN " + r.body.len().to_string())
        if r.body.len() > 400 {
            print("HEAD " + r.body.substring(0, 400))
        } else {
            print("HEAD " + r.body)
        }
        print("---")
    }
    print("SURFACE_DONE")
}
