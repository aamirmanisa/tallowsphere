// msurface_one.tl — single-URL status probe (env MSURL). One invocation per URL so an
// unreachable host (Err) aborts only its own run, not the batch.
//
// Run: MSURL=https://host/path ./target/debug/tallow run examples/msurface_one.tl

@legal(
    basis: .public_data,
    purpose: "status-level surface probe of a public API host",
    personal_data: false,
    rate_limit: 2.per_second
)
fn main() {
    let u = env.get("MSURL")
    print("URL " + u)
    let r = http.get(u)
    print("STATUS " + r.status.to_string())
}
