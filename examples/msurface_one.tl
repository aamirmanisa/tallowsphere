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
@cra_class(.default)
@persona(id: "msurface-one", cover_class: .researcher, compartment: "msurface", fingerprint_seed: "msurface-1020")
@burn_plan(persona: "msurface-one", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowMSurface/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    let u = env.get("MSURL")
    print("URL " + u)
    let r = http.get(u)
    print("STATUS " + r.status.to_string())
}
