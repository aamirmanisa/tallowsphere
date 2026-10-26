// G01 P0.2 positive fixture (E0144): the shape every network helper must have.
//
// `main` is the trust root: it originates the capability with `scope.grant(Net)`.
// `fetch` never originates anything — it takes the `Grant<Net>` as a parameter
// and passes it on, and it declares the row for what it does. Authority flows
// through values, so the set reaching a socket is visible in the signatures.
@legal(basis: .public_data, purpose: "effect row fixture: grant threaded from main")
fn fetch(g: Grant<Net>, h: String) with Net(connect) {
    net.connect(h)
}

@legal(
    basis: .public_data,
    purpose: "effect row fixture: authority may only be originated in main",
    personal_data: false,
    rate_limit: 2.per_second
)
@cra_class(.default)
@persona(id: "grant-fixture", cover_class: .researcher, compartment: "effect-rows", fingerprint_seed: "grant-fixture-1")
@burn_plan(persona: "grant-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowGrantFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net(connect) {
    let g = scope.grant(Net)
    fetch(g, "example.com")
}
