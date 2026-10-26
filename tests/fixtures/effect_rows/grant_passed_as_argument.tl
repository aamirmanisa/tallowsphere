// G01 P0.2 positive: the legitimate flow of a capability through a call.
//
// `main` is the trust root and mints the capability with `scope.grant(Net)`;
// `fetch` takes it as a parameter and declares the row for what it does. The
// argument-position check must accept the real `Grant<Net>` here — tightening
// the call slot must not break the shape every network helper has.
@legal(basis: .public_data, purpose: "effect row fixture: grant passed as argument")
fn fetch(h: String, g: Grant<Net>) with Net(connect) {
    net.connect(h)
}

@legal(
    basis: .public_data,
    purpose: "effect row fixture: grant passed as argument",
    personal_data: false,
    rate_limit: 2.per_second
)
@cra_class(.default)
@persona(id: "grant-arg", cover_class: .researcher, compartment: "effect-rows", fingerprint_seed: "grant-arg-1")
@burn_plan(persona: "grant-arg", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowGrantFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net(connect) {
    let g = scope.grant(Net)
    fetch("example.com", g)
}
