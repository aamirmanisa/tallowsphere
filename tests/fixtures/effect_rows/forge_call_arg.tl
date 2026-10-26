// G01 P0.2 / audit F-7: call arguments are slots.
//
// The caller here legitimately holds `scope.grant(Net)` (it is `main`, and the
// grant is in scope before the call), so E0142 cannot be what refuses this:
// the refusal is that `7` is passed into `scan`'s `Grant<Net>` parameter.
@legal(basis: .public_data, purpose: "effect row fixture: call-argument forgery")
fn scan(g: Grant<Net>, h: String) with Net(connect) {
    net.connect(h)
}

@legal(
    basis: .public_data,
    purpose: "effect row fixture: call-argument forgery",
    personal_data: false,
    rate_limit: 2.per_second
)
@cra_class(.default)
@persona(id: "forge-arg", cover_class: .researcher, compartment: "effect-rows", fingerprint_seed: "forge-arg-1")
@burn_plan(persona: "forge-arg", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowGrantFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net(connect) {
    let g = scope.grant(Net)
    scan(7, "example.com")
}
