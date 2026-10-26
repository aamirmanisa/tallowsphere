// G01 P0.3 runtime half: the trust root mints authority and the program runs.
// Loopback only — the port is opened by tests/scope_grant_runtime.rs, so this
// proves the producer exists without any external egress.
@legal(
    basis: .public_data,
    purpose: "effect row fixture: the trust root grants itself over loopback",
    personal_data: false,
    rate_limit: 2.per_second
)
@cra_class(.default)
@persona(id: "grant-fixture", cover_class: .researcher, compartment: "effect-rows", fingerprint_seed: "grant-fixture-1")
@burn_plan(persona: "grant-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowGrantFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net(connect) {
    let g = scope.grant(Net)
    net.connect("127.0.0.1:45991")
    print("granted")
}
