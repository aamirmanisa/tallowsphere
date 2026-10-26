// G01 P0.2: `main` is the trust root. It originates authority from the runtime
// scope registry (`scope.grant`, which reads the same deny-by-default register
// `src/scope.rs` uses) instead of receiving it from a caller, so it needs no
// incoming grant. That exemption is not a hole: a network-touching `main` is
// already gated by the plan annotations below (`@legal`, `@cra_class`,
// `@persona`, `@burn_plan`, `@fingerprint_policy`), which is what makes it the
// only place authority can legitimately originate.
@legal(
    basis: .public_data,
    purpose: "effect row fixture: the trust root grants itself",
    personal_data: false,
    rate_limit: 2.per_second
)
@cra_class(.default)
@persona(id: "grant-fixture", cover_class: .researcher, compartment: "effect-rows", fingerprint_seed: "grant-fixture-1")
@burn_plan(persona: "grant-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowGrantFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net(connect) {
    let g = scope.grant(Net)
    // `host:port` — net.connect takes a socket address; the portless spelling
    // was never reachable because this fixture used to die at `scope.grant`.
    net.connect("example.com:443")
}
