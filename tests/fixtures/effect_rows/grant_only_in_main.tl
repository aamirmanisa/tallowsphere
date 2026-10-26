// G01 P0.2 negative fixture (E0144): `helper` declares the row *and* mints its
// own capability, so before E0144 it satisfied both halves of the rule — row
// declared, grant in scope — while never being handed any authority. That is
// the hole: `Grant<Net>` was decorative because any body could print one.
//
// `main` below is the legitimate trust root and keeps its exemption; the
// finding is the grant in `helper`, reported at line 10.
@legal(basis: .public_data, purpose: "probe")
fn helper(h: String) with Net(connect) {
    let g = scope.grant(Net)
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
    net.connect("example.com")
}
