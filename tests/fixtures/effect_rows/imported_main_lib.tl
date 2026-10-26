// Library module for the E0147 fixture (audit F-11).
//
// Import resolution merges this file's items into the entry program, so this
// `main` used to inherit the trust-root exemption: it could originate authority
// with `scope.grant` even though it is a library item nobody invoked. A trust
// root is an item in the file the compiler was invoked on, not a spelling.
@legal(
    basis: .public_data,
    purpose: "trust root fixture",
    personal_data: false,
    rate_limit: 2.per_second
)
@cra_class(.default)
@persona(id: "lib", cover_class: .researcher, compartment: "lib", fingerprint_seed: "lib-1")
@burn_plan(persona: "lib", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "Fixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net(connect) {
    let g = scope.grant(Net)
    net.connect("example.com")
}

@legal(basis: .public_data, purpose: "trust root fixture")
fn library_helper() {
    print("lib")
}
