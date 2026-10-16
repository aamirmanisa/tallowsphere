// expected: E5002
// context: production fetch path reads TALLOW_ALLOW_DIRECT and branches on it — the operator opt-out must never be a program affordance.
// Acceptance fixture for A5.2.1 (§2 E5002). Not expected to pass current gates.

@legal(basis: .public_data, purpose: "opsec corpus: direct-egress opt-out misuse fixture", personal_data: false)
@cra_class(.default)
fn main() {
    let mode = env.get("TALLOW_ALLOW_DIRECT")
    if mode == "1" {
        print("direct egress requested by program logic (must be E5002)")
    }
    let r = fetch("https://example.org/probe")
    print(r.text())
}
