// expected: clean
// context: full plan bundle (one persona, unique seed, burn plan, legal, class), proxy-default egress, no browser nav — must stay green after the new gates land.
// Acceptance fixture for A5.2.1 (§5 control). No new-gate expectation.

@legal(basis: .public_data, purpose: "opsec corpus: clean control", personal_data: false, jurisdiction: [.us], robots_txt: .respect, rate_limit: 1.per_second)
@cra_class(.default)
@persona(id: "control-01", cover_class: .researcher, compartment: "ctrl-1", fingerprint_seed: "ctrl-seed-4f9a")
@burn_plan(persona: "control-01", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
fn main() {
    let r = fetch("https://example.org/ok")
    print(r.text())
}
