// expected: E5003
// context: persona p-7 is burned for disposal, then reused by run_two; both fns also share one fingerprint seed literal (reuse, no rotation).
// Acceptance fixture for A5.2.1 (§2 E5003). Not expected to pass current gates.

@legal(basis: .public_data, purpose: "opsec corpus: persona/fingerprint reuse fixture", personal_data: false)
@cra_class(.default)
@burn_plan(persona: "p-7", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
fn main() {
    run_one()
    run_two()
}

@persona(id: "p-7", cover_class: .engineer, compartment: "lab-c", fingerprint_seed: "seed-abc123")
fn run_one() {
    let r = fetch("https://example.org/one")
    print(r.text())
}

// reuse of the burned id, and of the same seed under a second identity
@persona(id: "p-7", cover_class: .engineer, compartment: "lab-c", fingerprint_seed: "seed-abc123")
fn run_two() {
    let r = fetch("https://example.org/two")
    print(r.text())
}
