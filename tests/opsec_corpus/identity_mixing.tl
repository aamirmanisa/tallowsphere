// expected: E5001
// context: two distinct personas (alex-01, morgan-02) in one program; their outputs mix in main — identity mixing across compartments.
// Acceptance fixture for A5.2.1 (§2 E5001). Not expected to pass current gates.

@legal(basis: .public_data, purpose: "opsec corpus: identity mixing acceptance fixture", personal_data: false)
@cra_class(.default)
@persona(id: "alex-01", cover_class: .journalist, compartment: "press-a")
fn collect_a() -> String {
    let r = fetch("https://example.org/a")
    r.text()
}

@persona(id: "morgan-02", cover_class: .researcher, compartment: "acad-b")
fn collect_b() -> String {
    let r = fetch("https://example.org/b")
    r.text()
}

fn main() {
    let a = collect_a()
    let b = collect_b()
    // mixed output path: both identities' material lands in one artifact
    print(a + b)
}
