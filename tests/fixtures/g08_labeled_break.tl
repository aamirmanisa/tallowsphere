// G08 fixture: a labeled break carries a value out of a `loop` expression.
//
// `found` is the value of the `break 'search` that leaves the loop, so the
// program prints 40 and exits 0 on both engines.
@cra_class(.default)
@legal(basis: .public_data, purpose: "G08 conformance fixture: labeled break with value", personal_data: false)
@persona(id: "g08-labeled-break", cover_class: .researcher, compartment: "conformance", fingerprint_seed: "g08-1")
@burn_plan(persona: "g08-labeled-break", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowConformance/1.0 (+https://tallow.invalid/bot)")
fn main() {
    var n: i32 = 0
    let found = 'search: loop {
        n = n + 1
        if n > 3 {
            break 'search n * 10
        }
    }
    print(found)
}
