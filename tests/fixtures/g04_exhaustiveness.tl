// G04 fixture: two non-exhaustive matches, one over a user enum and one over
// `Result`. Each must be reported at the match, naming the variant no arm
// handles (`Retired`, `Err`). A wildcard arm silences the report; there is
// none here on purpose.
enum Status {
    Active,
    Paused,
    Retired,
}

fn describe(s: Status) -> String {
    s match {
        Active -> "active"
        Paused -> "paused"
    }
}

fn name_of(r: Result<String>) -> String {
    r match {
        Ok(v) -> v
    }
}

@cra_class(.default)
@legal(basis: .public_data, purpose: "G04 conformance fixture: exhaustiveness diagnostics", personal_data: false)
@persona(id: "g04-exhaustiveness", cover_class: .researcher, compartment: "conformance", fingerprint_seed: "g04-1")
@burn_plan(persona: "g04-exhaustiveness", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowConformance/1.0 (+https://tallow.invalid/bot)")
fn main() {
    print(describe(Status.Active))
    print(name_of(Ok("x")))
}
