// Fixture: EU AI Act FAIL case (cycle-02/08 §b test list) — a prohibited-risk
// system. `tallow audit --ai-act` must exit 2.
@ai_system(risk: .prohibited)
fn social_scoring(subject_id: String) -> i64 {
    let _ = subject_id
    0
}

fn main() {
    let score = social_scoring("subject-1")
    print("score: {score}")
}
