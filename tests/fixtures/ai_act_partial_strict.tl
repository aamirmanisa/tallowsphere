// Fixture: EU AI Act PARTIAL case — Art.12 satisfied (AiInferenceLog), Annex IV
// provenance missing ⇒ 4/5 checks, PARTIAL. Default audit exits 0; `--strict`
// must escalate to exit 2 (cycle-02/08 §b).
@legal(basis: .public_data, purpose: "ai inference record-keeping")
fn infer(prompt: String) -> String {
    let log = AiInferenceLog.new(prompt)
    print(log)
    prompt
}

fn main() {
    print(infer("hello"))
}
