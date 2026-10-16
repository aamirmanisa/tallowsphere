// Fixture: EU AI Act pass case — all five checks satisfied.
// Art.12 needs an AiInferenceLog mention; Annex IV needs ModelProvenance.
@legal(basis: .public_data, purpose: "ai transparency evidence")
fn infer(prompt: String) -> String {
    let log = AiInferenceLog.new(prompt)
    let provenance = ModelProvenance.new("model-v1")
    print(log)
    print(provenance)
    prompt
}

fn main() {
    print(infer("hello"))
}
