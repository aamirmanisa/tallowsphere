// SENTINEL — one desk, running on real stdlib calls.
//
// This is the smallest honest demonstration of a desk: it turns a collection into
// a graded evidence record using `provenance`, then refuses to emit a finding
// whose grade is below the dissemination threshold. Nothing here is mocked — the
// hash is sha256 over the body, the grade is computed by the module's own
// validators, and the refusal path is a real branch.
//
// Run: tallow run examples/directorate/sentinel.tl
//
// What it does NOT do: decide what the evidence means. That is the `llm`-class
// task in the directorate graph, recorded in the journal when a model is attached.

@legal(
    basis:         .public_data,
    purpose:       "grade a collected artifact before it can be disseminated",
    personal_data: false,
    robots_txt:    .respect
)
fn main() {
    // A collected page. In production this arrives from `http`/`browser`; the
    // fixture keeps the desk runnable without network egress.
    let body = "<html><title>Quarterly advisory</title><p>Observed: 203.0.113.9</p></html>"

    let digest = provenance.hash_body(body)

    // One record per fetch: URL, plane, status, content hash, and when.
    // egress_level is stated because a claim about an anonymous plane must name it.
    let rec = provenance.record(
        "https://example.invalid/advisory/2026-q4",
        "tor-exit",
        "tor",
        200,
        digest
    )

    // Two independent validators, deliberately disagreeing on weight: TLS posture
    // contributes less than cross-source corroboration would.
    let checked = provenance.add_validator(rec, "tls", true, 0.10, "TLS 1.3, valid chain")
    let graded  = provenance.grade(checked)
    let fresh   = provenance.freshness(graded)

    print(graded.grade)
    print(fresh)
    print(graded.body_hash)

    // Dissemination gate: a D or F artifact may be retained but not published —
    // ICD 206's point is that the reader must be able to judge the source, so an
    // artifact that cannot be graded honestly does not leave the desk.
    if graded.grade == "D" || graded.grade == "F" {
        print("held: grade below dissemination threshold")
        return
    }

    print(provenance.to_json(graded))
}
