// ORACLE — crypto and exposure desk, running on real stdlib calls.
//
// The desk inventories the TLS posture the engine can present, grades the
// inventory as evidence, and refuses to publish an exposure ranking when the
// inventory itself is too thin to rank. Nothing here is mocked: the profile list
// comes from `TLSProfile.list()`, the hash from `provenance.hash_body`, the grade
// from the module's own validators.
//
// Run: tallow run examples/directorate/oracle.tl
//
// What it does NOT do: decide which exposure matters. That is a judgement for
// the analyst; the desk produces the graded record it is judged on.

@cra_class(.default)
@legal(
    basis:         .public_data,
    purpose:       "inventory the TLS postures this engine can present and grade the inventory",
    personal_data: false
)
fn main() {
    let profiles = TLSProfile.list()

    // The inventory is a document: hash the exact rendering so a replay can tell
    // whether the list changed, without trusting the list's own claim.
    var rendered = ""
    var weak = 0
    for p in profiles {
        rendered = rendered + p.name + ":" + p.tls_version + ":" + p.ja4 + "\n"
        if p.tls_version == "1.0" || p.tls_version == "1.1" {
            weak = weak + 1
        }
    }

    let digest = provenance.hash_body(rendered)
    let rec = provenance.record(
        "tallow://tls_profile/list",
        "local",
        "local",
        200,
        digest
    )

    // Two validators that can disagree: a modern floor is worth more than a
    // long list of profiles.
    let floor = provenance.add_validator(rec, "tls_floor", weak == 0, 0.40, "no TLS 1.0/1.1 profiles")
    let breadth = provenance.add_validator(floor, "breadth", profiles.len() >= 4, 0.20, "at least four profiles")
    let graded = provenance.grade(breadth)

    print("profiles=" + profiles.len().to_string())
    print("weak=" + weak.to_string())
    print("grade=" + graded.grade)
    print("hash=" + graded.body_hash)

    // Refusal branch: an exposure ranking computed from fewer than two profiles
    // ranks nothing — it would be a claim dressed as an analysis.
    if profiles.len() < 2 {
        print("held: inventory too thin to rank")
        return
    }
    if graded.grade == "D" || graded.grade == "F" {
        print("held: grade below dissemination threshold")
        return
    }

    print("ranking=modern-first; weak_profiles=" + weak.to_string())
}

// The task-graph fragment this desk contributes. The ids are the ones
// `directorate.tl` plans; keeping them here means a desk change that renames a
// task is visible in the same file as the desk.
fn fragment() -> String {
    return "oracle.inventory_crypto,oracle.exposure_model,oracle.migration_order"
}
