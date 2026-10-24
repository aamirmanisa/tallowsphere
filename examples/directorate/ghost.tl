// GHOST — data classification and plane choice, running on real stdlib calls.
//
// The desk decides which egress plane a piece of data may ride, and refuses the
// combination that no policy allows: private data on a plane that is not
// anonymous. The decision is a table, not a model's opinion, and the record it
// writes names the plane it claims.
//
// Run: tallow run examples/directorate/ghost.tl

@cra_class(.default)
@legal(
    basis:         .public_data,
    purpose:       "classify an artifact and choose an egress plane permitted for that class",
    personal_data: false
)
fn main() {
    // A classified artifact. `data_class` is the desk's input, not its opinion.
    let data_class = "private"
    let body = "customer_email=analyst@example.invalid; note=follow-up"

    let digest = provenance.hash_body(body)

    // Plane choice: private data may only leave over an anonymous plane; public
    // data may ride either, and the record says which it rode.
    var plane = "direct"
    var anonymous = false
    if data_class == "private" {
        plane = "tor-exit"
        anonymous = true
    }

    let rec = provenance.record(
        "tallow://ghost/plane-choice",
        plane,
        if anonymous { "tor" } else { "direct" },
        200,
        digest
    )
    let policy = provenance.add_validator(rec, "plane_policy", true, 0.30, "class/plane pair permitted")
    let graded = provenance.grade(policy)

    print("class=" + data_class)
    print("plane=" + plane)
    print("anonymous=" + anonymous.to_string())
    print("grade=" + graded.grade)

    // Refusal branch: private data on a plane that does not anonymise it is not
    // a trade-off to weigh, it is a leak. The desk stops.
    if data_class == "private" && !anonymous {
        print("refused: private data cannot ride a non-anonymous plane")
        return
    }

    // Second refusal: an artifact that cannot be graded honestly does not leave.
    if graded.grade == "D" || graded.grade == "F" {
        print("held: grade below dissemination threshold")
        return
    }

    print("emit=permitted")
}

fn fragment() -> String {
    return "ghost.classify_data,ghost.plane_choice"
}
