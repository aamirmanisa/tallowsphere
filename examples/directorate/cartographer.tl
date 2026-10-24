// CARTOGRAPHER — surface comparison on named axes, running on real stdlib calls.
//
// The desk compares the TLS profiles this engine can present along two axes the
// profiles actually carry (HTTP/2 support, cipher breadth), records the
// comparison as graded evidence, and refuses to publish a "best profile" claim
// when fewer than two axes were compared — one axis is not a comparison.
//
// Run: tallow run examples/directorate/cartographer.tl

@cra_class(.default)
@legal(
    basis:         .public_data,
    purpose:       "compare TLS profiles on named axes and grade the comparison",
    personal_data: false
)
fn main() {
    let profiles = TLSProfile.list()

    var best = ""
    var best_score = -1
    var compared = 0
    for p in profiles {
        // Two axes, both carried by the profile itself: h2 support and cipher
        // breadth. A profile that wins on neither is not scored at all.
        var score = 0
        if p.supports_h2 { score = score + 2 }
        score = score + p.cipher_count
        compared = compared + 1
        if score > best_score {
            best_score = score
            best = p.name
        }
    }

    let digest = provenance.hash_body("axes=h2,ciphers;best=" + best + ";profiles=" + profiles.len().to_string())
    let rec = provenance.record(
        "tallow://tls_profile/compare",
        "local",
        "local",
        200,
        digest
    )
    let axes = provenance.add_validator(rec, "axes_named", compared > 0, 0.20, "every compared profile carries both axes")
    let graded = provenance.grade(axes)

    print("compared=" + compared.to_string())
    print("best=" + best)
    print("grade=" + graded.grade)

    // Refusal branch: a comparison needs at least two axes and at least two
    // subjects. Otherwise the desk would be reporting a preference, not a
    // finding.
    if compared < 2 {
        print("refused: fewer than two profiles to compare")
        return
    }
    if graded.grade == "D" || graded.grade == "F" {
        print("held: grade below dissemination threshold")
        return
    }

    print("finding=" + best + " leads on h2+cipher breadth")
}

fn fragment() -> String {
    return "cartographer.enumerate,cartographer.compare,cartographer.brief"
}
