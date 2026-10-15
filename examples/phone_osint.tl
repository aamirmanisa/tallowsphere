// phone_osint.tl — end-to-end demo of all nine PhoneNumber.* stdlib dispatches.
// Sample number: 512-850-1815 (a NANP block seeded in the demo NPA-NXX dataset:
// rate center AUSTIN, TX, as-allocated to T-MOBILE USA, INC., wireless).
//
// Honest framing throughout: the owner name, current carrier (Tier C, needs an
// LRN/NPAC dip) and displayed caller-ID name (Tier D, needs a CNAM/LIDB dip) are
// NEVER guessed. Absent an authorized provider key they are reported as
// "unknown" and the gating status is surfaced.
//
// Run:  tallow run examples/phone_osint.tl

fn main() {
    let number = "512-850-1815"

    // ── 1. PhoneNumber.lookup ─────────────────────────────────────────────
    // P0 offline NANP/carrier truth layer. Parses the number and derives the
    // public "as-allocated" facts (state, rate center, CLLI, lat/lon, tz, OCN,
    // as-allocated carrier, line type) plus a provenance block. `current_carrier`
    // is honest: "unknown-needs-lrn-dip" until a Tier-C LRN dip is made.
    print("=== 1. PhoneNumber.lookup ===")
    let entity = PhoneNumber.lookup(number)
    print(entity)

    // ── 2. PhoneNumber.resolve_owner ──────────────────────────────────────
    // Aggregates owner-name evidence into a tiered attribution. Two independent
    // register sources (county deed + SOS filing) that agree on the normalized
    // name cross the >=2 independent register threshold => Documented. The
    // evidence tier + confidence + corroborating sources are returned, never a
    // bare guessed name.
    print("\n=== 2. PhoneNumber.resolve_owner ===")
    let evidence = [
        { "name": "JANE DOE", "source": "county deed", "source_url": "https://deeds.example/123", "source_class": "register", "observed_at": "2026-09-01" },
        { "name": "Jane Doe", "source": "SOS business filing", "source_url": "https://sos.example/abc", "source_class": "register", "observed_at": "2026-09-02" },
    ]
    let owner = PhoneNumber.resolve_owner(evidence)
    print(owner)

    // ── 3. PhoneNumber.reputation ─────────────────────────────────────────
    // Transparent recency-decayed spam reputation from aggregated signals.
    // source_bits is a bitmask: 1=USER_LABEL, 2=CONSENTED_CONTACT, 4=FCC_COMPLAINT,
    // 8=AG_COMPLAINT, 16=DNC_FLAG, 32=PUBLIC_BLOCKLIST. Two independent sources
    // above threshold => "confirmed"; a single source is only "suspected".
    print("\n=== 3. PhoneNumber.reputation ===")
    let signal = {
        "reports": 30,
        "category": "robocall",
        "source_bits": 5,            // USER_LABEL + FCC_COMPLAINT
        "verified_business": false,
        "report_entropy": 0.2,
        "last_seen": 0,
        "now": 0,
    }
    let reputation = PhoneNumber.reputation(signal)
    print(reputation)

    // ── 4. PhoneNumber.diff ───────────────────────────────────────────────
    // Diffs two field->value snapshots (before/after) and returns ONLY the
    // changed fields as a ChangeAlert — a precise, provenance-style alert. Here
    // carrier and spam_score change while line_type stays stable.
    print("\n=== 4. PhoneNumber.diff ===")
    let before = { "carrier": "T-MOBILE", "line_type": "wireless", "spam_score": "0.20" }
    let after  = { "carrier": "VERIZON",  "line_type": "wireless", "spam_score": "0.85" }
    let change_alert = PhoneNumber.diff(before, after)
    print(change_alert)

    // ── 5. PhoneNumber.linkage ────────────────────────────────────────────
    // Builds a multi-hop entity subgraph from confirmed-tie evidence (each tie
    // is a phone/email/etc. co-occurrence in ONE public registry row). The
    // composite-confidence rubric refuses a strong identity link without >=2
    // Very-High (phone/email) discriminators. The optional 2nd arg lists E.164
    // opt-outs from the do-not-index register — those ties are filtered out.
    print("\n=== 5. PhoneNumber.linkage ===")
    let ties = [
        { "from": "+15128501815", "to": "jane@example.com",  "relation": "email",  "source_url": "https://sos.example/1", "row_context": "SOS filing" },
        { "from": "+15128501815", "to": "+16095550100",      "relation": "person", "source_url": "https://990.example/2", "row_context": "990 officer block" },
        { "from": "+15128501815", "to": "JANE DOE",          "relation": "person", "source_url": "https://tag.example/3", "row_context": "community tag" },
    ]
    let opt_out = ["+16095550100", "+15128501815"]   // do-not-index register
    let subgraph = PhoneNumber.linkage(ties, opt_out)
    print(subgraph)

    // ── 6. PhoneNumber.mitigation ─────────────────────────────────────────
    // Resolves the number's as-allocated carrier, then looks up that carrier's
    // certification in the FCC Robocall Mitigation Database (RMDB). Keyed by
    // carrier, not phone — a public mitigation posture, never a verdict on the
    // individual number or subscriber.
    print("\n=== 6. PhoneNumber.mitigation ===")
    let mitigation = PhoneNumber.mitigation(number)
    print(mitigation)

    // ── 7. PhoneNumber.to_stix ────────────────────────────────────────────
    // Emits a STIX 2.1 bundle with a custom phone observable (x-tallow-phone-number)
    // carrying the E.164 value plus derived allocation fields and an `x-` metadata
    // block. Returns the JSON string for analyst-tool interop. Optional 2nd arg is
    // the entitlement/purpose label recorded in the object's metadata.
    print("\n=== 7. PhoneNumber.to_stix ===")
    let bundle_json = PhoneNumber.to_stix(number, "research")
    print(bundle_json)

    // ── 8. PhoneNumber.lrn_carrier ────────────────────────────────────────
    // Tier C current-carrier/ported dip. NOT public; needs an authorized
    // NPAC/LRN provider. Reads TALLOW_LRN_API_KEY: absent => NotConfigured with a
    // hint and current_carrier "unknown" (never guessed); present => Authorized
    // (the provider would be called to resolve current carrier).
    print("\n=== 8. PhoneNumber.lrn_carrier ===")
    let lrn = PhoneNumber.lrn_carrier(number)
    print(lrn)

    // ── 9. PhoneNumber.cnam_name ──────────────────────────────────────────
    // Tier D displayed caller-ID name dip. ALSO not public; needs a
    // carrier-authorized CNAM/LIDB provider. Reads TALLOW_CNAM_API_KEY: absent =>
    // NotConfigured with displayed_name "unknown" (and a hint that wireless CNAM
    // is often absent anyway); present => Authorized (provider call resolves it).
    print("\n=== 9. PhoneNumber.cnam_name ===")
    let cnam = PhoneNumber.cnam_name(number)
    print(cnam)
}
