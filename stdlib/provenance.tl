// tallow.provenance — collection-level provenance & source grading.
//
// Every fetched/crawled fact gets a sticker: where it came from, how fresh
// it is, which egress path fetched it, the HTTP outcome, a content
// fingerprint, a validation chain, a folded numeric confidence, and a final
// letter grade. Built on the same freshness/validation model as the
// Tallow provenance tracker (src/browser/provenance.rs) — those types
// are aliased, not duplicated.
//
// Capitalized namespace:   Provenance.record(...)  /  Provenance.grade(...)
// Lowercase alias:         provenance.record(...)  /  provenance.grade(...)
// (both resolve to the same module; interpreter normalizes the case)
//
// Typical flow:
//   let rec = Provenance.record(
//       "https://example.com/prices",   // source_url
//       "us-res-01",                    // egress_label
//       "residential",                  // egress_tier
//       200,                            // status_code
//       Provenance.hash_body(body))     // body_hash (sha256 hex)
//   rec = Provenance.add_validator(rec, "html_parse", true, 0.05, "parsed ok")
//   rec = Provenance.grade(rec)         // folds confidence, assigns A..F
//   print(rec.grade)                    // "A"
//   print(rec.confidence)
//   let json = Provenance.to_json(rec)  // durable roundtrip
//   let copy = Provenance.from_json(json)
//   rec = rec.grade()                   // method form works too

struct ValidationStep {
    validator: String,
    passed: Bool,
    adjustment: Float,
    note: String?,
}

struct CollectionRecord {
    source_url: String,
    fetched_at: Int,      // unix epoch seconds
    egress_label: String, // e.g. "pool-us-res-01"
    egress_tier: String,  // residential | mobile | datacenter | proxy | tor | ...
    status_code: Int,     // HTTP status; 0 = no response
    body_hash: String,    // sha256 hex of the fetched body
    confidence: Float,    // base before grade(), folded after grade()
    grade: String,        // A/B/C/D/F after grade(), "" before
}

/// Create a record. fetched_at defaults to now; base confidence defaults
/// to 0.8. Optional trailing args: fetched_at (Int), base_confidence (Float).
native fn record(source_url: String, egress_label: String, egress_tier: String, status_code: Int, body_hash: String) -> CollectionRecord

/// Create a record with an explicit fetch timestamp (unix epoch seconds).
native fn record_at(source_url: String, egress_label: String, egress_tier: String, status_code: Int, body_hash: String, fetched_at: Int) -> CollectionRecord

/// Append a validation step (passed adds |adjustment|, failed subtracts it).
native fn add_validator(rec: CollectionRecord, validator: String, passed: Bool, adjustment: Float, note: String?) -> CollectionRecord

/// Recompute confidence over the validator chain and assign the letter
/// grade. Rubric: 200 = A, other 2xx = B, 3xx = C, 4xx = D, 5xx/none = F;
/// downgraded by egress tier (datacenter/proxy −1, tor −2), confidence
/// (< 0.7 −1, < 0.5 −2) and freshness (Stale −1, Old −2).
native fn grade(rec: CollectionRecord) -> CollectionRecord

/// Freshness label of a record: "Fresh" | "Recent" | "Stale" | "Old"
/// (cutoffs < 15 min, < 6 h, < 24 h — same bands as the browser model).
native fn freshness(rec: CollectionRecord) -> String

/// sha256 hex fingerprint of a fetched body (64 lowercase hex chars).
native fn hash_body(body: String) -> String

/// Serialize a record (incl. validators) to durable JSON.
native fn to_json(rec: CollectionRecord) -> String

/// Parse a record back from the JSON produced by to_json().
native fn from_json(json: String) -> CollectionRecord
