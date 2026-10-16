// tallow.sourcegrade — source grading / provenance.
//
// Offline evidentiary-weight scoring for research pipelines: an A–F
// institutional grade derived from a static trusted-domain registry plus
// TLD policy, numeric confidence combining corroboration and contradiction
// counts, epoch timestamps, and citation formatting so every claim can
// carry a provenance sticker. No network access.

struct SourceGrade {
    grade: String,
    host: String,
    confidence: Float,
    rationale: String,
    ts_ms: Int,
}

/// Grade a host (A–F) with confidence and a rationale string.
/// A: official gov/treaty orgs  B: established wires/flagships/.edu
/// C: unlisted .org  D: unlisted commercial  E: junk TLDs  F: watchlist.
native fn grade(host: String) -> SourceGrade

/// Numeric confidence in [0,1] from an A–F grade plus independent
/// corroborating signals and contradictions.
native fn confidence(grade: String, signals: Int, contradictions: Int) -> Float

/// Current Unix epoch time in milliseconds.
native fn timestamp_ms() -> Int

/// Civil date "YYYY-MM-DD" from Unix epoch milliseconds.
native fn date_from_ms(ms: Int) -> String

/// Format a citation: "Title. URL. Accessed YYYY-MM-DD." Optional 4th
/// argument appends "[source grade: X]".
native fn citation(title: String, url: String, accessed_ms: Int, grade: String?) -> String
