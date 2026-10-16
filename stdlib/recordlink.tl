// tallow.recordlink — record linkage / entity resolution primitives.
//
// Offline scoring for deciding whether two records (names + optional
// US-format addresses) refer to the same real-world entity. All functions
// are pure and deterministic — no network access. Pair with tallow.geocode
// for address parsing and tallow.sourcegrade for provenance.

struct MatchResult {
    name_score: Float,
    addr_score: Float,
    combined: Float,
    verdict: String,
    best_signal: String,
}

/// Canonical name: lowercase, punctuation stripped, whitespace collapsed.
native fn normalize_name(s: String) -> String

/// Sorted unique token set — permutation-invariant name key.
native fn name_key(s: String) -> String

/// Jaro similarity in [0,1].
native fn jaro(a: String, b: String) -> Float

/// Jaro–Winkler similarity in [0,1] (prefix boost).
native fn jaro_winkler(a: String, b: String) -> Float

/// Token-set similarity in [0,1] (reorder / partial-overlap tolerant).
native fn token_set(a: String, b: String) -> Float

/// Jaccard index over token sets in [0,1].
native fn jaccard(a: String, b: String) -> Float

/// 4-character Soundex code ("Miller" -> "M460").
native fn soundex(s: String) -> String

/// Coarse blocking key: Soundex(first name token) + ZIP5 of address.
native fn block_key(name: String, address: String) -> String

/// Normalized exact-equality test for names.
native fn exact(a: String, b: String) -> Bool

/// Best name similarity in [0,1]: max(Jaro–Winkler, token-set).
native fn name_similarity(a: String, b: String) -> Float

/// Address similarity in [0,1] over canonical street forms.
native fn address_similarity(a: String, b: String) -> Float

/// Full pairwise record score. Verdicts: match / probable / possible / weak / no.
native fn score(name_a: String, addr_a: String, name_b: String, addr_b: String) -> MatchResult
