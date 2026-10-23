// tallow.entity — general entity resolution / record linkage.
//
// Offline, deterministic clustering of records (stores, companies,
// operators, people) across independent sources: "is the operator of
// store A the same as company B?" Blocking keys and per-field similarity
// reuse tallow.recordlink's normalization / Soundex / Jaro-Winkler /
// token-set primitives. Resolution is deliberately conservative
// (high precision; false negatives preferred over false merges) and every
// threshold is an explicit argument.
//
// Candidate records are structs/maps with identity fields; the default
// field names are id / name / address / phone / email / domain and can be
// overridden per call via the optional `keys` argument. Both spellings of
// every function are equivalent: the documented capital `Entity.*`
// namespace and the lowercase `entity.*` alias route to the same native
// implementation.
//
// Determinism: records are ordered by record id before clustering, so
// canonical members, cluster ids (cl-0001, cl-0002, ...) and scores are
// stable across runs and input orders. Prefix ids with their source
// (e.g. "txabc:123", "sos:456") when merging across registries.

struct PairScore {
    verdict: String,
    reason: String,
    combined: Float,
    name: Float,
    address: Float,
    phone: Float,
    email: Float,
    domain: Float,
}

struct EntityMember {
    cluster_id: String,
    record_id: String,
    name: String,
    score: Float,
    // Optional per-member provenance: passed through verbatim when the
    // source record carried a `provenance` field, nil otherwise. The
    // tallow.provenance module (roadmap #2) can populate this later.
    provenance: Map?,
}

struct EntityEvidence {
    record_id: String,
    compared_to: String,
    field: String,
    similarity: Float,
    note: String,
}

struct EntityCluster {
    cluster_id: String,
    canonical_id: String,
    canonical: String,
    score: Float,
    members: []EntityMember,
    evidence: []EntityEvidence,
}

// ── Clustering ────────────────────────────────────────────────────────
//
// keys (all optional, defaults shown):
//   id/name/address/phone/email/domain: String  field names on the records
//   combined_min:           Float 0.88  combined-score floor
//   exact_addr_name_min:    Float 0.72  name floor for an exact address
//   phone_name_min:         Float 0.80  name floor for an exact phone
//   phone_addr_min:         Float 0.90  address floor for an exact phone
//   email_name_min:         Float 0.50  name floor for an exact email
//   addr_contradict:        Float 0.50  address-similarity veto line
//
// Merge requires a strong identifier (exact normalized email/phone/
// address) plus name agreement, or a high combined score; disagreeing
// addresses/emails/phones veto merges unless a stronger identifier
// overrides. Returns one EntityCluster per entity — including singletons,
// which carry score 1.0 and empty evidence.

/// Cluster candidate records into entities.
native fn Entity.resolve(candidates: []Map, keys: Map?) -> []EntityCluster

/// Lowercase alias of Entity.resolve.
native fn entity.resolve(candidates: []Map, keys: Map?) -> []EntityCluster

/// Pairwise verdict (match/no) + reason + per-field similarities.
native fn Entity.pair(a: Map, b: Map, keys: Map?) -> PairScore

/// Lowercase alias of Entity.pair.
native fn entity.pair(a: Map, b: Map, keys: Map?) -> PairScore

// ── Blocking keys ─────────────────────────────────────────────────────
// Coarse keys for bucketing candidates before pairwise scoring. All are
// deterministic, offline, and case/punctuation-insensitive.

/// Canonical name key: sorted unique lowercase tokens (permutation-invariant).
native fn Entity.name_key(s: String) -> String

/// Lowercase alias.
native fn entity.name_key(s: String) -> String

/// Clean host ("WWW.Acme-shop-77.example:443/x" -> "acme-shop-77.example").
native fn Entity.domain_key(s: String) -> String

/// Lowercase alias.
native fn entity.domain_key(s: String) -> String

/// Canonical street form ("123 Main St #4" -> "123 main street apt 4").
native fn Entity.address_key(s: String) -> String

/// Lowercase alias.
native fn entity.address_key(s: String) -> String

/// Digit-only phone ("(512) 555-0142" == "512-555-0142" == "+1 512 555 0142").
native fn Entity.phone_key(s: String) -> String

/// Lowercase alias.
native fn entity.phone_key(s: String) -> String

/// Lowercased email (mailto: stripped, case-insensitive).
native fn Entity.email_key(s: String) -> String

/// Lowercase alias.
native fn entity.email_key(s: String) -> String

/// Soundex(first name token) + ZIP5 compound key for a whole record
/// (delegates to recordlink.block_key). Over-inclusive by design; pair
/// scoring restores precision.
native fn Entity.block_key(record: Map) -> String

/// Lowercase alias.
native fn entity.block_key(record: Map) -> String

// ── Field similarity (built on recordlink Jaro-Winkler / token-set) ──

/// Name similarity in [0,1]: max(Jaro-Winkler, token-set), normalized.
native fn Entity.name_similarity(a: String, b: String) -> Float

/// Lowercase alias.
native fn entity.name_similarity(a: String, b: String) -> Float

/// Address similarity in [0,1] over canonical street forms.
native fn Entity.address_similarity(a: String, b: String) -> Float

/// Lowercase alias.
native fn entity.address_similarity(a: String, b: String) -> Float

/// Phone similarity in [0,1] over digit keys (blank-vs-blank = 0.5 neutral).
native fn Entity.phone_similarity(a: String, b: String) -> Float

/// Lowercase alias.
native fn entity.phone_similarity(a: String, b: String) -> Float

/// Email similarity in [0,1] (equality is the strong signal).
native fn Entity.email_similarity(a: String, b: String) -> Float

/// Lowercase alias.
native fn entity.email_similarity(a: String, b: String) -> Float

/// Domain similarity in [0,1] (subdomain relation scores 0.9).
native fn Entity.domain_similarity(a: String, b: String) -> Float

/// Lowercase alias.
native fn entity.domain_similarity(a: String, b: String) -> Float

/// Dispatch by field kind: name | address | phone | email | domain.
/// Unknown kinds are a hard error, never a fabricated score.
native fn Entity.similarity(kind: String, a: String, b: String) -> Float

/// Lowercase alias.
native fn entity.similarity(kind: String, a: String, b: String) -> Float
