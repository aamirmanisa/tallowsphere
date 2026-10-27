// tallow.ip — offline IP intelligence: ASN/prefix attribution and a
// content-addressed intel cache.
//
// Nothing here opens a socket. `load` reads a table the caller or the
// environment names; `cache_put` stores bytes the caller supplies. A caller
// that wants a fresher answer fetches it itself, under its own grant, and
// writes it here — this module is the memory, not the fetch.
//
// N33 — an ASN is either measured or unknown, never 0 by default.
//
// `load` resolves its table in a fixed order, and the resolved path travels
// back in the result so every answer can name its own provenance:
//   1. the explicit `path` argument;
//   2. `TALLOW_IP2ASN` (the variable `topology` already honours);
//   3. `/usr/share/ip2asn/ip2asn-v4.tsv`.
// A missing or unreadable file is refused with `ip:table-missing`, naming the
// path and the step that chose it. An empty file is refused with
// `ip:table-empty`. A malformed line refuses the whole load with
// `ip:table-malformed` and names `source:line` — one bad line voids the table,
// because a partially-loaded routing table silently mislabels every prefix the
// lost line covered. Blank lines and `#` comments are skipped; a single leading
// header line is tolerated.
//
// `lookup` returns the **longest** matching prefix, not the first row that
// covers the address: a `/8` listed earlier cannot shadow a `/24` listed later.
// `prefix_len` is the number of leading bits the row's range covers (the exact
// prefix length for an aligned range). When nothing covers the address the
// refusal is `ip:not-in-table` — absence is not ASN 0. IPv6 is refused with
// `ip:unsupported-family` rather than answered from a v4 table.
//
// N37 — an expiry is information, not an error.
//
// An entry is identified by `(source, key)`; its content address is
// `sha256(body)`, returned on write and read, so two reads can be proved to be
// the same bytes without comparing them. TTL is per source because it is a
// property of how fast the source changes. A read past TTL is a hit carrying
// `stale: true` and `age_ms`; a genuine absence is `ip:cache-miss`. They are
// different results and neither panics. `cache_stats` takes no clock, so it
// judges staleness against wall time.
//
// N36 — clustering is a claim about shared *ownership*, so every merge must be
// explainable.
//
// A cluster is formed from weighted evidence, not equality: `cert_sha256`
// (0.60), `favicon_hash` (0.40), `header_signature` (0.30) and `asn` (0.10),
// where a pair's score is the sum of the weights of the signals both endpoints
// share, capped at 1.0. The split between those numbers is the design: a
// certificate is minted by whoever holds the key (operator-level), a favicon
// and a header set are application- or framework-level, and an ASN names a
// *provider* — every Cloudflare-fronted site shares AS13335 — so a shared ASN
// can only ever corroborate. It sits below `link_min_score` (0.25), which means
// two hosts in one ASN with nothing else in common are not even reported as
// linked, let alone clustered.
//
// Two floors, both visible in the report. A pair below `link_min_score` is not
// evidence and is not reported. A pair at or above `link_min_score` but below
// `merge_min_score` (0.60) is reported as `linked_not_merged` — the module
// refuses to union it and says so, because an operator can argue with a
// threshold they can see and cannot audit a silent union. A pair at or above
// `merge_min_score` merges.
//
// Every cluster carries the evidence that formed it: each link names the
// signals shared and the score, and `evidence_lines` renders each one as a
// sentence. A cluster's `confidence` is the **weakest** merge edge in it, not
// an average — a chain is only as strong as its weakest link, and averaging
// would let many weak pairs outvote the strong edge that justified the union.
//
// Output is deterministic: observations are sorted by IP string, clusters by
// their first member, members and links in sorted order, so the same input
// produces byte-identical JSON every run. One address observed twice is
// refused (`ip:cluster-duplicate`) rather than silently picking a winner.
// A cluster of one is not reported — a lone endpoint has no shared evidence.
//
// Nothing here fetches anything: `cluster` is pure over the observations it is
// handed. Certificates, favicons and headers are the caller's measurements.

// A loaded ASN table. `handle` is a process-local id, not data: it cannot be
// serialised, reconstructed, or forged into a table that was never loaded.
// `source` and `rows` are the provenance a caller needs to quote an answer.
struct IpAsnTable {
    handle: Int,
    source: String,
    rows:   Int,
}

// The longest matching entry for one address. `asn` is the ASN number
// (`64500`), not the string `AS64500`.
struct AsnMatch {
    asn:         Int,
    prefix_len:  Int,
    country:     String,
    description: String,
    source:      String,
}

// A cache handle. Process-local, like every handle here.
struct IpCache {
    handle:  Int,
    entries: Int,
}

// A cache entry as read, with its content address and its age. `stale` is
// true when `age_ms` is strictly greater than `ttl_ms`.
struct CacheEntry {
    source:       String,
    key:          String,
    content_hash: String,
    body:         String,
    stored_at_ms: Int,
    age_ms:       Int,
    ttl_ms:       Int,
    stale:        Bool,
}

// The receipt for one write: which key, which bytes, which moment.
struct CacheWritten {
    source:       String,
    key:          String,
    content_hash: String,
    stored_at_ms: Int,
    ttl_ms:       Int,
}

// `stale_entries` is judged against the wall clock, since this call takes no
// `now_ms`; use `cache_get` when the clock must be the caller's.
struct CacheStats {
    entries:       Int,
    sources:       Int,
    stale_entries: Int,
}

// Load the ASN table: explicit path, then `TALLOW_IP2ASN`, then the default
// location. Refuses (`ip:table-missing`, `ip:table-empty`, `ip:table-malformed`)
// rather than returning a table that was never read.
native fn ip.load(path: String?) -> IpAsnTable

// Preflight a path: returns false when the file exists, and the same
// `ip:table-missing` refusal when it does not — without parsing a real table.
native fn ip.load_missing(path: String) -> Bool

// Longest-prefix IPv4 lookup. Refuses `ip:not-in-table`, `ip:bad-address`,
// `ip:unsupported-family`, or `ip:table-unknown` for a handle not issued here.
native fn ip.lookup(table: IpAsnTable, ip: String) -> AsnMatch

// A fresh, empty cache.
native fn ip.cache_new() -> IpCache

// Store `body` under `(source, key)` as observed at `now_ms`. `content_hash` is
// `sha256(body)`. A negative `ttl_ms` is refused (`ip:cache-bad-ttl`).
native fn ip.cache_put(cache: IpCache, source: String, key: String, body: String, ttl_ms: Int, now_ms: Int) -> CacheWritten

// Read `(source, key)` as of `now_ms`. A hit past TTL returns with `stale: true`
// and its age; a genuine absence is `ip:cache-miss`.
native fn ip.cache_get(cache: IpCache, source: String, key: String, now_ms: Int) -> CacheEntry

// Entry, source and stale-entry counts.
native fn ip.cache_stats(cache: IpCache) -> CacheStats

// ── N36: infrastructure clustering ──────────────────────────────────────────

// One endpoint as the caller measured it. Every signal other than `ip` is
// optional and an absent signal is absent, not a sentinel: an unknown ASN is
// not ASN 0, and an unknown certificate must not match another unknown.
struct IpObservation {
    ip:               String,
    host:             String?,
    asn:              Int?,
    cert_sha256:      String?,
    favicon_hash:     String?,
    header_signature: String?,
}

// The two floors, overridable per call. Both are echoed back in the report, so
// a reader can always see which thresholds produced the answer. `link_min_score`
// must not exceed `merge_min_score`; 0 <= link <= merge <= 1 or the call is
// refused with `ip:cluster-bad-option`.
struct IpClusterOptions {
    link_min_score:  Float?,
    merge_min_score: Float?,
}

// One pair and the evidence that linked it. `signals` is a comma-separated list
// drawn from `cert_sha256`, `favicon_hash`, `header_signature`, `asn`, in that
// fixed order, and is never empty.
struct ClusterLink {
    ip_a:    String,
    ip_b:    String,
    signals: String,
    score:   Float,
}

// A group of addresses judged to share an operator. `confidence` is the weakest
// merge edge in the group, not an average. `evidence_lines` renders each link
// as a sentence, so a cluster can be justified without parsing structs.
struct IpCluster {
    members:        []String,
    size:           Int,
    confidence:     Float,
    evidence:       []ClusterLink,
    evidence_lines: []String,
}

// The weights, as used, so the numbers behind a cluster are in its output.
struct ClusterWeights {
    cert_sha256:      Float,
    favicon_hash:     Float,
    header_signature: Float,
    asn:              Float,
}

// `clusters` holds only groups of two or more. `linked_not_merged` holds every
// pair that was evidence enough to report and not enough to merge — the pairs
// the module deliberately refused to union.
struct IpClusterReport {
    clusters:           []IpCluster,
    linked_not_merged:  []ClusterLink,
    // Observations that joined no cluster: not findings, but counted, so the
    // members on show and `observation_count` can be reconciled by a reader.
    unclustered:        []String,
    observation_count:  Int,
    link_min_score:     Float,
    merge_min_score:    Float,
    weights:            ClusterWeights,
}

// Build one observation. A stdlib struct type cannot be written as a literal in
// a program (the typechecker only knows structs a program declares), so this
// constructor is the way a caller hands clustering its own measurements. An
// `asn` of 0 or less is refused (`ip:cluster-bad-observation`) — unknown is
// nil, never 0.
native fn ip.observation(ip: String, host: String?, asn: Int?, cert_sha256: String?, favicon_hash: String?, header_signature: String?) -> IpObservation

// Group observations by shared signals. Offline and pure: no socket, no clock.
// Refuses `ip:cluster-bad-observation`, `ip:cluster-bad-option` and
// `ip:cluster-duplicate` (one address observed twice) rather than guessing.
native fn ip.cluster(observations: []IpObservation, opts: IpClusterOptions?) -> IpClusterReport

// Render a report as pretty-printed JSON, evidence lines included. Deterministic:
// the same report renders byte-identically every run.
native fn ip.cluster_json(report: IpClusterReport) -> String
