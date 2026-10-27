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
