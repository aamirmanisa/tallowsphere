//! `tallow.ip` — offline IP intelligence: an ASN/prefix table (N33) and a
//! content-addressed intel cache (N37).
//!
//! **Offline by construction.** Nothing in this module opens a socket, resolves
//! a name, or reads a clock it was not handed. `load` reads a file the caller
//! (or the environment) names; `cache_*` store bytes the caller supplies. The
//! only network-shaped work — fetching a fresh ip2asn TSV, re-querying a
//! registry — belongs to a caller that holds a `Grant`, not here.
//!
//! # N33 — table resolution and refusal discipline
//!
//! A table is resolved in this order, and the resolved path travels back to the
//! caller so a result can always say *which* file produced it:
//!
//! 1. the explicit path argument to [`load`];
//! 2. `TALLOW_IP2ASN` (the same variable `topology` already honours, so one
//!    box needs one setting);
//! 3. `/usr/share/ip2asn/ip2asn-v4.tsv`.
//!
//! A file that is missing or unreadable is a **refusal** (`ip:table-missing`)
//! that names the path and the resolution step that chose it — never an empty
//! table. That distinction is the point of the module: an unknown ASN is not
//! ASN 0, and a scanner that reports `asn=0` from a table that was never loaded
//! has told a lie about the network. [`load_missing`] exists so a caller can
//! preflight a path and get that refusal without paying to parse a real table.
//!
//! ## Malformed lines — fail closed, by line
//!
//! One malformed data line **invalidates the whole table** (`ip:table-malformed`,
//! naming `source:line` and quoting the offending text). The alternative —
//! skip the bad line and load the rest — produces a table that looks
//! authoritative while silently mislabelling every prefix the lost line covered,
//! which is exactly the failure mode an offline table is supposed to prevent.
//! A file that parses to zero rows is likewise refused (`ip:table-empty`).
//!
//! Blank lines, `#` comments and a single leading header line (tolerated only
//! when its third column is not a number and the line names `ASN`, matching the
//! ip2asn column title) are not malformed.
//!
//! ## Longest prefix, not first match
//!
//! ip2asn rows are start/end ranges, not CIDRs. `prefix_len` is the number of
//! leading bits `start` and `end` share (`(start ^ end).leading_zeros()`), which
//! is the exact prefix length for an aligned range and the honest common prefix
//! for an unaligned one. Lookup scans every covering row and keeps the **largest**
//! `prefix_len`, so a `/8` appearing earlier in the file cannot shadow a `/24`
//! that appears later. Equal lengths break toward the earlier line, which is
//! documented and deterministic rather than accidental.
//!
//! # N37 — content-addressed cache with an honest stale flag
//!
//! An entry is identified by `(source, key)`; its **content address** is
//! `sha256(body)`, returned on both write and read so a caller can prove two
//! reads are the same bytes without comparing them. Expiry is per source
//! because TTL is a property of the source's change rate, not of the cache.
//!
//! A read past TTL is a **hit with `stale: true` and the age**, not an error and
//! not a silent miss: an expiry is information, and the caller may still want
//! the last known answer with its age attached. A genuine absence is
//! `ip:cache-miss`, which is a different result. Neither is a panic.
//!
//! `cache_stats` takes no `now`, so it judges staleness against the wall clock;
//! `cache_get` takes the clock its caller chooses. Both are documented behaviour,
//! and a test pins the judgement `cache_stats` makes.

use super::StdlibResult;
use crate::interp::{Value, type_name};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Environment variable naming the table, honoured when no explicit path is given.
pub const ENV_TABLE: &str = "TALLOW_IP2ASN";
/// Documented default location for the IPv4 table.
pub const DEFAULT_TABLE: &str = "/usr/share/ip2asn/ip2asn-v4.tsv";

pub const CODE_NOT_IN_TABLE: &str = "ip:not-in-table";
pub const CODE_TABLE_MISSING: &str = "ip:table-missing";
pub const CODE_TABLE_MALFORMED: &str = "ip:table-malformed";
pub const CODE_TABLE_EMPTY: &str = "ip:table-empty";
pub const CODE_TABLE_UNKNOWN: &str = "ip:table-unknown";
pub const CODE_BAD_ADDRESS: &str = "ip:bad-address";
pub const CODE_UNSUPPORTED_FAMILY: &str = "ip:unsupported-family";
pub const CODE_CACHE_MISS: &str = "ip:cache-miss";
pub const CODE_CACHE_UNKNOWN: &str = "ip:cache-unknown";

// ── Data ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Row {
    start: u32,
    end: u32,
    asn: u32,
    country: String,
    description: String,
}

impl Row {
    /// Leading bits `start` and `end` share — the prefix this range covers.
    fn prefix_len(&self) -> u32 {
        (self.start ^ self.end).leading_zeros()
    }

    fn covers(&self, key: u32) -> bool {
        self.start <= key && key <= self.end
    }
}

#[derive(Clone, Debug)]
struct AsnTable {
    source: String,
    rows: Vec<Row>,
}

#[derive(Clone, Debug)]
struct Entry {
    content_hash: String,
    body: String,
    stored_at_ms: i64,
    ttl_ms: i64,
}

#[derive(Default, Debug)]
struct Cache {
    entries: HashMap<(String, String), Entry>,
}

#[derive(Default)]
struct Registry {
    next_id: u64,
    tables: HashMap<u64, AsnTable>,
    caches: HashMap<u64, Cache>,
    geos: HashMap<u64, GeoTable>,
}

fn registry() -> MutexGuard<'static, Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    let m = R.get_or_init(|| Mutex::new(Registry::default()));
    // A panicking test must not poison every later lookup into a panic of its
    // own; the registry holds plain data with no cross-entry invariant.
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn register_table(table: AsnTable) -> u64 {
    let mut reg = registry();
    reg.next_id += 1;
    let id = reg.next_id;
    reg.tables.insert(id, table);
    id
}

fn register_cache(cache: Cache) -> u64 {
    let mut reg = registry();
    reg.next_id += 1;
    let id = reg.next_id;
    reg.caches.insert(id, cache);
    id
}

fn table_by_handle(id: u64) -> Result<AsnTable, String> {
    registry().tables.get(&id).cloned().ok_or_else(|| {
        format!(
            "{CODE_TABLE_UNKNOWN}: no ASN table with handle {id} in this process — a handle is \
             process-local and is not data, so it cannot be reconstructed from a serialised value"
        )
    })
}

fn with_cache<T>(id: u64, f: impl FnOnce(&mut Cache) -> T) -> Result<T, String> {
    let mut reg = registry();
    let cache = reg.caches.get_mut(&id).ok_or_else(|| {
        format!(
            "{CODE_CACHE_UNKNOWN}: no intel cache with handle {id} in this process — a handle is \
             process-local and is not data, so it cannot be reconstructed from a serialised value"
        )
    })?;
    Ok(f(cache))
}

// ── N33: parse and resolve ──────────────────────────────────────────────────

/// Parse an ip2asn TSV body. `source` labels the table in results and refusals.
///
/// Fail-closed: see the module docs — the first malformed data line aborts the
/// whole load.
fn parse_table(text: &str, source: &str) -> Result<AsnTable, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = Vec::new();
    let mut seen_data = false;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let ncols = line.split('\t').count();
        if ncols < 5 {
            // A single leading header line is the only short non-data line
            // tolerated: the ip2asn column title names ASN and never parses as
            // a range.
            if !seen_data && trimmed.to_ascii_uppercase().contains("ASN") {
                continue;
            }
            return Err(format!(
                "{CODE_TABLE_MALFORMED}: {source}:{line_no}: expected 5 tab-separated fields \
                 (start, end, asn, country, description), got {ncols} — `{}`",
                excerpt(line)
            ));
        }
        let mut cols = line.splitn(5, '\t');
        let start = cols.next().unwrap_or("").trim();
        let end = cols.next().unwrap_or("").trim();
        let asn = cols.next().unwrap_or("").trim();
        let country = cols.next().unwrap_or("").trim();
        let description = cols.next().unwrap_or("").trim();
        let parsed = (parse_v4(start), parse_v4(end), asn.parse::<u32>());
        if let (Ok(start), Ok(end), Ok(asn)) = parsed {
            if start > end {
                return Err(format!(
                    "{CODE_TABLE_MALFORMED}: {source}:{line_no}: range start {start} is after end \
                     {end} — a reversed range is not a range"
                ));
            }
            seen_data = true;
            rows.push(Row {
                start,
                end,
                asn,
                country: country.to_string(),
                description: description.to_string(),
            });
            continue;
        }
        // A leading header line whose third column is not a number is the only
        // other tolerated non-data line.
        if !seen_data && trimmed.to_ascii_uppercase().contains("ASN") {
            continue;
        }
        let why = if parse_v4(start).is_err() {
            format!("field 1 `{start}` is not an IPv4 address")
        } else if parse_v4(end).is_err() {
            format!("field 2 `{end}` is not an IPv4 address")
        } else {
            format!("field 3 `{asn}` is not an ASN number")
        };
        return Err(format!(
            "{CODE_TABLE_MALFORMED}: {source}:{line_no}: {why} — `{}`",
            excerpt(line)
        ));
    }
    if rows.is_empty() {
        return Err(format!(
            "{CODE_TABLE_EMPTY}: {source}: the file parsed to zero rows, so it describes no \
             network; an empty table must not look like a loaded one"
        ));
    }
    Ok(AsnTable {
        source: source.to_string(),
        rows,
    })
}

fn parse_v4(s: &str) -> Result<u32, ()> {
    s.parse::<Ipv4Addr>().map(u32::from).map_err(|_| ())
}

fn excerpt(line: &str) -> String {
    const MAX: usize = 80;
    let mut out: String = line.chars().take(MAX).collect();
    if line.chars().count() > MAX {
        out.push('…');
    }
    out
}

/// Resolution order as a pure function so the order is testable without
/// mutating the process environment.
fn resolve_source(explicit: Option<&str>, env: Option<&str>) -> (String, &'static str) {
    if let Some(p) = explicit.map(str::trim).filter(|p| !p.is_empty()) {
        return (p.to_string(), "explicit");
    }
    if let Some(p) = env.map(str::trim).filter(|p| !p.is_empty()) {
        return (p.to_string(), "env:TALLOW_IP2ASN");
    }
    (DEFAULT_TABLE.to_string(), "default")
}

/// Read and parse the table chosen by `explicit`, the environment, then the
/// default location.
fn load_table(explicit: Option<&str>) -> Result<AsnTable, String> {
    let env = std::env::var(ENV_TABLE).ok();
    let (path, origin) = resolve_source(explicit, env.as_deref());
    load_path(&path, origin)
}

fn load_path(path: &str, origin: &str) -> Result<AsnTable, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_table(&text, path),
        Err(e) => Err(format!(
            "{CODE_TABLE_MISSING}: {path} (chosen by {origin}) could not be read: {e} — set \
             {ENV_TABLE} to an ip2asn-v4.tsv or pass an explicit path; an ASN is reported as \
             unknown, never as 0"
        )),
    }
}

fn lookup_row(table: &AsnTable, ip: &str) -> Result<Row, String> {
    let addr: IpAddr = ip.trim().parse().map_err(|_| {
        format!("{CODE_BAD_ADDRESS}: `{ip}` is not an IPv4 or IPv6 address literal")
    })?;
    let key = match addr {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(_) => {
            return Err(format!(
                "{CODE_UNSUPPORTED_FAMILY}: {ip} is IPv6, but the loaded table {} is \
                 ip2asn-v4 (IPv4 ranges only); there is no honest v6 answer here",
                table.source
            ));
        }
    };
    let mut best: Option<&Row> = None;
    for row in &table.rows {
        if row.covers(key) {
            // Strictly greater, so an equal-length duplicate keeps the earlier
            // line: deterministic, and never a later row silently winning.
            if best.is_none_or(|b| row.prefix_len() > b.prefix_len()) {
                best = Some(row);
            }
        }
    }
    best.cloned().ok_or_else(|| {
        format!(
            "{CODE_NOT_IN_TABLE}: {ip} is not covered by any of the {} entries in {} — absence \
             from the table is not ASN 0",
            table.rows.len(),
            table.source
        )
    })
}

// ── N37: cache ──────────────────────────────────────────────────────────────

fn sha256_hex(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn wall_clock_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// `age` for a read at `now_ms`. A clock that moves backwards is clamped to 0
/// rather than reporting negative age: this module will not invent time travel,
/// and a negative age would make `stale` silently false.
fn age_ms(stored_at_ms: i64, now_ms: i64) -> i64 {
    now_ms.saturating_sub(stored_at_ms).max(0)
}

fn cache_put(
    cache: &mut Cache,
    source: &str,
    key: &str,
    body: &str,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<Entry, String> {
    if ttl_ms < 0 {
        return Err(format!(
            "ip:cache-bad-ttl: ttl_ms {ttl_ms} is negative; a TTL is a duration, and a negative \
             one would mean the entry was stale before it was written"
        ));
    }
    let entry = Entry {
        content_hash: sha256_hex(body),
        body: body.to_string(),
        stored_at_ms: now_ms,
        ttl_ms,
    };
    cache
        .entries
        .insert((source.to_string(), key.to_string()), entry.clone());
    Ok(entry)
}

/// `Ok(entry, stale)` — a hit is a hit even past TTL; staleness travels with it.
fn cache_get(cache: &Cache, source: &str, key: &str, now_ms: i64) -> Result<(Entry, bool), String> {
    let lookup = (source.to_string(), key.to_string());
    let entry = cache.entries.get(&lookup).ok_or_else(|| {
        format!(
            "{CODE_CACHE_MISS}: no entry for source `{source}` key `{key}` — an entry past its \
             TTL is returned stale, not missed, so this is a genuine absence"
        )
    })?;
    let age = age_ms(entry.stored_at_ms, now_ms);
    Ok((entry.clone(), age > entry.ttl_ms))
}

fn cache_stats(cache: &Cache) -> (usize, usize, usize) {
    let now = wall_clock_ms();
    let sources: std::collections::HashSet<&str> =
        cache.entries.keys().map(|(s, _)| s.as_str()).collect();
    let stale = cache
        .entries
        .values()
        .filter(|e| age_ms(e.stored_at_ms, now) > e.ttl_ms)
        .count();
    (cache.entries.len(), sources.len(), stale)
}

// ── N36: infrastructure clustering ──────────────────────────────────────────

// Weights are evidence, not equality. Each is the score a pair of endpoints
// gains from *sharing* that signal; a pair's score is the sum, capped at 1.0.
//
//   cert_sha256      0.60 — a certificate is minted by whoever holds the key.
//                            Same sha256 means same key material or a copied
//                            cert file: an operator-level artifact. Held below
//                            1.0 because a CDN/WAF or a hosting panel can
//                            present one cert for many customers, and a
//                            default-image self-signed cert is shared by every
//                            unconfigured install of that image. It clears the
//                            merge floor alone (0.60 >= 0.60): requiring
//                            corroboration for the strongest signal we have
//                            would make every single-signal cluster invisible.
//   favicon_hash     0.40 — application-owned, but default favicons (nginx,
//                            WordPress, cPanel, framework placeholders) are
//                            shared by millions of unrelated hosts. Strong,
//                            not decisive: never merges on its own.
//   header_signature 0.30 — Server / X-Powered-By / cookie names are a
//                            framework default as often as a fingerprint, and
//                            a WAF rewrites them for every customer. Pure
//                            corroboration.
//   asn              0.10 — the ASN names a *provider*, not an operator; every
//                            Cloudflare-fronted site shares AS13335. Below
//                            LINK_MIN_SCORE, so a shared ASN alone does not
//                            even produce a link, let alone a cluster.
// A reader who disagrees with a number can change the constant and re-run the
// tests: the thresholds below are exported in every report.
pub const W_CERT: f64 = 0.60;
pub const W_FAVICON: f64 = 0.40;
pub const W_HEADER: f64 = 0.30;
pub const W_ASN: f64 = 0.10;

// Two floors, not one. A pair scoring below LINK_MIN_SCORE is not reported at
// all (it is not evidence of anything). A pair at or above it but below
// MERGE_MIN_SCORE is reported as *linked but not merged* — visible, auditable,
// and never silently unioned. A pair at or above MERGE_MIN_SCORE is merged.
pub const LINK_MIN_SCORE: f64 = 0.25;
pub const MERGE_MIN_SCORE: f64 = 0.60;

pub const CODE_CLUSTER_DUPLICATE: &str = "ip:cluster-duplicate";
pub const CODE_CLUSTER_BAD_OPTION: &str = "ip:cluster-bad-option";
pub const CODE_CLUSTER_BAD_OBSERVATION: &str = "ip:cluster-bad-observation";

/// One endpoint as the caller observed it. Absent signals are `None`, never a
/// sentinel: an unknown ASN is not ASN 0, and an unknown certificate is not a
/// certificate that matches every other unknown one.
#[derive(Clone, Debug)]
struct Observation {
    ip: String,
    host: String,
    asn: Option<u32>,
    cert_sha256: Option<String>,
    favicon_hash: Option<String>,
    header_signature: Option<String>,
}

/// The evidence for one pair. `signals` is never empty: a `Link` exists only
/// because something was shared.
#[derive(Clone, Debug)]
struct Link {
    a: String,
    b: String,
    /// Hostnames as the caller supplied them, for human-readable evidence.
    a_host: String,
    b_host: String,
    signals: Vec<&'static str>,
    score: f64,
}

#[derive(Clone, Debug)]
struct Cluster {
    members: Vec<String>,
    confidence: f64,
    evidence: Vec<Link>,
}

#[derive(Clone, Debug)]
struct ClusterReport {
    clusters: Vec<Cluster>,
    linked_not_merged: Vec<Link>,
    /// Observations that joined no cluster. They are not findings — a lone
    /// endpoint shares evidence with nobody — but dropping them silently makes
    /// `observation_count` disagree with the members on show and leaves a
    /// reader unable to tell "nothing to report" from "the host was lost".
    unclustered: Vec<String>,
    observations: usize,
    link_min: f64,
    merge_min: f64,
}

/// Round to three decimals so the printed score is the compared score and
/// `0.6 + 0.3` renders as `0.9` rather than `0.8999999999999999`.
fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn link_between(a: &Observation, b: &Observation) -> Option<Link> {
    let mut signals: Vec<&'static str> = Vec::new();
    let mut score = 0.0;
    let pairs: [(&str, bool, f64); 3] = [
        (
            "cert_sha256",
            a.cert_sha256.is_some() && a.cert_sha256 == b.cert_sha256,
            W_CERT,
        ),
        (
            "favicon_hash",
            a.favicon_hash.is_some() && a.favicon_hash == b.favicon_hash,
            W_FAVICON,
        ),
        (
            "header_signature",
            a.header_signature.is_some() && a.header_signature == b.header_signature,
            W_HEADER,
        ),
    ];
    for (name, shared, weight) in pairs {
        if shared {
            signals.push(name);
            score += weight;
        }
    }
    if a.asn.is_some() && a.asn == b.asn {
        signals.push("asn");
        score += W_ASN;
    }
    if signals.is_empty() {
        return None;
    }
    Some(Link {
        a: a.ip.clone(),
        b: b.ip.clone(),
        a_host: a.host.clone(),
        b_host: b.host.clone(),
        signals,
        score: round3(score.min(1.0)),
    })
}

fn find(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

/// Cluster a set of observations. Deterministic: observations are sorted by IP
/// string (then the pair loop runs in index order), clusters are ordered by
/// their first member, members and evidence are in sorted order.
fn build_report(
    observations: &[Observation],
    link_min: f64,
    merge_min: f64,
) -> Result<ClusterReport, String> {
    let mut obs: Vec<Observation> = observations.to_vec();
    obs.sort_by(|a, b| a.ip.cmp(&b.ip));
    if let Some(w) = obs.windows(2).find(|w| w[0].ip == w[1].ip) {
        return Err(format!(
            "{CODE_CLUSTER_DUPLICATE}: {} is observed twice — two observations of one address \
             cannot be both authoritative, so the caller must reduce them to one before \
             clustering",
            w[0].ip
        ));
    }

    let mut links: Vec<(usize, usize, Link)> = Vec::new();
    for i in 0..obs.len() {
        for j in (i + 1)..obs.len() {
            if let Some(link) = link_between(&obs[i], &obs[j]) {
                links.push((i, j, link));
            }
        }
    }

    let mut parent: Vec<usize> = (0..obs.len()).collect();
    for (i, j, link) in &links {
        if link.score >= merge_min {
            let (ra, rb) = (find(&mut parent, *i), find(&mut parent, *j));
            if ra != rb {
                parent[rb] = ra;
            }
        }
    }

    // Group by union-find root; `i` ascends, so groups arrive ordered by their
    // lowest-index (and therefore lowest-IP) member.
    let mut roots: Vec<usize> = Vec::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for i in 0..obs.len() {
        let r = find(&mut parent, i);
        match roots.iter().position(|x| *x == r) {
            Some(p) => groups[p].push(i),
            None => {
                roots.push(r);
                groups.push(vec![i]);
            }
        }
    }

    let mut clusters: Vec<Cluster> = Vec::new();
    let mut unclustered: Vec<String> = Vec::new();
    for group in &groups {
        // A cluster of one is not a cluster: a single endpoint has no shared
        // evidence, and reporting it would dress a lone host as a finding. It
        // is reported as unclustered instead, so the count still adds up.
        if group.len() < 2 {
            unclustered.extend(group.iter().map(|&i| obs[i].ip.clone()));
            continue;
        }
        let mut evidence: Vec<Link> = Vec::new();
        let mut confidence = 1.0_f64;
        for (i, j, link) in &links {
            if link.score >= merge_min && group.contains(i) && group.contains(j) {
                // The weakest merge edge decides: an average would let a crowd
                // of corroborating weak pairs outvote the strong edge that
                // actually justifies the union.
                confidence = confidence.min(link.score);
                evidence.push(link.clone());
            }
        }
        clusters.push(Cluster {
            members: group.iter().map(|&i| obs[i].ip.clone()).collect(),
            confidence,
            evidence,
        });
    }
    clusters.sort_by(|a, b| a.members.first().cmp(&b.members.first()));
    unclustered.sort();

    let mut linked_not_merged: Vec<Link> = Vec::new();
    for (i, j, link) in &links {
        let in_range = link.score >= link_min && link.score < merge_min;
        if in_range && find(&mut parent, *i) != find(&mut parent, *j) {
            linked_not_merged.push(link.clone());
        }
    }

    Ok(ClusterReport {
        clusters,
        linked_not_merged,
        unclustered,
        observations: obs.len(),
        link_min,
        merge_min,
    })
}

/// Normalise a caller-supplied hash: digests are hex, so case and surrounding
/// space are noise. A non-empty value that differs only in case is the same
/// certificate, and pretending otherwise would split a cluster for nothing.
fn norm_hash(v: &str) -> Option<String> {
    let t = v.trim().to_ascii_lowercase();
    (!t.is_empty()).then_some(t)
}

/// Header signatures are compared after whitespace collapsing, so a signature
/// assembled with tabs and one assembled with spaces are still one signature.
fn norm_headers(v: &str) -> Option<String> {
    let t = v.split_whitespace().collect::<Vec<_>>().join(" ");
    (!t.is_empty()).then_some(t)
}

fn opt_text(fields: &[(String, Value)], name: &str) -> Option<String> {
    match field(fields, name) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn parse_observation(v: &Value) -> Result<Observation, String> {
    let Value::Struct { name, fields } = v else {
        return Err(format!(
            "{CODE_CLUSTER_BAD_OBSERVATION}: observation expected IpObservation, got {}",
            type_name(v)
        ));
    };
    if name != "IpObservation" {
        return Err(format!(
            "{CODE_CLUSTER_BAD_OBSERVATION}: observation expected IpObservation, got struct {name}"
        ));
    }
    let ip = match field(fields, "ip") {
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        other => {
            return Err(format!(
                "{CODE_CLUSTER_BAD_OBSERVATION}: IpObservation.ip must be a non-empty String, \
                 got {}",
                other.map(type_name).unwrap_or("nothing")
            ));
        }
    };
    // ASN 0 (and any non-positive value) is treated as unknown, matching the
    // module's rule that an ASN is measured or absent, never 0 by default.
    let asn = match field(fields, "asn") {
        Some(Value::Int(i)) if *i > 0 => u32::try_from(*i).ok(),
        _ => None,
    };
    Ok(Observation {
        ip,
        host: opt_text(fields, "host").unwrap_or_default(),
        asn,
        cert_sha256: opt_text(fields, "cert_sha256")
            .as_deref()
            .and_then(norm_hash),
        favicon_hash: opt_text(fields, "favicon_hash")
            .as_deref()
            .and_then(norm_hash),
        header_signature: opt_text(fields, "header_signature")
            .as_deref()
            .and_then(norm_headers),
    })
}

fn opt_score(v: Option<&Value>, name: &str, default: f64) -> Result<f64, String> {
    match v {
        None | Some(Value::Nil) => Ok(default),
        Some(Value::Float(f)) if f.is_finite() => Ok(*f),
        Some(Value::Int(i)) if *i >= 0 => Ok(*i as f64),
        Some(other) => Err(format!(
            "{CODE_CLUSTER_BAD_OPTION}: options.{name} expected Float, got {}",
            type_name(other)
        )),
    }
}

fn link_value(l: &Link) -> Value {
    Value::Struct {
        name: "ClusterLink".to_string(),
        fields: vec![
            ("ip_a".to_string(), Value::String(l.a.clone())),
            ("ip_b".to_string(), Value::String(l.b.clone())),
            ("signals".to_string(), Value::String(l.signals.join(","))),
            ("score".to_string(), Value::Float(l.score)),
        ],
    }
}

fn endpoint_label(ip: &str, host: &str) -> String {
    if host.is_empty() {
        ip.to_string()
    } else {
        format!("{ip} ({host})")
    }
}

fn evidence_line(l: &Link) -> String {
    format!(
        "{} <-> {} shared {} (score {:.3})",
        endpoint_label(&l.a, &l.a_host),
        endpoint_label(&l.b, &l.b_host),
        l.signals.join("+"),
        l.score
    )
}

fn report_value(r: &ClusterReport) -> Value {
    let clusters: Vec<Value> = r
        .clusters
        .iter()
        .map(|c| Value::Struct {
            name: "IpCluster".to_string(),
            fields: vec![
                (
                    "members".to_string(),
                    Value::Array(c.members.iter().cloned().map(Value::String).collect()),
                ),
                ("size".to_string(), Value::Int(c.members.len() as i128)),
                ("confidence".to_string(), Value::Float(c.confidence)),
                (
                    "evidence".to_string(),
                    Value::Array(c.evidence.iter().map(link_value).collect()),
                ),
                (
                    "evidence_lines".to_string(),
                    Value::Array(
                        c.evidence
                            .iter()
                            .map(|l| Value::String(evidence_line(l)))
                            .collect(),
                    ),
                ),
            ],
        })
        .collect();
    Value::Struct {
        name: "IpClusterReport".to_string(),
        fields: vec![
            ("clusters".to_string(), Value::Array(clusters)),
            (
                "linked_not_merged".to_string(),
                Value::Array(r.linked_not_merged.iter().map(link_value).collect()),
            ),
            (
                "unclustered".to_string(),
                Value::Array(r.unclustered.iter().cloned().map(Value::String).collect()),
            ),
            (
                "observation_count".to_string(),
                Value::Int(r.observations as i128),
            ),
            ("link_min_score".to_string(), Value::Float(r.link_min)),
            ("merge_min_score".to_string(), Value::Float(r.merge_min)),
            (
                "weights".to_string(),
                Value::Struct {
                    name: "ClusterWeights".to_string(),
                    fields: vec![
                        ("cert_sha256".to_string(), Value::Float(W_CERT)),
                        ("favicon_hash".to_string(), Value::Float(W_FAVICON)),
                        ("header_signature".to_string(), Value::Float(W_HEADER)),
                        ("asn".to_string(), Value::Float(W_ASN)),
                    ],
                },
            ),
        ],
    }
}

/// Generic value → JSON, so `cluster_json` renders whatever `cluster` returned
/// without a second hand-written parser that could drift from the first.
fn value_json(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Nil => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Int(i) => J::Number((*i as i64).into()),
        Value::Float(f) => J::from(*f),
        Value::String(s) => J::String(s.clone()),
        Value::Array(items) => J::Array(items.iter().map(value_json).collect()),
        Value::Struct { fields, .. } => J::Object(
            fields
                .iter()
                .map(|(k, val)| (k.clone(), value_json(val)))
                .collect(),
        ),
        Value::Map(pairs) => J::Object(
            pairs
                .iter()
                .map(|(k, val)| (format!("{k:?}"), value_json(val)))
                .collect(),
        ),
        other => J::String(format!("<{}>", type_name(other))),
    }
}

// ── N34: geolocation with uncertainty ───────────────────────────────────────

/// Environment variable naming the geolocation table, honoured when no explicit
/// path is given — the same shape as [`ENV_TABLE`], so one box needs one pair of
/// settings rather than two conventions.
pub const ENV_GEO: &str = "TALLOW_GEO";
/// Documented default location for the geolocation table.
pub const DEFAULT_GEO_TABLE: &str = "/usr/share/tallow/geo-ip.tsv";

pub const CODE_GEO_CITY_UNQUALIFIED: &str = "ip:geo-city-unqualified";
pub const CODE_GEO_RADIUS_UNQUALIFIED: &str = "ip:geo-radius-unqualified";

// A confidence is *derived* from the accuracy radius a row carries, never
// invented per call. The bands are flat steps rather than a curve because the
// inputs are themselves bands: a table saying "45 km" does not know the answer
// to 44.8 km, and a smooth interpolation would dress that ignorance as
// precision. Both the thresholds and the confidences they produce are exported,
// so a reader who disagrees with a number can change it and re-run the tests.
//
//   radius <=   5 km -> 0.95   the row is claiming street level
//   radius <=  25 km -> 0.80   city level
//   radius <= 100 km -> 0.55   metro / region level
//   radius <= 500 km -> 0.35   country level, roughly
//   wider            -> 0.15   "somewhere on this continent"
//   no radius        -> 0.20   country/region only — deliberately *below* every
//                              radius-qualified band, because an answer that
//                              names no radius makes no distance claim at all
pub const GEO_KM_TIGHT: f64 = 5.0;
pub const GEO_KM_CITY: f64 = 25.0;
pub const GEO_KM_REGION: f64 = 100.0;
pub const GEO_KM_COUNTRY: f64 = 500.0;

pub const GEO_CONF_TIGHT: f64 = 0.95;
pub const GEO_CONF_CITY: f64 = 0.80;
pub const GEO_CONF_REGION: f64 = 0.55;
pub const GEO_CONF_COUNTRY: f64 = 0.35;
pub const GEO_CONF_CONTINENT: f64 = 0.15;
pub const GEO_CONF_ADMIN: f64 = 0.20;

/// One geolocation row: an IPv4 range plus the administrative answer for it.
/// `city` and `accuracy_km` are independent `None`s, never sentinels — an empty
/// city column is not the string "" and an absent radius is not 0 km.
#[derive(Clone, Debug)]
struct GeoRow {
    start: u32,
    end: u32,
    country: String,
    region: String,
    city: Option<String>,
    accuracy_km: Option<f64>,
}

impl GeoRow {
    fn prefix_len(&self) -> u32 {
        (self.start ^ self.end).leading_zeros()
    }

    fn covers(&self, key: u32) -> bool {
        self.start <= key && key <= self.end
    }
}

#[derive(Clone, Debug)]
struct GeoTable {
    source: String,
    rows: Vec<GeoRow>,
}

/// The answer, with the qualification that produced it. `code` is `Some` exactly
/// when the answer was downgraded from what the row literally contained.
#[derive(Clone, Debug)]
struct GeoAnswer {
    country: String,
    region: String,
    city: Option<String>,
    accuracy_km: Option<f64>,
    confidence: f64,
    source: String,
    code: Option<&'static str>,
}

fn geo_confidence(accuracy_km: Option<f64>) -> f64 {
    match accuracy_km {
        None => GEO_CONF_ADMIN,
        Some(km) if km <= GEO_KM_TIGHT => GEO_CONF_TIGHT,
        Some(km) if km <= GEO_KM_CITY => GEO_CONF_CITY,
        Some(km) if km <= GEO_KM_REGION => GEO_CONF_REGION,
        Some(km) if km <= GEO_KM_COUNTRY => GEO_CONF_COUNTRY,
        Some(_) => GEO_CONF_CONTINENT,
    }
}

fn register_geo_table(table: GeoTable) -> u64 {
    let mut reg = registry();
    reg.next_id += 1;
    let id = reg.next_id;
    reg.geos.insert(id, table);
    id
}

fn geo_by_handle(id: u64) -> Result<GeoTable, String> {
    registry().geos.get(&id).cloned().ok_or_else(|| {
        format!(
            "{CODE_TABLE_UNKNOWN}: no geolocation table with handle {id} in this process — a \
             handle is process-local and is not data, so it cannot be reconstructed from a \
             serialised value"
        )
    })
}

/// Parse a geolocation TSV: `start, end, country, region[, city[, accuracy_km]]`.
///
/// Fail-closed exactly as the ASN table is: the first malformed data line voids
/// the whole load with `source:line`, because a half-loaded geo table mislabels
/// every range the lost line covered — and unlike an ASN, a wrong country is a
/// claim about a place and a person.
fn parse_geo_table(text: &str, source: &str) -> Result<GeoTable, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = Vec::new();
    let mut seen_data = false;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let ncols = line.split('\t').count();
        let looks_like_header = !seen_data
            && trimmed.to_ascii_uppercase().contains("COUNTRY")
            && parse_v4(line.split('\t').next().unwrap_or("").trim()).is_err();
        if ncols < 4 || looks_like_header {
            if looks_like_header {
                continue;
            }
            return Err(format!(
                "{CODE_TABLE_MALFORMED}: {source}:{line_no}: expected 4 to 6 tab-separated \
                 fields (start, end, country, region[, city[, accuracy_km]]), got {ncols} — `{}`",
                excerpt(line)
            ));
        }
        let mut cols = line.splitn(6, '\t');
        let start = cols.next().unwrap_or("").trim();
        let end = cols.next().unwrap_or("").trim();
        let country = cols.next().unwrap_or("").trim();
        let region = cols.next().unwrap_or("").trim();
        let city = cols.next().unwrap_or("").trim();
        let accuracy = cols.next().unwrap_or("").trim();
        let (Ok(start), Ok(end)) = (parse_v4(start), parse_v4(end)) else {
            return Err(format!(
                "{CODE_TABLE_MALFORMED}: {source}:{line_no}: fields 1 and 2 must be IPv4 \
                 addresses (start, end) — `{}`",
                excerpt(line)
            ));
        };
        if start > end {
            return Err(format!(
                "{CODE_TABLE_MALFORMED}: {source}:{line_no}: range start {start} is after end \
                 {end} — a reversed range is not a range"
            ));
        }
        if country.is_empty() || region.is_empty() {
            // Country and region are always reported, so a row that cannot
            // supply them cannot answer anything this module is willing to say.
            return Err(format!(
                "{CODE_TABLE_MALFORMED}: {source}:{line_no}: country and region are required \
                 (they are the answer when the city is unqualified) — `{}`",
                excerpt(line)
            ));
        }
        let accuracy_km = if accuracy.is_empty() {
            None
        } else {
            match accuracy.parse::<f64>() {
                Ok(km) if km.is_finite() && km >= 0.0 => Some(km),
                _ => {
                    return Err(format!(
                        "{CODE_TABLE_MALFORMED}: {source}:{line_no}: field 6 `{accuracy}` is not \
                         a non-negative accuracy radius in km — `{}`",
                        excerpt(line)
                    ));
                }
            }
        };
        seen_data = true;
        rows.push(GeoRow {
            start,
            end,
            country: country.to_string(),
            region: region.to_string(),
            city: (!city.is_empty()).then(|| city.to_string()),
            accuracy_km,
        });
    }
    if rows.is_empty() {
        return Err(format!(
            "{CODE_TABLE_EMPTY}: {source}: the file parsed to zero rows, so it locates nothing; \
             an empty table must not look like a loaded one"
        ));
    }
    Ok(GeoTable {
        source: source.to_string(),
        rows,
    })
}

fn resolve_geo_source(explicit: Option<&str>, env: Option<&str>) -> (String, &'static str) {
    if let Some(p) = explicit.map(str::trim).filter(|p| !p.is_empty()) {
        return (p.to_string(), "explicit");
    }
    if let Some(p) = env.map(str::trim).filter(|p| !p.is_empty()) {
        return (p.to_string(), "env:TALLOW_GEO");
    }
    (DEFAULT_GEO_TABLE.to_string(), "default")
}

fn load_geo_table(explicit: Option<&str>) -> Result<GeoTable, String> {
    let env = std::env::var(ENV_GEO).ok();
    let (path, origin) = resolve_geo_source(explicit, env.as_deref());
    load_geo_path(&path, origin)
}

fn load_geo_path(path: &str, origin: &str) -> Result<GeoTable, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_geo_table(&text, path),
        Err(e) => Err(format!(
            "{CODE_TABLE_MISSING}: {path} (chosen by {origin}) could not be read: {e} — set \
             {ENV_GEO} to a geo-ip.tsv or pass an explicit path; a location is reported as \
             unknown, never guessed"
        )),
    }
}

/// Longest-prefix geolocation, then *qualification* of what the row can honestly
/// claim.
///
/// A city is served only when the same row carries an accuracy radius to go with
/// it. A bare city name renders as `Paris` and reads as exact, which is the
/// defect this item exists to prevent, so an unqualified city is dropped and the
/// answer falls back to country/region with `ip:geo-city-unqualified` attached.
/// The mirror case — a radius with no city to qualify — drops the radius (there
/// is no point for it to be a radius *of*) and says
/// `ip:geo-radius-unqualified`.
fn geo_lookup_row(table: &GeoTable, ip: &str) -> Result<GeoAnswer, String> {
    let addr: IpAddr = ip.trim().parse().map_err(|_| {
        format!("{CODE_BAD_ADDRESS}: `{ip}` is not an IPv4 or IPv6 address literal")
    })?;
    let key = match addr {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(_) => {
            return Err(format!(
                "{CODE_UNSUPPORTED_FAMILY}: {ip} is IPv6, but the loaded table {} is IPv4 \
                 ranges only; there is no honest v6 answer here",
                table.source
            ));
        }
    };
    let mut best: Option<&GeoRow> = None;
    for row in &table.rows {
        if row.covers(key) && best.is_none_or(|b| row.prefix_len() > b.prefix_len()) {
            best = Some(row);
        }
    }
    let Some(row) = best else {
        return Err(format!(
            "{CODE_NOT_IN_TABLE}: {ip} is not covered by any of the {} entries in {} — absence \
             from the table is not a location",
            table.rows.len(),
            table.source
        ));
    };
    let (city, accuracy_km, code) = match (row.city.as_deref(), row.accuracy_km) {
        (Some(city), Some(km)) => (Some(city.to_string()), Some(km), None),
        (Some(_), None) => (None, None, Some(CODE_GEO_CITY_UNQUALIFIED)),
        (None, Some(_)) => (None, None, Some(CODE_GEO_RADIUS_UNQUALIFIED)),
        (None, None) => (None, None, None),
    };
    Ok(GeoAnswer {
        country: row.country.clone(),
        region: row.region.clone(),
        city,
        accuracy_km,
        confidence: geo_confidence(accuracy_km),
        source: table.source.clone(),
        code,
    })
}

fn geo_table_value(id: u64, table: &GeoTable) -> Value {
    Value::Struct {
        name: "IpGeoTable".to_string(),
        fields: vec![
            ("handle".to_string(), Value::Int(id as i128)),
            ("source".to_string(), Value::String(table.source.clone())),
            ("rows".to_string(), Value::Int(table.rows.len() as i128)),
        ],
    }
}

fn geo_answer_value(a: &GeoAnswer) -> Value {
    Value::Struct {
        name: "GeoAnswer".to_string(),
        fields: vec![
            ("country".to_string(), Value::String(a.country.clone())),
            ("region".to_string(), Value::String(a.region.clone())),
            (
                "city".to_string(),
                match &a.city {
                    Some(c) => Value::String(c.clone()),
                    None => Value::Nil,
                },
            ),
            (
                "accuracy_km".to_string(),
                match a.accuracy_km {
                    Some(km) => Value::Float(km),
                    None => Value::Nil,
                },
            ),
            ("confidence".to_string(), Value::Float(a.confidence)),
            ("source".to_string(), Value::String(a.source.clone())),
            (
                "code".to_string(),
                match a.code {
                    Some(c) => Value::String(c.to_string()),
                    None => Value::Nil,
                },
            ),
        ],
    }
}

fn geo_load_dispatch(args: Vec<Value>) -> StdlibResult {
    let explicit = opt_str_arg(&args, 0, "geo_load")?;
    let table = load_geo_table(explicit.as_deref())?;
    let id = register_geo_table(table.clone());
    Ok(geo_table_value(id, &table))
}

fn geo_lookup_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = handle_arg(&args, 0, "IpGeoTable", "geo_lookup")?;
    let ip = str_arg(&args, 1, "geo_lookup")?;
    let table = geo_by_handle(id)?;
    Ok(geo_answer_value(&geo_lookup_row(&table, &ip)?))
}

fn geo_json_dispatch(args: Vec<Value>) -> StdlibResult {
    let v = args
        .first()
        .ok_or_else(|| "ip.geo_json: missing argument 1 (GeoAnswer)".to_string())?;
    match v {
        Value::Struct { name, .. } if name == "GeoAnswer" => {}
        other => {
            return Err(format!(
                "ip.geo_json: argument 1 expected GeoAnswer, got {}",
                value_label(other)
            ));
        }
    }
    serde_json::to_string_pretty(&value_json(v))
        .map(Value::String)
        .map_err(|e| format!("ip.geo_json: {e}"))
}

// ── N35: multi-source join ──────────────────────────────────────────────────

pub const CODE_JOIN_BAD_SOURCE: &str = "ip:join-bad-source";
pub const CODE_JOIN_BAD_ROW: &str = "ip:join-bad-row";
pub const CODE_JOIN_DUPLICATE: &str = "ip:join-duplicate";

/// One field value as a source reported it. `authority` is a caller-assigned
/// rank (higher = more authoritative) and it **orders the display only**: it
/// never decides which value is true, which is why the report carries no
/// "winner" field for it to decide.
#[derive(Clone, Debug)]
struct JoinRow {
    ip: String,
    field: String,
    value: String,
    confidence: Option<f64>,
}

#[derive(Clone, Debug)]
struct JoinSource {
    name: String,
    authority: i64,
    retrieved_at_ms: i64,
    freshness_ms: i64,
    rows: Vec<JoinRow>,
}

/// A value in the report, with its provenance and its age. `stale` is
/// `age_ms > freshness_ms`: an expiry is information carried *with* the value,
/// never a reason to hide it and never a licence to serve it as current.
#[derive(Clone, Debug)]
struct JoinValue {
    source: String,
    authority: i64,
    value: String,
    confidence: Option<f64>,
    retrieved_at_ms: i64,
    age_ms: i64,
    stale: bool,
}

fn join_str(
    fields: &[(String, Value)],
    name: &str,
    code: &str,
    owner: &str,
) -> Result<String, String> {
    match field(fields, name) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        other => Err(format!(
            "{code}: {owner}.{name} must be a non-empty String, got {}",
            other.map(type_name).unwrap_or("nothing")
        )),
    }
}

fn parse_join_row(v: &Value) -> Result<JoinRow, String> {
    let Value::Struct { name, fields } = v else {
        return Err(format!(
            "{CODE_JOIN_BAD_ROW}: row expected IpJoinRow, got {}",
            type_name(v)
        ));
    };
    if name != "IpJoinRow" {
        return Err(format!(
            "{CODE_JOIN_BAD_ROW}: row expected IpJoinRow, got struct {name}"
        ));
    }
    let confidence = match field(fields, "confidence") {
        None | Some(Value::Nil) => None,
        Some(Value::Float(f)) if (0.0..=1.0).contains(f) => Some(*f),
        Some(other) => {
            return Err(format!(
                "{CODE_JOIN_BAD_ROW}: confidence must be a Float in 0..=1, got {}",
                value_label(other)
            ));
        }
    };
    Ok(JoinRow {
        ip: join_str(fields, "ip", CODE_JOIN_BAD_ROW, "IpJoinRow")?,
        field: join_str(fields, "field", CODE_JOIN_BAD_ROW, "IpJoinRow")?,
        value: join_str(fields, "value", CODE_JOIN_BAD_ROW, "IpJoinRow")?,
        confidence,
    })
}

fn parse_join_source(v: &Value) -> Result<JoinSource, String> {
    let Value::Struct { name, fields } = v else {
        return Err(format!(
            "{CODE_JOIN_BAD_SOURCE}: source expected IpJoinSource, got {}",
            type_name(v)
        ));
    };
    if name != "IpJoinSource" {
        return Err(format!(
            "{CODE_JOIN_BAD_SOURCE}: source expected IpJoinSource, got struct {name}"
        ));
    }
    let int = |n: &str| -> Result<i64, String> {
        match field(fields, n) {
            Some(Value::Int(i)) => i64::try_from(*i)
                .map_err(|_| format!("{CODE_JOIN_BAD_SOURCE}: {n} {i} is out of range")),
            other => Err(format!(
                "{CODE_JOIN_BAD_SOURCE}: IpJoinSource.{n} must be an Int, got {}",
                other.map(type_name).unwrap_or("nothing")
            )),
        }
    };
    let (authority, retrieved_at_ms, freshness_ms) = (
        int("authority")?,
        int("retrieved_at_ms")?,
        int("freshness_ms")?,
    );
    if authority < 0 {
        return Err(format!(
            "{CODE_JOIN_BAD_SOURCE}: authority {authority} is negative — authority is a rank, \
             and a negative rank orders nothing"
        ));
    }
    if retrieved_at_ms <= 0 {
        // A timestamp is evidence; a missing one is a refusal, not "now".
        // Accepting 0 would date every value to 1970 and make `stale` meaningless.
        return Err(format!(
            "{CODE_JOIN_BAD_SOURCE}: IpJoinSource.retrieved_at_ms is unset ({retrieved_at_ms}) — \
             an age needs the moment it was retrieved, and the current time is not evidence"
        ));
    }
    if freshness_ms < 0 {
        return Err(format!(
            "{CODE_JOIN_BAD_SOURCE}: freshness_ms {freshness_ms} is negative — a horizon is a \
             duration"
        ));
    }
    let Some(Value::Array(items)) = field(fields, "rows") else {
        return Err(format!(
            "{CODE_JOIN_BAD_SOURCE}: IpJoinSource.rows must be []IpJoinRow"
        ));
    };
    Ok(JoinSource {
        name: join_str(fields, "name", CODE_JOIN_BAD_SOURCE, "IpJoinSource")?,
        authority,
        retrieved_at_ms,
        freshness_ms,
        rows: items.iter().map(parse_join_row).collect::<Result<_, _>>()?,
    })
}

fn join_value_struct(v: &JoinValue) -> Value {
    Value::Struct {
        name: "IpJoinValue".to_string(),
        fields: vec![
            ("source".to_string(), Value::String(v.source.clone())),
            ("authority".to_string(), Value::Int(v.authority as i128)),
            ("value".to_string(), Value::String(v.value.clone())),
            (
                "confidence".to_string(),
                match v.confidence {
                    Some(c) => Value::Float(c),
                    None => Value::Nil,
                },
            ),
            (
                "retrieved_at_ms".to_string(),
                Value::Int(v.retrieved_at_ms as i128),
            ),
            ("age_ms".to_string(), Value::Int(v.age_ms as i128)),
            ("stale".to_string(), Value::Bool(v.stale)),
        ],
    }
}

fn disagreement_line(ip: &str, field_name: &str, values: &[JoinValue]) -> String {
    let parts: Vec<String> = values
        .iter()
        .map(|v| {
            format!(
                "{} (source {}, authority {}, age {}ms{})",
                v.value,
                v.source,
                v.authority,
                v.age_ms,
                if v.stale { ", stale" } else { "" }
            )
        })
        .collect();
    format!("{ip} {field_name}: {}", parts.join(" vs "))
}

/// Join what the caller already retrieved. No socket, no clock: `now_ms` is the
/// caller's, so age is arithmetic the caller can reproduce.
///
/// Ordering is total, so permuted input yields byte-identical output: sources
/// by name, fields by (ip, field), values by authority descending then source
/// name. A field where the sources differ is reported as a disagreement naming
/// every claimant — never averaged, never collapsed to a majority, never
/// resolved by authority, because the operator's question is *who is wrong*.
fn build_join(sources: &[JoinSource], now_ms: i64) -> Result<Value, String> {
    let mut ordered: Vec<&JoinSource> = sources.iter().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));
    if let Some(w) = ordered.windows(2).find(|w| w[0].name == w[1].name) {
        return Err(format!(
            "{CODE_JOIN_BAD_SOURCE}: source `{}` appears twice — two authorities for one name \
             would make every value it reported ambiguous",
            w[0].name
        ));
    }

    let mut groups: std::collections::BTreeMap<(String, String), Vec<JoinValue>> =
        std::collections::BTreeMap::new();
    let mut seen = std::collections::HashSet::new();
    for s in &ordered {
        for r in &s.rows {
            if !seen.insert((s.name.clone(), r.ip.clone(), r.field.clone())) {
                return Err(format!(
                    "{CODE_JOIN_DUPLICATE}: source `{}` reported {} {} twice — one source, one \
                     field, one value",
                    s.name, r.ip, r.field
                ));
            }
            groups
                .entry((r.ip.clone(), r.field.clone()))
                .or_default()
                .push(JoinValue {
                    source: s.name.clone(),
                    authority: s.authority,
                    value: r.value.clone(),
                    confidence: r.confidence,
                    retrieved_at_ms: s.retrieved_at_ms,
                    age_ms: age_ms(s.retrieved_at_ms, now_ms),
                    stale: age_ms(s.retrieved_at_ms, now_ms) > s.freshness_ms,
                });
        }
    }

    let (mut value_count, mut stale_values, mut agreements, mut disagreements) = (0, 0, 0, 0);
    let mut fields: Vec<Value> = Vec::new();
    for ((ip, name), mut values) in groups {
        values.sort_by(|a, b| b.authority.cmp(&a.authority).then(a.source.cmp(&b.source)));
        value_count += values.len();
        stale_values += values.iter().filter(|v| v.stale).count();
        let unanimous = values.iter().all(|v| v.value == values[0].value);
        let status = if values.len() == 1 {
            "single"
        } else if unanimous {
            "unanimous"
        } else {
            "disagreement"
        };
        if values.len() > 1 && unanimous {
            agreements += 1;
        }
        let lines = if status == "disagreement" {
            disagreements += 1;
            vec![disagreement_line(&ip, &name, &values)]
        } else {
            Vec::new()
        };
        fields.push(Value::Struct {
            name: "IpJoinField".to_string(),
            fields: vec![
                ("ip".to_string(), Value::String(ip)),
                ("field".to_string(), Value::String(name)),
                ("status".to_string(), Value::String(status.to_string())),
                (
                    "values".to_string(),
                    Value::Array(values.iter().map(join_value_struct).collect()),
                ),
                (
                    "disagreement".to_string(),
                    Value::Array(lines.into_iter().map(Value::String).collect()),
                ),
            ],
        });
    }

    let source_info: Vec<Value> = ordered
        .iter()
        .map(|s| Value::Struct {
            name: "IpJoinSourceInfo".to_string(),
            fields: vec![
                ("name".to_string(), Value::String(s.name.clone())),
                ("authority".to_string(), Value::Int(s.authority as i128)),
                (
                    "retrieved_at_ms".to_string(),
                    Value::Int(s.retrieved_at_ms as i128),
                ),
                (
                    "age_ms".to_string(),
                    Value::Int(age_ms(s.retrieved_at_ms, now_ms) as i128),
                ),
                (
                    "stale".to_string(),
                    Value::Bool(age_ms(s.retrieved_at_ms, now_ms) > s.freshness_ms),
                ),
                (
                    "freshness_ms".to_string(),
                    Value::Int(s.freshness_ms as i128),
                ),
            ],
        })
        .collect();

    let field_count = fields.len();
    Ok(Value::Struct {
        name: "IpJoinReport".to_string(),
        fields: vec![
            ("fields".to_string(), Value::Array(fields)),
            ("sources".to_string(), Value::Array(source_info)),
            ("now_ms".to_string(), Value::Int(now_ms as i128)),
            ("field_count".to_string(), Value::Int(field_count as i128)),
            ("value_count".to_string(), Value::Int(value_count as i128)),
            ("stale_values".to_string(), Value::Int(stale_values as i128)),
            ("agreements".to_string(), Value::Int(agreements as i128)),
            (
                "disagreements".to_string(),
                Value::Int(disagreements as i128),
            ),
        ],
    })
}

fn join_dispatch(args: Vec<Value>) -> StdlibResult {
    let Some(Value::Array(items)) = args.first() else {
        return Err(format!(
            "ip.join: argument 1 expected []IpJoinSource, got {}",
            args.first().map(type_name).unwrap_or("nothing")
        ));
    };
    let now_ms = int_arg(&args, 1, "join")?;
    if now_ms < 0 {
        return Err(format!(
            "ip.join: now_ms {now_ms} is before the Unix epoch — an age cannot be measured \
             against a clock that has not started"
        ));
    }
    let sources: Vec<JoinSource> = items
        .iter()
        .map(parse_join_source)
        .collect::<Result<_, _>>()?;
    build_join(&sources, now_ms)
}

fn join_row_dispatch(args: Vec<Value>) -> StdlibResult {
    let confidence = match args.get(3) {
        None | Some(Value::Nil) => Value::Nil,
        Some(Value::Float(f)) if (0.0..=1.0).contains(f) => Value::Float(*f),
        Some(other) => {
            return Err(format!(
                "{CODE_JOIN_BAD_ROW}: ip.join_row: confidence must be a Float in 0..=1, got {}",
                type_name(other)
            ));
        }
    };
    Ok(Value::Struct {
        name: "IpJoinRow".to_string(),
        fields: vec![
            (
                "ip".to_string(),
                Value::String(str_arg(&args, 0, "join_row")?),
            ),
            (
                "field".to_string(),
                Value::String(str_arg(&args, 1, "join_row")?),
            ),
            (
                "value".to_string(),
                Value::String(str_arg(&args, 2, "join_row")?),
            ),
            ("confidence".to_string(), confidence),
        ],
    })
}

/// A source constructor for the same reason [`observation_dispatch`] exists: a
/// stdlib struct cannot be written as a literal in a `.tl` program, so without
/// this the declared `join` surface would be unreachable from a program.
fn join_source_dispatch(args: Vec<Value>) -> StdlibResult {
    let rows = match args.get(4) {
        Some(Value::Array(items)) => Value::Array(items.clone()),
        Some(other) => {
            return Err(format!(
                "{CODE_JOIN_BAD_SOURCE}: ip.join_source: rows must be []IpJoinRow, got {}",
                type_name(other)
            ));
        }
        None => {
            return Err(format!(
                "{CODE_JOIN_BAD_SOURCE}: ip.join_source: missing argument 5 (rows)"
            ));
        }
    };
    Ok(Value::Struct {
        name: "IpJoinSource".to_string(),
        fields: vec![
            (
                "name".to_string(),
                Value::String(str_arg(&args, 0, "join_source")?),
            ),
            (
                "authority".to_string(),
                Value::Int(int_arg(&args, 1, "join_source")? as i128),
            ),
            (
                "retrieved_at_ms".to_string(),
                Value::Int(int_arg(&args, 2, "join_source")? as i128),
            ),
            (
                "freshness_ms".to_string(),
                Value::Int(int_arg(&args, 3, "join_source")? as i128),
            ),
            ("rows".to_string(), rows),
        ],
    })
}

fn join_json_dispatch(args: Vec<Value>) -> StdlibResult {
    let v = args
        .first()
        .ok_or_else(|| "ip.join_json: missing argument 1 (IpJoinReport)".to_string())?;
    match v {
        Value::Struct { name, .. } if name == "IpJoinReport" => {}
        other => {
            return Err(format!(
                "ip.join_json: argument 1 expected IpJoinReport, got {}",
                value_label(other)
            ));
        }
    }
    serde_json::to_string_pretty(&value_json(v))
        .map(Value::String)
        .map_err(|e| format!("ip.join_json: {e}"))
}

// ── Value plumbing ──────────────────────────────────────────────────────────

fn field<'a>(fields: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

fn int_arg(args: &[Value], idx: usize, fname: &str) -> Result<i64, String> {
    match args.get(idx) {
        Some(Value::Int(i)) => i64::try_from(*i)
            .map_err(|_| format!("ip.{fname}: argument {} out of i64 range", idx + 1)),
        Some(other) => Err(format!(
            "ip.{fname}: argument {} expected Int, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("ip.{fname}: missing argument {}", idx + 1)),
    }
}

fn str_arg(args: &[Value], idx: usize, fname: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(format!(
            "ip.{fname}: argument {} expected String, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("ip.{fname}: missing argument {}", idx + 1)),
    }
}

fn opt_str_arg(args: &[Value], idx: usize, fname: &str) -> Result<Option<String>, String> {
    match args.get(idx) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.clone())),
        Some(Value::String(_)) | Some(Value::Nil) | None => Ok(None),
        Some(other) => Err(format!(
            "ip.{fname}: argument {} expected String?, got {}",
            idx + 1,
            type_name(other)
        )),
    }
}

fn handle_arg(args: &[Value], idx: usize, struct_name: &str, fname: &str) -> Result<u64, String> {
    let Some(Value::Struct { name, fields }) = args.get(idx) else {
        return Err(format!(
            "ip.{fname}: argument {} expected {struct_name}, got {}",
            idx + 1,
            args.get(idx).map(type_name).unwrap_or("nothing")
        ));
    };
    if name != struct_name {
        return Err(format!(
            "ip.{fname}: argument {} expected {struct_name}, got struct {name}",
            idx + 1
        ));
    }
    match field(fields, "handle") {
        Some(Value::Int(i)) if *i >= 0 => Ok(*i as u64),
        Some(Value::Int(i)) => Err(format!(
            "ip.{fname}: handle {i} is not a handle this module issued"
        )),
        Some(other) => Err(format!(
            "ip.{fname}: {struct_name}.handle expected Int, got {}",
            type_name(other)
        )),
        None => Err(format!(
            "ip.{fname}: {struct_name} carries no `handle`, so it is not a value this module \
             issued"
        )),
    }
}

fn table_value(id: u64, table: &AsnTable) -> Value {
    Value::Struct {
        name: "IpAsnTable".to_string(),
        fields: vec![
            ("handle".to_string(), Value::Int(id as i128)),
            ("source".to_string(), Value::String(table.source.clone())),
            ("rows".to_string(), Value::Int(table.rows.len() as i128)),
        ],
    }
}

fn cache_value(id: u64, cache: &Cache) -> Value {
    Value::Struct {
        name: "IpCache".to_string(),
        fields: vec![
            ("handle".to_string(), Value::Int(id as i128)),
            (
                "entries".to_string(),
                Value::Int(cache.entries.len() as i128),
            ),
        ],
    }
}

fn entry_value(source: &str, key: &str, e: &Entry, age: i64, stale: bool) -> Value {
    Value::Struct {
        name: "CacheEntry".to_string(),
        fields: vec![
            ("source".to_string(), Value::String(source.to_string())),
            ("key".to_string(), Value::String(key.to_string())),
            (
                "content_hash".to_string(),
                Value::String(e.content_hash.clone()),
            ),
            ("body".to_string(), Value::String(e.body.clone())),
            (
                "stored_at_ms".to_string(),
                Value::Int(e.stored_at_ms as i128),
            ),
            ("age_ms".to_string(), Value::Int(age as i128)),
            ("ttl_ms".to_string(), Value::Int(e.ttl_ms as i128)),
            ("stale".to_string(), Value::Bool(stale)),
        ],
    }
}

// ── Dispatch ────────────────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let function = function
        .strip_prefix("ip.")
        .or_else(|| function.strip_prefix("intel_ip."))
        .unwrap_or(function);
    match function {
        "load" => Some(load_dispatch(args)),
        "load_missing" => Some(load_missing_dispatch(args)),
        "lookup" => Some(lookup_dispatch(args)),
        "cache_new" => Some(cache_new_dispatch()),
        "cache_put" => Some(cache_put_dispatch(args)),
        "cache_get" => Some(cache_get_dispatch(args)),
        "cache_stats" => Some(cache_stats_dispatch(args)),
        "cluster" => Some(cluster_dispatch(args)),
        "observation" => Some(observation_dispatch(args)),
        "cluster_json" => Some(cluster_json_dispatch(args)),
        "geo_load" => Some(geo_load_dispatch(args)),
        "geo_lookup" => Some(geo_lookup_dispatch(args)),
        "geo_json" => Some(geo_json_dispatch(args)),
        "join" => Some(join_dispatch(args)),
        "join_row" => Some(join_row_dispatch(args)),
        "join_source" => Some(join_source_dispatch(args)),
        "join_json" => Some(join_json_dispatch(args)),
        _ => None,
    }
}

fn load_dispatch(args: Vec<Value>) -> StdlibResult {
    let explicit = opt_str_arg(&args, 0, "load")?;
    let table = load_table(explicit.as_deref())?;
    let id = register_table(table.clone());
    Ok(table_value(id, &table))
}

fn load_missing_dispatch(args: Vec<Value>) -> StdlibResult {
    let path = str_arg(&args, 0, "load_missing")?;
    // Preflight: report the same refusal `load` would give, without parsing a
    // real table. A present file is *not* an error here — it answers `present`.
    if std::path::Path::new(&path).is_file() {
        return Ok(Value::Bool(false));
    }
    Err(format!(
        "{CODE_TABLE_MISSING}: {path} (chosen by explicit) does not exist or is not a regular \
         file — set {ENV_TABLE} or pass a readable ip2asn-v4.tsv"
    ))
}

fn lookup_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = handle_arg(&args, 0, "IpAsnTable", "lookup")?;
    let ip = str_arg(&args, 1, "lookup")?;
    let table = table_by_handle(id)?;
    let row = lookup_row(&table, &ip)?;
    Ok(Value::Struct {
        name: "AsnMatch".to_string(),
        fields: vec![
            ("asn".to_string(), Value::Int(row.asn as i128)),
            (
                "prefix_len".to_string(),
                Value::Int(row.prefix_len() as i128),
            ),
            ("country".to_string(), Value::String(row.country)),
            ("description".to_string(), Value::String(row.description)),
            ("source".to_string(), Value::String(table.source.clone())),
        ],
    })
}

fn cache_new_dispatch() -> StdlibResult {
    let id = register_cache(Cache::default());
    Ok(cache_value(id, &Cache::default()))
}

fn cache_put_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = handle_arg(&args, 0, "IpCache", "cache_put")?;
    let source = str_arg(&args, 1, "cache_put")?;
    let key = str_arg(&args, 2, "cache_put")?;
    let body = str_arg(&args, 3, "cache_put")?;
    let ttl_ms = int_arg(&args, 4, "cache_put")?;
    let now_ms = int_arg(&args, 5, "cache_put")?;
    let entry = with_cache(id, |c| cache_put(c, &source, &key, &body, ttl_ms, now_ms))??;
    Ok(Value::Struct {
        name: "CacheWritten".to_string(),
        fields: vec![
            ("source".to_string(), Value::String(source)),
            ("key".to_string(), Value::String(key)),
            (
                "content_hash".to_string(),
                Value::String(entry.content_hash),
            ),
            (
                "stored_at_ms".to_string(),
                Value::Int(entry.stored_at_ms as i128),
            ),
            ("ttl_ms".to_string(), Value::Int(entry.ttl_ms as i128)),
        ],
    })
}

fn cache_get_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = handle_arg(&args, 0, "IpCache", "cache_get")?;
    let source = str_arg(&args, 1, "cache_get")?;
    let key = str_arg(&args, 2, "cache_get")?;
    let now_ms = int_arg(&args, 3, "cache_get")?;
    let (entry, stale) = with_cache(id, |c| cache_get(c, &source, &key, now_ms))??;
    let age = age_ms(entry.stored_at_ms, now_ms);
    Ok(entry_value(&source, &key, &entry, age, stale))
}

fn cache_stats_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = handle_arg(&args, 0, "IpCache", "cache_stats")?;
    let (entries, sources, stale_entries) = with_cache(id, |c| cache_stats(c))?;
    Ok(Value::Struct {
        name: "CacheStats".to_string(),
        fields: vec![
            ("entries".to_string(), Value::Int(entries as i128)),
            ("sources".to_string(), Value::Int(sources as i128)),
            (
                "stale_entries".to_string(),
                Value::Int(stale_entries as i128),
            ),
        ],
    })
}

fn observation_dispatch(args: Vec<Value>) -> StdlibResult {
    let ip = str_arg(&args, 0, "observation")?;
    if ip.trim().is_empty() {
        return Err(format!(
            "{CODE_CLUSTER_BAD_OBSERVATION}: ip.observation: argument 1 must be a non-empty \
             address literal, got an empty string"
        ));
    }
    let host = opt_str_arg(&args, 1, "observation")?;
    let asn = match args.get(2) {
        Some(Value::Int(i)) if *i > 0 => Value::Int(*i),
        Some(Value::Nil) | None => Value::Nil,
        Some(Value::Int(i)) => {
            return Err(format!(
                "{CODE_CLUSTER_BAD_OBSERVATION}: ip.observation: asn {i} is not an ASN — an \
                 unknown ASN is nil, never 0"
            ));
        }
        Some(other) => {
            return Err(format!(
                "ip.observation: argument 3 expected Int?, got {}",
                type_name(other)
            ));
        }
    };
    let text = |idx: usize| -> Result<Value, String> {
        Ok(match opt_str_arg(&args, idx, "observation")? {
            Some(s) => Value::String(s),
            None => Value::Nil,
        })
    };
    Ok(Value::Struct {
        name: "IpObservation".to_string(),
        fields: vec![
            ("ip".to_string(), Value::String(ip)),
            (
                "host".to_string(),
                match host {
                    Some(h) => Value::String(h),
                    None => Value::Nil,
                },
            ),
            ("asn".to_string(), asn),
            ("cert_sha256".to_string(), text(3)?),
            ("favicon_hash".to_string(), text(4)?),
            ("header_signature".to_string(), text(5)?),
        ],
    })
}

fn cluster_dispatch(args: Vec<Value>) -> StdlibResult {
    let obs_val = args.first().ok_or_else(|| {
        "ip.cluster: missing argument 1 ([]IpObservation) — clustering needs observations to \
         cluster"
            .to_string()
    })?;
    let Value::Array(items) = obs_val else {
        return Err(format!(
            "ip.cluster: argument 1 expected []IpObservation, got {}",
            type_name(obs_val)
        ));
    };
    let observations: Vec<Observation> = items
        .iter()
        .map(parse_observation)
        .collect::<Result<_, _>>()?;

    let (link_min, merge_min) = match args.get(1) {
        None | Some(Value::Nil) => (LINK_MIN_SCORE, MERGE_MIN_SCORE),
        Some(Value::Struct { name, fields }) if name == "IpClusterOptions" => (
            opt_score(
                field(fields, "link_min_score"),
                "link_min_score",
                LINK_MIN_SCORE,
            )?,
            opt_score(
                field(fields, "merge_min_score"),
                "merge_min_score",
                MERGE_MIN_SCORE,
            )?,
        ),
        Some(other) => {
            return Err(format!(
                "ip.cluster: argument 2 expected IpClusterOptions?, got {}",
                value_label(other)
            ));
        }
    };
    if !(0.0..=1.0).contains(&link_min) || !(0.0..=1.0).contains(&merge_min) || merge_min < link_min
    {
        return Err(format!(
            "{CODE_CLUSTER_BAD_OPTION}: link_min_score {link_min} / merge_min_score {merge_min} \
             must satisfy 0 <= link <= merge <= 1 — a merge floor below the link floor would \
             merge pairs the caller said were never linked"
        ));
    }

    let report = build_report(&observations, link_min, merge_min)?;
    Ok(report_value(&report))
}

fn value_label(v: &Value) -> String {
    match v {
        Value::Struct { name, .. } => format!("struct {name}"),
        other => type_name(other).to_string(),
    }
}

fn cluster_json_dispatch(args: Vec<Value>) -> StdlibResult {
    let v = args
        .first()
        .ok_or_else(|| "ip.cluster_json: missing argument 1 (IpClusterReport)".to_string())?;
    match v {
        Value::Struct { name, .. } if name == "IpClusterReport" => {}
        other => {
            return Err(format!(
                "ip.cluster_json: argument 1 expected IpClusterReport, got {}",
                value_label(other)
            ));
        }
    }
    serde_json::to_string_pretty(&value_json(v))
        .map(Value::String)
        .map_err(|e| format!("ip.cluster_json: {e}"))
}

// ── Tests ───────────────────────────────────────────────────────────────────

// Named `intel_ip_tests` rather than plain `tests` on purpose: the module is
// registered as `ip` (the .tl namespace), so a bare `tests` module would make
// the documented gate `cargo test --lib intel_ip` select zero tests and pass
// vacuously. The name keeps that gate meaningful.
#[cfg(test)]
mod intel_ip_tests {
    use super::*;

    const TSV: &str = "\
# ip2asn-v4 fixture — deliberately not sorted by prefix length\n\
10.0.0.0\t10.255.255.255\t64500\tUS\tEXAMPLE-CORP, US\n\
10.1.2.0\t10.1.2.255\t64501\tDE\tEXAMPLE-EDGE, DE\n\
192.0.2.0\t192.0.2.255\t64496\tZZ\tTEST-NET-1\n";

    fn table() -> AsnTable {
        parse_table(TSV, "fixture.tsv").expect("fixture parses")
    }

    #[test]
    fn longest_prefix_beats_an_earlier_shorter_match() {
        let t = table();
        // /8 appears first, /24 second: the /24 must win.
        let row = lookup_row(&t, "10.1.2.7").unwrap();
        assert_eq!(row.asn, 64501);
        assert_eq!(row.prefix_len(), 24);
        // Outside the /24 but inside the /8: the /8 is the longest match.
        let row = lookup_row(&t, "10.9.9.9").unwrap();
        assert_eq!(row.asn, 64500);
        assert_eq!(row.prefix_len(), 8);
    }

    #[test]
    fn unmatched_address_is_a_coded_refusal() {
        let err = lookup_row(&table(), "203.0.113.9").unwrap_err();
        assert!(err.starts_with(CODE_NOT_IN_TABLE), "{err}");
        assert!(err.contains("not ASN 0"), "{err}");
    }

    #[test]
    fn missing_table_refuses_and_names_the_path() {
        let path = "/nonexistent/tallow-ip2asn-does-not-exist.tsv";
        let err = load_path(path, "explicit").unwrap_err();
        assert!(err.starts_with(CODE_TABLE_MISSING), "{err}");
        assert!(err.contains(path), "refusal must name the path: {err}");
        assert!(
            err.contains("explicit"),
            "refusal must name the resolution step: {err}"
        );
    }

    #[test]
    fn malformed_line_reports_its_line_number_and_voids_the_table() {
        let bad = "192.0.2.0\t192.0.2.255\t64496\tZZ\tTEST-NET-1\n\
                   198.51.100.0\tnot-an-address\t64497\tZZ\tBROKEN\n\
                   203.0.113.0\t203.0.113.255\t64498\tZZ\tLATER-ROW\n";
        let err = parse_table(bad, "bad.tsv").unwrap_err();
        assert!(err.starts_with(CODE_TABLE_MALFORMED), "{err}");
        assert!(err.contains("bad.tsv:2:"), "must name source:line: {err}");
        assert!(
            err.contains("not-an-address"),
            "must quote the offending field: {err}"
        );
    }

    #[test]
    fn reversed_range_is_malformed_not_silently_accepted() {
        let bad = "203.0.113.255\t203.0.113.0\t64498\tZZ\tREVERSED\n";
        let err = parse_table(bad, "bad.tsv").unwrap_err();
        assert!(err.contains("bad.tsv:1:"), "{err}");
    }

    #[test]
    fn header_comment_and_blank_lines_are_tolerated() {
        let with_header = "\u{feff}# comment\n\n\
            range_start\trange_end\tASN\tcountry\tdescription\n\
            192.0.2.0\t192.0.2.255\t64496\tZZ\tTEST-NET-1\n";
        let t = parse_table(with_header, "h.tsv").unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(lookup_row(&t, "192.0.2.5").unwrap().asn, 64496);
    }

    #[test]
    fn empty_table_is_refused() {
        let err = parse_table("# only comments\n\n", "empty.tsv").unwrap_err();
        assert!(err.starts_with(CODE_TABLE_EMPTY), "{err}");
    }

    #[test]
    fn resolution_order_is_explicit_then_env_then_default() {
        assert_eq!(
            resolve_source(Some("/a.tsv"), Some("/b.tsv")),
            ("/a.tsv".to_string(), "explicit")
        );
        assert_eq!(
            resolve_source(Some("  "), Some("/b.tsv")),
            ("/b.tsv".to_string(), "env:TALLOW_IP2ASN")
        );
        assert_eq!(
            resolve_source(None, None),
            (DEFAULT_TABLE.to_string(), "default")
        );
    }

    #[test]
    fn ipv6_is_refused_rather_than_answered_from_a_v4_table() {
        let err = lookup_row(&table(), "2001:db8::1").unwrap_err();
        assert!(err.starts_with(CODE_UNSUPPORTED_FAMILY), "{err}");
    }

    #[test]
    fn cache_hit_returns_body_and_content_address() {
        let mut c = Cache::default();
        let written = cache_put(&mut c, "asn", "10.1.2.7", "AS64501", 60_000, 1_000).unwrap();
        let (entry, stale) = cache_get(&c, "asn", "10.1.2.7", 31_000).unwrap();
        assert!(!stale);
        assert_eq!(entry.body, "AS64501");
        assert_eq!(entry.content_hash, written.content_hash);
        assert_eq!(entry.content_hash, sha256_hex("AS64501"));
        assert_eq!(entry.content_hash.len(), 64);
    }

    #[test]
    fn entry_past_ttl_is_a_stale_hit_with_age_not_an_error() {
        let mut c = Cache::default();
        cache_put(&mut c, "asn", "k", "body", 1_000, 5_000).unwrap();
        let (entry, stale) = cache_get(&c, "asn", "k", 8_500).unwrap();
        assert!(stale, "past TTL must be reported stale: {:?}", entry.ttl_ms);
        assert_eq!(age_ms(entry.stored_at_ms, 8_500), 3_500);
        // Exactly at TTL is still fresh; strictly past is stale.
        assert!(!cache_get(&c, "asn", "k", 6_000).unwrap().1);
        assert!(cache_get(&c, "asn", "k", 6_001).unwrap().1);
    }

    #[test]
    fn absence_is_a_cache_miss_distinct_from_stale() {
        let c = Cache::default();
        let err = cache_get(&c, "asn", "absent", 1).unwrap_err();
        assert!(err.starts_with(CODE_CACHE_MISS), "{err}");
        assert!(err.contains("stale, not missed"), "{err}");
    }

    #[test]
    fn identical_body_under_two_keys_has_the_same_content_address() {
        let mut c = Cache::default();
        let a = cache_put(&mut c, "asn", "k1", "same bytes", 10, 0).unwrap();
        let b = cache_put(&mut c, "other", "k2", "same bytes", 10, 0).unwrap();
        assert_eq!(a.content_hash, b.content_hash);
        let other = cache_put(&mut c, "asn", "k3", "different bytes", 10, 0).unwrap();
        assert_ne!(a.content_hash, other.content_hash);
    }

    #[test]
    fn ttl_is_per_entry_and_stats_count_sources_and_staleness() {
        let mut c = Cache::default();
        // stored_at far in the past with a tiny TTL: stale against the wall clock.
        cache_put(&mut c, "asn", "a", "x", 1, 0).unwrap();
        cache_put(&mut c, "asn", "b", "y", 1, 0).unwrap();
        cache_put(&mut c, "rpki", "c", "z", i64::MAX, 0).unwrap();
        let (entries, sources, stale) = cache_stats(&c);
        assert_eq!(entries, 3);
        assert_eq!(sources, 2);
        assert_eq!(stale, 2);
    }

    #[test]
    fn dispatch_wires_lookup_and_refuses_a_foreign_handle() {
        let id = register_table(table());
        let out = dispatch(
            "ip.lookup",
            vec![table_value(id, &table()), Value::String("10.1.2.7".into())],
        )
        .expect("routed")
        .expect("hit");
        match out {
            Value::Struct { name, fields } => {
                assert_eq!(name, "AsnMatch");
                assert!(matches!(field(&fields, "asn"), Some(Value::Int(64501))));
                assert!(matches!(field(&fields, "prefix_len"), Some(Value::Int(24))));
            }
            other => panic!("expected struct, got {}", type_name(&other)),
        }
        let bogus = Value::Struct {
            name: "IpAsnTable".to_string(),
            fields: vec![("handle".to_string(), Value::Int(999_999))],
        };
        let err = dispatch("ip.lookup", vec![bogus, Value::String("10.1.2.7".into())])
            .unwrap()
            .unwrap_err();
        assert!(err.starts_with(CODE_TABLE_UNKNOWN), "{err}");
    }

    // ── N36: clustering ─────────────────────────────────────────────────────

    fn ob(
        ip: &str,
        asn: Option<u32>,
        cert: Option<&str>,
        favicon: Option<&str>,
        headers: Option<&str>,
    ) -> Observation {
        Observation {
            ip: ip.to_string(),
            host: String::new(),
            asn,
            cert_sha256: cert.map(str::to_string),
            favicon_hash: favicon.map(str::to_string),
            header_signature: headers.map(str::to_string),
        }
    }

    fn cluster_of(obs: Vec<Observation>) -> ClusterReport {
        build_report(&obs, LINK_MIN_SCORE, MERGE_MIN_SCORE).expect("clusters")
    }

    #[test]
    fn shared_certificate_alone_forms_a_cluster() {
        // Different ASNs and nothing else in common: the certificate is the
        // operator-level artifact, so this must merge.
        let r = cluster_of(vec![
            ob("10.0.0.1", Some(64500), Some("aa11"), None, None),
            ob("10.0.0.2", Some(64501), Some("aa11"), None, None),
        ]);
        assert_eq!(r.clusters.len(), 1, "shared cert must form one cluster");
        assert_eq!(r.clusters[0].members, vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(r.clusters[0].confidence, W_CERT);
        assert_eq!(r.clusters[0].evidence[0].signals, vec!["cert_sha256"]);
        assert!(r.linked_not_merged.is_empty());
    }

    #[test]
    fn shared_favicon_plus_headers_merge_without_a_certificate() {
        let r = cluster_of(vec![
            ob("10.0.0.1", None, None, Some("f00d"), Some("nginx|php")),
            ob("10.0.0.2", None, None, Some("f00d"), Some("nginx|php")),
        ]);
        assert_eq!(r.clusters.len(), 1);
        assert_eq!(round3(W_FAVICON + W_HEADER), r.clusters[0].confidence);
        assert_eq!(
            r.clusters[0].evidence[0].signals,
            vec!["favicon_hash", "header_signature"]
        );
    }

    #[test]
    fn an_unlinked_observation_is_reported_as_unclustered_not_dropped() {
        let obs = vec![
            ob("10.0.0.1", Some(64500), Some("AA11"), None, None),
            ob("10.0.0.2", Some(64501), Some("AA11"), None, None),
            ob("10.0.0.9", Some(64500), None, None, None),
        ];
        let r = cluster_of(obs);
        assert_eq!(r.clusters.len(), 1);
        assert_eq!(r.unclustered, vec!["10.0.0.9".to_string()]);
        let in_clusters: usize = r.clusters.iter().map(|c| c.members.len()).sum();
        assert_eq!(
            in_clusters + r.unclustered.len(),
            r.observations,
            "every observation must be accounted for exactly once"
        );
    }

    #[test]
    fn a_shared_asn_alone_never_clusters_and_never_links() {
        // The exact case the design exists to prevent: every Cloudflare-fronted
        // site shares AS13335 and none of them is one operator.
        let r = cluster_of(vec![
            ob("10.0.0.1", Some(13335), None, None, None),
            ob("10.0.0.2", Some(13335), None, None, None),
        ]);
        assert!(r.clusters.is_empty(), "shared ASN must not cluster");
        assert!(
            r.linked_not_merged.is_empty(),
            "shared ASN is below the link floor, so it is not even a link"
        );
        assert_eq!(r.observations, 2);
    }

    #[test]
    fn a_weak_pair_is_reported_as_linked_but_not_merged() {
        let r = cluster_of(vec![
            ob("10.0.0.1", None, None, Some("f00d"), None),
            ob("10.0.0.2", None, None, Some("f00d"), None),
        ]);
        assert!(r.clusters.is_empty(), "favicon alone must not merge");
        assert_eq!(r.linked_not_merged.len(), 1);
        let link = &r.linked_not_merged[0];
        assert_eq!(link.signals, vec!["favicon_hash"]);
        assert_eq!(link.score, W_FAVICON);
        assert!(
            evidence_line(link).contains("favicon_hash"),
            "the refusal must name the signal: {}",
            evidence_line(link)
        );
    }

    #[test]
    fn every_member_of_a_cluster_is_explained_by_a_named_signal() {
        // a—b on a cert, b—c on favicon+headers: a chain, not a clique.
        let r = cluster_of(vec![
            ob("10.0.0.1", None, Some("aa11"), None, None),
            ob(
                "10.0.0.2",
                None,
                Some("aa11"),
                Some("f00d"),
                Some("nginx|php"),
            ),
            ob("10.0.0.3", None, None, Some("f00d"), Some("nginx|php")),
            ob("10.0.0.9", None, None, None, None),
        ]);
        assert_eq!(r.clusters.len(), 1, "the lone endpoint is not a cluster");
        let c = &r.clusters[0];
        assert_eq!(c.members, vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
        for m in &c.members {
            let explained = c
                .evidence
                .iter()
                .any(|l| (&l.a == m || &l.b == m) && !l.signals.is_empty());
            assert!(explained, "member {m} has no evidence naming a signal");
        }
        // Confidence is the weakest merge edge in the chain, not an average.
        assert_eq!(c.confidence, W_CERT);
        assert!(!c.evidence.is_empty() && c.evidence.iter().all(|l| l.score >= MERGE_MIN_SCORE));
    }

    #[test]
    fn a_shared_asn_corroborates_but_does_not_decide() {
        let r = cluster_of(vec![
            ob("10.0.0.1", Some(64500), Some("aa11"), None, None),
            ob("10.0.0.2", Some(64500), Some("aa11"), None, None),
        ]);
        assert_eq!(r.clusters.len(), 1);
        // cert + asn, and the link names both signals.
        assert_eq!(
            r.clusters[0].evidence[0].signals,
            vec!["cert_sha256", "asn"]
        );
        assert_eq!(round3(W_CERT + W_ASN), r.clusters[0].confidence);
    }

    #[test]
    fn the_thresholds_are_visible_and_raising_one_holds_a_cluster_apart() {
        let obs = vec![
            ob("10.0.0.1", None, Some("aa11"), None, None),
            ob("10.0.0.2", None, Some("aa11"), None, None),
        ];
        let r = build_report(&obs, LINK_MIN_SCORE, 0.80).expect("clusters");
        assert!(r.clusters.is_empty());
        assert_eq!(r.linked_not_merged.len(), 1);
        assert_eq!(r.merge_min, 0.80);
        let bad = cluster_dispatch(vec![
            Value::Array(vec![]),
            Value::Struct {
                name: "IpClusterOptions".to_string(),
                fields: vec![
                    ("link_min_score".to_string(), Value::Float(0.9)),
                    ("merge_min_score".to_string(), Value::Float(0.2)),
                ],
            },
        ])
        .unwrap_err();
        assert!(bad.starts_with(CODE_CLUSTER_BAD_OPTION), "{bad}");
    }

    #[test]
    fn json_is_byte_identical_across_runs_and_input_order() {
        let forward = vec![
            ob("10.0.0.1", None, Some("aa11"), Some("f00d"), None),
            ob("10.0.0.2", None, Some("aa11"), None, None),
            ob("10.0.0.3", None, None, Some("f00d"), Some("nginx")),
        ];
        let mut backward = forward.clone();
        backward.reverse();
        let a = serde_json::to_string_pretty(&value_json(&report_value(&cluster_of(forward))))
            .expect("json");
        let b = serde_json::to_string_pretty(&value_json(&report_value(&cluster_of(backward))))
            .expect("json");
        assert_eq!(a, b, "clustering must not depend on input order");
        assert!(a.contains("evidence_lines"), "{a}");
        assert!(
            a.contains("merge_min_score"),
            "thresholds must be visible: {a}"
        );
        assert!(a.contains("cert_sha256"), "{a}");
    }

    #[test]
    fn hashes_are_normalised_but_a_different_hash_is_not_shared() {
        let mk = |ip: &str, cert: &str| Value::Struct {
            name: "IpObservation".to_string(),
            fields: vec![
                ("ip".to_string(), Value::String(ip.to_string())),
                ("cert_sha256".to_string(), Value::String(cert.to_string())),
            ],
        };
        let out = dispatch(
            "ip.cluster",
            vec![Value::Array(vec![
                mk("10.0.0.1", "  AA11  "),
                mk("10.0.0.2", "aa11"),
            ])],
        )
        .expect("routed")
        .expect("cluster");
        let json = dispatch("ip.cluster_json", vec![out])
            .expect("routed")
            .expect("json");
        match json {
            Value::String(s) => {
                // Both spellings normalise to one digest, so the pair merges;
                // the value itself is not echoed, the signal name is.
                assert!(s.contains("cert_sha256"), "{s}");
                assert!(
                    s.contains("\"size\": 2"),
                    "case/space must not split it: {s}"
                );
            }
            other => panic!("expected String, got {}", type_name(&other)),
        }

        let apart = cluster_of(vec![
            ob("10.0.0.1", None, Some("aa11"), None, None),
            ob("10.0.0.2", None, Some("bb22"), None, None),
        ]);
        assert!(apart.clusters.is_empty());
        assert!(apart.linked_not_merged.is_empty());
    }

    #[test]
    fn observation_builds_a_value_the_clusterer_accepts() {
        // stdlib struct types cannot be written as .tl literals (typeck never
        // loads stdlib struct declarations), so the caller needs a constructor
        // or the declared surface is unreachable from a program.
        let a = dispatch(
            "ip.observation",
            vec![
                Value::String("10.0.0.2".into()),
                Value::Nil,
                Value::Int(64501),
                Value::String("AA11".into()),
                Value::Nil,
                Value::Nil,
            ],
        )
        .expect("routed")
        .expect("observation");
        let b = dispatch(
            "ip.observation",
            vec![
                Value::String("10.0.0.1".into()),
                Value::String("a.example".into()),
                Value::Nil,
                Value::String("aa11".into()),
                Value::Nil,
                Value::Nil,
            ],
        )
        .expect("routed")
        .expect("observation");
        let report = dispatch("ip.cluster", vec![Value::Array(vec![a, b])])
            .expect("routed")
            .expect("cluster");
        match report {
            Value::Struct { fields, .. } => {
                let Some(Value::Array(clusters)) = field(&fields, "clusters") else {
                    panic!("no clusters field");
                };
                assert_eq!(clusters.len(), 1);
                let Value::Struct { fields, .. } = &clusters[0] else {
                    panic!("cluster is not a struct");
                };
                assert!(matches!(field(fields, "members"), Some(Value::Array(m)) if m.len() == 2));
                // The hostname travels into the evidence line for a human.
                let Some(Value::Array(lines)) = field(fields, "evidence_lines") else {
                    panic!("no evidence_lines");
                };
                assert!(
                    matches!(lines.first(), Some(Value::String(s)) if s.contains("a.example")),
                    "{lines:?}"
                );
            }
            other => panic!("expected struct, got {}", type_name(&other)),
        }
        // An ASN of 0 is refused rather than silently treated as unknown.
        let err = dispatch(
            "ip.observation",
            vec![Value::String("10.0.0.3".into()), Value::Nil, Value::Int(0)],
        )
        .unwrap()
        .unwrap_err();
        assert!(err.starts_with(CODE_CLUSTER_BAD_OBSERVATION), "{err}");
    }

    #[test]
    fn one_address_observed_twice_is_refused() {
        let err = build_report(
            &[
                ob("10.0.0.1", None, Some("aa11"), None, None),
                ob("10.0.0.1", None, None, Some("f00d"), None),
            ],
            LINK_MIN_SCORE,
            MERGE_MIN_SCORE,
        )
        .unwrap_err();
        assert!(err.starts_with(CODE_CLUSTER_DUPLICATE), "{err}");
    }

    // ── N34: geolocation with uncertainty ───────────────────────────────────

    // A nested /16 inside a /8 so the fixture also pins longest-prefix order.
    const GEO_TSV: &str = "\
# start\tend\tcountry\tregion\tcity\taccuracy_km\n\
10.0.0.0\t10.255.255.255\tDE\tBavaria\tBerlin\t400\n\
10.1.0.0\t10.1.255.255\tDE\tBavaria\tMunich\t10\n";

    const GEO_NO_ACCURACY: &str = "\
10.1.0.0\t10.1.255.255\tDE\tBavaria\tMunich\n";

    fn geo() -> GeoTable {
        parse_geo_table(GEO_TSV, "geo.tsv").expect("fixture parses")
    }

    #[test]
    fn a_row_with_an_accuracy_radius_returns_city_radius_and_confidence() {
        let a = geo_lookup_row(&geo(), "10.1.2.3").expect("located");
        assert_eq!(a.country, "DE");
        assert_eq!(a.region, "Bavaria");
        assert_eq!(a.city.as_deref(), Some("Munich"));
        assert_eq!(a.accuracy_km, Some(10.0));
        // 10 km sits in the city band, and the confidence is the constant that
        // band names — not a number invented at the call site.
        assert_eq!(a.confidence, GEO_CONF_CITY);
        assert_eq!(a.code, None);
        assert_eq!(a.source, "geo.tsv");
        // The /16 wins over the /8 that also covers this address.
        let coarse = geo_lookup_row(&geo(), "10.9.9.9").expect("located");
        assert_eq!(coarse.city.as_deref(), Some("Berlin"));
        assert_eq!(coarse.confidence, GEO_CONF_COUNTRY);
    }

    #[test]
    fn a_city_without_an_accuracy_radius_is_refused_and_downgraded() {
        let table = parse_geo_table(GEO_NO_ACCURACY, "no-acc.tsv").expect("fixture parses");
        let a = geo_lookup_row(&table, "10.1.2.3").expect("located");
        // Country and region always; the bare city name is *gone*, because a
        // city with no radius reads as exact and is not.
        assert_eq!(a.country, "DE");
        assert_eq!(a.region, "Bavaria");
        assert_eq!(a.city, None, "an unqualified city must not be printed");
        assert_eq!(a.accuracy_km, None);
        assert_eq!(a.code, Some(CODE_GEO_CITY_UNQUALIFIED));
        assert_eq!(a.confidence, GEO_CONF_ADMIN);
        assert!(
            a.confidence < GEO_CONF_COUNTRY,
            "an unqualified answer must not outrank a radius-qualified one"
        );
    }

    #[test]
    fn an_accuracy_radius_without_a_city_is_refused_the_other_way() {
        let table = parse_geo_table("10.1.0.0\t10.1.255.255\tDE\tBavaria\t\t10\n", "r.tsv")
            .expect("fixture parses");
        let a = geo_lookup_row(&table, "10.1.2.3").expect("located");
        assert_eq!(a.city, None);
        assert_eq!(a.accuracy_km, None, "a radius of no point is not a radius");
        assert_eq!(a.code, Some(CODE_GEO_RADIUS_UNQUALIFIED));
    }

    #[test]
    fn geo_unknown_address_and_bad_input_are_coded_refusals() {
        let err = geo_lookup_row(&geo(), "203.0.113.9").unwrap_err();
        assert!(err.starts_with(CODE_NOT_IN_TABLE), "{err}");
        let err = geo_lookup_row(&geo(), "2001:db8::1").unwrap_err();
        assert!(err.starts_with(CODE_UNSUPPORTED_FAMILY), "{err}");
        let err = geo_lookup_row(&geo(), "not-an-ip").unwrap_err();
        assert!(err.starts_with(CODE_BAD_ADDRESS), "{err}");
    }

    #[test]
    fn geo_malformed_row_names_its_line_and_voids_the_table() {
        let bad = "10.0.0.0\t10.255.255.255\tDE\tBavaria\tBerlin\t800\n\
                   10.1.0.0\t10.1.255.255\tDE\tBavaria\tMunich\twide\n";
        let err = parse_geo_table(bad, "bad.tsv").unwrap_err();
        assert!(err.starts_with(CODE_TABLE_MALFORMED), "{err}");
        assert!(err.contains("bad.tsv:2:"), "must name source:line: {err}");
        assert!(err.contains("wide"), "must quote the field: {err}");
    }

    #[test]
    fn geo_missing_table_refuses_and_names_the_path() {
        let path = "/nonexistent/tallow-geo-does-not-exist.tsv";
        let err = load_geo_path(path, "explicit").unwrap_err();
        assert!(err.starts_with(CODE_TABLE_MISSING), "{err}");
        assert!(err.contains(path), "{err}");
        assert!(err.contains("explicit"), "{err}");
    }

    #[test]
    fn the_confidence_mapping_is_the_documented_one() {
        let cases = [
            (None, GEO_CONF_ADMIN),
            (Some(0.0), GEO_CONF_TIGHT),
            (Some(GEO_KM_TIGHT), GEO_CONF_TIGHT),
            (Some(GEO_KM_TIGHT + 0.1), GEO_CONF_CITY),
            (Some(GEO_KM_CITY), GEO_CONF_CITY),
            (Some(GEO_KM_CITY + 0.1), GEO_CONF_REGION),
            (Some(GEO_KM_REGION), GEO_CONF_REGION),
            (Some(GEO_KM_COUNTRY), GEO_CONF_COUNTRY),
            (Some(GEO_KM_COUNTRY + 1.0), GEO_CONF_CONTINENT),
        ];
        for (km, expected) in cases {
            assert_eq!(geo_confidence(km), expected, "radius {km:?}");
        }
    }

    #[test]
    fn geo_dispatch_loads_looks_up_and_refuses_a_foreign_handle() {
        let table = geo();
        let id = register_geo_table(table.clone());
        let out = dispatch(
            "ip.geo_lookup",
            vec![
                geo_table_value(id, &table),
                Value::String("10.1.2.3".into()),
            ],
        )
        .expect("routed")
        .expect("located");
        match &out {
            Value::Struct { name, fields } => {
                assert_eq!(name, "GeoAnswer");
                assert!(matches!(
                    field(fields, "city"),
                    Some(Value::String(c)) if c == "Munich"
                ));
                assert!(
                    matches!(field(fields, "confidence"), Some(Value::Float(f)) if *f == GEO_CONF_CITY)
                );
            }
            other => panic!("expected struct, got {}", type_name(other)),
        }
        let json = dispatch("ip.geo_json", vec![out])
            .expect("routed")
            .expect("json");
        match json {
            Value::String(s) => {
                assert!(s.contains("\"city\": \"Munich\""), "{s}");
                assert!(s.contains("\"accuracy_km\": 10.0"), "{s}");
            }
            other => panic!("expected String, got {}", type_name(&other)),
        }
        let bogus = Value::Struct {
            name: "IpGeoTable".to_string(),
            fields: vec![("handle".to_string(), Value::Int(999_999))],
        };
        let err = dispatch(
            "ip.geo_lookup",
            vec![bogus, Value::String("10.1.2.3".into())],
        )
        .unwrap()
        .unwrap_err();
        assert!(err.starts_with(CODE_TABLE_UNKNOWN), "{err}");
    }

    // ── N35: multi-source join ──────────────────────────────────────────────

    fn jrow(ip: &str, field_name: &str, value: &str) -> JoinRow {
        JoinRow {
            ip: ip.into(),
            field: field_name.into(),
            value: value.into(),
            confidence: None,
        }
    }

    fn jsrc(name: &str, authority: i64, at: i64, fresh: i64, rows: Vec<JoinRow>) -> JoinSource {
        JoinSource {
            name: name.into(),
            authority,
            retrieved_at_ms: at,
            freshness_ms: fresh,
            rows,
        }
    }

    fn sub<'a>(v: &'a Value, name: &str) -> &'a Value {
        match v {
            Value::Struct { fields, .. } => field(fields, name).unwrap_or(&Value::Nil),
            _ => &Value::Nil,
        }
    }

    fn two_sources() -> Vec<JoinSource> {
        // maxmind is more authoritative and current; rpki is older, past its
        // horizon, and disagrees about the country — the case that must not be
        // silently resolved in favour of the better-ranked source.
        vec![
            jsrc(
                "maxmind",
                90,
                100_000,
                3_600_000,
                vec![
                    jrow("10.0.0.1", "asn", "AS64500"),
                    jrow("10.0.0.1", "country", "DE"),
                ],
            ),
            jsrc(
                "rpki",
                60,
                1_000,
                60_000,
                vec![
                    jrow("10.0.0.1", "asn", "AS64500"),
                    jrow("10.0.0.1", "country", "NL"),
                ],
            ),
        ]
    }

    #[test]
    fn agreement_and_disagreement_are_both_reported_per_field() {
        let mut sources = two_sources();
        sources.reverse(); // order must not matter
        let report = build_join(&sources, 100_000).expect("join");
        let Value::Array(fields) = sub(&report, "fields") else {
            panic!("no fields array");
        };
        assert_eq!(fields.len(), 2);
        // Fields are ordered by (ip, field): asn before country.
        assert!(matches!(sub(&fields[0], "field"), Value::String(f) if f == "asn"));
        assert!(matches!(sub(&fields[0], "status"), Value::String(s) if s == "unanimous"));
        assert!(matches!(sub(&fields[1], "field"), Value::String(f) if f == "country"));
        assert!(matches!(sub(&fields[1], "status"), Value::String(s) if s == "disagreement"));

        let Value::Array(values) = sub(&fields[1], "values") else {
            panic!("no values array");
        };
        assert_eq!(values.len(), 2);
        // Authority orders the display: the 90 comes first ...
        assert!(matches!(sub(&values[0], "source"), Value::String(s) if s == "maxmind"));
        assert!(matches!(sub(&values[0], "stale"), Value::Bool(false)));
        // ... but the lower-authority disagreement is still shown, with its age.
        assert!(matches!(sub(&values[1], "source"), Value::String(s) if s == "rpki"));
        assert!(matches!(sub(&values[1], "age_ms"), Value::Int(99_000)));
        assert!(matches!(sub(&values[1], "stale"), Value::Bool(true)));
        assert!(matches!(sub(&values[1], "value"), Value::String(v) if v == "NL"));

        // The disagreement entry names who said what — no winner, no average.
        let Value::Array(lines) = sub(&fields[1], "disagreement") else {
            panic!("no disagreement lines");
        };
        let Value::String(line) = &lines[0] else {
            panic!("line is not a string");
        };
        for needle in ["DE", "NL", "maxmind", "rpki", "stale"] {
            assert!(line.contains(needle), "{needle} missing from: {line}");
        }
        // A field struct carries the claims only: no `value`/`winner` field for a
        // silent resolution to hide in.
        if let Value::Struct { fields: fs, .. } = &fields[1] {
            assert_eq!(
                fs.len(),
                5,
                "field struct must be ip/field/status/values/disagreement"
            );
        }

        assert!(matches!(sub(&report, "agreements"), Value::Int(1)));
        assert!(matches!(sub(&report, "disagreements"), Value::Int(1)));
        assert!(matches!(sub(&report, "value_count"), Value::Int(4)));
        assert!(matches!(sub(&report, "stale_values"), Value::Int(2)));
        assert!(matches!(sub(&report, "field_count"), Value::Int(2)));
        // Sources are echoed with the horizon each value was judged against.
        let Value::Array(infos) = sub(&report, "sources") else {
            panic!("no sources array");
        };
        assert!(matches!(sub(&infos[1], "name"), Value::String(s) if s == "rpki"));
        assert!(matches!(sub(&infos[1], "freshness_ms"), Value::Int(60_000)));
    }

    #[test]
    fn join_json_is_byte_identical_across_input_order() {
        let forward = two_sources();
        let mut backward = forward.clone();
        backward.reverse();
        let a = serde_json::to_string_pretty(&value_json(
            &build_join(&forward, 100_000).expect("join"),
        ))
        .expect("json");
        let b = serde_json::to_string_pretty(&value_json(
            &build_join(&backward, 100_000).expect("join"),
        ))
        .expect("json");
        assert_eq!(a, b, "the join must not depend on source order");
        assert!(a.contains("\"status\": \"disagreement\""), "{a}");
        assert!(a.contains("\"stale\": true"), "{a}");
    }

    #[test]
    fn a_missing_timestamp_is_a_refusal_not_now() {
        let source = dispatch(
            "ip.join_source",
            vec![
                Value::String("maxmind".into()),
                Value::Int(90),
                Value::Int(0),
                Value::Int(1_000),
                Value::Array(vec![]),
            ],
        )
        .expect("routed")
        .expect("source");
        let err = dispatch(
            "ip.join",
            vec![Value::Array(vec![source]), Value::Int(100_000)],
        )
        .unwrap()
        .unwrap_err();
        assert!(err.starts_with(CODE_JOIN_BAD_SOURCE), "{err}");
        assert!(err.contains("current time is not evidence"), "{err}");
    }

    #[test]
    fn join_source_and_row_constructors_reach_the_declared_surface() {
        // Without constructors the declared surface is unreachable from a .tl
        // program, because a stdlib struct cannot be written as a literal.
        let row = |ip: &str, f: &str, v: &str, c: Value| {
            dispatch(
                "ip.join_row",
                vec![
                    Value::String(ip.into()),
                    Value::String(f.into()),
                    Value::String(v.into()),
                    c,
                ],
            )
            .expect("routed")
            .expect("row")
        };
        let src = |name: &str, auth: i128, at: i128, fresh: i128, rows: Vec<Value>| {
            dispatch(
                "ip.join_source",
                vec![
                    Value::String(name.into()),
                    Value::Int(auth),
                    Value::Int(at),
                    Value::Int(fresh),
                    Value::Array(rows),
                ],
            )
            .expect("routed")
            .expect("source")
        };
        let report = dispatch(
            "ip.join",
            vec![
                Value::Array(vec![
                    src(
                        "maxmind",
                        90,
                        100_000,
                        3_600_000,
                        vec![row("10.0.0.1", "asn", "AS64500", Value::Float(0.9))],
                    ),
                    src(
                        "rpki",
                        60,
                        1_000,
                        60_000,
                        vec![row("10.0.0.1", "asn", "AS64501", Value::Nil)],
                    ),
                ]),
                Value::Int(100_000),
            ],
        )
        .expect("routed")
        .expect("join");
        let json = dispatch("ip.join_json", vec![report])
            .expect("routed")
            .expect("json");
        match json {
            Value::String(s) => {
                assert!(s.contains("AS64500") && s.contains("AS64501"), "{s}");
                assert!(s.contains("\"confidence\": 0.9"), "{s}");
                assert!(s.contains("\"disagreements\": 1"), "{s}");
            }
            other => panic!("expected String, got {}", type_name(&other)),
        }

        // One source reporting one field twice is refused: one source, one answer.
        let dup = dispatch(
            "ip.join",
            vec![
                Value::Array(vec![src(
                    "maxmind",
                    90,
                    100_000,
                    1_000,
                    vec![
                        row("10.0.0.1", "asn", "AS64500", Value::Nil),
                        row("10.0.0.1", "asn", "AS64501", Value::Nil),
                    ],
                )]),
                Value::Int(100_000),
            ],
        )
        .unwrap()
        .unwrap_err();
        assert!(dup.starts_with(CODE_JOIN_DUPLICATE), "{dup}");
    }
}
