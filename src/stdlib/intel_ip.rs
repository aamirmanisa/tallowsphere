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
}
