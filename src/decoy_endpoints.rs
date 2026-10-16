//! Decoy endpoints — self-honeypot surfaces for the operator's own estate
//! (frozen interface §4 / B5.6.1–B5.6.3).
//!
//! A decoy endpoint is a plausible-looking page an operator deploys on their
//! *own* infrastructure purely as a tripwire: nothing legitimate should ever
//! reach it, so any visit is signal. The rendered page embeds
//! [`crate::canary_tokens`] tripwires in its text and carries honeypot links
//! to paths that exist only to be followed; when the page — or its tokens —
//! later surfaces somewhere else, the tokens prove the harvest.
//!
//! ## Determinism vs. `generate`
//!
//! [`render_endpoint`] is **byte-identical across calls** for the same spec:
//! no randomness, no clock, no allocation-order dependence. The page is a
//! re-deployable scripted artifact that must diff cleanly between renders.
//! That is why the embedded tokens are *derived* from
//! `sha256("tallow-decoy-endpoint" ‖ id ‖ path ‖ title ‖ index ‖ salt)`
//! instead of being drawn from [`crate::canary_tokens::generate`] (which is
//! random by design, uuid-backed — a fresh draw per call would defeat the
//! byte-identity pin). Derived tokens keep the exact frozen shape
//! `TLW-<KIND>-<16 lower hex>-<4 lower hex>` of [`crate::canary_tokens`],
//! with the `KIND` cycling in [`KINDS`] order, so they are accepted by
//! [`crate::canary_tokens::is_valid`] and interchangeable with generated
//! ones — pinned by the `generated_and_derived_tokens_are_interchangeable`
//! test. [`DecoyError::Token`] is the render-time tripwire that fails closed
//! if a derived token ever drifts from that format.
//!
//! ## Contract surface (frozen §4)
//!
//! * [`DecoySpec`] — one endpoint. `token_count` must be `1..=MAX_TOKENS`
//!   and `path` must start with `/` and contain no `..` (no traversal bait),
//!   else [`DecoyError::BadInput`].
//! * [`render_endpoint`] — deterministic HTML embedding `token_count` unique
//!   tokens (in unique-id'd elements) plus at least two `rel="nofollow"`
//!   honeypot anchors pointing at unique nested trap paths.
//! * [`validate_all`] — whole-estate check: per-spec checks plus duplicate
//!   paths → [`DecoyError::DupPath`]. Duplicate *ids* are permitted by the
//!   interface and aggregate in [`HitLog::for_endpoint`].
//! * [`HitLog`] — in-memory hit recorder ([`HitLog::record`],
//!   [`HitLog::for_endpoint`], [`HitLog::count`]); the caller owns
//!   persistence and passes timestamps in (`at_ms`), keeping the module
//!   pure.
//! * [`deploy_doc`] — deterministic deployment manifest (endpoints sorted by
//!   id) with monitoring and rotation notes. It cannot fail; pair it with
//!   [`validate_all`] before deploying.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canary_tokens::{self, CanaryKind};

/// Maximum tokens per endpoint (frozen §4: `token_count ∈ 1..=32`).
pub const MAX_TOKENS: usize = 32;

/// Kind cycle used for embedded tokens, in embed order.
const KINDS: [CanaryKind; 3] = [CanaryKind::Url, CanaryKind::Marker, CanaryKind::Serial];

/// One decoy endpoint description.
///
/// * `id` — stable operator-facing identifier; keys [`HitLog::for_endpoint`]
///   and the rendered element anchors.
/// * `path` — the URL path the endpoint is deployed at; must start with `/`
///   and contain no `..`.
/// * `title` — visible page title (and part of the token derivation, so
///   changing it rotates every embedded token).
/// * `token_count` — how many canary tokens to embed (`1..=MAX_TOKENS`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoySpec {
    pub id: String,
    pub path: String,
    pub title: String,
    pub token_count: usize,
}

/// Errors from decoy-endpoint rendering / validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DecoyError {
    /// Invalid input field (the payload names the field).
    BadInput(&'static str),
    /// Two specs in one estate carry the same `path`.
    DupPath,
    /// A token produced for embedding failed [`crate::canary_tokens::is_valid`]
    /// (render-time fail-closed tripwire; unreachable while the derivation
    /// matches the frozen token format).
    Token(String),
}

impl std::fmt::Display for DecoyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecoyError::BadInput(field) => write!(f, "invalid decoy input: {field}"),
            DecoyError::DupPath => write!(f, "duplicate decoy path"),
            DecoyError::Token(token) => write!(f, "invalid canary token: {token}"),
        }
    }
}

impl std::error::Error for DecoyError {}

/// Shared per-spec validation used by [`render_endpoint`] and [`validate_all`].
///
/// Refusals (all [`DecoyError::BadInput`], payload = field name):
/// * `token_count` outside `1..=MAX_TOKENS` → `"token_count"`;
/// * `path` not starting with `/`, or containing `..` → `"path"`;
/// * empty `id` or `title` → `"id"` / `"title"` (house fail-closed
///   extension: the id keys [`HitLog::for_endpoint`] and the HTML anchors,
///   and an untitled decoy cannot be recognised in a served-estate diff).
fn check_spec(spec: &DecoySpec) -> Result<(), DecoyError> {
    if spec.token_count == 0 || spec.token_count > MAX_TOKENS {
        return Err(DecoyError::BadInput("token_count"));
    }
    if !spec.path.starts_with('/') || spec.path.contains("..") {
        return Err(DecoyError::BadInput("path"));
    }
    if spec.id.is_empty() {
        return Err(DecoyError::BadInput("id"));
    }
    if spec.title.is_empty() {
        return Err(DecoyError::BadInput("title"));
    }
    Ok(())
}

/// Render the deterministic HTML page for `spec`.
///
/// The page embeds `spec.token_count` unique canary tokens (kinds cycling
/// URL → MARKER → SERIAL), each inside a uniquely-id'd `<span>` carrying both
/// `id="<slug>-token-<i>"` and `data-canary="<token>"`; it carries
/// `max(token_count, 2)` honeypot anchors with `rel="nofollow"` to the unique
/// nested paths `<path>/trap/<slug>-<i>`; and a `<meta name="generator">`
/// stamp. Repeated calls with an equal spec return byte-identical HTML.
///
/// `spec.id` / `spec.path` / `spec.title` are HTML-escaped, so hostile input
/// round-trips without breaking the page.
pub fn render_endpoint(spec: &DecoySpec) -> Result<String, DecoyError> {
    check_spec(spec)?;
    let id = escape_html(&spec.id);
    let title = escape_html(&spec.title);
    let path = escape_html(&spec.path);
    let slug = slugify(&spec.id);
    let tokens = derive_tokens(spec)?;
    // Trailing slashes trimmed so the trap paths nest under the endpoint
    // without a double slash (`/` alone nests at the root).
    let base = escape_html(spec.path.trim_end_matches('/'));
    let trap_count = spec.token_count.max(2);

    let mut html = String::with_capacity(768 + spec.token_count * 160);
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"generator\" content=\"tallow-decoy-endpoint v1\">\n");
    html.push_str("<meta name=\"robots\" content=\"noindex, nofollow, noarchive\">\n");
    html.push_str("<title>");
    html.push_str(&title);
    html.push_str("</title>\n</head>\n<body>\n");
    html.push_str("<h1>");
    html.push_str(&title);
    html.push_str("</h1>\n");
    html.push_str("<p class=\"decoy-intro\">Decoy endpoint <code>");
    html.push_str(&path);
    html.push_str("</code> (id <code>");
    html.push_str(&id);
    html.push_str(
        "</code>). This surface exists only as a tripwire: requests and harvests \
         contaminate the downstream corpus with detectable canary tokens.</p>\n",
    );
    html.push_str("<ul class=\"decoy-tokens\">\n");
    for (i, token) in tokens.iter().enumerate() {
        html.push_str("<li><span id=\"");
        html.push_str(&slug);
        html.push_str("-token-");
        html.push_str(&i.to_string());
        html.push_str("\" data-canary=\"");
        html.push_str(token);
        html.push_str("\">");
        html.push_str(token);
        html.push_str("</span></li>\n");
    }
    html.push_str("</ul>\n<div class=\"honeypots\">\n");
    for i in 0..trap_count {
        html.push_str("<a id=\"");
        html.push_str(&slug);
        html.push_str("-trap-");
        html.push_str(&i.to_string());
        html.push_str("\" class=\"trap\" rel=\"nofollow\" href=\"");
        html.push_str(&base);
        html.push_str("/trap/");
        html.push_str(&slug);
        html.push('-');
        html.push_str(&i.to_string());
        html.push_str("\">archive ");
        html.push_str(&i.to_string());
        html.push_str("</a>\n");
    }
    html.push_str("</div>\n</body>\n</html>\n");
    Ok(html)
}

/// Validate a whole decoy estate: per-spec checks ([`check_spec`]) plus
/// duplicate `path` detection → [`DecoyError::DupPath`] (first duplicate in
/// input order; paths compare byte-for-byte). An empty estate is valid.
pub fn validate_all(specs: &[DecoySpec]) -> Result<(), DecoyError> {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for spec in specs {
        check_spec(spec)?;
        if !seen.insert(spec.path.as_str()) {
            return Err(DecoyError::DupPath);
        }
    }
    Ok(())
}

/// One observed hit on a decoy endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyHit {
    /// The decoy endpoint's id ([`DecoySpec::id`]).
    pub endpoint: String,
    /// When the hit was observed, in caller-supplied milliseconds.
    pub at_ms: i64,
    /// Where it came from (log line, referrer, monitoring label).
    pub source_hint: String,
}

/// In-memory hit log for decoy endpoints.
///
/// The log is deliberately pure and ephemeral: no clock (timestamps are
/// passed in), no IO, no storage. The caller owns persistence and feeds it
/// observed requests; ordering rules of [`HitLog::for_endpoint`] make reads
/// deterministic for any storage/replay shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitLog {
    hits: Vec<DecoyHit>,
}

impl HitLog {
    /// A new, empty log.
    pub fn new() -> Self {
        HitLog { hits: Vec::new() }
    }

    /// Append a hit and return a reference to the stored entry.
    ///
    /// Empty `endpoint` → [`DecoyError::BadInput("endpoint")`]. An empty
    /// `source_hint` is allowed (the source may genuinely be unknown at
    /// record time); the caller decides the convention.
    pub fn record(
        &mut self,
        endpoint: &str,
        at_ms: i64,
        source_hint: &str,
    ) -> Result<&DecoyHit, DecoyError> {
        if endpoint.is_empty() {
            return Err(DecoyError::BadInput("endpoint"));
        }
        self.hits.push(DecoyHit {
            endpoint: endpoint.to_string(),
            at_ms,
            source_hint: source_hint.to_string(),
        });
        // Total form (no unwrap): the push above guarantees a last element.
        match self.hits.last() {
            Some(hit) => Ok(hit),
            None => Err(DecoyError::BadInput("endpoint")),
        }
    }

    /// All hits for endpoint `id`, sorted by `(at_ms, insertion order)` —
    /// ties on `at_ms` keep the order they were recorded in.
    pub fn for_endpoint(&self, id: &str) -> Vec<&DecoyHit> {
        let mut selected: Vec<(usize, &DecoyHit)> = self
            .hits
            .iter()
            .enumerate()
            .filter(|(_, hit)| hit.endpoint == id)
            .collect();
        selected.sort_by(|(ia, a), (ib, b)| a.at_ms.cmp(&b.at_ms).then_with(|| ia.cmp(ib)));
        selected.into_iter().map(|(_, hit)| hit).collect()
    }

    /// Total number of recorded hits across all endpoints.
    pub fn count(&self) -> usize {
        self.hits.len()
    }
}

/// Deterministic deployment manifest for `specs` (endpoints sorted by
/// `(id, path)` for stability).
///
/// Renders whatever it is given — it cannot fail — so run [`validate_all`]
/// first; the manifest is the operational companion to the rendered pages:
/// per-endpoint path/token counts, a monitoring note anchored on [`HitLog`],
/// and a canary rotation note.
pub fn deploy_doc(specs: &[DecoySpec]) -> String {
    let mut sorted: Vec<&DecoySpec> = specs.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.path.cmp(&b.path)));

    let mut doc = String::with_capacity(512 + specs.len() * 96);
    doc.push_str("# Decoy endpoints — deployment manifest\n\n");
    doc.push_str(&format!("endpoints: {}\n\n", specs.len()));
    doc.push_str(
        "Deploy each path below as a static HTML endpoint rendered by \
         `render_endpoint`; validate the estate with `validate_all` before \
         serving it.\n\n",
    );
    doc.push_str("## Endpoints\n");
    for spec in &sorted {
        doc.push_str(&format!(
            "- {} | path: {} | tokens: {}\n",
            spec.id, spec.path, spec.token_count
        ));
    }
    doc.push_str(
        "\n## Monitoring\n\
         Every request to a decoy path is a tripwire. Record each observed hit \
         with `HitLog::record(endpoint, at_ms, source_hint)`; read one \
         endpoint's history (sorted by time) with `HitLog::for_endpoint(id)`; \
         `HitLog::count()` is the total across all endpoints. A non-zero count \
         means something followed a path it had no reason to follow — treat \
         the hit as a lead and correlate `source_hint` with upstream logs.\n",
    );
    doc.push_str(
        "\n## Rotation\n\
         Rotate the canary tokens of an endpoint by changing any derivation \
         input (`id`, `path`, or `title`) and re-rendering: the embedded \
         tokens are derived per (id, path, title, index), so a single input \
         change rotates the whole token set. Re-render after every rotation \
         and keep the previous tokens recorded in `HitLog` history so a later \
         sighting of an old token still maps to the deployment it came from.\n",
    );
    doc
}

/// Deterministically derive `spec.token_count` unique tokens, kinds cycling
/// and document order equal to index order. The `salt` bump makes collisions
/// (astronomically unlikely, but cheap to guard) resolve deterministically;
/// exhausting it fails closed with [`DecoyError::Token`].
fn derive_tokens(spec: &DecoySpec) -> Result<Vec<String>, DecoyError> {
    let mut out: Vec<String> = Vec::with_capacity(spec.token_count);
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for i in 0..spec.token_count {
        let kind = KINDS[i % KINDS.len()];
        let mut salt: u32 = 0;
        loop {
            let token = derive_token(&spec.id, &spec.path, &spec.title, i, kind, salt);
            if !canary_tokens::is_valid(&token) {
                // Unreachable while the derivation matches the frozen
                // format; fail closed rather than embed a broken tripwire.
                return Err(DecoyError::Token(token));
            }
            if seen.insert(token.clone()) {
                out.push(token);
                break;
            }
            if salt == u32::MAX {
                return Err(DecoyError::Token(token));
            }
            salt += 1;
        }
    }
    Ok(out)
}

/// One token: `TLW-<KIND>-<16 lower hex>-<4 lower hex>` where the random part
/// is the first 8 bytes of `sha256(domain-separator ‖ id ‖ path ‖ title ‖
/// index ‖ salt)` hex-encoded, and the checksum is `sha256(random_hex)[..4]`
/// (the frozen format's rule, mirrored from `canary_tokens`'s private
/// checksum; validated through the public `is_valid`).
fn derive_token(id: &str, path: &str, title: &str, idx: usize, kind: CanaryKind, salt: u32) -> String {
    let seed = format!("tallow-decoy-endpoint\x1f{id}\x1f{path}\x1f{title}\x1f{idx}\x1f{salt}");
    let digest = Sha256::digest(seed.as_bytes());
    let random_hex = to_hex(&digest[..8]);
    let checksum = checksum_of(&random_hex);
    format!("TLW-{}-{}-{}", kind.as_str(), random_hex, checksum)
}

/// First 4 hex chars of `sha256(random_hex)` — mirrors `canary_tokens`'s
/// private checksum rule.
fn checksum_of(random_hex: &str) -> String {
    to_hex(Sha256::digest(random_hex.as_bytes()).as_slice())[..4].to_string()
}

/// Lower-case hex (local; `hex` crate is not a dependency).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Escape text/attribute-hostile HTML characters so the page stays
/// well-formed whatever `id`/`path`/`title` contain.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Path-safe slug for element ids / trap paths: ASCII alphanumerics
/// lowercased, every other run collapsed to `-`, ends trimmed; empty →
/// `"decoy"`.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "decoy".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn spec(id: &str, path: &str, title: &str, token_count: usize) -> DecoySpec {
        DecoySpec {
            id: id.to_string(),
            path: path.to_string(),
            title: title.to_string(),
            token_count,
        }
    }

    /// Tokens in document order (from the `data-canary` attributes).
    fn attr_tokens(page: &str) -> Vec<String> {
        page.split("data-canary=\"")
            .skip(1)
            .map(|s| s.split('"').next().unwrap_or_default().to_string())
            .collect()
    }

    /// All `id="..."` attribute values, in document order.
    fn ids(page: &str) -> Vec<String> {
        page.split("id=\"")
            .skip(1)
            .map(|s| s.split('"').next().unwrap_or_default().to_string())
            .collect()
    }

    #[test]
    fn render_embeds_all_tokens_valid_and_unique() {
        let s = spec(
            "analytics-export",
            "/analytics/export.csv",
            "Analytics export (legacy)",
            7,
        );
        let page = render_endpoint(&s).expect("valid spec renders");
        let embedded = attr_tokens(&page);
        assert_eq!(embedded.len(), 7, "7 tokens embedded");
        let uniq: HashSet<&String> = embedded.iter().collect();
        assert_eq!(uniq.len(), 7, "embedded tokens are unique");
        for t in &embedded {
            assert!(crate::canary_tokens::is_valid(t), "invalid token: {t}");
        }
        // Kind cycle: URL, MARKER, SERIAL, URL, ...
        let kinds: Vec<&str> = embedded
            .iter()
            .map(|t| t.split('-').nth(1).unwrap())
            .collect();
        assert_eq!(
            kinds,
            ["URL", "MARKER", "SERIAL", "URL", "MARKER", "SERIAL", "URL"]
        );
    }

    #[test]
    fn render_is_byte_identical_across_calls() {
        let s = spec("alpha", "/alpha", "Alpha decoy", 9);
        let a = render_endpoint(&s).unwrap();
        let b = render_endpoint(&s.clone()).unwrap();
        assert_eq!(a, b, "same spec ⇒ byte-identical page");
        // Sensitivity: id/title feed token derivation, so an input change
        // must show up in the bytes.
        let mut other = s.clone();
        other.title = "Other title".to_string();
        let c = render_endpoint(&other).unwrap();
        assert_ne!(a, c, "title change changes the page");
        assert_eq!(attr_tokens(&a).len(), attr_tokens(&c).len(), "count unchanged");
    }

    #[test]
    fn render_refuses_bad_token_count() {
        for bad in [0usize, MAX_TOKENS + 1, 1000] {
            assert_eq!(
                render_endpoint(&spec("e", "/e", "t", bad)).unwrap_err(),
                DecoyError::BadInput("token_count"),
                "token_count {bad} must be refused"
            );
        }
        // Boundaries are valid.
        let one = render_endpoint(&spec("e", "/e", "t", 1)).expect("count 1 ok");
        assert_eq!(attr_tokens(&one).len(), 1);
        let full = render_endpoint(&spec("e", "/e", "t", MAX_TOKENS)).expect("count 32 ok");
        assert_eq!(attr_tokens(&full).len(), MAX_TOKENS);
    }

    #[test]
    fn render_refuses_bad_paths() {
        for bad in ["", "admin", "x/y", "..", "/..", "/a/../b", "/x/.."] {
            assert_eq!(
                render_endpoint(&spec("e", bad, "t", 2)).unwrap_err(),
                DecoyError::BadInput("path"),
                "path {bad:?} must be refused"
            );
        }
        // `/` alone and traversal-free deep paths are valid.
        assert!(render_endpoint(&spec("e", "/", "t", 1)).is_ok());
        let deep = render_endpoint(&spec("e", "/admin/db-backup.sql", "t", 1)).unwrap();
        assert!(deep.contains("href=\"/admin/db-backup.sql/trap/e-0\""));
        let root = render_endpoint(&spec("e", "/", "t", 1)).unwrap();
        assert!(root.contains("href=\"/trap/e-0\""));
    }

    #[test]
    fn validate_all_accepts_clean_estate_and_rejects_dup_paths() {
        let ok = vec![spec("a", "/a", "A", 2), spec("b", "/b", "B", 3)];
        assert_eq!(validate_all(&ok), Ok(()));
        assert_eq!(validate_all(&[]), Ok(()), "empty estate is vacuously valid");

        let dup = vec![spec("a", "/same", "A", 2), spec("b", "/same", "B", 3)];
        assert_eq!(validate_all(&dup), Err(DecoyError::DupPath));

        // Per-spec checks run first: an invalid spec refuses even if the
        // paths also collide.
        let bad = vec![spec("a", "bad", "A", 2), spec("b", "bad", "B", 3)];
        assert_eq!(validate_all(&bad), Err(DecoyError::BadInput("path")));
        let bad_count = vec![spec("a", "/a", "A", 2), spec("b", "/b", "B", 0)];
        assert_eq!(
            validate_all(&bad_count),
            Err(DecoyError::BadInput("token_count"))
        );

        // Paths compare byte-for-byte; case differs ⇒ not a duplicate.
        let case = vec![spec("a", "/A", "A", 2), spec("b", "/a", "B", 3)];
        assert_eq!(validate_all(&case), Ok(()));
    }

    #[test]
    fn render_unique_element_ids_and_nofollow_trap_paths() {
        for count in [1usize, 2, 5, MAX_TOKENS] {
            let s = spec("decoy-x", "/x/y", "T", count);
            let page = render_endpoint(&s).unwrap();

            let doc_ids = ids(&page);
            let uniq: HashSet<&String> = doc_ids.iter().collect();
            assert_eq!(uniq.len(), doc_ids.len(), "element ids unique (count={count})");

            let anchors: Vec<&str> = page.split("<a ").skip(1).collect();
            assert_eq!(anchors.len(), count.max(2), "max(count, 2) honeypots");
            let hrefs: Vec<String> = anchors
                .iter()
                .map(|a| {
                    a.split("href=\"")
                        .nth(1)
                        .and_then(|s| s.split('"').next())
                        .unwrap_or_default()
                        .to_string()
                })
                .collect();
            assert!(
                hrefs.iter().all(|h| h.starts_with("/x/y/trap/decoy-x-")),
                "trap paths nest under the endpoint path: {hrefs:?}"
            );
            let uniq_h: HashSet<&String> = hrefs.iter().collect();
            assert_eq!(uniq_h.len(), hrefs.len(), "trap paths unique");
            for a in &anchors {
                assert!(a.contains("rel=\"nofollow\""), "nofollow on every trap: {a}");
            }
        }
    }

    #[test]
    fn render_escapes_hostile_inputs() {
        let s = spec("a\"&<>", "/e\"q", "<script>alert(1)</script>", 2);
        let page = render_endpoint(&s).unwrap();
        assert!(!page.contains("<script>"), "raw script must not survive");
        assert!(page.contains("&lt;script&gt;"));
        assert!(page.contains("&quot;"));
        let embedded = attr_tokens(&page);
        assert_eq!(embedded.len(), 2);
        assert!(embedded.iter().all(|t| crate::canary_tokens::is_valid(t)));
    }

    #[test]
    fn generated_and_derived_tokens_are_interchangeable() {
        // Same frozen format: tokens from `generate` and tokens embedded by
        // `render_endpoint` both validate under the shared `is_valid`.
        for kind in [CanaryKind::Url, CanaryKind::Marker, CanaryKind::Serial] {
            let g = crate::canary_tokens::generate(kind);
            assert!(crate::canary_tokens::is_valid(&g), "generate output: {g}");
            assert!(g.starts_with(&format!("TLW-{}-", kind.as_str())));
        }
        let page = render_endpoint(&spec("x", "/x", "t", 3)).unwrap();
        for t in attr_tokens(&page) {
            assert!(crate::canary_tokens::is_valid(&t), "derived token: {t}");
        }
    }

    #[test]
    fn hit_log_records_filters_sorts_and_counts() {
        let mut log = HitLog::new();
        assert_eq!(log.count(), 0);
        assert!(log.for_endpoint("a").is_empty());

        // Recorded out of time order on purpose.
        let a1 = log.record("a", 300, "crawler-1").unwrap().clone();
        let a0 = log.record("a", 100, "crawler-0").unwrap().clone();
        let a0b = log.record("a", 100, "crawler-0b").unwrap().clone(); // same at_ms, later insertion
        let b1 = log.record("b", 50, "scanner").unwrap().clone();

        assert_eq!(
            a1,
            DecoyHit {
                endpoint: "a".to_string(),
                at_ms: 300,
                source_hint: "crawler-1".to_string()
            }
        );
        assert_eq!(log.count(), 4);

        let a_hits = log.for_endpoint("a");
        assert_eq!(a_hits.len(), 3);
        assert_eq!(a_hits[0], &a0);
        assert_eq!(a_hits[1], &a0b, "at_ms tie broken by insertion order");
        assert_eq!(a_hits[2], &a1);
        let b_hits = log.for_endpoint("b");
        assert_eq!(b_hits.len(), 1);
        assert_eq!(b_hits[0], &b1);
        assert!(log.for_endpoint("nope").is_empty());

        // Returned reference points at the stored hit.
        let r = log.record("a", 400, "x").unwrap();
        assert_eq!((r.endpoint.as_str(), r.at_ms, r.source_hint.as_str()), ("a", 400, "x"));
        assert_eq!(log.count(), 5);

        // Empty endpoint refused; empty source hint allowed.
        assert_eq!(
            log.record("", 1, "why").unwrap_err(),
            DecoyError::BadInput("endpoint")
        );
        assert!(log.record("a", 401, "").is_ok());
        assert_eq!(log.count(), 6);
    }

    #[test]
    fn hit_log_default_and_serde_roundtrip() {
        let mut log = HitLog::default();
        assert_eq!(log.count(), 0);
        log.record("a", 1, "h").unwrap();
        log.record("b", 2, "").unwrap();

        let json = serde_json::to_string(&log).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["hits"][0]["endpoint"], "a");
        assert_eq!(v["hits"][0]["at_ms"], 1);
        assert_eq!(v["hits"][0]["source_hint"], "h");

        let back: HitLog = serde_json::from_str(&json).unwrap();
        assert_eq!(log, back);
        assert_eq!(back.count(), 2);
        assert_eq!(back.for_endpoint("a").len(), 1);
        assert_eq!(back.for_endpoint("b").len(), 1);
    }

    #[test]
    fn deploy_doc_sections_sorted_and_deterministic() {
        let specs = vec![
            spec("zeta", "/z", "Z", 2),
            spec("alpha", "/a", "A", 3),
            spec("mid", "/m", "M", 1),
        ];
        let doc = deploy_doc(&specs);
        for section in ["## Endpoints", "## Monitoring", "## Rotation"] {
            assert!(doc.contains(section), "missing section {section}");
        }
        assert!(doc.contains("HitLog"), "monitoring notes reference HitLog");
        assert!(doc.contains("endpoints: 3"));
        assert!(doc.contains("- alpha | path: /a | tokens: 3"));
        // Sorted by id regardless of input order.
        let pa = doc.find("alpha").unwrap();
        let pm = doc.find("mid").unwrap();
        let pz = doc.find("zeta").unwrap();
        assert!(pa < pm && pm < pz, "endpoints sorted by id");
        // Deterministic, and independent of the input order.
        assert_eq!(doc, deploy_doc(&specs));
        let rev: Vec<DecoySpec> = specs.iter().rev().cloned().collect();
        assert_eq!(doc, deploy_doc(&rev));
        // Empty estate still renders every section.
        let empty = deploy_doc(&[]);
        assert!(empty.contains("endpoints: 0"));
        for section in ["## Endpoints", "## Monitoring", "## Rotation"] {
            assert!(empty.contains(section));
        }
    }

    #[test]
    fn rotation_changes_every_token() {
        let gen1 = attr_tokens(&render_endpoint(&spec("x", "/x", "Generation 1", 4)).unwrap());
        let gen2 = attr_tokens(&render_endpoint(&spec("x", "/x", "Generation 2", 4)).unwrap());
        let s1: HashSet<&String> = gen1.iter().collect();
        assert!(
            gen2.iter().all(|t| !s1.contains(t)),
            "title change rotates every token"
        );
        let other_path =
            attr_tokens(&render_endpoint(&spec("x", "/y", "Generation 1", 4)).unwrap());
        assert!(
            other_path.iter().all(|t| !s1.contains(t)),
            "path change rotates every token"
        );
    }

    #[test]
    fn serde_roundtrips_and_error_shapes() {
        let s = spec("a", "/a", "A", 4);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<DecoySpec>(&json).unwrap(), s);

        let h = DecoyHit {
            endpoint: "a".to_string(),
            at_ms: -5,
            source_hint: "h".to_string(),
        };
        let hj = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<DecoyHit>(&hj).unwrap(), h);

        // DecoyError is outbound-only (Serialize): the `&'static str`
        // payload cannot deserialize to a borrow-free value.
        let v: serde_json::Value = serde_json::to_value(DecoyError::BadInput("path")).unwrap();
        assert_eq!(v, serde_json::json!({ "BadInput": "path" }));
        let v: serde_json::Value = serde_json::to_value(DecoyError::DupPath).unwrap();
        assert_eq!(v, serde_json::Value::String("DupPath".to_string()));
        let v: serde_json::Value = serde_json::to_value(DecoyError::Token("t".to_string())).unwrap();
        assert_eq!(v, serde_json::json!({ "Token": "t" }));

        assert_eq!(
            DecoyError::BadInput("token_count").to_string(),
            "invalid decoy input: token_count"
        );
        assert_eq!(DecoyError::DupPath.to_string(), "duplicate decoy path");
        assert_eq!(
            DecoyError::Token("bad".to_string()).to_string(),
            "invalid canary token: bad"
        );
    }
}
