//! Decoy-maze heuristics + extraordinary-claim flags → review queue (task A3.4.2 / spec E11).
//!
//! Some sources are built to waste a collector's time: link **mazes** that fan
//! out across domains and path depths for no informational reason, and copy
//! that reads like an advert for a miracle (kombucha-cures-cancer pages,
//! guaranteed-return schemes, "one weird trick" landing pages). This module is
//! the pure, deterministic core that turns those observations into reviewable
//! flags — it never fetches, never clocks, never writes:
//!
//! * [`profile_links`] summarizes a batch of links into a [`LinkProfile`]
//!   (count, unique hosts, deepest path).
//! * [`maze_heuristic`] fires when **all three** minima in [`MazeThresholds`]
//!   are met (`>=`, inclusive). Defaults are a policy breakpoint, not physics.
//! * [`claims_in_text`] scans text **case-insensitively** for
//!   [`EXTRAORDINARY_PATTERNS`] and returns [`ClaimFlag`]s carrying the
//!   matched pattern plus a ±[`CLAIM_EXCERPT_CONTEXT_CHARS`]-char excerpt of
//!   the **original** text (original casing preserved).
//! * [`triage`] combines both into a [`TriageVerdict`] of [`ReviewFlag`]s.
//! * [`ReviewQueue`] is a FIFO review queue with id dedupe and removal.
//!
//! # Purity contract
//! Every function is **pure and deterministic**: no clock, no IO, no
//! randomness. `now_ms` in [`triage`] is echoed into
//! [`TriageVerdict::created_ms`]; the queue only stores caller-supplied
//! timestamps.
//!
//! # Link-profile semantics (documented per interface §8)
//! * `total` = number of links supplied, including unparseable ones.
//! * The **domain key** is the lowercased, trimmed host: the link is split
//!   after `scheme://` (or a leading `//`), everything up to the first
//!   `/`, `?` or `#` is the authority; userinfo (`user@`) is dropped; a
//!   trailing `:port` is dropped when the port is all-digits; the remainder
//!   is trimmed and ASCII-lowercased (`to_ascii_lowercase` — hostnames are
//!   ASCII; IDNs are expected punycoded). An empty host contributes **no**
//!   unique domain but still counts in `total`.
//! * `max_path_depth` = the maximum, over links, of non-empty `/`-separated
//!   path segments. Scheme, query and fragment are excluded
//!   (`https://a.example/x/y/z?q=1#f` → depth 3). Parsing targets http(s)-style
//!   links; anything else degrades to "host = leading token, depth = 0".
//!
//! # Threshold semantics
//! [`maze_heuristic`] requires `total >= min_links` **and**
//! `unique_domains >= min_unique_domains` **and** `max_path_depth >= min_depth`.
//! A minimum of `0` is trivially satisfied (effectively disables that arm) —
//! deliberate, thresholds are the operator's policy knobs.
//!
//! # Claim-scan semantics
//! Patterns are matched against a lowercased copy of the input
//! (case-insensitive, Unicode-aware lowering; patterns themselves are
//! ASCII-lowercase by convention and are lowered defensively). Flags are
//! emitted in [`EXTRAORDINARY_PATTERNS`] order; within one pattern, matches
//! are emitted in text order. Every occurrence produces its own flag. The
//! excerpt is the matched region ± [`CLAIM_EXCERPT_CONTEXT_CHARS`] **characters**
//! of the original string, clipped at the string edges (no ellipses).
//!
//! # Note on [`FlagKind::DecoyContent`]
//! This kind is part of the detector family but has **no trigger defined in
//! the frozen interface**, so [`triage`] never emits it here; it is reserved
//! for caller-side decoy-content detectors (and future tasks).
//!
//! # Serde note
//! All public data types round-trip. [`DecoyError`] derives `Serialize` only —
//! [`DecoyError::EmptyField`] carries `&'static str`, which cannot implement
//! `Deserialize` for arbitrary input lifetimes.
//!
//! # Wiring
//! No call site is wired here; the parent integrates the module (E11).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Extraordinary-claim patterns, matched case-insensitively.
///
/// Entries are ASCII-lowercase by convention (the implementation lowers them
/// defensively). Pattern order is the emission order of [`claims_in_text`].
pub const EXTRAORDINARY_PATTERNS: &[&str] = &[
    "miracle cure",
    "guaranteed returns",
    "one weird trick",
    "doctors hate",
    "secret formula",
    "free money",
    "100% guaranteed",
    "immortality",
    "cures cancer",
    "government cover-up",
];

/// Characters of context kept on each side of a claimed match in
/// [`ClaimFlag::excerpt`].
pub const CLAIM_EXCERPT_CONTEXT_CHARS: usize = 20;

/// Severity of a [`FlagKind::DecoyMaze`] flag (interface §8).
pub const SEVERITY_DECOY_MAZE: u8 = 2;

/// Severity of a [`FlagKind::ExtraordinaryClaim`] flag (interface §8).
pub const SEVERITY_EXTRAORDINARY_CLAIM: u8 = 1;

/// Summary of a batch of links. Serde-serializable for audit records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkProfile {
    /// Number of links supplied (including unparseable ones).
    pub total: usize,
    /// Distinct lowercased host keys.
    pub unique_domains: usize,
    /// Deepest non-empty path-segment count seen across the links.
    pub max_path_depth: usize,
}

/// Maze thresholds — all three must hold (`>=`) for [`maze_heuristic`] to fire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MazeThresholds {
    /// Minimum link count.
    pub min_links: usize,
    /// Minimum distinct domains.
    pub min_unique_domains: usize,
    /// Minimum path depth.
    pub min_depth: usize,
}

impl Default for MazeThresholds {
    /// Documented default policy breakpoint (interface §8):
    /// `20 / 10 / 4` — twenty links across ten hosts with a four-deep path is
    /// past incidental citation, it is maze-shaped.
    fn default() -> Self {
        Self {
            min_links: 20,
            min_unique_domains: 10,
            min_depth: 4,
        }
    }
}

/// A matched extraordinary claim: which pattern matched, and where in context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimFlag {
    /// The [`EXTRAORDINARY_PATTERNS`] entry that matched.
    pub pattern: String,
    /// Matched region ± [`CLAIM_EXCERPT_CONTEXT_CHARS`] chars of the original
    /// text, clipped at the string edges, original casing preserved.
    pub excerpt: String,
}

/// Flag class emitted by [`triage`] (and available to caller-side detectors).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlagKind {
    /// Link fan-out shaped like a decoy maze.
    DecoyMaze,
    /// Text matched an [`EXTRAORDINARY_PATTERNS`] entry.
    ExtraordinaryClaim,
    /// Decoy content detected by a caller-side detector (reserved: not
    /// emitted by [`triage`] in this version — no trigger in the interface).
    DecoyContent,
}

/// One triage flag, ready for the review queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewFlag {
    /// Which detector fired.
    pub kind: FlagKind,
    /// Human-readable evidence (profile numbers / pattern + excerpt).
    pub detail: String,
    /// Severity: maze [`SEVERITY_DECOY_MAZE`], claim [`SEVERITY_EXTRAORDINARY_CLAIM`].
    pub severity: u8,
}

/// Result of triaging one document (text + its outgoing links).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageVerdict {
    /// Flags in stable order: maze first (if any), then claims in
    /// [`claims_in_text`] order.
    pub flags: Vec<ReviewFlag>,
    /// `!flags.is_empty()`.
    pub needs_review: bool,
    /// Caller's timestamp, echoed unchanged.
    pub created_ms: i64,
}

/// One queued review item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewItem {
    /// Unique item id (dedupe key for [`ReviewQueue`]).
    pub id: String,
    /// Source the flags came from.
    pub source: String,
    /// The flags to review.
    pub flags: Vec<ReviewFlag>,
    /// Caller's timestamp, stored unchanged.
    pub created_ms: i64,
}

/// Queue errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DecoyError {
    /// An item with this id is already pending.
    DuplicateId(String),
    /// A required field was empty (after trimming); carries the field name.
    EmptyField(&'static str),
}

impl std::fmt::Display for DecoyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecoyError::DuplicateId(id) => write!(f, "duplicate review item id: {id}"),
            DecoyError::EmptyField(field) => write!(f, "empty required field: {field}"),
        }
    }
}

impl std::error::Error for DecoyError {}

// ---------------------------------------------------------------------------
// Link profiling
// ---------------------------------------------------------------------------

/// Split a link into `(host key, path depth)`. See module docs for the
/// documented parsing rules.
fn host_and_depth(link: &str) -> (String, usize) {
    let trimmed = link.trim();
    let after_scheme = match trimmed.find("://") {
        Some(i) => &trimmed[i + 3..],
        None => trimmed.strip_prefix("//").unwrap_or(trimmed),
    };

    let authority_end = after_scheme
        .find(|c| matches!(c, '/' | '?' | '#'))
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];

    // Drop userinfo, then a numeric port.
    let host_port = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };
    let host = match host_port.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            h
        }
        _ => host_port,
    };
    let host = host.trim().to_ascii_lowercase();

    let rest = &after_scheme[authority_end..];
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let depth = rest[..path_end]
        .split('/')
        .filter(|seg| !seg.is_empty())
        .count();

    (host, depth)
}

/// Summarize `links` into a [`LinkProfile`]. Pure and deterministic.
pub fn profile_links(links: &[String]) -> LinkProfile {
    let mut domains: BTreeSet<String> = BTreeSet::new();
    let mut max_depth = 0usize;
    for link in links {
        let (host, depth) = host_and_depth(link);
        if !host.is_empty() {
            domains.insert(host);
        }
        max_depth = max_depth.max(depth);
    }
    LinkProfile {
        total: links.len(),
        unique_domains: domains.len(),
        max_path_depth: max_depth,
    }
}

/// True when the profile meets **all three** minima (`>=`, inclusive).
pub fn maze_heuristic(profile: &LinkProfile, thresholds: &MazeThresholds) -> bool {
    profile.total >= thresholds.min_links
        && profile.unique_domains >= thresholds.min_unique_domains
        && profile.max_path_depth >= thresholds.min_depth
}

// ---------------------------------------------------------------------------
// Claim scanning
// ---------------------------------------------------------------------------

/// Lowercase `text` and build a byte map from the lowered string back to the
/// original: `map[i]` is the byte offset (in `text`) of the original char
/// whose lowered form contains lowered byte `i`; `map` has one sentinel entry
/// (`text.len()`) after the end. This keeps excerpts aligned with the
/// original text even when lowering changes byte lengths (e.g. `İ`).
fn lowered_with_map(text: &str) -> (String, Vec<usize>) {
    let mut lowered = String::with_capacity(text.len());
    let mut map: Vec<usize> = Vec::with_capacity(text.len() + 1);
    for (orig_idx, ch) in text.char_indices() {
        for lc in ch.to_lowercase() {
            lowered.push(lc);
            while map.len() < lowered.len() {
                map.push(orig_idx);
            }
        }
    }
    map.push(text.len());
    (lowered, map)
}

/// Step back up to `n` chars from byte offset `from` (a char boundary).
fn walk_back_chars(s: &str, from: usize, n: usize) -> usize {
    let mut idx = from;
    for _ in 0..n {
        match s[..idx].char_indices().next_back() {
            Some((i, _)) => idx = i,
            None => break,
        }
    }
    idx
}

/// Step forward up to `n` chars from byte offset `from` (a char boundary).
fn walk_fwd_chars(s: &str, from: usize, n: usize) -> usize {
    let mut idx = from;
    for _ in 0..n {
        match s[idx..].chars().next() {
            Some(c) => idx += c.len_utf8(),
            None => break,
        }
    }
    idx
}

/// Excerpt of the **original** `text` around a matched region.
fn excerpt_around(text: &str, match_start: usize, match_end: usize, ctx: usize) -> String {
    let start = walk_back_chars(text, match_start, ctx);
    let end = walk_fwd_chars(text, match_end, ctx);
    text[start..end].to_string()
}

/// Case-insensitive scan for [`EXTRAORDINARY_PATTERNS`].
///
/// Emission order: pattern order, then text order within each pattern; every
/// occurrence yields one [`ClaimFlag`].
pub fn claims_in_text(text: &str) -> Vec<ClaimFlag> {
    let (lowered, map) = lowered_with_map(text);
    let mut flags = Vec::new();
    for pattern in EXTRAORDINARY_PATTERNS {
        let needle = pattern.to_lowercase();
        for (s, m) in lowered.match_indices(&needle) {
            let e = s + m.len();
            flags.push(ClaimFlag {
                pattern: (*pattern).to_string(),
                excerpt: excerpt_around(text, map[s], map[e], CLAIM_EXCERPT_CONTEXT_CHARS),
            });
        }
    }
    flags
}

// ---------------------------------------------------------------------------
// Triage
// ---------------------------------------------------------------------------

/// Triage one document: link maze (using [`MazeThresholds::default`]) plus
/// extraordinary claims. Flags: maze first (severity 2), then one per claim
/// (severity 1). `needs_review = !flags.is_empty()`. Pure/deterministic;
/// `now_ms` is echoed into [`TriageVerdict::created_ms`].
pub fn triage(text: &str, links: &[String], now_ms: i64) -> TriageVerdict {
    let mut flags = Vec::new();

    let profile = profile_links(links);
    let thresholds = MazeThresholds::default();
    if maze_heuristic(&profile, &thresholds) {
        flags.push(ReviewFlag {
            kind: FlagKind::DecoyMaze,
            detail: format!(
                "decoy maze: {} links, {} unique domains, max path depth {} (thresholds {}/{}/{})",
                profile.total,
                profile.unique_domains,
                profile.max_path_depth,
                thresholds.min_links,
                thresholds.min_unique_domains,
                thresholds.min_depth,
            ),
            severity: SEVERITY_DECOY_MAZE,
        });
    }

    for claim in claims_in_text(text) {
        flags.push(ReviewFlag {
            kind: FlagKind::ExtraordinaryClaim,
            detail: format!(
                "extraordinary claim \"{}\" — excerpt: {}",
                claim.pattern, claim.excerpt
            ),
            severity: SEVERITY_EXTRAORDINARY_CLAIM,
        });
    }

    TriageVerdict {
        needs_review: !flags.is_empty(),
        flags,
        created_ms: now_ms,
    }
}

// ---------------------------------------------------------------------------
// Review queue
// ---------------------------------------------------------------------------

/// FIFO review queue with id dedupe and removal.
///
/// Semantics (documented):
/// * `enqueue` validates id then source (non-empty after trim →
///   [`DecoyError::EmptyField`]), then rejects ids already **pending**
///   (→ [`DecoyError::DuplicateId`]).
/// * [`ReviewQueue::take`] removes and returns the item with the exact id;
///   taking an id frees it for re-enqueue.
/// * [`ReviewQueue::pending`] yields items in enqueue order (FIFO).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewQueue {
    items: Vec<ReviewItem>,
}

impl ReviewQueue {
    /// Empty queue.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Enqueue `item`, validating fields and rejecting duplicate pending ids.
    pub fn enqueue(&mut self, item: ReviewItem) -> Result<(), DecoyError> {
        if item.id.trim().is_empty() {
            return Err(DecoyError::EmptyField("id"));
        }
        if item.source.trim().is_empty() {
            return Err(DecoyError::EmptyField("source"));
        }
        if self.items.iter().any(|i| i.id == item.id) {
            return Err(DecoyError::DuplicateId(item.id));
        }
        self.items.push(item);
        Ok(())
    }

    /// Pending items, in enqueue order.
    pub fn pending(&self) -> &[ReviewItem] {
        &self.items
    }

    /// Number of pending items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Remove and return the pending item with `id`, if any.
    pub fn take(&mut self, id: &str) -> Option<ReviewItem> {
        let pos = self.items.iter().position(|i| i.id == id)?;
        Some(self.items.remove(pos))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, source: &str, now_ms: i64) -> ReviewItem {
        ReviewItem {
            id: id.to_string(),
            source: source.to_string(),
            flags: vec![ReviewFlag {
                kind: FlagKind::ExtraordinaryClaim,
                detail: "test".to_string(),
                severity: SEVERITY_EXTRAORDINARY_CLAIM,
            }],
            created_ms: now_ms,
        }
    }

    fn links(specs: &[&str]) -> Vec<String> {
        specs.iter().map(|s| s.to_string()).collect()
    }

    /// `n` links over `d` distinct domains, all at depth `depth`.
    fn maze_links(n: usize, d: usize, depth: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                let dom = format!("host{}.example", i % d);
                let path = vec!["seg"; depth].join("/");
                format!("https://{dom}/{path}")
            })
            .collect()
    }

    // -- profile_links ------------------------------------------------------

    #[test]
    fn profile_links_counts_total_domains_and_depth() {
        let p = profile_links(&links(&[
            "https://a.example/x",
            "https://b.example/x/y/z",
            "http://a.example/",
        ]));
        assert_eq!(
            p,
            LinkProfile {
                total: 3,
                unique_domains: 2,
                max_path_depth: 3
            }
        );
    }

    #[test]
    fn profile_links_host_key_is_lowercased_trimmed_and_deduped() {
        let p = profile_links(&links(&[
            "https://Example.COM/x",
            "https://example.com/y",
            "http://EXAMPLE.com:443/z",
            "//example.com/q",
            "https://sub.example.com/x",
            "https://user:pw@example.com/x",
        ]));
        assert_eq!(p.total, 6);
        assert_eq!(p.unique_domains, 2); // example.com, sub.example.com
        assert_eq!(p.max_path_depth, 1);
    }

    #[test]
    fn profile_links_depth_ignores_scheme_query_and_fragment() {
        let p = profile_links(&links(&[
            "https://a.example/deep/path/here?q=1#frag",
            "https://a.example/?q=/a/b/c",
            "https://a.example/#/x/y",
        ]));
        assert_eq!(p.max_path_depth, 3);
    }

    #[test]
    fn profile_links_empty_and_unparseable_inputs_are_tolerated() {
        let p = profile_links(&links(&["", "   ", "not a url"]));
        assert_eq!(p.total, 3);
        assert_eq!(p.unique_domains, 1); // "not a url" → host "not a url"
        assert_eq!(p.max_path_depth, 0);

        let p0 = profile_links(&[]);
        assert_eq!(
            p0,
            LinkProfile {
                total: 0,
                unique_domains: 0,
                max_path_depth: 0
            }
        );
    }

    // -- maze_heuristic -----------------------------------------------------

    #[test]
    fn maze_fires_at_and_above_thresholds() {
        let t = MazeThresholds {
            min_links: 20,
            min_unique_domains: 10,
            min_depth: 4,
        };
        let at = profile_links(&maze_links(20, 10, 4));
        assert!(maze_heuristic(&at, &t), "exactly at thresholds must fire");
        let above = profile_links(&maze_links(25, 12, 6));
        assert!(maze_heuristic(&above, &t), "above thresholds must fire");
    }

    #[test]
    fn maze_requires_all_three_minima() {
        let t = MazeThresholds {
            min_links: 20,
            min_unique_domains: 10,
            min_depth: 4,
        };
        let shortage_links = profile_links(&maze_links(19, 10, 4));
        let shortage_domains = profile_links(&maze_links(20, 9, 4));
        let shortage_depth = profile_links(&maze_links(20, 10, 3));
        assert!(!maze_heuristic(&shortage_links, &t));
        assert!(!maze_heuristic(&shortage_domains, &t));
        assert!(!maze_heuristic(&shortage_depth, &t));
    }

    #[test]
    fn maze_default_thresholds_are_documented_breakpoints() {
        let d = MazeThresholds::default();
        assert_eq!(d.min_links, 20);
        assert_eq!(d.min_unique_domains, 10);
        assert_eq!(d.min_depth, 4);
    }

    #[test]
    fn maze_zero_minima_are_trivially_satisfied() {
        let t = MazeThresholds {
            min_links: 0,
            min_unique_domains: 0,
            min_depth: 0,
        };
        assert!(maze_heuristic(&LinkProfile {
            total: 0,
            unique_domains: 0,
            max_path_depth: 0
        }, &t));
    }

    // -- claims_in_text -----------------------------------------------------

    #[test]
    fn patterns_are_ascii_lowercase_convention() {
        for p in EXTRAORDINARY_PATTERNS {
            assert!(!p.is_empty());
            assert_eq!(*p, p.to_lowercase(), "pattern not lowercase: {p}");
            assert!(p.is_ascii(), "pattern not ASCII: {p}");
        }
        assert_eq!(EXTRAORDINARY_PATTERNS.len(), 10);
    }

    #[test]
    fn claims_matched_case_insensitively_with_excerpt() {
        let text = "Buy the MiRaClE cUrE now, it really works!";
        let flags = claims_in_text(text);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].pattern, "miracle cure");
        // Excerpt preserves the ORIGINAL casing and includes context.
        assert!(
            flags[0].excerpt.contains("MiRaClE cUrE"),
            "excerpt must carry the original-cased match: {:?}",
            flags[0].excerpt
        );
        assert!(flags[0].excerpt.contains("Buy the"));
    }

    #[test]
    fn claims_excerpt_is_match_plus_twenty_chars_each_side() {
        let prefix = "a".repeat(30);
        let suffix = "b".repeat(30);
        let text = format!("{prefix}MIRACLE CURE{suffix}");
        let flags = claims_in_text(&text);
        assert_eq!(flags.len(), 1);
        let expected = format!("{}{}{}", "a".repeat(20), "MIRACLE CURE", "b".repeat(20));
        assert_eq!(flags[0].excerpt, expected);
    }

    #[test]
    fn claims_excerpt_clips_at_text_edges() {
        let flags = claims_in_text("immortality");
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].excerpt, "immortality");

        let flags2 = claims_in_text("free money!");
        assert_eq!(flags2[0].excerpt, "free money!");
    }

    #[test]
    fn claims_every_pattern_is_findable() {
        for p in EXTRAORDINARY_PATTERNS {
            let text = format!("prelude — {p} — coda");
            let flags = claims_in_text(&text);
            assert_eq!(flags.len(), 1, "pattern did not match: {p}");
            assert_eq!(flags[0].pattern, *p);
            assert!(flags[0].excerpt.contains(p));
        }
    }

    #[test]
    fn claims_each_occurrence_yields_a_flag() {
        let text = format!(
            "{}miracle cure{}{}miracle cure{}",
            "a".repeat(30),
            "b".repeat(30),
            "c".repeat(30),
            "d".repeat(30)
        );
        let flags = claims_in_text(&text);
        assert_eq!(flags.len(), 2);
        assert_eq!(flags[0].pattern, "miracle cure");
        assert_eq!(flags[1].pattern, "miracle cure");
        assert_ne!(
            flags[0].excerpt, flags[1].excerpt,
            "distinct occurrences carry distinct contexts"
        );
    }

    #[test]
    fn claims_order_follows_pattern_table_then_text() {
        let text = "free money and a miracle cure and more free money";
        let flags = claims_in_text(text);
        assert_eq!(
            flags.iter().map(|f| f.pattern.as_str()).collect::<Vec<_>>(),
            vec!["miracle cure", "free money", "free money"]
        );
    }

    #[test]
    fn claims_clean_text_is_empty() {
        assert!(claims_in_text("").is_empty());
        assert!(claims_in_text("Council minutes: the bridge budget was approved.").is_empty());
    }

    #[test]
    fn claims_non_ascii_context_is_handled_without_panicking() {
        let text = "İstanbul — MIRACLE CURE — naïve café";
        let flags = claims_in_text(text);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].pattern, "miracle cure");
        assert!(flags[0].excerpt.contains("MIRACLE CURE"));
        assert!(flags[0].excerpt.contains("İstanbul"));
    }

    // -- triage -------------------------------------------------------------

    #[test]
    fn triage_clean_input_needs_no_review() {
        let v = triage(
            "Quarterly report: revenue rose 3%.",
            &links(&["https://a.example/report", "https://b.example/data"]),
            1_700_000_000_000,
        );
        assert!(v.flags.is_empty());
        assert!(!v.needs_review);
        assert_eq!(v.created_ms, 1_700_000_000_000);
    }

    #[test]
    fn triage_maze_and_claims_flags_order_severity_and_review() {
        let verdict = triage(
            "Doctors hate this secret formula. Guaranteed returns await!",
            &maze_links(20, 10, 4),
            42,
        );
        assert!(verdict.needs_review);
        let kinds: Vec<FlagKind> = verdict.flags.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FlagKind::DecoyMaze,
                FlagKind::ExtraordinaryClaim,
                FlagKind::ExtraordinaryClaim,
                FlagKind::ExtraordinaryClaim,
            ]
        );
        assert_eq!(verdict.flags[0].severity, SEVERITY_DECOY_MAZE);
        assert_eq!(verdict.flags[1].severity, SEVERITY_EXTRAORDINARY_CLAIM);
        assert!(verdict.flags[0].detail.contains("decoy maze"));
        // Claims are emitted in EXTRAORDINARY_PATTERNS table order:
        // "guaranteed returns" (idx 1), "doctors hate" (idx 3), "secret formula" (idx 4).
        assert!(verdict.flags[1].detail.contains("guaranteed returns"));
        assert!(verdict.flags[2].detail.contains("doctors hate"));
        assert!(verdict.flags[3].detail.contains("secret formula"));
    }

    #[test]
    fn triage_claims_only_no_maze() {
        let v = triage("A miracle cure for sale.", &links(&["https://a.example/x"]), 7);
        assert_eq!(v.flags.len(), 1);
        assert_eq!(v.flags[0].kind, FlagKind::ExtraordinaryClaim);
        assert!(v.needs_review);
    }

    #[test]
    fn triage_deterministic_for_same_input() {
        let text = "One weird trick; free money; immortality.";
        let links = maze_links(21, 11, 5);
        let a = triage(text, &links, 99);
        let b = triage(text, &links, 99);
        assert_eq!(a, b);
        assert_eq!(claims_in_text(text), claims_in_text(text));
        assert_eq!(profile_links(&links), profile_links(&links));
    }

    // -- ReviewQueue --------------------------------------------------------

    #[test]
    fn queue_is_fifo_and_take_removes() {
        let mut q = ReviewQueue::new();
        assert!(q.is_empty());
        q.enqueue(item("a", "src-1", 1)).unwrap();
        q.enqueue(item("b", "src-2", 2)).unwrap();
        q.enqueue(item("c", "src-3", 3)).unwrap();
        assert_eq!(q.len(), 3);
        assert_eq!(
            q.pending().iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );

        let taken = q.take("b").expect("b pending");
        assert_eq!(taken.id, "b");
        assert_eq!(taken.source, "src-2");
        assert_eq!(q.len(), 2);
        assert_eq!(
            q.pending().iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "c"]
        );
        assert!(q.take("b").is_none(), "take removes exactly once");
        assert!(q.take("zzz").is_none(), "unknown id yields None");
    }

    #[test]
    fn queue_rejects_duplicate_ids() {
        let mut q = ReviewQueue::new();
        q.enqueue(item("dup", "src-1", 1)).unwrap();
        let err = q.enqueue(item("dup", "src-2", 2)).unwrap_err();
        assert_eq!(err, DecoyError::DuplicateId("dup".to_string()));
        assert_eq!(q.len(), 1, "rejected enqueue must not mutate the queue");

        // Taking the pending id frees it for re-enqueue.
        q.take("dup").unwrap();
        q.enqueue(item("dup", "src-3", 3)).unwrap();
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn queue_rejects_empty_fields() {
        let mut q = ReviewQueue::new();
        assert_eq!(
            q.enqueue(item("", "src", 1)).unwrap_err(),
            DecoyError::EmptyField("id")
        );
        assert_eq!(
            q.enqueue(item("   ", "src", 1)).unwrap_err(),
            DecoyError::EmptyField("id")
        );
        assert_eq!(
            q.enqueue(item("id", "", 1)).unwrap_err(),
            DecoyError::EmptyField("source")
        );
        assert_eq!(
            q.enqueue(item("id", "  \t ", 1)).unwrap_err(),
            DecoyError::EmptyField("source")
        );
        assert!(q.is_empty());
    }

    #[test]
    fn queue_take_returns_item_with_flags_intact() {
        let mut q = ReviewQueue::new();
        let mut it = item("x", "src", 5);
        it.flags.push(ReviewFlag {
            kind: FlagKind::DecoyMaze,
            detail: "maze".to_string(),
            severity: SEVERITY_DECOY_MAZE,
        });
        q.enqueue(it.clone()).unwrap();
        assert_eq!(q.take("x"), Some(it));
        assert!(q.pending().is_empty());
    }

    // -- serde --------------------------------------------------------------

    #[test]
    fn serde_round_trips_public_types() {
        let profile = LinkProfile {
            total: 3,
            unique_domains: 2,
            max_path_depth: 5,
        };
        let thresholds = MazeThresholds::default();
        let claim = ClaimFlag {
            pattern: "miracle cure".to_string(),
            excerpt: "a miracle cure for".to_string(),
        };
        let flag = ReviewFlag {
            kind: FlagKind::DecoyContent,
            detail: "d".to_string(),
            severity: 3,
        };
        let verdict = triage("A miracle cure!", &links(&["https://a.example/x"]), 11);
        let review_item = item("id-1", "src-1", 7);

        macro_rules! round_trip {
            ($v:expr, $t:ty) => {{
                let json = serde_json::to_string(&$v).unwrap();
                let back: $t = serde_json::from_str(&json).unwrap();
                assert_eq!(back, $v);
            }};
        }

        round_trip!(profile, LinkProfile);
        round_trip!(thresholds, MazeThresholds);
        round_trip!(claim, ClaimFlag);
        round_trip!(flag, ReviewFlag);
        round_trip!(verdict, TriageVerdict);
        round_trip!(review_item, ReviewItem);

        for kind in [
            FlagKind::DecoyMaze,
            FlagKind::ExtraordinaryClaim,
            FlagKind::DecoyContent,
        ] {
            round_trip!(kind, FlagKind);
        }

        let mut q = ReviewQueue::new();
        q.enqueue(item("q1", "s1", 1)).unwrap();
        q.enqueue(item("q2", "s2", 2)).unwrap();
        round_trip!(q, ReviewQueue);
    }

    #[test]
    fn serde_decoy_error_serializes() {
        let dup = DecoyError::DuplicateId("abc".to_string());
        let json = serde_json::to_string(&dup).unwrap();
        assert_eq!(json, r#"{"DuplicateId":"abc"}"#);

        let empty = DecoyError::EmptyField("id");
        let json2 = serde_json::to_string(&empty).unwrap();
        assert_eq!(json2, r#"{"EmptyField":"id"}"#);

        assert_eq!(dup.to_string(), "duplicate review item id: abc");
        assert_eq!(empty.to_string(), "empty required field: id");
    }
}
