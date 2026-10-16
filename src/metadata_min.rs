//! Metadata-minimization transforms — URL redaction, name hashing,
//! timestamp coarsening, size padding (task B7.2.1–B7.2.3, frozen
//! interface §2).
//!
//! [`crate::redaction`] decides *which document fields* may leave the vault
//! and pins both sides by sha256. This module answers the adjacent question:
//! *what incidental metadata leaves with them* — URLs (query strings and
//! fragments leak parameters, tokens, session ids), names (stable linkable
//! identifiers), timestamps (activity patterns), and sizes (content
//! fingerprints). Each transform is pure, deterministic, and lossy on
//! purpose:
//!
//! - [`redact_url`] drops the query string and fragment, keeping only
//!   `scheme://host/path` (string-level: no URL parser, no network).
//! - [`hash_name`] replaces a name with `"n-"` + sha256 hex of its bytes —
//!   equal names stay joinable, the name itself does not survive.
//! - [`coarse_timestamp`] floors a unix-ms instant to the enclosing UTC hour
//!   (`div_euclid`, so pre-1970 instants floor toward −∞).
//! - [`pad_size`] rounds a byte size up to the next 4096-byte block
//!   (0 stays 0): exact sizes become block counts.
//!
//! [`MetaPolicy`] selects which transforms run; [`MetaPolicy::strict`] turns
//! all of them on, `MetaPolicy::default()` (none) is the verbatim pass-through
//! baseline. [`minimize`] applies the enabled transforms to one
//! [`MetaItem`]; [`minimize_all`] maps it over a slice preserving input order.
//! Flags off ⇒ that field is copied verbatim (identity transform).
//!
//! Errors are [`MetaError::BadInput`] carrying the offending field token
//! (`"id"`, `"name"`, `"url"`) — id is always validated, the other two only
//! when their transform is enabled (#[`hash_name`] on an empty name /
//! [`redact_url`] on an empty URL both refuse; a disabled transform accepts
//! the empty value verbatim).
//!
//! No I/O, no clock reads, no randomness: the caller supplies every input,
//! so minimized output is reproducible for tests and replays.
//!
//! Not wired into `lib.rs` yet (the parent does that — §2 wiring line
//! `pub mod metadata_min;`).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Padding block for [`pad_size`] (4 KiB).
const PAD_BLOCK: usize = 4096;

/// One hour in milliseconds; flooring unit for [`coarse_timestamp`].
const HOUR_MS: i64 = 3_600_000;

/// Prefix of a hashed name ([`hash_name`]).
const NAME_HASH_PREFIX: &str = "n-";

// ── Transforms ───────────────────────────────────────────────────────────────

/// Strip the query string and fragment from `url`, keeping only
/// `scheme://host/path`.
///
/// String-level transform (frozen §2): the input is trimmed of surrounding
/// whitespace, then cut at the **first** `?` or `#` (whichever comes first)
/// and everything before it is kept verbatim. No URL syntax is validated —
/// malformed inputs are passed through with only the cut applied.
///
/// Errors: empty or whitespace-only input → [`MetaError::BadInput`] with
/// `"url"`; likewise input that becomes empty after the cut (e.g. `"?a=1"`),
/// since nothing of `scheme://host/path` would remain.
///
/// # Panics
/// Never (slicing is on a char boundary: `?` and `#` are ASCII, and the trim
/// keeps boundaries aligned).
pub fn redact_url(url: &str) -> Result<String, MetaError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(MetaError::BadInput("url"));
    }
    let cut = trimmed.find(['?', '#']).unwrap_or(trimmed.len());
    let kept = trimmed[..cut].trim_end();
    if kept.is_empty() {
        return Err(MetaError::BadInput("url"));
    }
    Ok(kept.to_string())
}

/// Pseudonymize a name: `"n-"` + sha256 hex (lowercase, 64 chars) of the
/// name's UTF-8 bytes.
///
/// Deterministic and unsalted: the same name always maps to the same
/// `n-<64 hex>`, so equal names remain joinable across releases while the
/// name text does not survive. The transform is byte-exact — no case folding
/// or Unicode normalization (`"Alice"` and `"alice"` hash differently).
///
/// Errors: empty `name` → [`MetaError::BadInput`] with `"name"`. A
/// whitespace-only name is non-empty and is hashed as-is (consistent with
/// the byte-exact rule).
pub fn hash_name(name: &str) -> Result<String, MetaError> {
    if name.is_empty() {
        return Err(MetaError::BadInput("name"));
    }
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    Ok(format!("{NAME_HASH_PREFIX}{}", to_hex(h.finalize().as_slice())))
}

/// Floor a unix-millisecond instant to the enclosing hour.
///
/// `ms.div_euclid(3_600_000) * 3_600_000` — exact-hour inputs are unchanged;
/// for negative (pre-1970) inputs the floor goes toward −∞, not toward zero
/// (pin: `-1 → -3_600_000`). Callers keep millisecond units; only the
/// precision changes (≤ 1 h bucket boundary resolution).
///
/// `i64::MIN` saturates to `i64::MIN` instead of panicking: its mathematical
/// hour floor (`-9223372036854777600`) is not representable in `i64`, and
/// every representable input gets the exact `div_euclid` floor (argued
/// deviation — hardening at the single unrepresentable extreme).
pub fn coarse_timestamp(ms: i64) -> i64 {
    ms.div_euclid(HOUR_MS).saturating_mul(HOUR_MS)
}

/// Round a byte size up to the next 4096-byte multiple: 0 → 0 (already
/// canonical), otherwise the smallest `n * 4096 >= size` (pin: `1 → 4096`,
/// `4096 → 4096`, `4097 → 8192`). Saturates at [`usize::MAX`] instead of
/// overflowing.
pub fn pad_size(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        size.div_ceil(PAD_BLOCK).saturating_mul(PAD_BLOCK)
    }
}

/// Lowercase hex encoding — local helper, same convention as
/// `crate::redaction::to_hex`.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ── Policy ───────────────────────────────────────────────────────────────────

/// Which metadata-minimization transforms [`minimize`] applies. Flags off ⇒
/// the corresponding field is copied verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaPolicy {
    /// Apply [`redact_url`] to `url`.
    pub redact_urls: bool,
    /// Apply [`hash_name`] to `name`.
    pub hash_names: bool,
    /// Apply [`coarse_timestamp`] to `created_ms`.
    pub coarse_timestamps: bool,
    /// Apply [`pad_size`] to `size`.
    pub pad_sizes: bool,
}

impl MetaPolicy {
    /// All transforms enabled — the strict minimization profile.
    pub fn strict() -> MetaPolicy {
        MetaPolicy {
            redact_urls: true,
            hash_names: true,
            coarse_timestamps: true,
            pad_sizes: true,
        }
    }
}

impl Default for MetaPolicy {
    /// No transforms — every field passes through verbatim.
    fn default() -> MetaPolicy {
        MetaPolicy {
            redact_urls: false,
            hash_names: false,
            coarse_timestamps: false,
            pad_sizes: false,
        }
    }
}

// ── Items ────────────────────────────────────────────────────────────────────

/// One metadata-bearing item as it exists before minimization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaItem {
    /// Stable identifier (never transformed; always required).
    pub id: String,
    /// Human-readable name; target of [`hash_name`].
    pub name: String,
    /// Optional URL; target of [`redact_url`].
    pub url: Option<String>,
    /// Byte size; target of [`pad_size`].
    pub size: usize,
    /// Creation instant, unix ms; target of [`coarse_timestamp`].
    pub created_ms: i64,
}

/// One item after policy application. Same shape as [`MetaItem`] (the
/// transforms are value-level, so the schema is unchanged); a separate type
/// so call sites can tell minimized data from raw data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizedItem {
    /// Copied verbatim from [`MetaItem::id`].
    pub id: String,
    /// Hashed or verbatim name (per policy).
    pub name: String,
    /// Redacted or verbatim URL (per policy; `None` stays `None`).
    pub url: Option<String>,
    /// Padded or verbatim size (per policy).
    pub size: usize,
    /// Coarsened or verbatim creation instant (per policy).
    pub created_ms: i64,
}

// ── Application ──────────────────────────────────────────────────────────────

/// Apply the enabled transforms of `p` to `item`. The input is never
/// mutated.
///
/// Validation and error precedence (pinned): `id` must be non-empty
/// regardless of policy → [`MetaError::BadInput`]`("id")`; then, for each
/// enabled transform in field order (`name` before `url`), a value its
/// transform refuses (empty name / empty URL) aborts with that field's
/// token. Disabled transforms accept any value verbatim — including an empty
/// name or `Some("")` URL.
///
/// Dedupe pin: enabling `hash_names` maps equal names to equal `n-<hex>`
/// values (deterministic [`hash_name`]), so minimization preserves name
/// equality and inequality exactly.
pub fn minimize(p: &MetaPolicy, item: &MetaItem) -> Result<MinimizedItem, MetaError> {
    if item.id.is_empty() {
        return Err(MetaError::BadInput("id"));
    }
    let name = if p.hash_names {
        hash_name(&item.name)?
    } else {
        item.name.clone()
    };
    let url = match (&item.url, p.redact_urls) {
        (Some(u), true) => Some(redact_url(u)?),
        (Some(u), false) => Some(u.clone()),
        (None, _) => None,
    };
    let size = if p.pad_sizes {
        pad_size(item.size)
    } else {
        item.size
    };
    let created_ms = if p.coarse_timestamps {
        coarse_timestamp(item.created_ms)
    } else {
        item.created_ms
    };
    Ok(MinimizedItem {
        id: item.id.clone(),
        name,
        url,
        size,
        created_ms,
    })
}

/// [`minimize`] over a slice, preserving input order; an empty slice is
/// `Ok(vec![])`. The first failing item aborts the whole run with its error
/// (no partial output).
pub fn minimize_all(
    p: &MetaPolicy,
    items: &[MetaItem],
) -> Result<Vec<MinimizedItem>, MetaError> {
    items.iter().map(|item| minimize(p, item)).collect()
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from metadata minimization.
///
/// `Serialize` is derived (wire form = snake_case: `{"bad_input":"id"}`);
/// `Deserialize` is not — the `BadInput(&'static str)` payload cannot be
/// deserialized into a `'static` lifetime. This mirrors the in-repo
/// precedent (`crate::foresight_adapter::AdapterError`,
/// `crate::decay_model::DecayError`). Payloads are the offending field
/// tokens: `"id"`, `"name"`, `"url"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaError {
    /// A named input was empty or malformed; carries the field token.
    BadInput(&'static str),
}

impl fmt::Display for MetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetaError::BadInput(field) => write!(f, "invalid input: {field}"),
        }
    }
}

impl std::error::Error for MetaError {}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Externally computed constants (printf … | sha256sum) so the hashing
    // convention is grounded outside this module's own code path.
    const SHA256_ALICE: &str = "2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90";
    const SHA256_BOB: &str = "81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9";
    const SHA256_ABG: &str = "a36d0b22783c5fac3141df5bd7c0cd4c58abfaf8e2eff196ff3043226d66fbb1";
    const SHA256_ALICE_CAP: &str =
        "3bc51062973c458d5a6f2d8d64a023246354ad7e064b1e4e009ec8a0699a3043";

    fn item(id: &str, name: &str, url: Option<&str>, size: usize, created_ms: i64) -> MetaItem {
        MetaItem {
            id: id.to_string(),
            name: name.to_string(),
            url: url.map(str::to_string),
            size,
            created_ms,
        }
    }

    // ── redact_url ───────────────────────────────────────────────────────────

    #[test]
    fn redact_url_strips_query() {
        assert_eq!(
            redact_url("https://example.com/a/b?x=1&y=2").unwrap(),
            "https://example.com/a/b"
        );
    }

    #[test]
    fn redact_url_strips_fragment() {
        assert_eq!(
            redact_url("https://example.com/p#section-3").unwrap(),
            "https://example.com/p"
        );
    }

    #[test]
    fn redact_url_strips_query_and_fragment() {
        assert_eq!(
            redact_url("https://example.com/p?a=1&b=2#frag").unwrap(),
            "https://example.com/p"
        );
        // First delimiter wins; a '#' inside the (already dropped) query is
        // irrelevant.
        assert_eq!(
            redact_url("https://example.com/p?next=/x#/y").unwrap(),
            "https://example.com/p"
        );
    }

    #[test]
    fn redact_url_keeps_scheme_host_path_shapes_verbatim() {
        for (input, expected) in [
            ("https://example.com", "https://example.com"),
            ("https://example.com/", "https://example.com/"),
            ("https://example.com:8443/a/b/", "https://example.com:8443/a/b/"),
            ("http://user@example.com/p", "http://user@example.com/p"),
            ("file:///etc/passwd?x", "file:///etc/passwd"),
            ("mailto:user@example.com?subject=hi", "mailto:user@example.com"),
            // No query/fragment at all → byte-identical.
            ("custom://host/path", "custom://host/path"),
        ] {
            assert_eq!(redact_url(input).unwrap(), expected, "input {input}");
        }
    }

    #[test]
    fn redact_url_errors_on_empty_whitespace_and_empty_after_cut() {
        for input in ["", "   ", "\t\n ", "?a=1", "#frag"] {
            assert_eq!(redact_url(input), Err(MetaError::BadInput("url")), "input {input:?}");
        }
    }

    #[test]
    fn redact_url_trims_wrapping_whitespace_and_keeps_interior() {
        assert_eq!(
            redact_url("  https://e.com/a b?x=1  ").unwrap(),
            "https://e.com/a b"
        );
        assert_eq!(redact_url(" https://e.com/p ").unwrap(), "https://e.com/p");
    }

    // ── hash_name ────────────────────────────────────────────────────────────

    #[test]
    fn hash_name_prefix_shape_and_known_vectors() {
        assert_eq!(hash_name("alice").unwrap(), format!("n-{SHA256_ALICE}"));
        assert_eq!(hash_name("bob").unwrap(), format!("n-{SHA256_BOB}"));
        // Unicode names hash over UTF-8 bytes (no normalization).
        assert_eq!(hash_name("αβγ").unwrap(), format!("n-{SHA256_ABG}"));
        let out = hash_name("alice").unwrap();
        assert!(out.starts_with("n-"));
        assert_eq!(out.len(), 2 + 64);
        assert!(
            out[2..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "hex not lowercase: {out}"
        );
    }

    #[test]
    fn hash_name_is_stable_and_case_sensitive() {
        assert_eq!(hash_name("alice").unwrap(), hash_name("alice").unwrap());
        assert_ne!(hash_name("Alice").unwrap(), hash_name("alice").unwrap());
        assert_eq!(hash_name("Alice").unwrap(), format!("n-{SHA256_ALICE_CAP}"));
    }

    #[test]
    fn hash_name_rejects_empty_hashes_whitespace() {
        assert_eq!(hash_name(""), Err(MetaError::BadInput("name")));
        // Byte-exact rule: whitespace is a value like any other.
        assert_eq!(hash_name(" ").unwrap().len(), 66);
    }

    // ── coarse_timestamp ─────────────────────────────────────────────────────

    #[test]
    fn coarse_timestamp_floors_to_hour() {
        for (ms, expected) in [
            (0, 0),
            (1, 0),
            (3_599_999, 0),
            (3_600_000, 3_600_000),
            (3_600_001, 3_600_000),
            (1_700_000_123_456, 1_699_999_200_000),
        ] {
            assert_eq!(coarse_timestamp(ms), expected, "ms {ms}");
        }
    }

    #[test]
    fn coarse_timestamp_negative_floors_toward_minus_infinity() {
        for (ms, expected) in [
            (-1, -3_600_000),
            (-3_600_000, -3_600_000),
            (-3_600_001, -7_200_000),
            (-7_200_000, -7_200_000),
        ] {
            assert_eq!(coarse_timestamp(ms), expected, "ms {ms}");
        }
        // Extremes: MAX floors normally; MIN saturates (its true hour floor
        // is unrepresentable in i64) instead of panicking.
        assert_eq!(coarse_timestamp(i64::MAX), 9_223_372_036_854_000_000);
        assert_eq!(coarse_timestamp(i64::MIN), i64::MIN);
    }

    // ── pad_size ─────────────────────────────────────────────────────────────

    #[test]
    fn pad_size_boundaries() {
        for (size, expected) in [
            (0, 0),
            (1, 4096),
            (4095, 4096),
            (4096, 4096),
            (4097, 8192),
            (8191, 8192),
            (8192, 8192),
            (65_537, 69_632),
        ] {
            assert_eq!(pad_size(size), expected, "size {size}");
        }
        assert_eq!(pad_size(usize::MAX), usize::MAX, "saturates, no overflow");
    }

    // ── Policy ───────────────────────────────────────────────────────────────

    #[test]
    fn policy_strict_and_default() {
        let strict = MetaPolicy::strict();
        assert!(strict.redact_urls && strict.hash_names && strict.coarse_timestamps && strict.pad_sizes);
        let none = MetaPolicy::default();
        assert!(!none.redact_urls && !none.hash_names && !none.coarse_timestamps && !none.pad_sizes);
        assert_ne!(strict, none);
        assert_ne!(none, strict); // Eq symmetric, both directions pinned.
    }

    // ── minimize / minimize_all ──────────────────────────────────────────────

    #[test]
    fn minimize_with_none_policy_is_verbatim() {
        let it = item("id-1", "alice", Some("https://e.com/p?x=1#f"), 1, -1);
        let out = minimize(&MetaPolicy::default(), &it).unwrap();
        assert_eq!(out.id, it.id);
        assert_eq!(out.name, it.name);
        assert_eq!(out.url, it.url);
        assert_eq!(out.size, it.size);
        assert_eq!(out.created_ms, it.created_ms);
    }

    #[test]
    fn minimize_strict_applies_every_transform() {
        let it = item("id-1", "alice", Some("https://e.com/p?x=1#f"), 1, 1_700_000_123_456);
        let out = minimize(&MetaPolicy::strict(), &it).unwrap();
        assert_eq!(out.id, "id-1");
        assert_eq!(out.name, format!("n-{SHA256_ALICE}"));
        assert_eq!(out.url.as_deref(), Some("https://e.com/p"));
        assert_eq!(out.size, 4096);
        assert_eq!(out.created_ms, 1_699_999_200_000);
        // Input untouched.
        assert_eq!(it.name, "alice");
        assert_eq!(it.url.as_deref(), Some("https://e.com/p?x=1#f"));
        assert_eq!(it.size, 1);
        assert_eq!(it.created_ms, 1_700_000_123_456);
    }

    #[test]
    fn minimize_partial_policies_are_independent() {
        let it = item("id-1", "alice", Some("https://e.com/p?x=1"), 7, 5_400_001);

        let url_only = MetaPolicy { redact_urls: true, ..MetaPolicy::default() };
        let out = minimize(&url_only, &it).unwrap();
        assert_eq!(out.url.as_deref(), Some("https://e.com/p"));
        assert_eq!(out.name, "alice");
        assert_eq!(out.size, 7);
        assert_eq!(out.created_ms, 5_400_001);

        let name_only = MetaPolicy { hash_names: true, ..MetaPolicy::default() };
        let out = minimize(&name_only, &it).unwrap();
        assert_eq!(out.name, format!("n-{SHA256_ALICE}"));
        assert_eq!(out.url.as_deref(), Some("https://e.com/p?x=1"));
        assert_eq!(out.size, 7);
        assert_eq!(out.created_ms, 5_400_001);

        let time_only = MetaPolicy { coarse_timestamps: true, ..MetaPolicy::default() };
        let out = minimize(&time_only, &it).unwrap();
        assert_eq!(out.created_ms, 3_600_000);
        assert_eq!(out.name, "alice");
        assert_eq!(out.size, 7);

        let size_only = MetaPolicy { pad_sizes: true, ..MetaPolicy::default() };
        let out = minimize(&size_only, &it).unwrap();
        assert_eq!(out.size, 4096);
        assert_eq!(out.name, "alice");
        assert_eq!(out.created_ms, 5_400_001);
    }

    #[test]
    fn minimize_requires_non_empty_id() {
        let bad = item("", "alice", None, 0, 0);
        assert_eq!(minimize(&MetaPolicy::default(), &bad), Err(MetaError::BadInput("id")));
        assert_eq!(minimize(&MetaPolicy::strict(), &bad), Err(MetaError::BadInput("id")));
    }

    #[test]
    fn minimize_propagates_enabled_transform_errors_and_accepts_when_disabled() {
        let bad_name = item("id-1", "", None, 0, 0);
        assert_eq!(
            minimize(&MetaPolicy { hash_names: true, ..MetaPolicy::default() }, &bad_name),
            Err(MetaError::BadInput("name"))
        );
        // Disabled transform → empty name passes verbatim.
        assert_eq!(minimize(&MetaPolicy::default(), &bad_name).unwrap().name, "");

        let bad_url = item("id-1", "alice", Some(""), 0, 0);
        assert_eq!(
            minimize(&MetaPolicy { redact_urls: true, ..MetaPolicy::default() }, &bad_url),
            Err(MetaError::BadInput("url"))
        );
        // Disabled transform → Some("") passes verbatim.
        assert_eq!(minimize(&MetaPolicy::default(), &bad_url).unwrap().url.as_deref(), Some(""));

        // Error precedence: id before name before url.
        let both_bad = item("", "", Some(""), 0, 0);
        assert_eq!(
            minimize(&MetaPolicy::strict(), &both_bad),
            Err(MetaError::BadInput("id"))
        );
    }

    #[test]
    fn minimize_none_url_stays_none() {
        let it = item("id-1", "alice", None, 5, 5);
        assert_eq!(minimize(&MetaPolicy::strict(), &it).unwrap().url, None);
    }

    #[test]
    fn minimize_hash_dedupe_equal_names_equal_hashes() {
        let a = minimize(&MetaPolicy::strict(), &item("id-1", "alice", None, 1, 0)).unwrap();
        let b = minimize(&MetaPolicy::strict(), &item("id-2", "alice", None, 2, 0)).unwrap();
        let c = minimize(&MetaPolicy::strict(), &item("id-3", "bob", None, 3, 0)).unwrap();
        assert_eq!(a.name, b.name, "equal names must dedupe to equal hashes");
        assert_ne!(a.name, c.name, "different names must not collide");
    }

    #[test]
    fn minimize_all_preserves_order_and_empty_slice() {
        let items = vec![
            item("id-a", "alice", Some("https://e.com/a?x=1"), 1, 0),
            item("id-b", "bob", None, 4096, 1),
            item("id-c", "carol", Some("https://e.com/c#f"), 4097, -1),
        ];
        let out = minimize_all(&MetaPolicy::strict(), &items).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(
            out.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["id-a", "id-b", "id-c"]
        );
        assert_eq!(out[0].name, format!("n-{SHA256_ALICE}"));
        assert_eq!(out[1].name, format!("n-{SHA256_BOB}"));
        assert_eq!(out[1].url, None);
        assert_eq!(out[1].size, 4096);
        assert_eq!(out[2].url.as_deref(), Some("https://e.com/c"));
        assert_eq!(out[2].created_ms, -3_600_000);
        assert_eq!(out[2].size, 8192);

        let empty: Vec<MetaItem> = Vec::new();
        assert_eq!(minimize_all(&MetaPolicy::strict(), &empty), Ok(Vec::new()));
    }

    #[test]
    fn minimize_all_aborts_on_first_failure() {
        let items = vec![
            item("id-a", "alice", None, 0, 0),
            item("", "bob", None, 0, 0),
            item("id-c", "", None, 0, 0),
        ];
        assert_eq!(
            minimize_all(&MetaPolicy::strict(), &items),
            Err(MetaError::BadInput("id"))
        );
        // A later item's transform error surfaces only when earlier items pass.
        let items2 = vec![
            item("id-a", "alice", None, 0, 0),
            item("id-b", "", None, 0, 0),
        ];
        assert_eq!(
            minimize_all(&MetaPolicy::strict(), &items2),
            Err(MetaError::BadInput("name"))
        );
    }

    #[test]
    fn determinism_across_runs_and_instances() {
        let items = vec![
            item("id-a", "alice", Some("https://e.com/a?x=1"), 1, 1_800_001),
            item("id-b", "alice", Some("https://e.com/b#f"), 4097, -1),
        ];
        let p = MetaPolicy::strict();
        let run1 = minimize_all(&p, &items).unwrap();
        let run2 = minimize_all(&MetaPolicy::strict(), &items).unwrap();
        assert_eq!(run1, run2);
        assert_eq!(hash_name("carol").unwrap(), hash_name("carol").unwrap());
        assert_eq!(coarse_timestamp(5_400_001), 3_600_000);
        assert_eq!(pad_size(1), 4096);
    }

    // ── Serde / errors ───────────────────────────────────────────────────────

    #[test]
    fn serde_round_trips() {
        let policy = MetaPolicy { redact_urls: true, hash_names: false, coarse_timestamps: true, pad_sizes: false };
        let s = serde_json::to_string(&policy).unwrap();
        assert_eq!(serde_json::from_str::<MetaPolicy>(&s).unwrap(), policy);

        let it = item("id-1", "alice", Some("https://e.com/p?x=1"), 3, 1_800_001);
        let s = serde_json::to_string(&it).unwrap();
        assert_eq!(serde_json::from_str::<MetaItem>(&s).unwrap(), it);

        let min = minimize(&MetaPolicy::strict(), &it).unwrap();
        let s = serde_json::to_string(&min).unwrap();
        assert_eq!(serde_json::from_str::<MinimizedItem>(&s).unwrap(), min);

        // Wire pins: field names and error shape.
        assert_eq!(
            serde_json::to_value(&it).unwrap(),
            json!({"id":"id-1","name":"alice","url":"https://e.com/p?x=1","size":3,"created_ms":1800001})
        );
        assert_eq!(
            serde_json::to_value(MetaError::BadInput("id")).unwrap(),
            json!({"bad_input":"id"})
        );
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(MetaError::BadInput("id").to_string(), "invalid input: id");
        assert_eq!(MetaError::BadInput("url").to_string(), "invalid input: url");
        let _: &dyn std::error::Error = &MetaError::BadInput("name");
    }
}
