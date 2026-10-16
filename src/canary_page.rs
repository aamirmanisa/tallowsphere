//! Canary page — a scrape-detection surface for the operator's own docs.
//!
//! A canary page is a small, public HTML document whose text and attributes
//! carry [`crate::canary_tokens`] tripwires plus honeypot links. When a
//! crawler harvests the page into some downstream corpus, the planted tokens
//! travel with the text; finding them in the wild later is proof the page —
//! and not merely its facts — was copied.
//!
//! Design constraints:
//!
//! * **Deterministic output.** `render_page` is byte-identical across calls
//!   for the same config: no randomness, no clock, no allocation-order
//!   dependence. The page is a scripted artifact (a "poisoned" decoy document
//!   that must be reproducible for diffing / re-deployment), so tokens are
//!   derived from `sha256(site ‖ title ‖ index ‖ salt)` instead of being
//!   drawn from [`crate::canary_tokens::generate`] (which is random by
//!   design, uuid-backed).
//! * **Frozen token format.** Derived tokens keep the exact canonical shape
//!   `TLW-<KIND>-<16 lower hex>-<4 lower hex>` of the frozen §5 interface and
//!   are accepted by [`crate::canary_tokens::is_valid`]. The 4-hex checksum
//!   is computed locally over the hex-string form of the random part because
//!   `canary_tokens::checksum_of` is private; the local copy mirrors that
//!   function exactly (see its unit test `derived_tokens_validate`).
//! * **Unique tokens.** A deterministic collision bump (`salt`) guarantees
//!   the `count` embedded tokens are distinct even if two derived draws ever
//!   collided — which keeps `verify_embed`'s count check sound (dedup in
//!   `tokens_in` can never silently shrink the found set).
//! * **HTML escaping.** `site`/`title` are escaped before embedding, so the
//!   rendered page is always well-formed for its own extraction scan.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canary_tokens::{self, CanaryKind};

/// Maximum token count per page (frozen interface §6: count 0 or > 64 is a
/// config error).
pub const MAX_TOKENS: usize = 64;

/// Configuration for one canary page.
///
/// `site` identifies the property the page belongs to (used in the intro
/// text and in honeypot trap paths), `title` is the visible page title, and
/// `count` is how many canary tokens to embed (`1..=MAX_TOKENS`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryPageConfig {
    pub site: String,
    pub title: String,
    pub count: usize,
}

/// Errors from canary-page rendering / verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryPageError {
    /// `count == 0` or `count > MAX_TOKENS`.
    BadConfig,
    /// `verify_embed` found a different number of valid tokens than
    /// configured.
    Mismatch { expected: usize, found: usize },
}

impl std::fmt::Display for CanaryPageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanaryPageError::BadConfig => write!(
                f,
                "invalid canary page config: count must be in 1..={MAX_TOKENS}"
            ),
            CanaryPageError::Mismatch { expected, found } => write!(
                f,
                "canary embed mismatch: expected {expected} token(s), found {found}"
            ),
        }
    }
}

impl std::error::Error for CanaryPageError {}

/// Kind cycle used for tokens, in embed order.
const KINDS: [CanaryKind; 3] = [CanaryKind::Url, CanaryKind::Marker, CanaryKind::Serial];

/// Render a deterministic canary page for `cfg`.
///
/// The page embeds `cfg.count` unique canary tokens (kinds cycling
/// URL → MARKER → SERIAL), each in a uniquely-id'd `<span>` carrying both
/// `id="canary-<i>"` and `data-canary="<token>"`; `max(count, 2)` honeypot
/// anchors with `rel="nofollow"` to unique `/trap/<site>-<i>` paths; and a
/// `<meta name="generator">` stamp. Repeated calls with an equal config
/// return byte-identical HTML.
pub fn render_page(cfg: &CanaryPageConfig) -> Result<String, CanaryPageError> {
    if cfg.count == 0 || cfg.count > MAX_TOKENS {
        return Err(CanaryPageError::BadConfig);
    }
    let title = escape_html(&cfg.title);
    let site = escape_html(&cfg.site);
    let tokens = derive_tokens(cfg);
    let trap_count = cfg.count.max(2);
    let slug = slugify(&cfg.site);

    let mut html = String::with_capacity(768 + cfg.count * 160);
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"generator\" content=\"tallow-canary-page v1\">\n");
    html.push_str("<meta name=\"robots\" content=\"noindex, nofollow, noarchive\">\n");
    html.push_str("<title>");
    html.push_str(&title);
    html.push_str("</title>\n</head>\n<body>\n");
    html.push_str("<h1>");
    html.push_str(&title);
    html.push_str("</h1>\n");
    html.push_str("<p class=\"canary-intro\">Canary page for <code>");
    html.push_str(&site);
    html.push_str(
        "</code>. The tokens below are tripwires; harvesting this page contaminates \
         the downstream corpus with detectable markers.</p>\n",
    );
    html.push_str("<ul class=\"canary-tokens\">\n");
    for (i, token) in tokens.iter().enumerate() {
        html.push_str("<li><span id=\"canary-");
        html.push_str(&i.to_string());
        html.push_str("\" data-canary=\"");
        html.push_str(token);
        html.push_str("\">");
        html.push_str(token);
        html.push_str("</span></li>\n");
    }
    html.push_str("</ul>\n<div class=\"honeypots\">\n");
    for i in 0..trap_count {
        html.push_str("<a id=\"trap-");
        html.push_str(&i.to_string());
        html.push_str("\" class=\"trap\" rel=\"nofollow\" href=\"/trap/");
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

/// Extract the embedded canary tokens from `page`.
///
/// Scans for runs shaped like a token (literal `TLW-` followed by
/// `[0-9A-Za-z-]*`), keeps only runs accepted by
/// [`crate::canary_tokens::is_valid`] (so near-misses, truncated tokens, and
/// corruption all drop out), then returns them **sorted and deduplicated**.
/// Each distinct valid token appears once regardless of how many times it
/// occurs in the page.
pub fn tokens_in(page: &str) -> Vec<String> {
    let bytes = page.as_bytes();
    let mut found: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        if &bytes[i..i + 4] == b"TLW-" {
            let mut j = i + 4;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'-') {
                j += 1;
            }
            let candidate = &page[i..j];
            if canary_tokens::is_valid(candidate) {
                found.push(candidate.to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Round-trip check: render `cfg`, extract, and require the found token count
/// to equal `cfg.count`. Returns the found count on success.
pub fn verify_embed(cfg: &CanaryPageConfig) -> Result<usize, CanaryPageError> {
    let page = render_page(cfg)?;
    let found = tokens_in(&page).len();
    count_check(cfg.count, found)
}

/// The single count-comparison seam used by [`verify_embed`] (testable for
/// the mismatch branch, which a correct renderer cannot reach for valid
/// configs).
fn count_check(expected: usize, found: usize) -> Result<usize, CanaryPageError> {
    if expected == found {
        Ok(found)
    } else {
        Err(CanaryPageError::Mismatch { expected, found })
    }
}

/// Deterministically derive `cfg.count` unique tokens, kinds cycling and
/// document order equal to index order. The `salt` bump makes collisions
/// (astronomically unlikely, but cheap to guard) resolve deterministically.
fn derive_tokens(cfg: &CanaryPageConfig) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(cfg.count);
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for i in 0..cfg.count {
        let kind = KINDS[i % KINDS.len()];
        let mut salt: u32 = 0;
        loop {
            let token = derive_token(&cfg.site, &cfg.title, i, kind, salt);
            if seen.insert(token.clone()) {
                out.push(token);
                break;
            }
            salt += 1;
        }
    }
    out
}

/// One token: `TLW-<KIND>-<16 lower hex>-<4 lower hex>` where the random part
/// is the first 8 bytes of `sha256(domain-separator ‖ site ‖ title ‖ index ‖
/// salt)` hex-encoded, and the checksum is `sha256(random_hex)[..4]` (the
/// frozen format's rule, mirrored from `canary_tokens::checksum_of`).
fn derive_token(site: &str, title: &str, idx: usize, kind: CanaryKind, salt: u32) -> String {
    let seed = format!("tallow-canary-page\x1f{site}\x1f{title}\x1f{idx}\x1f{salt}");
    let digest = Sha256::digest(seed.as_bytes());
    let random_hex = to_hex(&digest[..8]);
    let checksum = checksum_of(&random_hex);
    format!("TLW-{}-{}-{}", kind.as_str(), random_hex, checksum)
}

/// First 4 hex chars of `sha256(random_hex)` — mirrors `canary_tokens`'s
/// private checksum rule (kept private here too; validated through the public
/// `is_valid`).
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
/// well-formed whatever `site`/`title` contain.
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

/// Path-safe slug for honeypot trap paths: ASCII alphanumerics lowercased,
/// every other run collapsed to `-`, ends trimmed; empty → `"trap"`.
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
        "trap".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn cfg(count: usize) -> CanaryPageConfig {
        CanaryPageConfig {
            site: "docs.tallow.example".to_string(),
            title: "Field notes — decoy".to_string(),
            count,
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
    fn count_respected_all_valid_and_kinds_cycle() {
        let page = render_page(&cfg(7)).expect("valid config renders");
        let embedded = attr_tokens(&page);
        assert_eq!(embedded.len(), 7, "7 tokens embedded");
        let found = tokens_in(&page);
        assert_eq!(found.len(), 7, "tokens_in sees all 7");
        assert_eq!(found, {
            let mut v = embedded.clone();
            v.sort();
            v
        });
        // Every embedded token passes the shared validator.
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
        // Unique in doc order too (no duplicate derived draw).
        let uniq: HashSet<&String> = embedded.iter().collect();
        assert_eq!(uniq.len(), 7);
    }

    #[test]
    fn derived_tokens_validate_and_checksum_matches_format() {
        // Mirror check: the local checksum rule equals the shared validator's
        // expectation for the hex-string random part.
        for i in 0..KINDS.len() {
            let t = derive_token("s", "t", i, KINDS[i], 0);
            assert!(crate::canary_tokens::is_valid(&t), "not canonical: {t}");
            let parts: Vec<&str> = t.split('-').collect();
            assert_eq!(parts.len(), 4);
            assert_eq!(parts[2].len(), 16);
            assert_eq!(parts[3], checksum_of(parts[2]));
        }
        // Different index ⇒ different token (domain separation works).
        assert_ne!(
            derive_token("s", "t", 0, CanaryKind::Url, 0),
            derive_token("s", "t", 1, CanaryKind::Url, 0)
        );
    }

    #[test]
    fn honeypots_present_unique_nofollow_and_ids_unique() {
        for count in [1usize, 2, 5, 64] {
            let page = render_page(&cfg(count)).expect("valid config renders");
            let anchors: Vec<&str> = page.split("<a ").skip(1).collect();
            assert!(
                anchors.len() >= 2,
                "want >= 2 honeypot anchors, got {} (count={count})",
                anchors.len()
            );
            assert_eq!(anchors.len(), count.max(2), "max(count, 2) traps");
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
            assert!(hrefs.iter().all(|h| h.starts_with("/trap/")));
            let uniq: HashSet<&String> = hrefs.iter().collect();
            assert_eq!(uniq.len(), hrefs.len(), "trap paths unique");
            for a in &anchors {
                assert!(
                    a.contains("rel=\"nofollow\""),
                    "every honeypot is nofollow: {a}"
                );
            }
            let doc_ids = ids(&page);
            let uniq_ids: HashSet<&String> = doc_ids.iter().collect();
            assert_eq!(uniq_ids.len(), doc_ids.len(), "element ids unique");
        }
    }

    #[test]
    fn deterministic_byte_equality() {
        let a = render_page(&cfg(9)).unwrap();
        let b = render_page(&cfg(9)).unwrap();
        assert_eq!(a, b, "same config ⇒ byte-identical page");
        // Config sensitivity (same count, different inputs).
        let mut other = cfg(9);
        other.title = "Other title".to_string();
        let c = render_page(&other).unwrap();
        assert_ne!(a, c, "title feeds token derivation");
        assert_eq!(
            attr_tokens(&a).len(),
            attr_tokens(&c).len(),
            "count unchanged"
        );
    }

    #[test]
    fn count_bounds_enforced() {
        assert_eq!(render_page(&cfg(0)).unwrap_err(), CanaryPageError::BadConfig);
        assert_eq!(
            render_page(&cfg(MAX_TOKENS + 1)).unwrap_err(),
            CanaryPageError::BadConfig
        );
        // Boundary values are valid.
        let one = render_page(&cfg(1)).expect("count 1 ok");
        assert_eq!(tokens_in(&one).len(), 1);
        let full = render_page(&cfg(MAX_TOKENS)).expect("count 64 ok");
        assert_eq!(tokens_in(&full).len(), MAX_TOKENS);
        assert_eq!(verify_embed(&cfg(MAX_TOKENS)).unwrap(), MAX_TOKENS);
    }

    #[test]
    fn tokens_in_finds_sorts_dedupes_and_validates() {
        let a = derive_token("s", "t", 0, CanaryKind::Serial, 0); // SERIAL
        let b = derive_token("s", "t", 1, CanaryKind::Url, 0); // URL
        // Deliberately out of order, duplicated, plus invalid near-misses.
        let text = format!(
            "x {a} y {b} z {a} \
             TLW-URL-0000000000000000-zzzz TLW-NOPE-0123456789abcdef-dead \
             TLW-URL-0123456789abcdef none"
        );
        let got = tokens_in(&text);
        let mut want = vec![a.clone(), b.clone()];
        want.sort();
        assert_eq!(got, want, "sorted, deduped, invalid excluded");
        assert!(tokens_in("no tokens here").is_empty());
        // Corrupted copy of a real token is rejected (flip the first checksum
        // char to a guaranteed-different hex char).
        let parts: Vec<&str> = a.split('-').collect();
        let mut bad_cs = parts[3].to_string();
        let repl = if parts[3].as_bytes()[0] == b'0' { "1" } else { "0" };
        bad_cs.replace_range(0..1, repl);
        let corrupted = format!("TLW-{}-{}-{}", parts[1], parts[2], bad_cs);
        assert!(tokens_in(&corrupted).is_empty(), "checksum corruption must fail");
    }

    #[test]
    fn verify_embed_success_and_mismatch() {
        for count in [1usize, 3, 8, 64] {
            assert_eq!(verify_embed(&cfg(count)).unwrap(), count);
        }
        // Mismatch branch: renderer is correct for valid configs, so exercise
        // the count-comparison seam directly.
        assert_eq!(
            count_check(3, 2),
            Err(CanaryPageError::Mismatch {
                expected: 3,
                found: 2
            })
        );
        assert_eq!(count_check(2, 2), Ok(2));
        // And the error renders/compares predictably.
        let e = CanaryPageError::Mismatch {
            expected: 3,
            found: 2,
        };
        assert_eq!(e.to_string(), "canary embed mismatch: expected 3 token(s), found 2");
        assert_eq!(CanaryPageError::BadConfig.to_string(), "invalid canary page config: count must be in 1..=64");
    }

    #[test]
    fn serde_roundtrip_config_and_error() {
        let c = cfg(4);
        let json = serde_json::to_string(&c).unwrap();
        let back: CanaryPageConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);

        let err = CanaryPageError::Mismatch {
            expected: 5,
            found: 1,
        };
        let ejson = serde_json::to_string(&err).unwrap();
        let eback: CanaryPageError = serde_json::from_str(&ejson).unwrap();
        assert_eq!(err, eback);
        let bjson = serde_json::to_string(&CanaryPageError::BadConfig).unwrap();
        assert_eq!(
            serde_json::from_str::<CanaryPageError>(&bjson).unwrap(),
            CanaryPageError::BadConfig
        );
    }

    #[test]
    fn escaping_keeps_page_well_formed() {
        let mut c = cfg(2);
        c.site = "ex<ample>\"&".to_string();
        c.title = "<script>alert(1)</script>".to_string();
        let page = render_page(&c).unwrap();
        assert!(!page.contains("<script>"), "raw script must not survive");
        assert!(page.contains("&lt;script&gt;"));
        assert!(page.contains("&quot;"));
        // Extraction still round-trips despite hostile inputs.
        assert_eq!(verify_embed(&c).unwrap(), 2);
        assert_eq!(tokens_in(&page).len(), 2);
    }
}
