//! Correspondence minimization for ephemeral channels (A2.1.4).
//!
//! Correspondence items (messages, call notes, drop confirmations — anything
//! that exists briefly and must not accumulate) carry an explicit
//! [`Correspondence::ttl_ms`]. Past that TTL the item is **expired** and the
//! caller is expected to drop it ([`purge_expired`]).
//!
//! The one way an item may outlive its TTL is **redacted archival**: an item
//! may only be moved to `archived` state when a redaction receipt is supplied
//! ([`archive`]). Archival is therefore never a silent "keep the plaintext
//! around" path — retention without redaction is impossible by construction,
//! and [`purge_expired`] never touches archived (already-redacted) items.
//!
//! Time is Unix-epoch **milliseconds** (`now_ms`), consistent with the rest of
//! the ledger family. All functions are pure except [`archive`] and
//! [`purge_expired`], which mutate their arguments; none panic (expiry
//! arithmetic saturates and never overflows).

use std::fmt;

use serde::{Deserialize, Serialize};

/// Milliseconds in the default ephemeral TTL (24 hours).
pub const DEFAULT_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

// ── Policy ───────────────────────────────────────────────────────────────────

/// Retention policy applied to newly created correspondence.
///
/// [`Default`] is documented as **24 h** ([`DEFAULT_TTL_MS`]): correspondence
/// is ephemeral by default and a longer window must be requested explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EphemeralPolicy {
    /// Time-to-live in milliseconds; must be `> 0` (see [`EphemeralPolicy::validate`]).
    pub ttl_ms: i64,
}

impl Default for EphemeralPolicy {
    /// Documented default: 24 h ([`DEFAULT_TTL_MS`]).
    fn default() -> Self {
        Self {
            ttl_ms: DEFAULT_TTL_MS,
        }
    }
}

impl EphemeralPolicy {
    /// A non-positive TTL is nonsense (an item that is expired before it
    /// exists) — refuse it up front.
    pub fn validate(&self) -> Result<(), EphemeralError> {
        if self.ttl_ms > 0 {
            Ok(())
        } else {
            Err(EphemeralError::BadTtl)
        }
    }
}

// ── Correspondence item ──────────────────────────────────────────────────────

/// One ephemeral correspondence item.
///
/// * `id` — caller-supplied identifier (must be non-empty to be created).
/// * `created_ms` / `ttl_ms` — expiry is `created_ms + ttl_ms`
///   (see [`is_expired`]).
/// * `archived` / `redaction_receipt` — set together by [`archive`]; an
///   archived item is already redacted and is exempt from purging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Correspondence {
    /// Caller-supplied identifier (non-empty at creation).
    pub id: String,
    /// Unix-epoch ms at creation.
    pub created_ms: i64,
    /// TTL in ms carried from the creation policy.
    pub ttl_ms: i64,
    /// `true` once archived via [`archive`] (redaction receipt attached).
    pub archived: bool,
    /// Redaction receipt that authorized archival; `None` until archived.
    pub redaction_receipt: Option<String>,
}

// ── Denial reason ────────────────────────────────────────────────────────────

/// Why a correspondence operation was refused. One variant per rule so audit
/// records can aggregate refusals by cause; serde-round-trippable for ledger
/// payloads. `Display` renders a human audit line and [`code`](Self::code) a
/// stable machine token (same pattern as the sibling gate modules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EphemeralError {
    /// `id` was empty (or whitespace-only).
    EmptyId,
    /// Archival was attempted without a redaction receipt.
    MissingRedactionReceipt,
    /// The item is already archived; archival is one-way.
    AlreadyArchived,
    /// Policy TTL was not `> 0`.
    BadTtl,
}

impl EphemeralError {
    /// Stable machine code for audit aggregation (never localized).
    pub fn code(&self) -> &'static str {
        match self {
            EphemeralError::EmptyId => "deny.empty-id",
            EphemeralError::MissingRedactionReceipt => "deny.missing-redaction-receipt",
            EphemeralError::AlreadyArchived => "deny.already-archived",
            EphemeralError::BadTtl => "deny.bad-ttl",
        }
    }
}

impl fmt::Display for EphemeralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EphemeralError::EmptyId => f.write_str("correspondence refused: empty id"),
            EphemeralError::MissingRedactionReceipt => {
                f.write_str("archival refused: redaction receipt required")
            }
            EphemeralError::AlreadyArchived => {
                f.write_str("archival refused: item already archived")
            }
            EphemeralError::BadTtl => {
                f.write_str("policy refused: ttl_ms must be > 0")
            }
        }
    }
}

impl std::error::Error for EphemeralError {}

// ── Operations ───────────────────────────────────────────────────────────────

/// Is `c` expired at `now_ms`?
///
/// Boundary is **inclusive**: expired iff `now_ms >= created_ms + ttl_ms`, so
/// at exactly `created_ms + ttl_ms` the item is already expired and a fresh
/// item is live for exactly `ttl_ms` milliseconds of wall time. The addition
/// saturates (never panics on extreme timestamps).
pub fn is_expired(c: &Correspondence, now_ms: i64) -> bool {
    now_ms >= c.created_ms.saturating_add(c.ttl_ms)
}

/// Archive `c` — **only** with a redaction receipt.
///
/// * `Err(AlreadyArchived)` — `c` is already archived; nothing is mutated.
///   This guard takes precedence over the receipt check below so a second
///   archival attempt is reported as such even with an empty receipt.
/// * `Err(MissingRedactionReceipt)` — `receipt` is empty or whitespace-only;
///   nothing is mutated (an archival without a trace of the redaction is
///   never allowed).
/// * `Ok(())` — `c.archived = true` and `c.redaction_receipt = Some(receipt)`
///   (stored verbatim, not trimmed).
///
/// `_now_ms` is an audit-time parameter reserved for callers that stamp the
/// archival; the current rule set does not gate on it (same shape as the
/// sibling gates' audit fields).
pub fn archive(c: &mut Correspondence, receipt: &str, _now_ms: i64) -> Result<(), EphemeralError> {
    if c.archived {
        return Err(EphemeralError::AlreadyArchived);
    }
    if receipt.trim().is_empty() {
        return Err(EphemeralError::MissingRedactionReceipt);
    }
    c.archived = true;
    c.redaction_receipt = Some(receipt.to_string());
    Ok(())
}

/// Remove expired items from `items` in place and return how many were removed.
///
/// **Archived items are never purged**, expired or not: they were explicitly
/// redacted before being kept, so the retention decision has already been
/// adjudicated — deleting them here would destroy the redaction record the
/// archival workflow depends on. Live items are kept. Order of the survivors
/// is preserved. Idempotent: a second call with the same `now_ms` returns 0.
pub fn purge_expired(items: &mut Vec<Correspondence>, now_ms: i64) -> usize {
    let before = items.len();
    items.retain(|c| c.archived || !is_expired(c, now_ms));
    before - items.len()
}

/// Create a fresh correspondence item under `policy`.
///
/// * `Err(EmptyId)` — `id` is empty or whitespace-only.
/// * `Err(BadTtl)` — `policy` fails [`EphemeralPolicy::validate`]
///   (fail-closed judgment call: a non-positive TTL would otherwise yield an
///   item that is expired on arrival).
/// * `Ok(c)` — `archived: false`, `redaction_receipt: None`, `id` stored
///   verbatim.
pub fn new_correspondence(
    id: &str,
    now_ms: i64,
    policy: &EphemeralPolicy,
) -> Result<Correspondence, EphemeralError> {
    if id.trim().is_empty() {
        return Err(EphemeralError::EmptyId);
    }
    policy.validate()?;
    Ok(Correspondence {
        id: id.to_string(),
        created_ms: now_ms,
        ttl_ms: policy.ttl_ms,
        archived: false,
        redaction_receipt: None,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn item(id: &str, created_ms: i64) -> Correspondence {
        new_correspondence(id, created_ms, &EphemeralPolicy::default()).unwrap()
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let c = item("m-1", 1_000);
        // TTL 24h => expired at exactly created + ttl.
        let deadline = 1_000 + DEFAULT_TTL_MS;
        assert!(!is_expired(&c, deadline - 1), "one ms before: live");
        assert!(is_expired(&c, deadline), "exactly at deadline: expired");
        assert!(is_expired(&c, deadline + 1), "after deadline: expired");
        assert!(!is_expired(&c, 1_000), "at creation: live");
    }

    #[test]
    fn expiry_arithmetic_saturates_without_panic() {
        let c = Correspondence {
            id: "x".into(),
            created_ms: i64::MAX,
            ttl_ms: i64::MAX,
            archived: false,
            redaction_receipt: None,
        };
        assert!(is_expired(&c, i64::MAX));
        let c2 = Correspondence {
            id: "x".into(),
            created_ms: i64::MIN,
            ttl_ms: 1,
            archived: false,
            redaction_receipt: None,
        };
        assert!(is_expired(&c2, 0));
    }

    #[test]
    fn archive_requires_redaction_receipt() {
        let mut c = item("m-2", 0);
        assert_eq!(
            archive(&mut c, "", 5),
            Err(EphemeralError::MissingRedactionReceipt)
        );
        assert!(!c.archived, "failed archival must not mutate");
        assert_eq!(c.redaction_receipt, None);
        assert_eq!(
            archive(&mut c, "   \t", 5),
            Err(EphemeralError::MissingRedactionReceipt),
            "whitespace-only counts as missing"
        );
        assert!(!c.archived);
    }

    #[test]
    fn archive_succeeds_with_receipt() {
        let mut c = item("m-3", 0);
        assert_eq!(archive(&mut c, "redact-2026-09-11-001", 42), Ok(()));
        assert!(c.archived);
        assert_eq!(
            c.redaction_receipt.as_deref(),
            Some("redact-2026-09-11-001"),
            "receipt stored verbatim"
        );
    }

    #[test]
    fn archive_is_one_way() {
        let mut c = item("m-4", 0);
        archive(&mut c, "r-1", 1).unwrap();
        assert_eq!(archive(&mut c, "r-2", 2), Err(EphemeralError::AlreadyArchived));
        assert_eq!(c.redaction_receipt.as_deref(), Some("r-1"), "no overwrite");
        // AlreadyArchived precedence: even with an empty receipt.
        assert_eq!(archive(&mut c, "", 3), Err(EphemeralError::AlreadyArchived));
        assert_eq!(c.redaction_receipt.as_deref(), Some("r-1"));
    }

    #[test]
    fn purge_removes_only_live_expired() {
        let now = 10_000;
        let ttl = 1_000;
        let mut items = vec![
            new_correspondence("live", now, &EphemeralPolicy { ttl_ms: ttl }).unwrap(),
            new_correspondence("expired", now - ttl, &EphemeralPolicy { ttl_ms: ttl }).unwrap(),
            new_correspondence("expired-2", now - 5 * ttl, &EphemeralPolicy { ttl_ms: ttl })
                .unwrap(),
        ];
        // Archive the second expired one: it must survive the purge.
        archive(&mut items[2], "r-9", now).unwrap();
        let removed = purge_expired(&mut items, now);
        assert_eq!(removed, 1, "only the un-archived expired item goes");
        let ids: Vec<&str> = items.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["live", "expired-2"], "order preserved");
        assert_eq!(purge_expired(&mut items, now), 0, "idempotent");
    }

    #[test]
    fn purge_boundary_exact_deadline_removes() {
        let mut items = vec![item("edge", 1_000)];
        let deadline = 1_000 + DEFAULT_TTL_MS;
        assert_eq!(purge_expired(&mut items, deadline - 1), 0);
        assert_eq!(purge_expired(&mut items, deadline), 1, "deadline is expired");
        assert!(items.is_empty());
    }

    #[test]
    fn archived_never_purged_even_far_past_ttl() {
        let mut c = item("kept", 0);
        archive(&mut c, "r-keep", 0).unwrap();
        let mut items = vec![c];
        assert_eq!(purge_expired(&mut items, DEFAULT_TTL_MS * 100), 0);
        assert_eq!(items.len(), 1);
        assert!(items[0].archived);
    }

    #[test]
    fn default_policy_is_24h_ephemeral() {
        let p = EphemeralPolicy::default();
        assert_eq!(p.ttl_ms, DEFAULT_TTL_MS);
        assert_eq!(p.ttl_ms, 86_400_000);
        p.validate().unwrap();
        let c = new_correspondence("d-1", 0, &p).unwrap();
        assert_eq!(c.ttl_ms, DEFAULT_TTL_MS);
        assert!(!c.archived, "default is ephemeral, not archived");
        assert_eq!(c.redaction_receipt, None);
        assert!(!is_expired(&c, DEFAULT_TTL_MS - 1));
        assert!(is_expired(&c, DEFAULT_TTL_MS));
    }

    #[test]
    fn new_correspondence_refuses_empty_id() {
        let p = EphemeralPolicy::default();
        assert_eq!(new_correspondence("", 0, &p), Err(EphemeralError::EmptyId));
        assert_eq!(
            new_correspondence(" \n\t", 0, &p),
            Err(EphemeralError::EmptyId)
        );
        assert!(new_correspondence("ok", 0, &p).is_ok());
    }

    #[test]
    fn bad_ttl_refused_everywhere() {
        assert_eq!(EphemeralPolicy { ttl_ms: 0 }.validate(), Err(EphemeralError::BadTtl));
        assert_eq!(EphemeralPolicy { ttl_ms: -1 }.validate(), Err(EphemeralError::BadTtl));
        assert_eq!(
            new_correspondence("x", 0, &EphemeralPolicy { ttl_ms: 0 }),
            Err(EphemeralError::BadTtl)
        );
    }

    #[test]
    fn serde_roundtrips() {
        let c = item("s-1", 123);
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j, json!({
            "id": "s-1",
            "created_ms": 123,
            "ttl_ms": DEFAULT_TTL_MS,
            "archived": false,
            "redaction_receipt": null,
        }));
        let back: Correspondence = serde_json::from_value(j).unwrap();
        assert_eq!(back, c);

        let p: EphemeralPolicy =
            serde_json::from_value(serde_json::to_value(EphemeralPolicy::default()).unwrap())
                .unwrap();
        assert_eq!(p, EphemeralPolicy::default());

        for (e, tok) in [
            (EphemeralError::EmptyId, "\"empty_id\""),
            (
                EphemeralError::MissingRedactionReceipt,
                "\"missing_redaction_receipt\"",
            ),
            (EphemeralError::AlreadyArchived, "\"already_archived\""),
            (EphemeralError::BadTtl, "\"bad_ttl\""),
        ] {
            assert_eq!(serde_json::to_string(&e).unwrap(), tok);
            let back: EphemeralError = serde_json::from_str(tok).unwrap();
            assert_eq!(back, e);
        }
    }

    #[test]
    fn error_display_and_code_are_stable() {
        assert_eq!(EphemeralError::EmptyId.code(), "deny.empty-id");
        assert_eq!(
            EphemeralError::MissingRedactionReceipt.code(),
            "deny.missing-redaction-receipt"
        );
        assert_eq!(EphemeralError::AlreadyArchived.code(), "deny.already-archived");
        assert_eq!(EphemeralError::BadTtl.code(), "deny.bad-ttl");
        assert!(format!("{}", EphemeralError::MissingRedactionReceipt).contains("receipt"));
        // std::error::Error is implemented (usable with ?/anyhow).
        let _e: Box<dyn std::error::Error> = Box::new(EphemeralError::EmptyId);
    }

    #[test]
    fn deterministic_pipeline() {
        let run = || {
            let p = EphemeralPolicy { ttl_ms: 500 };
            let mut items = vec![
                new_correspondence("a", 0, &p).unwrap(),
                new_correspondence("b", 0, &p).unwrap(),
                new_correspondence("c", 400, &p).unwrap(),
            ];
            archive(&mut items[1], "r-b", 0).unwrap();
            let removed = purge_expired(&mut items, 500);
            (removed, items)
        };
        let (r1, v1) = run();
        let (r2, v2) = run();
        assert_eq!(r1, 1);
        assert_eq!((r1, &v1), (r2, &v2), "same inputs -> same outcome");
        let ids: Vec<&str> = v1.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "c"]);
    }
}
