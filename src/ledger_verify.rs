//! Ledger chain verification — recompute-and-compare tamper evidence (task A1.1.3).
//!
//! [`verify_events`] re-derives the hash chain of a slice of [`EventEnvelope`]s
//! using the shared primitives in [`crate::ledger_events`] ([`canonical_bytes`],
//! [`compute_hash`], [`GENESIS`]) and reports the *first* structural violation,
//! with the index of the failing event. [`render_report`] turns a
//! [`VerifyReport`] into stable CLI text.
//!
//! ## Checks (in order, first failure wins)
//! 1. **empty-chain** — an empty slice is valid; the reported head is `GENESIS`.
//! 2. **link** — `events[0].prev_hash == "GENESIS"`; for every `i > 0`,
//!    `events[i].prev_hash == events[i-1].hash`.
//! 3. **hash-recompute** — `compute_hash(ev.prev_hash, canonical_bytes(ev))`
//!    must equal `ev.hash` (any edit to a committed field is caught here).
//! 4. **gap/restart** — classified within the link pass: a non-first event
//!    whose `prev_hash` resets to `"GENESIS"` (a spliced/restarted chain) is
//!    reported with the reason `"gap/restart at index N"`; a plain mismatch is
//!    a `"broken link at index N"`.
//!
//! ## Reality note — detection scope
//! `EventEnvelope` has **no `seq` field**, so event *removal* cannot be proven
//! by sequence numbering. "Gap" here means exactly what the chain structure
//! can prove: a mid-list `GENESIS` link (chain restart/splice) or a
//! `prev_hash` that does not equal the predecessor's stored hash (broken
//! link). An interior deletion that leaves a re-sealed, self-consistent chain
//! is only detectable if the stored hashes no longer verify (check 3) — the
//! structural checks alone cannot see it.
//!
//! Hashing is **never re-implemented** here: this module only recomputes via
//! `crate::ledger_events`, so any future change to the hashing rule is picked
//! up automatically and cannot drift.

use crate::ledger_events::{EventEnvelope, GENESIS, canonical_bytes, compute_hash};

/// First failing event of a verification pass.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct VerifyFailure {
    /// 0-based index (into the verified slice) of the event that failed.
    pub index: usize,
    /// Stable, human-readable reason. Starts with the name of the failing
    /// check: `"broken link at index N: …"`, `"hash mismatch at index N: …"`,
    /// or `"gap/restart at index N: …"`.
    pub reason: String,
}

/// Outcome of [`verify_events`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct VerifyReport {
    /// True iff every check passed.
    pub ok: bool,
    /// Number of events examined (always the full input length).
    pub event_count: usize,
    /// Claimed head: the last event's stored `hash`, or `GENESIS` when empty.
    /// Read from the data as-shipped — when `ok == false` this is the head the
    /// (possibly tampered) chain *claims*, not a verified value.
    pub head_hash: String,
    /// First violation; `None` iff `ok`.
    pub first_failure: Option<VerifyFailure>,
}

/// Verify a hash-chained event list (checks 1–4 above, first failure wins).
///
/// Returns a [`VerifyReport`]; it never panics and never fabricates a pass —
/// a violation always yields `ok == false` with the failing event's index in
/// `first_failure.index` and a check-named `reason`.
#[allow(dead_code)]
pub fn verify_events(events: &[EventEnvelope]) -> VerifyReport {
    let event_count = events.len();
    // Claimed head of the chain as shipped (GENESIS for the empty chain).
    let head_hash = events
        .last()
        .map(|ev| ev.hash.clone())
        .unwrap_or_else(|| GENESIS.to_string());

    if events.is_empty() {
        // Check 1: the empty chain is trivially valid, head is GENESIS.
        return VerifyReport {
            ok: true,
            event_count,
            head_hash,
            first_failure: None,
        };
    }

    let mut expected_prev = GENESIS.to_string();
    let mut first_failure: Option<VerifyFailure> = None;

    for (index, ev) in events.iter().enumerate() {
        // Checks 2 + 4: structural link pass, with restarts classified
        // separately from plain breaks.
        if ev.prev_hash != expected_prev {
            let reason = if index > 0 && ev.prev_hash == GENESIS {
                format!(
                    "gap/restart at index {index}: prev_hash resets to GENESIS (expected {expected_prev})"
                )
            } else {
                format!(
                    "broken link at index {index}: expected {expected_prev}, got {}",
                    ev.prev_hash
                )
            };
            first_failure = Some(VerifyFailure { index, reason });
            break;
        }

        // Check 3: recompute the committed hash from the canonical preimage.
        let recomputed = compute_hash(&ev.prev_hash, &canonical_bytes(ev));
        if recomputed != ev.hash {
            first_failure = Some(VerifyFailure {
                index,
                reason: format!(
                    "hash mismatch at index {index}: stored {}, recomputed {recomputed}",
                    ev.hash
                ),
            });
            break;
        }

        expected_prev = ev.hash.clone();
    }

    VerifyReport {
        ok: first_failure.is_none(),
        event_count,
        head_hash,
        first_failure,
    }
}

/// Render a [`VerifyReport`] as stable, human-readable CLI text.
///
/// Format (deterministic given the report — no timestamps):
/// ```text
/// verify-ledger: <n> event(s), head=<hash>
///   [ok|FAIL|skipped] empty-chain: …
///   [ok|FAIL|skipped] link: …
///   [ok|FAIL|skipped] hash-recompute: …
///   [ok|FAIL|skipped] gap/restart: …
/// verdict: OK — … | FAIL — …
/// ```
#[allow(dead_code)]
pub fn render_report(r: &VerifyReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "verify-ledger: {} event(s), head={}\n",
        r.event_count, r.head_hash
    ));

    // Check 1: empty-chain.
    if r.event_count == 0 {
        out.push_str("  [ok] empty-chain: empty chain is valid (head=GENESIS)\n");
    } else {
        out.push_str(&format!(
            "  [ok] empty-chain: chain non-empty ({} event(s))\n",
            r.event_count
        ));
    }

    // Checks 2–4: one line per check; at most one FAIL, later checks skipped.
    match r.first_failure.as_ref() {
        None => {
            out.push_str(
                "  [ok] link: first prev_hash=GENESIS; each successor links to its predecessor\n",
            );
            out.push_str(
                "  [ok] hash-recompute: every stored hash reproduces from canonical bytes\n",
            );
            out.push_str("  [ok] gap/restart: no mid-chain GENESIS or break detected\n");
        }
        Some(f) => match check_kind(&f.reason) {
            Some(CheckKind::Link) => {
                out.push_str(&format!("  [FAIL] link: {}\n", f.reason));
                out.push_str(&format!(
                    "  [skipped] hash-recompute: stopped at first failure (index {})\n",
                    f.index
                ));
                out.push_str(&format!(
                    "  [skipped] gap/restart: stopped at first failure (index {})\n",
                    f.index
                ));
            }
            Some(CheckKind::Hash) => {
                out.push_str(
                    "  [ok] link: first prev_hash=GENESIS; each successor links to its predecessor\n",
                );
                out.push_str(&format!("  [FAIL] hash-recompute: {}\n", f.reason));
                out.push_str(&format!(
                    "  [skipped] gap/restart: stopped at first failure (index {})\n",
                    f.index
                ));
            }
            Some(CheckKind::Gap) => {
                out.push_str(&format!("  [ok] link: links intact before index {}\n", f.index));
                out.push_str(&format!(
                    "  [skipped] hash-recompute: stopped at first failure (index {})\n",
                    f.index
                ));
                out.push_str(&format!("  [FAIL] gap/restart: {}\n", f.reason));
            }
            None => {
                out.push_str(&format!("  [FAIL] check: {}\n", f.reason));
                out.push_str(&format!(
                    "  [skipped] hash-recompute: stopped at first failure (index {})\n",
                    f.index
                ));
                out.push_str(&format!(
                    "  [skipped] gap/restart: stopped at first failure (index {})\n",
                    f.index
                ));
            }
        },
    }

    // Verdict line.
    if r.ok {
        out.push_str(&format!(
            "verdict: OK — chain valid ({} event(s), head {})\n",
            r.event_count, r.head_hash
        ));
    } else {
        match r.first_failure.as_ref() {
            Some(f) => out.push_str(&format!(
                "verdict: FAIL — {} (head {})\n",
                f.reason, r.head_hash
            )),
            None => out.push_str("verdict: FAIL — no failure detail recorded\n"),
        }
    }

    out
}

// ── internal helpers ────────────────────────────────────────────────────────

/// The check that owned a failure, derived from the reason's stable prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckKind {
    Link,
    Hash,
    Gap,
}

/// Classify a [`verify_events`] reason into its check. Reason strings are
/// module-owned and stable, so exact prefix matching is safe; unknown
/// prefixes fall through (`None`) and render as a generic `check` failure.
fn check_kind(reason: &str) -> Option<CheckKind> {
    if reason.starts_with("gap/restart") {
        Some(CheckKind::Gap)
    } else if reason.starts_with("broken link") {
        Some(CheckKind::Link)
    } else if reason.starts_with("hash mismatch") {
        Some(CheckKind::Hash)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_events::{EventKind, chain_next};

    /// Build a clean, `chain_next`-linked chain of `n` events.
    fn build_chain(n: usize) -> Vec<EventEnvelope> {
        let mut out: Vec<EventEnvelope> = Vec::new();
        for i in 0..n {
            let ev = chain_next(
                out.last(),
                EventKind::Grade,
                "agent:verifier",
                "run-verify",
                &format!("{{\"i\":{i}}}"),
            );
            out.push(ev);
        }
        out
    }

    #[test]
    fn empty_chain_is_ok_with_genesis_head() {
        let r = verify_events(&[]);
        assert!(r.ok);
        assert_eq!(r.event_count, 0);
        assert_eq!(r.head_hash, "GENESIS");
        assert_eq!(r.head_hash, GENESIS);
        assert!(r.first_failure.is_none());
        let text = render_report(&r);
        assert!(text.contains("verdict: OK"), "text:\n{text}");
        assert!(text.contains("empty-chain"), "text:\n{text}");
    }

    #[test]
    fn clean_chain_verifies_ok() {
        let events = build_chain(5);
        let head = events.last().unwrap().hash.clone();
        let r = verify_events(&events);
        assert!(r.ok, "unexpected failure: {:?}", r.first_failure);
        assert_eq!(r.event_count, 5);
        assert_eq!(r.head_hash, head);
        assert!(r.first_failure.is_none());
        let text = render_report(&r);
        assert!(text.contains("verdict: OK"), "text:\n{text}");
        assert!(text.contains("hash-recompute"), "text:\n{text}");
    }

    #[test]
    fn payload_tamper_at_lead_index_is_caught() {
        let mut events = build_chain(3);
        events[0].payload = "{\"evil\":true}".to_string();
        let r = verify_events(&events);
        assert!(!r.ok);
        let f = r.first_failure.expect("tamper must be detected");
        assert_eq!(f.index, 0);
        assert!(f.reason.starts_with("hash mismatch"), "reason: {}", f.reason);
        assert_eq!(r.event_count, 3, "count reports the full slice");
    }

    #[test]
    fn payload_tamper_mid_chain_is_caught() {
        let mut events = build_chain(4);
        events[2].payload = "{\"evil\":true}".to_string();
        let r = verify_events(&events);
        assert!(!r.ok);
        let f = r.first_failure.expect("tamper must be detected");
        assert_eq!(f.index, 2);
        assert!(f.reason.starts_with("hash mismatch"), "reason: {}", f.reason);
    }

    #[test]
    fn broken_link_is_caught() {
        let mut events = build_chain(3);
        let expected = events[1].hash.clone();
        events[2].prev_hash = "deadbeef".to_string();
        let r = verify_events(&events);
        assert!(!r.ok);
        let f = r.first_failure.unwrap();
        assert_eq!(f.index, 2);
        assert!(f.reason.starts_with("broken link"), "reason: {}", f.reason);
        assert!(
            f.reason.contains(&expected),
            "reason should name the expected link; got: {}",
            f.reason
        );
    }

    #[test]
    fn first_event_prev_must_be_genesis() {
        let mut events = build_chain(2);
        events[0].prev_hash = "deadbeef".to_string();
        let r = verify_events(&events);
        assert!(!r.ok);
        let f = r.first_failure.unwrap();
        assert_eq!(f.index, 0);
        assert!(f.reason.starts_with("broken link"), "reason: {}", f.reason);
        assert!(f.reason.contains("GENESIS"), "reason: {}", f.reason);
    }

    #[test]
    fn chain_splice_flags_gap_restart() {
        // Two independently-built chains spliced together: the tail's first
        // event links to GENESIS, not to the head of the leading chain.
        // (The tail is internally self-consistent, so only the structural
        // link check can see the splice.)
        let mut events = build_chain(2);
        events.extend(build_chain(3));
        let r = verify_events(&events);
        assert!(!r.ok);
        let f = r.first_failure.unwrap();
        assert_eq!(f.index, 2, "restart detected at the tail's first event");
        assert!(
            f.reason.starts_with("gap/restart at index 2"),
            "reason: {}",
            f.reason
        );
        assert!(!f.reason.starts_with("broken link"));
    }

    #[test]
    fn render_report_is_stable_and_one_line_per_check() {
        let ok = verify_events(&build_chain(3));
        let a = render_report(&ok);
        let b = render_report(&ok);
        assert_eq!(a, b, "same report renders identically");
        assert!(a.starts_with("verify-ledger: 3 event(s), head="), "text:\n{a}");
        for needle in [
            "empty-chain",
            "link:",
            "hash-recompute",
            "gap/restart",
            "verdict: OK",
        ] {
            assert!(a.contains(needle), "missing {needle:?} in:\n{a}");
        }

        let mut tampered = build_chain(3);
        tampered[1].payload = "{\"evil\":true}".to_string();
        let bad = render_report(&verify_events(&tampered));
        assert!(bad.contains("verdict: FAIL"), "text:\n{bad}");
        assert!(bad.contains("index 1"), "text:\n{bad}");
        assert!(bad.contains("[FAIL] hash-recompute"), "text:\n{bad}");
    }
}
