//! Corroboration → auto re-grade (task A3.1.2 · E6 · frozen interface §3).
//!
//! When independent sources pile up behind an intake item, the item's
//! credibility digit should not stay frozen at its intake value. This module
//! is the deterministic policy that turns corroboration evidence into a
//! re-grade decision — and, per E6, only in the upgrading direction:
//!
//! * [`CorroborationSignal`] — how many independent domains back one item
//!   ([`domain_signal`] bridges from [`crate::corroboration::Instance`]s via
//!   [`independent_domain_count`]).
//! * [`RegradePolicy`] — the two thresholds, `probable_domains` and
//!   `confirm_domains` (documented defaults `2` / `3`).
//! * [`regrade_item`] — the single-item decision. Only digits `3`
//!   ("possibly true") and `4` ("doubtful") can move:
//!   `>= probable_domains` flips to `2` ("probably true"), `>= confirm_domains`
//!   flips to `1` ("confirmed by independent sources"). Digits `1` and `2`
//!   are already at/above the ceiling corroboration can grant; digits `5`
//!   and `6` are the unreliable class — corroboration does not rescue them.
//!   An invalid digit (`0`, `> 6`) is refused with `None`.
//! * [`apply_regrades`] — batch form over `(item_id, digit)` tuples: one
//!   event per item that has a signal and actually flips, ascending by
//!   `item_id`.
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * The policy is validated: `confirm_domains >= probable_domains >= 1`.
//!   An invalid policy is **not a panic and not an error type**: every
//!   [`regrade_item`] call returns `None` and [`apply_regrades`] returns an
//!   empty vec — a misconfigured policy can never *upgrade* anything
//!   (the documented "invalid policy = return no upgrades" semantics).
//! * Thresholds are inclusive (`>=`): exactly `probable_domains` corroborating
//!   domains is enough for the probable flip, exactly `confirm_domains` is
//!   enough for the confirmed flip.
//! * The confirm tier wins when both match: a single direct jump `4 -> 1` is
//!   intended — corroboration does not have to walk an item through `2`.
//! * Duplicate signals for one item: the **largest** `domains` value wins
//!   ({[`apply_regrades`]} takes the max over matching signals). Independent
//!   domain evidence is additive, so the strongest evidence governs.
//! * Event ordering is stable: equal `item_id`s keep input order (stable
//!   sort); items with no signal, unchanged digits, and invalid digits are
//!   skipped silently (never panics, never errors).
//! * [`ItemCredibility`](crate::source_registry::ItemCredibility) is used
//!   only to render human-readable wording in [`RegradeEvent::reason`]; the
//!   decision itself is pure digit/threshold arithmetic.
//!
//! Nothing here touches the clock, the filesystem, or global state: identical
//! inputs always produce identical outputs.

use serde::{Deserialize, Serialize};

use crate::corroboration::{independent_domain_count, Instance};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Corroboration evidence for one item: how many INDEPENDENT domains back it.
///
/// `domains` is expected to come from
/// [`independent_domain_count`](crate::corroboration::independent_domain_count),
/// which counts distinct normalized domains (same-site repeats count once).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorroborationSignal {
    /// Intake item the evidence belongs to.
    pub item_id: String,
    /// Number of independent (distinct-domain) sources behind the item.
    pub domains: usize,
}

/// One applied re-grade: an item's credibility digit moved because of
/// corroboration. Events are only ever emitted for actual changes in the
/// upgrading direction (E6: corroboration can only flip a digit up).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegradeEvent {
    /// Intake item that was re-graded.
    pub item_id: String,
    /// Credibility digit before the re-grade (`3` or `4` — the only movable digits).
    pub old_digit: u8,
    /// Credibility digit after the re-grade (`2` at the probable tier, `1` at the confirm tier).
    pub new_digit: u8,
    /// Human-readable, deterministic justification.
    pub reason: String,
}

/// Thresholds for the auto re-grade.
///
/// * `probable_domains` — at least this many independent domains flips a
///   `3`/`4` to `2` ("probably true").
/// * `confirm_domains` — at least this many flips a `3`/`4` to `1`
///   ("confirmed by independent sources").
///
/// [`RegradePolicy::default`] is `confirm_domains: 3, probable_domains: 2`.
/// A valid policy satisfies `confirm_domains >= probable_domains >= 1`;
/// invalid policies produce no upgrades (see [`RegradePolicy::is_valid`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegradePolicy {
    /// Domains needed for the confirmed (`-> 1`) flip.
    pub confirm_domains: usize,
    /// Domains needed for the probable (`-> 2`) flip.
    pub probable_domains: usize,
}

impl Default for RegradePolicy {
    /// `confirm_domains: 3`, `probable_domains: 2` (documented defaults).
    fn default() -> Self {
        Self {
            confirm_domains: 3,
            probable_domains: 2,
        }
    }
}

impl RegradePolicy {
    /// `confirm_domains >= probable_domains >= 1`.
    ///
    /// An invalid policy is handled as "return no upgrades" by every function
    /// in this module — never a panic, never an error.
    pub fn is_valid(&self) -> bool {
        self.probable_domains >= 1 && self.confirm_domains >= self.probable_domains
    }
}

// ---------------------------------------------------------------------------
// Re-grade decision
// ---------------------------------------------------------------------------

/// NATO wording for a credibility digit, for [`RegradeEvent::reason`] text.
fn word_of(digit: u8) -> &'static str {
    match crate::source_registry::ItemCredibility::from_digit(digit) {
        Ok(cred) => cred.word(),
        Err(_) => "unknown",
    }
}

/// Decide whether `current_digit` moves up given `signal_domains` independent
/// corroborating domains.
///
/// E6 semantics — corroboration can only FLIP UP, and only within the
/// unreliable class:
///
/// * digits `3`/`4` → `2` when `signal_domains >= p.probable_domains`;
/// * digits `3`/`4` → `1` when `signal_domains >= p.confirm_domains`
///   (the confirm tier wins; `4 -> 1` may skip `2`);
/// * digits `1`/`2` unchanged (already high) → `None`;
/// * digits `5`/`6` unchanged (unreliable class — corroboration does not
///   rescue them) → `None`;
/// * invalid digit (`0` or `> 6`) → `None`;
/// * invalid policy (`!p.is_valid()`) → `None` (no upgrades anywhere).
///
/// Returns `Some(event)` only when the digit actually changes; a
/// below-threshold signal yields `None`. Never panics.
pub fn regrade_item(
    item_id: &str,
    current_digit: u8,
    signal_domains: usize,
    p: &RegradePolicy,
) -> Option<RegradeEvent> {
    if !p.is_valid() {
        return None;
    }
    if !(3..=4).contains(&current_digit) {
        return None; // 1/2 already high, 5/6 unreliable, 0/>6 invalid
    }
    let new_digit = if signal_domains >= p.confirm_domains {
        1
    } else if signal_domains >= p.probable_domains {
        2
    } else {
        return None;
    };
    let (tier, threshold) = if new_digit == 1 {
        ("confirm", p.confirm_domains)
    } else {
        ("probable", p.probable_domains)
    };
    Some(RegradeEvent {
        item_id: item_id.to_string(),
        old_digit: current_digit,
        new_digit,
        reason: format!(
            "corroboration: {signal_domains} independent domain(s) >= {threshold} ({tier} threshold); digit {current_digit} ({}) -> digit {new_digit} ({})",
            word_of(current_digit),
            word_of(new_digit),
        ),
    })
}

/// Batch re-grade: for each `(item_id, digit)` use that item's signal if one
/// is present, emit only actual flips, and return events ascending by
/// `item_id` (stable: equal `item_id`s keep input order).
///
/// Items with no matching signal, below-threshold signals, unchanged digits,
/// and invalid digits are skipped silently. Duplicate signals for one item
/// are collapsed to the largest `domains` value (documented edge rule).
pub fn apply_regrades(
    items: &[(String, u8)],
    signals: &[CorroborationSignal],
    p: &RegradePolicy,
) -> Vec<RegradeEvent> {
    let mut events = Vec::new();
    for (item_id, digit) in items {
        let domains = signals
            .iter()
            .filter(|s| s.item_id.as_str() == item_id.as_str())
            .map(|s| s.domains)
            .max();
        if let Some(domains) = domains {
            if let Some(event) = regrade_item(item_id, *digit, domains, p) {
                events.push(event);
            }
        }
    }
    events.sort_by(|a, b| a.item_id.cmp(&b.item_id));
    events
}

/// Bridge from intake instances to a corroboration signal: count the
/// INDEPENDENT domains behind `item_id`'s instances
/// ([`independent_domain_count`] — blank domains are not counted, same-domain
/// repeats count once).
pub fn domain_signal(item_id: &str, instances: &[Instance]) -> CorroborationSignal {
    CorroborationSignal {
        item_id: item_id.to_string(),
        domains: independent_domain_count(instances),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corroboration::Instance;

    fn inst(source: &str, domain: &str) -> Instance {
        Instance {
            source: source.to_string(),
            domain: domain.to_string(),
        }
    }

    fn policy(confirm: usize, probable: usize) -> RegradePolicy {
        RegradePolicy {
            confirm_domains: confirm,
            probable_domains: probable,
        }
    }

    fn signal(item_id: &str, domains: usize) -> CorroborationSignal {
        CorroborationSignal {
            item_id: item_id.to_string(),
            domains,
        }
    }

    // ----- policy -----------------------------------------------------------

    #[test]
    fn default_policy_is_three_two_and_valid() {
        let p = RegradePolicy::default();
        assert_eq!(p.confirm_domains, 3);
        assert_eq!(p.probable_domains, 2);
        assert!(p.is_valid());
    }

    #[test]
    fn policy_validity_matrix() {
        assert!(policy(3, 2).is_valid());
        assert!(policy(2, 2).is_valid()); // equal thresholds: valid
        assert!(policy(1, 1).is_valid());
        assert!(!policy(1, 2).is_valid()); // confirm < probable
        assert!(!policy(2, 0).is_valid()); // probable == 0
        assert!(!policy(0, 0).is_valid());
        assert!(!policy(0, 1).is_valid());
    }

    // ----- regrade_item: upgrades ------------------------------------------

    #[test]
    fn digit_3_upgrades_at_probable_then_confirmed_threshold() {
        let p = policy(3, 2);
        assert!(regrade_item("i", 3, 1, &p).is_none(), "below probable: no event");
        let ev = regrade_item("i", 3, 2, &p).expect("probable threshold upgrades");
        assert_eq!(ev.item_id, "i");
        assert_eq!(ev.old_digit, 3);
        assert_eq!(ev.new_digit, 2);
        assert!(ev.reason.contains("probable"), "reason: {}", ev.reason);
        let ev = regrade_item("i", 3, 3, &p).expect("confirm threshold upgrades");
        assert_eq!((ev.old_digit, ev.new_digit), (3, 1));
        assert!(ev.reason.contains("confirm"), "reason: {}", ev.reason);
        // Far beyond the confirm threshold stays at digit 1 (no over-grade).
        assert_eq!(regrade_item("i", 3, 10_000, &p).unwrap().new_digit, 1);
    }

    #[test]
    fn digit_4_upgrades_directly_to_1_at_confirm() {
        let p = policy(3, 2);
        let ev = regrade_item("i", 4, 2, &p).expect("probable");
        assert_eq!((ev.old_digit, ev.new_digit), (4, 2));
        let ev = regrade_item("i", 4, 3, &p).expect("confirm");
        assert_eq!((ev.old_digit, ev.new_digit), (4, 1)); // direct 4 -> 1, skips 2
    }

    #[test]
    fn thresholds_are_inclusive_for_custom_policies() {
        let p = policy(5, 4);
        assert!(regrade_item("i", 4, 3, &p).is_none());
        assert_eq!(regrade_item("i", 4, 4, &p).unwrap().new_digit, 2); // == probable
        assert_eq!(regrade_item("i", 4, 5, &p).unwrap().new_digit, 1); // == confirm
        // Degenerate-but-valid: both thresholds equal → confirm tier wins.
        let p = policy(2, 2);
        assert_eq!(regrade_item("i", 3, 2, &p).unwrap().new_digit, 1);
    }

    // ----- regrade_item: refusals ------------------------------------------

    #[test]
    fn digits_1_2_5_6_are_never_regraded() {
        let p = policy(3, 2);
        for digit in [1u8, 2, 5, 6] {
            for domains in [0usize, 1, 2, 3, 100] {
                assert!(
                    regrade_item("i", digit, domains, &p).is_none(),
                    "digit {digit} must not move (domains {domains})"
                );
            }
        }
    }

    #[test]
    fn invalid_digit_is_none() {
        let p = policy(3, 2);
        for digit in [0u8, 7, 255] {
            assert!(regrade_item("i", digit, 100, &p).is_none());
        }
    }

    #[test]
    fn invalid_policy_returns_no_upgrades() {
        for bad in [policy(1, 2), policy(2, 0), policy(0, 0), policy(0, 1)] {
            assert!(!bad.is_valid());
            assert!(regrade_item("i", 4, 100, &bad).is_none());
            let items = vec![("i".to_string(), 4u8)];
            let sigs = vec![signal("i", 100)];
            assert!(apply_regrades(&items, &sigs, &bad).is_empty());
        }
    }

    // ----- apply_regrades ---------------------------------------------------

    #[test]
    fn apply_regrades_orders_ascending_and_skips_silently() {
        let p = policy(3, 2);
        let items = vec![
            ("zeta".to_string(), 4u8),    // signal, upgrades to 1
            ("alpha".to_string(), 3u8),   // signal, upgrades to 2
            ("missing".to_string(), 3u8), // no signal → skipped
            ("high".to_string(), 1u8),    // signal but digit 1 → unchanged → skipped
            ("low".to_string(), 4u8),     // signal below probable → skipped
            ("bad".to_string(), 0u8),     // invalid digit → skipped
        ];
        let signals = vec![
            signal("zeta", 3),
            signal("alpha", 2),
            signal("high", 9),
            signal("low", 1),
            signal("bad", 9),
        ];
        let evs = apply_regrades(&items, &signals, &p);
        let ids: Vec<&str> = evs.iter().map(|e| e.item_id.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "zeta"]); // ascending, not input order
        assert_eq!((evs[0].old_digit, evs[0].new_digit), (3, 2));
        assert_eq!((evs[1].old_digit, evs[1].new_digit), (4, 1));
    }

    #[test]
    fn apply_regrades_duplicate_signals_take_the_max() {
        let p = policy(3, 2);
        let items = vec![("dup".to_string(), 3u8)];
        let signals = vec![
            signal("dup", 1), // weakest first
            signal("dup", 3), // strongest governs
        ];
        let evs = apply_regrades(&items, &signals, &p);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].new_digit, 1, "max domains (3) must reach the confirm tier");
    }

    #[test]
    fn apply_regrades_empty_and_no_signal_cases() {
        let p = RegradePolicy::default();
        assert!(apply_regrades(&[], &[], &p).is_empty());
        let items = vec![("a".to_string(), 3u8)];
        assert!(apply_regrades(&items, &[], &p).is_empty());
    }

    #[test]
    fn apply_regrades_skips_are_not_errors_never_panics() {
        // Digit 255, item with no signal, signal with zero domains: all silent.
        let p = RegradePolicy::default();
        let items = vec![
            ("x".to_string(), 255u8),
            ("y".to_string(), 6u8),
        ];
        let signals = vec![signal("x", 0), signal("y", 0)];
        assert!(apply_regrades(&items, &signals, &p).is_empty());
    }

    // ----- bridge -----------------------------------------------------------

    #[test]
    fn bridge_counts_distinct_domains() {
        let instances = [
            inst("Reuters", "site-26.example"),
            inst("Reuters mirror", "site-26.example "), // same domain, case/space variant
            inst("AP", "site-01.example"),
            inst("anonymous tip", ""), // blank domain: no independence evidence
            inst("AP again", " site-01.example"),
        ];
        let sig = domain_signal("report-1", &instances);
        assert_eq!(sig.item_id, "report-1");
        assert_eq!(sig.domains, 2);

        // No instances → zero domains → the bridge cannot upgrade anything.
        let sig = domain_signal("report-2", &[]);
        assert_eq!(sig.domains, 0);
        assert!(regrade_item(&sig.item_id, 4, sig.domains, &RegradePolicy::default()).is_none());
    }

    #[test]
    fn bridge_feeds_apply_regrades() {
        let p = RegradePolicy::default();
        let instances = [
            inst("one", "one.example"),
            inst("two", "two.example"),
            inst("three", "three.example"),
        ];
        let sig = domain_signal("multi", &instances); // 3 distinct domains
        let items = vec![("multi".to_string(), 3u8)];
        let evs = apply_regrades(&items, std::slice::from_ref(&sig), &p);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].new_digit, 1); // 3 >= confirm default of 3
    }

    // ----- determinism + serde ---------------------------------------------

    #[test]
    fn deterministic_same_input_twice() {
        let p = policy(3, 2);
        let items = vec![("b".to_string(), 4u8), ("a".to_string(), 3u8)];
        let signals = vec![signal("a", 2), signal("b", 3)];
        assert_eq!(
            apply_regrades(&items, &signals, &p),
            apply_regrades(&items, &signals, &p),
            "same input must produce identical output"
        );
    }

    #[test]
    fn reason_is_deterministic_and_informative() {
        let p = policy(3, 2);
        let ev = regrade_item("r", 4, 3, &p).unwrap();
        assert_eq!(
            ev.reason,
            "corroboration: 3 independent domain(s) >= 3 (confirm threshold); digit 4 (doubtful) -> digit 1 (confirmed by independent sources)"
        );
    }

    #[test]
    fn serde_round_trip_and_wire_form() {
        let s = signal("report-1", 3);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"item_id":"report-1","domains":3}"#);
        assert_eq!(serde_json::from_str::<CorroborationSignal>(&json).unwrap(), s);

        let e = RegradeEvent {
            item_id: "report-1".to_string(),
            old_digit: 3,
            new_digit: 2,
            reason: "corroborated".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(
            json,
            r#"{"item_id":"report-1","old_digit":3,"new_digit":2,"reason":"corroborated"}"#
        );
        assert_eq!(serde_json::from_str::<RegradeEvent>(&json).unwrap(), e);

        let p = policy(4, 2);
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, r#"{"confirm_domains":4,"probable_domains":2}"#);
        assert_eq!(serde_json::from_str::<RegradePolicy>(&json).unwrap(), p);
    }
}
