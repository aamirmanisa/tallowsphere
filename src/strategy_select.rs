//! State-dependent strategy selection (frozen interface §6, tasks B2.3.1–B2.3.3).
//!
//! The strategy layer maps an observed *state hint* onto a [`StrategyPlan`]:
//! which move leads ([`StrategyPlan::primary`]) and which moves are on the
//! table at all ([`StrategyPlan::moves`]). The mapping is a pinned,
//! table-driven policy — [`STRATEGY_TABLE`] is the single source of truth and
//! [`select`] is a pure lookup through it, so the policy can be audited in
//! one place:
//!
//! | hint | primary | intent |
//! |------|---------|--------|
//! | `Sluggish` | `Explore` | explore / widen — slow state, look for options |
//! | `Agitated` | `Stabilize` | narrow / stabilize — agitated state, reduce surface |
//! | `Steady` | `Monitor` | neutral — observation only |
//!
//! # Monitor is always on (B2.3.1)
//! Every plan carries [`Move::Monitor`] in `moves`, whatever the hint — the
//! three-row mapping above is the frozen pin. `moves` always contains the
//! primary plus `Monitor`, deduplicated and sorted by [`Move`] order
//! (`Explore < Stabilize < Monitor`, the enum declaration order, pinned by a
//! test), so plans are deterministic and directly comparable across callers.
//! For `Steady` the primary *is* `Monitor`, so a plan always has at least one
//! move and `Monitor` appears exactly once.
//!
//! # Meta-controller aggregation (B2.3.2, [`from_hints`])
//! A meta-controller may observe several hints at once and must collapse them
//! into one plan with a fixed precedence — **Agitated > Sluggish > Steady**
//! (agitation dominates: stabilizing wins any conflict; otherwise sluggish
//! over steady; observation is the floor). An empty hint slice is the steady
//! default. Aggregation is order-independent (any permutation of the same
//! multiset yields the same plan) and `Monitor` is always present.
//!
//! # Scope / integration
//! Pure functions: no I/O, no clock, no globals, no state. Not wired into
//! `lib.rs` yet (the parent does that). Intended consumers: the runtime
//! orchestration loop (one [`select`] per observed hint) and the
//! meta-controller hook ([`from_hints`]) that aggregates hints reported by
//! subordinate cells. [`StateHint`], [`Move`], and [`StrategyPlan`] are
//! serde-round-trippable so hints and plans can travel the ledger with stable
//! variant names.

use serde::{Deserialize, Serialize};

/// Coarse observed-state hint that drives strategy selection (B2.3.1).
///
/// Frozen vocabulary: `Sluggish` (slow, low throughput), `Steady` (nominal),
/// `Agitated` (elevated, unstable). Wire form is the variant name
/// (`"Sluggish"` / `"Steady"` / `"Agitated"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateHint {
    /// Low throughput / slow progress — widen the search.
    Sluggish,
    /// Nominal — observe only.
    Steady,
    /// Elevated / unstable — narrow and stabilize.
    Agitated,
}

/// A strategic move available to the planner.
///
/// Declaration order **is** the frozen sort order
/// (`Explore < Stabilize < Monitor`) that [`StrategyPlan::moves`] relies on;
/// a test pins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Move {
    /// Explore / widen: take on options and seek new information.
    Explore,
    /// Stabilize / narrow: reduce surface, hold what exists.
    Stabilize,
    /// Monitor: observation only, no intervention (always on).
    Monitor,
}

/// A strategy plan: one primary move plus the set of moves in play.
///
/// `moves` always contains [`Move::Monitor`] (monitor is always-on) and the
/// primary; it is deduplicated and sorted by [`Move`] order, so plans built
/// from the same hint are equal and serialization is stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyPlan {
    /// The move that leads the plan.
    pub primary: Move,
    /// All moves in play: `Monitor` plus `primary`, deduplicated, sorted.
    pub moves: Vec<Move>,
}

/// The frozen hint → primary-move policy table (single source of truth).
///
/// [`select`] is a pure lookup over this table; changing strategy policy means
/// changing this table. A test pins it exact and total over every
/// [`StateHint`].
const STRATEGY_TABLE: &[(StateHint, Move)] = &[
    (StateHint::Sluggish, Move::Explore),
    (StateHint::Agitated, Move::Stabilize),
    (StateHint::Steady, Move::Monitor),
];

/// Select the strategy plan for one observed state hint (B2.3.1).
///
/// Pure table lookup: [`StateHint::Sluggish`] ⇒ [`Move::Explore`],
/// [`StateHint::Agitated`] ⇒ [`Move::Stabilize`], [`StateHint::Steady`] ⇒
/// [`Move::Monitor`]. The resulting plan always carries [`Move::Monitor`] in
/// `moves` alongside the primary (deduplicated, sorted by [`Move`] order).
pub fn select(hint: StateHint) -> StrategyPlan {
    let primary = primary_for(hint);
    StrategyPlan {
        primary,
        moves: plan_moves(primary),
    }
}

/// Aggregate many observed hints into one plan (B2.3.2 meta-controller hook).
///
/// Precedence is fixed — **Agitated > Sluggish > Steady**: any agitated hint
/// makes the plan stabilize, else any sluggish hint makes it explore, else the
/// plan is the steady default (observation only). An empty slice returns the
/// steady default. Order-independent and deterministic; [`Move::Monitor`] is
/// always in `moves`.
pub fn from_hints(hints: &[StateHint]) -> StrategyPlan {
    let dominant = if hints.contains(&StateHint::Agitated) {
        StateHint::Agitated
    } else if hints.contains(&StateHint::Sluggish) {
        StateHint::Sluggish
    } else {
        StateHint::Steady
    };
    select(dominant)
}

/// Look up the primary move for `hint` in [`STRATEGY_TABLE`].
///
/// The table is total over [`StateHint`] (pinned by a test); the `Monitor`
/// fallback only guards a future table edit that drops a row — observation
/// only is the safe default.
fn primary_for(hint: StateHint) -> Move {
    STRATEGY_TABLE
        .iter()
        .find_map(|&(h, m)| (h == hint).then_some(m))
        .unwrap_or(Move::Monitor)
}

/// Build `moves` for a primary: always `Monitor`, plus `primary`, deduplicated
/// and sorted by [`Move`] order.
fn plan_moves(primary: Move) -> Vec<Move> {
    let mut moves = vec![Move::Monitor, primary];
    moves.sort();
    moves.dedup();
    moves
}

// ---------------------------------------------------------------------------
// Escalation ladder (P1 W3-S1) — strategy_select as the escalation seed
// ---------------------------------------------------------------------------
//
// The antibot/retry path classifies the state it observed (a block signal, a
// transient error, a transport failure) and asks for the next move here. The
// ladder is deterministic over `(attempt, signal)` and its action order is
// **plain → stealth → escalate → rotate-egress → back-off**; the strategy
// plan for the signal's hint ([`select`]) rides along as the escalation seed,
// so the recorded trace carries both the tactical action and the strategic
// posture. No I/O, no clock — callers own the effects and the timestamps.

/// Observed attempt signal, classified by the caller (antibot/retry path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttemptSignal {
    /// No block signal — serve as-is; escalation must be a no-op.
    Clean,
    /// Transient server/network condition (timeout, 5xx): back off only.
    Transient,
    /// Soft block (429 / interstitial): escalate gradually.
    SoftBlock,
    /// Hard block / captcha wall: escalate egress immediately.
    HardBlock,
    /// Transport-level failure (refused/reset): escalate like a hard block.
    TransportError,
}

/// One ladder action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscalationAction {
    /// Serve as-is (the no-signal path; zero behavior change).
    Serve,
    /// Re-apply the stealth bootstrap on the active page before retrying.
    ApplyStealth,
    /// Escalate the proxy tier.
    EscalateTier,
    /// Rotate egress (drop the cached circuit / request a fresh one).
    RotateEgress,
    /// Back off and retry at the same posture (the last rung).
    BackOff,
}

/// The deterministic escalation step for one `(attempt, signal)`.
///
/// `attempt` is the zero-based index of the attempt that just failed
/// (`attempt = 0` is the first attempt; the ladder applies from the first
/// retry). `backoff_ms` preserves the historical per-signal exponential
/// shape: `base * 2^min(attempt, cap)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationStep {
    /// The ladder action the caller must apply before the next attempt.
    pub action: EscalationAction,
    /// The state hint the signal maps to (the strategy seed).
    pub hint: StateHint,
    /// The strategy plan for `hint` (Monitor always present).
    pub strategy: StrategyPlan,
    /// Milliseconds to wait before the next attempt.
    pub backoff_ms: u64,
}

/// Map an observed signal to the state hint that seeds the strategy plan.
///
/// `Agitated` (stabilize/narrow) for block signals — reduce surface. `Sluggish`
/// (explore/widen) for transport/transient conditions — try other options.
pub fn hint_for(signal: AttemptSignal) -> StateHint {
    match signal {
        AttemptSignal::Clean => StateHint::Steady,
        AttemptSignal::Transient => StateHint::Sluggish,
        AttemptSignal::SoftBlock | AttemptSignal::HardBlock => StateHint::Agitated,
        AttemptSignal::TransportError => StateHint::Sluggish,
    }
}

/// The deterministic escalation step for `(attempt, signal)` (W3-S1).
///
/// Ladder (first retry → last):
/// - `Clean` → [`EscalationAction::Serve`], `backoff_ms = 0`. This is the
///   "no behavior change when no block signal" contract: nothing escalates.
/// - `Transient` → `BackOff` at every attempt (server-side issue; no posture
///   change), `500 * 2^n` ms (capped n=4).
/// - `SoftBlock` → `ApplyStealth` → `EscalateTier` → `RotateEgress` →
///   `BackOff` (repeats), `1000 * 2^n` ms (capped n=4).
/// - `HardBlock` → `EscalateTier` → `RotateEgress` → `BackOff` (repeats),
///   `3000 * 2^n` ms (capped n=3).
/// - `TransportError` → `EscalateTier` → `RotateEgress` → `BackOff`
///   (repeats), `2000 * 2^n` ms (capped n=3).
pub fn escalation_step(attempt: u32, signal: AttemptSignal) -> EscalationStep {
    let (action, base, cap) = match signal {
        AttemptSignal::Clean => (EscalationAction::Serve, 0, 0),
        AttemptSignal::Transient => (EscalationAction::BackOff, 500, 4),
        AttemptSignal::SoftBlock => (
            match attempt {
                0 => EscalationAction::ApplyStealth,
                1 => EscalationAction::EscalateTier,
                2 => EscalationAction::RotateEgress,
                _ => EscalationAction::BackOff,
            },
            1000,
            4,
        ),
        AttemptSignal::HardBlock => (
            match attempt {
                0 => EscalationAction::EscalateTier,
                1 => EscalationAction::RotateEgress,
                _ => EscalationAction::BackOff,
            },
            3000,
            3,
        ),
        AttemptSignal::TransportError => (
            match attempt {
                0 => EscalationAction::EscalateTier,
                1 => EscalationAction::RotateEgress,
                _ => EscalationAction::BackOff,
            },
            2000,
            3,
        ),
    };
    let hint = hint_for(signal);
    EscalationStep {
        action,
        hint,
        strategy: select(hint),
        backoff_ms: base * 2u64.pow(attempt.min(cap)),
    }
}

/// One recorded escalation decision (W3-S2) — the run-evidence row shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationTrace {
    /// Zero-based attempt index that just failed.
    pub attempt: u32,
    /// Classified signal for that attempt.
    pub signal: AttemptSignal,
    /// Ladder action applied before the next attempt.
    pub action: EscalationAction,
    /// Strategy seed: hint → plan.
    pub hint: StateHint,
    /// The plan's primary move (Monitor for the clean path).
    pub primary: Move,
    /// Backoff applied before the next attempt (ms).
    pub backoff_ms: u64,
}

impl EscalationTrace {
    /// Build the trace row for one decision.
    pub fn from_step(attempt: u32, signal: AttemptSignal, step: &EscalationStep) -> Self {
        EscalationTrace {
            attempt,
            signal,
            action: step.action,
            hint: step.hint,
            primary: step.strategy.primary,
            backoff_ms: step.backoff_ms,
        }
    }

    /// JSON form for the run-evidence sink (`kind = "escalation"`).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "attempt": self.attempt,
            "signal": self.signal,
            "action": self.action,
            "hint": self.hint,
            "primary": self.primary,
            "backoff_ms": self.backoff_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ALL_HINTS: [StateHint; 3] =
        [StateHint::Sluggish, StateHint::Steady, StateHint::Agitated];

    fn plan(hint: StateHint) -> StrategyPlan {
        select(hint)
    }

    // ── STRATEGY_TABLE pins (B2.3.1) ────────────────────────────────────────

    #[test]
    fn strategy_table_pins_sluggish_explore() {
        let p = plan(StateHint::Sluggish);
        assert_eq!(p.primary, Move::Explore);
        assert_eq!(p.moves, vec![Move::Explore, Move::Monitor]);
    }

    #[test]
    fn strategy_table_pins_agitated_stabilize() {
        let p = plan(StateHint::Agitated);
        assert_eq!(p.primary, Move::Stabilize);
        assert_eq!(p.moves, vec![Move::Stabilize, Move::Monitor]);
    }

    #[test]
    fn strategy_table_pins_steady_monitor() {
        let p = plan(StateHint::Steady);
        assert_eq!(p.primary, Move::Monitor);
        assert_eq!(p.moves, vec![Move::Monitor]);
    }

    #[test]
    fn strategy_table_is_exact_and_total() {
        // Exactly the three frozen rows.
        assert_eq!(STRATEGY_TABLE.len(), 3);
        for expected in [
            (StateHint::Sluggish, Move::Explore),
            (StateHint::Steady, Move::Monitor),
            (StateHint::Agitated, Move::Stabilize),
        ] {
            assert!(
                STRATEGY_TABLE.contains(&expected),
                "missing row {expected:?} from STRATEGY_TABLE"
            );
        }
        // Every hint resolves through a table row (no fallback hit).
        for hint in ALL_HINTS {
            assert!(
                STRATEGY_TABLE.iter().any(|&(h, _)| h == hint),
                "hint {hint:?} missing from STRATEGY_TABLE"
            );
        }
    }

    // ── monitor always-on + order (B2.3.1) ──────────────────────────────────

    #[test]
    fn monitor_always_on_in_moves() {
        for hint in ALL_HINTS {
            let p = plan(hint);
            assert!(
                p.moves.contains(&Move::Monitor),
                "{hint:?} plan lost Monitor"
            );
            assert_eq!(
                p.moves.iter().filter(|m| **m == Move::Monitor).count(),
                1,
                "Monitor must appear exactly once in {:?}",
                p.moves
            );
            assert!(!p.moves.is_empty());
            assert!(p.moves.contains(&p.primary), "primary absent from moves");
            // strictly ascending ⇒ sorted and deduplicated
            assert!(
                p.moves.windows(2).all(|w| w[0] < w[1]),
                "moves not sorted/deduped: {:?}",
                p.moves
            );
        }
    }

    #[test]
    fn move_order_is_frozen_explore_stabilize_monitor() {
        assert!(Move::Explore < Move::Stabilize);
        assert!(Move::Stabilize < Move::Monitor);
        assert!(Move::Explore < Move::Monitor);
        let mut v = vec![Move::Monitor, Move::Explore, Move::Stabilize, Move::Explore];
        v.sort();
        v.dedup();
        assert_eq!(v, vec![Move::Explore, Move::Stabilize, Move::Monitor]);
    }

    #[test]
    fn select_is_deterministic() {
        for hint in ALL_HINTS {
            assert_eq!(plan(hint), plan(hint));
            assert_eq!(
                serde_json::to_string(&plan(hint)).unwrap(),
                serde_json::to_string(&plan(hint)).unwrap()
            );
        }
    }

    // ── from_hints aggregation + precedence (B2.3.2) ────────────────────────

    #[test]
    fn from_hints_precedence_agitated_beats_sluggish_and_steady() {
        let p = from_hints(&[
            StateHint::Steady,
            StateHint::Sluggish,
            StateHint::Agitated,
        ]);
        assert_eq!(p.primary, Move::Stabilize);
        assert_eq!(p.moves, vec![Move::Stabilize, Move::Monitor]);
        // order does not matter: agitation wins from either end
        assert_eq!(from_hints(&[StateHint::Agitated, StateHint::Sluggish]), p);
    }

    #[test]
    fn from_hints_precedence_sluggish_beats_steady() {
        let p = from_hints(&[StateHint::Steady, StateHint::Sluggish]);
        assert_eq!(p.primary, Move::Explore);
        assert_eq!(p.moves, vec![Move::Explore, Move::Monitor]);
        assert_eq!(from_hints(&[StateHint::Sluggish, StateHint::Steady]), p);
    }

    #[test]
    fn from_hints_steady_only_is_observation() {
        let p = from_hints(&[StateHint::Steady, StateHint::Steady]);
        assert_eq!(p, select(StateHint::Steady));
        assert_eq!(p.primary, Move::Monitor);
        assert_eq!(p.moves, vec![Move::Monitor]);
    }

    #[test]
    fn from_hints_empty_is_steady_default() {
        assert_eq!(from_hints(&[]), select(StateHint::Steady));
        assert_eq!(from_hints(&[]).primary, Move::Monitor);
    }

    #[test]
    fn from_hints_monitor_always_on_and_order_independent() {
        let cases: [&[StateHint]; 5] = [
            &[],
            &[StateHint::Steady],
            &[StateHint::Sluggish],
            &[StateHint::Sluggish, StateHint::Agitated],
            &[StateHint::Steady, StateHint::Sluggish],
        ];
        for hints in cases {
            let p = from_hints(hints);
            assert!(
                p.moves.contains(&Move::Monitor),
                "{hints:?} lost Monitor"
            );
            assert!(p.moves.contains(&p.primary));
            // order-independent: reversed slice yields the same plan
            let mut rev = hints.to_vec();
            rev.reverse();
            assert_eq!(
                from_hints(&rev),
                p,
                "aggregation not order-independent for {hints:?}"
            );
        }
    }

    // ── serde (B2.3.3) ──────────────────────────────────────────────────────

    #[test]
    fn serde_state_hint_roundtrip_and_wire_form() {
        for hint in ALL_HINTS {
            let s = serde_json::to_string(&hint).unwrap();
            assert_eq!(s, format!("\"{hint:?}\""), "unit variant wire form");
            assert_eq!(serde_json::from_str::<StateHint>(&s).unwrap(), hint);
        }
        assert_eq!(
            serde_json::to_string(&StateHint::Agitated).unwrap(),
            "\"Agitated\""
        );
    }

    #[test]
    fn serde_move_roundtrip_and_wire_form() {
        for m in [Move::Explore, Move::Stabilize, Move::Monitor] {
            let s = serde_json::to_string(&m).unwrap();
            assert_eq!(s, format!("\"{m:?}\""), "unit variant wire form");
            assert_eq!(serde_json::from_str::<Move>(&s).unwrap(), m);
        }
        assert_eq!(serde_json::to_string(&Move::Monitor).unwrap(), "\"Monitor\"");
    }

    #[test]
    fn serde_plan_roundtrip_and_exact_shape() {
        for hint in ALL_HINTS {
            let p = plan(hint);
            let s = serde_json::to_string(&p).unwrap();
            assert_eq!(serde_json::from_str::<StrategyPlan>(&s).unwrap(), p);
        }
        // exact shape for the explore plan
        assert_eq!(
            serde_json::to_value(plan(StateHint::Sluggish)).unwrap(),
            json!({"primary": "Explore", "moves": ["Explore", "Monitor"]})
        );
        // wire acceptance: a plan JSON round-trips in from the outside too
        let p: StrategyPlan =
            serde_json::from_value(json!({"primary": "Stabilize", "moves": ["Stabilize", "Monitor"]}))
                .unwrap();
        assert_eq!(p, plan(StateHint::Agitated));
    }

    // ── Escalation ladder (P1 W3) ──────────────────────────────────────────

    #[test]
    fn escalation_ladder_is_deterministic_and_ordered() {
        use EscalationAction::{ApplyStealth, BackOff, EscalateTier, RotateEgress};

        // Soft block: plain → stealth → escalate → rotate-egress → back-off.
        let seq: Vec<_> = (0..5)
            .map(|a| escalation_step(a, AttemptSignal::SoftBlock).action)
            .collect();
        assert_eq!(
            seq,
            vec![ApplyStealth, EscalateTier, RotateEgress, BackOff, BackOff]
        );
        // Hard block jumps straight to egress escalation.
        let seq: Vec<_> = (0..4)
            .map(|a| escalation_step(a, AttemptSignal::HardBlock).action)
            .collect();
        assert_eq!(seq, vec![EscalateTier, RotateEgress, BackOff, BackOff]);
        // Transport errors mirror hard blocks.
        let seq: Vec<_> = (0..4)
            .map(|a| escalation_step(a, AttemptSignal::TransportError).action)
            .collect();
        assert_eq!(seq, vec![EscalateTier, RotateEgress, BackOff, BackOff]);
        // Transient: back off only — never a posture change.
        for a in 0..5 {
            assert_eq!(
                escalation_step(a, AttemptSignal::Transient).action,
                BackOff
            );
        }
        // Same inputs → identical steps (deterministic).
        for a in 0..4 {
            assert_eq!(
                escalation_step(a, AttemptSignal::SoftBlock),
                escalation_step(a, AttemptSignal::SoftBlock)
            );
        }
    }

    #[test]
    fn escalation_backoff_preserves_the_historical_shape() {
        // base * 2^min(attempt, cap) — the pre-ladder constants stay exact.
        assert_eq!(escalation_step(0, AttemptSignal::Transient).backoff_ms, 500);
        assert_eq!(escalation_step(3, AttemptSignal::Transient).backoff_ms, 4000);
        assert_eq!(escalation_step(0, AttemptSignal::SoftBlock).backoff_ms, 1000);
        assert_eq!(escalation_step(0, AttemptSignal::HardBlock).backoff_ms, 3000);
        assert_eq!(
            escalation_step(2, AttemptSignal::HardBlock).backoff_ms,
            12000
        );
    }

    #[test]
    fn no_block_signal_means_no_escalation() {
        // The Clean contract: serve as-is, no backoff, Monitor primary.
        let step = escalation_step(0, AttemptSignal::Clean);
        assert_eq!(step.action, EscalationAction::Serve);
        assert_eq!(step.backoff_ms, 0);
        assert_eq!(step.hint, StateHint::Steady);
        assert_eq!(step.strategy.primary, Move::Monitor);
        // Even a high attempt index stays a no-op for Clean.
        let step = escalation_step(7, AttemptSignal::Clean);
        assert_eq!(step.action, EscalationAction::Serve);
        assert_eq!(step.backoff_ms, 0);
    }

    #[test]
    fn escalation_trace_serializes_for_run_evidence() {
        let step = escalation_step(1, AttemptSignal::SoftBlock);
        let trace = EscalationTrace::from_step(1, AttemptSignal::SoftBlock, &step);
        assert_eq!(trace.action, EscalationAction::EscalateTier);
        assert_eq!(trace.hint, StateHint::Agitated);
        assert_eq!(trace.primary, Move::Stabilize);
        let j = trace.to_json();
        assert_eq!(j["attempt"], 1);
        assert_eq!(j["action"], "EscalateTier");
        assert_eq!(j["signal"], "SoftBlock");
        // Round-trip through serde: the trace shape is wire-stable.
        let back: EscalationTrace = serde_json::from_value(j).unwrap();
        assert_eq!(back, trace);
    }
}
