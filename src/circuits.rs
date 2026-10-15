//! Persona-scoped circuit discipline — task A5.1.4 (interface batch 09 §1).
//!
//! A **circuit** is the bounded channel through which a persona interacts
//! with a target: a cover identity should never keep one channel warm
//! indefinitely, and a burned persona's channels must be closed. This module
//! is the *model* half of that discipline: [`Circuit`] records one opened
//! channel (persona, purpose, when opened, when it must rotate), and
//! [`CircuitStore`] owns the deterministic lifecycle —
//! [`CircuitStore::open`], [`CircuitStore::close`],
//! [`CircuitStore::rotate_due`], [`CircuitStore::rotate`] and
//! [`CircuitStore::close_all_for_persona`].
//!
//! # Rotation semantics (pinned)
//! A circuit is *due for rotation* when `now_ms >= opened_ms +
//! rotate_after_ms` — the boundary is **inclusive** (exactly at the
//! scheduled instant it counts as due). [`CircuitStore::rotate_due`]
//! reports due circuits; [`CircuitStore::rotate`] executes the rotation:
//! the old circuit is closed at `now_ms` and a replacement is opened with
//! the **same** persona/purpose/rotate-after schedule and a fresh id.
//!
//! # Burn link (documentation only — burn_flow is NOT edited here)
//! [`CircuitStore::close_all_for_persona`] is the execution half of the
//! burn path: [`crate::burn_flow::BurnPlan::close_circuits`] carries the
//! operator's "revoke circuits" request and
//! [`crate::burn_flow::BurnReceipt::circuits_closed`] records that it was
//! requested. Today burn_flow only *records the intent*; when the parent
//! wires this store, the burn executor should call
//! `store.close_all_for_persona(persona_id, now_ms)` and may use the
//! returned count to strengthen the receipt. No code in burn_flow changes
//! as part of A5.1.4.
//!
//! # Ids
//! Ids are deterministic **per store**: `circ-<seq:04>` where `seq` is
//! `1 + the number of circuits this store has ever opened` (rotations
//! consume a sequence number too, so ids are never reused). Two stores
//! driven through the same call sequence produce the same ids — no clock,
//! no randomness.
//!
//! Deltas vs the frozen interface (if any) are argued in the batch report
//! (AGT-91.md).


use std::fmt;

use serde::{Deserialize, Serialize};

/// One opened persona circuit: a bounded channel (persona × purpose) with an
/// explicit rotation schedule and optional close timestamp.
///
/// Serde round-trippable so a persisted store keeps its lifecycle intact;
/// `closed_ms == None` means the circuit is still open. A closed circuit is
/// never reopened — rotation opens a *replacement* with a fresh id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Circuit {
    /// Deterministic store-scoped id (`circ-0001`, `circ-0002`, …).
    pub id: String,
    /// The persona this circuit serves (persona ids are single-use; see
    /// [`crate::persona`]).
    pub persona_id: String,
    /// What the channel is for (operator-facing label, non-empty).
    pub purpose: String,
    /// When the circuit was opened (ms since epoch, caller-supplied clock).
    pub opened_ms: i64,
    /// Rotation is due at `opened_ms + rotate_after_ms` (inclusive); must be
    /// strictly positive.
    pub rotate_after_ms: i64,
    /// When the circuit was closed, or `None` while open.
    pub closed_ms: Option<i64>,
}

impl Circuit {
    /// Whether the circuit is still open (not yet closed).
    pub fn is_open(&self) -> bool {
        self.closed_ms.is_none()
    }

    /// The instant at which rotation becomes due (`opened_ms +
    /// rotate_after_ms`). Pure arithmetic — compare with `now_ms >= due_ms`
    /// for the inclusive boundary.
    pub fn due_ms(&self) -> i64 {
        self.opened_ms.saturating_add(self.rotate_after_ms)
    }

    /// Whether the circuit is open and due for rotation at `now_ms`
    /// (`now_ms >= opened_ms + rotate_after_ms`, inclusive).
    pub fn is_due(&self, now_ms: i64) -> bool {
        self.is_open() && now_ms >= self.due_ms()
    }
}

/// Store of circuits — the single place circuit lifecycle is decided.
///
/// Owns every circuit it ever opened (closed ones are retained as audit
/// history). Ordering of the two sorted read surfaces is pinned: by
/// `opened_ms` ascending, then `id` ascending (`id` breaks ties for
/// circuits opened at the same millisecond).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitStore {
    circuits: Vec<Circuit>,
}

impl CircuitStore {
    /// A new, empty store (first id allocated will be `circ-0001`).
    pub fn new() -> Self {
        CircuitStore {
            circuits: Vec::new(),
        }
    }

    /// Open a new circuit for `persona_id` / `purpose`.
    ///
    /// Fail-closed validation: `persona_id` or `purpose` empty →
    /// [`CircuitError::EmptyField`]; `rotate_after_ms <= 0` →
    /// [`CircuitError::BadRotation`]. On success the circuit is stored and
    /// a clone is returned. The id is `circ-<seq:04>` with `seq` = 1 + the
    /// number of circuits this store has opened so far (deterministic; not
    /// derived from `now_ms`).
    pub fn open(
        &mut self,
        persona_id: &str,
        purpose: &str,
        rotate_after_ms: i64,
        now_ms: i64,
    ) -> Result<Circuit, CircuitError> {
        if persona_id.is_empty() || purpose.is_empty() {
            return Err(CircuitError::EmptyField);
        }
        if rotate_after_ms <= 0 {
            return Err(CircuitError::BadRotation);
        }
        let id = format!("circ-{:04}", self.circuits.len() + 1);
        let circuit = Circuit {
            id,
            persona_id: persona_id.to_string(),
            purpose: purpose.to_string(),
            opened_ms: now_ms,
            rotate_after_ms,
            closed_ms: None,
        };
        self.circuits.push(circuit.clone());
        Ok(circuit)
    }

    /// Close an open circuit at `now_ms`.
    ///
    /// Unknown id → [`CircuitError::NotFound`]; already-closed circuit →
    /// [`CircuitError::AlreadyClosed`] (closing is not idempotent — the
    /// caller must be able to tell "wrote nothing" from "wrote now").
    pub fn close(&mut self, id: &str, now_ms: i64) -> Result<(), CircuitError> {
        let circuit = self
            .circuits
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(CircuitError::NotFound)?;
        if circuit.closed_ms.is_some() {
            return Err(CircuitError::AlreadyClosed);
        }
        circuit.closed_ms = Some(now_ms);
        Ok(())
    }

    /// All **open** circuits whose rotation is due at `now_ms`:
    /// `now_ms >= opened_ms + rotate_after_ms` (**inclusive** — at exactly
    /// the scheduled instant the circuit counts as due).
    ///
    /// Sorted by `opened_ms` ascending, then `id` ascending. Closed
    /// circuits are never due.
    pub fn rotate_due(&self, now_ms: i64) -> Vec<&Circuit> {
        self.sorted(|c| c.is_due(now_ms))
    }

    /// Rotate a circuit: close the old one at `now_ms` and open a
    /// replacement with the same `persona_id` / `purpose` /
    /// `rotate_after_ms`, returning the **new** circuit.
    ///
    /// Unknown id → [`CircuitError::NotFound`]; already-closed circuit →
    /// [`CircuitError::AlreadyClosed`] (a closed circuit is rotated by
    /// opening a fresh one, not by re-rotating the dead id). The new id is
    /// fresh by construction (the old circuit still occupies its sequence
    /// slot), so `old.id != new.id` always holds on success.
    pub fn rotate(&mut self, id: &str, now_ms: i64) -> Result<Circuit, CircuitError> {
        let old = self
            .circuits
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(CircuitError::NotFound)?;
        if old.closed_ms.is_some() {
            return Err(CircuitError::AlreadyClosed);
        }
        old.closed_ms = Some(now_ms);
        let (persona_id, purpose, rotate_after_ms) =
            (old.persona_id.clone(), old.purpose.clone(), old.rotate_after_ms);
        // Same persona/purpose/schedule; fresh id. Validation is a no-op
        // here (values came from an already-validated circuit) but the
        // single open() path keeps id allocation in one place.
        self.open(&persona_id, &purpose, rotate_after_ms, now_ms)
    }

    /// Close **all open** circuits belonging to `persona_id`; returns how
    /// many were actually closed (already-closed circuits are not
    /// recounted, so a second call returns 0).
    ///
    /// This is the execution half of the burn path: see the module docs for
    /// the [`crate::burn_flow::BurnPlan::close_circuits`] link. A
    /// `persona_id` with no open circuits (including the empty string)
    /// closes nothing and returns 0 — the burn caller treats 0 as "nothing
    /// to revoke", not as an error.
    pub fn close_all_for_persona(&mut self, persona_id: &str, now_ms: i64) -> usize {
        let mut closed = 0;
        for circuit in self.circuits.iter_mut() {
            if circuit.persona_id == persona_id && circuit.closed_ms.is_none() {
                circuit.closed_ms = Some(now_ms);
                closed += 1;
            }
        }
        closed
    }

    /// All **open** circuits for `persona_id`, sorted by `opened_ms`
    /// ascending then `id` ascending.
    pub fn active_for(&self, persona_id: &str) -> Vec<&Circuit> {
        self.sorted(|c| c.is_open() && c.persona_id == persona_id)
    }

    /// Shared ordering: filter, then sort by `(opened_ms, id)`.
    fn sorted(&self, keep: impl Fn(&Circuit) -> bool) -> Vec<&Circuit> {
        let mut out: Vec<&Circuit> = self.circuits.iter().filter(|c| keep(c)).collect();
        out.sort_by(|a, b| (a.opened_ms, &a.id).cmp(&(b.opened_ms, &b.id)));
        out
    }
}

/// Error surface of [`CircuitStore`] operations.
///
/// Serde round-trippable (snake_case variant names) so lifecycle failures
/// can be persisted in receipts/ledgers alongside the circuits themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitError {
    /// `persona_id` or `purpose` was empty on open.
    EmptyField,
    /// `rotate_after_ms <= 0` on open — a rotation schedule must be
    /// positive; "never rotate" is expressed by simply not rotating.
    BadRotation,
    /// No circuit with the given id exists in this store.
    NotFound,
    /// The circuit with the given id was already closed.
    AlreadyClosed,
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            CircuitError::EmptyField => "circuit field must not be empty",
            CircuitError::BadRotation => "rotate_after_ms must be positive",
            CircuitError::NotFound => "circuit not found",
            CircuitError::AlreadyClosed => "circuit already closed",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CircuitError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn circuit_err_json(e: &CircuitError) -> String {
        serde_json::to_string(e).unwrap()
    }

    // ---- open / close -------------------------------------------------

    #[test]
    fn open_then_close_roundtrip() {
        let mut store = CircuitStore::new();
        let c = store
            .open("p-1", "recruit", 60_000, 1_000)
            .expect("open");
        assert_eq!(c.id, "circ-0001");
        assert_eq!(c.persona_id, "p-1");
        assert_eq!(c.purpose, "recruit");
        assert_eq!(c.opened_ms, 1_000);
        assert_eq!(c.rotate_after_ms, 60_000);
        assert_eq!(c.closed_ms, None);
        assert!(c.is_open());

        assert_eq!(store.active_for("p-1").len(), 1);
        store.close("circ-0001", 5_000).expect("close");
        assert!(store.active_for("p-1").is_empty());
        let stored = &store.circuits[0];
        assert_eq!(stored.closed_ms, Some(5_000));
        assert!(!stored.is_open());
    }

    #[test]
    fn open_rejects_empty_fields_and_bad_rotation() {
        let mut store = CircuitStore::new();
        assert_eq!(
            store.open("", "recruit", 1_000, 0),
            Err(CircuitError::EmptyField)
        );
        assert_eq!(
            store.open("p-1", "", 1_000, 0),
            Err(CircuitError::EmptyField)
        );
        assert_eq!(
            store.open("p-1", "recruit", 0, 0),
            Err(CircuitError::BadRotation)
        );
        assert_eq!(
            store.open("p-1", "recruit", -1, 0),
            Err(CircuitError::BadRotation)
        );
        // nothing was stored by the failed opens → next id is still 0001
        let c = store.open("p-1", "recruit", 1, 0).unwrap();
        assert_eq!(c.id, "circ-0001");
    }

    #[test]
    fn close_unknown_is_not_found_and_double_close_is_already_closed() {
        let mut store = CircuitStore::new();
        assert_eq!(store.close("circ-9999", 0), Err(CircuitError::NotFound));
        let c = store.open("p-1", "recruit", 1_000, 0).unwrap();
        store.close(&c.id, 10).unwrap();
        assert_eq!(store.close(&c.id, 20), Err(CircuitError::AlreadyClosed));
        // the failed re-close must not have rewritten the timestamp
        assert_eq!(store.circuits[0].closed_ms, Some(10));
    }

    // ---- rotation -----------------------------------------------------

    #[test]
    fn due_boundary_is_inclusive_and_pinned() {
        let mut store = CircuitStore::new();
        store.open("p-1", "recruit", 500, 1_000).unwrap(); // due at 1500
        assert!(store.rotate_due(1_499).is_empty());
        let due = store.rotate_due(1_500); // exactly at opened+rotate_after
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, "circ-0001");
        assert_eq!(store.rotate_due(1_501).len(), 1);
        assert_eq!(store.circuits[0].due_ms(), 1_500);
    }

    #[test]
    fn closed_circuits_are_never_due() {
        let mut store = CircuitStore::new();
        let c = store.open("p-1", "recruit", 500, 1_000).unwrap();
        store.close(&c.id, 1_200).unwrap();
        assert!(store.rotate_due(10_000).is_empty());
    }

    #[test]
    fn rotate_closes_old_and_opens_replacement_with_fresh_id() {
        let mut store = CircuitStore::new();
        let old = store.open("p-1", "recruit", 500, 1_000).unwrap();
        let new = store.rotate(&old.id, 1_500).unwrap();

        assert_ne!(old.id, new.id);
        assert_eq!(new.id, "circ-0002");
        assert_eq!(new.persona_id, "p-1");
        assert_eq!(new.purpose, "recruit");
        assert_eq!(new.rotate_after_ms, 500);
        assert_eq!(new.opened_ms, 1_500);
        assert_eq!(new.closed_ms, None);

        let stored_old = store.circuits.iter().find(|c| c.id == old.id).unwrap();
        assert_eq!(stored_old.closed_ms, Some(1_500));
        let active = store.active_for("p-1");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, new.id);
        // replacement is not due until its own schedule fires
        assert!(!store.rotate_due(1_999).iter().any(|c| c.id == new.id));
        assert!(store.rotate_due(2_000).iter().any(|c| c.id == new.id));
    }

    #[test]
    fn rotate_errors_pinned() {
        let mut store = CircuitStore::new();
        assert_eq!(store.rotate("circ-0001", 0), Err(CircuitError::NotFound));
        let c = store.open("p-1", "recruit", 500, 0).unwrap();
        store.close(&c.id, 100).unwrap();
        assert_eq!(store.rotate(&c.id, 200), Err(CircuitError::AlreadyClosed));
    }

    // ---- persona-scoped bulk close (burn half) ------------------------

    #[test]
    fn close_all_for_persona_closes_only_that_personas_open_circuits() {
        let mut store = CircuitStore::new();
        store.open("p-1", "a", 1_000, 0).unwrap();
        store.open("p-1", "b", 1_000, 10).unwrap();
        store.open("p-2", "c", 1_000, 20).unwrap();
        let only = store.open("p-1", "d", 1_000, 30).unwrap();
        store.close(&only.id, 40).unwrap(); // already closed → not recounted

        assert_eq!(store.close_all_for_persona("p-1", 50), 2);
        assert!(store.active_for("p-1").is_empty());
        assert_eq!(store.active_for("p-2").len(), 1);
        // second call: nothing left to close
        assert_eq!(store.close_all_for_persona("p-1", 60), 0);
        // unknown persona / empty id: vacuous, no error
        assert_eq!(store.close_all_for_persona("nobody", 60), 0);
        assert_eq!(store.close_all_for_persona("", 60), 0);
        // timestamps: closed at the burn instant
        let a = store.circuits.iter().find(|c| c.purpose == "a").unwrap();
        assert_eq!(a.closed_ms, Some(50));
    }

    // ---- ordering & determinism ---------------------------------------

    #[test]
    fn sorted_outputs_by_opened_then_id() {
        let mut store = CircuitStore::new();
        // same opened_ms → id tiebreak; earlier ms first
        let c1 = store.open("p-1", "late", 1_000, 5_000).unwrap();
        let c2 = store.open("p-1", "early-a", 1_000, 1_000).unwrap();
        let c3 = store.open("p-1", "early-b", 1_000, 1_000).unwrap();
        let c4 = store.open("p-1", "shifted", 10_000, 0).unwrap();

        let active = store.active_for("p-1");
        let ids: Vec<&str> = active.iter().map(|c| c.id.as_str()).collect();
        // c4 opened at 0; c2/c3 at 1000 (id order); c1 at 5000
        assert_eq!(
            ids,
            vec![
                c4.id.as_str(),
                c2.id.as_str(),
                c3.id.as_str(),
                c1.id.as_str()
            ]
        );

        let due: Vec<&str> = store
            .rotate_due(10_000)
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(
            due,
            vec![
                c4.id.as_str(),
                c2.id.as_str(),
                c3.id.as_str(),
                c1.id.as_str()
            ]
        );
    }

    #[test]
    fn ids_are_deterministic_per_store() {
        let run = || {
            let mut s = CircuitStore::new();
            let _ = s.open("p-1", "a", 100, 0).unwrap();
            let first = s.open("p-1", "b", 100, 1).unwrap();
            let second = s.rotate(&first.id, 2).unwrap();
            let _ = s.open("p-2", "c", 100, 3).unwrap();
            (
                s.circuits.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
                second.id,
            )
        };
        let a = run();
        let b = run();
        assert_eq!(a, b);
        assert_eq!(a.0, vec!["circ-0001", "circ-0002", "circ-0003", "circ-0004"]);
        assert_eq!(a.1, "circ-0003");
    }

    // ---- serde ---------------------------------------------------------

    #[test]
    fn circuit_and_store_serde_roundtrip() {
        let mut store = CircuitStore::new();
        store.open("p-1", "recruit", 500, 1_000).unwrap();
        let c = store.open("p-1", "exfil", 500, 1_100).unwrap();
        store.close(&c.id, 1_400).unwrap();

        let json = serde_json::to_string(&store).unwrap();
        let back: CircuitStore = serde_json::from_str(&json).unwrap();
        assert_eq!(store, back);

        let one = serde_json::to_string(&store.circuits[1]).unwrap();
        let one_back: Circuit = serde_json::from_str(&one).unwrap();
        assert_eq!(one_back.closed_ms, Some(1_400));
        assert!(one.contains("\"closed_ms\":1400"));
        // open circuit serializes closed_ms as null
        let open_json = serde_json::to_string(&store.circuits[0]).unwrap();
        assert!(open_json.contains("\"closed_ms\":null"));
    }

    #[test]
    fn circuit_error_serde_and_display_pinned() {
        assert_eq!(circuit_err_json(&CircuitError::EmptyField), "\"empty_field\"");
        assert_eq!(
            circuit_err_json(&CircuitError::BadRotation),
            "\"bad_rotation\""
        );
        assert_eq!(circuit_err_json(&CircuitError::NotFound), "\"not_found\"");
        assert_eq!(
            circuit_err_json(&CircuitError::AlreadyClosed),
            "\"already_closed\""
        );
        let back: CircuitError = serde_json::from_str("\"not_found\"").unwrap();
        assert_eq!(back, CircuitError::NotFound);

        assert_eq!(
            CircuitError::EmptyField.to_string(),
            "circuit field must not be empty"
        );
        assert_eq!(
            CircuitError::BadRotation.to_string(),
            "rotate_after_ms must be positive"
        );
        assert_eq!(CircuitError::NotFound.to_string(), "circuit not found");
        assert_eq!(
            CircuitError::AlreadyClosed.to_string(),
            "circuit already closed"
        );
        // usable as a std error (bridge to anyhow/thiserror chains)
        let _dyn: &dyn std::error::Error = &CircuitError::NotFound;
    }
}
