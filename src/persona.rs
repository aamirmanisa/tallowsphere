//! Persona model + burn / never-reuse registry — task A5.1.x starter (dossier E13).
//!
//! **Not wired to the vault yet.** This module is the *model* half of A5.1.2 /
//! A5.1.3: a first-class, single-use persona object and the registry that
//! enforces the **never-reuse invariant** for burned identities. Runtime
//! integration (vault storage, circuit close-out, artifact quarantine, graph
//! taint of derived nodes) is A5.1.2/A5.1.3 work — the parent wires it later.
//!
//! Design sources:
//! - dossier E13 / `raw/02` #3–4: personas are disposable objects (identity
//!   bundle = fingerprint + contact surface + legend/backstory + provenance
//!   tag), `cover_class` attribute, explicit `burn(persona)` that revokes,
//!   quarantines and **hard-fails reuse**;
//! - ruleset A5.2.1: `@persona(id, cover_class, compartment, fingerprint_seed)`
//!   and `@burn_plan(persona, after, method: .revoke_and_quarantine,
//!   artifacts: .quarantine)` — the runtime half of E5003 ("reuse across
//!   separate runs cannot be decided statically; the registry is consulted at
//!   persona open").
//!
//! # Never-reuse invariant
//! [`PersonaRegistry::burn`] moves a persona's lifecycle `Active → Burned{
//! at_ms, method, quarantine }` and records the id in the registry's tainted
//! (burned) set. From that moment:
//! - [`PersonaRegistry::assert_reusable`] **hard-fails** (`Err`) for the id —
//!   the vault-open boundary (A5.1.2) refuses the run;
//! - [`PersonaRegistry::register`] refuses to (re-)register a burned id, so a
//!   fresh persona can never inherit a burned identity's id;
//! - a fingerprint seed already worn by another persona is refused too
//!   (E5003(b): "rotation must produce a fresh seed per persona").
//!
//! A *fresh* id (never registered) passes `assert_reusable`: the registry's
//! job is the taint check, not existence — "unknown" is not "burned".
//!
//! Deltas vs the frozen interface and the checklist item are listed in the
//! batch report (AGT-29.md); serde round-trips both the persona state and the
//! burned set so the taint survives persistence.


use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// Cover class of a persona — the `cover_class: .ident` annotation arg
/// (ruleset A5.2.1, corpus `tests/opsec_corpus/*.tl`: `.researcher`,
/// `.engineer`, `.journalist`).
///
/// Stored verbatim (transparent serde) because the corpus vocabulary is an
/// open set of role idents: a new cover role must not require a code change.
///
/// Delta: dossier E13 also frames cover class as *attributable vs deniable*
/// (official-vs-NOC, `raw/02` #3). That axis is policy for A5.1.2/A5.1.3 and
/// is intentionally not modeled here — no frozen vocabulary exists yet.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CoverClass(String);

impl CoverClass {
    /// Build a cover class from any ident-shaped string (stored verbatim).
    pub fn new(ident: impl Into<String>) -> Self {
        CoverClass(ident.into())
    }

    /// The verbatim ident (e.g. `"researcher"`).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for CoverClass {
    fn from(s: &str) -> Self {
        CoverClass(s.to_string())
    }
}

impl From<String> for CoverClass {
    fn from(s: String) -> Self {
        CoverClass(s)
    }
}

impl fmt::Display for CoverClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Legend fields of a persona: the backstory an operator wears while acting
/// as it. Kept as one object so the legend is an inspectable artifact of the
/// persona (dossier E13: "legend/backstory + contact surface + provenance
/// tag").
///
/// `contact_surface` and `provenance_tag` are plain strings here; hashing /
/// redaction-at-rest belongs to the vault layer (A5.1.2/A5.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Legend {
    /// The cover story / backstory presented as this identity.
    pub backstory: String,
    /// Where the identity can be contacted (email, handle, …).
    pub contact_surface: String,
    /// Provenance tag: which collection run / operator generated the persona.
    pub provenance_tag: String,
}

impl Legend {
    pub fn new(
        backstory: impl Into<String>,
        contact_surface: impl Into<String>,
        provenance_tag: impl Into<String>,
    ) -> Self {
        Legend {
            backstory: backstory.into(),
            contact_surface: contact_surface.into(),
            provenance_tag: provenance_tag.into(),
        }
    }
}

/// How a persona was disposed of — mirrors the corpus burn-plan method
/// literal `.revoke_and_quarantine` (the doctrine default: revoke credentials
/// *and* quarantine artifacts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnMethod {
    /// Revoke credentials/circuits and quarantine artifacts (corpus default).
    RevokeAndQuarantine,
    /// Revoke credentials only; artifacts handled separately.
    RevokeOnly,
    /// Quarantine artifacts only (credentials were external/dev-scoped).
    QuarantineOnly,
}

impl BurnMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            BurnMethod::RevokeAndQuarantine => "revoke_and_quarantine",
            BurnMethod::RevokeOnly => "revoke_only",
            BurnMethod::QuarantineOnly => "quarantine_only",
        }
    }
}

/// Disposition of the persona's artifacts at burn time — mirrors the corpus
/// burn-plan `artifacts:` literal `.quarantine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineMode {
    /// Artifacts are moved to quarantine (doctrine default).
    Quarantine,
    /// No quarantine — escape hatch for dev/test personas; callers must
    /// justify it (the burn report is the audit trail).
    None,
}

/// Lifecycle of a persona: created `Active`, disposed of `Burned`. A burned
/// persona is **terminal** — there is no "revive" edge by design (E13
/// never-reuse).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// The persona may be used (and re-checked via `assert_reusable`).
    Active,
    /// The persona was burned: when, how, and what happened to artifacts.
    Burned {
        /// Burn timestamp (ms since epoch, caller-supplied — no clock here).
        at_ms: u64,
        /// Disposal method (revoke / quarantine split).
        method: BurnMethod,
        /// Artifact disposition.
        quarantine: QuarantineMode,
    },
}

/// A first-class, disposable cover identity (dossier E13 / checklist A5.1.2).
///
/// The *identity bundle* is `fingerprint_seed` (browser/transport
/// fingerprint material) + `legend` (backstory, contact surface, provenance)
/// + `compartment` (the A5.1.1 isolation unit this persona owns).
/// `fingerprint_seed` must be unique per persona (ruleset E5003(b)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persona {
    /// Persona id — single-use, never reused once burned (E5003).
    pub id: String,
    /// Cover class (role ident, e.g. `"researcher"`).
    pub cover_class: CoverClass,
    /// Compartment this persona owns (A5.1.1).
    pub compartment: String,
    /// Legend fields (backstory / contact surface / provenance tag).
    pub legend: Legend,
    /// Per-persona unique fingerprint seed; rotation produces a fresh seed.
    pub fingerprint_seed: String,
    /// Creation timestamp (ms since epoch; caller-supplied).
    pub created_ms: u64,
    /// `Active` until burned; then terminal `Burned { .. }`.
    pub lifecycle: Lifecycle,
}

impl Persona {
    /// New *active* persona with the given identity bundle.
    pub fn new(
        id: impl Into<String>,
        cover_class: impl Into<CoverClass>,
        compartment: impl Into<String>,
        legend: Legend,
        fingerprint_seed: impl Into<String>,
        created_ms: u64,
    ) -> Self {
        Persona {
            id: id.into(),
            cover_class: cover_class.into(),
            compartment: compartment.into(),
            legend,
            fingerprint_seed: fingerprint_seed.into(),
            created_ms,
            lifecycle: Lifecycle::Active,
        }
    }

    /// True iff this persona has been burned.
    pub fn is_burned(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Burned { .. })
    }
}

/// The working bundle for an open persona (A5.1.2 open-bundle flow):
/// everything an operation needs to act *as* this persona. Assembled by
/// [`PersonaRegistry::open_bundle`]; opening is gated by the never-reuse
/// check, so a burned persona can never be opened again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonaBundle {
    /// Persona id this bundle belongs to.
    pub id: String,
    /// Cover class (what kind of identity this is).
    pub cover_class: CoverClass,
    /// The isolation compartment the persona owns.
    pub compartment: String,
    /// The identity's legend (cover story, contact surface, provenance).
    pub legend: Legend,
    /// Unique fingerprint seed (never reused across personas).
    pub fingerprint_seed: String,
}

/// What triggered a burn (P1 W5-P1) — the runtime adapter for the compile-time
/// `@burn_plan` contract: a plan point, a canary/leak alert, or an operator
/// decision all fire the same terminal disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnTrigger {
    /// The plan's scheduled point (e.g. `after: .run`) was reached.
    PlanReached {
        /// Plan/annotation name that reached its point.
        plan: String,
    },
    /// A canary/leak alert implicated this persona (detection-ops trigger).
    CanaryAlert {
        /// Observation origin the leaked canary was found in.
        origin: String,
        /// The canary token that leaked.
        canary: String,
    },
    /// An operator ordered the burn (recorded with the reason).
    OperatorDecision {
        /// Why the operator burned the persona.
        reason: String,
    },
}

impl BurnTrigger {
    /// Stable wire/log name.
    pub fn as_str(&self) -> &'static str {
        match self {
            BurnTrigger::PlanReached { .. } => "plan_reached",
            BurnTrigger::CanaryAlert { .. } => "canary_alert",
            BurnTrigger::OperatorDecision { .. } => "operator_decision",
        }
    }
}

/// The audit record for one burn-on-trigger (P1 W5-P1/P2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnRecord {
    /// Persona id that was burned (now permanently tainted).
    pub id: String,
    /// Burn timestamp (ms since epoch; caller-supplied — no clock here).
    pub at_ms: u64,
    /// Disposal method.
    pub method: BurnMethod,
    /// Artifact disposition.
    pub quarantine: QuarantineMode,
    /// What fired the burn.
    pub trigger: BurnTrigger,
}

impl BurnRecord {
    /// JSON form for run evidence (`kind = "persona_burn"`).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "at_ms": self.at_ms,
            "method": self.method.as_str(),
            "quarantine": self.quarantine,
            "trigger": self.trigger,
            "trigger_kind": self.trigger.as_str(),
        })
    }
}

/// Why a persona operation was refused. All variants are security-relevant:
/// the registry denies by default and never silently repairs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaError {
    /// Operation referenced a persona id the registry does not know.
    UnknownPersona { id: String },
    /// `register` was given an id that already exists.
    DuplicatePersona { id: String },
    /// A pre-burned persona was presented to `register`.
    AlreadyBurned { id: String },
    /// **Never-reuse hard-fail**: the id was burned and must not be used
    /// again — not for `assert_reusable`, not for re-registration.
    BurnedReuse {
        id: String,
        /// Burn timestamp recorded when the persona was burned.
        at_ms: u64,
        /// Burn method recorded when the persona was burned.
        method: BurnMethod,
    },
    /// E5003(b): two personas must not share one fingerprint seed.
    FingerprintReuse {
        seed: String,
        existing_id: String,
        new_id: String,
    },
}

impl fmt::Display for PersonaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersonaError::UnknownPersona { id } => {
                write!(f, "unknown persona `{id}`")
            }
            PersonaError::DuplicatePersona { id } => {
                write!(f, "persona `{id}` already registered")
            }
            PersonaError::AlreadyBurned { id } => {
                write!(f, "persona `{id}` is already burned (terminal state)")
            }
            PersonaError::BurnedReuse { id, at_ms, method } => write!(
                f,
                "burned persona `{id}` must never be reused (burned at {at_ms} ms, method {})",
                method.as_str()
            ),
            PersonaError::FingerprintReuse {
                seed,
                existing_id,
                new_id,
            } => write!(
                f,
                "fingerprint seed `{seed}` already worn by persona `{existing_id}`; \
                 `{new_id}` must rotate to a fresh seed"
            ),
        }
    }
}

impl std::error::Error for PersonaError {}

/// Registry of personas + the **tainted (burned) id set** that enforces the
/// never-reuse invariant across runs.
///
/// Persisted state is serde round-trippable *including* the burned set, so a
/// reloaded registry still refuses burned ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonaRegistry {
    /// Personas by id (BTreeMap: deterministic ordering for stable serde).
    personas: BTreeMap<String, Persona>,
    /// Ids tainted by `burn` — the never-reuse set.
    burned: BTreeSet<String>,
}

impl Default for PersonaRegistry {
    fn default() -> Self {
        PersonaRegistry::new()
    }
}

impl PersonaRegistry {
    pub fn new() -> Self {
        PersonaRegistry {
            personas: BTreeMap::new(),
            burned: BTreeSet::new(),
        }
    }

    /// Register a fresh persona.
    ///
    /// Deny-by-default: a burned id is refused outright ([`PersonaError::
    /// BurnedReuse`]) — never-reuse is checked *before* existence — and a
    /// fingerprint seed already worn by another persona is refused
    /// ([`PersonaError::FingerprintReuse`], E5003(b)).
    pub fn register(&mut self, persona: Persona) -> Result<(), PersonaError> {
        // Never-reuse first: a burned id must never come back, even as a
        // "new" persona object.
        self.assert_reusable(&persona.id)?;
        if let Lifecycle::Burned { .. } = persona.lifecycle {
            return Err(PersonaError::AlreadyBurned { id: persona.id });
        }
        if self.personas.contains_key(&persona.id) {
            return Err(PersonaError::DuplicatePersona { id: persona.id });
        }
        // Fingerprint seed is single-use across personas (E5003(b)).
        if let Some((existing_id, _)) = self
            .personas
            .iter()
            .find(|(_, p)| p.fingerprint_seed == persona.fingerprint_seed)
        {
            return Err(PersonaError::FingerprintReuse {
                seed: persona.fingerprint_seed.clone(),
                existing_id: existing_id.clone(),
                new_id: persona.id.clone(),
            });
        }
        self.personas.insert(persona.id.clone(), persona);
        Ok(())
    }

    /// Look up a persona (active or burned).
    pub fn get(&self, id: &str) -> Option<&Persona> {
        self.personas.get(id)
    }

    /// True iff `id` is in the tainted (burned) set.
    pub fn is_burned(&self, id: &str) -> bool {
        self.burned.contains(id)
    }

    /// The tainted (burned) id set — the never-reuse ledger.
    pub fn burned_ids(&self) -> &BTreeSet<String> {
        &self.burned
    }

    /// **Hard-fail on reuse.** `Ok(())` only if `id` is not tainted; burned
    /// ids return [`PersonaError::BurnedReuse`] carrying when/how the burn
    /// happened. An id that was never registered is *not* burned — fresh ids
    /// are reusable (existence is not this check's job).
    ///
    /// The vault-open boundary (A5.1.2) propagates this error as a refusal;
    /// callers must not swallow it.
    pub fn assert_reusable(&self, id: &str) -> Result<(), PersonaError> {
        if self.burned.contains(id) {
            let (at_ms, method) = match self.personas.get(id) {
                Some(Persona {
                    lifecycle: Lifecycle::Burned { at_ms, method, .. },
                    ..
                }) => (*at_ms, *method),
                // Burned set without a persona record should not happen; keep
                // the hard-fail (sentinel timestamp) rather than healing.
                _ => (0, BurnMethod::RevokeAndQuarantine),
            };
            return Err(PersonaError::BurnedReuse {
                id: id.to_string(),
                at_ms,
                method,
            });
        }
        Ok(())
    }

    /// Burn a persona: move its lifecycle `Active → Burned { at_ms, method,
    /// quarantine }` and taint its id in the burned set. From here on
    /// `assert_reusable(id)` hard-fails and `register` refuses the id.
    ///
    /// Open the working bundle for `id` (A5.1.2 open-bundle flow): the
    /// assembled identity material for an operation — id, cover class,
    /// compartment, legend, fingerprint seed.
    ///
    /// Refusals: [`PersonaError::UnknownPersona`] for ids the registry does
    /// not know; [`PersonaError::BurnedReuse`] for burned ids — no bundle
    /// material is handed out for either case.
    ///
    /// `open_bundle` never mutates the registry; [`PersonaRegistry::burn`]
    /// remains the only lifecycle transition.
    pub fn open_bundle(&self, id: &str) -> Result<PersonaBundle, PersonaError> {
        let persona = self
            .get(id)
            .ok_or_else(|| PersonaError::UnknownPersona { id: id.to_string() })?;
        self.assert_reusable(id)?;
        Ok(PersonaBundle {
            id: persona.id.clone(),
            cover_class: persona.cover_class.clone(),
            compartment: persona.compartment.clone(),
            legend: persona.legend.clone(),
            fingerprint_seed: persona.fingerprint_seed.clone(),
        })
    }

    /// Returns the now-burned persona. Errors: [`PersonaError::
    /// UnknownPersona`] if the id is unknown, [`PersonaError::
    /// AlreadyBurned`] on a second burn (terminal state — double-burn is a
    /// caller bug worth surfacing, not silently idempotent).
    pub fn burn(
        &mut self,
        id: &str,
        at_ms: u64,
        method: BurnMethod,
        quarantine: QuarantineMode,
    ) -> Result<&Persona, PersonaError> {
        let persona = self
            .personas
            .get_mut(id)
            .ok_or_else(|| PersonaError::UnknownPersona { id: id.to_string() })?;
        if let Lifecycle::Burned { .. } = persona.lifecycle {
            return Err(PersonaError::AlreadyBurned { id: id.to_string() });
        }
        persona.lifecycle = Lifecycle::Burned {
            at_ms,
            method,
            quarantine,
        };
        self.burned.insert(id.to_string());
        Ok(&self.personas[id])
    }

    /// Burn `id` **on a trigger** and hand back the audit record (P1 W5-P1).
    ///
    /// The runtime complement of the compile-time `@burn_plan` contract
    /// (E5003): a canary/leak alert, a reached plan point, or an operator
    /// decision fires the same terminal disposition via [`Self::burn`], and
    /// **subsequent use is refused by the existing gates** —
    /// [`Self::assert_reusable`] / [`Self::open_bundle`] return
    /// [`PersonaError::BurnedReuse`], and [`Self::register`] refuses the id.
    ///
    /// Errors are exactly [`Self::burn`]'s: `UnknownPersona`, and
    /// `AlreadyBurned` for a second burn (double-burn is a caller bug worth
    /// surfacing, not silently idempotent).
    pub fn burn_on_trigger(
        &mut self,
        id: &str,
        at_ms: u64,
        method: BurnMethod,
        quarantine: QuarantineMode,
        trigger: BurnTrigger,
    ) -> Result<BurnRecord, PersonaError> {
        self.burn(id, at_ms, method, quarantine)?;
        Ok(BurnRecord {
            id: id.to_string(),
            at_ms,
            method,
            quarantine,
            trigger,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persona(id: &str, seed: &str) -> Persona {
        Persona::new(
            id,
            CoverClass::new("researcher"),
            "ctrl-1",
            Legend::new("grad student at a mid-tier university", "cover@example.invalid", "run-1"),
            seed,
            1_700_000_000_000,
        )
    }

    #[test]
    fn fresh_id_passes_reuse_check_and_registers() {
        let mut reg = PersonaRegistry::new();
        assert!(reg.assert_reusable("fresh-01").is_ok(), "unknown id is not tainted");
        reg.register(persona("fresh-01", "seed-a")).expect("fresh register");
        assert!(reg.get("fresh-01").is_some());
        assert!(!reg.is_burned("fresh-01"));
    }

    #[test]
    fn burn_then_reuse_is_refused() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();

        let burned = reg
            .burn("p-1", 1_800_000_000_000, BurnMethod::RevokeAndQuarantine, QuarantineMode::Quarantine)
            .expect("first burn ok");
        assert_eq!(
            burned.lifecycle,
            Lifecycle::Burned {
                at_ms: 1_800_000_000_000,
                method: BurnMethod::RevokeAndQuarantine,
                quarantine: QuarantineMode::Quarantine,
            }
        );
        assert!(burned.is_burned());

        // The never-reuse invariant: the burned id hard-fails from now on.
        let err = reg.assert_reusable("p-1").expect_err("burned id must hard-fail");
        match err {
            PersonaError::BurnedReuse { id, at_ms, method } => {
                assert_eq!(id, "p-1");
                assert_eq!(at_ms, 1_800_000_000_000);
                assert_eq!(method, BurnMethod::RevokeAndQuarantine);
            }
            other => panic!("wrong error: {other:?}"),
        }
        assert!(reg.is_burned("p-1"));
        assert!(reg.burned_ids().contains("p-1"));

        // Re-registering the burned id (new object, even fresh seed) fails too.
        let err = reg
            .register(persona("p-1", "seed-2"))
            .expect_err("re-registering burned id must fail");
        assert!(matches!(err, PersonaError::BurnedReuse { .. }));
        assert_eq!(reg.burned_ids().len(), 1);

        // Double burn surfaces rather than silently idempotent.
        let err = reg
            .burn("p-1", 1_800_000_000_001, BurnMethod::RevokeOnly, QuarantineMode::None)
            .expect_err("second burn must fail");
        assert!(matches!(err, PersonaError::AlreadyBurned { .. }));
    }

    #[test]
    fn burn_unknown_persona_errors() {
        let mut reg = PersonaRegistry::new();
        let err = reg
            .burn("ghost", 1, BurnMethod::RevokeAndQuarantine, QuarantineMode::Quarantine)
            .expect_err("unknown burn must fail");
        assert!(matches!(err, PersonaError::UnknownPersona { id } if id == "ghost"));
    }

    #[test]
    fn register_refuses_duplicates_and_fingerprint_reuse() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("dup-1", "seed-dup")).unwrap();

        let err = reg
            .register(persona("dup-1", "seed-other"))
            .expect_err("duplicate id must fail");
        assert!(matches!(err, PersonaError::DuplicatePersona { id } if id == "dup-1"));

        let err = reg
            .register(persona("other-1", "seed-dup"))
            .expect_err("shared fingerprint seed must fail");
        match err {
            PersonaError::FingerprintReuse { seed, existing_id, new_id } => {
                assert_eq!(seed, "seed-dup");
                assert_eq!(existing_id, "dup-1");
                assert_eq!(new_id, "other-1");
            }
            other => panic!("wrong error: {other:?}"),
        }

        // Registering an already-burned persona object is refused.
        let mut burned_in = persona("pre-2", "seed-pre");
        burned_in.lifecycle = Lifecycle::Burned {
            at_ms: 5,
            method: BurnMethod::RevokeOnly,
            quarantine: QuarantineMode::None,
        };
        let err = reg.register(burned_in).expect_err("pre-burned register must fail");
        assert!(matches!(err, PersonaError::AlreadyBurned { id } if id == "pre-2"));
    }

    #[test]
    fn registry_serde_round_trip_preserves_state_and_taint() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("active-1", "seed-act")).unwrap();
        reg.register(persona("burned-1", "seed-bur")).unwrap();
        reg.burn(
            "burned-1",
            1_900_000_000_000,
            BurnMethod::RevokeAndQuarantine,
            QuarantineMode::Quarantine,
        )
        .unwrap();

        let json = serde_json::to_string_pretty(&reg).expect("registry serializes");
        let back: PersonaRegistry = serde_json::from_str(&json).expect("registry deserializes");

        assert_eq!(back, reg, "round-trip must be lossless");
        assert_eq!(back.burned_ids().len(), 1);
        assert!(back.is_burned("burned-1"));
        assert!(!back.is_burned("active-1"));
        // Taint survives persistence: the reloaded registry still hard-fails.
        assert!(matches!(
            back.assert_reusable("burned-1"),
            Err(PersonaError::BurnedReuse { .. })
        ));
        assert!(back.assert_reusable("active-1").is_ok());
        // And the burned persona's lifecycle details survive too.
        assert_eq!(
            back.get("burned-1").unwrap().lifecycle,
            Lifecycle::Burned {
                at_ms: 1_900_000_000_000,
                method: BurnMethod::RevokeAndQuarantine,
                quarantine: QuarantineMode::Quarantine,
            }
        );
    }

    #[test]
    fn persona_and_legend_serde_round_trip() {
        let p = persona("serde-1", "seed-serif");
        let json = serde_json::to_string(&p).unwrap();
        let back: Persona = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
        // cover_class is transparent: stored as the bare ident string.
        assert!(json.contains("\"cover_class\":\"researcher\""), "json: {json}");

        let l = Legend::new("story", "contact", "provenance");
        let back: Legend = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back, l);
    }

    #[test]
    fn burn_error_display_names_the_persona() {
        let e = PersonaError::BurnedReuse {
            id: "p-9".into(),
            at_ms: 42,
            method: BurnMethod::RevokeAndQuarantine,
        };
        let msg = e.to_string();
        assert!(msg.contains("p-9"), "msg: {msg}");
        assert!(msg.contains("never be reused"), "msg: {msg}");
    }

    #[test]
    fn open_bundle_assembles_fields_and_refuses_burned_or_unknown() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("b-1", "seed-b")).unwrap();

        let bundle = reg.open_bundle("b-1").unwrap();
        assert_eq!(bundle.id, "b-1");
        assert_eq!(bundle.cover_class, CoverClass::new("researcher"));
        assert_eq!(bundle.compartment, "ctrl-1");
        assert_eq!(bundle.legend.contact_surface, "cover@example.invalid");
        assert_eq!(bundle.fingerprint_seed, "seed-b");

        assert!(matches!(
            reg.open_bundle("nope"),
            Err(PersonaError::UnknownPersona { .. })
        ));

        reg.burn(
            "b-1",
            1_900_000_000_000,
            BurnMethod::RevokeAndQuarantine,
            QuarantineMode::Quarantine,
        )
        .unwrap();
        assert!(matches!(
            reg.open_bundle("b-1"),
            Err(PersonaError::BurnedReuse { .. })
        ));
    }
}
