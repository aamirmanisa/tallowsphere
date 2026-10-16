//! Vault-side persona persistence (A5.1.2).
//!
//! [`crate::persona::PersonaRegistry`] is serde round-trippable *including*
//! its burned set, so a reloaded registry still refuses burned ids. This
//! module seals a registry under the vault password with the same hybrid
//! construction as `key_custody.rs` (see that module for the format
//! rationale), making persona objects persist at rest.
//!
//! The open-bundle flow itself belongs to the registry
//! ([`crate::persona::PersonaRegistry::open_bundle`]); this module is only
//! the sealed container. Sealed files are written mode 0600.
//!
//! # Persona firewall (row #107)
//!
//! [`firewall`] is the enforcement layer over the store's data shapes: a
//! read-only check API that **detects and refuses** identity-separation
//! violations — cross-persona references, and persona-scoped material
//! (compartment / fingerprint seed / contact surface) reachable from another
//! persona's context, including burned identities whose material must stay
//! quarantined. Checks bind at two boundaries:
//! - the identity-open boundary — [`firewall::PersonaFirewall::open_scope`]
//!   hands out a [`firewall::PersonaScope`] only for a persona whose material
//!   is separated (and [`firewall::PersonaFirewall::assert_reference`] /
//!   [`firewall::PersonaFirewall::assert_material_access`] gate later joins);
//! - the custody boundary — [`unseal_checked`] / [`load_checked`] refuse a
//!   sealed registry that violates separation, where plain [`unseal`] cannot
//!   (it re-runs no register-time gate).
//!
//! Findings and refusals are typed
//! ([`firewall::SeparationFinding`] / [`firewall::FirewallRefusal`]) and serde
//! round-trippable. The layer is additive: no existing store or registry
//! behavior changes.
//!
//! # Sector pseudonyms (row #195)
//!
//! [`pseudonym`] derives per-service pseudonymous identifiers for an open
//! identity context — `HKDF-SHA256(master, context)` per sector (the Austria
//! bPK pattern), with domain separation, no cross-sector linkability, and
//! persona-context binding. It is additive over both layers above: derivation
//! takes a [`firewall::PersonaScope`] (firewall-gated), and no existing type or
//! function changes.

use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::pqc;
use crate::persona::PersonaRegistry;

/// Persona custody-file format version.
pub const PERSONA_CUSTODY_VERSION: u32 = 1;

/// A sealed persona-registry custody file (see module docs).
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedPersonas {
    /// Format version ([`PERSONA_CUSTODY_VERSION`]).
    pub version: u32,
    /// Sealed registry payload (hybrid double-encrypted).
    pub blob: pqc::PQCEncryptedBlob,
    /// Hex-encoded 12-byte nonce wrapping the ML-KEM decapsulation key.
    pub dk_nonce: String,
    /// Hex-encoded ML-KEM decapsulation key, wrapped under the password.
    pub wrapped_dk: String,
}

/// Seal `registry` (personas + burned set) under `password`.
pub fn seal(registry: &PersonaRegistry, password: &str) -> Result<SealedPersonas, String> {
    let plaintext = Zeroizing::new(
        serde_json::to_string(registry).map_err(|e| format!("persona custody: encode: {e}"))?,
    );
    let (blob, dk_hex) = pqc::pqc_hybrid_encrypt(plaintext.as_bytes(), password)?;
    let (dk_nonce, wrapped_dk) =
        pqc::pqc_wrap_dk(password, &blob.pqc_encapsulation_key, &dk_hex)?;
    Ok(SealedPersonas {
        version: PERSONA_CUSTODY_VERSION,
        blob,
        dk_nonce: to_hex(&dk_nonce),
        wrapped_dk: to_hex(&wrapped_dk),
    })
}

/// Rebuild a [`PersonaRegistry`] from a sealed file; burned ids stay burned.
pub fn unseal(sealed: &SealedPersonas, password: &str) -> Result<PersonaRegistry, String> {
    if sealed.version != PERSONA_CUSTODY_VERSION {
        return Err(format!(
            "persona custody: unsupported version {} (expected {PERSONA_CUSTODY_VERSION})",
            sealed.version
        ));
    }
    let dk_nonce: [u8; 12] = hex_decode(&sealed.dk_nonce)?
        .try_into()
        .map_err(|_| "persona custody: invalid dk nonce length".to_string())?;
    let wrapped_dk = hex_decode(&sealed.wrapped_dk)?;
    let dk_hex = pqc::pqc_unwrap_dk(
        password,
        &sealed.blob.pqc_encapsulation_key,
        &dk_nonce,
        &wrapped_dk,
    )?;
    let plaintext = Zeroizing::new(pqc::pqc_hybrid_decrypt(&sealed.blob, password, &dk_hex)?);
    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("persona custody: corrupt sealed payload: {e}"))
}

/// Write a sealed persona file to `path` (new files are mode 0600).
pub fn save(path: &Path, sealed: &SealedPersonas) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(sealed).map_err(|e| format!("persona custody: encode: {e}"))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("persona custody: write '{}': {e}", path.display()))?;
    f.write_all(json.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("persona custody: write '{}': {e}", path.display()))
}

/// Read a sealed persona file from `path`.
pub fn load(path: &Path) -> Result<SealedPersonas, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("persona custody: read '{}': {e}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("persona custody: parse '{}': {e}", path.display()))
}

/// Unseal **and** firewall-audit a sealed registry (row #107 enforcement leg).
///
/// [`unseal`] rebuilds the registry without re-running any register-time
/// separation gate, so a crafted or legacy custody file could hand back a
/// registry whose identities share a compartment, fingerprint seed, or contact
/// surface. This checked leg refuses such a file instead of returning it; for a
/// separated registry it is identical to [`unseal`].
pub fn unseal_checked(sealed: &SealedPersonas, password: &str) -> Result<PersonaRegistry, String> {
    let registry = unseal(sealed, password)?;
    let firewall = firewall::PersonaFirewall::new(&registry)
        .map_err(|e| format!("persona firewall: audit unavailable: {e}"))?;
    let report = firewall.audit();
    if report.is_clean() {
        Ok(registry)
    } else {
        Err(format!(
            "persona firewall: sealed registry violates identity separation: {report}"
        ))
    }
}

/// [`load`] + [`unseal_checked`]: read a custody file and refuse it unless its
/// identities are separated.
pub fn load_checked(path: &Path, password: &str) -> Result<PersonaRegistry, String> {
    let sealed = load(path)?;
    unseal_checked(&sealed, password)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("persona custody: odd-length hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| "persona custody: invalid hex".to_string())
        })
        .collect()
}

/// Persona firewall: enforced identity-separation checks over the persona
/// custody data shapes (row #107, design source ag10 R-3).
///
/// # What separation means here
///
/// A persona is a *disposable identity*; separation is the invariant that the
/// material of one identity — its A5.1.1 isolation compartment, its
/// fingerprint seed, its legend contact surface — is never reachable from
/// another identity's context. [`PersonaRegistry`] enforces id/seed uniqueness
/// at `register` time and never-reuse at open time, but it does **not** enforce
/// compartment or contact-surface separation, and neither the plain custody
/// legs (`seal`/`unseal`, which are serde round-trips) nor a reloaded custody
/// file re-runs any register-time gate. This module closes that gap: it audits
/// a registry for violations and refuses to open an identity context (or a
/// checked custody file) while one exists.
///
/// # Rule set
///
/// - **Cross-persona reference** — an operation acting as persona `X` may
///   reference persona `X`; referencing any other persona id is refused
///   ([`FirewallRefusal::CrossPersonaReference`]). A reference is a join, and
///   identities must not be joined.
/// - **Foreign material** — a persona's context may hold only its own material
///   for the three tracked fields; material owned by another persona is
///   refused ([`FirewallRefusal::ForeignMaterial`]).
/// - **Shared material (live × live)** — two live personas sharing a
///   compartment, fingerprint seed, or contact surface is a finding; both
///   contexts are blocked until it is repaired
///   ([`FirewallRefusal::UnsafeSeparation`]).
/// - **Burned reachability** — a *live* persona sharing material with a burned
///   identity is a finding: burn revokes and quarantines, so burned material
///   must not be reachable from any live context.
///
/// # Determinism and blanks
///
/// Findings are emitted in a fixed order (personas sorted by id, fields in
/// [`MaterialField::ALL`] order), so reports and refusals are stable and
/// testable. Blank (empty-string) material is not persona-scoped and never
/// produces a finding.
///
/// # Enumeration note
///
/// [`PersonaRegistry`] exposes no iteration API, so the firewall reads the
/// registry's **serde projection** — the same codec the custody format uses
/// ([`seal`]/[`unseal`] are serde round-trips). See the lane log §OPEN for the
/// one-accessor follow-up in `src/persona.rs` that would let the audit drop the
/// projection.
pub mod firewall {
    use std::collections::{BTreeMap, BTreeSet};

    use serde::{Deserialize, Serialize};

    use crate::persona::{
        BurnMethod, Lifecycle, Persona, PersonaBundle, PersonaError, PersonaRegistry,
    };

    /// One tracked piece of persona-scoped material.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum MaterialField {
        /// The A5.1.1 isolation compartment the persona owns.
        Compartment,
        /// The persona's unique fingerprint seed (E5003(b)).
        FingerprintSeed,
        /// The legend's contact surface (email, handle, …).
        ContactSurface,
    }

    impl MaterialField {
        /// Every tracked field, in report order.
        pub const ALL: [MaterialField; 3] = [
            MaterialField::Compartment,
            MaterialField::FingerprintSeed,
            MaterialField::ContactSurface,
        ];

        /// Stable snake_case name (report/log vocabulary).
        pub fn as_str(&self) -> &'static str {
            match self {
                MaterialField::Compartment => "compartment",
                MaterialField::FingerprintSeed => "fingerprint_seed",
                MaterialField::ContactSurface => "contact_surface",
            }
        }
    }

    impl std::fmt::Display for MaterialField {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.as_str())
        }
    }

    /// A detected identity-separation violation. A finding *reports*; the
    /// refusal types below are what callers must handle.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum SeparationFinding {
        /// Two live personas claim the same isolation compartment.
        SharedCompartment {
            persona_a: String,
            persona_b: String,
            compartment: String,
        },
        /// Two live personas wear the same fingerprint seed (only reachable via
        /// a crafted/legacy custody payload — `register` refuses it).
        SharedFingerprintSeed {
            persona_a: String,
            persona_b: String,
            seed: String,
        },
        /// Two live personas present the same contact surface.
        SharedContactSurface {
            persona_a: String,
            persona_b: String,
            surface: String,
        },
        /// A burned (quarantined) identity's material is shared with a live one.
        BurnedMaterialReachable {
            active_persona: String,
            burned_persona: String,
            field: MaterialField,
            value: String,
        },
    }

    impl SeparationFinding {
        /// Stable snake_case kind (report/log vocabulary).
        pub fn kind(&self) -> &'static str {
            match self {
                SeparationFinding::SharedCompartment { .. } => "shared_compartment",
                SeparationFinding::SharedFingerprintSeed { .. } => "shared_fingerprint_seed",
                SeparationFinding::SharedContactSurface { .. } => "shared_contact_surface",
                SeparationFinding::BurnedMaterialReachable { .. } => "burned_material_reachable",
            }
        }

        /// True iff `persona` is one of the two identities the finding joins.
        pub fn involves(&self, persona: &str) -> bool {
            match self {
                SeparationFinding::SharedCompartment {
                    persona_a,
                    persona_b,
                    ..
                }
                | SeparationFinding::SharedFingerprintSeed {
                    persona_a,
                    persona_b,
                    ..
                }
                | SeparationFinding::SharedContactSurface {
                    persona_a,
                    persona_b,
                    ..
                } => persona_a.as_str() == persona || persona_b.as_str() == persona,
                SeparationFinding::BurnedMaterialReachable {
                    active_persona,
                    burned_persona,
                    ..
                } => active_persona.as_str() == persona || burned_persona.as_str() == persona,
            }
        }
    }

    impl std::fmt::Display for SeparationFinding {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                SeparationFinding::SharedCompartment {
                    persona_a,
                    persona_b,
                    compartment,
                } => write!(
                    f,
                    "personas `{persona_a}` and `{persona_b}` share compartment `{compartment}`"
                ),
                SeparationFinding::SharedFingerprintSeed {
                    persona_a,
                    persona_b,
                    seed,
                } => write!(
                    f,
                    "personas `{persona_a}` and `{persona_b}` share fingerprint seed `{seed}`"
                ),
                SeparationFinding::SharedContactSurface {
                    persona_a,
                    persona_b,
                    surface,
                } => write!(
                    f,
                    "personas `{persona_a}` and `{persona_b}` share contact surface `{surface}`"
                ),
                SeparationFinding::BurnedMaterialReachable {
                    active_persona,
                    burned_persona,
                    field,
                    value,
                } => write!(
                    f,
                    "burned persona `{burned_persona}`'s {field} `{value}` is reachable from \
                     active persona `{active_persona}`"
                ),
            }
        }
    }

    /// Why the firewall refused. Deny-by-default: every variant is a hard
    /// refusal a caller must not swallow, mirroring [`PersonaError`].
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum FirewallRefusal {
        /// The registry's own gate refused (unknown / burned / …).
        Registry(PersonaError),
        /// A joining reference between two identities was attempted.
        CrossPersonaReference {
            /// The acting persona.
            actor: String,
            /// The other persona id referenced from the actor's context.
            target: String,
        },
        /// Material that is not the presenting persona's own was presented.
        ForeignMaterial {
            /// The persona claiming the material.
            claimed_persona: String,
            /// The persona the material belongs to (`None` = no recorded owner;
            /// still refused for a bundle, since a bundle must be *this*
            /// persona's material).
            material_owner: Option<String>,
            /// Which tracked field.
            field: MaterialField,
            /// The material value presented.
            value: String,
        },
        /// The persona's context is not separated from another identity.
        UnsafeSeparation {
            /// The persona whose context was requested.
            persona: String,
            /// The findings that block it.
            findings: Vec<SeparationFinding>,
        },
        /// The audit could not enumerate the registry (defensive; a registry
        /// that came through `seal`/`unseal` always projects).
        AuditUnavailable {
            /// What failed.
            reason: String,
        },
    }

    impl std::fmt::Display for FirewallRefusal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                FirewallRefusal::Registry(e) => {
                    write!(f, "persona firewall: registry refused: {e}")
                }
                FirewallRefusal::CrossPersonaReference { actor, target } => write!(
                    f,
                    "persona firewall: cross-persona reference refused: persona `{actor}` must \
                     not reference persona `{target}`"
                ),
                FirewallRefusal::ForeignMaterial {
                    claimed_persona,
                    material_owner,
                    field,
                    value,
                } => match material_owner {
                    Some(owner) => write!(
                        f,
                        "persona firewall: foreign material: persona `{claimed_persona}` \
                         presented {field} `{value}` owned by persona `{owner}`"
                    ),
                    None => write!(
                        f,
                        "persona firewall: foreign material: persona `{claimed_persona}` \
                         presented {field} `{value}` with no recorded owner"
                    ),
                },
                FirewallRefusal::UnsafeSeparation { persona, findings } => {
                    let joined: Vec<String> = findings.iter().map(|x| x.to_string()).collect();
                    write!(
                        f,
                        "persona firewall: persona `{persona}` is not separated: {}",
                        joined.join("; ")
                    )
                }
                FirewallRefusal::AuditUnavailable { reason } => {
                    write!(f, "persona firewall: audit unavailable: {reason}")
                }
            }
        }
    }

    impl std::error::Error for FirewallRefusal {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                FirewallRefusal::Registry(e) => Some(e),
                _ => None,
            }
        }
    }

    impl From<PersonaError> for FirewallRefusal {
        fn from(e: PersonaError) -> Self {
            FirewallRefusal::Registry(e)
        }
    }

    /// The identity context of one operation. Only
    /// [`PersonaFirewall::open_scope`] constructs one, and only after the
    /// separation checks passed — holding a scope is evidence of separation at
    /// open time. Re-check with [`PersonaFirewall::check_scope`] after a burn,
    /// reload, or any custody change.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PersonaScope {
        id: String,
        compartment: String,
        fingerprint_seed: String,
        contact_surface: String,
    }

    impl PersonaScope {
        fn from_bundle(bundle: &PersonaBundle) -> Self {
            PersonaScope {
                id: bundle.id.clone(),
                compartment: bundle.compartment.clone(),
                fingerprint_seed: bundle.fingerprint_seed.clone(),
                contact_surface: bundle.legend.contact_surface.clone(),
            }
        }

        /// The acting persona id.
        pub fn id(&self) -> &str {
            &self.id
        }

        /// The isolation compartment this context may operate in.
        pub fn compartment(&self) -> &str {
            &self.compartment
        }

        /// The fingerprint seed this context wears.
        pub fn fingerprint_seed(&self) -> &str {
            &self.fingerprint_seed
        }

        /// The contact surface this context presents.
        pub fn contact_surface(&self) -> &str {
            &self.contact_surface
        }

        /// The scope's own value for a tracked field.
        pub fn material(&self, field: MaterialField) -> &str {
            match field {
                MaterialField::Compartment => &self.compartment,
                MaterialField::FingerprintSeed => &self.fingerprint_seed,
                MaterialField::ContactSurface => &self.contact_surface,
            }
        }
    }

    /// Every separation finding in a registry, in deterministic order.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SeparationReport {
        findings: Vec<SeparationFinding>,
    }

    impl SeparationReport {
        /// True iff no identity-separation violation exists.
        pub fn is_clean(&self) -> bool {
            self.findings.is_empty()
        }

        /// The findings, in report order.
        pub fn findings(&self) -> &[SeparationFinding] {
            &self.findings
        }

        /// How many findings the report carries.
        pub fn len(&self) -> usize {
            self.findings.len()
        }

        /// True iff the report carries no findings (alias of [`Self::is_clean`]).
        pub fn is_empty(&self) -> bool {
            self.findings.is_empty()
        }

        /// The findings that join `persona` to another identity.
        pub fn for_persona(&self, persona: &str) -> Vec<SeparationFinding> {
            self.findings
                .iter()
                .filter(|f| f.involves(persona))
                .cloned()
                .collect()
        }
    }

    impl std::fmt::Display for SeparationReport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.findings.is_empty() {
                return f.write_str("identity separation clean (no findings)");
            }
            for (i, finding) in self.findings.iter().enumerate() {
                if i > 0 {
                    f.write_str("; ")?;
                }
                write!(f, "{finding}")?;
            }
            Ok(())
        }
    }

    /// The persona firewall: a read-only check layer over a
    /// [`PersonaRegistry`]. Construction is fallible only because the audit
    /// needs the registry's serde projection (see the module docs).
    pub struct PersonaFirewall<'a> {
        registry: &'a PersonaRegistry,
        roster: Vec<Persona>,
    }

    impl<'a> PersonaFirewall<'a> {
        /// Build the firewall over `registry` (projection read once).
        pub fn new(registry: &'a PersonaRegistry) -> Result<Self, FirewallRefusal> {
            Ok(PersonaFirewall {
                registry,
                roster: roster_of(registry)?,
            })
        }

        /// The registry under audit.
        pub fn registry(&self) -> &'a PersonaRegistry {
            self.registry
        }

        /// Audit every identity-separation rule over the whole registry.
        pub fn audit(&self) -> SeparationReport {
            audit_roster(&self.roster, self.registry.burned_ids())
        }

        /// The findings that join `persona` to another identity.
        pub fn report_for(&self, persona: &str) -> Vec<SeparationFinding> {
            self.audit().for_persona(persona)
        }

        /// Open the identity context for `id` — the enforced boundary.
        ///
        /// Refuses when the registry does not know `id`
        /// ([`PersonaError::UnknownPersona`]), when `id` is burned
        /// ([`PersonaError::BurnedReuse`] — never-reuse, plus the lifecycle
        /// double-check so a stale taint set cannot hand out a burned identity's
        /// material), when the scope's material is not `id`'s own
        /// ([`FirewallRefusal::ForeignMaterial`]), or when `id`'s material is
        /// shared with another identity ([`FirewallRefusal::UnsafeSeparation`]).
        pub fn open_scope(&self, id: &str) -> Result<PersonaScope, FirewallRefusal> {
            let bundle = self.registry.open_bundle(id).map_err(FirewallRefusal::Registry)?;
            let scope = PersonaScope::from_bundle(&bundle);
            self.check_scope(&scope)?;
            Ok(scope)
        }

        /// Re-check an already-opened scope against the current registry —
        /// call after a burn, a reload, or any custody change.
        pub fn check_scope(&self, scope: &PersonaScope) -> Result<(), FirewallRefusal> {
            let stored = self.registry.get(&scope.id).ok_or_else(|| {
                FirewallRefusal::Registry(PersonaError::UnknownPersona {
                    id: scope.id.clone(),
                })
            })?;
            if let Some((at_ms, method)) = burned_state(self.registry, &scope.id) {
                return Err(FirewallRefusal::Registry(PersonaError::BurnedReuse {
                    id: scope.id.clone(),
                    at_ms,
                    method,
                }));
            }
            for field in MaterialField::ALL {
                let held = scope.material(field);
                if held != field_value(stored, field) {
                    return Err(FirewallRefusal::ForeignMaterial {
                        claimed_persona: scope.id.clone(),
                        material_owner: self.owner_of(field, held),
                        field,
                        value: held.to_string(),
                    });
                }
            }
            let findings = self.audit().for_persona(&scope.id);
            if !findings.is_empty() {
                return Err(FirewallRefusal::UnsafeSeparation {
                    persona: scope.id.clone(),
                    findings,
                });
            }
            Ok(())
        }

        /// Vet a [`PersonaBundle`] that did not come straight from
        /// `open_bundle` (e.g. one deserialized from a pipeline payload): every
        /// tracked field must be the claimed persona's own stored material.
        pub fn check_bundle(&self, bundle: &PersonaBundle) -> Result<(), FirewallRefusal> {
            let stored = self.registry.get(&bundle.id).ok_or_else(|| {
                FirewallRefusal::Registry(PersonaError::UnknownPersona {
                    id: bundle.id.clone(),
                })
            })?;
            if let Some((at_ms, method)) = burned_state(self.registry, &bundle.id) {
                return Err(FirewallRefusal::Registry(PersonaError::BurnedReuse {
                    id: bundle.id.clone(),
                    at_ms,
                    method,
                }));
            }
            for field in MaterialField::ALL {
                let held = match field {
                    MaterialField::Compartment => bundle.compartment.as_str(),
                    MaterialField::FingerprintSeed => bundle.fingerprint_seed.as_str(),
                    MaterialField::ContactSurface => bundle.legend.contact_surface.as_str(),
                };
                if held != field_value(stored, field) {
                    return Err(FirewallRefusal::ForeignMaterial {
                        claimed_persona: bundle.id.clone(),
                        material_owner: self.owner_of(field, held),
                        field,
                        value: held.to_string(),
                    });
                }
            }
            Ok(())
        }

        /// The cross-persona reference gate: a context acting as persona `X`
        /// may reference `X` and nothing else. Registered or not, any other id
        /// is refused — a reference resolves inside one identity context.
        pub fn assert_reference(
            &self,
            scope: &PersonaScope,
            target: &str,
        ) -> Result<(), FirewallRefusal> {
            if target == scope.id {
                Ok(())
            } else {
                Err(FirewallRefusal::CrossPersonaReference {
                    actor: scope.id.clone(),
                    target: target.to_string(),
                })
            }
        }

        /// The persona-scoped-material gate: the context may hold its own value
        /// for `field`; a value owned by another persona is refused as
        /// [`FirewallRefusal::ForeignMaterial`]. Values owned by nobody (and
        /// blanks) are not persona-scoped material — a firewall refuses joins,
        /// it is not an allow-list.
        pub fn assert_material_access(
            &self,
            scope: &PersonaScope,
            field: MaterialField,
            value: &str,
        ) -> Result<(), FirewallRefusal> {
            if value.is_empty() || value == scope.material(field) {
                return Ok(());
            }
            match self.owner_of(field, value) {
                Some(owner) if owner != scope.id => Err(FirewallRefusal::ForeignMaterial {
                    claimed_persona: scope.id.clone(),
                    material_owner: Some(owner),
                    field,
                    value: value.to_string(),
                }),
                _ => Ok(()),
            }
        }

        /// First roster owner of `value` for `field` (roster is id-sorted, so
        /// the answer is deterministic), or `None` if nobody owns it.
        fn owner_of(&self, field: MaterialField, value: &str) -> Option<String> {
            if value.is_empty() {
                return None;
            }
            self.roster
                .iter()
                .find(|p| field_value(p, field) == value)
                .map(|p| p.id.clone())
        }
    }

    /// The pure audit core over an explicit roster (persona objects) and burned
    /// id set — the same computation [`PersonaFirewall::audit`] runs.
    pub fn audit_roster(personas: &[Persona], burned: &BTreeSet<String>) -> SeparationReport {
        let mut roster: Vec<&Persona> = personas.iter().collect();
        roster.sort_by(|a, b| a.id.cmp(&b.id));
        let mut findings = Vec::new();
        for (i, a) in roster.iter().enumerate() {
            for b in roster[i + 1..].iter() {
                let a_burned = burned.contains(&a.id) || a.is_burned();
                let b_burned = burned.contains(&b.id) || b.is_burned();
                if a_burned && b_burned {
                    // Both identities are terminal: no live context to protect.
                    continue;
                }
                for field in MaterialField::ALL {
                    let value = field_value(a, field);
                    if value.is_empty() || value != field_value(b, field) {
                        continue;
                    }
                    if a_burned || b_burned {
                        let (active, burned_persona) = if a_burned { (b, a) } else { (a, b) };
                        findings.push(SeparationFinding::BurnedMaterialReachable {
                            active_persona: active.id.clone(),
                            burned_persona: burned_persona.id.clone(),
                            field,
                            value: value.to_string(),
                        });
                    } else {
                        findings.push(match field {
                            MaterialField::Compartment => SeparationFinding::SharedCompartment {
                                persona_a: a.id.clone(),
                                persona_b: b.id.clone(),
                                compartment: value.to_string(),
                            },
                            MaterialField::FingerprintSeed => {
                                SeparationFinding::SharedFingerprintSeed {
                                    persona_a: a.id.clone(),
                                    persona_b: b.id.clone(),
                                    seed: value.to_string(),
                                }
                            }
                            MaterialField::ContactSurface => {
                                SeparationFinding::SharedContactSurface {
                                    persona_a: a.id.clone(),
                                    persona_b: b.id.clone(),
                                    surface: value.to_string(),
                                }
                            }
                        });
                    }
                }
            }
        }
        SeparationReport { findings }
    }

    /// One tracked field of a stored persona.
    fn field_value<'p>(persona: &'p Persona, field: MaterialField) -> &'p str {
        match field {
            MaterialField::Compartment => &persona.compartment,
            MaterialField::FingerprintSeed => &persona.fingerprint_seed,
            MaterialField::ContactSurface => &persona.legend.contact_surface,
        }
    }

    /// Burned state per the registry: the taint set is canonical (that is what
    /// `assert_reusable` reads), but a burned *lifecycle* counts too — a stale
    /// taint set must not let a burned identity's material out.
    fn burned_state(registry: &PersonaRegistry, id: &str) -> Option<(u64, BurnMethod)> {
        let persona = registry.get(id);
        let tainted = registry.is_burned(id) || persona.is_some_and(Persona::is_burned);
        if !tainted {
            return None;
        }
        let (at_ms, method) = match persona {
            Some(Persona {
                lifecycle: Lifecycle::Burned { at_ms, method, .. },
                ..
            }) => (*at_ms, *method),
            // Tainted without a burn record: keep the hard-fail (sentinel),
            // mirroring `PersonaRegistry::assert_reusable`.
            _ => (0, BurnMethod::RevokeAndQuarantine),
        };
        Some((at_ms, method))
    }

    /// The registry's persona roster via its **serde projection**.
    ///
    /// `PersonaRegistry` exposes no iteration API; the custody format is itself
    /// a serde projection of the registry, so the audit reads the same codec.
    /// See the lane log §OPEN for the `persona.rs` accessor follow-up.
    fn roster_of(registry: &PersonaRegistry) -> Result<Vec<Persona>, FirewallRefusal> {
        #[derive(Deserialize)]
        struct RegistryProjection {
            personas: BTreeMap<String, Persona>,
        }
        let value = serde_json::to_value(registry).map_err(|e| {
            FirewallRefusal::AuditUnavailable {
                reason: format!("registry projection encode: {e}"),
            }
        })?;
        let projection: RegistryProjection =
            serde_json::from_value(value).map_err(|e| FirewallRefusal::AuditUnavailable {
                reason: format!("registry projection decode: {e}"),
            })?;
        let mut roster: Vec<Persona> = projection.personas.into_values().collect();
        roster.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(roster)
    }

    #[cfg(test)]
    mod firewall_tests {
        use super::*;
        use crate::persona::{CoverClass, Legend, QuarantineMode};
        use crate::vault::persona_store::{
            load_checked, save, seal, unseal, unseal_checked,
        };

        fn persona_full(id: &str, seed: &str, compartment: &str, contact: &str) -> Persona {
            Persona::new(
                id,
                CoverClass::new("researcher"),
                compartment,
                Legend::new("backstory", contact, "run-1"),
                seed,
                1_700_000_000_000,
            )
        }

        fn clean_registry() -> PersonaRegistry {
            let mut reg = PersonaRegistry::new();
            reg.register(persona_full(
                "p-1",
                "seed-1",
                "ctrl-1",
                "one@example.invalid",
            ))
            .unwrap();
            reg.register(persona_full(
                "p-2",
                "seed-2",
                "ctrl-2",
                "two@example.invalid",
            ))
            .unwrap();
            reg
        }

        #[test]
        fn clean_registry_audits_clean_and_opens_scopes() {
            let reg = clean_registry();
            let fw = PersonaFirewall::new(&reg).unwrap();

            let report = fw.audit();
            assert!(report.is_clean(), "report: {report}");
            assert!(report.findings().is_empty());
            assert!(fw.report_for("p-1").is_empty());

            let scope = fw.open_scope("p-1").unwrap();
            assert_eq!(scope.id(), "p-1");
            assert_eq!(scope.compartment(), "ctrl-1");
            assert_eq!(scope.fingerprint_seed(), "seed-1");
            assert_eq!(scope.contact_surface(), "one@example.invalid");
            assert_eq!(scope.material(MaterialField::FingerprintSeed), "seed-1");
            assert!(fw.check_scope(&scope).is_ok());
        }

        #[test]
        fn shared_compartment_is_detected_and_blocks_both_contexts() {
            let mut reg = PersonaRegistry::new();
            reg.register(persona_full(
                "p-1",
                "seed-1",
                "shared-ctrl",
                "one@example.invalid",
            ))
            .unwrap();
            reg.register(persona_full(
                "p-2",
                "seed-2",
                "shared-ctrl",
                "two@example.invalid",
            ))
            .unwrap();
            let fw = PersonaFirewall::new(&reg).unwrap();

            let report = fw.audit();
            assert_eq!(report.findings().len(), 1, "report: {report}");
            match &report.findings()[0] {
                SeparationFinding::SharedCompartment {
                    persona_a,
                    persona_b,
                    compartment,
                } => {
                    assert_eq!(persona_a.as_str(), "p-1");
                    assert_eq!(persona_b.as_str(), "p-2");
                    assert_eq!(compartment.as_str(), "shared-ctrl");
                }
                other => panic!("wrong finding: {other:?}"),
            }

            for id in ["p-1", "p-2"] {
                match fw.open_scope(id) {
                    Err(FirewallRefusal::UnsafeSeparation { persona, findings }) => {
                        assert_eq!(persona.as_str(), id);
                        assert_eq!(findings.len(), 1);
                    }
                    other => panic!("expected UnsafeSeparation for {id}, got {other:?}"),
                }
            }
        }

        #[test]
        fn shared_contact_surface_is_detected() {
            let mut reg = PersonaRegistry::new();
            reg.register(persona_full(
                "p-1",
                "seed-1",
                "ctrl-1",
                "shared@example.invalid",
            ))
            .unwrap();
            reg.register(persona_full(
                "p-2",
                "seed-2",
                "ctrl-2",
                "shared@example.invalid",
            ))
            .unwrap();
            let fw = PersonaFirewall::new(&reg).unwrap();

            let report = fw.audit();
            assert!(
                matches!(
                    report.findings(),
                    [SeparationFinding::SharedContactSurface { surface, .. }]
                        if surface.as_str() == "shared@example.invalid"
                ),
                "report: {report}"
            );
            assert!(matches!(
                fw.open_scope("p-1"),
                Err(FirewallRefusal::UnsafeSeparation { .. })
            ));
        }

        #[test]
        fn blank_material_is_not_persona_scoped() {
            let mut reg = PersonaRegistry::new();
            reg.register(persona_full("p-1", "seed-1", "ctrl-1", "")).unwrap();
            reg.register(persona_full("p-2", "seed-2", "ctrl-2", "")).unwrap();
            let fw = PersonaFirewall::new(&reg).unwrap();

            assert!(
                fw.audit().is_clean(),
                "blank contact surfaces must not join identities"
            );
            assert!(fw.open_scope("p-1").is_ok());
        }

        #[test]
        fn tampered_registry_seed_reuse_is_detected_and_checked_open_refuses() {
            let mut reg = PersonaRegistry::new();
            reg.register(persona_full(
                "t-1",
                "seed-t1",
                "comp-1",
                "one@example.invalid",
            ))
            .unwrap();
            reg.register(persona_full(
                "t-2",
                "seed-t2",
                "comp-2",
                "two@example.invalid",
            ))
            .unwrap();
            // `register` refuses seed reuse, but a crafted custody payload
            // bypasses every register-time gate — the gap this lane closes.
            let mut value = serde_json::to_value(&reg).unwrap();
            value["personas"]["t-2"]["fingerprint_seed"] = serde_json::json!("seed-t1");
            let tampered: PersonaRegistry = serde_json::from_value(value).unwrap();

            let fw = PersonaFirewall::new(&tampered).unwrap();
            let report = fw.audit();
            assert!(
                matches!(
                    report.findings(),
                    [SeparationFinding::SharedFingerprintSeed { seed, .. }]
                        if seed.as_str() == "seed-t1"
                ),
                "report: {report}"
            );
            assert!(matches!(
                fw.open_scope("t-2"),
                Err(FirewallRefusal::UnsafeSeparation { .. })
            ));

            // The plain custody leg is unchanged; the checked leg refuses.
            let sealed = seal(&tampered, "pw").unwrap();
            assert!(unseal(&sealed, "pw").is_ok());
            let err = unseal_checked(&sealed, "pw").expect_err("tampered registry refused");
            assert!(err.contains("persona firewall"), "err: {err}");
            assert!(err.contains("share fingerprint seed"), "err: {err}");
        }

        #[test]
        fn burned_material_reachable_blocks_the_live_context() {
            let mut reg = PersonaRegistry::new();
            reg.register(persona_full(
                "live-1",
                "seed-l",
                "ctrl-1",
                "live@example.invalid",
            ))
            .unwrap();
            reg.register(persona_full(
                "dead-1",
                "seed-d",
                "ctrl-1",
                "dead@example.invalid",
            ))
            .unwrap();
            reg.burn(
                "dead-1",
                1_800_000_000_000,
                BurnMethod::RevokeAndQuarantine,
                QuarantineMode::Quarantine,
            )
            .unwrap();

            let fw = PersonaFirewall::new(&reg).unwrap();
            match fw.audit().findings() {
                [SeparationFinding::BurnedMaterialReachable {
                    active_persona,
                    burned_persona,
                    field,
                    value,
                }] => {
                    assert_eq!(active_persona.as_str(), "live-1");
                    assert_eq!(burned_persona.as_str(), "dead-1");
                    assert_eq!(*field, MaterialField::Compartment);
                    assert_eq!(value.as_str(), "ctrl-1");
                }
                other => panic!("wrong findings: {other:?}"),
            }

            assert!(matches!(
                fw.open_scope("live-1"),
                Err(FirewallRefusal::UnsafeSeparation { .. })
            ));
            // The burned context itself stays refused by the never-reuse gate.
            assert!(matches!(
                fw.open_scope("dead-1"),
                Err(FirewallRefusal::Registry(PersonaError::BurnedReuse { .. }))
            ));
            assert_eq!(fw.report_for("dead-1").len(), 1);
        }

        #[test]
        fn cross_persona_reference_is_refused_self_reference_allowed() {
            let reg = clean_registry();
            let fw = PersonaFirewall::new(&reg).unwrap();
            let scope = fw.open_scope("p-1").unwrap();

            assert!(
                fw.assert_reference(&scope, "p-1").is_ok(),
                "the acting persona may reference itself"
            );
            match fw.assert_reference(&scope, "p-2") {
                Err(FirewallRefusal::CrossPersonaReference { actor, target }) => {
                    assert_eq!(actor.as_str(), "p-1");
                    assert_eq!(target.as_str(), "p-2");
                }
                other => panic!("expected CrossPersonaReference, got {other:?}"),
            }
            // Unknown ids are refused too: a reference resolves inside one
            // identity context, registered or not.
            assert!(matches!(
                fw.assert_reference(&scope, "ghost"),
                Err(FirewallRefusal::CrossPersonaReference { .. })
            ));
        }

        #[test]
        fn foreign_material_access_is_refused_own_and_unowned_values_pass() {
            let reg = clean_registry();
            let fw = PersonaFirewall::new(&reg).unwrap();
            let scope = fw.open_scope("p-1").unwrap();

            assert!(fw
                .assert_material_access(&scope, MaterialField::Compartment, "ctrl-1")
                .is_ok());
            assert!(fw
                .assert_material_access(&scope, MaterialField::ContactSurface, "one@example.invalid")
                .is_ok());

            match fw.assert_material_access(&scope, MaterialField::FingerprintSeed, "seed-2") {
                Err(FirewallRefusal::ForeignMaterial {
                    claimed_persona,
                    material_owner,
                    field,
                    value,
                }) => {
                    assert_eq!(claimed_persona.as_str(), "p-1");
                    assert_eq!(material_owner.as_deref(), Some("p-2"));
                    assert_eq!(field, MaterialField::FingerprintSeed);
                    assert_eq!(value.as_str(), "seed-2");
                }
                other => panic!("expected ForeignMaterial, got {other:?}"),
            }

            // Material owned by nobody (or blank) is not persona-scoped — the
            // firewall refuses joins, it is not an allow-list.
            assert!(fw
                .assert_material_access(&scope, MaterialField::Compartment, "future-compartment")
                .is_ok());
            assert!(fw
                .assert_material_access(&scope, MaterialField::ContactSurface, "")
                .is_ok());
        }

        #[test]
        fn forged_bundle_material_is_refused() {
            let reg = clean_registry();
            let fw = PersonaFirewall::new(&reg).unwrap();
            let bundle = reg.open_bundle("p-1").unwrap();
            assert!(fw.check_bundle(&bundle).is_ok(), "honest bundle passes");

            // p-1's id wearing p-2's fingerprint seed.
            let mut forged = bundle.clone();
            forged.fingerprint_seed = "seed-2".to_string();
            match fw.check_bundle(&forged) {
                Err(FirewallRefusal::ForeignMaterial {
                    claimed_persona,
                    material_owner,
                    field,
                    value,
                }) => {
                    assert_eq!(claimed_persona.as_str(), "p-1");
                    assert_eq!(material_owner.as_deref(), Some("p-2"));
                    assert_eq!(field, MaterialField::FingerprintSeed);
                    assert_eq!(value.as_str(), "seed-2");
                }
                other => panic!("expected ForeignMaterial, got {other:?}"),
            }

            // Material owned by nobody is refused outright for a bundle: a
            // bundle must be *this* persona's own stored material.
            let mut unowned = bundle.clone();
            unowned.legend.contact_surface = "nowhere@example.invalid".to_string();
            assert!(matches!(
                fw.check_bundle(&unowned),
                Err(FirewallRefusal::ForeignMaterial {
                    material_owner: None,
                    ..
                })
            ));

            // Unknown id and burned id are both refused by the registry gates.
            let mut ghost = bundle.clone();
            ghost.id = "ghost".to_string();
            assert!(matches!(
                fw.check_bundle(&ghost),
                Err(FirewallRefusal::Registry(PersonaError::UnknownPersona { .. }))
            ));

            let mut reg2 = clean_registry();
            reg2.burn(
                "p-2",
                1_800_000_000_000,
                BurnMethod::RevokeAndQuarantine,
                QuarantineMode::Quarantine,
            )
            .unwrap();
            let fw2 = PersonaFirewall::new(&reg2).unwrap();
            let burned_bundle = PersonaBundle {
                id: "p-2".to_string(),
                cover_class: CoverClass::new("researcher"),
                compartment: "ctrl-2".to_string(),
                legend: Legend::new("backstory", "two@example.invalid", "run-1"),
                fingerprint_seed: "seed-2".to_string(),
            };
            assert!(matches!(
                fw2.check_bundle(&burned_bundle),
                Err(FirewallRefusal::Registry(PersonaError::BurnedReuse { .. }))
            ));
        }

        #[test]
        fn reopened_scope_recheck_refuses_after_burn() {
            let mut reg = clean_registry();
            let scope = {
                let fw = PersonaFirewall::new(&reg).unwrap();
                fw.open_scope("p-1").unwrap()
            };
            reg.burn(
                "p-1",
                1_800_000_000_000,
                BurnMethod::RevokeAndQuarantine,
                QuarantineMode::Quarantine,
            )
            .unwrap();

            let fw = PersonaFirewall::new(&reg).unwrap();
            assert!(matches!(
                fw.check_scope(&scope),
                Err(FirewallRefusal::Registry(PersonaError::BurnedReuse { .. }))
            ));
            assert!(matches!(
                fw.open_scope("p-1"),
                Err(FirewallRefusal::Registry(PersonaError::BurnedReuse { .. }))
            ));
            // The remaining live persona is still separated and opens fine.
            assert!(fw.open_scope("p-2").is_ok());
        }

        #[test]
        fn findings_and_refusals_round_trip_and_display_identities() {
            let mut reg = PersonaRegistry::new();
            reg.register(persona_full(
                "p-1",
                "seed-1",
                "shared-ctrl",
                "one@example.invalid",
            ))
            .unwrap();
            reg.register(persona_full(
                "p-2",
                "seed-2",
                "shared-ctrl",
                "two@example.invalid",
            ))
            .unwrap();
            let fw = PersonaFirewall::new(&reg).unwrap();

            let refusal = fw.open_scope("p-1").expect_err("shared compartment refuses");
            let json = serde_json::to_string(&refusal).unwrap();
            let back: FirewallRefusal = serde_json::from_str(&json).unwrap();
            assert_eq!(back, refusal);
            let msg = refusal.to_string();
            assert!(msg.contains("p-1"), "msg: {msg}");
            assert!(msg.contains("shared-ctrl"), "msg: {msg}");

            let finding = fw.audit().findings()[0].clone();
            assert_eq!(finding.kind(), "shared_compartment");
            assert!(finding.involves("p-2") && !finding.involves("p-9"));
            let back: SeparationFinding =
                serde_json::from_str(&serde_json::to_string(&finding).unwrap()).unwrap();
            assert_eq!(back, finding);
            assert!(finding.to_string().contains("p-2"), "finding: {finding}");

            // Registry refusals wrap the underlying persona error and surface it.
            let wrapped: FirewallRefusal =
                PersonaError::UnknownPersona { id: "ghost".to_string() }.into();
            assert!(matches!(
                wrapped,
                FirewallRefusal::Registry(PersonaError::UnknownPersona { .. })
            ));
            assert!(wrapped.to_string().contains("ghost"));
        }

        #[test]
        fn checked_custody_legs_accept_a_separated_registry_and_keep_burn_taint() {
            let mut reg = clean_registry();
            reg.burn(
                "p-2",
                1_800_000_000_000,
                BurnMethod::RevokeAndQuarantine,
                QuarantineMode::Quarantine,
            )
            .unwrap();
            let sealed = seal(&reg, "pw-9").unwrap();

            let restored = unseal_checked(&sealed, "pw-9").unwrap();
            assert_eq!(restored, reg);
            assert!(restored.is_burned("p-2"), "taint survives the checked leg");
            assert!(unseal_checked(&sealed, "wrong").is_err());

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("personas.json");
            save(&path, &sealed).unwrap();
            assert_eq!(load_checked(&path, "pw-9").unwrap(), reg);
            assert!(load_checked(&path, "wrong").is_err());
        }
    }
}

/// Sector pseudonyms for personas — `HKDF-SHA256(master, context)` derivation
/// (row #195; design source `phase2-agents/agent-09-geopolitics.md` F9/R-8, the
/// Austria bPK pattern: per-sector pseudonymous identifiers derived from a
/// master secret + context label).
///
/// # What this gives
///
/// - **Deterministic per (persona, sector)** — the same master and context
///   always derive the same pseudonym ([`SectorPseudonym::id`]); nothing is
///   stored per pseudonym.
/// - **Domain separation** — every derivation is
///   `HKDF-SHA256(salt = [`PSEUDONYM_DOMAIN`], ikm = master,
///   info = length-prefixed (persona id ‖ sector label ‖ leg))`: one extract
///   keyed by the master, then an expand per identity *context* and per output
///   *leg* (`id` vs `key`), so no two sectors share key material and the
///   published identifier is never the private leg.
/// - **No cross-sector linkability** — two sectors of one persona yield
///   independent identifiers with no shared derivation path; a service that
///   sees one sector's identifier learns nothing about another sector's.
/// - **Persona-context binding** — derivation is gated by the row #107
///   firewall: [`PersonaPseudonyms::derive`] takes a [`firewall::PersonaScope`]
///   (only [`firewall::PersonaFirewall::open_scope`] constructs one, and only
///   for a separated identity), and [`PersonaPseudonyms::derive_checked`]
///   re-validates that scope against the firewall first.
///   [`PseudonymPublication`] carries only `(sector, id)` — no persona id, no
///   master, no private leg — so a verifier can confirm a binding by
///   recomputation without any global identifier.
///
/// # Threat-model note (honest scope)
///
/// Unlinkability here is the KDF property (independent pseudorandom outputs per
/// context) — exactly the bPK construction. It protects against *cross-service
/// correlation by the services*, not against an operator who holds both the
/// master and the persona roster. Rotating a persona's master re-randomizes
/// every sector pseudonym at once.
///
/// # Refusals (deny-by-default)
///
/// Blank/short masters, blank personas, non-canonical sector labels, and
/// separation refusals are typed [`PseudonymRefusal`]s. A label is **refused,
/// never normalized** into a different sector; no failure path echoes master
/// material.
pub mod pseudonym {
    use std::fmt;

    use serde::{Deserialize, Serialize};
    use zeroize::Zeroizing;

    use super::firewall::{FirewallRefusal, PersonaFirewall, PersonaScope};
    use super::to_hex;

    /// Domain-separation salt for every derivation in this module (versioned
    /// label — bump it for any change to the derivation spec).
    pub const PSEUDONYM_DOMAIN: &str = "tallow-persona-pseudonym-v1";

    /// Prefix on published identifiers (`tp1_` + lowercase hex).
    pub const PSEUDONYM_ID_PREFIX: &str = "tp1_";

    /// Minimum accepted master length, in bytes (256-bit floor).
    pub const MIN_MASTER_LEN: usize = 32;

    /// Maximum accepted sector-label length, in bytes.
    pub const MAX_SECTOR_LEN: usize = 64;

    /// Expand-leg label for the published identifier.
    const LEG_ID: &str = "id";
    /// Expand-leg label for the private per-service key.
    const LEG_KEY: &str = "key";
    /// Expand-leg label for deriving a per-persona master from vault IKM.
    const LEG_PERSONA_MASTER: &str = "persona-master";

    /// Length-prefixed, domain-separated HKDF `info`:
    /// `DOMAIN NUL leg (len32 ‖ part)*`. Length prefixes (u32 big-endian) make
    /// part boundaries unambiguous, so no two distinct contexts can collide by
    /// delimiter confusion.
    fn context_info(leg: &str, parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            PSEUDONYM_DOMAIN.len() + 1 + leg.len()
                + parts.iter().map(|p| 4 + p.len()).sum::<usize>(),
        );
        out.extend_from_slice(PSEUDONYM_DOMAIN.as_bytes());
        out.push(0);
        out.extend_from_slice(leg.as_bytes());
        for part in parts {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// Why a derivation (or a master construction) was refused. Deny-by-default:
    /// every variant is a hard `Err` — nothing is silently normalized,
    /// truncated, or defaulted.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PseudonymRefusal {
        /// The master IKM was empty.
        BlankMaster,
        /// The master IKM was shorter than [`MIN_MASTER_LEN`] bytes.
        ShortMaster {
            /// Observed IKM length in bytes.
            len: usize,
        },
        /// The master hex was malformed. Carries no echo of the input (the
        /// input *is* key material).
        InvalidMasterHex {
            /// What was wrong with the encoding.
            reason: &'static str,
        },
        /// The persona id bound to the context was empty.
        BlankPersona,
        /// The sector label was empty.
        BlankSector,
        /// The sector label was not canonical (see [`Sector::new`]).
        InvalidSector {
            /// The refused label (a public service name, not a secret).
            value: String,
            /// Why it was refused.
            reason: &'static str,
        },
        /// The derivation primitive failed. Unreachable for the widths used
        /// here (32-byte legs are far below the HKDF expansion limit); kept so
        /// the API stays fail-closed instead of panicking.
        Derivation {
            /// Underlying failure description.
            reason: String,
        },
        /// The row #107 firewall refused the identity context.
        Separation(FirewallRefusal),
    }

    impl fmt::Display for PseudonymRefusal {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                PseudonymRefusal::BlankMaster => {
                    f.write_str("pseudonym: master IKM is empty")
                }
                PseudonymRefusal::ShortMaster { len } => write!(
                    f,
                    "pseudonym: master IKM is {len} bytes (need >= {MIN_MASTER_LEN})"
                ),
                PseudonymRefusal::InvalidMasterHex { reason } => {
                    write!(f, "pseudonym: invalid master hex ({reason})")
                }
                PseudonymRefusal::BlankPersona => {
                    f.write_str("pseudonym: persona id is empty")
                }
                PseudonymRefusal::BlankSector => {
                    f.write_str("pseudonym: sector label is empty")
                }
                PseudonymRefusal::InvalidSector { value, reason } => {
                    write!(f, "pseudonym: invalid sector label `{value}`: {reason}")
                }
                PseudonymRefusal::Derivation { reason } => {
                    write!(f, "pseudonym: derivation failed: {reason}")
                }
                PseudonymRefusal::Separation(e) => {
                    write!(f, "pseudonym: identity separation refused: {e}")
                }
            }
        }
    }

    impl std::error::Error for PseudonymRefusal {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                PseudonymRefusal::Separation(e) => Some(e),
                _ => None,
            }
        }
    }

    impl From<FirewallRefusal> for PseudonymRefusal {
        fn from(e: FirewallRefusal) -> Self {
            PseudonymRefusal::Separation(e)
        }
    }

    /// A canonical sector (service) label: 1–[`MAX_SECTOR_LEN`] bytes, ASCII,
    /// first and last byte alphanumeric, interior bytes from `[a-z0-9._-]`.
    ///
    /// Non-canonical labels are **refused, not normalized** — `"Banking"` is a
    /// different (and refused) label, never silently folded into `"banking"`.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(try_from = "String")]
    pub struct Sector(String);

    impl Sector {
        /// Validate and wrap a sector label.
        pub fn new(raw: &str) -> Result<Self, PseudonymRefusal> {
            if raw.is_empty() {
                return Err(PseudonymRefusal::BlankSector);
            }
            if raw.len() > MAX_SECTOR_LEN {
                return Err(PseudonymRefusal::InvalidSector {
                    value: raw.to_string(),
                    reason: "sector label is longer than 64 bytes",
                });
            }
            if !raw
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
            {
                return Err(PseudonymRefusal::InvalidSector {
                    value: raw.to_string(),
                    reason: "sector label must be lowercase ASCII [a-z0-9._-]",
                });
            }
            if !raw.as_bytes()[0].is_ascii_alphanumeric()
                || !raw.as_bytes()[raw.len() - 1].is_ascii_alphanumeric()
            {
                return Err(PseudonymRefusal::InvalidSector {
                    value: raw.to_string(),
                    reason: "sector label must start and end with an alphanumeric",
                });
            }
            Ok(Sector(raw.to_string()))
        }

        /// The canonical label.
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl fmt::Display for Sector {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl TryFrom<String> for Sector {
        type Error = PseudonymRefusal;

        /// Deserialization path: validate instead of trusting the payload.
        fn try_from(value: String) -> Result<Self, Self::Error> {
            Sector::new(&value)
        }
    }

    impl TryFrom<&str> for Sector {
        type Error = PseudonymRefusal;

        fn try_from(value: &str) -> Result<Self, Self::Error> {
            Sector::new(value)
        }
    }

    /// One derived pseudonym: the persona it is bound to, its sector, the
    /// **published identifier**, and the **private per-service key leg**.
    ///
    /// Deliberately **not** `Serialize` and not `Deserialize`: the private leg
    /// must never reach a file or the wire. Publish
    /// [`Self::publication`] instead.
    #[derive(Clone, PartialEq, Eq)]
    pub struct SectorPseudonym {
        persona: String,
        sector: Sector,
        id: String,
        key: Zeroizing<[u8; 32]>,
    }

    impl SectorPseudonym {
        /// The persona this pseudonym is bound to (local knowledge — never part
        /// of [`Self::publication`]).
        pub fn persona_id(&self) -> &str {
            &self.persona
        }

        /// The sector this pseudonym is valid in.
        pub fn sector(&self) -> &Sector {
            &self.sector
        }

        /// The published identifier (`tp1_` + lowercase hex of the id leg).
        pub fn id(&self) -> &str {
            &self.id
        }

        /// The private per-service key leg (32 bytes, zeroized on drop) — the
        /// part a service may use as this persona's service-specific secret.
        pub fn service_key(&self) -> &[u8] {
            &self.key[..]
        }

        /// The publication-safe projection: `(sector, id)` only.
        pub fn publication(&self) -> PseudonymPublication {
            PseudonymPublication {
                sector: self.sector.clone(),
                id: self.id.clone(),
            }
        }

        /// True iff this pseudonym was derived for `persona_id` in `sector`.
        pub fn matches(&self, persona_id: &str, sector: &str) -> bool {
            self.persona == persona_id && self.sector.as_str() == sector
        }

        /// Recompute and compare — confirms the binding without any stored
        /// state. `false` on any mismatch (persona, sector, or master).
        pub fn verify(&self, master: &PseudonymMaster, persona_id: &str, sector: &str) -> bool {
            derive_pair(master, persona_id, sector)
                .map(|(id, _key)| id == self.id)
                .unwrap_or(false)
        }
    }

    impl fmt::Debug for SectorPseudonym {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("SectorPseudonym")
                .field("persona", &self.persona)
                .field("sector", &self.sector.as_str())
                .field("id", &self.id)
                .field("key", &"<redacted>")
                .finish()
        }
    }

    impl fmt::Display for SectorPseudonym {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "pseudonym {} (persona {}, sector {})",
                self.id, self.persona, self.sector
            )
        }
    }

    /// What may be published to (or handed over by) a service: the sector and
    /// the pseudonymous identifier. No persona id, no master, no private leg —
    /// the global identifier stays local.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PseudonymPublication {
        /// The sector the identifier is valid in.
        pub sector: Sector,
        /// The pseudonymous identifier (`tp1_` + lowercase hex).
        pub id: String,
    }

    /// The per-persona master secret (the HKDF input key material).
    ///
    /// Deliberately not `Serialize`; zeroized on drop; redacted in `Debug`;
    /// no method returns the raw bytes (only derivation uses them).
    pub struct PseudonymMaster {
        ikm: Zeroizing<Vec<u8>>,
    }

    impl PseudonymMaster {
        /// Wrap a caller-supplied 32-byte master.
        pub fn from_bytes(bytes: [u8; 32]) -> Self {
            PseudonymMaster {
                ikm: Zeroizing::new(bytes.to_vec()),
            }
        }

        /// Wrap caller-supplied IKM (at least [`MIN_MASTER_LEN`] bytes).
        pub fn from_slice(ikm: &[u8]) -> Result<Self, PseudonymRefusal> {
            if ikm.is_empty() {
                return Err(PseudonymRefusal::BlankMaster);
            }
            if ikm.len() < MIN_MASTER_LEN {
                return Err(PseudonymRefusal::ShortMaster { len: ikm.len() });
            }
            Ok(PseudonymMaster {
                ikm: Zeroizing::new(ikm.to_vec()),
            })
        }

        /// Parse a hex master (even length, ≥ 2 × [`MIN_MASTER_LEN`] chars).
        /// A malformed encoding is refused without echoing the input.
        pub fn from_hex(hex: &str) -> Result<Self, PseudonymRefusal> {
            fn nibble(b: u8) -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                }
            }
            let raw = hex.as_bytes();
            if raw.len() % 2 != 0 {
                return Err(PseudonymRefusal::InvalidMasterHex {
                    reason: "odd-length hex",
                });
            }
            let mut bytes = Zeroizing::new(Vec::with_capacity(raw.len() / 2));
            for chunk in raw.chunks_exact(2) {
                match (nibble(chunk[0]), nibble(chunk[1])) {
                    (Some(hi), Some(lo)) => bytes.push((hi << 4) | lo),
                    _ => {
                        return Err(PseudonymRefusal::InvalidMasterHex {
                            reason: "non-hex character",
                        })
                    }
                }
            }
            Self::from_slice(&bytes)
        }

        /// Derive a **per-persona** master from a vault-wide secret and an open
        /// identity context:
        /// `HKDF-SHA256(salt = DOMAIN, ikm = vault_master,
        /// info = "persona-master" ‖ persona id ‖ compartment)`.
        ///
        /// One vault secret then serves every persona while no two personas
        /// share a master; the compartment (row #107 material) is part of the
        /// binding, so re-registering a persona with a different compartment
        /// yields a different master.
        pub fn from_vault_master(
            vault_master: &[u8],
            scope: &PersonaScope,
        ) -> Result<Self, PseudonymRefusal> {
            if scope.id().is_empty() {
                return Err(PseudonymRefusal::BlankPersona);
            }
            if vault_master.is_empty() {
                return Err(PseudonymRefusal::BlankMaster);
            }
            if vault_master.len() < MIN_MASTER_LEN {
                return Err(PseudonymRefusal::ShortMaster {
                    len: vault_master.len(),
                });
            }
            let info = context_info(
                LEG_PERSONA_MASTER,
                &[scope.id().as_bytes(), scope.compartment().as_bytes()],
            );
            let okm = tallow_crypto::kdf::hkdf::derive(
                PSEUDONYM_DOMAIN.as_bytes(),
                vault_master,
                &info,
                MIN_MASTER_LEN,
            )
            .map_err(|e| PseudonymRefusal::Derivation {
                reason: e.to_string(),
            })?;
            Self::from_slice(&okm)
        }
    }

    impl fmt::Debug for PseudonymMaster {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("PseudonymMaster(<redacted>)")
        }
    }

    /// The derivation core: one HKDF extract over the master, one expand per
    /// leg. Returns `(published identifier, private key leg)`.
    fn derive_pair(
        master: &PseudonymMaster,
        persona_id: &str,
        sector: &str,
    ) -> Result<(String, Zeroizing<[u8; 32]>), PseudonymRefusal> {
        if persona_id.is_empty() {
            return Err(PseudonymRefusal::BlankPersona);
        }
        let sector = Sector::new(sector)?;
        let parts: [&[u8]; 2] = [persona_id.as_bytes(), sector.as_str().as_bytes()];
        let info_id = context_info(LEG_ID, &parts);
        let info_key = context_info(LEG_KEY, &parts);
        let mut legs = tallow_crypto::kdf::hkdf::derive_multiple(
            PSEUDONYM_DOMAIN.as_bytes(),
            &master.ikm[..],
            &[(info_id.as_slice(), 32), (info_key.as_slice(), 32)],
        )
        .map_err(|e| PseudonymRefusal::Derivation {
            reason: e.to_string(),
        })?
        .into_iter();

        let id_leg = legs.next().ok_or_else(|| PseudonymRefusal::Derivation {
            reason: "missing id leg".to_string(),
        })?;
        let key_leg = legs.next().ok_or_else(|| PseudonymRefusal::Derivation {
            reason: "missing key leg".to_string(),
        })?;
        if key_leg.len() != 32 {
            return Err(PseudonymRefusal::Derivation {
                reason: format!("unexpected key-leg width {}", key_leg.len()),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_leg);

        Ok((
            format!("{PSEUDONYM_ID_PREFIX}{}", to_hex(&id_leg[..])),
            Zeroizing::new(key),
        ))
    }

    /// The derivation engine: holds one persona's master and derives its
    /// per-sector pseudonyms.
    ///
    /// [`Self::derive`] is the firewall-gated doorway — it takes a
    /// [`firewall::PersonaScope`], so a pseudonym can only be derived for an
    /// identity whose material passed the row #107 separation checks at open
    /// time. [`Self::derive_checked`] additionally re-validates the scope
    /// against the firewall, closing the stale-scope trap (burn, reload, or
    /// custody change after open).
    pub struct PersonaPseudonyms {
        master: PseudonymMaster,
    }

    impl PersonaPseudonyms {
        /// Build the engine over a per-persona master.
        pub fn new(master: PseudonymMaster) -> Self {
            PersonaPseudonyms { master }
        }

        /// Derive `sector`'s pseudonym for the scope's persona.
        ///
        /// The persona context comes from the scope alone — there is no
        /// parameter that could name a different identity, so cross-persona
        /// joins are unrepresentable in this API.
        pub fn derive(
            &self,
            scope: &PersonaScope,
            sector: &str,
        ) -> Result<SectorPseudonym, PseudonymRefusal> {
            let (id, key) = derive_pair(&self.master, scope.id(), sector)?;
            Ok(SectorPseudonym {
                persona: scope.id().to_string(),
                sector: Sector::new(sector)?,
                id,
                key,
            })
        }

        /// [`Self::derive`] after re-checking `scope` against `firewall`
        /// ([`firewall::PersonaFirewall::check_scope`]): a burned identity, a
        /// scope whose material is no longer the registry's, or a separation
        /// finding refuses instead of deriving.
        pub fn derive_checked(
            &self,
            firewall: &PersonaFirewall<'_>,
            scope: &PersonaScope,
            sector: &str,
        ) -> Result<SectorPseudonym, PseudonymRefusal> {
            firewall.check_scope(scope)?;
            self.derive(scope, sector)
        }

        /// Recompute the scope persona's pseudonym for `publication.sector` and
        /// confirm it matches `publication.id` — the binding check for a holder
        /// of the master. Needs no global identifier: the publication carries
        /// none.
        pub fn verify_publication(
            &self,
            scope: &PersonaScope,
            publication: &PseudonymPublication,
        ) -> Result<bool, PseudonymRefusal> {
            let fresh = self.derive(scope, publication.sector.as_str())?;
            Ok(fresh.id == publication.id)
        }
    }

    #[cfg(test)]
    mod pseudonym_tests {
        use super::super::{seal, to_hex, unseal};
        use super::*;
        use crate::persona::{
            BurnMethod, CoverClass, Legend, Persona, PersonaRegistry, QuarantineMode,
        };

        fn persona(id: &str, n: u32) -> Persona {
            Persona::new(
                id,
                CoverClass::new("researcher"),
                format!("ctrl-{n}"),
                Legend::new(
                    "backstory",
                    format!("cover-{n}@example.invalid"),
                    format!("run-{n}"),
                ),
                format!("seed-{n}"),
                1_700_000_000_000,
            )
        }

        fn registry(ids: &[(&str, u32)]) -> PersonaRegistry {
            let mut reg = PersonaRegistry::new();
            for (id, n) in ids {
                reg.register(persona(id, *n)).unwrap();
            }
            reg
        }

        fn master(pattern: u8) -> PseudonymMaster {
            PseudonymMaster::from_bytes([pattern; 32])
        }

        #[test]
        fn sector_pseudonym_derivation_is_deterministic_across_calls_and_custody_reload() {
            let reg = registry(&[("p-1", 1)]);
            let fw = PersonaFirewall::new(&reg).unwrap();
            let scope = fw.open_scope("p-1").unwrap();
            let engine = PersonaPseudonyms::new(master(0xA1));

            let first = engine.derive(&scope, "banking").unwrap();
            let second = engine.derive(&scope, "banking").unwrap();
            assert_eq!(first.id(), second.id());
            assert_eq!(first.service_key(), second.service_key());
            assert!(first.verify(&master(0xA1), "p-1", "banking"));
            assert!(first.matches("p-1", "banking"));

            // Custody round trip: the derivation is a pure function of
            // (master, persona id, sector) — a reloaded registry re-derives the
            // same identifier through a fresh firewall scope.
            let restored = unseal(&seal(&reg, "pw-k").unwrap(), "pw-k").unwrap();
            let fw2 = PersonaFirewall::new(&restored).unwrap();
            let scope2 = fw2.open_scope("p-1").unwrap();
            let after = engine.derive(&scope2, "banking").unwrap();
            assert_eq!(
                after.id(),
                first.id(),
                "custody reload must not change the derivation"
            );
            assert!(engine
                .verify_publication(&scope2, &first.publication())
                .unwrap());
        }

        #[test]
        fn sector_pseudonyms_are_isolated_per_sector() {
            let reg = registry(&[("p-1", 1)]);
            let fw = PersonaFirewall::new(&reg).unwrap();
            let scope = fw.open_scope("p-1").unwrap();
            let engine = PersonaPseudonyms::new(master(0xB2));

            let banking = engine.derive(&scope, "banking").unwrap();
            let health = engine.derive(&scope, "health").unwrap();

            assert_ne!(banking.id(), health.id());
            assert_ne!(banking.service_key(), health.service_key());
            // No shared material between the two publications beyond the format
            // prefix: neither hex body is contained in the other.
            let a = &banking.id()[PSEUDONYM_ID_PREFIX.len()..];
            let b = &health.id()[PSEUDONYM_ID_PREFIX.len()..];
            assert!(!a.contains(b) && !b.contains(a));

            // An identifier from one sector must not verify as another
            // sector's pseudonym for the same persona.
            let mut crossed = banking.publication();
            crossed.sector = health.sector().clone();
            assert!(
                !engine.verify_publication(&scope, &crossed).unwrap(),
                "one sector's id must not verify in another sector"
            );
            assert!(engine
                .verify_publication(&scope, &banking.publication())
                .unwrap());
            assert!(banking.matches("p-1", "banking"));
            assert!(!banking.matches("p-1", "health"));
        }

        #[test]
        fn sector_pseudonyms_are_isolated_per_persona() {
            let reg = registry(&[("p-1", 1), ("p-2", 2)]);
            let fw = PersonaFirewall::new(&reg).unwrap();
            let s1 = fw.open_scope("p-1").unwrap();
            let s2 = fw.open_scope("p-2").unwrap();
            let engine = PersonaPseudonyms::new(master(0xC3));

            let a = engine.derive(&s1, "banking").unwrap();
            let b = engine.derive(&s2, "banking").unwrap();

            assert_ne!(a.id(), b.id(), "same master+sector, different personas");
            assert_ne!(a.service_key(), b.service_key());
            assert!(!engine.verify_publication(&s2, &a.publication()).unwrap());
            assert!(engine.verify_publication(&s1, &a.publication()).unwrap());
            assert!(engine.verify_publication(&s2, &b.publication()).unwrap());
        }

        #[test]
        fn published_identifier_never_carries_master_or_private_leg() {
            let sentinel = 0xABu8;
            let reg = registry(&[("p-1", 1)]);
            let fw = PersonaFirewall::new(&reg).unwrap();
            let scope = fw.open_scope("p-1").unwrap();
            let engine = PersonaPseudonyms::new(master(sentinel));
            let p = engine.derive(&scope, "banking").unwrap();

            let master_hex = "ab".repeat(32);
            assert!(!p.id().contains(&master_hex));
            assert!(!format!("{p:?}").to_lowercase().contains("abababab"));
            assert!(!format!("{p}").to_lowercase().contains("abababab"));
            assert!(format!("{p:?}").contains("<redacted>"));
            assert!(!format!("{p:?}").contains(&to_hex(p.service_key())));

            // Publication JSON: exactly (sector, id) — no persona id, no
            // master, no private leg.
            let json = serde_json::to_string(&p.publication()).unwrap();
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            let mut keys: Vec<String> = v
                .as_object()
                .unwrap()
                .keys()
                .map(|k| k.to_string())
                .collect();
            keys.sort();
            assert_eq!(keys, vec!["id".to_string(), "sector".to_string()]);
            assert!(!json.contains("p-1"));
            assert!(!json.contains(&master_hex));
            assert!(!json.contains("seed-1"));

            // The private leg is neither the master nor the public id body.
            assert_ne!(p.service_key(), &[sentinel; 32]);
            assert_ne!(to_hex(p.service_key()), p.id()[PSEUDONYM_ID_PREFIX.len()..]);
        }

        #[test]
        fn master_debug_and_failure_paths_are_redacted() {
            let m = master(0xCD);
            let dbg = format!("{m:?}");
            assert!(dbg.contains("<redacted>"));
            assert!(!dbg.to_lowercase().contains("cdcd"));

            assert!(matches!(
                PseudonymMaster::from_slice(&[]),
                Err(PseudonymRefusal::BlankMaster)
            ));
            assert!(matches!(
                PseudonymMaster::from_slice(&[0u8; 31]),
                Err(PseudonymRefusal::ShortMaster { len: 31 })
            ));

            // Hex refusals never echo the input.
            let bad = format!("{}zx", "ab".repeat(32));
            let err = PseudonymMaster::from_hex(&bad).unwrap_err();
            let shown = err.to_string();
            assert!(shown.contains("non-hex"));
            assert!(!shown.contains(&bad));
            assert!(!shown.contains("abab"));
            assert!(matches!(
                PseudonymMaster::from_hex("abc"),
                Err(PseudonymRefusal::InvalidMasterHex {
                    reason: "odd-length hex"
                })
            ));
        }

        #[test]
        fn binding_verification_recomputes_and_refuses_foreign_pairs() {
            let reg = registry(&[("p-1", 1), ("p-2", 2)]);
            let fw = PersonaFirewall::new(&reg).unwrap();
            let s1 = fw.open_scope("p-1").unwrap();
            let s2 = fw.open_scope("p-2").unwrap();
            let engine = PersonaPseudonyms::new(master(0x11));
            let p = engine.derive(&s1, "gov").unwrap();

            assert!(p.verify(&master(0x11), "p-1", "gov"));
            assert!(!p.verify(&master(0x12), "p-1", "gov"), "wrong master");
            assert!(!p.verify(&master(0x11), "p-2", "gov"), "wrong persona");
            assert!(!p.verify(&master(0x11), "p-1", "health"), "wrong sector");
            assert_eq!(
                p.publication(),
                engine.derive(&s1, "gov").unwrap().publication()
            );
            assert!(!engine.verify_publication(&s2, &p.publication()).unwrap());
        }

        #[test]
        fn firewall_gates_derivation_and_closes_the_stale_scope_trap() {
            let mut reg = registry(&[("p-1", 1), ("p-2", 2)]);
            let fw = PersonaFirewall::new(&reg).unwrap();
            let stale = fw.open_scope("p-2").unwrap();
            let engine = PersonaPseudonyms::new(master(0x22));
            assert!(engine.derive(&stale, "banking").is_ok());
            drop(fw);

            reg.burn(
                "p-2",
                1_800_000_000_000,
                BurnMethod::RevokeAndQuarantine,
                QuarantineMode::Quarantine,
            )
            .unwrap();

            // Re-opened: a burned identity has no scope at all.
            let fw_after = PersonaFirewall::new(&reg).unwrap();
            assert!(matches!(
                fw_after.open_scope("p-2"),
                Err(FirewallRefusal::Registry(_))
            ));
            // Stale scope: only the checked doorway re-validates, and refuses.
            assert!(matches!(
                engine.derive_checked(&fw_after, &stale, "banking"),
                Err(PseudonymRefusal::Separation(_))
            ));
            // Untouched persona keeps deriving through the checked doorway.
            let live = fw_after.open_scope("p-1").unwrap();
            assert!(engine.derive_checked(&fw_after, &live, "banking").is_ok());
        }

        #[test]
        fn sector_labels_are_validated_not_normalized() {
            let reg = registry(&[("p-1", 1)]);
            let fw = PersonaFirewall::new(&reg).unwrap();
            let scope = fw.open_scope("p-1").unwrap();
            let engine = PersonaPseudonyms::new(master(0x44));

            assert!(matches!(Sector::new(""), Err(PseudonymRefusal::BlankSector)));
            for bad in ["Banking", "bank ing", "bank/ing", "-bank", "bank-", "bänking"] {
                assert!(
                    Sector::new(bad).is_err(),
                    "sector label {bad:?} must be refused"
                );
            }
            let long = "a".repeat(MAX_SECTOR_LEN + 1);
            assert!(matches!(
                Sector::new(&long),
                Err(PseudonymRefusal::InvalidSector { .. })
            ));
            assert!(matches!(
                engine.derive(&scope, "Banking"),
                Err(PseudonymRefusal::InvalidSector { .. })
            ));

            let ok = Sector::new("banking").unwrap();
            assert_eq!(ok.as_str(), "banking");
            assert_eq!(Sector::new("at.gov-1_x").unwrap().as_str(), "at.gov-1_x");

            // Serde validates on the way in (try_from), round-trips as a string.
            let json = serde_json::to_string(&ok).unwrap();
            assert_eq!(json, "\"banking\"");
            let back: Sector = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ok);
            assert!(serde_json::from_str::<Sector>("\"Banking\"").is_err());
        }

        #[test]
        fn master_sources_agree_and_vault_derivation_binds_persona_context() {
            let reg = registry(&[("p-1", 1), ("p-2", 2)]);
            let fw = PersonaFirewall::new(&reg).unwrap();
            let s1 = fw.open_scope("p-1").unwrap();
            let s2 = fw.open_scope("p-2").unwrap();

            let body = [0x5Au8; 32];
            let e_hex = PersonaPseudonyms::new(PseudonymMaster::from_hex(&to_hex(&body)).unwrap());
            let e_slice = PersonaPseudonyms::new(PseudonymMaster::from_slice(&body).unwrap());
            let e_bytes = PersonaPseudonyms::new(PseudonymMaster::from_bytes(body));
            assert_eq!(
                e_hex.derive(&s1, "banking").unwrap().id(),
                e_slice.derive(&s1, "banking").unwrap().id()
            );
            assert_eq!(
                e_hex.derive(&s1, "banking").unwrap().id(),
                e_bytes.derive(&s1, "banking").unwrap().id()
            );

            // Vault-wide secret → per-persona master: deterministic, and
            // distinct per persona (persona id + compartment are in context).
            let vm = [0x33u8; 48];
            let m_a = PseudonymMaster::from_vault_master(&vm, &s1).unwrap();
            let m_a2 = PseudonymMaster::from_vault_master(&vm, &s1).unwrap();
            let m_b = PseudonymMaster::from_vault_master(&vm, &s2).unwrap();
            let pa = PersonaPseudonyms::new(m_a).derive(&s1, "banking").unwrap();
            let pa2 = PersonaPseudonyms::new(m_a2)
                .derive(&s1, "banking")
                .unwrap();
            let pb = PersonaPseudonyms::new(m_b).derive(&s2, "banking").unwrap();
            assert_eq!(pa.id(), pa2.id());
            assert_ne!(pa.id(), pb.id(), "personas must not share a master");
            assert!(matches!(
                PseudonymMaster::from_vault_master(&[0u8; 8], &s1),
                Err(PseudonymRefusal::ShortMaster { len: 8 })
            ));
        }

        #[test]
        fn refusals_render_without_secrets() {
            let long = "z".repeat(MAX_SECTOR_LEN + 1);
            let shown = PseudonymRefusal::InvalidSector {
                value: long.clone(),
                reason: "sector label is longer than 64 bytes",
            }
            .to_string();
            assert!(shown.contains("invalid sector label"));
            let shown = PseudonymRefusal::ShortMaster { len: 3 }.to_string();
            assert!(shown.contains("3 bytes"));
            assert!(shown.contains(">= 32"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persona::{BurnMethod, CoverClass, Legend, Persona, QuarantineMode};

    fn persona(id: &str, seed: &str) -> Persona {
        Persona::new(
            id,
            CoverClass::new("researcher"),
            "ctrl-1",
            Legend::new("backstory", "cover@example.invalid", "run-1"),
            seed,
            1_700_000_000_000,
        )
    }

    #[test]
    fn sealed_registry_round_trips_and_keeps_burned_ids_burned() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();
        reg.register(persona("p-2", "seed-2")).unwrap();
        reg.burn(
            "p-2",
            1_800_000_000_000,
            BurnMethod::RevokeAndQuarantine,
            QuarantineMode::Quarantine,
        )
        .unwrap();

        let sealed = seal(&reg, "pw-9").unwrap();
        let restored = unseal(&sealed, "pw-9").unwrap();

        assert!(restored.get("p-1").is_some());
        assert!(restored.is_burned("p-2"), "burned set survives custody");
        assert!(restored.assert_reusable("p-2").is_err());

        // The open-bundle flow reads through the restored registry and keeps
        // the never-reuse gate.
        let bundle = restored.open_bundle("p-1").unwrap();
        assert_eq!(bundle.id, "p-1");
        assert!(restored.open_bundle("p-2").is_err());
    }

    #[test]
    fn wrong_password_is_refused() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();
        let sealed = seal(&reg, "right").unwrap();
        assert!(unseal(&sealed, "wrong").is_err());
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personas.json");
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();
        let sealed = seal(&reg, "pw").unwrap();
        save(&path, &sealed).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, sealed.version);
        let restored = unseal(&loaded, "pw").unwrap();
        assert!(restored.get("p-1").is_some());
    }
}
