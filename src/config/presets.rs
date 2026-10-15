//! KB-7 hardening preset tables (row #66; report §7.2.3 profiles, §7.5.1
//! secure defaults, §7.6.3 operator-gate).
//!
//! A *preset* is deployable data, not prose: for every profile in
//! [`Profile::ALL`] this module records the stance, the tier ceiling, and the
//! **floors** the profile pins for kernel keys. Floors are tighten-only
//! (report §7.2.3: "profiles tighten or set defaults; they can never loosen
//! below a locked/floor value"), so:
//!
//! - [`FloorKind::Required`] — the profile *requires* this value; a looser
//!   configured value is drift ([`violations`]), and [`apply_floors`] would fix
//!   it (never in the other direction).
//! - [`FloorKind::GatedDefault`] — the preset sets this default; a looser
//!   configured value is an operator-gated relaxation (report §7.6.3): it is
//!   reported by lint, never applied automatically, never refused here.
//!
//! The KB-1 key subset this module can *evaluate* today is deliberately small
//! (the only ordered kernel key is `telemetry`, where `false` is the secure
//! end; [`looseness`] is the one place the lattice is registered). Floors the
//! subset cannot express yet are recorded in [`ProfilePosture::pending_floors`]
//! as `[target-only]` strings naming the report source — later KB tasks extend
//! the table instead of re-deriving the posture. Switching to a *less*
//! restrictive profile is an operator-authorization event (§7.6.3.5) and is
//! **not** a CLI surface yet: this batch ships the tables + read-only scoring.

use crate::config::schema::{Config, Profile};

// ── Preset values ────────────────────────────────────────────────────────────

/// A value a preset pins for a key. Typed so the table stays schema-checked
/// (tests pin every floor key against [`crate::config::schema::key_class`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetValue {
    /// Boolean key value.
    Bool(bool),
    /// Integer key value.
    Integer(i64),
    /// Enum-word key value (rendered quoted).
    Word(&'static str),
}

impl PresetValue {
    /// Human kind word for diagnostics.
    pub fn kind(self) -> &'static str {
        match self {
            PresetValue::Bool(_) => "boolean",
            PresetValue::Integer(_) => "integer",
            PresetValue::Word(_) => "word",
        }
    }

    /// TOML-ish rendering (what the operator would write in the artifact).
    pub fn render(self) -> String {
        match self {
            PresetValue::Bool(b) => b.to_string(),
            PresetValue::Integer(n) => n.to_string(),
            PresetValue::Word(w) => format!("\"{w}\""),
        }
    }
}

/// How a floor binds (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorKind {
    /// Tightening: the profile requires this value; looser = drift.
    Required,
    /// Preset default: looser = operator-gated relaxation (§7.6.3), reported
    /// but never applied automatically.
    GatedDefault,
}

impl FloorKind {
    /// Stable lowercase word (JSON/text surfaces).
    pub fn word(self) -> &'static str {
        match self {
            FloorKind::Required => "required",
            FloorKind::GatedDefault => "gated-default",
        }
    }
}

/// One floor: the secure end a profile pins for a kernel key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Floor {
    /// Dotted kernel key path.
    pub key: &'static str,
    /// The tightening end of the key's value lattice.
    pub secure: PresetValue,
    /// How the floor binds.
    pub kind: FloorKind,
    /// One-line rationale (report §).
    pub rationale: &'static str,
}

/// One profile's deployable posture row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfilePosture {
    /// The profile this row is about.
    pub profile: Profile,
    /// Stance from report §7.2.3 (quoted, not paraphrased into hype).
    pub stance: &'static str,
    /// Tier posture word from §7.2.3 (`operator`, `vault_admin`, `n/a`).
    pub tier_ceiling: &'static str,
    /// Floors this profile pins **and** the engine can evaluate today.
    pub floors: &'static [Floor],
    /// Floors §7.2.3/§7.5 states for this profile that the KB-1 key subset
    /// cannot express yet — recorded so later KB tasks extend, not re-derive.
    pub pending_floors: &'static [&'static str],
}

/// Telemetry floor shared by every profile that *requires* secure defaults
/// (§7.5.1: "telemetry = false"). `performance` overrides this with a
/// [`FloorKind::GatedDefault`] (its stance allows an explicit opt-in).
const TELEMETRY_REQUIRED: Floor = Floor {
    key: "telemetry",
    secure: PresetValue::Bool(false),
    kind: FloorKind::Required,
    rationale: "§7.5.1 secure default: telemetry is an explicit opt-in, off by default",
};

/// All eight profile postures, in [`Profile::ALL`] canonical order.
pub const PROFILE_POSTURES: &[ProfilePosture] = &[
    ProfilePosture {
        profile: Profile::Balanced,
        stance: "current defaults: Tor fail-closed, telemetry off, typed config v1",
        tier_ceiling: "operator",
        floors: &[TELEMETRY_REQUIRED],
        pending_floors: &[],
    },
    ProfilePosture {
        profile: Profile::Privacy,
        stance: "metadata-min on, logs 0600+redacted, cloud-LLM backends disabled, DNS via egress",
        tier_ceiling: "operator",
        floors: &[TELEMETRY_REQUIRED],
        pending_floors: &[
            "[target-only] `[ai] cloud = \"deny\"` (cloud-LLM backends; §7.2.3 privacy stance)",
            "[target-only] logs 0600 + redaction policy hooks (§7.5.1; audit-07 F-10)",
            "[target-only] DNS via egress (§7.2.3)",
        ],
    },
    ProfilePosture {
        profile: Profile::MaximumSecurity,
        stance: "pqc_required, signature-required everywhere, no direct egress, sandbox floors mandatory, no session overrides for security keys, two-person ops",
        tier_ceiling: "vault_admin",
        floors: &[TELEMETRY_REQUIRED],
        pending_floors: &[
            "[target-only] `crypto_policy_pass` policy = pqc_required (§7.2.3)",
            "[target-only] `require_signature` for remote registries (§7.5.1)",
            "[target-only] `TALLOW_ALLOW_DIRECT` forbidden (§7.2.3)",
            "[target-only] sandbox floors mandatory; no session overrides for security keys (§7.2.3)",
            "[target-only] two-person ops for vault-class reach (§7.6.3, TIER_GATE §3.2)",
        ],
    },
    ProfilePosture {
        profile: Profile::Performance,
        stance: "latency-friendly egress timeouts, telemetry opt-in possible but explicit operator-gated, no reduction of crypto floors",
        tier_ceiling: "operator",
        floors: &[Floor {
            key: "telemetry",
            secure: PresetValue::Bool(false),
            kind: FloorKind::GatedDefault,
            rationale: "§7.2.3 performance stance: telemetry opt-in is possible but ⚠operator-gated (§7.6.3)",
        }],
        pending_floors: &[
            "[target-only] latency-friendly egress timeouts (§7.2.3)",
            "[target-only] no reduction of crypto floors (§7.2.3)",
        ],
    },
    ProfilePosture {
        profile: Profile::Developer,
        stance: "hot-reload allowed with pass re-run, verbose diagnostics, direct egress only with explicit lock-free dev key",
        tier_ceiling: "operator",
        floors: &[TELEMETRY_REQUIRED],
        pending_floors: &[
            "[target-only] hot-reload gated (`off`|`gated`, pass re-run required; §7.5.4)",
            "[target-only] verbose diagnostics (§7.2.3)",
            "[target-only] direct egress only behind an explicit developer key ⚠OP (§7.6.3.2)",
        ],
    },
    ProfilePosture {
        profile: Profile::Server,
        stance: "headless, hardened systemd unit emission, log rotation + 0600, daemon token via vault ref",
        tier_ceiling: "operator",
        floors: &[TELEMETRY_REQUIRED],
        pending_floors: &[
            "[target-only] hardened systemd unit emission (§7.5.4; audit-04 F-6)",
            "[target-only] log rotation + 0600 (§7.2.3)",
            "[target-only] daemon token via `vault://` reference (§7.2.3; KB-4)",
        ],
    },
    ProfilePosture {
        profile: Profile::Mobile,
        stance: "speculative device class — no mobile target exists in-tree; schema placeholders only",
        tier_ceiling: "n/a",
        floors: &[TELEMETRY_REQUIRED],
        pending_floors: &[
            "[target-only] speculative: define schema placeholders, do not implement (§7.2.3)",
        ],
    },
    ProfilePosture {
        profile: Profile::Swarm,
        stance: "signed sync defaults, per-peer grants, no secret values synced",
        tier_ceiling: "operator",
        floors: &[TELEMETRY_REQUIRED],
        pending_floors: &[
            "[target-only] signed sync defaults + per-peer grants (§7.8)",
            "[target-only] no secret values synced, references re-resolve per device (§7.8)",
        ],
    },
];

/// Every posture row (table order = [`Profile::ALL`]).
pub fn postures() -> &'static [ProfilePosture] {
    PROFILE_POSTURES
}

/// The posture row for one profile, if the table covers it (it always should —
/// pinned by tests; `None` instead of a panic keeps the lib path panic-free).
pub fn posture_for(profile: Profile) -> Option<&'static ProfilePosture> {
    PROFILE_POSTURES.iter().find(|p| p.profile == profile)
}

// ── Floor evaluation (tighten-only lattice) ──────────────────────────────────

/// Rank a value by *looseness* for keys whose lattice is registered.
///
/// Today the only ordered kernel key is `telemetry` (a boolean, `false` =
/// secure = 0). Non-boolean values return `None`: the KB-1 subset has no
/// ordered integer/word key, so floors about them are recorded as
/// `pending_floors` rather than compared. Register new lattices here — the
/// floor table itself does not change.
fn looseness(value: PresetValue) -> Option<u8> {
    match value {
        PresetValue::Bool(false) => Some(0),
        PresetValue::Bool(true) => Some(1),
        PresetValue::Integer(_) | PresetValue::Word(_) => None,
    }
}

/// Outcome of checking one floor against a config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorCheck {
    /// Configured value is at the floor or tighter (a tightening is never a
    /// finding — the ratchet only turns one way).
    Met,
    /// Configured value is looser than the floor.
    Looser,
    /// The engine has no lattice for this key yet (recorded, not evaluated).
    NotEvaluable,
}

/// The configured value a floor is about, when the KB-1 subset exposes it.
fn current_value(floor: &Floor, cfg: &Config) -> Option<PresetValue> {
    match floor.key {
        "telemetry" => Some(PresetValue::Bool(cfg.telemetry)),
        _ => None,
    }
}

/// Check one floor against a config.
pub fn check_floor(floor: &Floor, cfg: &Config) -> FloorCheck {
    let Some(current) = current_value(floor, cfg) else {
        return FloorCheck::NotEvaluable;
    };
    match (looseness(current), looseness(floor.secure)) {
        (Some(c), Some(f)) if c > f => FloorCheck::Looser,
        (Some(_), Some(_)) => FloorCheck::Met,
        _ => FloorCheck::NotEvaluable,
    }
}

/// A floor the configured values do not meet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetViolation {
    /// The profile whose floor this is.
    pub profile: Profile,
    /// The floor.
    pub key: &'static str,
    /// How the floor binds (`Required` = drift, `GatedDefault` = gated
    /// relaxation).
    pub kind: FloorKind,
    /// Configured value.
    pub found: PresetValue,
    /// The pinned secure value.
    pub secure: PresetValue,
    /// Rationale carried through from the table.
    pub rationale: &'static str,
    /// Human message (never contains secret material — these keys are scalars).
    pub message: String,
}

/// Every floor of `profile` the config does not meet, deterministic order.
///
/// `Required` floors are drift; `GatedDefault` floors are operator-gated
/// relaxations (§7.6.3) — the caller decides how loud each one is.
pub fn violations(profile: Profile, cfg: &Config) -> Vec<PresetViolation> {
    let Some(posture) = posture_for(profile) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for floor in posture.floors {
        if check_floor(floor, cfg) != FloorCheck::Looser {
            continue;
        }
        let found = current_value(floor, cfg).unwrap_or(floor.secure);
        let kind_word = match floor.kind {
            FloorKind::Required => "required floor",
            FloorKind::GatedDefault => "gated-default floor",
        };
        out.push(PresetViolation {
            profile,
            key: floor.key,
            kind: floor.kind,
            found,
            secure: floor.secure,
            rationale: floor.rationale,
            message: format!(
                "profile `{}` {kind_word} `{} = {}` is violated: configured {} is looser — {}",
                profile.word(),
                floor.key,
                floor.secure.render(),
                found.render(),
                floor.rationale
            ),
        });
    }
    out
}

/// A floor application performed by [`apply_floors`] — always a tightening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFloor {
    /// Key that was tightened.
    pub key: &'static str,
    /// Value before.
    pub from: PresetValue,
    /// Value after (the floor's secure value).
    pub to: PresetValue,
}

/// Apply a profile's floors to a config, **tightening only** (report §7.2.3).
///
/// A floor is applied when the configured value is strictly looser than the
/// floor; values already at/tighter than the floor are left untouched, and a
/// floor that would loosen is skipped (impossible for a well-formed table —
/// pinned by tests). Returns the applied changes, in table order.
///
/// Note: this batch ships the engine and its tests; the CLI surface that calls
/// it (`config preset apply`) stays gated behind the operator-authorization
/// boundary (§7.6.3) — switching profiles is not a read-only operation.
pub fn apply_floors(profile: Profile, cfg: &mut Config) -> Vec<AppliedFloor> {
    let mut applied = Vec::new();
    let Some(posture) = posture_for(profile) else {
        return applied;
    };
    for floor in posture.floors {
        if check_floor(floor, cfg) != FloorCheck::Looser {
            continue;
        }
        match (floor.key, floor.secure) {
            ("telemetry", PresetValue::Bool(false)) => {
                if cfg.telemetry {
                    cfg.telemetry = false;
                    applied.push(AppliedFloor {
                        key: "telemetry",
                        from: PresetValue::Bool(true),
                        to: PresetValue::Bool(false),
                    });
                }
            }
            // Any other key: the lattice exists but the write path is not
            // registered yet — skip rather than guess (extend with the key).
            _ => {}
        }
    }
    applied
}

// ── Rendering (CLI surfaces) ─────────────────────────────────────────────────

/// Human-readable table of every posture (the "deployable tables, not prose"
/// artifact from R-12).
pub fn render_text() -> String {
    let mut out = String::new();
    out.push_str("tallow config presets — hardening profile floors (tighten-only; report §7.2.3)\n");
    for posture in PROFILE_POSTURES {
        out.push_str(&format!(
            "\n  {}  (tier ceiling: {})\n    stance: {}\n",
            posture.profile.word(),
            posture.tier_ceiling,
            posture.stance
        ));
        for floor in posture.floors {
            out.push_str(&format!(
                "    floor: {} = {} [{}] — {}\n",
                floor.key,
                floor.secure.render(),
                floor.kind.word(),
                floor.rationale
            ));
        }
        for pending in posture.pending_floors {
            out.push_str(&format!("    pending: {pending}\n"));
        }
    }
    out
}

/// Machine-readable table of every posture (stable field names).
pub fn render_json() -> String {
    let payload = serde_json::json!({
        "table": "hardening-profile-floors",
        "source": "report §7.2.3 / §7.5.1 (row #66)",
        "postures": PROFILE_POSTURES
            .iter()
            .map(|p| serde_json::json!({
                "profile": p.profile.word(),
                "stance": p.stance,
                "tier_ceiling": p.tier_ceiling,
                "floors": p.floors
                    .iter()
                    .map(|f| serde_json::json!({
                        "key": f.key,
                        "secure": f.secure.render(),
                        "kind": f.kind.word(),
                        "rationale": f.rationale,
                    }))
                    .collect::<Vec<_>>(),
                "pending_floors": p.pending_floors,
            }))
            .collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&payload)
        .unwrap_or_else(|e| format!("{{\"error\":\"preset table could not be serialized: {e}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{key_class, OutputFormat, SCHEMA_VERSION};

    #[test]
    fn every_profile_has_a_posture_row() {
        assert_eq!(PROFILE_POSTURES.len(), Profile::ALL.len());
        for profile in Profile::ALL {
            let posture = posture_for(profile).unwrap_or_else(|| panic!("{profile:?}"));
            assert_eq!(posture.profile, profile);
            assert!(!posture.stance.is_empty(), "{profile:?} stance empty");
            assert!(
                !posture.tier_ceiling.is_empty(),
                "{profile:?} tier ceiling empty"
            );
        }
        // No duplicate rows.
        for (i, a) in PROFILE_POSTURES.iter().enumerate() {
            for b in &PROFILE_POSTURES[i + 1..] {
                assert_ne!(a.profile, b.profile, "duplicate posture row");
            }
        }
    }

    #[test]
    fn floor_keys_are_known_kernel_keys() {
        for posture in PROFILE_POSTURES {
            for floor in posture.floors {
                assert!(
                    key_class(floor.key).is_some(),
                    "floor key `{}` is not a known kernel key",
                    floor.key
                );
                assert_eq!(
                    floor.secure.kind(),
                    "boolean",
                    "today's evaluable floors are boolean ({} = {})",
                    floor.key,
                    floor.secure.render()
                );
            }
            for pending in posture.pending_floors {
                assert!(
                    pending.starts_with("[target-only]"),
                    "pending floors must be labelled: {pending}"
                );
            }
        }
    }

    #[test]
    fn required_floor_violation_is_reported_with_rationale() {
        let cfg = Config {
            telemetry: true,
            ..Config::default()
        };
        let found = violations(Profile::Privacy, &cfg);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].key, "telemetry");
        assert_eq!(found[0].kind, FloorKind::Required);
        assert_eq!(found[0].found, PresetValue::Bool(true));
        assert_eq!(found[0].secure, PresetValue::Bool(false));
        assert!(found[0].message.contains("`privacy`"), "{}", found[0].message);
        assert!(found[0].message.contains("telemetry"), "{}", found[0].message);
        assert!(
            found[0].message.contains("§7.5.1"),
            "rationale carried: {}",
            found[0].message
        );
    }

    #[test]
    fn performance_telemetry_is_gated_default_not_required() {
        let cfg = Config {
            telemetry: true,
            ..Config::default()
        };
        let found = violations(Profile::Performance, &cfg);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].kind, FloorKind::GatedDefault, "§7.2.3 stance");
        assert!(
            found[0].message.contains("gated-default"),
            "{}",
            found[0].message
        );
        // The other profiles treat the same state as required-floor drift.
        for profile in Profile::ALL {
            if profile == Profile::Performance {
                continue;
            }
            let found = violations(profile, &cfg);
            assert_eq!(found.len(), 1, "{profile:?}");
            assert_eq!(found[0].kind, FloorKind::Required, "{profile:?}");
        }
    }

    #[test]
    fn secure_or_tighter_values_are_never_violations() {
        let secure = Config::default(); // telemetry = false
        for profile in Profile::ALL {
            assert!(violations(profile, &secure).is_empty(), "{profile:?}");
        }
        // A synthetic floor demanding the *loose* value must not fire on a
        // secure config: tightenings are always allowed (one-way ratchet).
        let loose_floor = Floor {
            key: "telemetry",
            secure: PresetValue::Bool(true),
            kind: FloorKind::Required,
            rationale: "synthetic",
        };
        assert_eq!(check_floor(&loose_floor, &secure), FloorCheck::Met);
        assert_eq!(check_floor(&TELEMETRY_REQUIRED, &secure), FloorCheck::Met);
    }

    #[test]
    fn floor_check_is_not_evaluable_for_unregistered_keys() {
        let floor = Floor {
            key: "format",
            secure: PresetValue::Word("json"),
            kind: FloorKind::Required,
            rationale: "synthetic",
        };
        let cfg = Config::default();
        assert_eq!(check_floor(&floor, &cfg), FloorCheck::NotEvaluable);
        assert!(looseness(PresetValue::Word("json")).is_none());
        assert!(looseness(PresetValue::Integer(1)).is_none());
    }

    #[test]
    fn apply_floors_tightens_only_and_is_idempotent() {
        let mut cfg = Config {
            telemetry: true,
            format: OutputFormat::Json,
            no_color: true,
            ..Config::default()
        };
        let applied = apply_floors(Profile::Privacy, &mut cfg);
        assert_eq!(applied.len(), 1, "{applied:?}");
        assert_eq!(applied[0].key, "telemetry");
        assert_eq!(applied[0].from, PresetValue::Bool(true));
        assert_eq!(applied[0].to, PresetValue::Bool(false));
        assert!(!cfg.telemetry, "floor applied");
        assert_eq!(cfg.format, OutputFormat::Json, "unrelated keys untouched");
        assert!(cfg.no_color, "unrelated keys untouched");
        assert_eq!(cfg.schema_version, SCHEMA_VERSION);
        // Idempotent: a second application is a no-op.
        assert!(apply_floors(Profile::Privacy, &mut cfg).is_empty());
        // Already-secure config: nothing to do.
        let mut secure = Config::default();
        assert!(apply_floors(Profile::Privacy, &mut secure).is_empty());
        assert!(!secure.telemetry);
    }

    #[test]
    fn pending_floors_are_recorded_for_postures_the_subset_cannot_express() {
        let privacy = posture_for(Profile::Privacy).expect("privacy");
        assert!(
            privacy.pending_floors.iter().any(|p| p.contains("cloud")),
            "privacy cloud-LLM floor recorded: {:?}",
            privacy.pending_floors
        );
        let maxsec = posture_for(Profile::MaximumSecurity).expect("maximum-security");
        assert!(
            maxsec.pending_floors.iter().any(|p| p.contains("pqc")),
            "maximum-security pqc floor recorded: {:?}",
            maxsec.pending_floors
        );
        // balanced is the current-defaults profile: no pending floors.
        assert!(posture_for(Profile::Balanced).expect("balanced").pending_floors.is_empty());
        // Every pending string is non-empty and deterministic (no drift).
        for posture in PROFILE_POSTURES {
            for pending in posture.pending_floors {
                assert!(!pending.trim().is_empty());
            }
        }
    }

    #[test]
    fn rendering_is_stable_and_covers_every_profile() {
        let text = render_text();
        for profile in Profile::ALL {
            assert!(text.contains(profile.word()), "text misses {}", profile.word());
        }
        assert!(text.contains("tighten-only"), "{text}");
        let json = render_json();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("preset JSON must parse");
        let rows = parsed["postures"].as_array().expect("postures array");
        assert_eq!(rows.len(), Profile::ALL.len());
        assert_eq!(rows[0]["profile"], "balanced");
        assert!(
            rows.iter().any(|r| r["profile"] == "maximum-security"),
            "kebab-case words in JSON"
        );
    }
}
