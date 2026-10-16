//! Vault access seam (R1 wiring, 2026-09-28) — the single production gate
//! between the vault and the CLI read/release paths.
//!
//! Wraps the pure gates ([`crate::enforcement::enforce_read`],
//! [`crate::access_class::check_export`]) into one composition object so the
//! policy plumbing is unit-testable without a TTY, and so every call site
//! shares the same resolution rules. Fail-closed everywhere: a refusal is an
//! [`EnforceError`] carrying a stable code; CLI callers map it to exit 4
//! (`PERMISSION_VIOLATION`) and journal it (D9: denials → security journal).
//!
//! # Policy source (decision D10 → C2)
//! `[access]` in `tallow.toml`, discovered beside the target vault (or its
//! parent), exactly like the `[crypto] policy` read. Absent table →
//! deny-by-default base policy: `default_class = restricted`, no embargo —
//! and "no class ⇒ no release" holds (Restricted has no export path).
//!
//! ```toml
//! [access]
//! default_class = "restricted"      # open|research|restricted|sealed — never "open"
//! embargo_until_ms = 0              # 0/absent = none; else retention::embargo_active
//! [access.entry_class]              # optional per-entry overrides (id or name)
//! "prod-root-key" = "sealed"
//! ```
//!
//! # Class resolution (decision D2)
//! explicit `entry_class` (by id, then name) → `class:<token>` tags
//! (tightest wins; unknown token ⇒ `sealed`, fail-closed) → `default_class`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::access_class::{AccessClass, Audience};
use crate::enforcement::{
    EnforceError, ExportRequest, ReleaseAuthority, ReleasedExport, enforce_export_with,
    enforce_read,
};
use crate::redaction::{RedactError, RedactMode, RedactionRule, produce_release};
use crate::retention::{Embargo, embargo_active};
use crate::vault::VaultEntry;

/// Reserved tag prefix for per-entry classification (e.g. `class:sealed`).
pub const CLASS_TAG_PREFIX: &str = "class:";

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Parse a class token (`"open"`, `"research"`, `"restricted"`, `"sealed"`).
pub fn class_from_token(t: &str) -> Option<AccessClass> {
    match t.trim().to_ascii_lowercase().as_str() {
        "open" => Some(AccessClass::Open),
        "research" => Some(AccessClass::Research),
        "restricted" => Some(AccessClass::Restricted),
        "sealed" => Some(AccessClass::Sealed),
        _ => None,
    }
}

/// Parse an audience token (`public`, `third-party`, `teammate`, `operator`).
pub fn audience_from_token(t: &str) -> Option<Audience> {
    match t.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "public" => Some(Audience::Public),
        "third-party" | "thirdparty" | "third party" => Some(Audience::ThirdParty),
        "teammate" => Some(Audience::Teammate),
        "operator" => Some(Audience::Operator),
        _ => None,
    }
}

/// Stable code of a refusal (for stderr lines and journal records).
pub fn code_of(e: &EnforceError) -> &str {
    match e {
        EnforceError::ReadDenied(c)
        | EnforceError::ExportDenied(c)
        | EnforceError::Redaction(c) => c,
        EnforceError::MissingReceipt => "redaction.receipt-required",
    }
}

/// Whom the operation is being performed for (D3: CLI reads = Operator).
#[derive(Debug, Clone, Copy)]
pub struct AccessContext {
    pub audience: Audience,
}

impl AccessContext {
    /// The owner at the console — the CLI default for reads.
    pub fn operator() -> Self {
        Self {
            audience: Audience::Operator,
        }
    }
}

/// Resolved `[access]` policy.
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub default_class: AccessClass,
    pub embargo_until_ms: Option<i64>,
    pub entry_class: BTreeMap<String, AccessClass>,
    /// Release redaction rules (`[redaction]` table; empty = identity release).
    pub redaction: Vec<RedactionRule>,
}

impl Default for AccessPolicy {
    /// Deny-by-default base policy (no config table present).
    fn default() -> Self {
        Self {
            default_class: AccessClass::Restricted,
            embargo_until_ms: None,
            entry_class: BTreeMap::new(),
            redaction: Vec::new(),
        }
    }
}

impl AccessPolicy {
    /// Parse `[access]` from an already-parsed toml document.
    pub fn from_table(t: &toml::Table) -> Result<Self, String> {
        let mut p = AccessPolicy::default();
        if let Some(r) = t.get("redaction").and_then(|v| v.as_table()) {
            let mut rules: Vec<RedactionRule> = Vec::new();
            let mut push_fields = |key: &str, mode: RedactMode| -> Result<(), String> {
                if let Some(arr) = r.get(key).and_then(|v| v.as_array()) {
                    for v in arr {
                        let f = v
                            .as_str()
                            .ok_or_else(|| format!("[redaction] {key} entries must be strings"))?;
                        rules.push(RedactionRule {
                            field: f.to_string(),
                            mode: mode.clone(),
                        });
                    }
                }
                Ok(())
            };
            push_fields("remove", RedactMode::Remove)?;
            push_fields("hash", RedactMode::Hash)?;
            if let Some(arr) = r.get("mask").and_then(|v| v.as_array()) {
                for v in arr {
                    let tbl = v
                        .as_table()
                        .ok_or_else(|| "[redaction] mask entries must be tables".to_string())?;
                    let f = tbl
                        .get("field")
                        .and_then(|x| x.as_str())
                        .ok_or_else(|| "[redaction] mask entry needs a field".to_string())?;
                    let kp = tbl
                        .get("keep_prefix")
                        .and_then(|x| x.as_integer())
                        .unwrap_or(0)
                        .max(0) as usize;
                    let ks = tbl
                        .get("keep_suffix")
                        .and_then(|x| x.as_integer())
                        .unwrap_or(0)
                        .max(0) as usize;
                    rules.push(RedactionRule {
                        field: f.to_string(),
                        mode: RedactMode::Mask {
                            keep_prefix: kp,
                            keep_suffix: ks,
                        },
                    });
                }
            }
            p.redaction = rules;
        }
        let Some(a) = t.get("access").and_then(|v| v.as_table()) else {
            return Ok(p);
        };
        if let Some(dc) = a.get("default_class").and_then(|v| v.as_str()) {
            let c = class_from_token(dc)
                .ok_or_else(|| format!("[access] default_class '{dc}' is not a class"))?;
            if c == AccessClass::Open {
                return Err(
                    "[access] default_class = \"open\" is not allowed — classify entries explicitly"
                        .to_string(),
                );
            }
            p.default_class = c;
        }
        if let Some(em) = a.get("embargo_until_ms").and_then(|v| v.as_integer()) {
            p.embargo_until_ms = if em > 0 { Some(em) } else { None };
        }
        if let Some(map) = a.get("entry_class").and_then(|v| v.as_table()) {
            for (k, v) in map {
                let s = v
                    .as_str()
                    .ok_or_else(|| format!("[access.entry_class] '{k}' must be a class string"))?;
                let c = class_from_token(s)
                    .ok_or_else(|| format!("[access.entry_class] '{k}' = '{s}' is not a class"))?;
                p.entry_class.insert(k.clone(), c);
            }
        }
        Ok(p)
    }

    /// Discover `tallow.toml` beside `target` (or its parent) and load
    /// `[access]`. Parse errors degrade to the deny-by-default base policy
    /// with a warning — never to a looser one.
    pub fn load_for(target: &Path) -> Self {
        let toml_path: Option<PathBuf> = target.parent().and_then(|dir| {
            let same_dir = dir.join("tallow.toml");
            let parent_dir = dir.parent().map(|p| p.join("tallow.toml"));
            if same_dir.exists() {
                Some(same_dir)
            } else {
                parent_dir.filter(|p| p.exists())
            }
        });
        if let Some(p) = toml_path {
            if let Ok(text) = std::fs::read_to_string(&p) {
                if let Ok(parsed) = text.parse::<toml::Table>() {
                    return AccessPolicy::from_table(&parsed).unwrap_or_else(|e| {
                        eprintln!("warning: {e} — using deny-by-default [access] policy");
                        AccessPolicy::default()
                    });
                }
            }
        }
        AccessPolicy::default()
    }

    /// Class of one entry from its parts: explicit map (id, then name) →
    /// `class:*` tags (tightest wins; unknown token ⇒ sealed) → default.
    pub fn class_of_parts(&self, id: &str, name: &str, tags: &[String]) -> AccessClass {
        if let Some(c) = self
            .entry_class
            .get(id)
            .or_else(|| self.entry_class.get(name))
        {
            return *c;
        }
        let mut class: Option<AccessClass> = None;
        for t in tags {
            if let Some(rest) = t.strip_prefix(CLASS_TAG_PREFIX) {
                // Unknown token fails closed (sealed), not open.
                let c = class_from_token(rest).unwrap_or(AccessClass::Sealed);
                class = Some(match class {
                    Some(prev) => AccessClass::tightest_of(prev, c),
                    None => c,
                });
            }
        }
        class.unwrap_or(self.default_class)
    }

    /// Class of one entry (delegates to [`AccessPolicy::class_of_parts`]).
    pub fn class_of(&self, e: &VaultEntry) -> AccessClass {
        self.class_of_parts(&e.id, &e.name, &e.tags)
    }

    /// Tightest class across the given entries (a container is never looser
    /// than its members; an empty selection falls back to `default_class`).
    pub fn tightest_class<'a>(&self, entries: impl Iterator<Item = &'a VaultEntry>) -> AccessClass {
        entries
            .map(|e| self.class_of(e))
            .max()
            .unwrap_or(self.default_class)
    }

    /// Active embargo per [`crate::retention::embargo_active`] (D4).
    pub fn is_embargo_active(&self, now_ms: i64) -> bool {
        embargo_active(
            &Embargo {
                embargo_until_ms: self.embargo_until_ms,
                staged_open: false,
                notes: String::new(),
            },
            now_ms,
        )
    }
}

/// A loaded gate: policy + context + the instant the operation runs.
#[derive(Debug, Clone)]
pub struct VaultGate {
    pub policy: AccessPolicy,
    pub ctx: AccessContext,
    pub now_ms: i64,
}

impl VaultGate {
    pub fn for_path(target: &Path, ctx: AccessContext) -> Self {
        Self {
            policy: AccessPolicy::load_for(target),
            ctx,
            now_ms: now_ms(),
        }
    }

    /// Gate one entry for reading (fail-closed; error carries the stable code).
    pub fn read_gate(&self, e: &VaultEntry) -> Result<(), EnforceError> {
        enforce_read(self.policy.class_of(e), self.ctx.audience)
    }

    /// Split a listing into (visible, withheld-with-reason). Order preserved.
    pub fn visible<'a>(
        &self,
        entries: &[&'a VaultEntry],
    ) -> (Vec<&'a VaultEntry>, Vec<(&'a VaultEntry, EnforceError)>) {
        let mut ok = Vec::new();
        let mut denied = Vec::new();
        for e in entries {
            match self.read_gate(e) {
                Ok(()) => ok.push(*e),
                Err(err) => denied.push((*e, err)),
            }
        }
        (ok, denied)
    }

    /// First denial in a whole-command read (health/audit/ssh-agent shape).
    pub fn first_denied(&self, entries: &[&VaultEntry]) -> Option<EnforceError> {
        entries.iter().find_map(|e| self.read_gate(e).err())
    }
}

/// Best-effort journal record for a refusal (D9: denials → security journal).
/// Metadata only — code + class + audience; never entry content.
pub fn log_denial(e: &EnforceError, class: Option<AccessClass>, audience: Audience) {
    let target = format!(
        "vault {}{} audience={audience:?}",
        code_of(e),
        class.map(|c| format!(" class={c}")).unwrap_or_default()
    );
    let _ = crate::observability::emit_to_default_journal(&crate::observability::SecurityEvent {
        class: crate::observability::EventClass::PolicyVerdict,
        actor: "vault.access".to_string(),
        target: Some(target),
        size: 0,
        at_ms: now_ms(),
    });
}

// ── Tests ────────────────────────────────────────────────────────────────────

// ── Release pipeline (design §5) ────────────────────────────────────────────

/// A completed release: the redaction receipt plus the gated export.
#[derive(Debug, Clone)]
pub struct ReleaseOutcome {
    /// The redaction receipt (audit trail; goes to the KT log).
    pub receipt: crate::redaction::ReleaseBundle,
    /// The released export (derivative bytes + receipt hashes + caveats).
    pub released: ReleasedExport,
}

/// The full release pipeline for an export document:
/// redact → pin (canonical compact) → gate. Refusals carry stable codes and
/// happen before any byte reaches the caller's output path.
pub fn release_gated(
    policy: &AccessPolicy,
    ctx: AccessContext,
    class: AccessClass,
    value: &serde_json::Value,
    required_caveats: Vec<String>,
    now_ms: i64,
) -> Result<ReleaseOutcome, EnforceError> {
    release_gated_with(
        policy,
        ctx,
        class,
        value,
        required_caveats,
        now_ms,
        ReleaseAuthority::default(),
    )
}

/// [`release_gated`] with an explicit [`ReleaseAuthority`].
///
/// The default authority is render-only, so the six-argument wrapper is
/// byte-for-byte the previous behaviour and no existing caller changes. Passing
/// `ReleaseAuthority::from_env()` — which is what the CLI does — is the
/// operator's opt-in: with `TALLOW_CAVEAT_GATE=enforce` the caveats this
/// request carries are evaluated before any byte is released.
pub fn release_gated_with(
    policy: &AccessPolicy,
    ctx: AccessContext,
    class: AccessClass,
    value: &serde_json::Value,
    required_caveats: Vec<String>,
    now_ms: i64,
    authority: ReleaseAuthority,
) -> Result<ReleaseOutcome, EnforceError> {
    let bundle = produce_release(value, &policy.redaction, now_ms).map_err(|e| match e {
        RedactError::Denied(code) => EnforceError::ExportDenied(code),
        other => EnforceError::Redaction(format!("redaction.{}", redact_err_token(&other))),
    })?;
    let derivative = serde_json::to_vec(&bundle.released)
        .map_err(|e| EnforceError::Redaction(format!("redaction.encode-error: {e}")))?;
    let req = ExportRequest {
        class,
        audience: ctx.audience,
        embargo_active: policy.is_embargo_active(now_ms),
        derivative,
        required_caveats,
    };
    let released = enforce_export_with(&req, &bundle.released_hash, now_ms, &bundle, authority)?;
    Ok(ReleaseOutcome {
        receipt: bundle,
        released,
    })
}

fn redact_err_token(e: &RedactError) -> String {
    match e {
        RedactError::NonObject => "non-object".to_string(),
        RedactError::EmptyField => "empty-field".to_string(),
        RedactError::Denied(c) => c.clone(),
        other => format!("{other:?}").to_ascii_lowercase(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_class::{check_export, check_read};

    fn note(name: &str, tags: &[&str]) -> VaultEntry {
        let mut e = VaultEntry::new_note(name, "body");
        e.tags = tags.iter().map(|s| s.to_string()).collect();
        e
    }

    /// The seam's read path must agree, code-for-code, with the pure gate.
    #[test]
    fn read_matrix_matches_pure_gate() {
        for c in AccessClass::ALL {
            for a in Audience::ALL {
                let via_enforce = enforce_read(c, a);
                let via_check = check_read(c, a);
                match (via_enforce, via_check) {
                    (Ok(()), Ok(())) => {}
                    (Err(EnforceError::ReadDenied(code)), Err(reason)) => {
                        assert_eq!(code, reason.code(), "{c:?}/{a:?}");
                    }
                    (x, y) => panic!("divergence {c:?}/{a:?}: {x:?} vs {y:?}"),
                }
            }
        }
    }

    #[test]
    fn unclassified_defaults_to_restricted_and_never_exports() {
        let p = AccessPolicy::default();
        let c = p.class_of_parts("id1", "test", &[]);
        assert_eq!(c, AccessClass::Restricted);
        assert!(enforce_read(c, Audience::Operator).is_ok());
        let err = check_export(c, Audience::Operator, false).unwrap_err();
        assert_eq!(err.code(), "deny.no-export-path");
    }

    #[test]
    fn sealed_is_never_readable_or_visible() {
        let p = AccessPolicy::default();
        let e = note("k", &["class:sealed"]);
        assert_eq!(p.class_of(&e), AccessClass::Sealed);
        let gate = VaultGate {
            policy: p,
            ctx: AccessContext::operator(),
            now_ms: 0,
        };
        let err = gate.read_gate(&e).unwrap_err();
        assert_eq!(code_of(&err), "deny.sealed");
        let open = note("open", &[]);
        let entries = vec![&open, &e];
        let (visible, withheld) = gate.visible(&entries);
        assert_eq!(visible.len(), 1);
        assert_eq!(withheld.len(), 1);
        assert_eq!(withheld[0].0.name, "k");
        assert_eq!(code_of(&withheld[0].1), "deny.sealed");
        assert!(gate.first_denied(&entries).is_some());
    }

    #[test]
    fn unknown_tag_token_fails_closed_and_tightest_wins() {
        let p = AccessPolicy::default();
        assert_eq!(
            p.class_of_parts("i", "n", &["class:fubar".to_string()]),
            AccessClass::Sealed
        );
        assert_eq!(
            p.class_of_parts(
                "i",
                "n",
                &["class:open".to_string(), "class:restricted".to_string()]
            ),
            AccessClass::Restricted
        );
    }

    #[test]
    fn entry_class_override_beats_tags() {
        let mut p = AccessPolicy::default();
        p.entry_class
            .insert("prod-root-key".to_string(), AccessClass::Sealed);
        assert_eq!(
            p.class_of_parts("id", "prod-root-key", &["class:open".to_string()]),
            AccessClass::Sealed
        );
        assert_eq!(
            p.class_of_parts("prod-root-key", "other", &["class:open".to_string()]),
            AccessClass::Sealed
        );
    }

    #[test]
    fn policy_table_parses_and_refuses_open_default() {
        let ok: toml::Table =
            "[access]\ndefault_class = \"research\"\nembargo_until_ms = 123\n[access.entry_class]\nx = \"sealed\"\n"
                .parse()
                .unwrap();
        let p = AccessPolicy::from_table(&ok).unwrap();
        assert_eq!(p.default_class, AccessClass::Research);
        assert_eq!(p.embargo_until_ms, Some(123));
        assert_eq!(p.entry_class.get("x"), Some(&AccessClass::Sealed));

        let bad: toml::Table = "[access]\ndefault_class = \"open\"\n".parse().unwrap();
        assert!(AccessPolicy::from_table(&bad).is_err());

        let empty: toml::Table = "".parse().unwrap();
        assert_eq!(
            AccessPolicy::from_table(&empty).unwrap().default_class,
            AccessClass::Restricted
        );
    }

    #[test]
    fn embargo_uses_retention_semantics() {
        let mut p = AccessPolicy::default();
        assert!(!p.is_embargo_active(1000));
        p.embargo_until_ms = Some(2000);
        assert!(p.is_embargo_active(1000));
        assert!(!p.is_embargo_active(2000)); // end exclusive
        assert!(!p.is_embargo_active(3000));
        // An active embargo refuses every export, including Open (D4).
        assert_eq!(
            check_export(AccessClass::Open, Audience::Public, true)
                .unwrap_err()
                .code(),
            "deny.embargo-active"
        );
    }

    #[test]
    fn audience_tokens_round_trip() {
        for (tok, a) in [
            ("public", Audience::Public),
            ("third-party", Audience::ThirdParty),
            ("teammate", Audience::Teammate),
            ("operator", Audience::Operator),
        ] {
            assert_eq!(audience_from_token(tok), Some(a), "{tok}");
        }
        assert_eq!(audience_from_token("nope"), None);
        assert_eq!(audience_from_token(" Operator "), Some(Audience::Operator));
    }

    #[test]
    fn tightest_class_never_looser_than_members() {
        let mut p = AccessPolicy::default();
        p.entry_class.insert("a".to_string(), AccessClass::Open);
        p.entry_class.insert("b".to_string(), AccessClass::Research);
        let open = note("a", &[]);
        let research = note("b", &[]);
        let sealed = note("c", &["class:sealed"]);
        let pair = vec![&open, &research];
        assert_eq!(p.tightest_class(pair.into_iter()), AccessClass::Research);
        let pair2 = vec![&open, &sealed];
        assert_eq!(p.tightest_class(pair2.into_iter()), AccessClass::Sealed);
        let empty: Vec<&VaultEntry> = vec![];
        assert_eq!(p.tightest_class(empty.into_iter()), AccessClass::Restricted);
    }

    #[test]
    fn redaction_table_parses() {
        let t: toml::Table =
            "[redaction]\nremove = [\"password\"]\nhash = [\"username\"]\nmask = [{ field = \"card\", keep_prefix = 4, keep_suffix = 2 }]\n"
                .parse()
                .unwrap();
        let p = AccessPolicy::from_table(&t).unwrap();
        assert_eq!(p.redaction.len(), 3);
        assert_eq!(p.redaction[0].field, "password");
        assert_eq!(p.redaction[0].mode, RedactMode::Remove);
        assert_eq!(p.redaction[1].mode, RedactMode::Hash);
        assert_eq!(
            p.redaction[2].mode,
            RedactMode::Mask {
                keep_prefix: 4,
                keep_suffix: 2
            }
        );
    }

    #[test]
    fn release_gated_pins_bytes_and_denies() {
        let p = AccessPolicy::default();
        let value = serde_json::json!({"items": [], "folders": []});
        let out = release_gated(
            &p,
            AccessContext {
                audience: Audience::Public,
            },
            AccessClass::Open,
            &value,
            vec![],
            1_700_000_000_000,
        )
        .unwrap();
        assert_eq!(out.receipt.released_hash.len(), 64);
        assert_eq!(out.released.receipt_hash, out.receipt.released_hash);
        assert_eq!(
            out.released.derivative,
            serde_json::to_vec(&out.receipt.released).unwrap()
        );
        // Restricted has no export path, even for the operator.
        let err = release_gated(
            &p,
            AccessContext::operator(),
            AccessClass::Restricted,
            &value,
            vec![],
            0,
        )
        .unwrap_err();
        assert_eq!(code_of(&err), "deny.no-export-path");
        // An active embargo refuses every export, even Open/Public.
        let mut pe = AccessPolicy::default();
        pe.embargo_until_ms = Some(9_999_999_999_999);
        let err = release_gated(
            &pe,
            AccessContext {
                audience: Audience::Public,
            },
            AccessClass::Open,
            &value,
            vec![],
            0,
        )
        .unwrap_err();
        assert_eq!(code_of(&err), "deny.embargo-active");
    }
}
