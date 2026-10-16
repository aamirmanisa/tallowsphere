//! KB-2 resolution — deep-merge across the scope stack with per-key
//! provenance and lock enforcement (row #84, R-7.2).
//!
//! [`resolve_layers`] folds a set of [`ScopeLayer`]s into one effective
//! value tree using the R-7.2 rules (§7.2.2):
//!
//! - layers are applied in [`crate::config::scopes::APPLICATION_ORDER`]
//!   (stable: layers of the same scope keep their input order, e.g.
//!   `config.toml` before `conf.d/*.toml`);
//! - **tables deep-merge**; every leaf overwrite is recorded;
//! - **arrays replace** by default; a `[merge] "key.path" = "append"`
//!   directive (highest layer wins) concatenates lower→higher instead;
//! - **no coercion**: a structural kind conflict (table vs scalar/array)
//!   between two scopes is refused ([`ScopeError::MergeConflict`], `E7042`),
//!   never reconciled best-effort;
//! - **locks beat precedence** (§7.2.1): a key locked at a system-class
//!   scope wins over every later scope; a later scope setting a *different*
//!   value is refused naming the lock origin ([`ScopeError::LockViolation`],
//!   `E7041`). Setting an identical value is not an override — the winner
//!   stays the lock origin and the later scopes are recorded as shadowed.
//! - absence is not erase: an unset key keeps the lower scope's value.
//!
//! Provenance is recorded per **leaf** (scalars, arrays, and the table nodes
//! a scope introduces): the winning scope, the scopes it shadowed, and the
//! `locked_by` origin — the `tallow config get <key> --explain` data model
//! (§7.2.2).

use std::collections::BTreeMap;

use toml::Value;

use crate::config::bundle::ConfigScope;
use crate::config::scopes::{ladder_index, kind_word, LockTable, MergeDirective, ScopeError, ScopeLayer};
use crate::config::schema::{Config, ConfigError};

/// Per-key provenance of a resolved value (the `--explain` model).
#[derive(Debug, Clone, PartialEq)]
pub struct Provenance {
    /// The scope whose value won.
    pub winner: ConfigScope,
    /// The winning value (a leaf: scalar or array).
    pub value: Value,
    /// Scopes whose values were shadowed, in application order.
    pub shadowed: Vec<ConfigScope>,
    /// The system-class scope that pinned this key (`None` when unlocked).
    pub locked_by: Option<ConfigScope>,
}

impl Provenance {
    /// One-line explanation: winning scope, lock origin, shadowed scopes.
    pub fn explain_line(&self, key: &str) -> String {
        let lock = match self.locked_by {
            Some(origin) if origin == self.winner => format!(" (locked by `{}`)" , origin.word()),
            Some(origin) => format!(" (locked by `{}`; winner is the lock origin)" , origin.word()),
            None => String::new(),
        };
        let shadowed = if self.shadowed.is_empty() {
            "shadowed: —".to_string()
        } else {
            format!(
                "shadowed: {}",
                self.shadowed
                    .iter()
                    .map(|s| format!("`{}`", s.word()))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        format!(
            "`{key}` = {}{lock} — winning scope: `{}`; {shadowed}",
            render_value(&self.value),
            self.winner.word()
        )
    }
}

/// One set event for one key path: which scope set it, and the value
/// (`None` for a table node a scope introduced).
#[derive(Debug, Clone, PartialEq)]
struct SetEvent {
    scope: ConfigScope,
    value: Option<Value>,
}

/// The resolved effective config: the merged tree, per-key provenance, the
/// lock table, and the application order actually used.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    table: toml::Table,
    provenance: BTreeMap<String, Provenance>,
    locks: LockTable,
    order: Vec<ConfigScope>,
}

impl Resolved {
    /// The effective (merged) value tree, control tables excluded.
    pub fn table(&self) -> &toml::Table {
        &self.table
    }

    /// Read a resolved leaf/table by dotted key path.
    pub fn get(&self, key: &str) -> Option<&Value> {
        let mut parts = key.split('.');
        let first = parts.next()?;
        let mut current = self.table.get(first)?;
        for part in parts {
            current = current.as_table()?.get(part)?;
        }
        Some(current)
    }

    /// Per-key provenance (leaves only — see module docs).
    pub fn provenance(&self) -> &BTreeMap<String, Provenance> {
        &self.provenance
    }

    /// Provenance of one key, if the key was set by any layer.
    pub fn explain(&self, key: &str) -> Option<&Provenance> {
        self.provenance.get(key)
    }

    /// `--explain` rendering of one key: winning scope + shadowed scopes +
    /// locked-by origin. Returns a not-set line when no layer sets the key.
    pub fn explain_text(&self, key: &str) -> String {
        match self.explain(key) {
            Some(p) => p.explain_line(key),
            None => format!("`{key}` is not set in any scope (defaults apply)"),
        }
    }

    /// The resolved lock table.
    pub fn locks(&self) -> &LockTable {
        &self.locks
    }

    /// The application order actually used (ascending precedence).
    pub fn scope_order(&self) -> &[ConfigScope] {
        &self.order
    }

    /// Serialize the effective tree back to TOML.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(&self.table).map_err(|e| ConfigError::Artifact {
            message: format!("serialize resolved config: {e}"),
        })
    }

    /// The effective tree as the kernel's strict typed view — only when the
    /// merged result is strictly valid (foreign tables refuse it, exactly as
    /// for a file artifact; the consumer owns that verdict). Routed through
    /// the sectioned **loader** so canonical words (`format = "json"`, …)
    /// validate exactly as they do for a file artifact.
    pub fn into_strict_config(&self) -> Result<Config, ConfigError> {
        let text = self.to_toml_string()?;
        crate::config::load::load_from_str(&text, None).into_strict()
    }
}

/// Resolve a layer set into the effective config (§7.2.2 deep-merge +
/// provenance + lock enforcement).
pub fn resolve_layers(layers: &[ScopeLayer]) -> Result<Resolved, ScopeError> {
    let locks = LockTable::from_layers(layers)?;

    let mut ordered: Vec<&ScopeLayer> = layers.iter().collect();
    // Stable sort: same-scope layers (config.toml, conf.d/*.toml, …) keep
    // their input order, which is the application order within a scope.
    ordered.sort_by_key(|l| ladder_index(l.scope()));

    let directives = collect_directives(&ordered);

    let mut table = toml::Table::new();
    let mut events: BTreeMap<String, Vec<SetEvent>> = BTreeMap::new();
    for layer in ordered.iter() {
        merge_into(
            &mut table,
            layer.table(),
            layer.scope(),
            "",
            &mut events,
            &directives,
        )?;
    }

    let mut provenance = build_provenance(&events);
    enforce_locks(&events, &locks, &mut provenance)?;

    let order = ordered.iter().map(|l| l.scope()).collect();
    Ok(Resolved {
        table,
        provenance,
        locks,
        order,
    })
}

/// Merge directives: highest-precedence declarer wins; same-scope layers use
/// input order (last wins).
fn collect_directives(ordered: &[&ScopeLayer]) -> BTreeMap<String, MergeDirective> {
    let mut directives = BTreeMap::new();
    for layer in ordered {
        for (key, directive) in layer.merge_directives() {
            directives.insert(key.clone(), *directive);
        }
    }
    directives
}

/// Merge one layer's table into `dst` (children of `dst`), recording every
/// set event under its dotted path.
fn merge_into(
    dst: &mut toml::Table,
    src: &toml::Table,
    scope: ConfigScope,
    prefix: &str,
    events: &mut BTreeMap<String, Vec<SetEvent>>,
    directives: &BTreeMap<String, MergeDirective>,
) -> Result<(), ScopeError> {
    for (key, incoming) in src.iter() {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let existing = dst.get(key).cloned();
        let merged = merge_node(existing, incoming, scope, &path, events, directives)?;
        dst.insert(key.clone(), merged);
    }
    Ok(())
}

/// Merge one value at one key path (see module docs for the rules).
fn merge_node(
    existing: Option<Value>,
    incoming: &Value,
    scope: ConfigScope,
    path: &str,
    events: &mut BTreeMap<String, Vec<SetEvent>>,
    directives: &BTreeMap<String, MergeDirective>,
) -> Result<Value, ScopeError> {
    match (existing, incoming) {
        // Fresh node.
        (None, Value::Table(t)) => {
            record(events, path, scope, None);
            let mut out = toml::Table::new();
            merge_into(&mut out, t, scope, path, events, directives)?;
            Ok(Value::Table(out))
        }
        (None, other) => {
            record(events, path, scope, Some(other.clone()));
            Ok(other.clone())
        }
        // Tables deep-merge (§7.2.2).
        (Some(Value::Table(mut e)), Value::Table(i)) => {
            merge_into(&mut e, i, scope, path, events, directives)?;
            Ok(Value::Table(e))
        }
        // Everything else: replacement, append, or a structural conflict.
        (Some(existing_value), incoming_value) => {
            if existing_value.is_table() || incoming_value.is_table() {
                let lower = owner_of(events, path).unwrap_or(ConfigScope::Defaults);
                return Err(ScopeError::MergeConflict {
                    key: path.to_string(),
                    lower,
                    higher: scope,
                    detail: format!(
                        "scope `{}` holds {}, scope `{}` sets {}",
                        lower.word(),
                        kind_word(&existing_value),
                        scope.word(),
                        kind_word(incoming_value)
                    ),
                });
            }
            if let (Value::Array(a), Value::Array(b)) = (&existing_value, incoming_value) {
                if directives.get(path) == Some(&MergeDirective::Append) {
                    let mut merged = a.clone();
                    merged.extend(b.iter().cloned());
                    let value = Value::Array(merged);
                    record(events, path, scope, Some(value.clone()));
                    return Ok(value);
                }
            }
            record(events, path, scope, Some(incoming_value.clone()));
            Ok(incoming_value.clone())
        }
    }
}

fn record(
    events: &mut BTreeMap<String, Vec<SetEvent>>,
    path: &str,
    scope: ConfigScope,
    value: Option<Value>,
) {
    events
        .entry(path.to_string())
        .or_default()
        .push(SetEvent { scope, value });
}

fn owner_of(events: &BTreeMap<String, Vec<SetEvent>>, path: &str) -> Option<ConfigScope> {
    events.get(path).and_then(|evs| evs.last()).map(|e| e.scope)
}

/// Public provenance = the last set event (the winner) plus every earlier
/// setter as shadowed. Table nodes carry no leaf value → no entry.
fn build_provenance(events: &BTreeMap<String, Vec<SetEvent>>) -> BTreeMap<String, Provenance> {
    let mut provenance = BTreeMap::new();
    for (key, evs) in events.iter() {
        let Some(last) = evs.last() else { continue };
        let Some(value) = last.value.clone() else {
            continue;
        };
        let shadowed = evs[..evs.len() - 1].iter().map(|e| e.scope).collect();
        provenance.insert(
            key.clone(),
            Provenance {
                winner: last.scope,
                value,
                shadowed,
                locked_by: None,
            },
        );
    }
    provenance
}

/// Lock enforcement (§7.2.1): a system-class lock beats precedence. A later
/// scope setting a *different* value is refused naming the lock origin; an
/// identical value is not an effective override (the lock origin stays the
/// winner and the later scope is recorded as shadowed).
fn enforce_locks(
    events: &BTreeMap<String, Vec<SetEvent>>,
    locks: &LockTable,
    provenance: &mut BTreeMap<String, Provenance>,
) -> Result<(), ScopeError> {
    for (key, origin) in locks.iter() {
        let Some(evs) = events.get(key) else {
            continue;
        };
        let origin_idx = ladder_index(*origin);
        let origin_value = evs
            .iter()
            .rev()
            .find(|e| e.scope == *origin)
            .and_then(|e| e.value.clone());
        let later: Vec<&SetEvent> = evs
            .iter()
            .filter(|e| ladder_index(e.scope) > origin_idx)
            .collect();

        if !later.is_empty() {
            let identical = origin_value
                .as_ref()
                .map(|v| later.iter().all(|e| e.value.as_ref() == Some(v)))
                .unwrap_or(false);
            if !identical {
                return Err(ScopeError::LockViolation {
                    key: key.clone(),
                    locked_by: *origin,
                    overridden_by: later[0].scope,
                    detail: if origin_value.is_some() {
                        "the locking scope pins a different value — remove the lower-scope override \
                         (lock removal is operator-authorized, §7.6.3)"
                            .to_string()
                    } else {
                        "the locking scope pins no value, so a later scope cannot introduce this key"
                            .to_string()
                    },
                });
            }
            // Identical value: the lock origin wins; later scopes shadowed.
            if let Some(v) = origin_value {
                let mut shadowed = Vec::new();
                let mut skipped_winner = false;
                for event in evs.iter().rev() {
                    if !skipped_winner && event.scope == *origin && event.value.as_ref() == Some(&v) {
                        skipped_winner = true;
                        continue;
                    }
                    shadowed.push(event.scope);
                }
                shadowed.reverse();
                provenance.insert(
                    key.clone(),
                    Provenance {
                        winner: *origin,
                        value: v,
                        shadowed,
                        locked_by: Some(*origin),
                    },
                );
            }
        }

        if let Some(entry) = provenance.get_mut(key) {
            entry.locked_by = Some(*origin);
        }
    }
    Ok(())
}

/// Human rendering of a TOML value for `--explain` (never for secret values:
/// secret-class keys hold references, which are safe to render).
fn render_value(value: &Value) -> String {
    match value {
        Value::String(s) => format!("{s:?}"),
        Value::Integer(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Datetime(_) => "datetime".to_string(),
        Value::Array(a) => format!("array[{}]", a.len()),
        Value::Table(t) => format!("table({} keys)", t.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::scopes::ScopeLayer;

    fn table(text: &str) -> toml::Table {
        toml::from_str(text).expect("test table parses")
    }

    fn user(text: &str) -> ScopeLayer {
        ScopeLayer::parse(ConfigScope::User, text, None).expect("user layer")
    }

    fn device(text: &str) -> ScopeLayer {
        ScopeLayer::parse(ConfigScope::Device, text, None).expect("device layer")
    }

    fn defaults(text: &str) -> ScopeLayer {
        ScopeLayer::builtin_defaults(table(text)).expect("defaults layer")
    }

    fn profile(text: &str) -> ScopeLayer {
        ScopeLayer::from_builtin(ConfigScope::Profile, table(text)).expect("profile layer")
    }

    fn system(text: &str) -> ScopeLayer {
        ScopeLayer::verified_for_test(ConfigScope::System, text).expect("system layer")
    }

    /// Every rung of the ladder, in ascending precedence, setting
    /// `[probe] value = N` (N = ladder index + 1).
    fn full_ladder() -> Vec<ScopeLayer> {
        vec![
            defaults("schema_version = 1\n[probe]\nvalue = 1\n"),
            profile("schema_version = 1\n[probe]\nvalue = 2\n"),
            system("schema_version = 1\n[probe]\nvalue = 3\n"),
            user("schema_version = 1\n[probe]\nvalue = 4\n"),
            device("schema_version = 1\n[probe]\nvalue = 5\n"),
            ScopeLayer::parse(ConfigScope::Project, "schema_version = 1\n[probe]\nvalue = 6\n", None)
                .expect("project layer"),
            ScopeLayer::parse(ConfigScope::Agent, "schema_version = 1\n[probe]\nvalue = 7\n", None)
                .expect("agent layer"),
            ScopeLayer::session_layer([(
                "TALLOW_CONFIG_PROBE__VALUE".to_string(),
                "8".to_string(),
            )])
            .expect("session layer"),
        ]
    }

    #[test]
    fn each_scope_wins_over_every_lower_scope() {
        let mut layers = full_ladder();
        // Peel from the top: the winner is always the highest remaining rung.
        for expected in (1..=8).rev() {
            let resolved = resolve_layers(&layers).expect("resolves");
            assert_eq!(
                resolved.get("probe.value"),
                Some(&Value::Integer(expected)),
                "expected scope value {expected} to win; order={:?}",
                resolved.scope_order()
            );
            // Application order is the R-7.2 order, ascending.
            assert!(resolved.scope_order().windows(2).all(|w| ladder_index(w[0]) <= ladder_index(w[1])));
            layers.pop();
        }
        // And the provenance names the winning scope.
        let resolved = resolve_layers(&full_ladder()).expect("resolves");
        let p = resolved.explain("probe.value").expect("provenance");
        assert_eq!(p.winner, ConfigScope::Session);
        assert_eq!(p.value, Value::Integer(8));
        assert_eq!(p.shadowed.len(), 7, "all lower scopes shadowed: {:?}", p.shadowed);
        assert!(resolved.explain_text("probe.value").contains("session"));
        assert!(resolved.explain_text("nothing.here").contains("not set"));
    }

    #[test]
    fn tables_deep_merge_and_absence_does_not_erase() {
        let layers = vec![
            user("schema_version = 1\n\n[probe]\nx = 1\nkeep = 9\n"),
            device("schema_version = 1\n\n[probe]\ny = 2\n"),
        ];
        let resolved = resolve_layers(&layers).expect("resolves");
        assert_eq!(resolved.get("probe.x"), Some(&Value::Integer(1)));
        assert_eq!(resolved.get("probe.y"), Some(&Value::Integer(2)));
        assert_eq!(resolved.get("probe.keep"), Some(&Value::Integer(9)), "unset ≠ erase");
        // Deeper nesting merges too.
        let layers = vec![
            user("schema_version = 1\n\n[probe.deep]\na = 1\n"),
            device("schema_version = 1\n\n[probe.deep]\nb = 2\n"),
        ];
        let resolved = resolve_layers(&layers).expect("resolves");
        assert_eq!(resolved.get("probe.deep.a"), Some(&Value::Integer(1)));
        assert_eq!(resolved.get("probe.deep.b"), Some(&Value::Integer(2)));
    }

    #[test]
    fn arrays_replace_by_default_and_append_with_directive() {
        let base = vec![
            user("schema_version = 1\n\n[probe]\nlist = [\"a\"]\n"),
            device("schema_version = 1\n\n[probe]\nlist = [\"b\"]\n"),
        ];
        let resolved = resolve_layers(&base).expect("resolves");
        assert_eq!(
            resolved.get("probe.list"),
            Some(&Value::Array(vec![Value::String("b".to_string())])),
            "arrays replace by default"
        );
        let p = resolved.explain("probe.list").expect("provenance");
        assert_eq!(p.winner, ConfigScope::Device);
        assert_eq!(p.shadowed, vec![ConfigScope::User]);

        // Explicit opt-in: `[merge] "probe.list" = "append"` concatenates
        // lower→higher.
        let appended = vec![
            user("schema_version = 1\n\n[probe]\nlist = [\"a\"]\n"),
            device("schema_version = 1\n\n[probe]\nlist = [\"b\"]\n\n[merge]\n\"probe.list\" = \"append\"\n"),
        ];
        let resolved = resolve_layers(&appended).expect("resolves");
        assert_eq!(
            resolved.get("probe.list"),
            Some(&Value::Array(vec![
                Value::String("a".to_string()),
                Value::String("b".to_string())
            ]))
        );
    }

    #[test]
    fn structural_conflicts_refuse_without_coercion() {
        // Table below, scalar above (`[probe.deep]` is a table; `probe.deep`
        // then becomes a scalar).
        let layers = vec![
            user("schema_version = 1\n\n[probe.deep]\na = 1\n"),
            device("schema_version = 1\n\n[probe]\ndeep = 5\n"),
        ];
        let err = resolve_layers(&layers).expect_err("kind conflict refused");
        assert_eq!(err.code(), crate::config::scopes::CODE_SCOPE_MERGE, "{err}");
        let text = err.to_string();
        assert!(text.contains("probe.deep"), "{text}");
        assert!(text.contains("user") && text.contains("device"), "names both scopes: {text}");
        assert!(text.contains("coercion"), "{text}");

        // Scalar below, table above.
        let layers = vec![
            user("schema_version = 1\n\n[probe]\nx = 1\n"),
            device("schema_version = 1\n\n[probe]\nx = { nested = true }\n"),
        ];
        let err = resolve_layers(&layers).expect_err("nested conflict refused");
        assert_eq!(err.code(), crate::config::scopes::CODE_SCOPE_MERGE, "{err}");
    }

    #[test]
    fn lock_violation_names_lock_origin() {
        let layers = vec![
            system("schema_version = 1\ntelemetry = true\n\n[lock]\n\"telemetry\" = true\n"),
            user("schema_version = 1\ntelemetry = false\n"),
        ];
        let err = resolve_layers(&layers).expect_err("override refused");
        assert_eq!(err.code(), crate::config::scopes::CODE_SCOPE_LOCK, "{err}");
        let text = err.to_string();
        assert!(text.contains("telemetry"), "{text}");
        assert!(text.contains("system"), "names lock origin: {text}");
        assert!(text.contains("user"), "names offender: {text}");
        assert!(text.contains("lock violation"), "{text}");
    }

    #[test]
    fn identical_value_is_not_an_override_and_lock_origin_wins() {
        let layers = vec![
            system("schema_version = 1\ntelemetry = true\n\n[lock]\n\"telemetry\" = true\n"),
            user("schema_version = 1\ntelemetry = true\n"),
            device("schema_version = 1\ntelemetry = true\n"),
        ];
        let resolved = resolve_layers(&layers).expect("identical value allowed");
        assert_eq!(resolved.get("telemetry"), Some(&Value::Boolean(true)));
        let p = resolved.explain("telemetry").expect("provenance");
        assert_eq!(p.winner, ConfigScope::System, "the lock origin wins");
        assert_eq!(p.locked_by, Some(ConfigScope::System));
        assert_eq!(p.shadowed, vec![ConfigScope::User, ConfigScope::Device]);
        let text = resolved.explain_text("telemetry");
        assert!(text.contains("locked by `system`"), "{text}");
        assert!(text.contains("winning scope: `system`"), "{text}");
        // The lock table is surfaced too.
        assert_eq!(resolved.locks().locked_by("telemetry"), Some(ConfigScope::System));
    }

    #[test]
    fn locked_key_without_value_cannot_be_introduced_below() {
        let layers = vec![
            system("schema_version = 1\n\n[lock]\n\"probe.value\" = true\n"),
            user("schema_version = 1\n\n[probe]\nvalue = 4\n"),
        ];
        let err = resolve_layers(&layers).expect_err("introducing a lockless scope's key refused");
        assert_eq!(err.code(), crate::config::scopes::CODE_SCOPE_LOCK, "{err}");
        assert!(err.to_string().contains("pins no value"), "{err}");
    }

    #[test]
    fn lower_than_origin_setters_do_not_violate() {
        // defaults sets a locked key; the lock is at system — that is below
        // the origin, so it is not an override, and the system value wins.
        let layers = vec![
            defaults("schema_version = 1\ntelemetry = false\n"),
            system("schema_version = 1\ntelemetry = true\n\n[lock]\n\"telemetry\" = true\n"),
        ];
        let resolved = resolve_layers(&layers).expect("resolves");
        assert_eq!(resolved.get("telemetry"), Some(&Value::Boolean(true)));
        let p = resolved.explain("telemetry").expect("provenance");
        assert_eq!(p.winner, ConfigScope::System);
        assert_eq!(p.shadowed, vec![ConfigScope::Defaults]);
    }

    #[test]
    fn same_scope_layers_apply_in_input_order() {
        let layers = vec![
            user("schema_version = 1\nformat = \"json\"\n"),
            user("schema_version = 1\nformat = \"text\"\n"),
        ];
        let resolved = resolve_layers(&layers).expect("resolves");
        assert_eq!(resolved.get("format"), Some(&Value::String("text".to_string())));
        assert_eq!(resolved.explain("format").unwrap().shadowed, vec![ConfigScope::User]);
    }

    #[test]
    fn resolved_serializes_and_projects_strict_config() {
        let layers = vec![
            user("schema_version = 1\nformat = \"json\"\nno_color = true\n"),
            device("schema_version = 1\ntelemetry = false\n"),
        ];
        let resolved = resolve_layers(&layers).expect("resolves");
        let text = resolved.to_toml_string().expect("serialize");
        assert!(text.contains("format = \"json\""), "{text}");
        let config = resolved.into_strict_config().expect("strict typed view");
        assert_eq!(config.format, crate::config::schema::OutputFormat::Json);
        assert!(config.no_color);
        // Foreign tables keep the merged tree out of strict reach (consumer
        // verdict) — same semantics as a file artifact.
        let layers = vec![user("schema_version = 1\n\n[browser]\nnav_timeout_ms = 10\n")];
        let resolved = resolve_layers(&layers).expect("resolves");
        let text = resolved.to_toml_string().expect("serialize");
        assert!(text.contains("[browser]"), "{text}");
        assert!(resolved.into_strict_config().is_err(), "foreign table → not strictly clean");
    }
}
