//! Budget model + hard stops (checklist 3.7, A-part).
//!
//! The mechanism — the *values* are an operator decision. Three enforcement
//! surfaces, all checked **before** anything executes:
//!
//! 1. **Kill switch (fleet stop):** a halt file exists ⇒ every dispatch is
//!    refused, everywhere, immediately (`TALLOW_JOBS_HALT` env overrides the
//!    path; the budget file may set `halt_file` too).
//! 2. **Caps:** per-day run counts and estimated spend, global and per
//!    recipe, counted from today's `job.run` receipts (UTC day).
//! 3. **Fail closed:** a budget file that cannot be parsed, or a ledger that
//!    cannot be read, refuses dispatch — never "run anyway".
//!
//! Refusals are recorded in the human run log (`event: "refused"`) and the
//! scheduler report; they never touch the signed ledger (nothing ran, nothing
//! spent). Actual-spend reconciliation is a human/operator report — estimates
//! here are deliberate and documented.
//!
//! Contract for other components (e.g. locator provisioning, 3.3): honor the
//! same halt file — **exists ⇒ refuse** — before minting or spending.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use tallow_registry::ledger::{Ledger, LedgerError};

/// Limits for one scope (global or a single recipe).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    #[serde(default)]
    pub max_runs_per_day: Option<u64>,
    #[serde(default)]
    pub max_spend_eur_per_day: Option<f64>,
    /// Estimated cost of ONE run of this recipe (EUR); used to accumulate
    /// spend against the caps. Absent ⇒ 0.0 for recipes, but see `global`.
    #[serde(default)]
    pub est_cost_eur: Option<f64>,
    /// Reserved for the worker-node surface (3.3); not enforceable until the
    /// provisioner exists.
    #[serde(default)]
    pub max_worker_nodes: Option<u64>,
}

/// The budget file (`tallow-budget/v1`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub schema: String,
    /// Kill-switch file (default live path: `/var/lib/tallow-jobs/HALT`).
    #[serde(default)]
    pub halt_file: Option<PathBuf>,
    #[serde(default)]
    pub global: BudgetLimits,
    #[serde(default)]
    pub recipes: BTreeMap<String, BudgetLimits>,
}

/// Scheduler-side budget state.
#[derive(Debug, Clone)]
pub enum BudgetState {
    /// No budget file: no caps. The env kill switch still applies.
    Disabled,
    Active(Budget),
    /// Budget file present but unreadable/invalid ⇒ refuse everything.
    Invalid(String),
}

/// Why a dispatch was refused.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    Halt {
        file: String,
    },
    Invalid(String),
    CapRunsGlobal {
        limit: u64,
        used: u64,
    },
    CapRunsRecipe {
        recipe: String,
        limit: u64,
        used: u64,
    },
    CapSpendGlobal {
        limit: f64,
        used: f64,
    },
    CapSpendRecipe {
        recipe: String,
        limit: f64,
        used: f64,
    },
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Halt { .. } => "halt",
            Refusal::Invalid(_) => "budget-invalid",
            Refusal::CapRunsGlobal { .. } => "cap-runs-global",
            Refusal::CapRunsRecipe { .. } => "cap-runs-recipe",
            Refusal::CapSpendGlobal { .. } => "cap-spend-global",
            Refusal::CapSpendRecipe { .. } => "cap-spend-recipe",
        }
    }

    pub fn reason(&self) -> String {
        match self {
            Refusal::Halt { file } => format!("kill switch engaged (halt file {file})"),
            Refusal::Invalid(e) => format!("budget config unusable (fail-closed): {e}"),
            Refusal::CapRunsGlobal { limit, used } => {
                format!("global daily run cap reached ({used}/{limit})")
            }
            Refusal::CapRunsRecipe {
                recipe,
                limit,
                used,
            } => format!("daily run cap reached for '{recipe}' ({used}/{limit})"),
            Refusal::CapSpendGlobal { limit, used } => {
                format!("global daily spend cap reached (~{used:.2}/~{limit:.2} EUR est)")
            }
            Refusal::CapSpendRecipe {
                recipe,
                limit,
                used,
            } => format!("daily spend cap reached for '{recipe}' (~{used:.2}/~{limit:.2} EUR est)"),
        }
    }
}

impl Budget {
    /// Parse + validate a budget file (strict schema).
    pub fn load(path: &Path) -> Result<Budget, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("budget file {}: {e}", path.display()))?;
        let b: Budget = serde_json::from_str(&text)
            .map_err(|e| format!("budget file {}: {e}", path.display()))?;
        if b.schema != "tallow-budget/v1" {
            return Err(format!(
                "budget file {}: unsupported schema {:?} (this reader: tallow-budget/v1)",
                path.display(),
                b.schema
            ));
        }
        Ok(b)
    }

    pub fn limits_for(&self, recipe: &str) -> BudgetLimits {
        self.recipes.get(recipe).cloned().unwrap_or_default()
    }

    fn est_cost_for(&self, recipe: &str) -> f64 {
        self.recipes
            .get(recipe)
            .and_then(|l| l.est_cost_eur)
            .or(self.global.est_cost_eur)
            .unwrap_or(0.0)
    }
}

/// UTC midnight for the day containing `now_ms`.
pub fn day_start_ms(now_ms: i64) -> i64 {
    now_ms - now_ms.rem_euclid(86_400_000)
}

/// Today's counters (UTC) derived from `job.run` receipts.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DayCounters {
    pub runs_global: u64,
    pub runs_recipe: u64,
    pub spend_global_est: f64,
    pub spend_recipe_est: f64,
}

pub fn counters_today(
    budget: &Budget,
    ledger: &Ledger,
    recipe: &str,
    now_ms: i64,
) -> Result<DayCounters, LedgerError> {
    let start = day_start_ms(now_ms);
    let mut c = DayCounters::default();
    for r in ledger.iter()? {
        if r.kind != "job.run" || (r.ts_ms as i64) < start {
            continue;
        }
        let rid = r
            .data
            .get("recipe")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .or_else(|| r.subject.clone())
            .unwrap_or_default();
        let est = budget.est_cost_for(&rid);
        c.runs_global += 1;
        c.spend_global_est += est;
        if rid == recipe {
            c.runs_recipe += 1;
            c.spend_recipe_est += est;
        }
    }
    Ok(c)
}

fn check_caps(b: &Budget, ledger: &Ledger, recipe: &str, now_ms: i64) -> Result<(), Refusal> {
    let c = counters_today(b, ledger, recipe, now_ms)
        .map_err(|e| Refusal::Invalid(format!("ledger unreadable: {e}")))?;
    let l = b.limits_for(recipe);
    if let Some(max) = b.global.max_runs_per_day {
        if c.runs_global >= max {
            return Err(Refusal::CapRunsGlobal {
                limit: max,
                used: c.runs_global,
            });
        }
    }
    if let Some(max) = l.max_runs_per_day {
        if c.runs_recipe >= max {
            return Err(Refusal::CapRunsRecipe {
                recipe: recipe.to_string(),
                limit: max,
                used: c.runs_recipe,
            });
        }
    }
    if let Some(max) = b.global.max_spend_eur_per_day {
        if c.spend_global_est >= max {
            return Err(Refusal::CapSpendGlobal {
                limit: max,
                used: c.spend_global_est,
            });
        }
    }
    if let Some(max) = l.max_spend_eur_per_day {
        if c.spend_recipe_est >= max {
            return Err(Refusal::CapSpendRecipe {
                recipe: recipe.to_string(),
                limit: max,
                used: c.spend_recipe_est,
            });
        }
    }
    Ok(())
}

/// The single gate every dispatch (and every future mint/spend) goes through.
/// Order: kill switch → fail-closed state → caps.
pub fn gate(
    state: &BudgetState,
    halt_override: Option<&PathBuf>,
    ledger: &Ledger,
    recipe: &str,
    now_ms: i64,
) -> Result<(), Refusal> {
    let halt: Option<&PathBuf> = halt_override.or(match state {
        BudgetState::Active(b) => b.halt_file.as_ref(),
        _ => None,
    });
    if let Some(h) = halt {
        if h.exists() {
            return Err(Refusal::Halt {
                file: h.display().to_string(),
            });
        }
    }
    match state {
        BudgetState::Disabled => Ok(()),
        BudgetState::Invalid(e) => Err(Refusal::Invalid(e.clone())),
        BudgetState::Active(b) => check_caps(b, ledger, recipe, now_ms),
    }
}

/// Status lines for `tallow-jobs budget` (human rendering).
pub fn status_lines(state: &BudgetState, ledger: &Ledger, now_ms: i64) -> Vec<String> {
    let mut out = Vec::new();
    match state {
        BudgetState::Disabled => {
            out.push(
                "budget: disabled (no --budget file) — caps not enforced; env kill switch only"
                    .into(),
            );
        }
        BudgetState::Invalid(e) => {
            out.push(format!(
                "budget: INVALID (fail-closed, all dispatch refused): {e}"
            ));
        }
        BudgetState::Active(b) => {
            out.push(format!(
                "budget: tallow-budget/v1 — halt file {}",
                b.halt_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(none configured)".into())
            ));
            let day = day_start_ms(now_ms);
            out.push(format!("UTC day start: {day} ({} runs counted)", {
                // count once for display
                counters_today(b, ledger, "", now_ms)
                    .map(|c| c.runs_global)
                    .unwrap_or(0)
            }));
            let gl = &b.global;
            out.push(format!(
                "global: runs today {}/{} · spend est {:.2}/{} EUR",
                counters_today(b, ledger, "", now_ms)
                    .map(|c| c.runs_global)
                    .unwrap_or(0),
                gl.max_runs_per_day
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                counters_today(b, ledger, "", now_ms)
                    .map(|c| c.spend_global_est)
                    .unwrap_or(0.0),
                gl.max_spend_eur_per_day
                    .map(|v| format!("{v:.2}"))
                    .unwrap_or_else(|| "-".into()),
            ));
            for (rid, lim) in &b.recipes {
                let c = counters_today(b, ledger, rid, now_ms).unwrap_or_default();
                out.push(format!(
                    "  {rid}: runs today {}/{} · spend est {:.2}/{} EUR",
                    c.runs_recipe,
                    lim.max_runs_per_day
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".into()),
                    c.spend_recipe_est,
                    lim.max_spend_eur_per_day
                        .map(|v| format!("{v:.2}"))
                        .unwrap_or_else(|| "-".into()),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::append_run_at;
    use serde_json::json;

    const NOW: i64 = 1_790_568_000_000; // fixed point; any day ok

    fn budget_json() -> serde_json::Value {
        json!({
            "schema": "tallow-budget/v1",
            "halt_file": null,
            "global": {"max_runs_per_day": 10, "max_spend_eur_per_day": 5.0},
            "recipes": {
                "a": {"max_runs_per_day": 2, "est_cost_eur": 0.1},
                "b": {"max_runs_per_day": 3, "est_cost_eur": 0.2, "max_spend_eur_per_day": 0.25}
            }
        })
    }

    fn write_budget(dir: &Path, name: &str, v: &serde_json::Value) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, serde_json::to_string_pretty(v).unwrap()).unwrap();
        p
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tallow-budget-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn load_valid_and_strict() {
        let d = tmpdir("load");
        let p = write_budget(&d, "b.json", &budget_json());
        let b = Budget::load(&p).unwrap();
        assert_eq!(b.global.max_runs_per_day, Some(10));
        assert_eq!(b.recipes["a"].est_cost_eur, Some(0.1));

        // unknown field ⇒ refused (fail closed)
        let mut bad = budget_json();
        bad["global"]["nonsense"] = json!(1);
        let p2 = write_budget(&d, "bad.json", &bad);
        assert!(Budget::load(&p2).is_err());

        // wrong schema ⇒ refused
        let mut ws = budget_json();
        ws["schema"] = json!("tallow-budget/v9");
        let p3 = write_budget(&d, "ws.json", &ws);
        assert!(Budget::load(&p3).is_err());
    }

    #[test]
    fn kill_switch_beats_everything() {
        let d = tmpdir("halt");
        let halt = d.join("HALT");
        std::fs::write(&halt, b"stop").unwrap();
        let ledger = Ledger::new(d.join("l.jsonl"));
        // Disabled state + override halt ⇒ refused
        let r = gate(&BudgetState::Disabled, Some(&halt), &ledger, "a", NOW).unwrap_err();
        assert_eq!(r.code(), "halt");
        // Invalid state + override halt ⇒ still halt first
        let r = gate(
            &BudgetState::Invalid("x".into()),
            Some(&halt),
            &ledger,
            "a",
            NOW,
        )
        .unwrap_err();
        assert_eq!(r.code(), "halt");
        // Active with halt_file set ⇒ refused without override
        let mut bj = budget_json();
        bj["halt_file"] = json!(halt.display().to_string());
        let b = Budget::load(&write_budget(&d, "b.json", &bj)).unwrap();
        let r = gate(&BudgetState::Active(b), None, &ledger, "a", NOW).unwrap_err();
        assert_eq!(r.code(), "halt");
    }

    #[test]
    fn invalid_state_fails_closed_and_disabled_passes() {
        let d = tmpdir("state");
        let ledger = Ledger::new(d.join("l.jsonl"));
        assert!(gate(&BudgetState::Disabled, None, &ledger, "a", NOW).is_ok());
        let r = gate(&BudgetState::Invalid("bad".into()), None, &ledger, "a", NOW).unwrap_err();
        assert_eq!(r.code(), "budget-invalid");
    }

    #[test]
    fn recipe_run_cap_enforced() {
        let d = tmpdir("cap");
        let ledger = Ledger::new(d.join("l.jsonl"));
        let b = Budget::load(&write_budget(&d, "b.json", &budget_json())).unwrap();
        let st = BudgetState::Active(b);
        // empty ⇒ ok
        assert!(gate(&st, None, &ledger, "a", NOW).is_ok());
        // two runs today for 'a' ⇒ at cap (2) ⇒ refused
        append_run_at(&ledger, "a", NOW - 1_000, true, 1);
        append_run_at(&ledger, "a", NOW - 2_000, true, 1);
        let r = gate(&st, None, &ledger, "a", NOW).unwrap_err();
        assert_eq!(r.code(), "cap-runs-recipe");
        // but recipe 'b' still fine (its own cap is 3)
        assert!(gate(&st, None, &ledger, "b", NOW).is_ok());
    }

    #[test]
    fn global_run_cap_and_recipe_isolation() {
        let d = tmpdir("gcap");
        let ledger = Ledger::new(d.join("l.jsonl"));
        let b = Budget::load(&write_budget(&d, "b.json", &budget_json())).unwrap();
        let st = BudgetState::Active(b);
        for i in 0..10 {
            append_run_at(
                &ledger,
                if i % 2 == 0 { "a" } else { "zz" },
                NOW - i,
                true,
                1,
            );
        }
        // 'a' has 5 today; recipe cap 2 would fire, but global (10) fires first
        let r = gate(&st, None, &ledger, "a", NOW).unwrap_err();
        assert_eq!(r.code(), "cap-runs-global");
    }

    #[test]
    fn spend_cap_uses_estimates() {
        let d = tmpdir("spend");
        let ledger = Ledger::new(d.join("l.jsonl"));
        let b = Budget::load(&write_budget(&d, "b.json", &budget_json())).unwrap();
        let st = BudgetState::Active(b);
        // 'b' est 0.2/run, cap 0.25 ⇒ one run (0.2) allowed, two (0.4) refuse
        append_run_at(&ledger, "b", NOW - 1_000, true, 1);
        assert!(gate(&st, None, &ledger, "b", NOW).is_ok());
        append_run_at(&ledger, "b", NOW - 500, true, 1);
        let r = gate(&st, None, &ledger, "b", NOW).unwrap_err();
        assert_eq!(r.code(), "cap-spend-recipe");
    }

    #[test]
    fn yesterday_does_not_count() {
        let d = tmpdir("day");
        let ledger = Ledger::new(d.join("l.jsonl"));
        let b = Budget::load(&write_budget(&d, "b.json", &budget_json())).unwrap();
        let st = BudgetState::Active(b);
        for _ in 0..5 {
            append_run_at(&ledger, "a", NOW - 86_400_000 - 1_000, true, 1);
        }
        assert!(gate(&st, None, &ledger, "a", NOW).is_ok());
    }

    #[test]
    fn counters_skip_other_kinds() {
        let d = tmpdir("kinds");
        let ledger = Ledger::new(d.join("l.jsonl"));
        append_run_at(&ledger, "a", NOW - 1_000, true, 1);
        // append a non-job.run receipt via registry API
        let key = tallow_registry::receipt::dev_actor_key();
        let seq = ledger.next_seq().unwrap();
        let prev = ledger.next_prev().unwrap();
        let r = tallow_registry::receipt::Receipt::sign_new(
            seq,
            "locator.scorecard",
            "tallow-locator",
            None,
            json!({"class": "privacy"}),
            prev,
            &key,
        );
        ledger.append(&r).unwrap();
        let b = Budget::load(&write_budget(&d, "b.json", &budget_json())).unwrap();
        let c = counters_today(&b, &ledger, "a", NOW).unwrap();
        assert_eq!(c.runs_global, 1);
        assert_eq!(c.runs_recipe, 1);
    }

    #[test]
    fn day_start_is_utc_midnight() {
        // 2026-09-28T00:00:00Z = 1790553600000 (1790553600 % 86400 == 0)
        let mid = 1_790_553_600_000;
        assert_eq!(day_start_ms(mid), mid);
        assert_eq!(day_start_ms(mid + 5), mid);
        assert_eq!(day_start_ms(mid - 1), mid - 86_400_000);
    }
}
