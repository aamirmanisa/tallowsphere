//! Standard library: `tallow.agent` — real agent orchestration primitives.
//!
//! Provides:
//! - `Playbook`: a named, ordered list of steps with execution state. A step
//!   records `name`, `action`, optional `args`, and a per-step `status` that
//!   advances `pending -> running -> succeeded | failed`. Steps are executed
//!   through a real [`AgentRuntime`] (budget checks, heartbeat, step counters),
//!   so a playbook run is governed by the same runtime-safety machinery as any
//!   other Tallow agent.
//!
//!   `Playbook.execute` genuinely dispatches every step. Because this module
//!   has no interpreter or I/O access, the only actions it can honestly run
//!   are the deterministic set [`SUPPORTED_ACTIONS`]: `noop` (intentionally do
//!   nothing — rejects stray args), `record` (persist the step's `args`
//!   verbatim as the step `output`), and `fail` (mark the step failed, with an
//!   optional `String` reason from `args`). Any other action — including
//!   plausible-sounding ones like `fetch` — returns an explicit
//!   `not_implemented` `Err`; a step is never reported `succeeded` without
//!   being run. Step `args` are carried through compile → execute and echoed
//!   on both the executed step and the `StepResult`, never discarded.
//! - `Alert`: a typed alert with severity, title, description, status, and an
//!   optional escalation trail. Supports creation, triage, and escalation.
//! - Orchestration dispatch: `spawn`/`spawn_agent`, `await_all`, `await_any`,
//!   `parallel_map`, and `current_stats` operate on real playbook/agent data.
//!
//! All functions are deterministic given their inputs (no network I/O), so they
//! are unit-testable and safe to call from the compiler's stdlib dispatch.



use super::StdlibResult;
use crate::agent_runtime::{AgentRuntime, ResourceBudget, StepAction};
use crate::interp::Value;

use uuid::Uuid;

// ── Helpers ──────────────────────────────────────────────────────────────

/// Current time as an RFC3339 (ISO 8601) UTC string.
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Return a fresh AgentRuntime with default safety margins.
fn new_runtime(agent_id: &str) -> AgentRuntime {
    AgentRuntime::new(
        agent_id.to_string(),
        None,                                    // no heartbeat timeout (default)
        Some(100),                               // human checkpoint every 100 steps
        ResourceBudget::new(Some(1_000_000), Some(1 << 31), None),
    )
}

/// Convert a struct-field list into a fresh Playbook `Value::Struct`.
fn playbook_value(
    name: &str,
    steps: Vec<Value>,
    state: Value,
    results: Vec<Value>,
    runtime: &AgentRuntime,
) -> Value {
    Value::Struct {
        name: "Playbook".to_string(),
        fields: vec![
            ("name".to_string(), Value::String(name.to_string())),
            ("steps".to_string(), Value::Array(steps)),
            ("state".to_string(), state),
            ("results".to_string(), Value::Array(results)),
            (
                "steps_executed".to_string(),
                Value::Int(runtime.steps_executed as i128),
            ),
            (
                "killed".to_string(),
                Value::Bool(runtime.killed),
            ),
        ],
    }
}

/// Extract the `steps` array from a Playbook struct.
fn playbook_steps(object: &Value) -> Result<Vec<Value>, String> {
    let Value::Struct { name, fields } = object else {
        return Err("expected a Playbook struct".to_string());
    };
    if name != "Playbook" {
        return Err(format!("expected Playbook, got {name}"));
    }
    for (k, v) in fields {
        if k == "steps" {
            if let Value::Array(items) = v {
                return Ok(items.clone());
            }
        }
    }
    Ok(Vec::new())
}

/// Extract the `name` field from a Playbook struct.
fn playbook_name(object: &Value) -> String {
    if let Value::Struct { name, fields } = object {
        if name == "Playbook" {
            for (k, v) in fields {
                if k == "name" {
                    return v.as_string();
                }
            }
        }
    }
    "unnamed".to_string()
}

/// Build a step struct value.
fn step_value(name: &str, action: &str, args: Vec<Value>, status: &str) -> Value {
    Value::Struct {
        name: "PlaybookStep".to_string(),
        fields: vec![
            ("name".to_string(), Value::String(name.to_string())),
            ("action".to_string(), Value::String(action.to_string())),
            ("args".to_string(), Value::Array(args)),
            ("status".to_string(), Value::String(status.to_string())),
        ],
    }
}

// ── Playbook dispatch ────────────────────────────────────────────────────

/// `Playbook.compile(name, steps)` → create a compiled Playbook.
///
/// `steps` is an array of step structs `{name, action, args}`. Compilation
/// validates each step has a non-empty name and action, then records the
/// initial `pending` status.
fn playbook_compile(args: Vec<Value>) -> StdlibResult {
    let name = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.as_string(),
        None => "default".to_string(),
    };

    let steps = match args.get(1) {
        Some(Value::Array(items)) => items.clone(),
        _ => return Err("Playbook.compile: steps must be an Array".to_string()),
    };

    let mut compiled: Vec<Value> = Vec::with_capacity(steps.len());
    for s in &steps {
        // FIX12 (2026-08-27): match arms produce (playbook_name, step_name, action)
        // S1-honesty (2026-09-05): args are carried through compile so execute()
        // can honor them instead of discarding them.
        let (_pb_name, step_name, action, step_args) = match s {
            Value::Struct { name, fields } => {
                let sn = fields
                    .iter()
                    .find(|(k, _)| k == "name")
                    .map(|(_, v)| v.as_string())
                    .unwrap_or_default();
                let action = fields
                    .iter()
                    .find(|(k, _)| k == "action")
                    .map(|(_, v)| v.as_string())
                    .unwrap_or_default();
                let step_args = fields
                    .iter()
                    .find(|(k, _)| k == "args")
                    .map(|(_, v)| v.clone())
                    .unwrap_or(Value::Array(Vec::new()));
                (name.clone(), sn, action, step_args)
            }
            other => (
                name.clone(),
                other.as_string(),
                "passthrough".to_string(),
                Value::Nil,
            ),
        };
        let _ = &step_name;
        if action.is_empty() {
            return Err(format!(
                "Playbook.compile: step '{name}' has an empty action"
            ));
        }
        let step_args_vec = match &step_args {
            Value::Array(items) => items.clone(),
            _ => Vec::new(),
        };
        compiled.push(step_value(&step_name, &action, step_args_vec, "pending"));
    }

    let mut runtime = new_runtime(&name);
    // compile counts as a recorded step in the runtime
    let _ = runtime.pre_step();

    Ok(playbook_value(
        &name,
        compiled,
        Value::String("compiled".to_string()),
        Vec::new(),
        &runtime,
    ))
}

/// `Playbook.validate(playbook)` → validate step structure.
fn playbook_validate(args: Vec<Value>) -> StdlibResult {
    let object = args
        .first()
        .ok_or_else(|| "Playbook.validate: missing playbook".to_string())?;
    let steps = playbook_steps(object)?;

    for s in &steps {
        let Value::Struct { fields, .. } = s else {
            return Ok(Value::Struct {
                name: "PlaybookValidation".to_string(),
                fields: vec![
                    ("valid".to_string(), Value::Bool(false)),
                    ("error".to_string(), Value::String("step is not a struct".to_string())),
                ],
            });
        };
        let has_name = fields.iter().any(|(k, _)| k == "name");
        let has_action = fields.iter().any(|(k, _)| k == "action");
        if !has_name || !has_action {
            return Ok(Value::Struct {
                name: "PlaybookValidation".to_string(),
                fields: vec![
                    ("valid".to_string(), Value::Bool(false)),
                    (
                        "error".to_string(),
                        Value::String("every step must have name and action fields".to_string()),
                    ),
                ],
            });
        }
    }

    Ok(Value::Struct {
        name: "PlaybookValidation".to_string(),
        fields: vec![
            ("valid".to_string(), Value::Bool(true)),
            ("step_count".to_string(), Value::Int(steps.len() as i128)),
            ("error".to_string(), Value::Nil),
        ],
    })
}

/// Actions the stdlib playbook runner can genuinely perform.
///
/// The module has no interpreter or I/O access, so any action outside this
/// deterministic set is refused with an explicit `not_implemented` error —
/// never a simulated success.
const SUPPORTED_ACTIONS: &[&str] = &["noop", "record", "fail"];

/// Run one step action.
///
/// Returns `(status, extra_fields)` where `extra_fields` are additional
/// `(name, value)` pairs attached to the step's `StepResult`. An unsupported
/// action returns an honest `not_implemented` `Err`.
fn run_action(
    step_name: &str,
    action: &str,
    args: &[Value],
) -> Result<(&'static str, Vec<(String, Value)>), String> {
    match action {
        // Intentionally does nothing; claiming success is only honest if the
        // step carries no args that would then have been silently ignored.
        "noop" => {
            if !args.is_empty() {
                return Err(format!(
                    "Playbook.execute: action 'noop' takes no args, but step '{step_name}' \
                     passed {}; refusing rather than silently discarding them",
                    args.len()
                ));
            }
            Ok(("succeeded", Vec::new()))
        }
        // Real effect: persist the step's args verbatim as the step output.
        "record" => Ok((
            "succeeded",
            vec![("output".to_string(), Value::Array(args.to_vec()))],
        )),
        // Reserved failure marker; the optional first arg is the reason.
        "fail" => {
            let reason = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => "step marked failed by caller".to_string(),
            };
            Ok((
                "failed",
                vec![("reason".to_string(), Value::String(reason))],
            ))
        }
        other => Err(format!(
            "Playbook.execute: step '{step_name}' uses action '{other}', which the stdlib \
             playbook runner does not implement (supported actions: {}). No simulated success.",
            SUPPORTED_ACTIONS.join(", ")
        )),
    }
}

/// `Playbook.execute(playbook)` → run steps through an AgentRuntime.
///
/// Each step advances the runtime step counter and heartbeat; the playbook's
/// per-step status transitions `pending -> running -> succeeded | failed`.
/// Every step is genuinely dispatched through [`run_action`]: supported
/// actions (`noop`, `record`, `fail`) are executed with their `args` honored,
/// and any unsupported action aborts the run with an explicit
/// `not_implemented` error. The resulting playbook carries a `results` array
/// mirroring step status, outputs and failure reasons.
fn playbook_execute(args: Vec<Value>) -> StdlibResult {
    let object = args
        .first()
        .ok_or_else(|| "Playbook.execute: missing playbook".to_string())?;
    let name = playbook_name(object);
    let steps = playbook_steps(object)?;

    let mut runtime = new_runtime(&name);
    let mut executed: Vec<Value> = Vec::with_capacity(steps.len());
    let mut results: Vec<Value> = Vec::with_capacity(steps.len());

    for s in &steps {
        let (step_name, action, step_args) = match s {
            Value::Struct { fields, .. } => {
                let sn = fields
                    .iter()
                    .find(|(k, _)| k == "name")
                    .map(|(_, v)| v.as_string())
                    .unwrap_or_default();
                let action = fields
                    .iter()
                    .find(|(k, _)| k == "action")
                    .map(|(_, v)| v.as_string())
                    .unwrap_or_default();
                let step_args = fields
                    .iter()
                    .find(|(k, _)| k == "args")
                    .map(|(_, v)| v.clone())
                    .unwrap_or(Value::Array(Vec::new()));
                (sn, action, step_args)
            }
            other => (other.as_string(), "passthrough".to_string(), Value::Nil),
        };
        // Flatten the step's args into a Vec so they are honored (recorded on
        // the executed step and consumed by the action) rather than discarded.
        let step_args_vec = match &step_args {
            Value::Array(items) => items.clone(),
            _ => Vec::new(),
        };

        runtime.heartbeat();
        match runtime.pre_step() {
            Ok(StepAction::Continue) => {
                // Genuinely dispatch the action. Unsupported actions abort the
                // run with an honest not_implemented error — a step is never
                // reported succeeded without being run.
                let (status, extra_fields) =
                    match run_action(&step_name, &action, &step_args_vec) {
                        Ok(outcome) => outcome,
                        Err(msg) => return Err(msg),
                    };
                executed.push(step_value(
                    &step_name,
                    &action,
                    step_args_vec,
                    status,
                ));
                let mut fields = vec![
                    ("name".to_string(), Value::String(step_name.clone())),
                    ("status".to_string(), Value::String(status.to_string())),
                    (
                        "steps_executed".to_string(),
                        Value::Int(runtime.steps_executed as i128),
                    ),
                ];
                fields.extend(extra_fields);
                results.push(Value::Struct {
                    name: "StepResult".to_string(),
                    fields,
                });
            }
            Ok(StepAction::PauseForHumanCheckpoint) => {
                // A checkpoint is due; pause bookkeeping but continue — the
                // interpreter treats checkpoints as advisory pausing points.
                executed.push(step_value(
                    &step_name,
                    &action,
                    step_args_vec,
                    "paused",
                ));
                results.push(Value::Struct {
                    name: "StepResult".to_string(),
                    fields: vec![
                        ("name".to_string(), Value::String(step_name.clone())),
                        ("status".to_string(), Value::String("paused".to_string())),
                    ],
                });
            }
            Err(kill) => {
                executed.push(step_value(
                    &step_name,
                    &action,
                    step_args_vec,
                    "killed",
                ));
                results.push(Value::Struct {
                    name: "StepResult".to_string(),
                    fields: vec![
                        ("name".to_string(), Value::String(step_name.clone())),
                        ("status".to_string(), Value::String("killed".to_string())),
                        ("reason".to_string(), Value::String(kill.to_string())),
                    ],
                });
                break;
            }
        }
    }

    Ok(playbook_value(
        &name,
        executed,
        Value::String("executed".to_string()),
        results,
        &runtime,
    ))
}

// ── Alert dispatch ───────────────────────────────────────────────────────

/// `Alert.create(severity, title, description)` → a typed Alert.
fn alert_create(args: Vec<Value>) -> StdlibResult {
    let severity = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.as_string(),
        None => "info".to_string(),
    };
    let title = match args.get(1) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.as_string(),
        None => return Err("Alert.create: requires a title".to_string()),
    };
    let description = match args.get(2) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.as_string(),
        None => String::new(),
    };

    Ok(Value::Struct {
        name: "Alert".to_string(),
        fields: vec![
            ("id".to_string(), Value::String(format!("alert--{}", Uuid::new_v4()))),
            ("severity".to_string(), Value::String(severity)),
            ("title".to_string(), Value::String(title)),
            ("description".to_string(), Value::String(description)),
            ("status".to_string(), Value::String("open".to_string())),
            ("priority".to_string(), Value::Int(0)),
            ("escalated".to_string(), Value::Bool(false)),
            ("created_at".to_string(), Value::String(now_iso())),
            ("escalation_trail".to_string(), Value::Array(Vec::new())),
        ],
    })
}

/// `Alert.triage(alert)` → assign a priority from severity.
fn alert_triage(args: Vec<Value>) -> StdlibResult {
    let object = args
        .first()
        .ok_or_else(|| "Alert.triage: missing alert".to_string())?;
    let Value::Struct { name, fields } = object else {
        return Err("Alert.triage: expected an Alert struct".to_string());
    };
    if name != "Alert" {
        return Err(format!("Alert.triage: expected Alert, got {name}"));
    }

    let severity = fields
        .iter()
        .find(|(k, _)| k == "severity")
        .map(|(_, v)| v.as_string())
        .unwrap_or_default();

    let priority = match severity.as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };

    let mut out = fields.clone();
    for (k, v) in out.iter_mut() {
        if k == "priority" {
            *v = Value::Int(priority);
        }
    }
    Ok(Value::Struct { name: name.clone(), fields: out })
}

/// `Alert.escalate(alert, reason)` → escalate an alert, recording a trail.
fn alert_escalate(args: Vec<Value>) -> StdlibResult {
    let object = args
        .first()
        .ok_or_else(|| "Alert.escalate: missing alert".to_string())?;
    let reason = match args.get(1) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.as_string(),
        None => "escalated".to_string(),
    };
    let Value::Struct { name, fields } = object else {
        return Err("Alert.escalate: expected an Alert struct".to_string());
    };
    if name != "Alert" {
        return Err(format!("Alert.escalate: expected Alert, got {name}"));
    }

    let mut out = fields.clone();
    let mut trail: Vec<Value> = Vec::new();
    for (k, v) in out.iter_mut() {
        match k.as_str() {
            "escalated" => *v = Value::Bool(true),
            "status" => *v = Value::String("escalated".to_string()),
            "escalation_trail" => {
                if let Value::Array(existing) = v {
                    trail = existing.clone();
                }
            }
            _ => {}
        }
    }
    trail.push(Value::Struct {
        name: "EscalationEntry".to_string(),
        fields: vec![
            ("reason".to_string(), Value::String(reason)),
            ("at".to_string(), Value::String(now_iso())),
        ],
    });
    for (k, v) in out.iter_mut() {
        if k == "escalation_trail" {
            *v = Value::Array(trail.clone());
        }
    }
    Ok(Value::Struct { name: name.clone(), fields: out })
}

// ── Orchestration dispatch ───────────────────────────────────────────────

/// `agent.spawn(name, steps)` — create + compile a playbook (alias spawn_agent).
fn spawn(args: Vec<Value>) -> StdlibResult {
    playbook_compile(args)
}

/// `agent.await_all(playbooks)` — merge results of an array of playbooks.
fn await_all(args: Vec<Value>) -> StdlibResult {
    let array = args
        .first()
        .ok_or_else(|| "agent.await_all: missing array".to_string())?;
    let Value::Array(playbooks) = array else {
        return Err("agent.await_all: expected an Array of Playbooks".to_string());
    };

    let mut merged: Vec<Value> = Vec::new();
    for pb in playbooks {
        let results = match pb {
            Value::Struct { name, fields } if name == "Playbook" => fields
                .iter()
                .find(|(k, _)| k == "results")
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Array(Vec::new())),
            other => Value::Array(vec![Value::String(other.as_string())]),
        };
        if let Value::Array(items) = results {
            merged.extend(items);
        }
    }

    Ok(Value::Struct {
        name: "AwaitAllResult".to_string(),
        fields: vec![
            ("playbook_count".to_string(), Value::Int(playbooks.len() as i128)),
            ("results".to_string(), Value::Array(merged)),
        ],
    })
}

/// `agent.await_any(playbooks)` — return the first playbook with results.
fn await_any(args: Vec<Value>) -> StdlibResult {
    let array = args
        .first()
        .ok_or_else(|| "agent.await_any: missing array".to_string())?;
    let Value::Array(playbooks) = array else {
        return Err("agent.await_any: expected an Array of Playbooks".to_string());
    };

    for pb in playbooks {
        if let Value::Struct { name, fields } = pb {
            if name == "Playbook" {
                let has_results = fields
                    .iter()
                    .any(|(k, v)| k == "results" && matches!(v, Value::Array(a) if !a.is_empty()));
                if has_results {
                    return Ok(Value::Struct {
                        name: "AwaitAnyResult".to_string(),
                        fields: vec![
                            ("resolved".to_string(), Value::Bool(true)),
                            ("playbook".to_string(), pb.clone()),
                        ],
                    });
                }
            }
        }
    }

    Ok(Value::Struct {
        name: "AwaitAnyResult".to_string(),
        fields: vec![
            ("resolved".to_string(), Value::Bool(false)),
            ("error".to_string(), Value::String("no playbook with results".to_string())),
        ],
    })
}

/// `agent.parallel_map(items, step_name)` — wrap each item as a completed
/// playbook step. Real parallelism is provided by the compiled/codegen backends;
/// this stdlib form maps the input into an array of per-item playbook results.
fn parallel_map(args: Vec<Value>) -> StdlibResult {
    let array = args
        .first()
        .ok_or_else(|| "agent.parallel_map: missing items array".to_string())?;
    let Value::Array(items) = array else {
        return Err("agent.parallel_map: expected an Array".to_string());
    };
    let step_name = args
        .get(1)
        .map(|v| v.as_string())
        .unwrap_or_else(|| "map_step".to_string());

    let mut out: Vec<Value> = Vec::with_capacity(items.len());
    for item in items {
        out.push(Value::Struct {
            name: "MappedResult".to_string(),
            fields: vec![
                ("step".to_string(), Value::String(step_name.clone())),
                ("value".to_string(), item.clone()),
            ],
        });
    }
    Ok(Value::Array(out))
}

/// `agent.current_stats(playbook)` → runtime safety stats for a playbook.
fn current_stats(args: Vec<Value>) -> StdlibResult {
    let object = args
        .first()
        .ok_or_else(|| "agent.current_stats: missing playbook".to_string())?;
    let name = playbook_name(object);
    let steps = playbook_steps(object)?;

    let mut runtime = new_runtime(&name);
    for _ in &steps {
        let _ = runtime.pre_step();
    }

    Ok(Value::Struct {
        name: "AgentStats".to_string(),
        fields: vec![
            ("agent_id".to_string(), Value::String(name)),
            ("steps_executed".to_string(), Value::Int(runtime.steps_executed as i128)),
            ("killed".to_string(), Value::Bool(runtime.killed)),
            (
                "budget_requests_remaining".to_string(),
                Value::Int(runtime.budget.requests_remaining().unwrap_or(0) as i128),
            ),
            (
                "remaining_spawn_depth".to_string(),
                Value::Int(runtime.remaining_spawn_depth as i128),
            ),
            ("total_agents_spawned".to_string(), Value::Int(runtime.total_agents_spawned as i128)),
        ],
    })
}

// ── Public dispatch ──────────────────────────────────────────────────────

/// Dispatch a `tallow.agent.*` static function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "spawn" | "spawn_agent" => Some(spawn(args)),
        "await_all" => Some(await_all(args)),
        "await_any" => Some(await_any(args)),
        "parallel_map" => Some(parallel_map(args)),
        "current_stats" => Some(current_stats(args)),
        _ => None,
    }
}

/// Dispatch a `tallow.agent.*` struct method call.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, .. } = object else {
        return None;
    };
    match name.as_str() {
        "Playbook" => match method {
            "compile" => Some(playbook_compile(args)),
            "execute" => Some(playbook_execute(prepend_object(object, args))),
            "validate" => Some(playbook_validate(prepend_object(object, args))),
            _ => None,
        },
        "Alert" => match method {
            "create" => Some(alert_create(args)),
            "triage" => Some(alert_triage(prepend_object(object, args))),
            "escalate" => Some(alert_escalate(prepend_object(object, args))),
            _ => None,
        },
        _ => None,
    }
}

/// FIX16: `execute`/`validate`/`triage`/`escalate` take the target struct as
/// their first argument, but the interpreter's `dispatch_method` contract
/// passes only the method-call arguments (the object arrives separately).
/// Previously the arms forwarded `args` unchanged, so every `pb.execute()`,
/// `pb.validate()`, `alert.triage()`, `alert.escalate()` call failed with
/// "missing playbook"/"missing alert" — both in tests and at runtime through
/// interp.rs's stdlib dispatch hook. Prepend the receiver so the documented
/// signatures (`Playbook.execute(playbook)`, `Alert.triage(alert)`, ...) hold.
fn prepend_object(object: &Value, args: Vec<Value>) -> Vec<Value> {
    let mut full = Vec::with_capacity(args.len() + 1);
    full.push(object.clone());
    full.extend(args);
    full
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn step(name: &str, action: &str) -> Value {
        step_with_args(name, action, vec![])
    }

    fn step_with_args(name: &str, action: &str, args: Vec<Value>) -> Value {
        Value::Struct {
            name: "PlaybookStep".to_string(),
            fields: vec![
                ("name".to_string(), Value::String(name.to_string())),
                ("action".to_string(), Value::String(action.to_string())),
                ("args".to_string(), Value::Array(args)),
            ],
        }
    }

    #[test]
    fn test_playbook_compile() {
        let result = dispatch(
            "spawn",
            vec![
                Value::String("ingest".into()),
                Value::Array(vec![step("a", "fetch"), step("b", "parse")]),
            ],
        )
        .unwrap()
        .unwrap();
        let Value::Struct { name, fields } = result else {
            panic!("expected Playbook");
        };
        assert_eq!(name, "Playbook");
        assert!(matches!(get(&fields, "state"), Some(Value::String(s)) if s == "compiled"));
        if let Some(Value::Array(steps)) = get(&fields, "steps") {
            assert_eq!(steps.len(), 2);
            let Value::Struct { fields: f, .. } = &steps[0] else { panic!() };
            assert!(matches!(get(f, "status"), Some(Value::String(s)) if s == "pending"));
        }
    }

    #[test]
    fn test_playbook_compile_rejects_empty_action() {
        let bad = Value::Struct {
            name: "PlaybookStep".to_string(),
            fields: vec![
                ("name".to_string(), Value::String("x".into())),
                ("action".to_string(), Value::String("".into())),
            ],
        };
        let result = dispatch(
            "spawn",
            vec![Value::String("p".into()), Value::Array(vec![bad])],
        );
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn test_playbook_validate() {
        let pb = dispatch(
            "spawn",
            vec![
                Value::String("p".into()),
                Value::Array(vec![step("a", "fetch"), step("b", "parse")]),
            ],
        )
        .unwrap()
        .unwrap();
        let v = dispatch_method(&pb, "validate", vec![]).unwrap().unwrap();
        let Value::Struct { fields, .. } = v else { panic!() };
        assert!(matches!(get(&fields, "valid"), Some(Value::Bool(true))));
        assert!(matches!(get(&fields, "step_count"), Some(Value::Int(2))));
    }

    #[test]
    fn test_playbook_execute() {
        let pb = dispatch(
            "spawn",
            vec![
                Value::String("p".into()),
                Value::Array(vec![
                    step("a", "noop"),
                    step("b", "record"),
                    step("c", "fail"),
                ]),
            ],
        )
        .unwrap()
        .unwrap();
        let ex = dispatch_method(&pb, "execute", vec![]).unwrap().unwrap();
        let Value::Struct { name, fields } = ex else { panic!() };
        assert_eq!(name, "Playbook");
        // runtime step counter should reflect executed steps
        assert!(matches!(get(&fields, "steps_executed"), Some(Value::Int(n)) if *n >= 2));
        if let Some(Value::Array(results)) = get(&fields, "results") {
            let statuses: Vec<String> = results
                .iter()
                .filter_map(|r| {
                    if let Value::Struct { fields, .. } = r {
                        fields
                            .iter()
                            .find(|(k, _)| k == "status")
                            .map(|(_, v)| v.as_string())
                    } else {
                        None
                    }
                })
                .collect();
            assert!(statuses.contains(&"succeeded".to_string()));
            assert!(statuses.contains(&"failed".to_string()));
        }
    }

    #[test]
    fn test_playbook_execute_unsupported_action_errors() {
        // A realistic-but-unimplementable action (fetch) must produce an honest
        // not_implemented error — never a simulated success.
        let pb = dispatch(
            "spawn",
            vec![
                Value::String("p".into()),
                Value::Array(vec![step("a", "fetch")]),
            ],
        )
        .unwrap()
        .unwrap();
        let ex = dispatch_method(&pb, "execute", vec![]).unwrap();
        let msg = match ex {
            Err(m) => m,
            Ok(v) => panic!("execute must not simulate success for 'fetch'; got Ok({v:?})"),
        };
        assert!(msg.contains("does not implement"), "unexpected: {msg}");
        assert!(msg.contains("fetch"), "error should name the action: {msg}");
        assert!(msg.contains("noop"), "error should list supported actions: {msg}");
    }

    #[test]
    fn test_playbook_execute_record_honors_args() {
        // `record` must persist its args verbatim as step output — args are
        // honored end-to-end (compile keeps them, execute records them).
        let pb = dispatch(
            "spawn",
            vec![
                Value::String("p".into()),
                Value::Array(vec![step_with_args(
                    "capture",
                    "record",
                    vec![Value::String("note".into()), Value::Int(42)],
                )]),
            ],
        )
        .unwrap()
        .unwrap();
        let ex = dispatch_method(&pb, "execute", vec![]).unwrap().unwrap();
        let Value::Struct { fields, .. } = ex else { panic!() };

        // Executed steps carry the args through (not discarded).
        if let Some(Value::Array(steps)) = get(&fields, "steps") {
            let Value::Struct { fields: f, .. } = &steps[0] else { panic!() };
            assert!(matches!(get(f, "args"), Some(Value::Array(a)) if a.len() == 2));
        }

        // The StepResult has an `output` field holding the recorded args.
        if let Some(Value::Array(results)) = get(&fields, "results") {
            let Value::Struct { fields: r, .. } = &results[0] else { panic!() };
            let output = get(r, "output").expect("record step must have an output");
            let Value::Array(items) = output else { panic!("output should be an array") };
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].as_string(), "note");
            assert!(matches!(items[1], Value::Int(42)));
        }
    }

    #[test]
    fn test_playbook_execute_fail_records_reason() {
        let pb = dispatch(
            "spawn",
            vec![
                Value::String("p".into()),
                Value::Array(vec![step_with_args(
                    "x",
                    "fail",
                    vec![Value::String("denied by policy".into())],
                )]),
            ],
        )
        .unwrap()
        .unwrap();
        let ex = dispatch_method(&pb, "execute", vec![]).unwrap().unwrap();
        let Value::Struct { fields, .. } = ex else { panic!() };
        if let Some(Value::Array(results)) = get(&fields, "results") {
            let Value::Struct { fields: r, .. } = &results[0] else { panic!() };
            assert!(matches!(get(r, "status"), Some(Value::String(s)) if s == "failed"));
            assert!(
                matches!(get(r, "reason"), Some(Value::String(s)) if s == "denied by policy")
            );
        }
    }

    #[test]
    fn test_playbook_execute_noop_rejects_args() {
        let pb = dispatch(
            "spawn",
            vec![
                Value::String("p".into()),
                Value::Array(vec![step_with_args(
                    "x",
                    "noop",
                    vec![Value::String("payload".into())],
                )]),
            ],
        )
        .unwrap()
        .unwrap();
        let ex = dispatch_method(&pb, "execute", vec![]).unwrap();
        let msg = match ex {
            Err(m) => m,
            Ok(v) => panic!("noop with args must not silently discard them; got Ok({v:?})"),
        };
        assert!(msg.contains("noop"), "unexpected: {msg}");
    }

    #[test]
    fn test_alert_create_triage_escalate() {
        // FIX16: `Alert.create` was previously routed via `dispatch("Alert.create", ...)`
        // which returns None — that arm described removed fake behavior. Static
        // `Alert.create(source, severity, description)` is served by the interpreter's
        // inline handler (interp.rs), so the stdlib unit under test is `alert_create`
        // itself (severity, title, description). Triage/escalate are method calls on
        // an Alert struct and go through dispatch_method, which now prepends the
        // receiver (FIX16 impl fix).
        let alert = alert_create(vec![
            Value::String("high".into()),
            Value::String("suspicious login".into()),
            Value::String("new IP".into()),
        ])
        .unwrap();
        let Value::Struct { name, fields } = &alert else { panic!() };
        assert_eq!(name, "Alert");
        assert!(matches!(get(&fields, "severity"), Some(Value::String(s)) if s == "high"));

        let triaged = dispatch_method(&alert, "triage", vec![]).unwrap().unwrap();
        let Value::Struct { fields, .. } = &triaged else { panic!() };
        assert!(matches!(get(&fields, "priority"), Some(Value::Int(3))));

        let escalated = dispatch_method(
            &triaged,
            "escalate",
            vec![Value::String("more evidence".into())],
        )
        .unwrap()
        .unwrap();
        let Value::Struct { fields, .. } = escalated else { panic!() };
        assert!(matches!(get(&fields, "escalated"), Some(Value::Bool(true))));
        assert!(matches!(get(&fields, "status"), Some(Value::String(s)) if s == "escalated"));
        if let Some(Value::Array(trail)) = get(&fields, "escalation_trail") {
            assert_eq!(trail.len(), 1);
        }
    }

    #[test]
    fn test_await_all() {
        let p1 = dispatch(
            "spawn",
            vec![
                Value::String("a".into()),
                Value::Array(vec![step("s", "noop")]),
            ],
        )
        .unwrap()
        .unwrap();
        let p1 = dispatch_method(&p1, "execute", vec![]).unwrap().unwrap();
        let p2 = dispatch(
            "spawn",
            vec![
                Value::String("b".into()),
                Value::Array(vec![step("s2", "record")]),
            ],
        )
        .unwrap()
        .unwrap();
        let p2 = dispatch_method(&p2, "execute", vec![]).unwrap().unwrap();

        let merged = dispatch("await_all", vec![Value::Array(vec![p1, p2])])
            .unwrap()
            .unwrap();
        let Value::Struct { fields, .. } = merged else { panic!() };
        assert!(matches!(get(&fields, "playbook_count"), Some(Value::Int(2))));
        if let Some(Value::Array(results)) = get(&fields, "results") {
            assert_eq!(results.len(), 2);
        }
    }

    #[test]
    fn test_current_stats() {
        let pb = dispatch(
            "spawn",
            vec![
                Value::String("p".into()),
                Value::Array(vec![step("a", "fetch"), step("b", "parse")]),
            ],
        )
        .unwrap()
        .unwrap();
        let stats = dispatch("current_stats", vec![pb]).unwrap().unwrap();
        let Value::Struct { name, fields } = stats else { panic!() };
        assert_eq!(name, "AgentStats");
        assert!(matches!(get(&fields, "steps_executed"), Some(Value::Int(n)) if *n >= 0));
        assert!(matches!(get(&fields, "agent_id"), Some(Value::String(s)) if s == "p"));
    }

    #[test]
    fn test_unknown_function_returns_none() {
        assert!(dispatch("no_such_fn", vec![]).is_none());
        assert!(dispatch_method(&Value::Nil, "whatever", vec![]).is_none());
    }

    fn get<'a>(fields: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
        fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}
