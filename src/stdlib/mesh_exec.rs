//! Standard library: `tallow.mesh` execution surface — the part that is real.
//!
//! This module exposes exactly two things to Tallow programs:
//!
//! - `Mesh.plan(tasks, seed)` — the deterministic wave plan. Pure graph work:
//!   it validates task classes, rejects cycles by name, and returns the wave
//!   layout. Anything a caller does with it is reproducible.
//! - `Mesh.replay(path)` — verify a run journal against its own recorded
//!   checkpoints and report the first wave that disagrees.
//!
//! `Mesh.run` is implemented in `interp.rs`, not here: it executes functions of
//! the calling program, so it needs the interpreter that owns them. The
//! dispatcher in this module is stateless by design and could not reach them.

use super::StdlibResult;
use crate::interp::{type_name, Value};
use crate::mesh::{plan as mesh_plan, Task, TaskClass};

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "plan" => Some(do_plan(args)),
        "replay" => Some(do_replay(args)),
        _ => None,
    }
}

fn field<'a>(fields: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

fn class_from(name: &str) -> TaskClass {
    match name {
        "io" => TaskClass::Io,
        "llm" => TaskClass::Llm,
        _ => TaskClass::Pure,
    }
}

pub(crate) fn task_from_value(v: &Value) -> Result<Task, String> {
    let Value::Struct { name, fields } = v else {
        return Err(format!("Mesh.plan: expected a MeshTask struct, got {}", type_name(v)));
    };
    if name != "MeshTask" {
        return Err(format!("Mesh.plan: expected MeshTask, got {name}"));
    }
    let id = field(fields, "id").map(Value::as_string).unwrap_or_default();
    let func = field(fields, "func").map(Value::as_string).unwrap_or_default();
    let class = field(fields, "class")
        .map(Value::as_string)
        .unwrap_or_else(|| "pure".to_string());
    let deps: Vec<String> = match field(fields, "deps") {
        Some(Value::Array(items)) => items.iter().map(Value::as_string).collect(),
        Some(Value::Nil) | None => Vec::new(),
        Some(other) => return Err(format!("Mesh.plan: deps must be []String, got {}", type_name(other))),
    };
    let key = field(fields, "idempotency_key").and_then(|v| match v {
        Value::Nil => None,
        other => Some(other.as_string()),
    });
    Ok(Task {
        id,
        func,
        deps,
        class: class_from(&class),
        idempotency_key: key,
    })
}

fn do_plan(args: Vec<Value>) -> StdlibResult {
    let items = match args.first() {
        Some(Value::Array(items)) => items,
        Some(other) => return Err(format!("Mesh.plan: expected []MeshTask, got {}", type_name(other))),
        None => return Err("Mesh.plan: expected []MeshTask".to_string()),
    };
    let seed = match args.get(1) {
        Some(Value::Int(n)) => *n as u64,
        Some(_) => 0,
        None => 0,
    };
    let mut tasks = Vec::with_capacity(items.len());
    for item in items {
        tasks.push(task_from_value(item)?);
    }
    let waves = mesh_plan(&tasks).map_err(|e| format!("Mesh.plan: {e}"))?;
    let sizes: Vec<Value> = waves
        .iter()
        .map(|w| Value::Int(w.tasks.len() as i128))
        .collect();
    Ok(Value::Struct {
        name: "MeshPlan".to_string(),
        fields: vec![
            ("waves".to_string(), Value::Int(waves.len() as i128)),
            ("tasks".to_string(), Value::Int(tasks.len() as i128)),
            ("seed".to_string(), Value::Int(seed as i128)),
            ("wave_sizes".to_string(), Value::Array(sizes)),
        ],
    })
}

fn do_replay(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(v) => v.as_string(),
        None => return Err("Mesh.replay: expected a journal path".to_string()),
    };
    let waves = crate::mesh::journal::replay(&path).map_err(|e| format!("Mesh.replay: {e}"))?;
    let checkpoints: Vec<Value> = waves
        .iter()
        .map(|w| {
            Value::Struct {
                name: "WaveCheckpoint".to_string(),
                fields: vec![
                    ("wave".to_string(), Value::Int(w.wave as i128)),
                    ("tasks".to_string(), Value::Int(w.tasks as i128)),
                    ("checkpoint".to_string(), Value::String(w.checkpoint.clone())),
                ],
            }
        })
        .collect();
    Ok(Value::Struct {
        name: "MeshReplay".to_string(),
        fields: vec![
            ("waves".to_string(), Value::Int(waves.len() as i128)),
            ("ok".to_string(), Value::Bool(true)),
            ("checkpoints".to_string(), Value::Array(checkpoints)),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, deps: &[&str], class: &str, key: Option<&str>) -> Value {
        Value::Struct {
            name: "MeshTask".to_string(),
            fields: vec![
                ("id".to_string(), Value::String(id.to_string())),
                ("func".to_string(), Value::String("f".to_string())),
                ("class".to_string(), Value::String(class.to_string())),
                (
                    "deps".to_string(),
                    Value::Array(deps.iter().map(|d| Value::String(d.to_string())).collect()),
                ),
                (
                    "idempotency_key".to_string(),
                    key.map(|k| Value::String(k.to_string())).unwrap_or(Value::Nil),
                ),
            ],
        }
    }

    #[test]
    fn plan_shapes_a_diamond_into_three_waves() {
        let tasks = Value::Array(vec![
            task("a", &[], "pure", None),
            task("b", &["a"], "pure", None),
            task("c", &["a"], "pure", None),
            task("d", &["b", "c"], "pure", None),
        ]);
        let out = dispatch("plan", vec![tasks, Value::Int(42)]).unwrap().unwrap();
        let Value::Struct { name, fields } = out else { panic!("expected struct") };
        assert_eq!(name, "MeshPlan");
        match field(&fields, "waves").unwrap() {
            Value::Int(n) => assert_eq!(*n, 3),
            other => panic!("waves: {}", type_name(other)),
        }
        match field(&fields, "tasks").unwrap() {
            Value::Int(n) => assert_eq!(*n, 4),
            other => panic!("tasks: {}", type_name(other)),
        }
        match field(&fields, "wave_sizes").unwrap() {
            Value::Array(s) => {
                let v: Vec<i128> = s.iter().filter_map(|x| match x { Value::Int(n) => Some(*n), _ => None }).collect();
                assert_eq!(v, vec![1, 2, 1]);
            }
            other => panic!("wave_sizes: {}", type_name(other)),
        }
    }

    #[test]
    fn plan_refuses_a_cycle_by_name() {
        let tasks = Value::Array(vec![
            task("a", &["b"], "pure", None),
            task("b", &["a"], "pure", None),
        ]);
        let err = dispatch("plan", vec![tasks, Value::Int(0)]).unwrap().unwrap_err();
        assert!(err.contains(" -> "), "{err}");
    }

    #[test]
    fn plan_refuses_an_io_task_without_a_key() {
        let tasks = Value::Array(vec![task("a", &[], "io", None)]);
        let err = dispatch("plan", vec![tasks, Value::Int(0)]).unwrap().unwrap_err();
        assert!(err.contains("idempotency key"), "{err}");
    }

    #[test]
    fn replay_reports_an_unreadable_journal_as_an_error() {
        let err = dispatch("replay", vec![Value::String("/nonexistent/journal.jsonl".into())])
            .unwrap()
            .unwrap_err();
        assert!(err.contains("Mesh.replay"), "{err}");
    }
}
