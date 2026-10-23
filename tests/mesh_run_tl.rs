//! `Mesh.run` from Tallow source, through the shipped binary.
//!
//! The published surface is only honest if a program can name its own functions
//! as tasks and get the same checkpoints regardless of worker count. These tests
//! run the binary, not the library, for the same reason `mesh_plan_tl` does: the
//! module-registration defect lived between the router and the interpreter.

use std::process::Command;

struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(source: &str, name: &str) -> Run {
    let dir = std::env::temp_dir().join(format!("tallow-mesh-run-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join(format!("{name}.tl"));
    std::fs::write(&file, source).expect("write");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&file)
        .current_dir(&dir)
        .output()
        .expect("run tallow");
    Run {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// Declarations the real `stdlib/mesh.tl` publishes; repeated here so the test
/// exercises the same shape a program sees.
const PRELUDE: &str = r#"
struct MeshTask {
    id:              String,
    func:            String,
    deps:            []String,
    class:           String,
    idempotency_key: String?,
}

struct MeshRun {
    waves:      i64,
    committed:  i64,
    failed:     i64,
    journal:    String,
}
"#;

fn program(workers: i64, journal: &str) -> String {
    format!(
        r#"{PRELUDE}
fn alpha() -> String {{ "a" }}
fn beta() -> String {{ "b" }}
fn gamma() -> String {{ "c" }}

@legal(basis: .public_data, purpose: "mesh run test", personal_data: false)
fn main() {{
    let tasks = [
        MeshTask {{ id: "a", func: "alpha", deps: [], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "b", func: "beta",  deps: ["a"], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "c", func: "gamma", deps: ["a"], class: "pure", idempotency_key: nil }}
    ];
    let out = Mesh.run(tasks, {workers}, "{journal}", 7);
    print(out.waves);
    print(out.committed);
    print(out.failed);
}}
"#
    )
}

#[test]
fn a_plan_of_tallow_functions_runs_and_commits_each_task_once() {
    let r = run(&program(4, ".tallow/run-a.jsonl"), "happy");
    assert!(r.ok, "Mesh.run failed:\n{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.stdout.trim(), "2\n3\n0", "waves, committed, failed");
}

#[test]
fn one_worker_and_eight_workers_agree() {
    let one = run(&program(1, ".tallow/w1.jsonl"), "w1");
    let eight = run(&program(8, ".tallow/w8.jsonl"), "w8");
    assert!(one.ok && eight.ok, "runs failed:\n{}\n{}", one.stderr, eight.stderr);
    assert_eq!(
        one.stdout, eight.stdout,
        "worker count changed the observable result"
    );
}

#[test]
fn a_task_naming_a_missing_function_is_refused_before_any_work() {
    let src = format!(
        r#"{PRELUDE}
fn alpha() -> String {{ "a" }}

fn main() {{
    let tasks = [
        MeshTask {{ id: "a", func: "alpha", deps: [], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "ghost", func: "no_such_fn", deps: ["a"], class: "pure", idempotency_key: nil }}
    ];
    let out = Mesh.run(tasks, 2, ".tallow/refused.jsonl", 7);
    print(out.committed);
}}
"#
    );
    let r = run(&src, "missing");
    assert!(!r.ok, "a task naming a missing function must not run");
    assert!(
        r.stderr.contains("no_such_fn") && r.stderr.contains("not a function"),
        "the refusal must name the function:\n{}",
        r.stderr
    );
}
