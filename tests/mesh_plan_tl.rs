//! `Mesh.plan` from Tallow source, through the shipped binary.
//!
//! The Rust tests prove the planner; this proves the published surface is
//! reachable from the language — which is where the module registration bug
//! lived (`Mesh.plan(...)` was "undefined variable" even though the router knew
//! the function).

use std::process::Command;

fn run(source: &str, name: &str) -> (bool, String, String) {
    let dir = std::env::temp_dir().join(format!("tallow-mesh-tl-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join(format!("{name}.tl"));
    std::fs::write(&file, source).expect("write");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&file)
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

const PRELUDE: &str = r#"
struct MeshTask {
    id:              String,
    func:            String,
    deps:            []String,
    class:           String,
    idempotency_key: String?,
}

@legal(basis: .public_data, purpose: "mesh plan surface check", personal_data: false)
"#;

#[test]
fn plan_prints_the_wave_layout() {
    let src = format!(
        r#"{PRELUDE}
fn main() {{
    let tasks = [
        MeshTask {{ id: "a", func: "f", deps: [], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "b", func: "f", deps: ["a"], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "c", func: "f", deps: ["a"], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "d", func: "f", deps: ["b", "c"], class: "pure", idempotency_key: nil }},
    ]
    let p = Mesh.plan(tasks, 42)
    print(p.waves)
    print(p.wave_sizes)
}}
"#
    );
    let (ok, stdout, stderr) = run(&src, "plan");
    assert!(ok, "run failed\n{stdout}\n{stderr}");
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .collect();
    assert_eq!(lines, vec!["3", "[1, 2, 1]"], "{stdout}");
}

#[test]
fn a_cycle_is_refused_with_its_path() {
    let src = format!(
        r#"{PRELUDE}
fn main() {{
    let tasks = [
        MeshTask {{ id: "a", func: "f", deps: ["b"], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "b", func: "f", deps: ["a"], class: "pure", idempotency_key: nil }},
    ]
    let p = Mesh.plan(tasks, 0)
    print(p.waves)
}}
"#
    );
    let (ok, _stdout, stderr) = run(&src, "cycle");
    assert!(!ok, "a cycle must not plan");
    assert!(
        stderr.contains("->"),
        "the refusal must name the path: {stderr}"
    );
}

#[test]
fn an_io_task_without_a_key_is_refused() {
    let src = format!(
        r#"{PRELUDE}
fn main() {{
    let tasks = [
        MeshTask {{ id: "a", func: "charge", deps: [], class: "io", idempotency_key: nil }},
    ]
    let p = Mesh.plan(tasks, 0)
    print(p.waves)
}}
"#
    );
    let (ok, _stdout, stderr) = run(&src, "io");
    assert!(!ok, "an io task without a key must not plan");
    assert!(stderr.contains("idempotency key"), "{stderr}");
}
