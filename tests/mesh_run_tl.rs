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

// ── Signed scope manifest ────────────────────────────────────────────────────
//
// `Mesh.run` refuses a task id the run's signed manifest does not list. The
// manifest is Ed25519 over a fixed canonical byte string, so this test signs one
// the same way an operator would and checks both directions: listed tasks run,
// an unlisted one is refused by name.

use ed25519_dalek::{Signer, SigningKey};

fn manifest_json(run_id: &str, tasks: &[&str], key: &SigningKey) -> (String, String) {
    let purpose = "mesh run test";
    let issued_by = "test";
    let not_before = "2026-01-01";
    let expires_at = "2099-01-01";
    let mut canon = format!("{purpose}\n{run_id}\n{issued_by}\n{not_before}\n{expires_at}\n");
    for t in tasks {
        canon.push_str(t);
        canon.push('\n');
    }
    let sig = key.sign(canon.as_bytes());
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let json = serde_json::json!({
        "purpose": purpose,
        "run_id": run_id,
        "issued_by": issued_by,
        "not_before": not_before,
        "expires_at": expires_at,
        "allowed_tasks": tasks,
        "sig": hex(&sig.to_bytes()),
    });
    (json.to_string(), hex(&key.verifying_key().to_bytes()))
}

fn run_with_manifest(source: &str, name: &str, manifest: &str, key: &str) -> Run {
    let dir = std::env::temp_dir().join(format!("tallow-mesh-manifest-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join(format!("{name}.tl"));
    std::fs::write(&file, source).expect("write");
    let man = dir.join("manifest.json");
    std::fs::write(&man, manifest).expect("manifest");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&file)
        .current_dir(&dir)
        .env("TALLOW_SCOPE_MANIFEST", &man)
        .env("TALLOW_SCOPE_MANIFEST_KEY", key)
        .output()
        .expect("run tallow");
    Run {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

#[test]
fn a_signed_manifest_authorizes_listed_tasks_and_refuses_others_by_name() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let journal = ".tallow/manifest-run.jsonl";

    // Listed: the run proceeds.
    let (man, pubkey) = manifest_json("run-1", &["a", "b", "c"], &key);
    let r = run_with_manifest(&program(2, journal), "listed", &man, &pubkey);
    assert!(r.ok, "listed run failed: {}{}", r.stdout, r.stderr);

    // Not listed: refused, and the refusal names the task and the run.
    let (man, pubkey) = manifest_json("run-2", &["a", "b"], &key);
    let r = run_with_manifest(&program(2, journal), "unlisted", &man, &pubkey);
    assert!(!r.ok, "an unlisted task must refuse the run: {}", r.stdout);
    let all = format!("{}{}", r.stdout, r.stderr);
    assert!(all.contains("not listed as authorized"), "{all}");
    assert!(all.contains("'c'"), "the refusal names the task: {all}");
    assert!(all.contains("run-2"), "the refusal names the run: {all}");
}

#[test]
fn an_expired_manifest_authorizes_nothing() {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let purpose = "mesh run test";
    let canon = format!("{purpose}\nrun-old\ntest\n2025-01-01\n2026-01-01\na\nb\nc\n");
    let sig = key.sign(canon.as_bytes());
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let man = serde_json::json!({
        "purpose": purpose,
        "run_id": "run-old",
        "issued_by": "test",
        "not_before": "2025-01-01",
        "expires_at": "2026-01-01",
        "allowed_tasks": ["a", "b", "c"],
        "sig": hex(&sig.to_bytes()),
    })
    .to_string();
    let pubkey = hex(&key.verifying_key().to_bytes());
    let r = run_with_manifest(&program(2, ".tallow/expired.jsonl"), "expired", &man, &pubkey);
    assert!(!r.ok, "an expired manifest must refuse: {}", r.stdout);
    let all = format!("{}{}", r.stdout, r.stderr);
    assert!(all.contains("expired on 2026-01-01"), "{all}");
}
