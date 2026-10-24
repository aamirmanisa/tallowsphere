//! `Mesh.plan` must plan identically on both planes, for any field order the
//! program declares.
//!
//! The native lowering does not assume the stdlib's field order: codegen reads
//! the program's own `struct MeshTask`, verifies the five field types and passes
//! each field's byte offset to the FFI. These tests pin both halves of that
//! contract — a reordered declaration plans correctly, and a declaration whose
//! types the backend cannot read is refused at compile time instead of being
//! read at the wrong offsets.

use std::process::Command;

fn run(flag: &str, source: &str, tag: &str) -> (bool, Vec<String>, String) {
    let path = std::env::temp_dir().join(format!("tallow-mesh-plan-{}-{tag}.tl", std::process::id()));
    std::fs::write(&path, source).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with('*')
                && !l.starts_with("warning[")
                && !l.starts_with("runtime archive:")
                && !l.contains("--> ")
                && !l.contains('^')
                && !l.starts_with('|')
                && !(l.starts_with(|c: char| c.is_ascii_digit()) && l.contains(" | "))
        })
        .map(str::to_string)
        .collect();
    (out.status.success(), lines, text)
}

fn program(fields: &str, body: &str) -> String {
    format!(
        r#"import tallow.mesh

struct MeshTask {{
{fields}
}}

fn main() {{
{body}
}}
"#
    )
}

const CANONICAL: &str = r#"    id: String,
    func: String,
    deps: []String,
    class: String,
    idempotency_key: String?,"#;

const REORDERED: &str = r#"    class: String,
    deps: []String,
    id: String,
    idempotency_key: String?,
    func: String,"#;

const BODY: &str = r#"    let tasks = [
        MeshTask { class: "pure", deps: [], id: "a", idempotency_key: nil, func: "fa" },
        MeshTask { class: "io", deps: ["a"], id: "b", idempotency_key: "k-b", func: "fb" },
        MeshTask { class: "pure", deps: ["b"], id: "c", idempotency_key: nil, func: "fc" },
        MeshTask { class: "pure", deps: [], id: "d", idempotency_key: nil, func: "fd" }
    ]
    let p = Mesh.plan(tasks, 42)
    print("waves=" + p.waves)
    print("tasks=" + p.tasks)
    print("seed=" + p.seed)
    print("sizes=" + p.wave_sizes.len)
    print("w0=" + p.wave_sizes[0])
    print("w1=" + p.wave_sizes[1])
    print("w2=" + p.wave_sizes[2])"#;

const EXPECTED: [&str; 7] = [
    "waves=3",
    "tasks=4",
    "seed=42",
    "sizes=3",
    "w0=2",
    "w1=1",
    "w2=1",
];

#[test]
fn plan_matches_on_both_planes_with_the_canonical_declaration() {
    let source = program(CANONICAL, BODY);
    let (interp_ok, interp, _) = run("--interpret", &source, "interp-canon");
    assert!(interp_ok, "interpreter leg failed: {interp:?}");
    let (native_ok, native, _) = run("--require-native", &source, "native-canon");
    assert!(native_ok, "compiled leg failed: {native:?}");
    assert_eq!(native, interp, "planes disagree:\nnative={native:?}\ninterp={interp:?}");
    assert_eq!(native, EXPECTED.to_vec());
}

#[test]
fn plan_matches_on_both_planes_when_the_program_reorders_the_fields() {
    // The lowering must follow the program's declaration, not the stdlib's.
    let source = program(REORDERED, BODY);
    let (interp_ok, interp, _) = run("--interpret", &source, "interp-reorder");
    assert!(interp_ok, "interpreter leg failed: {interp:?}");
    let (native_ok, native, _) = run("--require-native", &source, "native-reorder");
    assert!(native_ok, "compiled leg failed: {native:?}");
    assert_eq!(native, interp, "planes disagree on a reordered struct:\nnative={native:?}\ninterp={interp:?}");
    assert_eq!(native, EXPECTED.to_vec());
}

#[test]
fn a_declaration_the_backend_cannot_read_is_refused_by_name() {
    // `deps: String` would be read as an array pointer — refuse instead.
    let bad_fields = r#"    id: String,
    func: String,
    deps: String,
    class: String,
    idempotency_key: String?,"#;
    let source = program(bad_fields, BODY);
    let (ok, _lines, raw) = run("--require-native", &source, "native-bad");
    assert!(!ok, "a mis-typed deps field must not build: {raw}");
    assert!(
        raw.contains("Mesh.plan") && raw.contains("deps"),
        "the refusal must name the field, got: {raw}"
    );
}

// ───────────────────────────── Mesh.replay ──────────────────────────────────

const TASK_STRUCT: &str = r#"struct MeshTask {
    id: String,
    func: String,
    deps: []String,
    class: String,
    idempotency_key: String?,
}

struct MeshRun {
    waves: i64,
    committed: i64,
    failed: i64,
    journal: String,
}

struct WaveCheckpoint {
    wave: i64,
    tasks: i64,
    checkpoint: String,
}

struct MeshReplay {
    waves: i64,
    ok: bool,
    checkpoints: []WaveCheckpoint,
}
"#;

fn journal_program(journal: &str) -> String {
    format!(
        r#"import tallow.mesh

{TASK_STRUCT}
fn alpha() -> String {{ "a" }}
fn beta() -> String {{ "b" }}
fn gamma() -> String {{ "c" }}

@legal(basis: .public_data, purpose: "mesh replay fixture", personal_data: false)
fn main() {{
    let tasks = [
        MeshTask {{ id: "a", func: "alpha", deps: [], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "b", func: "beta", deps: ["a"], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "c", func: "gamma", deps: ["a"], class: "pure", idempotency_key: nil }}
    ]
    let out = Mesh.run(tasks, 4, "{journal}", 7)
    print("waves=" + out.waves)
    print("committed=" + out.committed)
}}
"#
    )
}

fn replay_program(journal: &str) -> String {
    format!(
        r#"import tallow.mesh

{TASK_STRUCT}
fn main() {{
    let r = Mesh.replay("{journal}")
    print("waves=" + r.waves)
    if r.ok {{ print("ok=true") }} else {{ print("ok=false") }}
    print("checks=" + r.checkpoints.len)
    print("cp0_wave=" + r.checkpoints[0].wave)
    print("cp0_tasks=" + r.checkpoints[0].tasks)
    print("cp0_len=" + r.checkpoints[0].checkpoint.len)
    print("cp1_wave=" + r.checkpoints[1].wave)
}}
"#
    )
}

#[test]
fn replay_matches_on_both_planes_for_a_journal_the_runtime_wrote() {
    // The journal must come from the real execution plane, never be hand-built.
    let dir = std::env::temp_dir().join(format!("tallow-mesh-replay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let journal = dir.join("journal.jsonl");
    let journal_str = journal.display().to_string();

    let (produced, out, raw) = run("--interpret", &journal_program(&journal_str), "producer");
    assert!(produced, "Mesh.run failed: {raw}");
    assert!(
        out.contains(&"waves=2".to_string()) && out.contains(&"committed=3".to_string()),
        "the plan must run 2 waves and commit 3 tasks, got {out:?}"
    );
    assert!(journal.exists(), "Mesh.run must write the journal it reports");

    let source = replay_program(&journal_str);
    let (interp_ok, interp, interp_raw) = run("--interpret", &source, "replay-interp");
    assert!(interp_ok, "interpreter replay failed: {interp_raw}");
    let (native_ok, native, native_raw) = run("--require-native", &source, "replay-native");
    assert!(native_ok, "compiled replay failed: {native_raw}");
    assert_eq!(
        native, interp,
        "planes disagree on MeshReplay:\nnative={native:?}\ninterp={interp:?}"
    );
    assert_eq!(
        native,
        vec![
            "waves=2".to_string(),
            "ok=true".to_string(),
            "checks=2".to_string(),
            "cp0_wave=0".to_string(),
            "cp0_tasks=1".to_string(),
            "cp0_len=64".to_string(),
            "cp1_wave=1".to_string(),
        ]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn replay_of_a_missing_journal_is_refused_on_the_compiled_plane() {
    let missing = std::env::temp_dir().join(format!(
        "tallow-mesh-missing-{}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&missing);
    let source = replay_program(&missing.display().to_string());
    let (ok, _lines, raw) = run("--require-native", &source, "replay-missing");
    assert!(!ok, "a missing journal must not replay: {raw}");
    assert!(
        raw.contains("Mesh.replay") || raw.contains("journal"),
        "the refusal must name the journal, got: {raw}"
    );
}
