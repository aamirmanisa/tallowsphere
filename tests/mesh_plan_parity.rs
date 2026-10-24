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
