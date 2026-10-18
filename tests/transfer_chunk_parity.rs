//! Native/interpreter parity for `Transfer.chunk` / `tree_hash` / `manifest`.
//!
//! Register #86: the native backend refused these by name because "the value
//! model has no struct". The model does have structs; what was missing was the
//! marshalling — a runtime that fills `%struct.ChunkInfo` records and codegen
//! that reads them back. This test pins the whole path end to end, on a file
//! written by the test itself so the chunk boundaries are fixed:
//!
//!   10 000 bytes at 4 000 per chunk -> three chunks, 4000 / 4000 / 2000.
//!
//! Two failure modes are covered that a plain "does it run" check misses:
//! `cs.len()` on a native array reads the count slot (strlen on the same
//! buffer answers 1), and `cs[i].field` GEPs into the record (it used to fall
//! through to a literal 0). Both were silent, so both are asserted explicitly.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tallow_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("TALLOW_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    // Newest wins: a stale release binary would testify about an older tree.
    let release = repo_root().join("target/release/tallow");
    let debug = repo_root().join("target/debug/tallow");
    let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(&release), mtime(&debug)) {
        (Some(r), Some(d)) if r >= d => release,
        (Some(_), Some(_)) => debug,
        (Some(_), None) => release,
        (None, Some(_)) => debug,
        (None, None) => debug,
    }
}

struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[String]) -> Out {
    let out = Command::new(tallow_bin())
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("spawn tallow");
    Out {
        rc: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn run_interp(file: &Path) -> Out {
    run(&["run".into(), "--interpret".into(), file.display().to_string()])
}

fn run_native(file: &Path) -> Out {
    run(&[
        "run".into(),
        "--require-native".into(),
        file.display().to_string(),
    ])
}

/// Deterministic 10 000-byte payload: byte i is `(i * 31 + 7) % 251`, so the
/// content is not compressible into identical chunks by accident.
fn write_payload(path: &Path) {
    let data: Vec<u8> = (0..10_000u32)
        .map(|i| ((i * 31 + 7) % 251) as u8)
        .collect();
    std::fs::write(path, data).expect("write payload");
}

fn work_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow_chunk_parity_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create work dir");
    dir
}

#[test]
fn transfer_chunk_and_tree_hash_agree_across_engines() {
    let dir = work_dir();
    let payload = dir.join("payload.bin");
    write_payload(&payload);
    let prog = dir.join("chunk.tl");
    std::fs::write(
        &prog,
        format!(
            r#"fn main() {{
    let cs = Transfer.chunk("{path}", 4000)
    print(cs.len().to_string())
    print(cs[0].size.to_string())
    print(cs[1].offset.to_string())
    print(cs[2].size.to_string())
    print(cs[0].index.to_string())
    print(cs[1].hash)
    print(cs[2].hash)
    print(Transfer.tree_hash(cs))
}}
"#,
            path = payload.display()
        ),
    )
    .expect("write program");

    let interp = run_interp(&prog);
    assert_eq!(interp.rc, 0, "interpreter leg failed: {}", interp.stderr);

    let native = run_native(&prog);
    assert_eq!(native.rc, 0, "native leg failed: {}", native.stderr);
    assert!(
        !native.stderr.contains("native build unavailable"),
        "native leg fell back to the interpreter: {}",
        native.stderr
    );

    let lines: Vec<&str> = native.stdout.lines().map(|l| l.trim()).collect();
    assert_eq!(
        &lines[..5],
        &["3", "4000", "4000", "2000", "0"],
        "chunk count, sizes and offsets must come from the records"
    );
    assert_eq!(lines[5].len(), 64, "hash must be a 64-char blake3 hex");
    assert_ne!(lines[5], lines[6], "different data must hash differently");
    assert_eq!(lines[7].len(), 64, "tree root must be a 64-char hex");

    assert_eq!(
        native.stdout, interp.stdout,
        "engines must agree byte for byte"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn transfer_manifest_matches_except_timestamp() {
    let dir = work_dir();
    let payload = dir.join("payload2.bin");
    write_payload(&payload);
    let prog = dir.join("manifest.tl");
    std::fs::write(
        &prog,
        format!(
            r#"fn main() {{
    let cs = Transfer.chunk("{path}", 4000)
    print(Transfer.manifest("deadbeef", 10000, cs))
}}
"#,
            path = payload.display()
        ),
    )
    .expect("write program");

    let interp = run_interp(&prog);
    assert_eq!(interp.rc, 0, "interpreter leg failed: {}", interp.stderr);
    let native = run_native(&prog);
    assert_eq!(native.rc, 0, "native leg failed: {}", native.stderr);

    // `timestamp` is wall-clock seconds; everything before it is content.
    let head = |s: &str| -> String {
        s.split("\"timestamp\"")
            .next()
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    assert_eq!(
        head(&native.stdout),
        head(&interp.stdout),
        "manifest content must match; only the timestamp may differ"
    );
    assert!(
        native.stdout.contains("\"chunk_count\":3"),
        "manifest must report the real chunk count: {}",
        native.stdout
    );

    let _ = std::fs::remove_dir_all(&dir);
}
