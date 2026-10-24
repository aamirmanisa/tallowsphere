//! A refusal must leave a trace.
//!
//! When `Mesh.run` refuses a task the signed manifest does not list, and an
//! ombuds channel is configured, the refusal is appended to that channel with
//! its own signing key. This test drives the real binary and then verifies the
//! log the same way a reviewer would — with only the public half of the key.

use std::process::Command;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

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

#[test]
fn a_refused_task_is_written_to_the_ombuds_log_and_the_log_verifies() {
    use ed25519_dalek::{Signer, SigningKey};

    let dir = std::env::temp_dir().join(format!("ombuds-mesh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");

    // Manifest key and ombuds key are deliberately different keys: the point of
    // "its own credentials" is that one does not authenticate the other.
    let run_key = SigningKey::from_bytes(&[21u8; 32]);
    let ombuds_key = SigningKey::from_bytes(&[22u8; 32]);

    let purpose = "ombuds test";
    let canon = format!("{purpose}\nonly-a\ntest\n2026-01-01\n2099-01-01\na\n");
    let sig = run_key.sign(canon.as_bytes());
    let manifest = serde_json::json!({
        "purpose": purpose,
        "run_id": "only-a",
        "issued_by": "test",
        "not_before": "2026-01-01",
        "expires_at": "2099-01-01",
        "allowed_tasks": ["a"],
        "sig": hex(&sig.to_bytes()),
    });
    let manifest_path = dir.join("manifest.json");
    std::fs::write(&manifest_path, manifest.to_string()).expect("manifest");

    let key_path = dir.join("ombuds.key");
    std::fs::write(&key_path, hex(&ombuds_key.to_bytes())).expect("key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let log_path = dir.join("ombuds.jsonl");

    // Three tasks, manifest lists one: `b` is the first refusal.
    let src = format!(
        r#"{PRELUDE}
fn alpha() -> String {{ "a" }}
fn beta() -> String {{ "b" }}
fn main() {{
    let tasks = [
        MeshTask {{ id: "a", func: "alpha", deps: [], class: "pure", idempotency_key: nil }},
        MeshTask {{ id: "b", func: "beta",  deps: [], class: "pure", idempotency_key: nil }}
    ];
    let out = Mesh.run(tasks, 2, ".tallow/ombuds.jsonl", 1);
    print(out.committed);
}}
"#
    );
    let file = dir.join("run.tl");
    std::fs::write(&file, src).expect("write");

    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&file)
        .current_dir(&dir)
        .env("TALLOW_SCOPE_MANIFEST", &manifest_path)
        .env("TALLOW_SCOPE_MANIFEST_KEY", hex(&run_key.verifying_key().to_bytes()))
        .env("TALLOW_OMBUDS_LOG", &log_path)
        .env("TALLOW_OMBUDS_KEY_FILE", &key_path)
        .output()
        .expect("run tallow");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "the run must refuse: {all}");
    assert!(all.contains("'b' is not listed"), "{all}");

    // The channel now holds the refusal, verifiable with the public key alone.
    let text = std::fs::read_to_string(&log_path).expect("ombuds log must exist");
    assert!(text.contains("\"subject\":\"mesh.run\""), "{text}");
    assert!(text.contains("not listed"), "{text}");
    let n = tallow::ombuds::verify(&log_path, &hex(&ombuds_key.verifying_key().to_bytes()))
        .expect("log verifies");
    assert_eq!(n, 1, "exactly one refusal: {text}");
}

#[test]
fn without_a_channel_nothing_is_written_and_the_refusal_still_stands() {
    use ed25519_dalek::{Signer, SigningKey};
    let dir = std::env::temp_dir().join(format!("ombuds-mesh-none-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let run_key = SigningKey::from_bytes(&[31u8; 32]);
    let purpose = "ombuds test";
    let canon = format!("{purpose}\nempty\ntest\n2026-01-01\n2099-01-01\n");
    let sig = run_key.sign(canon.as_bytes());
    let manifest = serde_json::json!({
        "purpose": purpose,
        "run_id": "empty",
        "issued_by": "test",
        "not_before": "2026-01-01",
        "expires_at": "2099-01-01",
        "allowed_tasks": [],
        "sig": hex(&sig.to_bytes()),
    });
    let manifest_path = dir.join("manifest.json");
    std::fs::write(&manifest_path, manifest.to_string()).expect("manifest");

    let src = format!(
        r#"{PRELUDE}
fn alpha() -> String {{ "a" }}
fn main() {{
    let tasks = [
        MeshTask {{ id: "a", func: "alpha", deps: [], class: "pure", idempotency_key: nil }}
    ];
    let out = Mesh.run(tasks, 1, ".tallow/none.jsonl", 1);
    print(out.committed);
}}
"#
    );
    let file = dir.join("run.tl");
    std::fs::write(&file, src).expect("write");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&file)
        .current_dir(&dir)
        .env("TALLOW_SCOPE_MANIFEST", &manifest_path)
        .env("TALLOW_SCOPE_MANIFEST_KEY", hex(&run_key.verifying_key().to_bytes()))
        .env_remove("TALLOW_OMBUDS_LOG")
        .output()
        .expect("run tallow");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{all}");
    assert!(all.contains("not listed"), "{all}");
}
