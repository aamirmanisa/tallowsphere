//! CLI smoke — drives the real `tallow-registry` binary end-to-end: init,
//! mint ×2, revoke, list, receipts query, verify-ledger, then a tamper check
//! that must exit 3.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};

use tallow_registry::Receipt;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tallow-registry")
}

fn dev_pub_hex(name: &str) -> String {
    hex::encode(
        tallow_admission::device_identity(name)
            .ed
            .verifying_key()
            .to_bytes(),
    )
}

struct Cli {
    registry: PathBuf,
    ledger: PathBuf,
}

impl Cli {
    fn run(&self, args: &[&str]) -> std::process::Output {
        let mut full: Vec<String> = vec![
            "--registry".into(),
            self.registry.display().to_string(),
            "--ledger".into(),
            self.ledger.display().to_string(),
        ];
        full.extend(args.iter().map(|s| s.to_string()));
        Command::new(bin()).args(&full).output().expect("spawn cli")
    }
}

#[test]
fn cli_end_to_end() {
    let mut dir = std::env::temp_dir();
    dir.push(format!("tallow-registry-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");

    let cli = Cli {
        registry: dir.join("registry.json"),
        ledger: dir.join("receipts.jsonl"),
    };

    // init
    let out = cli.run(&["init"]);
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(cli.registry.exists() && cli.ledger.exists());

    // mint ×2 + revoke (one each, receipts written)
    for (id, role) in [("operator-1", "owner"), ("guest-1", "guest")] {
        let pub_hex = dev_pub_hex(id);
        let out = cli.run(&["mint", "--id", id, "--role", role, "--ed-pub-hex", &pub_hex]);
        assert!(
            out.status.success(),
            "mint {id} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = cli.run(&["revoke", "--id", "guest-1"]);
    assert!(
        out.status.success(),
        "revoke failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // list --json
    let out = cli.run(&["list", "--json"]);
    assert!(out.status.success());
    let doc: Value = serde_json::from_slice(&out.stdout).expect("list json");
    let devices = doc["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 2);
    let guest = devices
        .iter()
        .find(|d| d["id"] == json!("guest-1"))
        .expect("guest row");
    assert_eq!(guest["status"], json!("revoked"));
    let op = devices
        .iter()
        .find(|d| d["id"] == json!("operator-1"))
        .expect("op row");
    assert_eq!(op["status"], json!("active"));

    // receipts --json → 3 canonical lines, linked chain
    let out = cli.run(&["receipts", "--json"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("utf8");
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 3, "three receipts");
    let r1 = Receipt::from_line(lines[0]).expect("r1");
    let r2 = Receipt::from_line(lines[1]).expect("r2");
    let r3 = Receipt::from_line(lines[2]).expect("r3");
    assert_eq!((r1.seq, r2.seq, r3.seq), (1, 2, 3));
    assert_eq!(r1.kind, "device.mint");
    assert_eq!(r3.kind, "device.revoke");
    assert_eq!(r2.prev.as_deref(), Some(r1.digest_hex().as_str()));
    assert_eq!(r3.prev.as_deref(), Some(r2.digest_hex().as_str()));

    // verify-ledger → ok
    let out = cli.run(&["verify-ledger", "--json"]);
    assert!(out.status.success(), "verify must pass");
    let v: Value = serde_json::from_slice(&out.stdout).expect("verdict json");
    assert_eq!(v["ok"], json!(true));
    assert_eq!(v["rows"], json!(3));

    // tamper the ledger file (row 2 subject) → verify must exit 3
    let text = std::fs::read_to_string(&cli.ledger).expect("read ledger");
    let doctored = text.replacen("guest-1", "guest-9", 1);
    assert_ne!(text, doctored, "tamper should change the file");
    std::fs::write(&cli.ledger, doctored).expect("write doctored");
    let out = cli.run(&["verify-ledger"]);
    assert_eq!(out.status.code(), Some(3), "tampered ledger must exit 3");

    let _ = std::fs::remove_dir_all(&dir);
}
