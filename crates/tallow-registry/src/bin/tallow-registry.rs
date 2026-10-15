//! `tallow-registry` — local fleet-registry + receipts CLI (v1 skeleton).
//!
//! ```text
//! Usage: tallow-registry --registry <R> --ledger <L> [--key <K>] [--actor <A>] <verb> [args]
//!
//!   init                                    create registry + ledger files if missing
//!   mint --id ID --role R --ed-pub-hex HEX [--notes N]
//!                                           upsert a device; writes a device.mint receipt
//!   revoke --id ID                          revoke; writes a device.revoke receipt
//!   list [--json]                           print the registry
//!   receipts [--kind K] [--actor A] [--subject S] [--limit N] [--json]
//!                                           query the ledger (limit = last N)
//!   verify-ledger [--json]                  verify chain + signatures (exit 3 if broken)
//!
//!   --key <K>   JSON {"seed_hex": "<64 hex>"} Ed25519 actor key; default = DEV key
//!               (deterministic test material — loud warning)
//! ```
//!
//! Everything is local; no service is started (the v1 "registry service" is
//! this file-based CLI shape).

use std::collections::HashMap;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use serde_json::json;

use tallow_registry::ledger::{Ledger, Query};
use tallow_registry::receipt::{dev_actor_key, Receipt};
use tallow_registry::store::RegistryStore;

fn die(msg: &str) -> ! {
    eprintln!("tallow-registry: {msg}");
    std::process::exit(1);
}

fn usage() -> ! {
    eprintln!(
        "tallow-registry {}\n\
         Usage: tallow-registry --registry <R> --ledger <L> [--key <K>] [--actor <A>] <verb> [args]\n\
         Verbs: init | mint --id ID --role R --ed-pub-hex HEX [--notes N] | revoke --id ID\n\
         \x20      list [--json] | receipts [--kind K] [--limit N] [--json] | verify-ledger [--json]\n",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2);
}

fn load_key(path: &str) -> SigningKey {
    #[derive(serde::Deserialize)]
    struct KeyFile {
        seed_hex: String,
    }
    let data =
        std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("key: read {path}: {e}")));
    let f: KeyFile =
        serde_json::from_str(&data).unwrap_or_else(|e| die(&format!("key: bad JSON: {e}")));
    let raw = hex::decode(&f.seed_hex).unwrap_or_else(|e| die(&format!("key: bad hex: {e}")));
    let arr: [u8; 32] = raw
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| die(&format!("key: expected 32 bytes, got {}", v.len())));
    SigningKey::from_bytes(&arr)
}

fn short(digest: &str) -> &str {
    &digest[..16]
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        usage();
    }
    if argv.iter().any(|a| a == "--version") {
        println!("tallow-registry {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let known = [
        "registry",
        "ledger",
        "key",
        "actor",
        "id",
        "role",
        "ed-pub-hex",
        "notes",
        "kind",
        "subject",
        "limit",
        "json",
    ];
    let mut map: HashMap<String, String> = HashMap::new();
    let mut pos: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(name) = a.strip_prefix("--") {
            if name == "json" {
                map.insert("json".into(), "true".into());
                i += 1;
                continue;
            }
            if !known.contains(&name) {
                die(&format!("unknown flag --{name} (try --help)"));
            }
            let val = argv
                .get(i + 1)
                .unwrap_or_else(|| die(&format!("--{name} needs a value")));
            map.insert(name.into(), val.clone());
            i += 2;
        } else {
            pos.push(a.clone());
            i += 1;
        }
    }

    let verb = pos.first().cloned().unwrap_or_else(|| usage());
    let registry_path = PathBuf::from(
        map.get("registry")
            .cloned()
            .unwrap_or_else(|| die("--registry is required")),
    );
    let ledger_path = PathBuf::from(
        map.get("ledger")
            .cloned()
            .unwrap_or_else(|| die("--ledger is required")),
    );
    let (key, is_dev) = match map.get("key") {
        Some(p) => (load_key(p), false),
        None => (dev_actor_key(), true),
    };
    if is_dev {
        eprintln!(
            "tallow-registry: WARNING: DEV actor key in use (deterministic test material) — pass --key for real material"
        );
    }
    let actor = map
        .get("actor")
        .cloned()
        .unwrap_or_else(|| "anchor-0".into());
    let led = Ledger::new(&ledger_path);
    let json_out = map.contains_key("json");

    match verb.as_str() {
        "init" => {
            let store = RegistryStore::init(&registry_path).unwrap_or_else(|e| die(&e.to_string()));
            if !ledger_path.exists() {
                std::fs::write(&ledger_path, "").unwrap_or_else(|e| die(&e.to_string()));
            }
            println!(
                "init ok: registry {} ({} devices), ledger {}",
                registry_path.display(),
                store.devices().len(),
                ledger_path.display()
            );
        }

        "mint" => {
            let id = map
                .get("id")
                .cloned()
                .unwrap_or_else(|| die("mint needs --id"));
            let role = map
                .get("role")
                .cloned()
                .unwrap_or_else(|| die("mint needs --role"));
            let ed = map
                .get("ed-pub-hex")
                .cloned()
                .unwrap_or_else(|| die("mint needs --ed-pub-hex"));
            let notes = map.get("notes").cloned();
            let mut store =
                RegistryStore::load(&registry_path).unwrap_or_else(|e| die(&e.to_string()));
            store
                .upsert(&id, &role, "active", &ed, notes)
                .unwrap_or_else(|e| die(&e.to_string()));
            store.save().unwrap_or_else(|e| die(&e.to_string()));
            let receipt = Receipt::sign_new(
                led.next_seq().unwrap_or_else(|e| die(&e.to_string())),
                "device.mint",
                &actor,
                Some(&id),
                json!({"role": role, "ed_pub_hex": ed}),
                led.next_prev().unwrap_or_else(|e| die(&e.to_string())),
                &key,
            );
            led.append(&receipt).unwrap_or_else(|e| die(&e.to_string()));
            println!(
                "minted {id} (role={role}, status=active) — receipt #{} digest={}",
                receipt.seq,
                short(&receipt.digest_hex())
            );
        }

        "revoke" => {
            let id = map
                .get("id")
                .cloned()
                .unwrap_or_else(|| die("revoke needs --id"));
            let mut store =
                RegistryStore::load(&registry_path).unwrap_or_else(|e| die(&e.to_string()));
            let prev_status = store
                .get(&id)
                .map(|r| r.status.clone())
                .unwrap_or_else(|| die(&format!("unknown device: {id}")));
            store.revoke(&id).unwrap_or_else(|e| die(&e.to_string()));
            store.save().unwrap_or_else(|e| die(&e.to_string()));
            let receipt = Receipt::sign_new(
                led.next_seq().unwrap_or_else(|e| die(&e.to_string())),
                "device.revoke",
                &actor,
                Some(&id),
                json!({"prev_status": prev_status}),
                led.next_prev().unwrap_or_else(|e| die(&e.to_string())),
                &key,
            );
            led.append(&receipt).unwrap_or_else(|e| die(&e.to_string()));
            println!(
                "revoked {id} — receipt #{} digest={}",
                receipt.seq,
                short(&receipt.digest_hex())
            );
        }

        "list" => {
            let store = RegistryStore::load(&registry_path).unwrap_or_else(|e| die(&e.to_string()));
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&store.to_value()).expect("json")
                );
            } else {
                for row in store.devices() {
                    println!(
                        "{}\t{}\t{}\t{}",
                        row.id,
                        row.role,
                        row.status,
                        short(&row.ed_pub_hex)
                    );
                }
                println!("({} devices)", store.devices().len());
            }
        }

        "receipts" => {
            let q = Query {
                kind: map.get("kind").cloned(),
                actor: map.get("actor").cloned(),
                subject: map.get("subject").cloned(),
                limit: map.get("limit").map(|l| {
                    l.parse()
                        .unwrap_or_else(|_| die("--limit must be a number"))
                }),
            };
            let rows = led.query(&q).unwrap_or_else(|e| die(&e.to_string()));
            if json_out {
                for r in &rows {
                    println!("{}", r.to_line());
                }
            } else {
                for r in &rows {
                    println!(
                        "#{}\t{}\tactor={}\tsubject={}\tdigest={}",
                        r.seq,
                        r.kind,
                        r.actor,
                        r.subject.as_deref().unwrap_or("-"),
                        short(&r.digest_hex())
                    );
                }
                println!("({} receipts)", rows.len());
            }
        }

        "verify-ledger" => {
            if !ledger_path.exists() {
                eprintln!(
                    "tallow-registry: note: no ledger file at {} (verifying as empty)",
                    ledger_path.display()
                );
            }
            let verdict = led.verify(&key.verifying_key());
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "rows": verdict.rows,
                        "ok": verdict.ok(),
                        "errors": verdict.errors,
                    }))
                    .expect("json")
                );
            } else {
                println!(
                    "ledger {}: {} rows, {}",
                    ledger_path.display(),
                    verdict.rows,
                    if verdict.ok() {
                        "OK (chain + signatures verified)"
                    } else {
                        "BROKEN"
                    }
                );
                for e in &verdict.errors {
                    println!("  - {e}");
                }
            }
            if !verdict.ok() {
                std::process::exit(3);
            }
        }

        other => die(&format!("unknown verb {other:?} (try --help)")),
    }
}
