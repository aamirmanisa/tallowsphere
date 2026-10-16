//! `tallow pin` — manage the peer pin registry (pin + registry-verify arc).
//!
//! ```text
//! tallow pin --pins <P> --ledger <L> [--key <K>] [--actor <A>]
//!            add <id> --kind identity|spki [--source operator|qr|oob|self] [--notes N]
//! tallow pin --pins <P> list [--json]
//! tallow pin --pins <P> --ledger <L> [--key <K>] [--actor <A>] revoke <id>
//! ```
//!
//! Doctrine (do not weaken): pins enter the store ONLY through explicit
//! provisioning (`add`); verification paths resolve via
//! [`tallow_registry::pins::PinsStore::require_active_identity_pin`] /
//! `require_active_spki_pin` and **fail closed** on absent or revoked rows.
//! Every mutation is receipt-logged: `pin.add` / `pin.repin` / `pin.revoke`
//! append to the shared receipts ledger (`--ledger` is required for mutations;
//! a mutation that cannot be receipted is refused).
//!
//! The actor key: `--key <K>` = JSON `{"seed_hex": "<64 hex>"}` (Ed25519).
//! Without `--key`, the deterministic DEV key is used with a loud warning —
//! real deployments pass real material.

use std::path::Path;

use serde_json::json;
use tallow_registry::ledger::Ledger;
use tallow_registry::pins::PinsStore;
use tallow_registry::receipt::{Receipt, dev_actor_key};

fn print_help() {
    println!(
        "tallow pin — peer pin registry (pin + registry-verify; never trust-on-first-use)\n\
         \n\
         Usage:\n\
           tallow pin --pins <P> --ledger <L> [--key <K>] [--actor <A>] \\\n\
             add <id> --kind identity|spki [--source operator|qr|oob|self] [--notes N]\n\
           tallow pin --pins <P> list [--json]\n\
           tallow pin --pins <P> --ledger <L> [--key <K>] [--actor <A>] revoke <id>\n\
         \n\
         <id>: 64 hex chars (32 bytes). kind=identity → peer identity id (BLAKE3\n\
         fingerprint); kind=spki → sha256 of a server SubjectPublicKeyInfo DER.\n\
         Rows enter only through `add`; absent/revoked rows fail closed in every\n\
         verification path. Mutations append signed receipts (pin.add / pin.repin /\n\
         pin.revoke) to the ledger — mutations without a ledger are refused."
    );
}

fn load_key(path: &str) -> Result<ed25519_dalek::SigningKey, String> {
    #[derive(serde::Deserialize)]
    struct KeyFile {
        seed_hex: String,
    }
    let data = std::fs::read_to_string(path).map_err(|e| format!("key: read {path}: {e}"))?;
    let f: KeyFile = serde_json::from_str(&data).map_err(|e| format!("key: bad JSON: {e}"))?;
    let raw = hex::decode(&f.seed_hex).ok_or("key: bad hex (want 64 hex chars)")?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|v: Vec<u8>| format!("key: expected 32 bytes, got {}", v.len()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
}

/// Run the `tallow pin` subcommand (`args` is everything after `pin`).
pub fn run_pin_cmd(args: &[String]) -> Result<(), String> {
    let mut pins: Option<String> = None;
    let mut ledger: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut actor = "operator".to_string();
    let mut kind: Option<String> = None;
    let mut source = "operator".to_string();
    let mut notes: Option<String> = None;
    let mut json_out = false;
    let mut verb: Option<String> = None;
    let mut value: Option<String> = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" | "help" => {
                print_help();
                return Ok(());
            }
            "--pins" => pins = Some(it.next().cloned().unwrap_or_default()),
            "--ledger" => ledger = Some(it.next().cloned().unwrap_or_default()),
            "--key" => key_path = Some(it.next().cloned().unwrap_or_default()),
            "--actor" => actor = it.next().cloned().unwrap_or_default(),
            "--kind" => kind = Some(it.next().cloned().unwrap_or_default()),
            "--source" => source = it.next().cloned().unwrap_or_default(),
            "--notes" => notes = Some(it.next().cloned().unwrap_or_default()),
            "--json" => json_out = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown flag `{other}`; run `tallow pin --help`"));
            }
            other => {
                if verb.is_none() {
                    verb = Some(other.to_string());
                } else if value.is_none() {
                    value = Some(other.to_string());
                } else {
                    return Err(format!("unexpected argument `{other}`"));
                }
            }
        }
    }

    let Some(verb) = verb else {
        print_help();
        return Ok(());
    };
    let Some(pins_path) = pins else {
        return Err("--pins <P> is required (the pin store path)".to_string());
    };
    let pins_path = Path::new(&pins_path);

    match verb.as_str() {
        "add" => {
            let Some(id) = value else {
                return Err("add requires <id> (64 hex chars)".to_string());
            };
            let Some(kind) = kind else {
                return Err(
                    "add requires --kind identity|spki (no default: kind confusion is how a pin check becomes decorative)"
                        .to_string(),
                );
            };
            let Some(ledger_path) = ledger else {
                return Err(
                    "add requires --ledger <L>: a mutation that cannot be receipted is refused"
                        .to_string(),
                );
            };
            let key = load_key_or_dev(key_path.as_deref())?;
            let ledger = Ledger::new(&ledger_path);
            let mut store = PinsStore::init(pins_path).map_err(|e| format!("pins: {e}"))?;
            let change = store
                .add(&id, &kind, &source, notes.clone())
                .map_err(|e| format!("pin add refused: {e}"))?;
            let receipt_kind = if change.repin { "pin.repin" } else { "pin.add" };
            let mut data = json!({
                "id": change.row.id,
                "kind": change.row.kind,
                "mode": change.row.mode,
                "source": change.row.source,
            });
            if change.repin {
                data["repin"] = json!(true);
            }
            if let Some(n) = &change.row.notes {
                data["notes"] = json!(n);
            }
            let receipt = Receipt::sign_new(
                ledger.next_seq().map_err(|e| format!("ledger: {e}"))?,
                receipt_kind,
                &actor,
                Some(&change.row.id),
                data,
                ledger.next_prev().map_err(|e| format!("ledger: {e}"))?,
                &key,
            );
            ledger
                .append(&receipt)
                .map_err(|e| format!("ledger append: {e}"))?;
            store.save().map_err(|e| format!("pins save: {e}"))?;
            let action = if change.repin { "re-pinned" } else { "pinned" };
            println!(
                "{action} {} [{}] source={} · receipt seq {} {}",
                change.row.id, change.row.kind, change.row.source, receipt.seq, receipt_kind
            );
            Ok(())
        }
        "revoke" => {
            let Some(id) = value else {
                return Err("revoke requires <id>".to_string());
            };
            let Some(ledger_path) = ledger else {
                return Err(
                    "revoke requires --ledger <L>: a mutation that cannot be receipted is refused"
                        .to_string(),
                );
            };
            let key = load_key_or_dev(key_path.as_deref())?;
            let ledger = Ledger::new(&ledger_path);
            let mut store = PinsStore::load(pins_path)
                .map_err(|e| format!("pins load: {e} (nothing pinned here?)"))?;
            let row = store
                .revoke(&id)
                .map_err(|e| format!("pin revoke refused: {e}"))?;
            let receipt = Receipt::sign_new(
                ledger.next_seq().map_err(|e| format!("ledger: {e}"))?,
                "pin.revoke",
                &actor,
                Some(&row.id),
                json!({"id": row.id, "kind": row.kind}),
                ledger.next_prev().map_err(|e| format!("ledger: {e}"))?,
                &key,
            );
            ledger
                .append(&receipt)
                .map_err(|e| format!("ledger append: {e}"))?;
            store.save().map_err(|e| format!("pins save: {e}"))?;
            println!(
                "revoked {} [{}] · receipt seq {} pin.revoke",
                row.id, row.kind, receipt.seq
            );
            Ok(())
        }
        "list" => {
            let store = PinsStore::load(pins_path)
                .map_err(|e| format!("pins load: {e} (nothing pinned yet)"))?;
            if json_out {
                let rows =
                    serde_json::to_string_pretty(store.list()).map_err(|e| format!("json: {e}"))?;
                println!("{rows}");
                return Ok(());
            }
            if store.list().is_empty() {
                println!("no pins");
                return Ok(());
            }
            for r in store.list() {
                let notes = r.notes.as_deref().unwrap_or("");
                println!(
                    "{}  {}  {}  {}  created={}  {}",
                    r.id, r.kind, r.status, r.source, r.created_ms, notes
                );
            }
            Ok(())
        }
        other => Err(format!(
            "unknown verb `{other}` (want add | list | revoke); run `tallow pin --help`"
        )),
    }
}

fn load_key_or_dev(path: Option<&str>) -> Result<ed25519_dalek::SigningKey, String> {
    match path {
        Some(p) => load_key(p),
        None => {
            eprintln!(
                "WARNING: no --key given — using the DETERMINISTIC DEV actor key (test material)"
            );
            Ok(dev_actor_key())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal hex (crate convention: no `hex` dependency — same approach as
// `crate::kt_log` / `crate::merkle_audit`)
// ─────────────────────────────────────────────────────────────────────────────

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(s.len() / 2);
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16)?;
            let lo = (bytes[i + 1] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 2;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("tallow-pin-cmd-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn hex32(b: u8) -> String {
        hex::encode(&[b; 32])
    }

    #[test]
    fn add_repin_revoke_roundtrip_with_receipt_chain() {
        let dir = tmpdir("lifecycle");
        let pins = dir.join("pins.json");
        let lp = dir.join("receipts.jsonl");
        let id = hex32(0x77);

        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // add
        run_pin_cmd(&a(&[
            "--pins",
            pins.to_str().unwrap(),
            "--ledger",
            lp.to_str().unwrap(),
            "add",
            &id,
            "--kind",
            "identity",
            "--source",
            "oob",
        ]))
        .expect("add");

        // list --json shows the active row
        run_pin_cmd(&a(&["--pins", pins.to_str().unwrap(), "list", "--json"])).expect("list");
        let store = PinsStore::load(&pins).unwrap();
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.list()[0].status, "active");

        // re-pin
        run_pin_cmd(&a(&[
            "--pins",
            pins.to_str().unwrap(),
            "--ledger",
            lp.to_str().unwrap(),
            "add",
            &id,
            "--kind",
            "identity",
            "--source",
            "operator",
        ]))
        .expect("repin");

        // revoke
        run_pin_cmd(&a(&[
            "--pins",
            pins.to_str().unwrap(),
            "--ledger",
            lp.to_str().unwrap(),
            "revoke",
            &id,
        ]))
        .expect("revoke");

        let store = PinsStore::load(&pins).unwrap();
        assert_eq!(store.list()[0].status, "revoked");

        // The receipt chain must verify and carry the three kinds in order.
        let ledger = Ledger::new(&lp);
        let key = dev_actor_key();
        let verdict = ledger.verify(&key.verifying_key());
        assert!(verdict.ok(), "ledger must verify: {:?}", verdict.errors);
        let kinds: Vec<String> = ledger
            .iter()
            .unwrap()
            .iter()
            .map(|r| r.kind.clone())
            .collect();
        assert_eq!(kinds, vec!["pin.add", "pin.repin", "pin.revoke"]);
    }

    #[test]
    fn mutation_without_ledger_is_refused() {
        let dir = tmpdir("noledger");
        let pins = dir.join("pins.json");
        let id = hex32(0x11);
        let err = run_pin_cmd(&[
            "--pins".into(),
            pins.to_str().unwrap().into(),
            "add".into(),
            id,
            "--kind".into(),
            "identity".into(),
        ])
        .expect_err("must refuse without --ledger");
        assert!(err.contains("receipted"), "err: {err}");
        assert!(!pins.exists(), "nothing may be written without a receipt");
    }

    #[test]
    fn bad_kind_is_refused() {
        let dir = tmpdir("badkind");
        let pins = dir.join("pins.json");
        let lp = dir.join("receipts.jsonl");
        let err = run_pin_cmd(&[
            "--pins".into(),
            pins.to_str().unwrap().into(),
            "--ledger".into(),
            lp.to_str().unwrap().into(),
            "add".into(),
            hex32(1),
            "--kind".into(),
            "ed25519".into(),
        ])
        .expect_err("bad kind");
        assert!(err.contains("invalid pin kind"), "err: {err}");
    }

    #[test]
    fn add_without_kind_is_refused() {
        let dir = tmpdir("nokind");
        let pins = dir.join("pins.json");
        let lp = dir.join("receipts.jsonl");
        let err = run_pin_cmd(&[
            "--pins".into(),
            pins.to_str().unwrap().into(),
            "--ledger".into(),
            lp.to_str().unwrap().into(),
            "add".into(),
            hex32(1),
        ])
        .expect_err("kind required");
        assert!(err.contains("--kind"), "err: {err}");
    }

    #[test]
    fn revoke_absent_is_refused() {
        let dir = tmpdir("revabsent");
        let pins = dir.join("pins.json");
        let lp = dir.join("receipts.jsonl");
        let _ = PinsStore::init(&pins).unwrap();
        let err = run_pin_cmd(&[
            "--pins".into(),
            pins.to_str().unwrap().into(),
            "--ledger".into(),
            lp.to_str().unwrap().into(),
            "revoke".into(),
            hex32(9),
        ])
        .expect_err("absent");
        assert!(err.contains("unknown pin"), "err: {err}");
    }

    #[test]
    fn list_missing_store_errs() {
        let dir = tmpdir("listmissing");
        let pins = dir.join("pins.json");
        let err = run_pin_cmd(&[
            "--pins".into(),
            pins.to_str().unwrap().into(),
            "list".into(),
        ])
        .expect_err("missing store");
        assert!(err.contains("pins load"), "err: {err}");
        assert!(!pins.exists(), "list must not create the store");
    }
}
