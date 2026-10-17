//! `tallow pins` — author the project's package pin file (`.tallow-pins`).
//!
//! This is deliberately separate from `tallow pin`, which manages the **peer**
//! registry (`pins.json`: identity / SPKI pins + receipts). `.tallow-pins` is
//! the supply-chain store read by `tallow audit --supply-chain`: a TOML table
//! of package subject → BLAKE3/SHA-256 fingerprint.
//!
//! ```text
//! tallow pins [--file <dir>] add <subject> <fingerprint>
//! tallow pins [--file <dir>] list [--json]
//! tallow pins [--file <dir>] remove <subject>
//! ```
//!
//! Adding an existing subject with the same fingerprint is a no-op; adding a
//! different fingerprint is refused (re-pin deliberately by removing first).
//! The file is written atomically and entries are sorted.

use std::path::PathBuf;

use crate::supply_chain::{self, KeyPinStore, PINS_FILE_NAME};

fn print_help() {
    println!(
        "tallow pins — package pin file ({PINS_FILE_NAME}; distinct from `tallow pin`'s peer registry)\n\
         \n\
         Usage:\n\
           tallow pins [--file <project-dir>] add <subject> <fingerprint>\n\
           tallow pins [--file <project-dir>] list [--json]\n\
           tallow pins [--file <project-dir>] remove <subject>\n\
         \n\
         <fingerprint>: 64 hex chars, optionally prefixed blake3: or sha256:.\n\
         The file is read by `tallow audit --supply-chain`."
    );
}

/// Run `tallow pins` (`args` is everything after `pins`).
pub fn run_pins_cmd(args: &[String]) -> Result<(), String> {
    let mut project_dir: PathBuf = PathBuf::from(".");
    let mut json_out = false;
    let mut verb: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" | "help" => {
                print_help();
                return Ok(());
            }
            "--json" => json_out = true,
            "--file" | "--path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a project directory"))?;
                project_dir = PathBuf::from(value);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}` (try `tallow pins --help`)"));
            }
            other if verb.is_none() => verb = Some(other.to_string()),
            other => positionals.push(other.to_string()),
        }
    }

    let verb = verb.ok_or_else(|| "expected `add`, `list` or `remove` (try `tallow pins --help`)".to_string())?;
    if !project_dir.is_dir() {
        return Err(format!(
            "{} is not a directory (pass an existing project root with --file)",
            project_dir.display()
        ));
    }

    let loaded = supply_chain::load_pin_store(&project_dir)?;
    let mut store: KeyPinStore = loaded.store;

    match verb.as_str() {
        "list" => {
            let mut rows: Vec<_> = store.all_pins().iter().collect();
            rows.sort_by(|left, right| left.0.cmp(right.0));
            if json_out {
                let entries: Vec<_> = rows
                    .iter()
                    .map(|(subject, fingerprint)| {
                        format!(
                            "{{\"subject\":\"{}\",\"fingerprint\":\"{}\"}}",
                            json_escape(subject),
                            json_escape(fingerprint)
                        )
                    })
                    .collect();
                println!("{{\"file\":\"{}\",\"pins\":[{}]}}", json_escape(&loaded.source.as_ref().map(|p| p.display().to_string()).unwrap_or_default()), entries.join(","));
            } else {
                match &loaded.source {
                    Some(path) => println!("{} ({} pin(s))", path.display(), rows.len()),
                    None => println!("no {PINS_FILE_NAME} in {}", project_dir.display()),
                }
                for (subject, fingerprint) in rows {
                    println!("{subject}  {fingerprint}");
                }
            }
            Ok(())
        }
        "add" => {
            if positionals.len() != 2 {
                return Err("usage: tallow pins add <subject> <fingerprint>".to_string());
            }
            let subject = &positionals[0];
            let normalized = supply_chain::normalize_fingerprint(&positionals[1]).ok_or_else(|| {
                format!(
                    "`{}` is not a 64-hex fingerprint (optional blake3:/sha256: prefix)",
                    positionals[1]
                )
            })?;
            match store.pin_author_key(subject, &normalized) {
                supply_chain::PinResult::Pinned => {
                    let path = supply_chain::write_pin_store(&project_dir, &store)?;
                    println!("pinned {subject} -> {normalized}");
                    println!("wrote {}", path.display());
                    Ok(())
                }
                supply_chain::PinResult::AlreadyPinned => {
                    println!("{subject} is already pinned to {normalized}; unchanged");
                    Ok(())
                }
                supply_chain::PinResult::Mismatch { expected, actual } => Err(format!(
                    "{subject} is already pinned to {expected}; refusing to replace it with {actual}. \
                     Remove the row first if the key change is intentional."
                )),
            }
        }
        "remove" => {
            if positionals.len() != 1 {
                return Err("usage: tallow pins remove <subject>".to_string());
            }
            if !supply_chain::remove_pin(&mut store, &positionals[0]) {
                return Err(format!("no pin for `{}`", positionals[0]));
            }
            let path = supply_chain::write_pin_store(&project_dir, &store)?;
            println!("removed {}; wrote {}", positionals[0], path.display());
            Ok(())
        }
        other => Err(format!("unknown command `{other}` (expected add, list or remove)")),
    }
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
