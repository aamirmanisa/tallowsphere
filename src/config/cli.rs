//! KB-7 CLI entry points: `tallow config lint` (row #66 scoring) and
//! `tallow config presets` (the deployable floor tables); W3 batch-3 adds the
//! signed-bundle arms `tallow config bundle {keygen,export,import,verify}`
//! (rows #153/#198, [`crate::config::bundle`]).
//!
//! Thin presentation layer over [`crate::config::lint`] /
//! [`crate::config::presets`] / [`crate::config::bundle`] — all scoring and all
//! verification live in the kernel modules, so the CLI stays a
//! parse → run → print → code function.
//!
//! Exit-code contract (shared with `lint.rs` / `bundle.rs`):
//! - `0` — pass (no error findings; warnings only, unless `--strict`);
//! - `1` — findings / refusal fail the run (for bundles: a refusal that was
//!   *checked* — tamper, untrusted signer, scope gate, relabel, invalid artifact);
//! - `2` — the command could not run (unknown `--format`/`--preset`/`--scope`
//!   word, unresolvable default config path — `E7012`, key-material or I/O
//!   failure; the kernel never falls back to `.`).

use std::path::{Path, PathBuf};

use crate::config::bundle;
use crate::config::lint::{self, LintOptions};
use crate::config::load;
use crate::config::presets;
use crate::config::schema::{EXPECTED_PROFILE, OutputFormat, Profile};
use crate::config::write::WriteOptions;

/// `tallow config lint [--preset <profile>] [--strict] [--format text|json]
/// [--path <file>]`. Returns the process exit code (0/1/2).
pub fn run_config_lint(
    preset: Option<&str>,
    strict: bool,
    format: &str,
    path: Option<&Path>,
) -> i32 {
    let Some(format) = OutputFormat::parse(format) else {
        eprintln!("tallow config lint: unknown --format `{format}` (expected `text` or `json`)");
        return 2;
    };
    let preset = match preset {
        None => None,
        Some(word) => match Profile::parse(word) {
            Some(profile) => Some(profile),
            None => {
                eprintln!(
                    "tallow config lint: unknown --preset `{word}` — expected {EXPECTED_PROFILE}"
                );
                return 2;
            }
        },
    };

    let loaded = match path {
        Some(path) => load::load_file(path),
        None => match load::load_default() {
            Ok(loaded) => loaded,
            Err(e) => {
                eprintln!("tallow config lint: cannot resolve the default config path: {e}");
                return 2;
            }
        },
    };

    let report = lint::lint(
        &loaded,
        &LintOptions {
            preset,
            strict,
            ..LintOptions::default()
        },
    );
    match format {
        OutputFormat::Text => print!("{}", report.render_text()),
        OutputFormat::Json => println!("{}", report.render_json()),
    }
    report.exit_code()
}

/// `tallow config presets [--format text|json]`. Returns 0 (2 on a bad word).
pub fn run_config_presets(format: &str) -> i32 {
    let Some(format) = OutputFormat::parse(format) else {
        eprintln!("tallow config presets: unknown --format `{format}` (expected `text` or `json`)");
        return 2;
    };
    match format {
        OutputFormat::Text => print!("{}", presets::render_text()),
        OutputFormat::Json => println!("{}", presets::render_json()),
    }
    0
}

// ── Signed config bundles (rows #153/#198) ───────────────────────────────────

/// `tallow config bundle keygen --out <PATH>`.
///
/// Writes the Ed25519 signing seed (`0600` on unix) and `<PATH>.pub` (hex).
/// Returns 0, or 2 on key-material/I-O failure.
pub fn run_config_bundle_keygen(out: &Path, format: &str) -> i32 {
    let Some(format) = OutputFormat::parse(format) else {
        eprintln!("tallow config bundle keygen: unknown --format `{format}` (expected `text` or `json`)");
        return 2;
    };
    match bundle::write_keypair(out) {
        Ok((private, public)) => {
            match format {
                OutputFormat::Text => {
                    println!("wrote signing key  {}", private.display());
                    println!("wrote public key   {}", public.display());
                    println!("key id             {}", key_id_line(&private));
                }
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "op": "keygen",
                        "key": private.display().to_string(),
                        "public_key": public.display().to_string(),
                    })
                ),
            }
            0
        }
        Err(e) => {
            eprintln!("tallow config bundle keygen: {e}");
            e.exit_code()
        }
    }
}

fn key_id_line(key_path: &Path) -> String {
    match bundle::ed25519_signing_key_from_file(key_path) {
        Ok(k) => bundle::key_id_of(&k.verifying_key()),
        Err(_) => "unknown".to_string(),
    }
}

/// `tallow config bundle export --out <PATH> --key <PATH> [--config <PATH>]
/// [--scope <SCOPE>] [--format text|json]`.
///
/// Returns 0; 1 when the source artifact fails strict kernel validation
/// (`E7029` — an artifact the kernel would refuse is never signed); 2 on
/// usage/key-material/I-O failure.
pub fn run_config_bundle_export(
    config: Option<&Path>,
    out: &Path,
    scope: &str,
    key: &Path,
    format: &str,
) -> i32 {
    let Some(format) = OutputFormat::parse(format) else {
        eprintln!("tallow config bundle export: unknown --format `{format}` (expected `text` or `json`)");
        return 2;
    };
    let Some(scope) = bundle::ConfigScope::parse(scope) else {
        eprintln!(
            "tallow config bundle export: unknown --scope `{scope}` — expected {}",
            bundle::EXPECTED_SCOPE
        );
        return 2;
    };
    let source = match config {
        Some(path) => path.to_path_buf(),
        None => match load::default_config_path() {
            Ok(path) => path,
            Err(e) => {
                eprintln!("tallow config bundle export: cannot resolve the default config path: {e}");
                return 2;
            }
        },
    };
    let signing_key = match bundle::ed25519_signing_key_from_file(key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("tallow config bundle export: {e}");
            return e.exit_code();
        }
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    match bundle::export_bundle_to(&source, scope, &signing_key, now_ms, out) {
        Ok(outcome) => {
            match format {
                OutputFormat::Text => {
                    println!(
                        "exported {} bytes (scope {}, signer {}) → {}",
                        outcome.bytes,
                        outcome.scope.word(),
                        outcome.key_id,
                        outcome.path.display()
                    );
                    println!("body sha256 {}", outcome.body_sha256);
                }
                OutputFormat::Json => println!("{}", outcome.render_json()),
            }
            0
        }
        Err(e) => {
            eprintln!("tallow config bundle export: {e}");
            e.exit_code()
        }
    }
}

/// `tallow config bundle import --bundle <PATH> --to <PATH>
/// [--scope <SCOPE>] [--trusted-key <PATH>]… [--history-dir <PATH>]
/// [--dry-run] [--format text|json]`.
///
/// Order is **verify → strict kernel load → atomic kernel write**: a refusal
/// writes nothing and records nothing. Returns 0; 1 on a checked refusal
/// (tamper `E7025`, untrusted signer `E7026`, relabel `E7030`, invalid artifact);
/// 2 on usage/key-material/I-O failure.
pub fn run_config_bundle_import(
    bundle_path: &Path,
    to: &Path,
    scope: Option<&str>,
    trusted_keys: &[PathBuf],
    history_dir: Option<&Path>,
    dry_run: bool,
    format: &str,
) -> i32 {
    let Some(format) = OutputFormat::parse(format) else {
        eprintln!("tallow config bundle import: unknown --format `{format}` (expected `text` or `json`)");
        return 2;
    };
    let expected_scope = match scope {
        None => None,
        Some(word) => match bundle::ConfigScope::parse(word) {
            Some(s) => Some(s),
            None => {
                eprintln!(
                    "tallow config bundle import: unknown --scope `{word}` — expected {}",
                    bundle::EXPECTED_SCOPE
                );
                return 2;
            }
        },
    };

    let (bytes, anchors) = match (bundle::read_bundle_bytes(bundle_path), load_anchors(trusted_keys)) {
        (Ok(bytes), Ok(anchors)) => (bytes, anchors),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("tallow config bundle import: {e}");
            return e.exit_code();
        }
    };

    let opts = match history_dir {
        Some(dir) => WriteOptions::with_history_dir(dir.to_path_buf()),
        None => WriteOptions::new(),
    };

    match bundle::import_bundle(
        &bytes,
        to,
        expected_scope,
        &anchors,
        dry_run,
        &opts,
    ) {
        Ok(outcome) => {
            match format {
                OutputFormat::Text => {
                    println!(
                        "{} (scope {}, signer {}, assurance {}) → {}",
                        if outcome.dry_run { "import dry-run OK" } else { "imported" },
                        outcome.scope.word(),
                        outcome.key_id,
                        outcome.assurance.word(),
                        outcome.target.display()
                    );
                    match outcome.revision {
                        Some(rev) => println!(
                            "{} bytes · history revision {rev} · blake3 {}",
                            outcome.bytes, outcome.content_blake3
                        ),
                        None => println!(
                            "{} bytes · no write performed · blake3 {}",
                            outcome.bytes, outcome.content_blake3
                        ),
                    }
                }
                OutputFormat::Json => println!("{}", outcome.render_json()),
            }
            0
        }
        Err(e) => {
            eprintln!("tallow config bundle import: {e}");
            e.exit_code()
        }
    }
}

/// `tallow config bundle verify --bundle <PATH> [--trusted-key <PATH>]…
/// [--format text|json]`.
///
/// Returns 0 when the bundle verifies (under the supplied anchors, if any);
/// 1 on a checked refusal; 2 on usage/I-O failure.
pub fn run_config_bundle_verify(
    bundle_path: &Path,
    trusted_keys: &[PathBuf],
    format: &str,
) -> i32 {
    let Some(format) = OutputFormat::parse(format) else {
        eprintln!("tallow config bundle verify: unknown --format `{format}` (expected `text` or `json`)");
        return 2;
    };
    let (bytes, anchors) = match (bundle::read_bundle_bytes(bundle_path), load_anchors(trusted_keys)) {
        (Ok(bytes), Ok(anchors)) => (bytes, anchors),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("tallow config bundle verify: {e}");
            return e.exit_code();
        }
    };

    match bundle::verify_bundle_bytes(&bytes, &anchors) {
        Ok(verified) => {
            match format {
                OutputFormat::Text => {
                    println!(
                        "bundle OK — scope {}, signer {}, assurance {}, created_ms {}",
                        verified.scope.word(),
                        verified.key_id,
                        verified.assurance.word(),
                        verified.created_ms
                    );
                    println!("body sha256 {}", verified.body_sha256);
                }
                OutputFormat::Json => println!("{}", verified.render_json()),
            }
            0
        }
        Err(e) => {
            eprintln!("tallow config bundle verify: {e}");
            e.exit_code()
        }
    }
}

/// Load pinned trust anchors from key files (empty list ⇒ no anchors).
fn load_anchors(paths: &[PathBuf]) -> Result<bundle::TrustAnchors, bundle::BundleError> {
    if paths.is_empty() {
        return Ok(bundle::TrustAnchors::none());
    }
    bundle::TrustAnchors::from_files(paths)
}
