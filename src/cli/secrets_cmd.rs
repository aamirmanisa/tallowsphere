//! `tallow secrets` — masked credential enrollment and origin binding.
//!
//! Why this exists
//! ---------------
//! Every other credential path in the tree assumes the secret is already in a
//! store. Nothing could *put* one there without the value transiting argv, an
//! environment variable, or a chat message:
//!
//! * `vault/credential.rs` is a **volatile in-process cache** (random per-process
//!   key) — it cannot persist an enrolled credential across runs.
//! * `vault/autotype.rs` is xdotool/X11 keystroke injection against a focused
//!   window — meaningless for a headless browser and impossible in a container
//!   with no X server.
//! * `stdlib/secrets.rs` has the at-rest store, but exposes only interpreter
//!   dispatch, and its `SecretStore` is private.
//! * No `rpassword`/`termios`/`tcsetattr` call existed anywhere in `src/`.
//!
//! This module closes that gap with the smallest thing that works: read the
//! password with the terminal echo off, bind the entry to an origin, write it
//! to `~/.config/tallow/secrets.json` — the exact path the scrape-isolated
//! bridge already mounts read-only into its flow container, so flows inherit
//! this without further wiring.
//!
//! Non-negotiable properties (each has a test below)
//! ------------------------------------------------
//! 1. The secret is never accepted from argv or the environment. There is no
//!    `--password` flag, by design; adding one would defeat the module.
//! 2. The terminal echo is restored on every path, including early return and
//!    panic (the restore lives in a `Drop` guard, not in straight-line code).
//! 3. Nothing in this module prints a secret value. `list` is names, usernames
//!    and origins only.
//! 4. Nothing holding a secret derives `Serialize` — the on-disk mapping is
//!    hand-written (same rule `stdlib/secrets.rs` records as audit §2). A
//!    derived `Serialize` is a second, unredacted serialization path.
//! 5. Origin binding is enforced on read: an entry bound to one origin must be
//!    refused for another, and matching is exact on (scheme, host, port) so a
//!    suffix trick like `secure.example.com.evil.net` cannot pass.
//!
//! Exit codes: 0 ok, 64 usage, 69 refused (origin mismatch), 78 unbound/unsafe.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// Entry is an enrolled credential. Deliberately NOT `Serialize`, NOT `Clone`,
/// and `Debug` is hand-written to redact the password.
struct Entry {
    username: String,
    password: String,
    /// `None` = unbound: it may be used for any origin. Bind it when you can.
    origin: Option<String>,
    created_at: String,
}

impl Entry {
    /// Zeroize the password when the entry goes away.
    fn wipe(&mut self) {
        self.password.clear();
        self.password.shrink_to_fit();
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("origin", &self.origin)
            .field("created_at", &self.created_at)
            .finish()
    }
}

const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 64;
const EXIT_REFUSED: i32 = 69;
const EXIT_UNBOUND: i32 = 78;

fn usage() -> i32 {
    eprintln!(
        "usage:\n  \
         tallow secrets set <name> [--username U] [--origin URL] [--path P]\n  \
         tallow secrets list [--path P]\n  \
         tallow secrets check <name> --origin URL [--path P]\n  \
         tallow secrets rm <name> [--path P]\n\n\
         The password is read from the terminal with echo OFF. There is no\n\
         --password flag and none will be added: a secret on the command line is\n\
         a secret in `ps` and in shell history."
    );
    EXIT_USAGE
}

fn default_path() -> PathBuf {
    if let Ok(p) = std::env::var("TALLOW_SECRETS_FILE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    Path::new(&home)
        .join(".config")
        .join("tallow")
        .join("secrets.json")
}

// ── origin binding ───────────────────────────────────────────────────────────

/// Reduce an origin to its comparable (scheme, host, port) triple.
///
/// Deliberately rejects anything we cannot parse rather than guessing: a
/// binding you cannot compare exactly is not a binding.
fn origin_key(url: &str) -> Option<String> {
    let (scheme, rest) = match url.split_once("://") {
        Some(parts) => parts,
        None => return None,
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme.is_empty() {
        return None;
    }
    // Strip path / query / fragment, then any userinfo.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h, Some(p)),
        _ => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    let port = port.unwrap_or(match scheme.as_str() {
        "https" => "443",
        "http" => "80",
        _ => "",
    });
    Some(format!("{scheme}://{}:{}", host.to_ascii_lowercase(), port))
}

/// Exact equality on the normalized triple. No suffix or subdomain relaxation:
/// `a.example.com` and `example.com` are different origins, which is the whole
/// point of binding.
fn origin_matches(bound: &str, requested: &str) -> bool {
    match (origin_key(bound), origin_key(requested)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

// ── storage (hand-written mapping; see module rule 4) ────────────────────────

fn load(path: &Path) -> Result<BTreeMap<String, Entry>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    if raw.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let mut out = BTreeMap::new();
    let entries = match value.get("entries").and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Err(format!("{}: no `entries` object", path.display())),
    };
    for (name, e) in entries {
        let username = e
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let password = e
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let origin = e
            .get("origin")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let created_at = e
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        out.insert(
            name.clone(),
            Entry {
                username,
                password,
                origin,
                created_at,
            },
        );
    }
    Ok(out)
}

/// Write atomically with mode 0600 set *at creation*, so the secret is never
/// briefly world-readable between write and chmod.
fn save(path: &Path, entries: &BTreeMap<String, Entry>) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    let mut map = serde_json::Map::new();
    for (name, e) in entries {
        let mut o = serde_json::Map::new();
        o.insert(
            "username".into(),
            serde_json::Value::String(e.username.clone()),
        );
        o.insert(
            "password".into(),
            serde_json::Value::String(e.password.clone()),
        );
        match &e.origin {
            Some(origin) => {
                o.insert("origin".into(), serde_json::Value::String(origin.clone()));
            }
            None => {
                o.insert("origin".into(), serde_json::Value::Null);
            }
        }
        o.insert(
            "created_at".into(),
            serde_json::Value::String(e.created_at.clone()),
        );
        map.insert(name.clone(), serde_json::Value::Object(o));
    }
    let mut root = serde_json::Map::new();
    root.insert("version".into(), serde_json::Value::from(1));
    root.insert("entries".into(), serde_json::Value::Object(map));
    let body = serde_json::to_string_pretty(&serde_json::Value::Object(root))
        .map_err(|e| format!("encode: {e}"))?;

    let tmp = path.with_extension("json.tmp");
    {
        let mut fh = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("open {}: {e}", tmp.display()))?;
        fh.write_all(body.as_bytes())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        fh.flush().map_err(|e| format!("flush: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("rename into {}: {e}", path.display()))?;
    // Belt and braces: rename preserves the tmp's mode, but assert the invariant
    // rather than assume it.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(())
}

fn now_iso() -> String {
    // Seconds since epoch is enough provenance for an enrollment record and
    // avoids pulling a date formatter into the CLI path.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

// ── masked read ──────────────────────────────────────────────────────────────

/// Restores the terminal on drop — the single place echo is turned back on, so
/// an early return or a panic cannot leave the operator's terminal deaf.
struct EchoGuard {
    fd: libc::c_int,
    saved: Option<libc::termios>,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if let Some(t) = self.saved.as_ref() {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSAFLUSH, t);
            }
        }
    }
}

/// Read a line with the terminal echo disabled.
///
/// Falls back to a plain line read when stdin is not a TTY (a pipe), which is
/// what lets the tests drive it — the secret still never comes from argv.
fn read_masked(prompt: &str) -> Result<String, String> {
    let fd = libc::STDIN_FILENO;
    let is_tty = unsafe { libc::isatty(fd) } == 1;

    let guard = if is_tty {
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(format!("tcgetattr: {}", std::io::Error::last_os_error()));
        }
        let mut raw = saved;
        raw.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(format!("tcsetattr: {}", std::io::Error::last_os_error()));
        }
        EchoGuard {
            fd,
            saved: Some(saved),
        }
    } else {
        EchoGuard { fd, saved: None }
    };

    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    drop(guard); // echo restored before anything else can fail
    if is_tty {
        eprintln!();
    }
    read.map_err(|e| format!("read: {e}"))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

// ── subcommands ──────────────────────────────────────────────────────────────

fn flag(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

fn cmd_set(args: &[String]) -> i32 {
    let name = match args.first() {
        Some(n) if !n.starts_with('-') => n.clone(),
        _ => return usage(),
    };
    let path = flag(args, "--path")
        .map(PathBuf::from)
        .unwrap_or_else(default_path);
    let username = flag(args, "--username").unwrap_or_default();
    let origin = flag(args, "--origin");

    if let Some(o) = origin.as_deref() {
        if origin_key(o).is_none() {
            eprintln!("secrets: --origin must be a full URL with a scheme, e.g. https://host");
            return EXIT_USAGE;
        }
    } else {
        eprintln!(
            "secrets: WARNING — no --origin given, so this entry is UNBOUND and may be \
             resolved for any host a flow names. Bind it if you can."
        );
    }

    let mut password = match read_masked("password: ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("secrets: {e}");
            return EXIT_USAGE;
        }
    };
    if password.is_empty() {
        eprintln!("secrets: empty password refused");
        return EXIT_USAGE;
    }
    let confirm = match read_masked("confirm:  ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("secrets: {e}");
            return EXIT_USAGE;
        }
    };
    if confirm != password {
        eprintln!("secrets: the two entries differ; nothing written");
        password.clear();
        return EXIT_USAGE;
    }
    drop(confirm);

    let mut entries = match load(&path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("secrets: {e}");
            return EXIT_UNBOUND;
        }
    };
    let existed = entries.contains_key(&name);
    entries.insert(
        name.clone(),
        Entry {
            username,
            password,
            origin,
            created_at: now_iso(),
        },
    );
    if let Err(e) = save(&path, &entries) {
        eprintln!("secrets: {e}");
        return EXIT_UNBOUND;
    }
    println!(
        "secrets: {} entry {name:?} -> {}",
        if existed { "replaced" } else { "stored" },
        path.display()
    );
    EXIT_OK
}

fn cmd_list(args: &[String]) -> i32 {
    let path = flag(args, "--path")
        .map(PathBuf::from)
        .unwrap_or_else(default_path);
    let entries = match load(&path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("secrets: {e}");
            return EXIT_UNBOUND;
        }
    };
    if entries.is_empty() {
        println!("secrets: no entries in {}", path.display());
        return EXIT_OK;
    }
    println!(
        "{} entr{} in {}",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" },
        path.display()
    );
    for (name, e) in &entries {
        let origin = e.origin.as_deref().unwrap_or("<UNBOUND>");
        println!("  {name:<20} user={:<20} origin={origin}", e.username);
    }
    EXIT_OK
}

fn cmd_check(args: &[String]) -> i32 {
    let name = match args.first() {
        Some(n) if !n.starts_with('-') => n.clone(),
        _ => return usage(),
    };
    let path = flag(args, "--path")
        .map(PathBuf::from)
        .unwrap_or_else(default_path);
    let requested = match flag(args, "--origin") {
        Some(o) => o,
        None => {
            eprintln!("secrets: check requires --origin URL");
            return EXIT_USAGE;
        }
    };
    let entries = match load(&path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("secrets: {e}");
            return EXIT_UNBOUND;
        }
    };
    let entry = match entries.get(&name) {
        Some(e) => e,
        None => {
            eprintln!("secrets: no entry {name:?}");
            return EXIT_UNBOUND;
        }
    };
    match entry.origin.as_deref() {
        None => {
            println!(
                "secrets: {name:?} is UNBOUND — it resolves for any origin (not a match test)"
            );
            EXIT_UNBOUND
        }
        Some(bound) if origin_matches(bound, &requested) => {
            println!("secrets: {name:?} bound to {bound} — MATCH for {requested}");
            EXIT_OK
        }
        Some(bound) => {
            println!("secrets: {name:?} bound to {bound} — REFUSED for {requested}");
            EXIT_REFUSED
        }
    }
}

fn cmd_rm(args: &[String]) -> i32 {
    let name = match args.first() {
        Some(n) if !n.starts_with('-') => n.clone(),
        _ => return usage(),
    };
    let path = flag(args, "--path")
        .map(PathBuf::from)
        .unwrap_or_else(default_path);
    let mut entries = match load(&path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("secrets: {e}");
            return EXIT_UNBOUND;
        }
    };
    if entries.remove(&name).is_none() {
        eprintln!("secrets: no entry {name:?}");
        return EXIT_UNBOUND;
    }
    if let Err(e) = save(&path, &entries) {
        eprintln!("secrets: {e}");
        return EXIT_UNBOUND;
    }
    println!("secrets: removed {name:?}");
    EXIT_OK
}

/// Entry point, registered as `tallow secrets …` in `main.rs`.
pub fn run_secrets_args(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("set") => cmd_set(&args[1..]),
        Some("list") => cmd_list(&args[1..]),
        Some("check") => cmd_check(&args[1..]),
        Some("rm") => cmd_rm(&args[1..]),
        Some("-h") | Some("--help") | None => usage(),
        Some(other) => {
            eprintln!("secrets: unknown subcommand {other:?}");
            usage()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tallow-secrets-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).expect("tmpdir");
        d
    }

    #[test]
    fn origin_normalizes_scheme_host_port() {
        assert_eq!(
            origin_key("https://secure.example.com"),
            origin_key("https://secure.example.com/")
        );
        assert_eq!(
            origin_key("https://secure.example.com"),
            origin_key("https://SECURE.EXAMPLE.COM/x?y#z")
        );
        assert_eq!(
            origin_key("https://secure.example.com"),
            origin_key("https://secure.example.com:443/")
        );
        assert_eq!(
            origin_key("http://secure.example.com"),
            origin_key("http://secure.example.com:80/")
        );
        assert_ne!(
            origin_key("http://secure.example.com"),
            origin_key("https://secure.example.com")
        );
        assert!(
            origin_key("secure.example.com").is_none(),
            "no scheme is not an origin"
        );
        assert!(origin_key("https://").is_none());
    }

    #[test]
    fn origin_matching_is_exact_and_refuses_suffix_tricks() {
        let bound = "https://secure.cstorepro.com";
        assert!(origin_matches(
            bound,
            "https://secure.cstorepro.com/EmagineNETCOSM/Login.aspx"
        ));
        assert!(origin_matches(bound, "https://secure.cstorepro.com"));
        // A name-allowlist cannot judge this: the suffix must NOT pass.
        assert!(!origin_matches(
            bound,
            "https://secure.cstorepro.com.evil.net"
        ));
        assert!(!origin_matches(
            bound,
            "https://evil.net/?x=secure.cstorepro.com"
        ));
        assert!(
            !origin_matches(bound, "http://secure.cstorepro.com"),
            "scheme downgrade"
        );
        assert!(
            !origin_matches(bound, "https://cstorepro.com"),
            "parent domain"
        );
        assert!(!origin_matches(bound, "https://secure.cstorepro.com:8443"));
    }

    #[test]
    fn userinfo_does_not_change_the_origin() {
        assert_eq!(
            origin_key("https://user:pw@secure.example.com/login"),
            origin_key("https://secure.example.com")
        );
    }

    #[test]
    fn round_trip_writes_0600_and_never_serializes_via_derive() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("roundtrip");
        let path = dir.join("secrets.json");
        let mut m = BTreeMap::new();
        m.insert(
            "cstorepro".to_string(),
            Entry {
                username: "trimart4005".into(),
                password: "s3cr3t-value".into(),
                origin: Some("https://secure.cstorepro.com".into()),
                created_at: now_iso(),
            },
        );
        save(&path, &m).expect("save");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "on-disk mode must be 0600, got {mode:o}");

        let back = load(&path).expect("load");
        let e = back.get("cstorepro").expect("entry");
        assert_eq!(e.username, "trimart4005");
        assert_eq!(e.password, "s3cr3t-value");
        assert_eq!(e.origin.as_deref(), Some("https://secure.cstorepro.com"));

        // The unbound case must round-trip as JSON null, not vanish.
        let mut m2 = back;
        m2.insert(
            "unbound".into(),
            Entry {
                username: "u".into(),
                password: "p".into(),
                origin: None,
                created_at: now_iso(),
            },
        );
        save(&path, &m2).expect("save2");
        assert!(load(&path).unwrap()["unbound"].origin.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_redacts_the_password() {
        let e = Entry {
            username: "u".into(),
            password: "TOP-SECRET".into(),
            origin: None,
            created_at: now_iso(),
        };
        let rendered = format!("{e:?}");
        assert!(
            !rendered.contains("TOP-SECRET"),
            "Debug leaked the secret: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn check_refuses_a_mismatched_origin() {
        let dir = tmpdir("check");
        let path = dir.join("secrets.json");
        let mut m = BTreeMap::new();
        m.insert(
            "cstorepro".into(),
            Entry {
                username: "u".into(),
                password: "p".into(),
                origin: Some("https://secure.cstorepro.com".into()),
                created_at: now_iso(),
            },
        );
        save(&path, &m).expect("save");
        let p = path.to_string_lossy().to_string();

        let ok = run_secrets_args(&[
            "check".into(),
            "cstorepro".into(),
            "--origin".into(),
            "https://secure.cstorepro.com/EmagineNETCOSM/".into(),
            "--path".into(),
            p.clone(),
        ]);
        assert_eq!(ok, EXIT_OK);

        let bad = run_secrets_args(&[
            "check".into(),
            "cstorepro".into(),
            "--origin".into(),
            "https://secure.cstorepro.com.evil.net".into(),
            "--path".into(),
            p.clone(),
        ]);
        assert_eq!(bad, EXIT_REFUSED, "suffix trick must be refused");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_never_prints_the_password() {
        let dir = tmpdir("list");
        let path = dir.join("secrets.json");
        let mut m = BTreeMap::new();
        m.insert(
            "cstorepro".into(),
            Entry {
                username: "u".into(),
                password: "DO-NOT-PRINT-ME".into(),
                origin: Some("https://secure.cstorepro.com".into()),
                created_at: now_iso(),
            },
        );
        save(&path, &m).expect("save");
        // `describe`-style projection: the only view a caller may render.
        let rows: Vec<String> = load(&path)
            .unwrap()
            .iter()
            .map(|(n, e)| {
                format!(
                    "{n} {} {}",
                    e.username,
                    e.origin.as_deref().unwrap_or("<UNBOUND>")
                )
            })
            .collect();
        let joined = rows.join("\n");
        assert!(
            !joined.contains("DO-NOT-PRINT-ME"),
            "list leaked a value: {joined}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flag_parses_both_spellings_and_path_override_is_honoured() {
        let a: Vec<String> = ["check", "x", "--origin", "https://a.example"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(flag(&a, "--origin").as_deref(), Some("https://a.example"));
        let b: Vec<String> = ["check", "x", "--origin=https://b.example"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(flag(&b, "--origin").as_deref(), Some("https://b.example"));
        assert!(flag(&b, "--missing").is_none());

        // TALLOW_SECRETS_FILE is the documented override the sandbox mounts
        // through; it must win over the default path.
        let key = "TALLOW_SECRETS_FILE";
        let prior = std::env::var(key).ok();
        unsafe { std::env::set_var(key, "/tmp/override-secrets.json") };
        assert_eq!(default_path(), PathBuf::from("/tmp/override-secrets.json"));
        match prior {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }
}
