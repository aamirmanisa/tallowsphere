//! Ombuds channel: an append-only record of refusals and objections, with its
//! own credentials.
//!
//! The egress ledger records what the engine *did*. The ombuds log records what
//! the engine **refused to do, and why** — a task the manifest did not authorize,
//! a host outside the jurisdiction table, a budget that had run out. Those are the
//! events a person reviewing a run needs to see, and they must not be editable by
//! the process that produced them.
//!
//! Three properties, each with a test that fails if the property is lost:
//!
//! 1. **Append-only.** Opened `O_APPEND`; each line is written and `fsync`ed
//!    before the call returns. No rewrite path exists in this module.
//! 2. **Tamper-evident.** Each entry carries `seq`, the previous entry's hash, its
//!    own hash, and an Ed25519 signature over all of it. Editing a line, deleting
//!    one, or splicing two logs breaks `verify`, which names the first bad entry.
//! 3. **Separate credentials.** The key comes from `TALLOW_OMBUDS_KEY_FILE` and
//!    must be mode `0600`; it is not the run's key, not the mesh node key, and not
//!    the scope-manifest signing key. A reviewer holding only the public half can
//!    check the log without being able to add to it.
//!
//! Failure is closed: no log file configured means no ombuds channel, and a
//! configured channel that cannot be opened or signed makes `record` fail rather
//! than silently dropping the entry.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Environment variable holding the log path.
pub const ENV_LOG: &str = "TALLOW_OMBUDS_LOG";
/// Environment variable holding the path to the Ed25519 secret key (hex, 32 bytes).
pub const ENV_KEY: &str = "TALLOW_OMBUDS_KEY_FILE";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub seq: u64,
    /// RFC 3339 UTC.
    pub at: String,
    /// `refusal`, `objection`, or `note`.
    pub kind: String,
    /// What the entry is about: a host, a task id, a run id.
    pub subject: String,
    pub detail: String,
    pub prev_hash: String,
    pub hash: String,
    pub sig: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd number of hex digits".into());
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or("not hex")?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or("not hex")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Entry {
    /// The bytes the hash and the signature cover: everything except `hash` and
    /// `sig`, in a fixed order.
    pub fn canonical(&self) -> Vec<u8> {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.seq, self.at, self.kind, self.subject, self.detail, self.prev_hash
        )
        .into_bytes()
    }
}

#[derive(Debug)]
pub struct Ombuds {
    path: PathBuf,
    key: ed25519_dalek::SigningKey,
    seq: u64,
    prev_hash: String,
}

impl Ombuds {
    /// Open the channel named by the environment. `None` when no log is
    /// configured — an absent channel is not an error, it is simply not in use.
    pub fn from_env() -> Result<Option<Ombuds>, String> {
        let Ok(path) = std::env::var(ENV_LOG) else {
            return Ok(None);
        };
        if path.trim().is_empty() {
            return Ok(None);
        }
        let key_path = std::env::var(ENV_KEY).map_err(|_| {
            format!("ombuds: {ENV_LOG} is set but {ENV_KEY} is not; an unsigned ombuds log is not a channel")
        })?;
        Ombuds::open(Path::new(path.trim()), Path::new(key_path.trim())).map(Some)
    }

    pub fn open(path: &Path, key_path: &Path) -> Result<Ombuds, String> {
        // The key file must be private. A 0644 key is readable by every process
        // on the box, which makes "its own credentials" a phrase rather than a
        // property.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(key_path)
                .map_err(|e| format!("ombuds: key {} unreadable: {e}", key_path.display()))?;
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "ombuds: key {} is mode {mode:o}; it must be 0600",
                    key_path.display()
                ));
            }
        }
        let text = std::fs::read_to_string(key_path)
            .map_err(|e| format!("ombuds: key {} unreadable: {e}", key_path.display()))?;
        let raw = hex_decode(text.trim())
            .map_err(|e| format!("ombuds: key {} is not hex: {e}", key_path.display()))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| "ombuds: key must be 32 bytes (64 hex characters)".to_string())?;
        let key = ed25519_dalek::SigningKey::from_bytes(&bytes);

        // Resume the chain from the last entry so a restart does not silently
        // begin a second, unlinked log in the same file.
        let (seq, prev_hash) = match std::fs::read_to_string(path) {
            Ok(existing) if !existing.trim().is_empty() => {
                let last = existing
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .last()
                    .ok_or("ombuds: log is not empty but has no lines")?;
                let e: Entry = serde_json::from_str(last)
                    .map_err(|e| format!("ombuds: last entry is not a valid entry: {e}"))?;
                (e.seq + 1, e.hash.clone())
            }
            _ => (0, String::new()),
        };

        Ok(Ombuds {
            path: path.to_path_buf(),
            key,
            seq,
            prev_hash,
        })
    }

    /// Append one entry. Returns the entry as written.
    pub fn record(&mut self, kind: &str, subject: &str, detail: &str) -> Result<Entry, String> {
        use ed25519_dalek::Signer;
        let mut e = Entry {
            seq: self.seq,
            at: now_rfc3339(),
            kind: kind.to_string(),
            subject: subject.to_string(),
            detail: detail.to_string(),
            prev_hash: self.prev_hash.clone(),
            hash: String::new(),
            sig: String::new(),
        };
        e.hash = sha256_hex(&e.canonical());
        e.sig = hex_encode(&self.key.sign(&e.canonical()).to_bytes());

        let mut line = serde_json::to_string(&e)
            .map_err(|e| format!("ombuds: entry does not serialise: {e}"))?;
        line.push('\n');
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("ombuds: {} unopenable: {e}", self.path.display()))?;
        f.write_all(line.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("ombuds: write to {} failed: {e}", self.path.display()))?;

        self.seq += 1;
        self.prev_hash = e.hash.clone();
        Ok(e)
    }
}

/// Verify a whole log against a public key. Returns the number of entries on
/// success; on failure, the index and reason of the first bad entry.
pub fn verify(path: &Path, public_key_hex: &str) -> Result<usize, String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let raw = hex_decode(public_key_hex)
        .map_err(|e| format!("ombuds: public key is not hex: {e}"))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "ombuds: public key must be 32 bytes".to_string())?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|e| format!("ombuds: public key is not a valid point: {e}"))?;

    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("ombuds: {} unreadable: {e}", path.display()))?;
    let mut prev = String::new();
    let mut n = 0usize;
    for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let e: Entry = serde_json::from_str(line)
            .map_err(|e| format!("ombuds: entry {i} is not valid JSON: {e}"))?;
        if e.seq != i as u64 {
            return Err(format!(
                "ombuds: entry {i} has seq {} — an entry was removed or reordered",
                e.seq
            ));
        }
        if e.prev_hash != prev {
            return Err(format!(
                "ombuds: entry {i} does not link to its predecessor — the chain was broken"
            ));
        }
        let want = sha256_hex(&e.canonical());
        if e.hash != want {
            return Err(format!("ombuds: entry {i} was modified after it was written"));
        }
        let sig_raw = hex_decode(&e.sig)
            .map_err(|e| format!("ombuds: entry {i} signature is not hex: {e}"))?;
        let sig_bytes: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| format!("ombuds: entry {i} signature is not 64 bytes"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        key.verify(&e.canonical(), &sig)
            .map_err(|_| format!("ombuds: entry {i} signature does not verify"))?;
        prev = e.hash.clone();
        n += 1;
    }
    Ok(n)
}

fn now_rfc3339() -> String {
    // Seconds since the epoch, rendered by hand: the module has no need for a
    // date library, and a wrong format here would be visible in `verify`.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Record a refusal when a channel is configured. A failure to record is
/// returned as an error: an ombuds entry that could not be written must not be
/// pretend-written.
pub fn record_refusal(subject: &str, detail: &str) -> Result<(), String> {
    let Some(mut ch) = Ombuds::from_env()? else {
        return Ok(());
    };
    ch.record("refusal", subject, detail).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(name: &str) -> (PathBuf, PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("ombuds-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("ombuds.key");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        std::fs::write(&key, hex_encode(&sk.to_bytes())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (dir.join("ombuds.jsonl"), key, hex_encode(&sk.verifying_key().to_bytes()))
    }

    #[test]
    fn entries_append_and_verify() {
        let (log, key, pubkey) = setup("ok");
        let mut ch = Ombuds::open(&log, &key).unwrap();
        ch.record("refusal", "task:brief", "manifest did not list the task").unwrap();
        ch.record("refusal", "host:example.test", "outside the jurisdiction table").unwrap();
        assert_eq!(verify(&log, &pubkey).unwrap(), 2);
    }

    #[test]
    fn editing_an_entry_is_detected() {
        let (log, key, pubkey) = setup("edit");
        let mut ch = Ombuds::open(&log, &key).unwrap();
        ch.record("refusal", "a", "first").unwrap();
        ch.record("refusal", "b", "second").unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        std::fs::write(&log, text.replace("\"first\"", "\"rewritten\"")).unwrap();
        let err = verify(&log, &pubkey).unwrap_err();
        assert!(err.contains("modified after it was written"), "{err}");
    }

    #[test]
    fn deleting_an_entry_breaks_the_seq_chain() {
        let (log, key, pubkey) = setup("delete");
        let mut ch = Ombuds::open(&log, &key).unwrap();
        ch.record("refusal", "a", "one").unwrap();
        ch.record("refusal", "b", "two").unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        let second = text.lines().nth(1).unwrap().to_string();
        std::fs::write(&log, format!("{second}\n")).unwrap();
        let err = verify(&log, &pubkey).unwrap_err();
        // Dropping the first line leaves seq=1 at index 0: the sequence check
        // names the deletion before the hash link is even consulted.
        assert!(err.contains("was removed or reordered"), "{err}");
    }

    #[test]
    fn a_key_readable_by_others_is_refused() {
        let (log, key, _pubkey) = setup("perms");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = Ombuds::open(&log, &key).unwrap_err();
            assert!(err.contains("must be 0600"), "{err}");
        }
    }

    #[test]
    fn a_restart_resumes_the_chain_instead_of_starting_a_second_log() {
        let (log, key, pubkey) = setup("resume");
        {
            let mut ch = Ombuds::open(&log, &key).unwrap();
            ch.record("refusal", "a", "one").unwrap();
        }
        let mut ch = Ombuds::open(&log, &key).unwrap();
        ch.record("refusal", "b", "two").unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.lines().nth(1).unwrap().contains("\"seq\":1"), "{text}");
        assert_eq!(verify(&log, &pubkey).unwrap(), 2);
    }
}
