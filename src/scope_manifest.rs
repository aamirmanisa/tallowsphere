//! Scope manifest: the signed statement of what a run is allowed to do.
//!
//! The scope register answers "may we touch this host"; the jurisdiction table
//! answers "may we touch this country"; this answers a third question, asked
//! before any of that: **is this run the run it claims to be, and are these the
//! tasks it was signed for?**
//!
//! A manifest is a JSON object signed with Ed25519 over a canonical byte string
//! (the fields below, in a fixed order, `sig` excluded). The engine loads it from
//! `TALLOW_SCOPE_MANIFEST`, verifies it against `TALLOW_SCOPE_MANIFEST_KEY`
//! (32-byte hex public key), and then requires every task the program asks to run
//! to appear in `allowed_tasks`. Nothing is inferred: a task not listed is not
//! authorized, and an expired manifest authorizes nothing.
//!
//! Canonical bytes are `purpose\nrun_id\nissued_by\nnot_before\nexpires_at\n` then
//! each allowed task in the order written, joined by `\n`. That is deliberately
//! simple enough to reimplement in another language — a signature scheme whose
//! canonical form needs a spec to reproduce is a signature nobody can check.
//!
//! Failure modes are fail-closed, and each names itself: no key, malformed hex,
//! bad signature, expired, not yet valid, task not listed.

use std::path::Path;

/// Lower-case hex, without pulling a crate in for sixteen lines of formatting.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd number of hex digits".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16).ok_or("not hex")?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or("not hex")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}


#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Manifest {
    pub purpose: String,
    pub run_id: String,
    pub issued_by: String,
    /// ISO date `YYYY-MM-DD`.
    pub not_before: String,
    /// ISO date `YYYY-MM-DD`.
    pub expires_at: String,
    /// Task ids this run may execute. `*` matches every task (an explicit
    /// statement, not an omission).
    pub allowed_tasks: Vec<String>,
    /// Hex Ed25519 signature over [`Manifest::canonical_bytes`].
    pub sig: String,
}

impl Manifest {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut s = String::new();
        s.push_str(&self.purpose);
        s.push('\n');
        s.push_str(&self.run_id);
        s.push('\n');
        s.push_str(&self.issued_by);
        s.push('\n');
        s.push_str(&self.not_before);
        s.push('\n');
        s.push_str(&self.expires_at);
        s.push('\n');
        for t in &self.allowed_tasks {
            s.push_str(t);
            s.push('\n');
        }
        s.into_bytes()
    }

    /// Verify the signature against `key_hex` (32-byte hex).
    pub fn verify(&self, key_hex: &str) -> Result<(), String> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let raw = hex_decode(key_hex.trim())
            .map_err(|e| format!("scope manifest: key is not hex: {e}"))?;
        let key_bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| "scope manifest: key must be 32 bytes".to_string())?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| format!("scope manifest: key is not a valid Ed25519 point: {e}"))?;
        let sig_raw = hex_decode(self.sig.trim())
            .map_err(|e| format!("scope manifest: signature is not hex: {e}"))?;
        let sig_bytes: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| "scope manifest: signature must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_bytes);
        key.verify(&self.canonical_bytes(), &sig)
            .map_err(|_| "scope manifest: signature does not verify".to_string())
    }

    /// Date window. `today` is `YYYY-MM-DD`; string comparison is correct for
    /// that format and avoids a date library for one comparison.
    pub fn check_window(&self, today: &str) -> Result<(), String> {
        if !self.not_before.is_empty() && today < self.not_before.as_str() {
            return Err(format!(
                "scope manifest: not valid until {} (today {today})",
                self.not_before
            ));
        }
        if !self.expires_at.is_empty() && today > self.expires_at.as_str() {
            return Err(format!(
                "scope manifest: expired on {} (today {today})",
                self.expires_at
            ));
        }
        Ok(())
    }

    /// Whether `task_id` is listed. `*` authorizes everything explicitly.
    pub fn allows_task(&self, task_id: &str) -> bool {
        self.allowed_tasks
            .iter()
            .any(|t| t == "*" || t == task_id)
    }

    pub fn authorize_task(&self, task_id: &str) -> Result<(), String> {
        if self.allows_task(task_id) {
            Ok(())
        } else {
            Err(format!(
                "scope manifest: task '{task_id}' is not listed as authorized for run '{}'",
                self.run_id
            ))
        }
    }
}

/// The loaded policy: `None` when no manifest is configured.
pub fn manifest() -> Option<Result<Manifest, String>> {
    let path = std::env::var("TALLOW_SCOPE_MANIFEST").ok()?;
    if path.trim().is_empty() {
        return None;
    }
    Some(load(Path::new(path.trim())))
}

/// Load and verify, including the key and the date window.
pub fn load(path: &Path) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("scope manifest: {} unreadable: {e}", path.display()))?;
    let man: Manifest = serde_json::from_str(&text)
        .map_err(|e| format!("scope manifest: {} is not a valid manifest: {e}", path.display()))?;
    let key = std::env::var("TALLOW_SCOPE_MANIFEST_KEY")
        .map_err(|_| {
            "scope manifest: a manifest is configured but TALLOW_SCOPE_MANIFEST_KEY is not set"
                .to_string()
        })?;
    man.verify(&key)?;
    man.check_window(&crate::scope::utc_today())?;
    Ok(man)
}

/// The gate `Mesh.run` calls: authorize every task id, in the order given, and
/// name the first one that is not authorized.
pub fn authorize_tasks(ids: &[String]) -> Result<(), String> {
    let Some(policy) = manifest() else {
        return Ok(());
    };
    let man = policy?;
    for id in ids {
        man.authorize_task(id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(tasks: Vec<&str>, not_before: &str, expires_at: &str) -> (Manifest, String) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let mut m = Manifest {
            purpose: "directorate run".to_string(),
            run_id: "run-1".to_string(),
            issued_by: "operator".to_string(),
            not_before: not_before.to_string(),
            expires_at: expires_at.to_string(),
            allowed_tasks: tasks.into_iter().map(str::to_string).collect(),
            sig: String::new(),
        };
        let sig = sk.sign(&m.canonical_bytes());
        m.sig = hex_encode(&sig.to_bytes());
        (m, hex_encode(&sk.verifying_key().to_bytes()))
    }

    #[test]
    fn a_signed_manifest_verifies_and_names_its_tasks() {
        let (m, key) = signed(vec!["a", "b"], "2026-01-01", "2099-01-01");
        m.verify(&key).expect("signature");
        m.check_window("2026-10-24").expect("window");
        m.authorize_task("a").expect("listed");
        let err = m.authorize_task("c").unwrap_err();
        assert!(err.contains("'c' is not listed"), "{err}");
        assert!(err.contains("run-1"), "{err}");
    }

    #[test]
    fn tampering_with_any_field_breaks_the_signature() {
        let (mut m, key) = signed(vec!["a"], "2026-01-01", "2099-01-01");
        m.allowed_tasks.push("backdoor".to_string());
        let err = m.verify(&key).unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn an_expired_or_future_manifest_authorizes_nothing() {
        let (old, key) = signed(vec!["a"], "2025-01-01", "2026-01-01");
        old.verify(&key).unwrap();
        assert!(old.check_window("2026-10-24").unwrap_err().contains("expired"));

        let (future, key) = signed(vec!["a"], "2027-01-01", "2028-01-01");
        future.verify(&key).unwrap();
        assert!(future
            .check_window("2026-10-24")
            .unwrap_err()
            .contains("not valid until"));
    }

    #[test]
    fn a_wildcard_is_an_explicit_statement_not_an_omission() {
        let (m, key) = signed(vec!["*"], "2026-01-01", "2099-01-01");
        m.verify(&key).unwrap();
        assert!(m.authorize_task("anything").is_ok());
        let (empty, key) = signed(vec![], "2026-01-01", "2099-01-01");
        empty.verify(&key).unwrap();
        assert!(empty.authorize_task("anything").is_err());
    }

    #[test]
    fn an_unsigned_manifest_on_disk_is_refused_by_load() {
        let dir = std::env::temp_dir().join(format!("scope-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("manifest.json");
        let (m, key) = signed(vec!["a"], "2026-01-01", "2099-01-01");
        let mut json = serde_json::to_value(&m).unwrap();
        json["sig"] = serde_json::json!("00".repeat(64));
        std::fs::write(&path, json.to_string()).unwrap();
        // SAFETY: single-threaded test that sets one variable and checks a load.
        unsafe { std::env::set_var("TALLOW_SCOPE_MANIFEST_KEY", &key) };
        let err = load(&path).unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
    }
}
