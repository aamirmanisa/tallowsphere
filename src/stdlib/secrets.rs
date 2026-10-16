//! Standard library: `tallow.secrets` — API key manager and secrets store.
//!
//! Persistent key-value store for API keys, tokens, and credentials
//! discovered during reconnaissance. Backed by JSON on disk.
//!
//! # At-rest encryption (format v2, AEAD) — fail-closed
//! New writes are sealed with XChaCha20-Poly1305 via `tallow-crypto`
//! (per-object DEK wrapped under the KEK with AES-256-KW, fresh 192-bit
//! nonce, entry name bound as AAD) and stored base64-encoded under the
//! `enc:v2:` prefix. The key-encryption key comes from the
//! `TALLOW_SECRETS_KEY` environment variable (64-char hex or base64 of 32
//! bytes). Without it, writes and reads of sealed values **fail** — there is
//! no silent fallback to the legacy XOR path. Legacy values (`obf:`
//! XOR-obfuscated from older builds, or bare plaintext from the oldest) are
//! read transparently and migrate to the AEAD form on the next write.
//!
//! # API
//! - `SecretStore.new(path)` — open or create a secrets store
//! - `store.set(key, value)` — store a secret
//! - `store.get(key)` — retrieve a secret
//! - `store.delete(key)` — remove a secret
//! - `store.list()` — list all keys (values hidden)
//! - `store.export()` — export all as JSON map

use super::StdlibResult;
use crate::interp::{type_name, Value};
use tallow_crypto::symmetric::xchacha20 as at_rest;

use std::collections::HashMap;
use std::fs;
use zeroize::{Zeroize, Zeroizing};

/// Simple key-value secrets store backed by JSON file.
///
/// Zeroization sweep (2026-09-11, zer. MEDIUM): `Debug` is hand-written and
/// redacts entry values — `entries` holds the *decrypted* plaintext, so a
/// derived `Debug` would print live secrets into logs and panic messages.
///
/// `Serialize`/`Deserialize` are deliberately **not** implemented: nothing
/// (de)serializes this struct itself — `open`/`save` map the on-disk form
/// through [`deobfuscate`]/[`obfuscate`] by hand over a plain
/// `HashMap<String, String>` — so the serde derives were unused and only
/// offered a second, unredacted path for the plaintext entries (audit rule
/// §2: no raw secrets in `Serialize`).
///
/// Values are wiped on drop (best-effort, `zeroize`); the `path` and key
/// names are not secret (they are plaintext on disk by design).
struct SecretStore {
    path: String,
    entries: HashMap<String, String>,
}

impl std::fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretStore")
            .field("path", &self.path)
            .field(
                "entries",
                &format!("{} entries, values [redacted]", self.entries.len()),
            )
            .finish()
    }
}

impl Drop for SecretStore {
    fn drop(&mut self) {
        for value in self.entries.values_mut() {
            value.zeroize();
        }
        self.entries.clear();
    }
}

// ── At-rest obfuscation (NOT encryption) ─────────────────────────────────
// Values are XOR-mangled with a fixed key and base64-encoded before hitting
// disk. This stops casual plaintext inspection only; it is not encryption.

/// Prefix marking obfuscated values on disk (legacy plaintext values lack it).
const OBF_PREFIX: &str = "obf:";
/// Fixed XOR key — obfuscation only, never a real secret.
const OBF_KEY: &[u8] = b"tallow-secrets-obf-v1";

fn obfuscate(value: &str) -> String {
    use base64::Engine;
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        out.push(b ^ OBF_KEY[i % OBF_KEY.len()]);
    }
    format!(
        "{OBF_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(out)
    )
}

fn deobfuscate(value: &str) -> String {
    if let Some(rest) = value.strip_prefix(OBF_PREFIX) {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(rest)
            .unwrap_or_default();
        let plain: Vec<u8> = bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ OBF_KEY[i % OBF_KEY.len()])
            .collect();
        String::from_utf8_lossy(&plain).into_owned()
    } else {
        // Legacy plaintext value written by an older version.
        value.to_string()
    }
}

// ── At-rest encryption v2 (XChaCha20-Poly1305 via tallow-crypto) ─────────
// New writes are sealed as `enc:v2:<base64(nonce‖wrapped-dek‖ciphertext)>`
// with the same discipline as the vault's at-rest format (per-object DEK
// wrapped under the KEK with AES-256-KW, fresh 192-bit nonce, entry name
// bound as AAD). The KEK is `TALLOW_SECRETS_KEY`; without it, sealed reads
// and all writes fail — there is no silent fallback to the legacy XOR path.

/// Prefix marking AEAD-sealed values on disk (format v2).
const ENC_PREFIX: &str = "enc:v2:";
/// Environment variable holding the key-encryption key (32 bytes: 64-char
/// hex or standard base64).
const KEK_ENV: &str = "TALLOW_SECRETS_KEY";
/// AEAD domain separator: binds ciphertext to this store's format.
const AEAD_DOMAIN: &str = "tallow-secrets-v2";

/// Load the KEK from the environment. `Ok(None)` = not configured,
/// `Err` = configured but malformed (never silently ignored).
fn load_kek() -> Result<Option<Zeroizing<[u8; at_rest::KEY_LEN]>>, String> {
    let raw = match std::env::var(KEK_ENV) {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(e) => return Err(format!("{KEK_ENV}: {e}")),
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let bytes: Vec<u8> = if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        raw.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0))
            .collect()
    } else {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(raw)
            .map_err(|e| format!("{KEK_ENV}: not 64-char hex nor base64: {e}"))?
    };
    let key: [u8; at_rest::KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "{KEK_ENV}: expected 32 bytes, got {} (as 64-char hex or base64)",
            bytes.len()
        )
    })?;
    Ok(Some(Zeroizing::new(key)))
}

/// AAD binding a sealed value to this store format and its entry name —
/// a ciphertext cannot be swapped between entries undetected.
fn aad_for(entry_key: &str) -> Vec<u8> {
    format!("{AEAD_DOMAIN}:{entry_key}").into_bytes()
}

/// Seal `plaintext` for `entry_key` into the v2 on-disk form.
fn encrypt_value(
    kek: &[u8; at_rest::KEY_LEN],
    entry_key: &str,
    plaintext: &str,
) -> Result<String, String> {
    let sealed = at_rest::seal_object(kek, plaintext.as_bytes(), &aad_for(entry_key))
        .map_err(|e| format!("seal '{entry_key}': {e}"))?;
    let mut buf =
        Vec::with_capacity(at_rest::NONCE_LEN + at_rest::WRAPPED_DEK_LEN + sealed.ciphertext.len());
    buf.extend_from_slice(&sealed.nonce);
    buf.extend_from_slice(&sealed.wrapped_dek);
    buf.extend_from_slice(&sealed.ciphertext);
    use base64::Engine;
    Ok(format!(
        "{ENC_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(buf)
    ))
}

/// Decrypt a stored value. `kek` is `None` when `TALLOW_SECRETS_KEY` is not
/// set — that is fine for legacy values, but sealed (`enc:v2:`) values then
/// fail closed.
fn decrypt_value(
    kek: Option<&[u8; at_rest::KEY_LEN]>,
    entry_key: &str,
    stored: &str,
) -> Result<String, String> {
    let Some(rest) = stored.strip_prefix(ENC_PREFIX) else {
        // v1: `obf:` XOR-obfuscated, or bare plaintext from the oldest stores.
        return Ok(deobfuscate(stored));
    };
    let kek = kek.ok_or_else(|| {
        format!(
            "value for '{entry_key}' is sealed and {KEK_ENV} is not set — refusing (no silent fallback)"
        )
    })?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(rest)
        .map_err(|e| format!("decode '{entry_key}': {e}"))?;
    if bytes.len() < at_rest::NONCE_LEN + at_rest::WRAPPED_DEK_LEN + at_rest::TAG_LEN {
        return Err(format!(
            "sealed value for '{entry_key}' is too short ({} bytes)",
            bytes.len()
        ));
    }
    let mut nonce = [0u8; at_rest::NONCE_LEN];
    nonce.copy_from_slice(&bytes[..at_rest::NONCE_LEN]);
    let mut wrapped_dek = [0u8; at_rest::WRAPPED_DEK_LEN];
    wrapped_dek.copy_from_slice(
        &bytes[at_rest::NONCE_LEN..at_rest::NONCE_LEN + at_rest::WRAPPED_DEK_LEN],
    );
    let sealed = at_rest::SealedObject {
        nonce,
        wrapped_dek,
        ciphertext: bytes[at_rest::NONCE_LEN + at_rest::WRAPPED_DEK_LEN..].to_vec(),
    };
    let mut plain = at_rest::open_object(kek, &sealed, &aad_for(entry_key))
        .map_err(|e| format!("open '{entry_key}': {e}"))?;
    let out = String::from_utf8(plain.clone()).map_err(|e| format!("utf8 '{entry_key}': {e}"));
    plain.zeroize();
    out
}

impl SecretStore {
    fn open(path: &str) -> Result<Self, String> {
        let kek = load_kek()?;
        let entries = if std::path::Path::new(path).exists() {
            let data = fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
            let parsed: HashMap<String, String> =
                serde_json::from_str(&data).unwrap_or_default();
            let mut decrypted = HashMap::with_capacity(parsed.len());
            for (k, v) in parsed {
                decrypted.insert(k.clone(), decrypt_value(kek.as_ref().map(|k| &**k), &k, &v)?);
            }
            decrypted
        } else {
            HashMap::new()
        };
        Ok(SecretStore { path: path.to_string(), entries })
    }

    fn save(&self) -> Result<(), String> {
        // Fail closed BEFORE touching the file: persistence requires the KEK.
        // The legacy XOR path is read-only — writes never fall back to it.
        let kek = load_kek()?.ok_or_else(|| {
            format!(
                "refusing to persist secrets: {KEK_ENV} is not set (32 bytes as 64-char hex or base64; legacy XOR writes are disabled)"
            )
        })?;
        let parent = std::path::Path::new(&self.path).parent().unwrap_or(std::path::Path::new("."));
        fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?;
        let mut sealed_map: HashMap<String, String> = HashMap::with_capacity(self.entries.len());
        for (k, v) in &self.entries {
            sealed_map.insert(k.clone(), encrypt_value(&kek, k, v)?);
        }
        let json = serde_json::to_string_pretty(&sealed_map)
            .map_err(|e| format!("serialize: {e}"))?;
        // Mode-0600 write (A6.1.1 sweep completion): this store holds
        // credentials — never rely on the process umask. New files are
        // created 0600 and the mode is re-asserted on every write
        // (import_export.rs uses the same 0600-or-refuse pattern).
        let write_result = (|| -> Result<(), String> {
            use std::io::Write as _;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.path)
                .map_err(|e| format!("open: {e}"))?;
            file.write_all(json.as_bytes()).map_err(|e| format!("write: {e}"))?;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod: {e}"))
        })();
        // `sealed_map` holds ciphertext only (indistinguishable from random
        // without the KEK), so unlike the legacy XOR path there is no
        // secret material to wipe here.
        write_result
    }

    fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.entries.insert(key.to_string(), value.to_string());
        self.save()
    }

    fn get(&self, key: &str) -> Option<&String> {
        self.entries.get(key)
    }

    fn delete(&mut self, key: &str) -> Result<(), String> {
        self.entries.remove(key);
        self.save()
    }

    fn keys(&self) -> Vec<&String> {
        self.entries.keys().collect()
    }

    fn to_value(&self) -> Value {
        let entries: Vec<(Value, Value)> = self.entries.iter()
            .map(|(k, v)| (Value::String(k.clone()), Value::String(v.clone())))
            .collect();
        Value::Struct {
            name: "SecretStore".into(),
            fields: vec![
                ("path".into(), Value::String(self.path.clone())),
                ("count".into(), Value::Int(entries.len() as i128)),
                ("keys".into(), Value::Array(self.keys().iter().map(|k| Value::String(k.to_string())).collect())),
            ],
        }
    }

    fn to_map(&self) -> Value {
        let entries: Vec<(Value, Value)> = self.entries.iter()
            .map(|(k, v)| (Value::String(k.clone()), Value::String(v.clone())))
            .collect();
        Value::Map(entries)
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "open" => Some(ss_open(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "SecretStore") {
        return None;
    }
    match method {
        "set" => Some(ss_set(object, args)),
        "get" => Some(ss_get(object, args)),
        "delete" => Some(ss_delete(object, args)),
        "list" => Some(ss_list(object)),
        "export" => Some(ss_export(object)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "open")
}

fn ss_open(args: Vec<Value>) -> StdlibResult {
    let path = expect_first_str(&args, "path")?;
    let store = SecretStore::open(path)?;
    Ok(store.to_value())
}

fn ss_set(value: &Value, args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("SecretStore.set: requires (key, value)".into());
    }
    let fields = match value {
        Value::Struct { name, fields } if name == "SecretStore" => fields,
        _ => return Err(format!("Expected SecretStore, got {}", type_name(value))),
    };
    let path = field_str(fields, "path");
    let mut store = SecretStore::open(&path)?;
    let key = expect_str(&args[0], "key")?;
    let val = expect_str(&args[1], "value")?;
    store.set(key, val)?;
    Ok(store.to_value())
}

fn ss_get(value: &Value, args: Vec<Value>) -> StdlibResult {
    let fields = match value {
        Value::Struct { name, fields } if name == "SecretStore" => fields,
        _ => return Err(format!("Expected SecretStore, got {}", type_name(value))),
    };
    let path = field_str(fields, "path");
    let store = SecretStore::open(&path)?;
    let key = expect_first_str(&args, "key")?;
    match store.get(key) {
        Some(v) => Ok(Value::String(v.clone())),
        None => Ok(Value::Nil),
    }
}

fn ss_delete(value: &Value, args: Vec<Value>) -> StdlibResult {
    let fields = match value {
        Value::Struct { name, fields } if name == "SecretStore" => fields,
        _ => return Err(format!("Expected SecretStore, got {}", type_name(value))),
    };
    let path = field_str(fields, "path");
    let mut store = SecretStore::open(&path)?;
    let key = expect_first_str(&args, "key")?;
    store.delete(key)?;
    Ok(store.to_value())
}

fn ss_list(value: &Value) -> StdlibResult {
    let fields = match value {
        Value::Struct { name, fields } if name == "SecretStore" => fields,
        _ => return Err(format!("Expected SecretStore, got {}", type_name(value))),
    };
    let path = field_str(fields, "path");
    let store = SecretStore::open(&path)?;
    Ok(Value::Array(store.keys().iter().map(|k| Value::String(k.to_string())).collect()))
}

fn ss_export(value: &Value) -> StdlibResult {
    let fields = match value {
        Value::Struct { name, fields } if name == "SecretStore" => fields,
        _ => return Err(format!("Expected SecretStore, got {}", type_name(value))),
    };
    let path = field_str(fields, "path");
    let store = SecretStore::open(&path)?;
    Ok(store.to_map())
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}

fn expect_str<'a>(val: &'a Value, name: &str) -> Result<&'a String, String> {
    match val { Value::String(s) => Ok(s), _ => Err(format!("Expected String for {name}, got {}", type_name(val))) }
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that mutate the process-global KEK env var.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const TEST_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn with_test_key<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized by ENV_LOCK; no other test reads this variable.
        unsafe { std::env::set_var(KEK_ENV, TEST_KEY_HEX) };
        let out = f();
        unsafe { std::env::remove_var(KEK_ENV) };
        out
    }

    fn without_key<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized by ENV_LOCK; no other test reads this variable.
        unsafe { std::env::remove_var(KEK_ENV) };
        f()
    }

    #[test]
    fn obfuscation_round_trips() {
        // ASCII values
        let plain = "sk_live_abc123";
        let obf = obfuscate(plain);
        assert!(obf.starts_with("obf:"), "values must be marked obfuscated");
        assert!(!obf.contains(plain), "plaintext must not appear on disk");
        assert_eq!(deobfuscate(&obf), plain);

        // Multi-byte UTF-8 values (XOR + base64 must round-trip byte-exact)
        let unicode = "token-é-🔑";
        assert_eq!(deobfuscate(&obfuscate(unicode)), unicode);
    }

    #[test]
    fn legacy_plaintext_reads_transparently() {
        let legacy = "plain-ole-value";
        assert_eq!(deobfuscate(legacy), legacy);
    }

    #[test]
    fn store_save_load_round_trip() {
        with_test_key(|| {
            let dir =
                std::env::temp_dir().join(format!("tallow-secrets-test-{}", uuid::Uuid::new_v4()));
            let path = dir.join("secrets.json");
            let path_str = path.to_str().unwrap().to_string();

            let mut store = SecretStore::open(&path_str).unwrap();
            store.set("api_key", "sk_test_123").unwrap();
            store.set("note", "héllo-🔑").unwrap();
            assert_eq!(store.get("api_key").map(|s| s.as_str()), Some("sk_test_123"));

            // Reload from disk — values must survive the AEAD round-trip
            let reloaded = SecretStore::open(&path_str).unwrap();
            assert_eq!(reloaded.get("api_key").map(|s| s.as_str()), Some("sk_test_123"));
            assert_eq!(reloaded.get("note").map(|s| s.as_str()), Some("héllo-🔑"));

            // On-disk form must be sealed (v2) and must not contain plaintext
            let raw = fs::read_to_string(&path_str).unwrap();
            assert!(!raw.contains("sk_test_123"), "plaintext must not be written to disk");
            assert!(raw.contains("enc:v2:"), "values must be sealed in the v2 AEAD format");
            assert!(!raw.contains("obf:"), "no legacy XOR values may be written");

            let _ = fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn legacy_v1_reads_without_key_and_migrates_on_write() {
        // Craft a v1 store on disk: obfuscated value + bare plaintext value.
        let dir = std::env::temp_dir().join(format!("tallow-secrets-v1-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secrets.json");
        let path_str = path.to_str().unwrap().to_string();
        let v1 = format!(
            "{{\n  \"old_obf\": \"{}\",\n  \"old_plain\": \"bare-value\"\n}}\n",
            obfuscate("legacy-obf-value")
        );
        fs::write(&path_str, &v1).unwrap();

        // v1 reads transparently WITHOUT the KEK (legacy path stays readable).
        without_key(|| {
            let store = SecretStore::open(&path_str).unwrap();
            assert_eq!(store.get("old_obf").map(|s| s.as_str()), Some("legacy-obf-value"));
            assert_eq!(store.get("old_plain").map(|s| s.as_str()), Some("bare-value"));
        });

        // The first keyed write migrates everything to v2.
        with_test_key(|| {
            let mut store = SecretStore::open(&path_str).unwrap();
            store.set("fresh", "new-value").unwrap();
            let raw = fs::read_to_string(&path_str).unwrap();
            assert!(!raw.contains("obf:"), "write must migrate away from the XOR format");
            assert!(raw.contains("enc:v2:"));

            let reloaded = SecretStore::open(&path_str).unwrap();
            assert_eq!(reloaded.get("old_obf").map(|s| s.as_str()), Some("legacy-obf-value"));
            assert_eq!(reloaded.get("old_plain").map(|s| s.as_str()), Some("bare-value"));
            assert_eq!(reloaded.get("fresh").map(|s| s.as_str()), Some("new-value"));
        });

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fail_closed_without_key() {
        let dir = std::env::temp_dir().join(format!("tallow-secrets-nokey-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secrets.json");
        let path_str = path.to_str().unwrap().to_string();

        // A write without the KEK must refuse — no silent XOR fallback.
        without_key(|| {
            let mut store = SecretStore::open(&path_str).unwrap();
            let err = store.set("k", "v").unwrap_err();
            assert!(err.contains(KEK_ENV), "error must name the missing env var: {err}");
            assert!(
                !std::path::Path::new(&path_str).exists(),
                "no file may be created without the KEK"
            );
        });

        // A sealed value is unreadable without the KEK.
        with_test_key(|| {
            let mut store = SecretStore::open(&path_str).unwrap();
            store.set("k", "v").unwrap();
        });
        without_key(|| {
            let err = SecretStore::open(&path_str).unwrap_err();
            assert!(err.contains(KEK_ENV), "sealed read without key must fail closed: {err}");
        });

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_values_detect_tampering() {
        let dir = std::env::temp_dir().join(format!("tallow-secrets-tamper-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secrets.json");
        let path_str = path.to_str().unwrap().to_string();

        with_test_key(|| {
            let mut store = SecretStore::open(&path_str).unwrap();
            store.set("k", "top-secret").unwrap();
        });

        // Flip one byte of the sealed payload on disk.
        let raw = fs::read_to_string(&path_str).unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(&raw).unwrap();
        let stored = parsed.get("k").unwrap();
        let payload = stored.strip_prefix(ENC_PREFIX).unwrap();
        use base64::Engine;
        let mut bytes = base64::engine::general_purpose::STANDARD.decode(payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!(
            "{{\n  \"k\": \"{ENC_PREFIX}{}\"\n}}\n",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        );
        fs::write(&path_str, &tampered).unwrap();

        with_test_key(|| {
            let err = SecretStore::open(&path_str).unwrap_err();
            assert!(err.contains("open 'k'"), "tamper must be detected by the AEAD: {err}");
        });

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_fails_closed() {
        let dir = std::env::temp_dir().join(format!("tallow-secrets-wrongkey-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secrets.json");
        let path_str = path.to_str().unwrap().to_string();

        with_test_key(|| {
            let mut store = SecretStore::open(&path_str).unwrap();
            store.set("k", "v").unwrap();
        });

        {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            // SAFETY: serialized by ENV_LOCK; no other test reads this variable.
            unsafe {
                std::env::set_var(
                    KEK_ENV,
                    "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
                )
            };
            let err = SecretStore::open(&path_str).unwrap_err();
            assert!(err.contains("open 'k'"), "wrong KEK must fail closed: {err}");
            unsafe { std::env::remove_var(KEK_ENV) };
        }

        // Base64 form is accepted; malformed values are rejected loudly.
        {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD
                .encode([0x42u8; at_rest::KEY_LEN]);
            // SAFETY: serialized by ENV_LOCK; no other test reads this variable.
            unsafe { std::env::set_var(KEK_ENV, &b64) };
            assert!(load_kek().unwrap().is_some(), "base64 KEK must parse");
            unsafe { std::env::set_var(KEK_ENV, "zz-not-a-key") };
            assert!(load_kek().is_err(), "malformed KEK must be rejected");
            unsafe { std::env::remove_var(KEK_ENV) };
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_redacts_entry_values() {
        let mut entries = HashMap::new();
        entries.insert("api_key".to_string(), "sk_live_do_not_leak".to_string());
        entries.insert("github".to_string(), "ghp_do_not_leak".to_string());
        let store = SecretStore {
            path: "/tmp/tallow-secrets-debug.json".to_string(),
            entries,
        };

        let d = format!("{store:?}");
        assert!(d.contains("[redacted]"), "redaction marker missing: {d}");
        assert!(!d.contains("sk_live_do_not_leak"));
        assert!(!d.contains("ghp_do_not_leak"));
        assert!(d.contains("SecretStore"));
        assert!(d.contains("2 entries"));
    }
}
