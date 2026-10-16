//! Receipt format v1 — canonical-JSON body, sha256 digest, Ed25519
//! signature, `prev` hash chain.
//!
//! Full rules: `artifacts/tallow-mega-mesh-2026-09-27/registry/RECEIPT-FORMAT-v1.md`.
//!
//! Body fields: `v`, `seq`, `kind`, `ts_ms`, `actor`, `subject`, `data`,
//! `prev`. The signature is over `sha256(canonical_json(body))` (the body
//! is every top-level field except `sig`). Stored form is one canonical
//! JSON line. Unknown top-level fields are rejected on parse
//! (`deny_unknown_fields`) so no unsigned data can ride along.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::canonical::{canonical_digest_hex, canonical_json};
use crate::now_ms;

/// Receipt format version.
pub const RECEIPT_V: u32 = 1;

/// Signature block of a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    /// Signature algorithm (v1: `"ed25519"`).
    pub alg: String,
    /// Fingerprint of the signing key: first 8 bytes of `sha256(pubkey)`, hex.
    pub key_fp: String,
    /// Signature over the digest bytes, hex-encoded (128 hex chars).
    pub sig_hex: String,
}

/// One receipt (signed form when `sig` is `Some`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub v: u32,
    pub seq: u64,
    pub kind: String,
    pub ts_ms: u64,
    pub actor: String,
    pub subject: Option<String>,
    pub data: Value,
    pub prev: Option<String>,
    pub sig: Option<Signed>,
}

/// Receipt errors.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("bad JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsigned receipt")]
    Unsigned,
    #[error("bad hex: {0}")]
    BadHex(#[from] hex::FromHexError),
    #[error("signature must be 64 bytes, got {0}")]
    BadSigLen(usize),
    #[error("bad signature: {0}")]
    BadSignature(#[from] ed25519_dalek::SignatureError),
    #[error("key fingerprint mismatch: receipt {got}, verifier {want}")]
    KeyFp { got: String, want: String },
    #[error("unsupported receipt version {0} (this reader: v1)")]
    UnsupportedVersion(u32),
}

impl Receipt {
    /// The signed body as a JSON value (fixed fields, explicit nulls).
    pub fn body_value(&self) -> Value {
        json!({
            "v": self.v,
            "seq": self.seq,
            "kind": self.kind,
            "ts_ms": self.ts_ms,
            "actor": self.actor,
            "subject": self.subject,
            "data": self.data,
            "prev": self.prev,
        })
    }

    /// Digest of the body: `sha256(canonical_json(body))`, lowercase hex.
    pub fn digest_hex(&self) -> String {
        canonical_digest_hex(&self.body_value())
    }

    /// Full stored form as a JSON value (body + `sig`).
    pub fn to_value(&self) -> Value {
        let mut v = self.body_value();
        if let Value::Object(map) = &mut v {
            match &self.sig {
                Some(s) => {
                    map.insert(
                        "sig".into(),
                        json!({"alg": s.alg, "key_fp": s.key_fp, "sig_hex": s.sig_hex}),
                    );
                }
                None => {
                    map.insert("sig".into(), Value::Null);
                }
            }
        }
        v
    }

    /// Canonical single-line stored form.
    pub fn to_line(&self) -> String {
        canonical_json(&self.to_value())
    }

    /// Parse a stored line (strict: unknown fields rejected; version must
    /// equal [`RECEIPT_V`] — a v1 reader must not silently accept a future
    /// format it cannot interpret).
    pub fn from_line(line: &str) -> Result<Self, ReceiptError> {
        let r: Receipt = serde_json::from_str(line)?;
        if r.v != RECEIPT_V {
            return Err(ReceiptError::UnsupportedVersion(r.v));
        }
        Ok(r)
    }

    /// Build and sign a new receipt.
    pub fn sign_new(
        seq: u64,
        kind: &str,
        actor: &str,
        subject: Option<&str>,
        data: Value,
        prev: Option<String>,
        key: &SigningKey,
    ) -> Self {
        let mut r = Receipt {
            v: RECEIPT_V,
            seq,
            kind: kind.to_string(),
            ts_ms: now_ms(),
            actor: actor.to_string(),
            subject: subject.map(str::to_string),
            data,
            prev,
            sig: None,
        };
        let digest = r.digest_hex();
        let sig = key.sign(digest.as_bytes());
        r.sig = Some(Signed {
            alg: "ed25519".to_string(),
            key_fp: key_fp16(&key.verifying_key()),
            sig_hex: hex::encode(sig.to_bytes()),
        });
        r
    }

    /// Verify the signature against `pubkey` (fingerprint checked too).
    pub fn verify(&self, pubkey: &VerifyingKey) -> Result<(), ReceiptError> {
        let s = self.sig.as_ref().ok_or(ReceiptError::Unsigned)?;
        let want = key_fp16(pubkey);
        if s.key_fp != want {
            return Err(ReceiptError::KeyFp {
                got: s.key_fp.clone(),
                want,
            });
        }
        let raw = hex::decode(&s.sig_hex)?;
        let arr: [u8; 64] = raw
            .try_into()
            .map_err(|v: Vec<u8>| ReceiptError::BadSigLen(v.len()))?;
        let sig = Signature::from_bytes(&arr);
        let digest = self.digest_hex();
        Ok(pubkey.verify_strict(digest.as_bytes(), &sig)?)
    }
}

/// Key fingerprint: first 8 bytes of `sha256(pubkey)`, lowercase hex.
pub fn key_fp16(vk: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(vk.to_bytes())[..8])
}

/// Deterministic DEV actor key (TEST ONLY — seed `tallow-test/registry/actor`).
pub fn dev_actor_key() -> SigningKey {
    tallow_admission::devkeys::ed_from_label("tallow-test/registry/actor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_tamper() {
        let key = dev_actor_key();
        let r = Receipt::sign_new(
            1,
            "device.mint",
            "anchor-0",
            Some("operator-1"),
            json!({"role": "owner"}),
            None,
            &key,
        );
        r.verify(&key.verifying_key()).expect("verify");

        let mut tampered = r.clone();
        tampered.data = json!({"role": "guest"});
        assert!(
            tampered.verify(&key.verifying_key()).is_err(),
            "tamper must fail"
        );

        let other = tallow_admission::devkeys::ed_from_label("tallow-test/registry/other");
        assert!(
            r.verify(&other.verifying_key()).is_err(),
            "wrong key must fail"
        );
    }

    #[test]
    fn line_roundtrip_and_strictness() {
        let key = dev_actor_key();
        let r = Receipt::sign_new(
            7,
            "device.revoke",
            "anchor-0",
            Some("guest-1"),
            json!({}),
            None,
            &key,
        );
        let line = r.to_line();
        let parsed = Receipt::from_line(&line).expect("parse");
        assert_eq!(parsed, r);
        assert_eq!(parsed.digest_hex(), r.digest_hex());

        // extra top-level field → rejected (nothing unsigned rides along)
        let mut v: Value = serde_json::from_str(&line).expect("json");
        v.as_object_mut()
            .expect("obj")
            .insert("extra".into(), json!(1));
        let doctored = canonical_json(&v);
        assert!(Receipt::from_line(&doctored).is_err());
    }
}
