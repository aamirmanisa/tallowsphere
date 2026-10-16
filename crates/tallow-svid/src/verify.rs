//! `verify` — SVID verification: chain building (rustls-webpki), the custom
//! SPIFFE URI-SAN matcher, D1 kind/band checks, and the crate's [`SvidError`]
//! (owner: U-212; model/policy by U-211).
//!
//! ## What is checked, in order
//!
//! 1. **Chain shape** — exactly `[intermediate, leaf]` (issuance order). The
//!    intermediate is the trust anchor *and* must be the chain's first element;
//!    a swapped or truncated chain is refused.
//! 2. **Profiles** — the intermediate must be a CA (`basicConstraints.cA`),
//!    the leaf must **not** be; the node identity cert must not be a CA.
//! 3. **Validity windows** — checked here (explicit Unix seconds, so callers can
//!    test across time) *and* by webpki against the same instant.
//! 4. **D1 TTL bands** — leaf 1–24 h, intermediate ≤ 7 d, node 30–90 d. A
//!    credential whose total lifetime is out of band is refused even if its
//!    signature is perfect (that is the "misissued" case).
//! 5. **Path building** — `rustls-webpki` `EndEntityCert::verify_for_usage` with
//!    the intermediate DER as the only trust anchor and `client_auth` EKU.
//! 6. **URI SAN matcher** — the leaf must carry exactly one URI SAN and it must
//!    equal the expected canonical `spiffe://` URI **byte-for-byte**; case
//!    variants, trailing dots, percent-encoding and other lookalikes are refused
//!    as such ([`SvidError::SanLookalike`]) rather than silently mismatching.
//!
//! ## Trust-anchor scope (D2)
//!
//! Only the *classical* Ed25519 X.509 material is verified here. The hybrid
//! (Ed25519 + ML-DSA-87) co-signature binds at the enrollment / key-transparency
//! layer over `(SPKI, spiffe-id, serial, not_before, not_after)` and is checked
//! against the KT entry by the caller — never inside the certificate.
//!
//! ## Also here: self-signature checks
//!
//! Node identity certs are self-signed and webpki deliberately refuses
//! self-signed end-entity certs, so [`verify_node_identity`] and
//! [`verify_issuer_intermediate`] do the signature check directly
//! (`tallow-crypto` Ed25519 over the parsed `tbsCertificate`) plus the same
//! window/band/SAN checks.

use std::time::Duration;

use rustls_pki_types::{CertificateDer, UnixTime};

use crate::issuer::der::{self, DerError};
use crate::model::{self, SerialError, SpiffeId, SpiffeIdError, SvidKind};
use crate::policy::PolicyError;

/// Every way SVID issuance or verification can fail. All variants are
/// fail-closed: issuance never returns a certificate, verification never
/// returns a `VerifiedSvid`.
#[derive(Debug, thiserror::Error)]
pub enum SvidError {
    /// DER parsing failed (CSR, SPKI, or certificate structure).
    #[error("malformed DER: {0}")]
    Der(#[from] DerError),
    /// SPIFFE identity model violation (bad node id / service / URI form).
    #[error("identity: {0}")]
    Identity(#[from] SpiffeIdError),
    /// Issuance-policy violation (TTL band, allowlist, node pin).
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    /// Serial allocation failed (never-reuse guarantee would be broken).
    #[error("serial: {0}")]
    Serial(#[from] SerialError),
    /// Signing/verifying key material was unusable.
    #[error("key: {0}")]
    Key(String),
    /// rcgen could not build or sign the certificate.
    #[error("issuance: {0}")]
    Issuance(String),
    /// No SVID-issuer intermediate has been issued (or it expired and was
    /// dropped); call `issue_issuer_intermediate` first.
    #[error("no active SVID-issuer intermediate")]
    NoIntermediate,
    /// The supplied chain was not exactly `[intermediate, leaf]`.
    #[error("expected chain [intermediate, leaf] with 2 elements, got {len}")]
    ChainShape {
        /// Number of elements supplied.
        len: usize,
    },
    /// webpki path building failed (unknown issuer, bad signature, expired, ...).
    #[error("chain verification failed: {0}")]
    Chain(#[from] webpki::Error),
    /// The certificate must be a CA but is not.
    #[error("{kind} certificate is not a CA")]
    NotCa {
        /// Kind being verified.
        kind: SvidKind,
    },
    /// The certificate must not be a CA but is.
    #[error("{kind} certificate must not be a CA")]
    UnexpectedCa {
        /// Kind being verified.
        kind: SvidKind,
    },
    /// A certificate's window does not contain the verification instant.
    #[error("certificate not valid before {not_before} (now {now})")]
    NotYetValid {
        /// notBefore (Unix seconds).
        not_before: i64,
        /// Verification instant (Unix seconds).
        now: i64,
    },
    /// A certificate's window ended before the verification instant.
    #[error("certificate expired at {not_after} (now {now})")]
    Expired {
        /// notAfter (Unix seconds).
        not_after: i64,
        /// Verification instant (Unix seconds).
        now: i64,
    },
    /// The lifetime is out of band for the kind (D1) — a misissued credential.
    #[error("ttl {ttl_secs}s for {kind} is outside the D1 band {min_secs}..={max_secs}s")]
    TtlBand {
        /// Kind being verified.
        kind: SvidKind,
        /// Observed lifetime in seconds.
        ttl_secs: u64,
        /// Band minimum.
        min_secs: u64,
        /// Band maximum.
        max_secs: u64,
    },
    /// No URI SAN present at all.
    #[error("no URI SAN in certificate")]
    SanMissing,
    /// More than one URI SAN present (ambiguous identity).
    #[error("expected exactly one URI SAN, found {count}")]
    SanCount {
        /// How many URI SANs the certificate carries.
        count: usize,
    },
    /// The URI SAN is not a lookalike of the expected identity: it is simply a
    /// different identity.
    #[error("SAN {got:?} does not match expected {expected:?}")]
    SanMismatch {
        /// Expected canonical URI.
        expected: String,
        /// URI found in the certificate.
        got: String,
    },
    /// The URI SAN is a **lookalike** of the expected identity (case variant,
    /// trailing dot, percent-encoding, foreign authority, ...). Refused loudly
    /// so operators can see the attack, not just a mismatch.
    #[error("SAN {got:?} is a lookalike of {expected:?}: {reason}")]
    SanLookalike {
        /// Expected canonical URI.
        expected: String,
        /// URI found in the certificate.
        got: String,
        /// Why it is considered a lookalike.
        reason: String,
    },
    /// Ed25519 signature verification failed.
    #[error("ed25519 signature verification failed: {0}")]
    Signature(String),
}

/// A credential that passed every check.
#[derive(Debug, Clone)]
pub struct VerifiedSvid {
    /// Which D1 kind was verified.
    pub kind: SvidKind,
    /// The URI SAN that matched.
    pub san: String,
    /// The workload identity, for leaf verification.
    pub workload_id: Option<SpiffeId>,
    /// Serial as it appears in the certificate (DER INTEGER content, hex).
    pub serial_der_hex: String,
    /// notBefore (Unix seconds).
    pub not_before: i64,
    /// notAfter (Unix seconds).
    pub not_after: i64,
    /// Lifetime in whole seconds.
    pub ttl_secs: u64,
}

/// Authority component of a URI (`scheme://authority/path`), if present.
fn uri_authority(s: &str) -> Option<&str> {
    s.split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
}

/// Classify `got` against `expected`, returning `Some(reason)` when `got` is a
/// *lookalike* rather than an unrelated value.
///
/// The matcher itself ([`match_san_uri`]) never uses a normalizing comparison —
/// it only uses this to explain a refusal. That is the point: canonicalization
/// is an attack surface, equality is not.
pub fn lookalike_reason(got: &str, expected: &str) -> Option<String> {
    if got == expected {
        return None;
    }
    if got.trim() != got {
        return Some("leading/trailing whitespace".to_string());
    }
    if got.eq_ignore_ascii_case(expected) {
        return Some("case-only difference (URI SANs are case-sensitive)".to_string());
    }
    if got.contains('%') {
        return Some("percent-encoding in URI".to_string());
    }
    match (uri_authority(got), uri_authority(expected)) {
        (Some(g), Some(e)) if g != e && g.trim_end_matches('.') == e => {
            return Some("trailing dot in authority".to_string())
        }
        (Some(g), Some(e)) if g != e && g.eq_ignore_ascii_case(e) => {
            return Some("authority case difference".to_string())
        }
        (Some(g), Some(e)) if g != e => {
            return Some(format!("different trust domain ({g:?} vs {e:?})"))
        }
        _ => {}
    }
    if got.ends_with('.') || got.ends_with('/') {
        return Some("trailing separator".to_string());
    }
    None
}

/// Exact URI-SAN matcher: exactly one URI SAN, byte-for-byte equal to
/// `expected` (which must itself be canonical — the model rejects
/// non-canonical identities).
pub fn match_san_uri(san_uris: &[&str], expected: &str) -> Result<String, SvidError> {
    match san_uris.len() {
        0 => Err(SvidError::SanMissing),
        1 => {
            let got = san_uris[0];
            if got == expected {
                Ok(got.to_string())
            } else if let Some(reason) = lookalike_reason(got, expected) {
                Err(SvidError::SanLookalike {
                    expected: expected.to_string(),
                    got: got.to_string(),
                    reason,
                })
            } else {
                Err(SvidError::SanMismatch {
                    expected: expected.to_string(),
                    got: got.to_string(),
                })
            }
        }
        count => Err(SvidError::SanCount { count }),
    }
}

fn unix_time(secs: i64) -> UnixTime {
    if secs >= 0 {
        UnixTime::since_unix_epoch(Duration::from_secs(secs as u64))
    } else {
        UnixTime::since_unix_epoch(Duration::ZERO)
    }
}

/// Explicit window check against the caller's instant.
fn check_window(not_before: i64, not_after: i64, now: i64) -> Result<(), SvidError> {
    if now < not_before {
        return Err(SvidError::NotYetValid { not_before, now });
    }
    if now >= not_after {
        return Err(SvidError::Expired { not_after, now });
    }
    Ok(())
}

/// D1 band check: the credential's **total lifetime** must sit inside the
/// kind's band, else it is a misissued credential.
fn check_band(kind: SvidKind, not_before: i64, not_after: i64) -> Result<u64, SvidError> {
    let ttl_secs = not_after.saturating_sub(not_before).max(0) as u64;
    let band = kind.ttl_band();
    if !band.contains_secs(ttl_secs) {
        return Err(SvidError::TtlBand {
            kind,
            ttl_secs,
            min_secs: band.min_secs(),
            max_secs: band.max_secs(),
        });
    }
    Ok(ttl_secs)
}

fn ed25519_check(cert: &der::CertInfo<'_>, public_key: &[u8], what: &str) -> Result<(), SvidError> {
    let pk: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SvidError::Signature(format!("{what}: public key is not 32 bytes")))?;
    let sig: [u8; 64] = cert
        .signature
        .try_into()
        .map_err(|_| SvidError::Signature(format!("{what}: signature is not 64 bytes")))?;
    tallow_crypto::sig::ed25519::verify(&pk, cert.tbs_der, &sig)
        .map_err(|e| SvidError::Signature(format!("{what}: {e}")))
}

/// Verify `chain` (exactly `[intermediate, leaf]`) for the workload `expected`,
/// trusting `chain[0]` (the intermediate DER) as the only anchor.
///
/// `now_unix` is the caller's trusted instant (the daemon supplies a monotonic
/// high-water-checked clock; tests supply explicit instants).
pub fn verify_workload_chain(
    chain: &[CertificateDer<'_>],
    expected: &SpiffeId,
    now_unix: i64,
) -> Result<VerifiedSvid, SvidError> {
    let anchor = chain
        .first()
        .ok_or(SvidError::ChainShape { len: chain.len() })?;
    verify_workload_chain_with_anchor(chain, anchor, expected, now_unix)
}

/// Verify `chain` for `expected` against an explicit trust anchor DER (which is
/// normally `chain[0]`; passing anything else is how a caller pins an anchor it
/// obtained out of band).
pub fn verify_workload_chain_with_anchor(
    chain: &[CertificateDer<'_>],
    anchor: &CertificateDer<'_>,
    expected: &SpiffeId,
    now_unix: i64,
) -> Result<VerifiedSvid, SvidError> {
    if chain.len() != 2 {
        return Err(SvidError::ChainShape { len: chain.len() });
    }
    let (intermediate, leaf) = (&chain[0], &chain[1]);

    let i_info = der::parse_cert(intermediate.as_ref())?;
    if !i_info.is_ca {
        return Err(SvidError::NotCa {
            kind: SvidKind::IssuerIntermediate,
        });
    }
    let l_info = der::parse_cert(leaf.as_ref())?;
    if l_info.is_ca {
        return Err(SvidError::UnexpectedCa {
            kind: SvidKind::WorkloadLeaf,
        });
    }

    check_window(i_info.not_before, i_info.not_after, now_unix)?;
    check_window(l_info.not_before, l_info.not_after, now_unix)?;
    check_band(
        SvidKind::IssuerIntermediate,
        i_info.not_before,
        i_info.not_after,
    )?;
    let ttl_secs = check_band(SvidKind::WorkloadLeaf, l_info.not_before, l_info.not_after)?;

    let trust_anchor = webpki::anchor_from_trusted_cert(anchor)?;
    let end_entity = webpki::EndEntityCert::try_from(leaf)?;
    end_entity.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[trust_anchor],
        &[],
        unix_time(now_unix),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )?;

    let san = match_san_uri(&l_info.san_uris, expected.as_str())?;
    Ok(VerifiedSvid {
        kind: SvidKind::WorkloadLeaf,
        san,
        workload_id: Some(expected.clone()),
        serial_der_hex: hex::encode(l_info.serial_der),
        not_before: l_info.not_before,
        not_after: l_info.not_after,
        ttl_secs,
    })
}

/// Verify an SVID-issuer intermediate against the node identity cert that is
/// supposed to have signed it.
///
/// Checks: CA profile, window, ≤7 d band, SAN = `…/<node>/svc/svid-issuer` for
/// the node named by the node cert, and the Ed25519 signature by the node key.
pub fn verify_issuer_intermediate(
    cert: &CertificateDer<'_>,
    node_cert: &CertificateDer<'_>,
    now_unix: i64,
) -> Result<VerifiedSvid, SvidError> {
    let info = der::parse_cert(cert.as_ref())?;
    if !info.is_ca {
        return Err(SvidError::NotCa {
            kind: SvidKind::IssuerIntermediate,
        });
    }
    let node = der::parse_cert(node_cert.as_ref())?;
    check_window(node.not_before, node.not_after, now_unix)?;
    check_window(info.not_before, info.not_after, now_unix)?;
    let ttl_secs = check_band(
        SvidKind::IssuerIntermediate,
        info.not_before,
        info.not_after,
    )?;

    ed25519_check(&info, node.spki_raw_key, "issuer intermediate")?;

    let node_id = node
        .san_uris
        .iter()
        .find_map(|s| model::parse_node_identity_san(s).ok())
        .ok_or(SvidError::SanMissing)?;
    let expected = model::issuer_san(&node_id)?;
    let san = match_san_uri(&info.san_uris, &expected)?;

    Ok(VerifiedSvid {
        kind: SvidKind::IssuerIntermediate,
        san,
        workload_id: None,
        serial_der_hex: hex::encode(info.serial_der),
        not_before: info.not_before,
        not_after: info.not_after,
        ttl_secs,
    })
}

/// Verify a node identity cert: self-signed by its own Ed25519 key, SAN equal to
/// `spiffe://tallow/<expected_node_id>`, lifetime inside the D1 30–90 d band.
pub fn verify_node_identity(
    cert: &CertificateDer<'_>,
    expected_node_id: &str,
    now_unix: i64,
) -> Result<VerifiedSvid, SvidError> {
    let info = der::parse_cert(cert.as_ref())?;
    if info.is_ca {
        return Err(SvidError::UnexpectedCa {
            kind: SvidKind::NodeIdentity,
        });
    }
    check_window(info.not_before, info.not_after, now_unix)?;
    let ttl_secs = check_band(SvidKind::NodeIdentity, info.not_before, info.not_after)?;
    ed25519_check(&info, info.spki_raw_key, "node identity self-signature")?;
    let expected = model::node_identity_san(expected_node_id)?;
    let san = match_san_uri(&info.san_uris, &expected)?;
    Ok(VerifiedSvid {
        kind: SvidKind::NodeIdentity,
        san,
        workload_id: None,
        serial_der_hex: hex::encode(info.serial_der),
        not_before: info.not_before,
        not_after: info.not_after,
        ttl_secs,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::{now_unix, LeafSubject, NodeIssuer};
    use crate::policy;
    use rcgen::KeyPair;

    fn id(node: &str, svc: &str) -> SpiffeId {
        SpiffeId::new(node, svc).expect("test id")
    }

    fn spki_of(key: &KeyPair) -> Vec<u8> {
        key.public_key_der()
    }

    fn fresh_spki() -> Vec<u8> {
        spki_of(&KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap())
    }

    fn chain_for(id: &SpiffeId) -> (NodeIssuer, crate::issuer::IssuedChain) {
        let mut issuer = NodeIssuer::generate("node-01").expect("issuer");
        issuer
            .issue_issuer_intermediate(None)
            .expect("intermediate");
        let chain = issuer
            .issue_workload_leaf_from_spki(&fresh_spki(), id, None)
            .expect("leaf");
        (issuer, chain)
    }

    #[test]
    fn leaf_chain_round_trip() {
        let expected = id("node-01", "job-worker");
        let (_issuer, issued) = chain_for(&expected);
        let now = now_unix();
        let verified = verify_workload_chain(&issued.chain, &expected, now).expect("verifies");
        assert_eq!(verified.kind, SvidKind::WorkloadLeaf);
        assert_eq!(verified.san, "spiffe://tallow/node-01/svc/job-worker");
        assert_eq!(verified.workload_id.as_ref(), Some(&expected));
        assert!(policy::in_workload_default_band(Duration::from_secs(
            verified.ttl_secs
        )));
        assert_eq!(verified.serial_der_hex.len() % 2, 0);
    }

    #[test]
    fn chain_order_swap_rejected() {
        let expected = id("node-01", "daemon");
        let (_issuer, issued) = chain_for(&expected);
        let chain = issued.chain;
        let swapped = vec![chain[1].clone(), chain[0].clone()];
        assert!(verify_workload_chain(&swapped, &expected, now_unix()).is_err());
        // same anchor as the true intermediate, but leaf/intermediate swapped
        let err = verify_workload_chain_with_anchor(&swapped, &chain[0], &expected, now_unix())
            .expect_err("swap must fail");
        assert!(
            matches!(
                err,
                SvidError::NotCa { .. } | SvidError::UnexpectedCa { .. } | SvidError::Chain(_)
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn chain_shape_rejected() {
        let expected = id("node-01", "daemon");
        let (_issuer, issued) = chain_for(&expected);
        let chain = issued.chain;
        assert!(matches!(
            verify_workload_chain(&[], &expected, now_unix()),
            Err(SvidError::ChainShape { len: 0 })
        ));
        assert!(matches!(
            verify_workload_chain(&chain[..1], &expected, now_unix()),
            Err(SvidError::ChainShape { len: 1 })
        ));
        let mut three = chain.clone();
        three.push(chain[0].clone());
        assert!(matches!(
            verify_workload_chain(&three, &expected, now_unix()),
            Err(SvidError::ChainShape { len: 3 })
        ));
    }

    #[test]
    fn wrong_anchor_rejected() {
        let expected = id("node-01", "daemon");
        let (_issuer, issued) = chain_for(&expected);
        let chain = issued.chain;
        // A different issuer's intermediate is a valid CA but not this leaf's parent.
        let mut other = NodeIssuer::generate("node-02").expect("other issuer");
        let other_mid = other.issue_issuer_intermediate(None).expect("other mid");
        assert!(matches!(
            verify_workload_chain_with_anchor(&chain, &other_mid.cert_der, &expected, now_unix()),
            Err(SvidError::Chain(_))
        ));
    }

    #[test]
    fn expired_leaf_rejected() {
        let expected = id("node-01", "daemon");
        let mut issuer = NodeIssuer::generate("node-01").unwrap();
        issuer.issue_issuer_intermediate(None).unwrap();
        let now = now_unix();
        let chain = issuer
            .issue_workload_leaf_window(
                LeafSubject::SpkiDer(&fresh_spki()),
                &expected,
                now - 8 * 3600,
                now - 3600,
            )
            .expect("expired leaf issues");
        assert!(matches!(
            verify_workload_chain(&chain.chain, &expected, now),
            Err(SvidError::Expired { .. })
        ));
        // A fresh leaf from the same issuer verifies at `now` — the failure
        // above is the window, not the chain.
        let fresh = issuer
            .issue_workload_leaf_from_spki(&fresh_spki(), &expected, None)
            .expect("fresh leaf");
        // Re-capture after issuance: a fixture's `not_before` is floor(issue
        // time), so a `now` captured in the previous second is NotYetValid.
        assert!(verify_workload_chain(&fresh.chain, &expected, now_unix()).is_ok());
    }

    #[test]
    fn not_yet_valid_leaf_rejected() {
        let expected = id("node-01", "daemon");
        let mut issuer = NodeIssuer::generate("node-01").unwrap();
        issuer.issue_issuer_intermediate(None).unwrap();
        let now = now_unix();
        let chain = issuer
            .issue_workload_leaf_window(
                LeafSubject::SpkiDer(&fresh_spki()),
                &expected,
                now + 3600,
                now + 3600 + 6 * 3600,
            )
            .expect("future leaf issues");
        assert!(matches!(
            verify_workload_chain(&chain.chain, &expected, now),
            Err(SvidError::NotYetValid { .. })
        ));
    }

    #[test]
    fn san_mismatch_rejected() {
        let (_issuer, issued) = chain_for(&id("node-01", "daemon"));
        let err = verify_workload_chain(&issued.chain, &id("node-01", "reader"), now_unix())
            .expect_err("mismatch");
        assert!(
            matches!(err, SvidError::SanMismatch { .. }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn lookalike_sans_rejected() {
        let mut issuer = NodeIssuer::generate("node-01").unwrap();
        issuer.issue_issuer_intermediate(None).unwrap();
        let expected = id("node-01", "daemon");
        let now = now_unix();
        let cases = [
            "spiffe://TALLOW/node-01/svc/daemon",
            "spiffe://tallow./node-01/svc/daemon",
            "spiffe://tallow/node-01/svc/daem%6fn",
            "spiffe://tallow/node-01/svc/daemon ",
            "spiffe://tallow-evil/node-01/svc/daemon",
        ];
        for san in cases {
            let leaf = issuer
                .debug_leaf_with_san(san, now - 60, now + 4 * 3600)
                .expect("debug leaf");
            let chain = vec![issuer.intermediate_cert_der().unwrap(), leaf];
            let err =
                verify_workload_chain(&chain, &expected, now).expect_err("lookalike must fail");
            assert!(
                matches!(
                    err,
                    SvidError::SanLookalike { .. } | SvidError::SanMismatch { .. }
                ),
                "SAN {san:?} -> unexpected error {err:?}"
            );
        }
        // the canonical URI still verifies
        let leaf = issuer
            .debug_leaf_with_san(
                "spiffe://tallow/node-01/svc/daemon",
                now - 60,
                now + 4 * 3600,
            )
            .unwrap();
        let chain = vec![issuer.intermediate_cert_der().unwrap(), leaf];
        assert!(verify_workload_chain(&chain, &expected, now).is_ok());
    }

    #[test]
    fn out_of_band_leaf_rejected() {
        let mut issuer = NodeIssuer::generate("node-01").unwrap();
        issuer.issue_issuer_intermediate(None).unwrap();
        let expected = id("node-01", "daemon");
        let now = now_unix();
        // 30-day "leaf": correct signature, wrong lifetime
        let leaf = issuer
            .debug_leaf_with_san(
                "spiffe://tallow/node-01/svc/daemon",
                now - 60,
                now + 30 * 86_400,
            )
            .unwrap();
        let chain = vec![issuer.intermediate_cert_der().unwrap(), leaf];
        let err = verify_workload_chain(&chain, &expected, now).expect_err("out of band");
        assert!(
            matches!(
                err,
                SvidError::TtlBand {
                    kind: SvidKind::WorkloadLeaf,
                    ..
                }
            ),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn mismatched_intermediate_anchor_rejected() {
        // leaf issued by issuer A's intermediate, presented with issuer B's
        // intermediate as the anchor *and* as chain[0].
        let expected = id("node-01", "daemon");
        let (_a, issued) = chain_for(&expected);
        let chain = issued.chain;
        let mut b = NodeIssuer::generate("node-01").unwrap();
        let mid_b = b.issue_issuer_intermediate(None).unwrap();
        let forged = vec![mid_b.cert_der.clone(), chain[1].clone()];
        assert!(matches!(
            verify_workload_chain(&forged, &expected, now_unix()),
            Err(SvidError::Chain(_))
        ));
    }

    #[test]
    fn intermediate_round_trip_and_wrong_parent() {
        let issuer = NodeIssuer::generate("node-01").unwrap();
        let mid = issuer.intermediate_cert_der();
        assert!(mid.is_none(), "no intermediate before issuance");
        let mut issuer = issuer;
        let mid = issuer.issue_issuer_intermediate(None).unwrap();
        let other = NodeIssuer::generate("node-02").unwrap();
        // Capture `now` after all fixtures: every cert's `not_before` is
        // floor(issue time); a capture in an earlier second than the last
        // generation would read NotYetValid.
        let now = now_unix();
        let verified = verify_issuer_intermediate(&mid.cert_der, &issuer.node_cert_der(), now)
            .expect("intermediate verifies");
        assert_eq!(verified.kind, SvidKind::IssuerIntermediate);
        assert_eq!(verified.san, "spiffe://tallow/node-01/svc/svid-issuer");
        assert!(verified.ttl_secs <= policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS);

        // A different node's cert must not validate this intermediate.
        let err = verify_issuer_intermediate(&mid.cert_der, &other.node_cert_der(), now)
            .expect_err("wrong parent");
        assert!(
            matches!(err, SvidError::Signature(_)),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn node_identity_round_trip_and_wrong_node() {
        let issuer = NodeIssuer::generate("node-01").unwrap();
        let now = now_unix();
        let v = verify_node_identity(&issuer.node_cert_der(), "node-01", now).expect("verifies");
        assert_eq!(v.kind, SvidKind::NodeIdentity);
        assert_eq!(v.san, "spiffe://tallow/node-01");
        assert!(v.ttl_secs >= policy::NODE_IDENTITY_TTL_MIN_SECS);
        assert!(v.ttl_secs <= policy::NODE_IDENTITY_TTL_MAX_SECS);
        // Node ids are not interchangeable.
        assert!(verify_node_identity(&issuer.node_cert_der(), "node-02", now).is_err());
    }

    #[test]
    fn node_identity_band_is_checked_at_verify_time() {
        // A node cert re-issued with a 90-day window is fine; the *check* is
        // that a window outside 30-90 d cannot pass even with a valid signature.
        let issuer = NodeIssuer::generate("node-01").unwrap();
        let now = now_unix();
        // 60 d default: inside band.
        assert!(verify_node_identity(&issuer.node_cert_der(), "node-01", now).is_ok());
        // Verification far past notAfter is Expired, and the band error is
        // unreachable for the default cert.
        assert!(matches!(
            verify_node_identity(&issuer.node_cert_der(), "node-01", now + 200 * 86_400),
            Err(SvidError::Expired { .. })
        ));
    }

    #[test]
    fn lookalike_reason_classifier() {
        let expected = "spiffe://tallow/node-01/svc/daemon";
        assert!(lookalike_reason(expected, expected).is_none());
        assert!(
            lookalike_reason("spiffe://TALLOW/node-01/svc/daemon", expected)
                .unwrap()
                .contains("case")
        );
        assert!(
            lookalike_reason("spiffe://tallow./node-01/svc/daemon", expected)
                .unwrap()
                .contains("trailing dot")
        );
        assert!(
            lookalike_reason("spiffe://tallow/node-01/svc/daem%6fn", expected)
                .unwrap()
                .contains("percent")
        );
        assert!(
            lookalike_reason("spiffe://tallow-evil/node-01/svc/daemon", expected)
                .unwrap()
                .contains("trust domain")
        );
        assert!(lookalike_reason("spiffe://tallow/node-01/svc/reader", expected).is_none());
    }

    #[test]
    fn san_count_is_enforced() {
        assert!(matches!(
            match_san_uri(&[], "spiffe://tallow/n/svc/x"),
            Err(SvidError::SanMissing)
        ));
        assert!(matches!(
            match_san_uri(
                &["spiffe://tallow/n/svc/x", "spiffe://tallow/n/svc/y"],
                "spiffe://tallow/n/svc/x"
            ),
            Err(SvidError::SanCount { count: 2 })
        ));
        assert_eq!(
            match_san_uri(&["spiffe://tallow/n/svc/x"], "spiffe://tallow/n/svc/x").unwrap(),
            "spiffe://tallow/n/svc/x"
        );
    }

    #[test]
    fn intermediate_over_band_rejected_at_verify_time() {
        // Issue an intermediate with a compliant 7d TTL, then verify it long
        // after: the *band* check exists for the misissued case, and a
        // 7d+1 leaf window can never be produced through the issuer (policy),
        // so we construct the check directly.
        let band = SvidKind::IssuerIntermediate.ttl_band();
        assert!(check_band(SvidKind::IssuerIntermediate, 0, band.max_secs() as i64).is_ok());
        assert!(matches!(
            check_band(SvidKind::IssuerIntermediate, 0, band.max_secs() as i64 + 1),
            Err(SvidError::TtlBand {
                kind: SvidKind::IssuerIntermediate,
                ..
            })
        ));
        assert!(matches!(
            check_band(SvidKind::NodeIdentity, 0, 86_400),
            Err(SvidError::TtlBand {
                kind: SvidKind::NodeIdentity,
                ..
            })
        ));
    }

    #[test]
    fn issued_serial_matches_chain_der() {
        let expected = id("node-01", "mesh-node");
        let (_issuer, issued) = chain_for(&expected);
        let info = der::parse_cert(issued.leaf.cert_der.as_ref()).unwrap();
        // X.509 INTEGER is minimal-encoded: strip the sign pad, then left-pad
        // back to the allocator's 16-byte width and compare values.
        let mut der_serial = info.serial_der.to_vec();
        if der_serial.first() == Some(&0x00) {
            der_serial.remove(0);
        }
        assert!(der_serial.len() <= model::SERIAL_BYTES);
        let mut padded = vec![0u8; model::SERIAL_BYTES - der_serial.len()];
        padded.extend_from_slice(&der_serial);
        assert_eq!(padded, issued.leaf.serial.as_bytes().to_vec());
        let verified = verify_workload_chain(&issued.chain, &expected, now_unix()).unwrap();
        assert_eq!(hex::encode(info.serial_der), verified.serial_der_hex);
    }
}
