//! SPKI pinning for client TLS (D3 of the pin + registry-verify arc).
//!
//! [`PinnedSpkiVerifier`] accepts a server iff the sha256 of its end-entity
//! certificate's **SubjectPublicKeyInfo** DER equals the configured pin.
//! Certificate-chain and name checks are deliberately bypassed in this mode:
//! the trust root is the out-of-band pinned key, not a CA or a calendar
//! (self-signed peers are the motivating case; the paths that want CA
//! semantics keep using the default webpki verifier, and the dev-only
//! `dangerous_skip_verify` feature stays opt-in and separate). The handshake
//! transcript signature is still fully verified against the presented
//! certificate (via the rustls/webpki helpers), so possession of the pinned
//! key is *proven*, not asserted.
//!
//! Fail-closed: any parse failure or hash mismatch aborts the handshake.
//! Pins are produced by [`spki_sha256`] — compute them from a certificate
//! received over an **out-of-band** channel and record them in the pin
//! registry (`tallow-registry::pins`); never pin what a connection just
//! presented.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

/// sha256 of the certificate's SubjectPublicKeyInfo DER (the pin value).
///
/// Errors for anything that is not a parseable X.509 end-entity certificate.
pub fn spki_sha256(cert: &CertificateDer<'_>) -> Result<[u8; 32], Error> {
    let parsed = rustls::server::ParsedCertificate::try_from(cert)?;
    let spki = parsed.subject_public_key_info();
    Ok(Sha256::digest(spki.as_ref()).into())
}

fn provider_algs() -> rustls::crypto::WebPkiSupportedAlgorithms {
    rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
}

/// Certificate verifier that accepts exactly one SPKI pin.
///
/// Used only via [`super::tls_config::client_config_pinned`] (and the quinn
/// variant); the default client paths never construct it without a pin.
#[derive(Debug)]
pub struct PinnedSpkiVerifier {
    pin: [u8; 32],
}

impl PinnedSpkiVerifier {
    pub fn new(pin: [u8; 32]) -> Self {
        Self { pin }
    }
}

impl ServerCertVerifier for PinnedSpkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let got = spki_sha256(end_entity)?;
        if got == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            // Distinct, greppable failure — the "substitution detected" signal.
            Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &provider_algs())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &provider_algs())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider_algs().supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test: the SPKI bytes embedded in a certificate must equal
    /// the keypair's own `public_key_der()` (rcgen builds the cert from the
    /// same SPKI, so this cross-checks extraction against the source of truth).
    #[test]
    fn spki_extraction_matches_keypair_ground_truth() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();

        let expected: [u8; 32] = Sha256::digest(key.public_key_der()).into();
        let got = spki_sha256(cert.der()).expect("extract");
        assert_eq!(
            got, expected,
            "SPKI extraction must match keypair ground truth"
        );

        // Two independent certificates of the same key share the pin.
        let params2 = rcgen::CertificateParams::new(vec!["other.name".to_string()]).unwrap();
        let cert2 = params2.self_signed(&key).unwrap();
        assert_eq!(spki_sha256(cert2.der()).unwrap(), expected);

        // A different key gives a different pin.
        let key_b = rcgen::KeyPair::generate().unwrap();
        let params_b = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert_b = params_b.self_signed(&key_b).unwrap();
        assert_ne!(spki_sha256(cert_b.der()).unwrap(), expected);
    }

    #[test]
    fn garbage_cert_is_err() {
        let junk = CertificateDer::from(vec![0x30, 0x01, 0x00]);
        assert!(
            spki_sha256(&junk).is_err(),
            "malformed DER must fail closed"
        );
        let empty = CertificateDer::from(Vec::<u8>::new());
        assert!(spki_sha256(&empty).is_err());
    }
}
