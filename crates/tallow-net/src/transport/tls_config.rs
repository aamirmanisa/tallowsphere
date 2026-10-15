//! TLS configuration helpers for QUIC and TCP+TLS transports
//!
//! Generates self-signed certificates via rcgen for relay connections.
//! Tallow's relay is untrusted — the TLS layer is for transport encryption,
//! not identity verification (that's handled by the E2E crypto layer).
//!
//! Client-side server-certificate verification is gated by the
//! `dangerous_skip_verify` feature (explicit opt-in; NOT a default since the
//! fix-wave flip, 2026-09-28): enabled → self-signed relay/dev certs are
//! accepted via SkipServerVerification; disabled (default) → clients require
//! CA-validated certificates (webpki roots).
//!
//! ECH (RFC 9849, U-105): client-side ECH is supported by rustls 0.23 with
//! the aws_lc_rs provider (already used here) and is unconditional — no
//! cargo feature. [`super::ech`] provides the policy surface, ECHConfigList
//! supply (DoH or configured) and the no-ECH metadata-leak warning. Enabling
//! ECH forces TLS 1.3 only. rustls 0.23 has no server-side ECH.

use crate::{NetworkError, Result};
use std::sync::Arc;

/// Generated TLS certificate and key pair
pub struct TlsIdentity {
    /// DER-encoded leaf certificate
    pub cert_der: rustls::pki_types::CertificateDer<'static>,
    /// Additional DER-encoded certificates (intermediates), leaf-first order
    /// preserved as loaded. Empty for self-signed identities.
    pub extra_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// DER-encoded private key
    pub key_der: rustls::pki_types::PrivatePkcs8KeyDer<'static>,
}

impl TlsIdentity {
    /// Full certificate chain: leaf first, then any intermediates.
    pub fn chain(&self) -> Vec<rustls::pki_types::CertificateDer<'static>> {
        let mut chain = Vec::with_capacity(1 + self.extra_certs.len());
        chain.push(self.cert_der.clone());
        chain.extend(self.extra_certs.iter().cloned());
        chain
    }
}

/// Generate a self-signed TLS certificate for localhost
///
/// Used for QUIC and TCP+TLS connections. The relay is untrusted,
/// so we don't need CA-signed certs — transport-layer encryption
/// is complemented by E2E encryption at the crypto layer.
pub fn generate_self_signed() -> Result<TlsIdentity> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| NetworkError::TlsError(format!("cert generation failed: {}", e)))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    Ok(TlsIdentity {
        cert_der,
        extra_certs: Vec::new(),
        key_der,
    })
}

/// Build a quinn ServerConfig from a TLS identity
///
/// Configures a 5-minute idle timeout to keep connections alive while
/// peers wait for each other in relay rooms.
///
/// # Security — 0-RTT is disabled at two independent levels
///
/// 1. `rustls::ServerConfig::max_early_data_size` defaults to **0** inside
///    Quinn's `with_single_cert` constructor — the server never issues session
///    tickets that permit early data, so no 0-RTT handshake can be initiated.
/// 2. The relay never calls `Connection::accept_0rtt()` — even if a client
///    somehow attempted a 0-RTT connection it would be silently dropped by Quinn.
///
/// **NEVER** change this to use `with_early_data()` or set
/// `max_early_data_size > 0`. 0-RTT data is not forward secret and is
/// replayable.
#[cfg(feature = "quic")]
pub fn quinn_server_config(identity: &TlsIdentity) -> Result<quinn::ServerConfig> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(300)
            .try_into()
            .expect("300s fits in IdleTimeout"),
    ));

    let mut server_config = quinn::ServerConfig::with_single_cert(
        identity.chain(),
        identity.key_der.clone_key().into(),
    )
    .map_err(|e| NetworkError::TlsError(format!("quinn server config failed: {}", e)))?;

    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

/// Load a TLS identity from PEM files (certificate chain + private key).
///
/// The certificate file may contain the full chain (leaf first, then
/// intermediates — e.g. a Let's Encrypt `fullchain.pem`); every certificate is
/// kept. The private key must be PKCS#8 (`-----BEGIN PRIVATE KEY-----`).
pub fn load_pem_identity(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<TlsIdentity> {
    use rustls::pki_types::pem::PemObject;

    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
        NetworkError::TlsError(format!(
            "private key load failed ({}): {}",
            key_path.display(),
            e
        ))
    })?;
    let key_der = match key {
        rustls::pki_types::PrivateKeyDer::Pkcs8(k) => k,
        _ => {
            return Err(NetworkError::TlsError(format!(
                "unsupported private key format in {} (PKCS#8 required; convert with \
                 `openssl pkcs8 -topk8 -nocrypt`)",
                key_path.display()
            )));
        }
    };

    let mut certs = rustls::pki_types::CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| {
            NetworkError::TlsError(format!(
                "certificate load failed ({}): {}",
                cert_path.display(),
                e
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            NetworkError::TlsError(format!(
                "certificate parse failed ({}): {}",
                cert_path.display(),
                e
            ))
        })?;
    if certs.is_empty() {
        return Err(NetworkError::TlsError(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }
    let cert_der = certs.remove(0);

    Ok(TlsIdentity {
        cert_der,
        extra_certs: certs,
        key_der,
    })
}

/// Pinned QUIC idle timeout for the relay client (auditable constant; U-102).
#[cfg(feature = "quic")]
pub const QUINN_CLIENT_MAX_IDLE_TIMEOUT_SECS: u64 = 300;

/// Pinned QUIC keep-alive interval for the relay client (auditable constant; U-102).
#[cfg(feature = "quic")]
pub const QUINN_CLIENT_KEEP_ALIVE_INTERVAL_SECS: u64 = 15;

/// Plain-data mirror of the auditable subset of `quinn::TransportConfig`
/// applied by [`quinn_client_config`] (ag03 R-2 / U-102).
#[cfg(feature = "quic")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicClientTransportParams {
    pub max_idle_timeout_secs: Option<u64>,
    pub keep_alive_interval_secs: Option<u64>,
}

/// Audit view of the QUIC transport parameters the client actually applies.
/// quinn 0.11.x exposes no public getters for these fields, so the values are
/// returned from the same constants the builder applies (single source).
#[cfg(feature = "quic")]
pub fn quinn_client_transport_params() -> QuicClientTransportParams {
    QuicClientTransportParams {
        max_idle_timeout_secs: Some(QUINN_CLIENT_MAX_IDLE_TIMEOUT_SECS),
        keep_alive_interval_secs: Some(QUINN_CLIENT_KEEP_ALIVE_INTERVAL_SECS),
    }
}

/// Build a quinn ClientConfig that accepts any server certificate
///
/// Safe for Tallow because the relay is untrusted anyway — we rely on
/// E2E encryption, not TLS, for confidentiality. TLS provides transport
/// encryption against passive observers only.
///
/// Configures a 5-minute idle timeout and 15-second keep-alive interval
/// so connections survive while waiting for peers.
///
/// Verification behavior is gated by `dangerous_skip_verify` (see module doc):
/// disabled → webpki-root CA verification instead of SkipServerVerification.
#[cfg(feature = "quic")]
pub fn quinn_client_config() -> Result<quinn::ClientConfig> {
    quinn_client_config_from_rustls(client_config(&[])?)
}

/// Build a quinn ClientConfig with pinned-SPKI verification (same D3 semantics
/// as [`client_config_pinned`]; QUIC transport).
#[cfg(feature = "quic")]
pub fn quinn_client_config_pinned(spki_sha256: [u8; 32]) -> Result<quinn::ClientConfig> {
    quinn_client_config_from_rustls(client_config_pinned(&[], spki_sha256)?)
}

/// Shared quinn wrapper: transport parameters + rustls crypto config.
#[cfg(feature = "quic")]
fn quinn_client_config_from_rustls(crypto: rustls::ClientConfig) -> Result<quinn::ClientConfig> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(QUINN_CLIENT_MAX_IDLE_TIMEOUT_SECS)
            .try_into()
            .expect("300s fits in IdleTimeout"),
    ));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(
        QUINN_CLIENT_KEEP_ALIVE_INTERVAL_SECS,
    )));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| NetworkError::TlsError(format!("quinn client config failed: {}", e)))?,
    ));

    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Build a rustls ServerConfig from a TLS identity (for TCP+TLS)
pub fn rustls_server_config(identity: &TlsIdentity) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| NetworkError::TlsError(format!("TLS protocol versions: {}", e)))?
        .with_no_client_auth()
        .with_single_cert(identity.chain(), identity.key_der.clone_key().into())
        .map_err(|e| NetworkError::TlsError(format!("rustls server config failed: {}", e)))?;

    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig that accepts any server certificate (for TCP+TLS)
///
/// Verification behavior is gated by `dangerous_skip_verify`: disabled →
/// webpki-root CA verification instead of SkipServerVerification.
pub fn rustls_client_config() -> Result<Arc<rustls::ClientConfig>> {
    Ok(Arc::new(client_config(&[])?))
}

/// Build a rustls ClientConfig that verifies the server against a pinned SPKI
/// (`sha256` of the SubjectPublicKeyInfo DER) for the TCP+TLS transport. No
/// chain or name checks — the pin is the trust root. See
/// [`client_config_pinned`].
pub fn rustls_client_config_pinned(spki_sha256: [u8; 32]) -> Result<Arc<rustls::ClientConfig>> {
    Ok(Arc::new(client_config_pinned(&[], spki_sha256)?))
}

/// Build the client-side rustls config shared by the QUIC (quinn) and TCP+TLS clients.
///
/// This is the single place that defines Tallow's client TLS cohort: the
/// `aws_lc_rs` provider's cipher suites / key-exchange groups / signature
/// algorithms / extensions exactly as rustls builds them. The pinned, versioned
/// snapshot of that cohort lives in [`super::tls_cohort`] (`JA4_COHORT_V1`,
/// T-126 evidence) — change cohort-affecting settings ONLY together with that
/// snapshot, and re-pin it deliberately.
///
/// PQ-first ordering: the `prefer-post-quantum` rustls feature (Cargo.toml)
/// places X25519MLKEM768 first in `DEFAULT_KX_GROUPS` — this is itself a
/// cohort-affecting setting; keep it pinned together with
/// [`super::tls_cohort`]. (The SendTallow product reaches the same preference
/// with a custom CryptoProvider; the feature-based approach avoids a second
/// provider here.)
///
/// `alpn` is applied verbatim after the base config is built; pass `&[]` to
/// offer no ALPN (the pre-T-126 behavior for both clients).
pub fn client_config(alpn: &[&[u8]]) -> Result<rustls::ClientConfig> {
    client_config_with_ech(alpn, None)
}

/// Build a rustls ClientConfig with an optional ECH mode (RFC 9849).
///
/// ECH is client-side-only in rustls 0.23 (no server API) and requires the
/// `aws_lc_rs` HPKE provider — already used here. Passing `Some(mode)` routes
/// the builder through `ConfigBuilder::with_ech`, which implicitly narrows
/// the config to TLS 1.3 only (an ECH requirement).
pub fn client_config_with_ech(
    alpn: &[&[u8]],
    ech: Option<rustls::client::EchMode>,
) -> Result<rustls::ClientConfig> {
    client_config_inner(alpn, ech, None)
}

/// Build a rustls ClientConfig in the **pinned-SPKI** mode (D3 of the pin +
/// registry-verify arc): the server is accepted iff the sha256 of its
/// end-entity SubjectPublicKeyInfo DER equals `spki_sha256` (compute pins with
/// [`super::spki_pin::spki_sha256`]; record them in `tallow-registry::pins`).
/// Any mismatch or parse failure aborts the handshake. Chain/name checks are
/// bypassed by design (the pin *is* the trust root — self-signed peers are the
/// case this exists for); the handshake signature is still fully verified
/// against the presented certificate.
///
/// Takes precedence over `dangerous_skip_verify` when both could apply: an
/// explicit pin is a stronger statement than "accept anything".
pub fn client_config_pinned(alpn: &[&[u8]], spki_sha256: [u8; 32]) -> Result<rustls::ClientConfig> {
    client_config_inner(alpn, None, Some(spki_sha256))
}

/// Shared client-config builder: `pin = Some(..)` selects pinned-SPKI
/// verification; `None` keeps the existing behavior (skip-verify under the
/// gated feature, webpki roots otherwise).
fn client_config_inner(
    alpn: &[&[u8]],
    ech: Option<rustls::client::EchMode>,
    pin: Option<[u8; 32]>,
) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider);

    let stage = match ech {
        Some(mode) => builder
            .with_ech(mode)
            .map_err(|e| NetworkError::TlsError(format!("TLS ECH config: {}", e)))?,
        None => builder
            .with_safe_default_protocol_versions()
            .map_err(|e| NetworkError::TlsError(format!("TLS protocol versions: {}", e)))?,
    };

    let mut config = if let Some(pin) = pin {
        stage
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(super::spki_pin::PinnedSpkiVerifier::new(
                pin,
            )))
            .with_no_client_auth()
    } else {
        #[cfg(feature = "dangerous_skip_verify")]
        let config = stage
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        #[cfg(not(feature = "dangerous_skip_verify"))]
        let config = {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            stage.with_root_certificates(roots).with_no_client_auth()
        };

        config
    };

    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    }

    Ok(config)
}

/// Build a client config for a specific server name under an ECH policy,
/// emitting the no-ECH metadata-leak warning when ECH ends up inactive.
///
/// Only the synchronous policy variants resolve here; for [`super::ech::EchPolicy::Doh`]
/// callers must fetch first (`ech::fetch_ech_config_list_doh(..).await` +
/// `ech::mode_from_config_list(..)`, or `ech::resolve_ech_mode(..).await`)
/// and then call [`client_config_with_ech`].
pub fn client_config_for_host(
    server_name: &str,
    alpn: &[&[u8]],
    policy: &super::ech::EchPolicy,
) -> Result<rustls::ClientConfig> {
    let mode = super::ech::static_mode(policy)?;
    super::ech::warn_if_ech_absent(server_name, mode.is_some());
    client_config_with_ech(alpn, mode)
}

/// Certificate verifier that accepts any certificate
///
/// # Security rationale
///
/// This is an intentional design decision, NOT a vulnerability:
/// - The relay is **fully untrusted** by design (see threat model)
/// - E2E encryption (ML-KEM + X25519 + AES-256-GCM) handles confidentiality
/// - E2E authentication (PAKE + safety numbers) handles identity verification
/// - TLS provides defense-in-depth against passive observers only
/// - The relay uses self-signed certificates (no CA infrastructure)
/// - Even if an attacker MITMs the TLS layer, they only see E2E ciphertext
///
/// Only compiled when the `dangerous_skip_verify` feature is enabled (T-113);
/// without the feature, hardened builds use CA-validated certs instead.
#[cfg(feature = "dangerous_skip_verify")]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(feature = "dangerous_skip_verify")]
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_pem_identity_roundtrip() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!("tls-id-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let id = load_pem_identity(&cert_path, &key_path).unwrap();
        assert_eq!(id.cert_der.as_ref(), cert.cert.der().as_ref());
        assert!(id.extra_certs.is_empty());
        assert_eq!(id.chain().len(), 1);
        assert!(!id.key_der.secret_pkcs8_der().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_pem_identity_missing_file() {
        let missing = std::path::Path::new("/nonexistent/cert.pem");
        let err = load_pem_identity(missing, missing)
            .err()
            .expect("expected missing-file error");
        let msg = format!("{}", err);
        assert!(msg.contains("private key load failed"), "{}", msg);
    }

    #[test]
    fn test_generate_self_signed() {
        let identity = generate_self_signed().unwrap();
        assert!(!identity.cert_der.is_empty());
    }

    #[cfg(feature = "quic")]
    #[test]
    fn test_quinn_server_config() {
        let identity = generate_self_signed().unwrap();
        let config = quinn_server_config(&identity);
        assert!(config.is_ok());
    }

    #[cfg(feature = "quic")]
    #[test]
    fn test_quinn_client_config() {
        let config = quinn_client_config();
        assert!(config.is_ok());
    }

    #[test]
    fn test_client_config_with_ech_grease() {
        let config = client_config_with_ech(&[], Some(crate::transport::ech::grease_mode()));
        assert!(config.is_ok());
    }

    #[test]
    fn test_client_config_with_ech_configured() {
        let mode = crate::transport::ech::mode_from_config_list(
            &crate::transport::ech::test_vectors::ech_config_list(),
        )
        .unwrap();
        assert!(client_config_with_ech(&[b"h2"], Some(mode)).is_ok());
    }

    #[test]
    fn test_client_config_default_remains_ech_free() {
        // Plain path unchanged: no ECH, same builder entry point.
        assert!(client_config(&[]).is_ok());
    }

    #[test]
    fn test_client_config_for_host_localhost() {
        // localhost: no metadata-leak warning, config still builds.
        let config = client_config_for_host(
            "localhost",
            &[],
            &crate::transport::ech::EchPolicy::default(),
        );
        assert!(config.is_ok());
    }

    #[test]
    fn test_client_config_for_host_public_name() {
        // Public name with ECH Off still builds (warning emitted inside).
        let config = client_config_for_host(
            "relay.example.com",
            &[],
            &crate::transport::ech::EchPolicy::default(),
        );
        assert!(config.is_ok());
    }

    #[test]
    fn test_client_config_for_host_invalid_configured_list_errors() {
        let policy = crate::transport::ech::EchPolicy::Configured {
            config_list: vec![9, 9, 9],
        };
        assert!(client_config_for_host("relay.example.com", &[], &policy).is_err());
    }
}
