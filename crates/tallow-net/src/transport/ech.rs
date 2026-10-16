//! Encrypted Client Hello (ECH) support — RFC 9849.
//!
//! Support status (verified offline against the pinned dependency for U-105,
//! 2026-09-12):
//!
//! - rustls 0.23 (Cargo.lock: 0.23.37) ships **client-side** ECH
//!   unconditionally: `rustls::client::{EchConfig, EchGreaseConfig, EchMode,
//!   EchStatus}` are public and not behind a cargo feature — there is nothing
//!   to enable in `Cargo.toml`.
//! - ECH needs HPKE, which only the **aws_lc_rs** provider implements
//!   (`rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES`); the `ring`
//!   provider has no HPKE. tallow-net already builds TLS clients with
//!   aws-lc-rs (see `tls_config.rs`).
//! - rustls 0.23 has **no server-side ECH** (no API in `src/server/`), so
//!   matrix row #60's "and servers" half cannot be satisfied by this
//!   dependency version.
//! - Enabling ECH narrows the client to TLS 1.3 only (rustls applies this in
//!   `ConfigBuilder::with_ech`), as required for ECH.
//!
//! ECHConfigList supply: the preferred path is DoH (HTTPS/SVCB `ech`
//! parameter, RFC 9460 §7.8; base64 in presentation form) via
//! [`fetch_ech_config_list_doh`]; a pre-fetched list can be supplied through
//! [`EchPolicy::Configured`]. The HTTPS-RR lookup is implemented here rather
//! than in `privacy::doh::DohResolver` because that helper only exposes
//! `lookup_ip` — folding it in is a recorded follow-up.
//!
//! When ECH is not active, [`warn_if_ech_absent`] surfaces the SNI
//! metadata-leak warning for public clearnet names (never for loopback, IP
//! literals, `.local`, or `.onion` names).

use crate::{NetworkError, Result};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::hpke::HpkePublicKey;

/// Policy controlling Encrypted Client Hello for TLS connections.
///
/// Serialized as `{ "mode": "off" | "grease" | "configured" | "doh", ... }`
/// for config files (serde).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum EchPolicy {
    /// No ECH (default). The ClientHello — including SNI — travels in the
    /// clear; [`warn_if_ech_absent`] reports the metadata leak on clearnet.
    #[default]
    Off,
    /// GREASE ECH (RFC 9849 §6.1.6): a placeholder ECH extension.
    /// Anti-ossification only — it provides **no** confidentiality.
    Grease,
    /// Use this ECHConfigList verbatim (TLS wire format, RFC 9849 §4,
    /// as fetched from an HTTPS RR `ech` parameter).
    Configured { config_list: Vec<u8> },
    /// Fetch the ECHConfigList over DoH (HTTPS RR lookup) at connect time and
    /// fall back to a plain handshake (with warning) when unavailable.
    Doh { endpoint: String },
}

/// Build an [`EchMode`] from a TLS-wire-format `ECHConfigList`
/// (RFC 9849 §4), selecting the first config compatible with the
/// aws-lc-rs HPKE suites.
pub fn mode_from_config_list(config_list: &[u8]) -> Result<EchMode> {
    let bytes = rustls::pki_types::EchConfigListBytes::from(config_list);
    EchConfig::new(bytes, rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES)
        .map(EchMode::from)
        .map_err(|e| NetworkError::TlsError(format!("invalid ECHConfigList: {}", e)))
}

/// GREASE ECH mode: placeholder key, X25519/HKDF-SHA256/AES-128-GCM suite.
///
/// The placeholder public key is deliberately meaningless — GREASE exists so
/// that "no ECH offered" is not distinguishable on-path, not to hide the SNI.
pub fn grease_mode() -> EchMode {
    EchMode::Grease(EchGreaseConfig::new(
        rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128,
        HpkePublicKey(vec![0u8; 32]),
    ))
}

/// Resolve the ECH mode for the policy variants that need no network I/O.
///
/// [`EchPolicy::Doh`] returns `Ok(None)` here: the caller must first fetch
/// with [`fetch_ech_config_list_doh`] and then call
/// [`mode_from_config_list`] (or use [`resolve_ech_mode`]).
pub fn static_mode(policy: &EchPolicy) -> Result<Option<EchMode>> {
    match policy {
        EchPolicy::Off => Ok(None),
        EchPolicy::Grease => Ok(Some(grease_mode())),
        EchPolicy::Configured { config_list } => mode_from_config_list(config_list).map(Some),
        EchPolicy::Doh { .. } => Ok(None),
    }
}

/// Resolve the effective ECH mode for `hostname`, performing the DoH
/// HTTPS-RR fetch when the policy is [`EchPolicy::Doh`].
pub async fn resolve_ech_mode(policy: &EchPolicy, hostname: &str) -> Result<Option<EchMode>> {
    match policy {
        EchPolicy::Doh { endpoint } => match fetch_ech_config_list_doh(hostname, endpoint).await? {
            Some(list) => mode_from_config_list(&list).map(Some),
            None => Ok(None),
        },
        other => static_mode(other),
    }
}

/// Extract a raw `ECHConfigList` from an HTTPS/SVCB [`RData`] record's `ech`
/// parameter (RFC 9460 §7.8).
///
/// [`RData`]: hickory_resolver::proto::rr::RData
pub fn ech_config_list_from_rdata(rdata: &hickory_resolver::proto::rr::RData) -> Option<Vec<u8>> {
    use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};

    let hickory_resolver::proto::rr::RData::HTTPS(https) = rdata else {
        return None;
    };
    https
        .svc_params
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(list)) => {
                Some(list.0.clone())
            }
            _ => None,
        })
}

/// Fetch the origin's `ECHConfigList` over DoH by querying its HTTPS
/// resource record (RFC 9460) and extracting the `ech` SvcParam.
///
/// Returns `Ok(None)` when the record exists but carries no `ech` parameter.
/// Resolver construction mirrors `privacy::doh::DohResolver` (which only
/// exposes `lookup_ip`); consolidation is a recorded follow-up.
pub async fn fetch_ech_config_list_doh(hostname: &str, endpoint: &str) -> Result<Option<Vec<u8>>> {
    use hickory_resolver::config::ResolverConfig;
    use hickory_resolver::config::{CLOUDFLARE, GOOGLE, QUAD9};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::TokioResolver;

    // Pick the DoH provider group from the configured well-known endpoint,
    // matching `privacy::doh::DohResolver`.
    let config = if endpoint.contains("cloudflare") {
        ResolverConfig::https(&CLOUDFLARE)
    } else if endpoint.contains("google") {
        ResolverConfig::https(&GOOGLE)
    } else if endpoint.contains("quad9") {
        ResolverConfig::https(&QUAD9)
    } else {
        ResolverConfig::https(&CLOUDFLARE)
    };

    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| NetworkError::DnsResolution(format!("failed to build DoH resolver: {}", e)))?;

    let lookup = resolver
        .lookup(hostname, RecordType::HTTPS)
        .await
        .map_err(|e| {
            NetworkError::DnsResolution(format!(
                "DoH HTTPS-RR lookup failed for '{}': {}",
                hostname, e
            ))
        })?;

    for record in lookup.answers() {
        if let Some(list) = ech_config_list_from_rdata(&record.data) {
            return Ok(Some(list));
        }
    }
    Ok(None)
}

/// True when a server name is a public DNS name whose SNI is on-path
/// metadata worth hiding.
///
/// Loopback names, IP literals, `.local` (mDNS/LAN), `.onion` (Tor), and
/// single-label names are not.
pub fn sni_confidentiality_relevant(server_name: &str) -> bool {
    let name = server_name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name == "localhost" {
        return false;
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    for suffix in [".local", ".onion", ".internal", ".localhost"] {
        if name.ends_with(suffix) {
            return false;
        }
    }
    // Require a real (multi-label) DNS name: single-label names are not
    // resolvable on the public internet.
    name.contains('.')
}

/// Human-readable no-ECH metadata-leak warning for `server_name`, if
/// applicable (see [`sni_confidentiality_relevant`]).
pub fn no_ech_metadata_leak_warning(server_name: &str) -> Option<String> {
    if !sni_confidentiality_relevant(server_name) {
        return None;
    }
    Some(format!(
        "ECH unavailable for '{}': the TLS SNI/destination is visible to on-path observers \
         (RFC 9849 metadata leak). Supply an ECHConfigList (EchPolicy::Configured) or enable \
         DoH fetching (EchPolicy::Doh).",
        server_name
    ))
}

/// Emit the no-ECH metadata-leak warning when ECH is not active for
/// `server_name` (clearnet-relevant names only). Returns `true` if a warning
/// was emitted — useful for tests and callers that surface the state.
pub fn warn_if_ech_absent(server_name: &str, ech_active: bool) -> bool {
    if ech_active {
        return false;
    }
    match no_ech_metadata_leak_warning(server_name) {
        Some(msg) => {
            tracing::warn!("{}", msg);
            true
        }
        None => false,
    }
}

#[cfg(test)]
pub(crate) mod test_vectors {
    /// Minimal valid RFC 9849 ECHConfigList:
    /// one config, X25519 / HKDF-SHA256 / AES-128-GCM, dummy public key,
    /// public_name `example.com`, no extensions.
    pub fn ech_config_list() -> Vec<u8> {
        let mut contents = Vec::new();
        contents.push(0x01); // config_id
        contents.extend_from_slice(&0x0020u16.to_be_bytes()); // kem: DHKEM(X25519, HKDF-SHA256)
        contents.extend_from_slice(&32u16.to_be_bytes()); // public_key length
        contents.extend_from_slice(&[0u8; 32]); // public_key (test dummy)
        contents.extend_from_slice(&4u16.to_be_bytes()); // cipher_suites length
        contents.extend_from_slice(&0x0001u16.to_be_bytes()); // kdf: HKDF-SHA256
        contents.extend_from_slice(&0x0001u16.to_be_bytes()); // aead: AES-128-GCM
        contents.push(0); // maximum_name_length
        contents.push(11); // public_name length
        contents.extend_from_slice(b"example.com");
        contents.extend_from_slice(&0u16.to_be_bytes()); // extensions

        let mut config = Vec::new();
        config.extend_from_slice(&0xfe0du16.to_be_bytes()); // version: ECH (draft-18+ nomenclature)
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);

        let mut list = Vec::new();
        list.extend_from_slice(&(config.len() as u16).to_be_bytes());
        list.extend_from_slice(&config);
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_from_valid_config_list() {
        let mode = mode_from_config_list(&test_vectors::ech_config_list()).unwrap();
        assert!(matches!(mode, EchMode::Enable(_)));
    }

    #[test]
    fn mode_from_garbage_config_list_is_error() {
        assert!(mode_from_config_list(b"not-an-ech-config").is_err());
        assert!(mode_from_config_list(&[]).is_err());
        // Valid outer list, but an unknown/unsupported version → no compatible config.
        assert!(mode_from_config_list(&[0x00, 0x06, 0xde, 0xad, 0x00, 0x02, 0x00, 0x00]).is_err());
    }

    #[test]
    fn mode_from_real_world_config_list() {
        // Real ECHConfigList observed live for crypto.cloudflare.com's HTTPS RR
        // `ech` parameter (fetched 2026-09-12 over Tor; base64 presentation form
        // decoded to wire bytes). Structure: list_len=69, version=0xfe0d,
        // X25519/HKDF-SHA256/AES-128-GCM, public_name "cloudflare-ech.com".
        // Kept as an offline regression vector for the DoH → EchMode plumbing.
        const REAL_HEX: &str = "0045fe0d00417a0020002093e9a7c6d46c4f705dde0517eb3fb6de92aa211d165a111c32739f1abd0dd3050004000100010012636c6f7564666c6172652d6563682e636f6d0000";
        let real = hex::decode(REAL_HEX).expect("valid hex");
        assert_eq!(real.len(), 71);
        assert!(matches!(
            mode_from_config_list(&real).unwrap(),
            EchMode::Enable(_)
        ));
    }

    #[test]
    fn grease_mode_is_grease() {
        assert!(matches!(grease_mode(), EchMode::Grease(_)));
    }

    #[test]
    fn static_mode_policy_plumbing() {
        assert!(static_mode(&EchPolicy::Off).unwrap().is_none());
        assert!(matches!(
            static_mode(&EchPolicy::Grease).unwrap(),
            Some(EchMode::Grease(_))
        ));
        let configured = EchPolicy::Configured {
            config_list: test_vectors::ech_config_list(),
        };
        assert!(matches!(
            static_mode(&configured).unwrap(),
            Some(EchMode::Enable(_))
        ));
        // Doh resolves asynchronously — static_mode is a no-op for it.
        let doh = EchPolicy::Doh {
            endpoint: "https://cloudflare-dns.com/dns-query".to_string(),
        };
        assert!(static_mode(&doh).unwrap().is_none());
    }

    #[test]
    fn configured_invalid_list_is_error() {
        let policy = EchPolicy::Configured {
            config_list: vec![1, 2, 3],
        };
        assert!(static_mode(&policy).is_err());
    }

    #[test]
    fn rdata_extraction_finds_ech_param() {
        use hickory_resolver::proto::rr::rdata::svcb::{
            EchConfigList as RdataEchConfigList, SvcParamKey, SvcParamValue,
        };
        use hickory_resolver::proto::rr::rdata::{HTTPS, SVCB};
        use hickory_resolver::proto::rr::{Name, RData};

        let list = test_vectors::ech_config_list();
        let root = Name::from_ascii(".").unwrap();

        let with_ech = RData::HTTPS(HTTPS(SVCB::new(
            1,
            root.clone(),
            vec![(
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(RdataEchConfigList(list.clone())),
            )],
        )));
        assert_eq!(ech_config_list_from_rdata(&with_ech), Some(list));

        let without_ech = RData::HTTPS(HTTPS(SVCB::new(1, root, vec![])));
        assert_eq!(ech_config_list_from_rdata(&without_ech), None);
    }

    #[test]
    fn warning_applies_to_public_names_only() {
        assert!(no_ech_metadata_leak_warning("relay.example.com").is_some());
        for local in [
            "localhost",
            "127.0.0.1",
            "::1",
            "peer.local",
            "abcdef234.onion",
            "relay",
            "",
        ] {
            assert!(
                no_ech_metadata_leak_warning(local).is_none(),
                "expected no warning for {local:?}"
            );
        }
    }

    #[test]
    fn warn_if_ech_absent_contract() {
        assert!(warn_if_ech_absent("relay.example.com", false));
        assert!(!warn_if_ech_absent("relay.example.com", true));
        assert!(!warn_if_ech_absent("localhost", false));
    }

    #[test]
    fn policy_serde_roundtrip() {
        assert_eq!(EchPolicy::default(), EchPolicy::Off);
        let policy = EchPolicy::Configured {
            config_list: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"mode\":\"configured\""));
        let back: EchPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);

        let grease = EchPolicy::Grease;
        let json = serde_json::to_string(&grease).unwrap();
        assert_eq!(
            serde_json::from_str::<EchPolicy>(&json).unwrap(),
            EchPolicy::Grease
        );
    }

    #[tokio::test]
    async fn resolve_ech_mode_handles_networkless_policies() {
        assert!(resolve_ech_mode(&EchPolicy::Off, "example.com")
            .await
            .unwrap()
            .is_none());
        assert!(matches!(
            resolve_ech_mode(&EchPolicy::Grease, "example.com")
                .await
                .unwrap(),
            Some(EchMode::Grease(_))
        ));
    }
}
