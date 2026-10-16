//! Cipher suite negotiation and hardware detection

use super::CipherSuite;

/// Detect if AES-NI hardware acceleration is available
///
/// # Returns
///
/// `true` if AES-NI is supported, `false` otherwise
pub fn detect_aes_ni() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(target_feature = "aes")]
        {
            true
        }

        // Runtime detection on x86/x86_64
        #[cfg(not(target_feature = "aes"))]
        {
            is_x86_feature_detected!("aes")
        }
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// Select the best cipher suite for the current platform
///
/// This function detects hardware capabilities and selects the optimal
/// cipher suite:
/// - AES-256-GCM if AES-NI is available (hardware accelerated)
/// - ChaCha20-Poly1305 otherwise
///
/// # Returns
///
/// The recommended cipher suite
pub fn select_cipher() -> CipherSuite {
    if detect_aes_ni() {
        CipherSuite::Aes256Gcm
    } else {
        CipherSuite::ChaCha20Poly1305
    }
}

/// Negotiate cipher suite between two peers
///
/// # Arguments
///
/// * `our_suites` - List of cipher suites we support, in preference order
/// * `their_suites` - List of cipher suites the peer supports
///
/// # Returns
///
/// The first mutually supported cipher suite, or None if no match
pub fn negotiate(our_suites: &[CipherSuite], their_suites: &[CipherSuite]) -> Option<CipherSuite> {
    for our_suite in our_suites {
        if their_suites.contains(our_suite) {
            return Some(*our_suite);
        }
    }
    None
}

/// Get the default cipher suite list in preference order
///
/// Returns suites in order of preference based on hardware capabilities.
pub fn default_suites() -> Vec<CipherSuite> {
    let mut suites = Vec::new();

    if detect_aes_ni() {
        suites.push(CipherSuite::Aes256Gcm);
        suites.push(CipherSuite::ChaCha20Poly1305);
    } else {
        suites.push(CipherSuite::ChaCha20Poly1305);
        suites.push(CipherSuite::Aes256Gcm);
    }

    #[cfg(feature = "aegis")]
    {
        suites.push(CipherSuite::Aegis256);
    }

    suites
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_cipher() {
        let cipher = select_cipher();
        // Should return either AES or ChaCha20 depending on platform
        assert!(cipher == CipherSuite::Aes256Gcm || cipher == CipherSuite::ChaCha20Poly1305);
    }

    #[test]
    fn test_negotiate() {
        let our_suites = vec![CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305];
        let their_suites = vec![CipherSuite::ChaCha20Poly1305];

        let result = negotiate(&our_suites, &their_suites);
        assert_eq!(result, Some(CipherSuite::ChaCha20Poly1305));
    }

    #[test]
    fn test_negotiate_no_match() {
        let our_suites = vec![CipherSuite::Aes256Gcm];
        let their_suites = vec![CipherSuite::ChaCha20Poly1305];

        let result = negotiate(&our_suites, &their_suites);
        assert_eq!(result, None);
    }

    #[test]
    fn test_default_suites() {
        let suites = default_suites();
        assert!(!suites.is_empty());
        assert!(suites.contains(&CipherSuite::Aes256Gcm));
        assert!(suites.contains(&CipherSuite::ChaCha20Poly1305));
    }
}
