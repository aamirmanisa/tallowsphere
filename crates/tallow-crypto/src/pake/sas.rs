//! SAS (Short Authentication String) word comparison for the enrollment ceremony.
//!
//! R-5.5 (row #57): after the CPace exchange, both endpoints display a short word
//! sequence derived from the *same* transcript; a human compares the two screens and
//! confirms. A machine-in-the-middle that relays two independent PAKE legs derives two
//! different session keys, hence two different word sequences, and is caught by the
//! comparison (without any pre-shared secret).
//!
//! Construction:
//!
//! * `key_material = session_key ‖ context` — `context` is the ceremony transcript
//!   (both CPace public messages, session id, protocol label) supplied by the caller,
//!   so the SAS is bound to the exact exchange and not just to the shared secret.
//! * Words come from the in-crate EFF large diceware list (`7776` words, 13 bits) fed by
//!   a BLAKE3 `derive_key` stream split into 13-bit chunks. Chunks `>= 7776` are
//!   **rejected** and redrawn (rejection sampling — no modulo bias, no reduced entropy).
//! * A 4-byte fingerprint is derived under a separate domain separator for a compact
//!   hex rendering (useful when words are read over a narrow channel).
//!
//! [`SasCode::compare`] is constant-time ([`subtle`]); the type has no `PartialEq` derive
//! so comparisons cannot accidentally become variable-time.

use crate::error::{CryptoError, Result};
use crate::hash::blake3;
use crate::kdf::eff_wordlist::EFF_WORDLIST;
use std::fmt;
use subtle::ConstantTimeEq;

/// Number of words in a SAS phrase (spec default: six words ≈ 77 bits of display entropy).
pub const SAS_WORDS: usize = 6;
/// Size of the word list used for indices (EFF large diceware).
pub const WORDLIST_LEN: usize = 7776;
/// Length of the compact SAS fingerprint, in bytes.
pub const SAS_FINGERPRINT_BYTES: usize = 4;

/// Domain separator for the word derivation.
const SAS_DOMAIN: &str = "tallow-cpace-sas-v1";
/// Domain separator for the compact fingerprint derivation.
const SAS_FINGERPRINT_DOMAIN: &str = "tallow-cpace-sas-fingerprint-v1";
/// Bits consumed per word index (2^13 = 8192 ≥ 7776 ⇒ rejection sampling).
const BITS_PER_WORD: u32 = 13;
/// Mask for one 13-bit chunk.
const CHUNK_MASK: u32 = (1 << BITS_PER_WORD) - 1;

/// A derived SAS phrase: [`SAS_WORDS`] word indices plus a compact fingerprint.
///
/// The value is display material, not a secret; it must still be compared
/// constant-time-aware via [`SasCode::compare`] so a timing side channel cannot
/// distinguish "first word differs" from "last word differs".
#[derive(Clone, Copy)]
pub struct SasCode {
    /// Word-list indices, in display order.
    indices: [u16; SAS_WORDS],
    /// Compact fingerprint derived under a separate domain separator.
    fingerprint: [u8; SAS_FINGERPRINT_BYTES],
}

impl SasCode {
    /// Derive the SAS for one side of the exchange.
    ///
    /// `session_key` is the CPace output; `context` is the ceremony transcript both
    /// sides can build identically (see the module docs). Both sides of an honest
    /// exchange derive the *same* code; a different key or a different transcript
    /// yields a different code.
    pub fn derive(session_key: &[u8; 32], context: &[u8]) -> Self {
        let mut input = Vec::with_capacity(32 + context.len());
        input.extend_from_slice(session_key);
        input.extend_from_slice(context);

        let mut indices = [0u16; SAS_WORDS];
        let mut filled = 0usize;
        let mut counter: u8 = 0;

        'outer: loop {
            let mut block_input = input.clone();
            block_input.push(counter);
            let block = blake3::derive_key(SAS_DOMAIN, &block_input);

            let mut bitbuf: u32 = 0;
            let mut bits: u32 = 0;
            for &byte in block.iter() {
                bitbuf = (bitbuf << 8) | u32::from(byte);
                bits += 8;
                if bits >= BITS_PER_WORD {
                    let shift = bits - BITS_PER_WORD;
                    let chunk = (bitbuf >> shift) & CHUNK_MASK;
                    bits = shift;
                    bitbuf = if bits == 0 {
                        0
                    } else {
                        bitbuf & ((1u32 << bits) - 1)
                    };
                    // Rejection sampling: keep only 0..7776.
                    if (chunk as usize) < WORDLIST_LEN {
                        indices[filled] = chunk as u16;
                        filled += 1;
                        if filled == SAS_WORDS {
                            break 'outer;
                        }
                    }
                }
            }

            if counter == u8::MAX {
                // Statistically unreachable: one 32-byte block yields 19 chunks with only
                // ~5.1 % rejection, so six words come from a single block in practice.
                // The fallback keeps the function total and deterministic.
                for (offset, slot) in (filled..SAS_WORDS).enumerate() {
                    let mut fb_input = input.clone();
                    fb_input.push(0xFE);
                    fb_input.push(offset as u8);
                    let digest = blake3::derive_key(SAS_DOMAIN, &fb_input);
                    let value = u16::from_le_bytes([digest[0], digest[1]]) as usize % WORDLIST_LEN;
                    indices[slot] = value as u16;
                }
                break;
            }
            counter += 1;
        }

        let mut fp_input = input;
        fp_input.push(0xFF);
        let digest = blake3::derive_key(SAS_FINGERPRINT_DOMAIN, &fp_input);
        let mut fingerprint = [0u8; SAS_FINGERPRINT_BYTES];
        fingerprint.copy_from_slice(&digest[..SAS_FINGERPRINT_BYTES]);

        Self {
            indices,
            fingerprint,
        }
    }

    /// The words to show on screen, in display order.
    pub fn words(&self) -> [&'static str; SAS_WORDS] {
        let mut out = [""; SAS_WORDS];
        for (slot, index) in self.indices.iter().enumerate() {
            out[slot] = EFF_WORDLIST[usize::from(*index)];
        }
        out
    }

    /// Human-facing rendering: `word-word-…` (six words joined by `-`).
    pub fn display(&self) -> String {
        self.words().join("-")
    }

    /// Raw word indices (for tests/fixtures that need the numeric form).
    pub fn indices(&self) -> [u16; SAS_WORDS] {
        self.indices
    }

    /// The compact fingerprint bytes.
    pub fn fingerprint(&self) -> [u8; SAS_FINGERPRINT_BYTES] {
        self.fingerprint
    }

    /// Hex rendering of the compact fingerprint (8 lowercase hex chars).
    pub fn fingerprint_hex(&self) -> String {
        let mut out = String::with_capacity(SAS_FINGERPRINT_BYTES * 2);
        for byte in self.fingerprint {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Build a code from explicit indices (tests/fixtures only).
    ///
    /// Returns [`CryptoError::PakeFailure`] when any index is out of range, so a
    /// fixture can never produce a phrase that is not in the word list.
    pub fn from_indices(
        indices: [u16; SAS_WORDS],
        fingerprint: [u8; SAS_FINGERPRINT_BYTES],
    ) -> Result<Self> {
        for index in indices {
            if usize::from(index) >= WORDLIST_LEN {
                return Err(CryptoError::PakeFailure(format!(
                    "SAS word index {index} is outside the {WORDLIST_LEN}-word list"
                )));
            }
        }
        Ok(Self {
            indices,
            fingerprint,
        })
    }

    /// Constant-time comparison of two codes (indices **and** fingerprint).
    pub fn compare(&self, other: &SasCode) -> bool {
        let mut left = [0u8; SAS_WORDS * 2];
        let mut right = [0u8; SAS_WORDS * 2];
        for (slot, index) in self.indices.iter().enumerate() {
            left[slot * 2..slot * 2 + 2].copy_from_slice(&index.to_be_bytes());
        }
        for (slot, index) in other.indices.iter().enumerate() {
            right[slot * 2..slot * 2 + 2].copy_from_slice(&index.to_be_bytes());
        }
        let words_equal = left.ct_eq(&right);
        let fingerprints_equal = self.fingerprint.ct_eq(&other.fingerprint);
        (words_equal & fingerprints_equal).unwrap_u8() == 1
    }
}

/// Display form is the words themselves (the SAS is not secret); the fingerprint is
/// included so logs can correlate without the word list.
impl fmt::Debug for SasCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SasCode")
            .field("words", &self.display())
            .field("fingerprint", &self.fingerprint_hex())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn sas_is_deterministic_for_the_same_session_key_and_context() {
        let a = SasCode::derive(&key(7), b"tallow-enroll-v1|session-1");
        let b = SasCode::derive(&key(7), b"tallow-enroll-v1|session-1");
        assert!(a.compare(&b), "identical inputs must derive identical SAS");
        assert_eq!(a.display(), b.display());
        assert_eq!(a.fingerprint_hex(), b.fingerprint_hex());
    }

    #[test]
    fn sas_differs_when_the_session_key_differs() {
        // Two endpoints that did two independent PAKE legs (the MITM case) end up with
        // different session keys; their screens must not show the same words.
        let left = SasCode::derive(&key(1), b"same-context");
        let right = SasCode::derive(&key(2), b"same-context");
        assert!(
            !left.compare(&right),
            "different keys must not compare equal"
        );
        assert_ne!(left.display(), right.display());
    }

    #[test]
    fn sas_differs_when_the_transcript_differs() {
        let left = SasCode::derive(&key(9), b"ctx-A");
        let right = SasCode::derive(&key(9), b"ctx-B");
        assert!(!left.compare(&right));
        assert_ne!(left.fingerprint_hex(), right.fingerprint_hex());
    }

    #[test]
    fn sas_words_come_from_the_word_list() {
        let code = SasCode::derive(&key(3), b"context");
        let words = code.words();
        let indices = code.indices();
        assert_eq!(words.len(), SAS_WORDS);
        for (slot, index) in indices.iter().enumerate() {
            assert!(usize::from(*index) < WORDLIST_LEN);
            assert_eq!(words[slot], EFF_WORDLIST[usize::from(*index)]);
        }
        assert_eq!(code.display().split('-').count(), SAS_WORDS);
    }

    #[test]
    fn sas_out_of_range_fixture_index_is_refused() {
        let err = SasCode::from_indices([0, 1, 2, 3, 4, 7776], [0, 0, 0, 0]).unwrap_err();
        assert!(matches!(err, CryptoError::PakeFailure(_)));
        assert!(SasCode::from_indices([0, 1, 2, 3, 4, 7775], [0, 0, 0, 0]).is_ok());
    }

    /// Loose distribution sanity: a stuck generator, a tiny effective range or a
    /// broken rejection step would collapse the observed index set.
    #[test]
    fn sas_indices_are_well_spread_over_many_derivations() {
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..512u32 {
            let mut sk = [0u8; 32];
            sk[..4].copy_from_slice(&i.to_le_bytes());
            let code = SasCode::derive(&sk, b"distribution");
            for index in code.indices() {
                seen.insert(index);
            }
        }
        assert!(
            seen.len() > 1000,
            "expected a spread of indices over 3072 draws, saw {}",
            seen.len()
        );
        assert!(
            seen.iter().all(|v| usize::from(*v) < WORDLIST_LEN),
            "every index must be in range"
        );
    }

    #[test]
    fn sas_fingerprint_is_four_bytes_and_hex_is_eight_chars() {
        let code = SasCode::derive(&key(4), b"ctx");
        assert_eq!(code.fingerprint().len(), SAS_FINGERPRINT_BYTES);
        assert_eq!(code.fingerprint_hex().len(), SAS_FINGERPRINT_BYTES * 2);
        assert!(code
            .fingerprint_hex()
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }
}
