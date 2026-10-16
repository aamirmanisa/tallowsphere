//! Password strength estimation and generation

use crate::kdf::eff_wordlist::EFF_WORDLIST;
use rand::seq::SliceRandom;
use rand_core::OsRng;

/// Estimate the entropy of a password in bits
///
/// This is a simple estimation based on character set diversity.
/// It does NOT account for common patterns or dictionary words.
///
/// # Arguments
///
/// * `password` - The password to analyze
///
/// # Returns
///
/// Estimated entropy in bits
pub fn estimate_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut charset_size = 0;
    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digits = false;
    let mut has_special = false;

    for c in password.chars() {
        if c.is_lowercase() {
            has_lowercase = true;
        } else if c.is_uppercase() {
            has_uppercase = true;
        } else if c.is_numeric() {
            has_digits = true;
        } else {
            has_special = true;
        }
    }

    if has_lowercase {
        charset_size += 26;
    }
    if has_uppercase {
        charset_size += 26;
    }
    if has_digits {
        charset_size += 10;
    }
    if has_special {
        charset_size += 32; // Estimate
    }

    if charset_size == 0 {
        charset_size = 1;
    }

    let length = password.len() as f64;
    let bits_per_char = (charset_size as f64).log2();

    length * bits_per_char
}

/// Generate a diceware passphrase using the EFF Large Wordlist
///
/// Uses the full 7776-word EFF wordlist for ~12.9 bits of entropy per word.
/// 6 words provides ~77.5 bits, 8 words provides ~103.4 bits.
///
/// # Arguments
///
/// * `word_count` - Number of words in the passphrase (6+ recommended)
///
/// # Returns
///
/// A passphrase with words separated by hyphens
pub fn generate_diceware(word_count: usize) -> String {
    let mut words = Vec::with_capacity(word_count);

    for _ in 0..word_count {
        if let Some(word) = EFF_WORDLIST.choose(&mut OsRng) {
            words.push(*word);
        }
    }

    words.join("-")
}

/// Check if a password meets minimum strength requirements
///
/// # Arguments
///
/// * `password` - The password to check
/// * `min_entropy` - Minimum entropy in bits (64 bits recommended)
///
/// # Returns
///
/// `true` if the password meets requirements
pub fn is_strong_enough(password: &str, min_entropy: f64) -> bool {
    estimate_entropy(password) >= min_entropy
}

/// Generate a strength report for a password
#[derive(Debug, Clone)]
pub struct StrengthReport {
    /// Estimated entropy in bits
    pub entropy: f64,
    /// Password length
    pub length: usize,
    /// Has lowercase letters
    pub has_lowercase: bool,
    /// Has uppercase letters
    pub has_uppercase: bool,
    /// Has digits
    pub has_digits: bool,
    /// Has special characters
    pub has_special: bool,
    /// Strength category
    pub category: StrengthCategory,
}

/// Password strength categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthCategory {
    /// Very weak (< 28 bits)
    VeryWeak,
    /// Weak (28-35 bits)
    Weak,
    /// Fair (36-59 bits)
    Fair,
    /// Strong (60-127 bits)
    Strong,
    /// Very strong (>= 128 bits)
    VeryStrong,
}

/// Analyze password strength
pub fn analyze(password: &str) -> StrengthReport {
    let entropy = estimate_entropy(password);
    let length = password.len();

    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digits = false;
    let mut has_special = false;

    for c in password.chars() {
        if c.is_lowercase() {
            has_lowercase = true;
        } else if c.is_uppercase() {
            has_uppercase = true;
        } else if c.is_numeric() {
            has_digits = true;
        } else {
            has_special = true;
        }
    }

    let category = if entropy < 28.0 {
        StrengthCategory::VeryWeak
    } else if entropy < 36.0 {
        StrengthCategory::Weak
    } else if entropy < 60.0 {
        StrengthCategory::Fair
    } else if entropy < 128.0 {
        StrengthCategory::Strong
    } else {
        StrengthCategory::VeryStrong
    };

    StrengthReport {
        entropy,
        length,
        has_lowercase,
        has_uppercase,
        has_digits,
        has_special,
        category,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_entropy() {
        assert!(estimate_entropy("password") < estimate_entropy("P@ssw0rd!"));
        assert!(estimate_entropy("abc") < estimate_entropy("abcdefghijklmnop"));
    }

    #[test]
    fn test_generate_diceware() {
        let passphrase = generate_diceware(6);
        assert_eq!(passphrase.split('-').count(), 6);

        // Verify all words come from the EFF wordlist
        for word in passphrase.split('-') {
            assert!(
                EFF_WORDLIST.contains(&word),
                "Word '{}' not in EFF wordlist",
                word
            );
        }
    }

    #[test]
    fn test_is_strong_enough() {
        assert!(!is_strong_enough("weak", 64.0));
        assert!(is_strong_enough("This1sAV3ryStr0ngP@ssw0rd!", 64.0));
    }

    #[test]
    fn test_analyze() {
        let report = analyze("P@ssw0rd!");

        assert!(report.has_uppercase);
        assert!(report.has_lowercase);
        assert!(report.has_digits);
        assert!(report.has_special);
        assert_eq!(report.length, 9);
    }
}
