//! Password, passphrase, and username generator with entropy estimation.

use rand::Rng;

// ---------------------------------------------------------------------------
// Password generation
// ---------------------------------------------------------------------------

/// Options for random password generation.
pub struct PasswordOptions {
    pub length: u32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub special: bool,
    /// Exclude visually ambiguous characters: 0O, 1lI, etc.
    pub exclude_ambiguous: bool,
    /// Minimum number of uppercase characters.
    pub min_uppercase: u32,
    /// Minimum number of lowercase characters.
    pub min_lowercase: u32,
    /// Minimum number of digit characters.
    pub min_digits: u32,
    /// Minimum number of special characters.
    pub min_special: u32,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            special: true,
            exclude_ambiguous: false,
            min_uppercase: 0,
            min_lowercase: 0,
            min_digits: 0,
            min_special: 0,
        }
    }
}

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?/~`";
const AMBIGUOUS: &[u8] = b"0O1lI|`";

/// Generate a random password satisfying the given options.
///
/// Guarantees minimum character-class counts, then fills remaining slots
/// randomly from the combined pool.
pub fn generate_password(opts: &PasswordOptions) -> String {
    let mut rng = rand::rng();

    // Build per-class pools, optionally filtering ambiguous chars.
    let filter = |pool: &[u8]| -> Vec<u8> {
        if opts.exclude_ambiguous {
            pool.iter()
                .copied()
                .filter(|c| !AMBIGUOUS.contains(c))
                .collect()
        } else {
            pool.to_vec()
        }
    };

    let upper_pool = if opts.uppercase { filter(UPPERCASE) } else { Vec::new() };
    let lower_pool = if opts.lowercase { filter(LOWERCASE) } else { Vec::new() };
    let digit_pool = if opts.digits { filter(DIGITS) } else { Vec::new() };
    let special_pool = if opts.special { filter(SPECIAL) } else { Vec::new() };

    // Combined pool for fill characters.
    let mut combined: Vec<u8> = Vec::new();
    combined.extend_from_slice(&upper_pool);
    combined.extend_from_slice(&lower_pool);
    combined.extend_from_slice(&digit_pool);
    combined.extend_from_slice(&special_pool);

    // Fallback: if every class is off, use lowercase a-z.
    if combined.is_empty() {
        combined.extend_from_slice(LOWERCASE);
    }

    let length = opts.length.max(1) as usize;
    let mut chars: Vec<u8> = Vec::with_capacity(length);

    // Satisfy minimum requirements first.
    let mut pick_n = |pool: &[u8], n: u32| {
        for _ in 0..n {
            if !pool.is_empty() && chars.len() < length {
                chars.push(pool[rng.random_range(0..pool.len())]);
            }
        }
    };

    pick_n(&upper_pool, opts.min_uppercase);
    pick_n(&lower_pool, opts.min_lowercase);
    pick_n(&digit_pool, opts.min_digits);
    pick_n(&special_pool, opts.min_special);

    // Fill remaining slots from combined pool.
    while chars.len() < length {
        chars.push(combined[rng.random_range(0..combined.len())]);
    }

    // Fisher-Yates shuffle to avoid predictable positions.
    for i in (1..chars.len()).rev() {
        let j = rng.random_range(0..=i);
        chars.swap(i, j);
    }

    String::from_utf8(chars).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Passphrase generation
// ---------------------------------------------------------------------------

/// Options for diceware-style passphrase generation.
pub struct PassphraseOptions {
    /// Number of words in the passphrase.
    pub word_count: u32,
    /// Separator between words.
    pub separator: String,
    /// Capitalize the first letter of each word.
    pub capitalize: bool,
    /// Append a random digit to one word.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            word_count: 5,
            separator: "-".to_string(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Generate a diceware-style passphrase from a built-in word list.
pub fn generate_passphrase(opts: &PassphraseOptions) -> String {
    let mut rng = rand::rng();
    let count = opts.word_count.max(1) as usize;

    let mut words: Vec<String> = (0..count)
        .map(|_| {
            let w = WORDLIST[rng.random_range(0..WORDLIST.len())];
            if opts.capitalize {
                let mut c = w.chars();
                match c.next() {
                    None => String::new(),
                    Some(first) => {
                        let upper: String = first.to_uppercase().collect();
                        upper + c.as_str()
                    }
                }
            } else {
                w.to_string()
            }
        })
        .collect();

    // Optionally append a random digit to a random word.
    if opts.include_number && !words.is_empty() {
        let idx = rng.random_range(0..words.len());
        let digit = rng.random_range(0u32..10u32);
        words[idx].push_str(&digit.to_string());
    }

    words.join(&opts.separator)
}

// ---------------------------------------------------------------------------
// Username generation
// ---------------------------------------------------------------------------

/// Username generation mode.
pub enum UsernameMode {
    /// Pick a random word-based username.
    RandomWord,
    /// Generate a plus-address: `user+tag@domain`.
    PlusAddress { email: String },
    /// Generate a catch-all address: `random@domain`.
    CatchAll { domain: String },
}

/// Options for username generation.
pub struct UsernameOptions {
    pub mode: UsernameMode,
}

impl Default for UsernameOptions {
    fn default() -> Self {
        Self {
            mode: UsernameMode::RandomWord,
        }
    }
}

/// Generate a random username according to the given mode.
pub fn generate_username(opts: &UsernameOptions) -> String {
    let mut rng = rand::rng();

    match &opts.mode {
        UsernameMode::RandomWord => {
            let adj = ADJECTIVES[rng.random_range(0..ADJECTIVES.len())];
            let noun = NOUNS[rng.random_range(0..NOUNS.len())];
            let num: u32 = rng.random_range(10..9999);
            format!("{adj}{noun}{num}")
        }
        UsernameMode::PlusAddress { email } => {
            // Split on '@', insert random tag.
            let tag_word = WORDLIST[rng.random_range(0..WORDLIST.len())];
            let tag_num: u32 = rng.random_range(100..9999);
            if let Some(at_pos) = email.find('@') {
                let (local, domain) = email.split_at(at_pos);
                format!("{local}+{tag_word}{tag_num}{domain}")
            } else {
                format!("{email}+{tag_word}{tag_num}")
            }
        }
        UsernameMode::CatchAll { domain } => {
            let word = WORDLIST[rng.random_range(0..WORDLIST.len())];
            let num: u32 = rng.random_range(100..9999);
            let dom = domain.strip_prefix('@').unwrap_or(domain);
            format!("{word}{num}@{dom}")
        }
    }
}

// ---------------------------------------------------------------------------
// Entropy estimation
// ---------------------------------------------------------------------------

/// Estimate password entropy in bits (simplified model).
///
/// Computes `log2(pool_size ^ length)` where pool_size is the number of
/// distinct character classes present (upper, lower, digit, special, other).
/// Also applies a small penalty for detected patterns (sequences, repeats).
pub fn estimate_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_special = false;
    let mut has_other = false;

    for ch in password.chars() {
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if ch.is_ascii_punctuation() || ch == ' ' {
            has_special = true;
        } else {
            has_other = true;
        }
    }

    let mut pool_size: u32 = 0;
    if has_upper {
        pool_size += 26;
    }
    if has_lower {
        pool_size += 26;
    }
    if has_digit {
        pool_size += 10;
    }
    if has_special {
        pool_size += 33;
    }
    if has_other {
        pool_size += 128; // broad Unicode bucket
    }

    if pool_size == 0 {
        return 0.0;
    }

    let raw = (pool_size as f64).log2() * password.len() as f64;

    // Penalty for consecutive repeated characters.
    let bytes = password.as_bytes();
    let mut repeat_penalty = 0.0f64;
    for i in 1..bytes.len() {
        if bytes[i] == bytes[i - 1] {
            repeat_penalty += 1.0;
        }
    }

    // Penalty for sequential runs (abc, 123, etc.).
    let mut seq_penalty = 0.0f64;
    for i in 2..bytes.len() {
        let a = bytes[i - 2] as i16;
        let b = bytes[i - 1] as i16;
        let c = bytes[i] as i16;
        if c - b == b - a && (c - b).abs() == 1 {
            seq_penalty += 1.0;
        }
    }

    (raw - repeat_penalty * 2.0 - seq_penalty * 3.0).max(0.0)
}

/// Rate password strength as a human-readable label.
pub fn strength_rating(password: &str) -> &'static str {
    let bits = estimate_entropy(password);
    if bits < 28.0 {
        "very weak"
    } else if bits < 36.0 {
        "weak"
    } else if bits < 60.0 {
        "fair"
    } else if bits < 80.0 {
        "strong"
    } else {
        "very strong"
    }
}

// ---------------------------------------------------------------------------
// Word lists (embedded)
// ---------------------------------------------------------------------------

/// Adjectives for random username generation.
const ADJECTIVES: &[&str] = &[
    "swift", "brave", "calm", "dark", "eager", "fair", "glad",
    "happy", "iron", "just", "keen", "loud", "mild", "neat",
    "odd", "proud", "quick", "rare", "safe", "tall", "vivid",
    "warm", "zesty", "bold", "cool", "deep", "fast", "grand",
    "icy", "kind", "lean", "mute", "new", "open", "pale",
    "raw", "slim", "true", "vast", "wise", "young", "agile",
    "blue", "crisp", "dry", "even", "fine", "gray", "half",
];

/// Nouns for random username generation.
const NOUNS: &[&str] = &[
    "wolf", "hawk", "bear", "deer", "fox", "lynx", "owl",
    "pike", "seal", "toad", "vole", "wren", "yak", "ape",
    "bat", "cob", "dove", "elk", "frog", "goat", "hare",
    "ibis", "jay", "koi", "lark", "mole", "newt", "orca",
    "puma", "quail", "ram", "swan", "tern", "urial", "viper",
    "wasp", "ray", "ant", "bee", "cod", "dace", "eel",
    "finch", "gecko", "heron", "iguana", "jackal", "koala", "lemur",
];

/// Diceware-style word list (210 common English words, 3-6 letters each).
const WORDLIST: &[&str] = &[
    "able", "acid", "aged", "also", "arch", "area", "army",
    "away", "baby", "back", "ball", "band", "bank", "barn",
    "base", "bath", "beam", "bear", "beat", "been", "bell",
    "belt", "bend", "best", "bird", "bite", "blow", "blue",
    "boat", "body", "bolt", "bomb", "bond", "bone", "book",
    "boot", "born", "boss", "bowl", "bulk", "burn", "bush",
    "busy", "cafe", "cage", "cake", "calm", "came", "camp",
    "card", "care", "cart", "case", "cash", "cast", "cave",
    "cell", "chat", "chip", "city", "clad", "clan", "clay",
    "clip", "club", "clue", "coal", "coat", "code", "coil",
    "coin", "cold", "colt", "come", "cook", "cool", "cope",
    "copy", "cord", "core", "corn", "cost", "coup", "crew",
    "crop", "crow", "cure", "curl", "cute", "dale", "dame",
    "dare", "dark", "data", "dawn", "deal", "dear", "debt",
    "deck", "deed", "deem", "deep", "deny", "desk", "dial",
    "dice", "diet", "dime", "dirt", "disc", "dish", "dock",
    "dome", "done", "doom", "door", "dose", "dove", "down",
    "draw", "drew", "drop", "drum", "dual", "dumb", "dump",
    "dune", "dust", "duty", "each", "earl", "earn", "ease",
    "east", "easy", "edge", "edit", "else", "epic", "even",
    "ever", "evil", "exam", "exit", "face", "fact", "fade",
    "fail", "fair", "fake", "fall", "fame", "fang", "fare",
    "farm", "fast", "fate", "fear", "feat", "feed", "feel",
    "felt", "fern", "file", "fill", "film", "find", "fine",
    "fire", "firm", "fish", "fist", "five", "flag", "flat",
    "fled", "flew", "flip", "flow", "foam", "fold", "folk",
    "fond", "font", "food", "fool", "foot", "ford", "fore",
    "fork", "form", "fort", "foul", "four", "free", "from",
    "fuel", "full", "fund", "fury", "fuse", "gain", "gait",
    "gale", "game", "gang", "gate", "gave", "gaze", "gear",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_password_length() {
        let pw = generate_password(&PasswordOptions::default());
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn password_respects_length() {
        let opts = PasswordOptions { length: 64, ..Default::default() };
        let pw = generate_password(&opts);
        assert_eq!(pw.len(), 64);
    }

    #[test]
    fn password_minimum_classes() {
        let opts = PasswordOptions {
            length: 16,
            min_uppercase: 2,
            min_lowercase: 2,
            min_digits: 2,
            min_special: 2,
            ..Default::default()
        };
        let pw = generate_password(&opts);
        assert_eq!(pw.len(), 16);
        assert!(pw.chars().filter(|c| c.is_ascii_uppercase()).count() >= 2);
        assert!(pw.chars().filter(|c| c.is_ascii_lowercase()).count() >= 2);
        assert!(pw.chars().filter(|c| c.is_ascii_digit()).count() >= 2);
    }

    #[test]
    fn password_digits_only() {
        let opts = PasswordOptions {
            length: 8,
            uppercase: false,
            lowercase: false,
            digits: true,
            special: false,
            ..Default::default()
        };
        let pw = generate_password(&opts);
        assert_eq!(pw.len(), 8);
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn password_exclude_ambiguous() {
        let opts = PasswordOptions {
            length: 200,
            exclude_ambiguous: true,
            ..Default::default()
        };
        let pw = generate_password(&opts);
        for &amb in AMBIGUOUS {
            assert!(
                !pw.as_bytes().contains(&amb),
                "Password contains ambiguous char: {}",
                amb as char
            );
        }
    }

    #[test]
    fn passphrase_word_count() {
        let opts = PassphraseOptions { word_count: 6, ..Default::default() };
        let pp = generate_passphrase(&opts);
        assert_eq!(pp.split('-').count(), 6);
    }

    #[test]
    fn passphrase_capitalize() {
        let opts = PassphraseOptions {
            word_count: 4,
            capitalize: true,
            ..Default::default()
        };
        let pp = generate_passphrase(&opts);
        for word in pp.split('-') {
            let first = word.chars().next().unwrap();
            // First char should be uppercase (or a digit if include_number added one).
            assert!(
                first.is_ascii_uppercase() || first.is_ascii_digit(),
                "Expected uppercase or digit start, got '{first}' in '{word}'"
            );
        }
    }

    #[test]
    fn passphrase_custom_separator() {
        let opts = PassphraseOptions {
            word_count: 3,
            separator: ".".into(),
            ..Default::default()
        };
        let pp = generate_passphrase(&opts);
        assert_eq!(pp.split('.').count(), 3);
    }

    #[test]
    fn username_random_word() {
        let u = generate_username(&UsernameOptions::default());
        assert!(!u.is_empty());
        // Should end with digits.
        assert!(u.chars().last().unwrap().is_ascii_digit());
    }

    #[test]
    fn username_plus_address() {
        let opts = UsernameOptions {
            mode: UsernameMode::PlusAddress { email: "user@example.com".into() },
        };
        let u = generate_username(&opts);
        assert!(u.starts_with("user+"));
        assert!(u.contains("@example.com"));
    }

    #[test]
    fn username_catch_all() {
        let opts = UsernameOptions {
            mode: UsernameMode::CatchAll { domain: "example.org".into() },
        };
        let u = generate_username(&opts);
        assert!(u.ends_with("@example.org"));
    }

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(estimate_entropy(""), 0.0);
    }

    #[test]
    fn entropy_increases_with_length_and_classes() {
        let short = estimate_entropy("abc");
        let longer = estimate_entropy("abcdefgh");
        let mixed = estimate_entropy("aBc1@fGh");
        assert!(longer > short);
        assert!(mixed > longer);
    }

    #[test]
    fn strength_rating_categories() {
        assert_eq!(strength_rating(""), "very weak");
        assert_eq!(strength_rating("abc"), "very weak");
        // "abcdef" has sequential penalty, so it stays "very weak".
        assert_eq!(strength_rating("abcdef"), "very weak");
        // Non-sequential 8-char lowercase should be at least "weak".
        let rating_8 = strength_rating("qwmpzxnk");
        assert!(
            rating_8 == "weak" || rating_8 == "fair",
            "Expected weak/fair, got '{rating_8}'"
        );
        // A 20-char mixed password should be strong or very strong.
        let pw = generate_password(&PasswordOptions::default());
        let rating = strength_rating(&pw);
        assert!(
            rating == "strong" || rating == "very strong",
            "Expected strong+, got '{rating}' for '{pw}'"
        );
    }
}
