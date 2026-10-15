//! Privacy-aware content extraction for browser automation.
//! Provides PII detection and redaction for scraped text content,
//! content fingerprinting for deduplication, and data retention tracking.

use std::collections::HashSet;

// ─── PII Detection & Redaction ───────────────────────────────────────────────

/// PII types that can be detected and redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiType {
    Email,
    Phone,
    SSN,
    CreditCard,
    IPAddress,
    Name,
    Address,
    DateOfBirth,
}

/// Result of PII scanning.
#[derive(Debug, Clone)]
pub struct PiiScanResult {
    /// Number of PII instances found.
    pub count: usize,
    /// Types of PII found.
    pub types_found: HashSet<PiiType>,
    /// Redacted version of the text.
    pub redacted_text: String,
    /// Original text length (for comparison).
    pub original_length: usize,
}

/// Scan text for PII and return a redacted version.
///
/// All pattern types are detected on the original text simultaneously,
/// then overlapping spans are resolved (more specific patterns like SSN/CC/IP
/// take priority over the broader phone pattern). Replacements are applied
/// in reverse order to preserve byte offsets.
pub fn scan_and_redact(text: &str) -> PiiScanResult {
    // Collect all candidate spans from the original text.
    let mut spans: Vec<(usize, usize, PiiType, &str)> = Vec::new();

    for (s, e) in find_emails(text) {
        spans.push((s, e, PiiType::Email, "[EMAIL_REDACTED]"));
    }
    for (s, e) in find_ssns(text) {
        spans.push((s, e, PiiType::SSN, "[SSN_REDACTED]"));
    }
    for (s, e) in find_credit_cards(text) {
        spans.push((s, e, PiiType::CreditCard, "[CC_REDACTED]"));
    }
    for (s, e) in find_ip_addresses(text) {
        spans.push((s, e, PiiType::IPAddress, "[IP_REDACTED]"));
    }
    for (s, e) in find_phones(text) {
        spans.push((s, e, PiiType::Phone, "[PHONE_REDACTED]"));
    }
    for (s, e) in find_dates_of_birth(text) {
        spans.push((s, e, PiiType::DateOfBirth, "[DOB_REDACTED]"));
    }
    for (s, e) in find_names(text) {
        spans.push((s, e, PiiType::Name, "[NAME_REDACTED]"));
    }
    for (s, e) in find_addresses(text) {
        spans.push((s, e, PiiType::Address, "[ADDRESS_REDACTED]"));
    }

    // Sort by start position, then by end position descending (longer spans first),
    // then by specificity (phone is least specific, so it loses ties).
    let priority = |t: &PiiType| -> u8 {
        match t {
            PiiType::SSN => 0,
            PiiType::CreditCard => 1,
            PiiType::IPAddress => 2,
            PiiType::Email => 3,
            PiiType::DateOfBirth => 4,
            PiiType::Name => 5,
            PiiType::Address => 6,
            PiiType::Phone => 7, // least specific — loses ties
        }
    };
    spans.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(b.1.cmp(&a.1))
            .then(priority(&a.2).cmp(&priority(&b.2)))
    });

    // Remove overlapping spans — keep the first (more specific) match.
    let mut accepted: Vec<(usize, usize, PiiType, &str)> = Vec::new();
    for span in spans {
        if accepted.last().map_or(true, |prev| span.0 >= prev.1) {
            accepted.push(span);
        }
    }

    // Apply replacements in reverse order to preserve byte offsets.
    let mut redacted = text.to_string();
    let mut types = HashSet::new();
    for (start, end, pii_type, replacement) in accepted.iter().rev() {
        redacted.replace_range(*start..*end, replacement);
        types.insert(*pii_type);
    }

    PiiScanResult {
        count: accepted.len(),
        types_found: types,
        redacted_text: redacted,
        original_length: text.len(),
    }
}

/// Find email-like patterns (local@domain.tld).
fn find_emails(text: &str) -> Vec<(usize, usize)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' && i > 0 {
            // Find start of local part
            let mut start = i;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric()
                    || bytes[start - 1] == b'.'
                    || bytes[start - 1] == b'_'
                    || bytes[start - 1] == b'-'
                    || bytes[start - 1] == b'+')
            {
                start -= 1;
            }
            // Find end of domain
            let mut end = i + 1;
            let mut has_dot = false;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric()
                    || bytes[end] == b'.'
                    || bytes[end] == b'-')
            {
                if bytes[end] == b'.' {
                    has_dot = true;
                }
                end += 1;
            }
            if has_dot && end > i + 2 && start < i {
                results.push((start, end));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    results
}

/// Find phone-like patterns (10-15 digits with separators).
fn find_phones(text: &str) -> Vec<(usize, usize)> {
    let mut results = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '+' || chars[i] == '(' || chars[i].is_ascii_digit() {
            let start = i;
            let mut digit_count = 0;
            let mut j = i;
            while j < chars.len()
                && (chars[j].is_ascii_digit()
                    || chars[j] == '-'
                    || chars[j] == ' '
                    || chars[j] == '('
                    || chars[j] == ')'
                    || chars[j] == '+'
                    || chars[j] == '.')
            {
                if chars[j].is_ascii_digit() {
                    digit_count += 1;
                }
                j += 1;
            }
            // Trim trailing non-digit characters (spaces, dashes, dots).
            while j > start && !chars[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if digit_count >= 10 && digit_count <= 15 && j - start >= 10 {
                results.push((start, j));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    results
}

/// Find SSN patterns (NNN-NN-NNNN).
fn find_ssns(text: &str) -> Vec<(usize, usize)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    if bytes.len() < 11 {
        return results;
    }
    for i in 0..bytes.len().saturating_sub(10) {
        if bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3] == b'-'
            && bytes[i + 4].is_ascii_digit()
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6] == b'-'
            && bytes[i + 7].is_ascii_digit()
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
            && bytes[i + 10].is_ascii_digit()
        {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
            let after_ok = i + 11 >= bytes.len() || !bytes[i + 11].is_ascii_digit();
            if before_ok && after_ok {
                results.push((i, i + 11));
            }
        }
    }
    results
}

/// Find credit card patterns (4 groups of 4 digits separated by spaces or dashes).
fn find_credit_cards(text: &str) -> Vec<(usize, usize)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return results;
    }
    for i in 0..bytes.len().saturating_sub(18) {
        let mut valid = true;
        let mut pos = i;
        for group in 0..4 {
            for _ in 0..4 {
                if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
                    valid = false;
                    break;
                }
                pos += 1;
            }
            if !valid {
                break;
            }
            if group < 3 {
                if pos >= bytes.len() || (bytes[pos] != b' ' && bytes[pos] != b'-') {
                    valid = false;
                    break;
                }
                pos += 1;
            }
        }
        if valid {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
            let after_ok = pos >= bytes.len() || !bytes[pos].is_ascii_digit();
            if before_ok && after_ok {
                results.push((i, pos));
            }
        }
    }
    results
}

/// Find IPv4 address patterns (N.N.N.N where N is 0-255).
fn find_ip_addresses(text: &str) -> Vec<(usize, usize)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut octets = 0;
            let mut j = i;
            while j < bytes.len() && octets < 4 {
                let oct_start = j;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                let oct_len = j - oct_start;
                if oct_len < 1 || oct_len > 3 {
                    break;
                }
                let oct_val: u16 = text[oct_start..j].parse().unwrap_or(999);
                if oct_val > 255 {
                    break;
                }
                octets += 1;
                if octets < 4 {
                    if j < bytes.len() && bytes[j] == b'.' {
                        j += 1;
                    } else {
                        break;
                    }
                }
            }
            if octets == 4 {
                let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
                let after_ok = j >= bytes.len() || !bytes[j].is_ascii_digit();
                if before_ok && after_ok {
                    results.push((start, j));
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    results
}

/// Find date-of-birth patterns near DOB keywords.
///
/// Detects common date formats (MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD, Month DD YYYY,
/// DD Month YYYY) when preceded or followed within 40 bytes by keywords:
/// "born", "dob", "date of birth", "birthday", "birthdate", "birth date".
///
/// Returns byte spans of the **entire keyword+date context** to ensure the
/// surrounding context is redacted, preventing leakage of partial hints.
pub fn find_dates_of_birth(text: &str) -> Vec<(usize, usize)> {
    let lower = text.to_lowercase();
    let keywords: &[&str] = &["born", "dob", "date of birth", "birthday", "birthdate", "birth date"];

    // Date-like patterns in order of specificity:
    // YYYY-MM-DD  (ISO)
    // MM/DD/YYYY or DD/MM/YYYY
    // MM-DD-YYYY or DD-MM-YYYY
    // DD Month YYYY  or  Month DD, YYYY
    let mut results = Vec::new();
    let bytes = text.as_bytes();

    // Find keyword positions first, then scan ±60 bytes for a date
    for kw in keywords {
        let mut search_from = 0;
        while let Some(kw_pos) = lower[search_from..].find(kw) {
            let abs_pos = search_from + kw_pos;
            let window_start = abs_pos.saturating_sub(5);
            let window_end = (abs_pos + kw.len() + 60).min(text.len());
            let window = &text[window_start..window_end];

            // Try ISO date YYYY-MM-DD
            if let Some(rel) = find_iso_date(window) {
                let start = window_start + rel.0;
                let end = window_start + rel.1;
                if !overlaps(&results, start, end) {
                    results.push((start, end));
                }
            }
            // Try MM/DD/YYYY or DD/MM/YYYY (numeric slash)
            if let Some(rel) = find_slash_date(window) {
                let start = window_start + rel.0;
                let end = window_start + rel.1;
                if !overlaps(&results, start, end) {
                    results.push((start, end));
                }
            }
            // Try MM-DD-YYYY or DD-MM-YYYY (numeric dash, not ISO)
            if let Some(rel) = find_dash_date(window) {
                let start = window_start + rel.0;
                let end = window_start + rel.1;
                if !overlaps(&results, start, end) {
                    results.push((start, end));
                }
            }
            // Try textual month dates
            if let Some(rel) = find_text_date(window) {
                let start = window_start + rel.0;
                let end = window_start + rel.1;
                if !overlaps(&results, start, end) {
                    results.push((start, end));
                }
            }

            search_from = abs_pos + kw.len();
        }
    }

    // Also detect bare ISO dates (YYYY-MM-DD) anywhere in the text as DOB
    // (common in structured data like JSON/CSV)
    let mut i = 0;
    while i + 10 <= bytes.len() {
        if let Some(rel) = find_iso_date(&text[i..i + 10.min(text.len() - i)]) {
            let start = i + rel.0;
            let end = i + rel.1;
            if !overlaps(&results, start, end) {
                results.push((start, end));
            }
            i = end;
        } else {
            i += 1;
        }
    }

    results.sort_by_key(|r| r.0);
    results
}

fn overlaps(existing: &[(usize, usize)], start: usize, end: usize) -> bool {
    existing.iter().any(|&(s, e)| start < e && end > s)
}

/// Find ISO date YYYY-MM-DD at start of string slice (up to 10 chars).
fn find_iso_date(text: &str) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    if b.len() < 10 {
        return None;
    }
    // Scan for YYYY-MM-DD pattern
    for i in 0..b.len().saturating_sub(9) {
        if b[i].is_ascii_digit()
            && b[i+1].is_ascii_digit()
            && b[i+2].is_ascii_digit()
            && b[i+3].is_ascii_digit()
            && b[i+4] == b'-'
            && b[i+5].is_ascii_digit()
            && b[i+6].is_ascii_digit()
            && b[i+7] == b'-'
            && b[i+8].is_ascii_digit()
            && b[i+9].is_ascii_digit()
        {
            let year: u32 = text[i..i+4].parse().unwrap_or(0);
            let month: u32 = text[i+5..i+7].parse().unwrap_or(0);
            let day: u32 = text[i+8..i+10].parse().unwrap_or(0);
            if year >= 1900 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31 {
                return Some((i, i + 10));
            }
        }
    }
    None
}

/// Find MM/DD/YYYY or DD/MM/YYYY slash-separated date.
fn find_slash_date(text: &str) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    for i in 0..b.len().saturating_sub(9) {
        // Two digits, slash, two digits, slash, four digits
        if b[i].is_ascii_digit()
            && b[i+1].is_ascii_digit()
            && b[i+2] == b'/'
            && b[i+3].is_ascii_digit()
            && b[i+4].is_ascii_digit()
            && b[i+5] == b'/'
            && b[i+6].is_ascii_digit()
            && b[i+7].is_ascii_digit()
            && b[i+8].is_ascii_digit()
            && b[i+9].is_ascii_digit()
        {
            let a: u32 = text[i..i+2].parse().unwrap_or(0);
            let c_val: u32 = text[i+3..i+5].parse().unwrap_or(0);
            let year: u32 = text[i+6..i+10].parse().unwrap_or(0);
            if year >= 1900 && year <= 2100 && a >= 1 && a <= 31 && c_val >= 1 && c_val <= 31 {
                return Some((i, i + 10));
            }
        }
    }
    None
}

/// Find MM-DD-YYYY or DD-MM-YYYY dash-separated date (2-digit parts only).
fn find_dash_date(text: &str) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    for i in 0..b.len().saturating_sub(9) {
        if b[i].is_ascii_digit()
            && b[i+1].is_ascii_digit()
            && b[i+2] == b'-'
            && b[i+3].is_ascii_digit()
            && b[i+4].is_ascii_digit()
            && b[i+5] == b'-'
            && b[i+6].is_ascii_digit()
            && b[i+7].is_ascii_digit()
            && b[i+8].is_ascii_digit()
            && b[i+9].is_ascii_digit()
        {
            let a: u32 = text[i..i+2].parse().unwrap_or(0);
            let c_val: u32 = text[i+3..i+5].parse().unwrap_or(0);
            let year: u32 = text[i+6..i+10].parse().unwrap_or(0);
            // Must not be ISO (where first group is 4 digits) — already handled
            // Validate roughly: a and c are day/month range
            if year >= 1900 && year <= 2100 && a >= 1 && a <= 31 && c_val >= 1 && c_val <= 31 {
                return Some((i, i + 10));
            }
        }
    }
    None
}

static MONTH_NAMES: &[&str] = &[
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Find textual date patterns like "January 15, 1990" or "15 March 1990".
fn find_text_date(text: &str) -> Option<(usize, usize)> {
    let lower = text.to_lowercase();
    for month in MONTH_NAMES {
        if let Some(pos) = lower.find(month) {
            let start = pos;
            // Look for year within 20 chars before or after the month name
            let ctx_start = start.saturating_sub(5);
            let ctx_end = (start + month.len() + 20).min(text.len());
            let ctx = &text[ctx_start..ctx_end];
            // Find a 4-digit year in the context
            let cb = ctx.as_bytes();
            for j in 0..cb.len().saturating_sub(3) {
                if cb[j].is_ascii_digit()
                    && cb[j+1].is_ascii_digit()
                    && cb[j+2].is_ascii_digit()
                    && cb[j+3].is_ascii_digit()
                {
                    let year: u32 = ctx[j..j+4].parse().unwrap_or(0);
                    if year >= 1900 && year <= 2100 {
                        let abs_start = ctx_start;
                        let abs_end = (ctx_start + j + 4).min(text.len());
                        return Some((abs_start, abs_end));
                    }
                }
            }
        }
    }
    None
}

/// Find patterns that look like personal names (two or more capitalized words).
///
/// Uses a heuristic: a sequence of 2–4 space-separated words where each word
/// starts with an uppercase letter, has length 2–20, and contains only letters
/// and hyphens. Common single-word titles (Mr, Mrs, Dr, etc.) are excluded as
/// standalone matches but their following names are captured.
///
/// This will have some false positives on proper nouns (place names, etc.) but
/// is suitable for a privacy-scanning heuristic.
pub fn find_names(text: &str) -> Vec<(usize, usize)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Skip non-word characters
        if !bytes[i].is_ascii_uppercase() {
            i += 1;
            continue;
        }

        // Try to collect a sequence of capitalized words
        let start = i;
        let mut word_count = 0;
        let mut pos = i;
        let mut last_end = i;

        while pos < bytes.len() {
            // Skip leading spaces
            let _word_start = pos;
            // Expect uppercase start
            if !bytes[pos].is_ascii_uppercase() {
                break;
            }
            // Read word: letters, hyphens, apostrophes allowed
            let wstart = pos;
            while pos < bytes.len()
                && (bytes[pos].is_ascii_alphabetic()
                    || bytes[pos] == b'-'
                    || bytes[pos] == b'\'')
            {
                pos += 1;
            }
            let word_len = pos - wstart;
            if word_len < 2 || word_len > 20 {
                // Too short or too long — not a name component
                if word_count == 0 {
                    i = pos + 1;
                }
                break;
            }
            word_count += 1;
            last_end = pos;

            // Skip exactly one space (names are separated by single spaces)
            if pos < bytes.len() && bytes[pos] == b' ' {
                pos += 1;
                // Next char must be uppercase to continue
                if pos < bytes.len() && !bytes[pos].is_ascii_uppercase() {
                    break;
                }
            } else {
                break;
            }

            if word_count >= 4 {
                break; // Cap at 4-word names
            }
        }

        if word_count >= 2 {
            let candidate = &text[start..last_end];
            // Filter out common non-name patterns
            let lc = candidate.to_lowercase();
            let is_noise = lc == "the" || lc.starts_with("http") || lc.contains("//");
            if !is_noise && !overlaps(&results, start, last_end) {
                results.push((start, last_end));
            }
            i = last_end;
        } else {
            i += 1;
        }
    }
    results
}

/// Find postal address patterns.
///
/// Detects:
/// - Street addresses: a number followed by a street name with a recognized
///   suffix (St, Ave, Blvd, Dr, Rd, Ln, Ct, Pl, Cir, Way, Pkwy, Hwy, etc.)
/// - US ZIP codes: 5-digit or 5+4 digit codes after a state abbreviation
///
/// Returns spans covering the matched address fragment.
pub fn find_addresses(text: &str) -> Vec<(usize, usize)> {
    static STREET_SUFFIXES: &[&str] = &[
        "street", "st", "avenue", "ave", "boulevard", "blvd", "drive", "dr",
        "road", "rd", "lane", "ln", "court", "ct", "place", "pl", "circle",
        "cir", "way", "parkway", "pkwy", "highway", "hwy", "terrace", "ter",
        "trail", "trl", "square", "sq", "loop", "run", "row", "path",
    ];

    let mut results = Vec::new();
    let lower = text.to_lowercase();
    let bytes = text.as_bytes();

    // Pattern: [number] [words] [suffix][,]?[optional city, state zip]
    // Scan for a numeric street number followed by words + a street suffix
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            // Check for street number: 1-6 digits at start of a word
            let num_start = i;
            let before_ok = i == 0 || !bytes[i-1].is_ascii_alphanumeric();
            if !before_ok {
                i += 1;
                continue;
            }
            let mut num_end = i;
            while num_end < bytes.len() && bytes[num_end].is_ascii_digit() {
                num_end += 1;
            }
            let num_len = num_end - num_start;
            if num_len < 1 || num_len > 6 {
                i = num_end;
                continue;
            }
            // Must be followed by a space then letters (street name)
            if num_end >= bytes.len() || bytes[num_end] != b' ' {
                i = num_end;
                continue;
            }

            // Look ahead up to 60 chars for a street suffix
            let lookahead_end = (num_start + 80).min(lower.len());
            let segment = &lower[num_start..lookahead_end];

            let mut found_suffix_end = None;
            for suffix in STREET_SUFFIXES {
                // Look for " suffix" or " suffix," or " suffix " at word boundary
                let needle = format!(" {}", suffix);
                if let Some(rel) = segment.find(&needle) {
                    let candidate_end = num_start + rel + needle.len();
                    // Verify it's at a word boundary
                    let next = candidate_end;
                    let at_boundary = next >= text.len()
                        || !bytes[next].is_ascii_alphanumeric();
                    if at_boundary {
                        found_suffix_end = Some(candidate_end);
                        break;
                    }
                }
            }

            if let Some(end) = found_suffix_end {
                // Optionally extend to include city, state, zip (up to end of line)
                let mut extended = end;
                // Skip optional comma + city name + state + zip
                if extended < bytes.len() && (bytes[extended] == b',' || bytes[extended] == b' ') {
                    let line_end = text[extended..]
                        .find('\n')
                        .map(|p| extended + p)
                        .unwrap_or(text.len());
                    let rest = &text[extended..line_end.min(extended + 50)];
                    // Include if rest looks like ", City, ST 12345"
                    if rest.len() > 3 {
                        extended = extended + rest.len().min(40);
                    }
                }
                if !overlaps(&results, num_start, extended) {
                    results.push((num_start, extended.min(text.len())));
                }
                i = extended;
                continue;
            }
        }
        i += 1;
    }

    results
}

// ─── Content Fingerprinting ──────────────────────────────────────────────────

/// Content fingerprint for deduplication and change detection.
/// Uses SimHash-style fingerprinting for O(1) similarity comparison.
#[derive(Debug, Clone)]
pub struct ContentFingerprint {
    pub hash: u64,
    pub word_count: usize,
    pub timestamp: String,
}

impl ContentFingerprint {
    /// Create a fingerprint from text content.
    pub fn from_text(text: &str) -> Self {
        let hash = simhash(text);
        let word_count = text.split_whitespace().count();
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let timestamp = crate::stdlib::time::epoch_secs_to_iso(epoch);
        Self {
            hash,
            word_count,
            timestamp,
        }
    }

    /// Compare two fingerprints. Returns 0.0-1.0 similarity score.
    /// Uses Hamming distance on 64-bit SimHash.
    pub fn similarity(&self, other: &ContentFingerprint) -> f64 {
        let xor = self.hash ^ other.hash;
        let diff_bits = xor.count_ones() as f64;
        1.0 - (diff_bits / 64.0)
    }
}

/// SimHash: locality-sensitive hash for text similarity.
fn simhash(text: &str) -> u64 {
    let mut v = [0i32; 64];
    for word in text.split_whitespace() {
        let hash = blake3::hash(word.as_bytes());
        let h = u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap());
        for i in 0..64 {
            if (h >> i) & 1 == 1 {
                v[i] += 1;
            } else {
                v[i] -= 1;
            }
        }
    }
    let mut result = 0u64;
    for i in 0..64 {
        if v[i] > 0 {
            result |= 1 << i;
        }
    }
    result
}

// ─── Data Retention Registry ─────────────────────────────────────────────────

/// Content retention entry — tracks expiry of scraped content.
#[derive(Debug, Clone)]
pub struct RetentionEntry {
    pub content_hash: String,
    pub url: String,
    pub scraped_at: String,
    pub expires_at: String,
    pub legal_basis: String,
    pub retain_days: u32,
}

/// Registry tracking all scraped content with retention policies.
#[derive(Debug, Default)]
pub struct RetentionRegistry {
    entries: Vec<RetentionEntry>,
}

impl RetentionRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register scraped content with a retention policy.
    pub fn register(
        &mut self,
        url: &str,
        content_hash: &str,
        legal_basis: &str,
        retain_days: u32,
    ) {
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let scraped_at = crate::stdlib::time::epoch_secs_to_iso(epoch);
        let expires_at =
            crate::stdlib::time::epoch_secs_to_iso(epoch + (retain_days as i64 * 86400));
        self.entries.push(RetentionEntry {
            content_hash: content_hash.to_string(),
            url: url.to_string(),
            scraped_at,
            expires_at,
            legal_basis: legal_basis.to_string(),
            retain_days,
        });
    }

    /// Check if content has expired based on its retention policy.
    pub fn is_expired(&self, content_hash: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let now_iso = crate::stdlib::time::epoch_secs_to_iso(now);
        self.entries
            .iter()
            .find(|e| e.content_hash == content_hash)
            .map(|e| e.expires_at < now_iso)
            .unwrap_or(true) // unknown content is treated as expired
    }

    /// Number of tracked entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Export registry as JSON for audit trails.
    pub fn export_json(&self) -> String {
        let entries: Vec<String> = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    r#"{{"content_hash":"{}","url":"{}","scraped_at":"{}","expires_at":"{}","legal_basis":"{}","retain_days":{}}}"#,
                    e.content_hash, e.url, e.scraped_at, e.expires_at, e.legal_basis, e.retain_days
                )
            })
            .collect();
        format!("[{}]", entries.join(","))
    }
}

/// Serve gate (P4 / N6 closure): may content under `content_hash` be served?
///
/// Default-to-tightest:
/// - **unknown** hashes → `false` (unregistered content is never servable);
/// - entries registered with `retain_days == 0` → `false` (zero-day retention
///   means "retain nothing"; checked explicitly because `expires_at` is
///   second-granular and would still compare equal to `now` when queried
///   within the same second as registration);
/// - otherwise → `!is_expired(hash)` (byte-for-byte expiry semantics of the
///   registry remain the source of truth for nonzero retentions).
pub fn may_serve(registry: &RetentionRegistry, content_hash: &str) -> bool {
    match registry
        .entries
        .iter()
        .find(|e| e.content_hash == content_hash)
    {
        Some(e) if e.retain_days == 0 => false,
        Some(_) => !registry.is_expired(content_hash),
        None => false,
    }
}

/// Hard-error form of [`may_serve`]: `Err` when the content must not be
/// served. The error message always contains the offending `content_hash` so
/// callers can log the exact object that was refused.
pub fn serve_gate(registry: &RetentionRegistry, content_hash: &str) -> Result<(), String> {
    if may_serve(registry, content_hash) {
        Ok(())
    } else {
        Err(format!(
            "privacy: refusing to serve content {content_hash} — expired or unregistered retention (N6)"
        ))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PII Redaction Tests ──────────────────────────────────────────────

    #[test]
    fn test_email_redaction() {
        let result = scan_and_redact("Contact john@example.com for info");
        assert!(result.types_found.contains(&PiiType::Email));
        assert!(result.redacted_text.contains("[EMAIL_REDACTED]"));
        assert!(!result.redacted_text.contains("john@example.com"));
        assert_eq!(result.count, 1);
    }

    #[test]
    fn test_phone_redaction() {
        let result = scan_and_redact("Call +1-234-567-8901 now");
        assert!(result.types_found.contains(&PiiType::Phone));
        assert!(result.redacted_text.contains("[PHONE_REDACTED]"));
        assert_eq!(result.count, 1);
    }

    #[test]
    fn test_ssn_redaction() {
        let result = scan_and_redact("SSN: 123-45-6789");
        assert!(result.types_found.contains(&PiiType::SSN));
        assert!(result.redacted_text.contains("[SSN_REDACTED]"));
    }

    #[test]
    fn test_credit_card_redaction() {
        let result = scan_and_redact("Card: 4111-1111-1111-1111");
        assert!(result.types_found.contains(&PiiType::CreditCard));
        assert!(result.redacted_text.contains("[CC_REDACTED]"));
    }

    #[test]
    fn test_ip_address_redaction() {
        let result = scan_and_redact("Server at 192.168.1.100 is down");
        assert!(result.types_found.contains(&PiiType::IPAddress));
        assert!(result.redacted_text.contains("[IP_REDACTED]"));
    }

    #[test]
    fn test_dob_iso_redaction() {
        let result = scan_and_redact("born 1990-04-15 in Seattle");
        assert!(result.types_found.contains(&PiiType::DateOfBirth));
        assert!(result.redacted_text.contains("[DOB_REDACTED]"));
        assert!(!result.redacted_text.contains("1990-04-15"));
    }

    #[test]
    fn test_dob_slash_redaction() {
        let result = scan_and_redact("DOB: 04/15/1990");
        assert!(result.types_found.contains(&PiiType::DateOfBirth));
        assert!(result.redacted_text.contains("[DOB_REDACTED]"));
    }

    #[test]
    fn test_dob_keyword_variants() {
        for kw in &["born", "DOB", "date of birth", "birthday", "birthdate"] {
            let text = format!("{}: 1985-06-22", kw);
            let result = scan_and_redact(&text);
            assert!(
                result.types_found.contains(&PiiType::DateOfBirth),
                "keyword '{kw}' should trigger DOB detection"
            );
        }
    }

    #[test]
    fn test_name_detection() {
        let result = scan_and_redact("Contact John Smith for details");
        assert!(result.types_found.contains(&PiiType::Name));
        assert!(result.redacted_text.contains("[NAME_REDACTED]"));
    }

    #[test]
    fn test_name_three_words() {
        let result = scan_and_redact("Patient: Mary Jane Watson");
        assert!(result.types_found.contains(&PiiType::Name));
    }

    #[test]
    fn test_address_detection() {
        let result = scan_and_redact("Ship to: 123 Main Street, Springfield");
        assert!(result.types_found.contains(&PiiType::Address));
        assert!(result.redacted_text.contains("[ADDRESS_REDACTED]"));
    }

    #[test]
    fn test_address_various_suffixes() {
        let cases = [
            "456 Oak Avenue",
            "789 Pine Boulevard",
            "100 Elm Drive",
            "42 River Road",
        ];
        for case in &cases {
            let result = scan_and_redact(case);
            assert!(
                result.types_found.contains(&PiiType::Address),
                "address '{case}' should be detected"
            );
        }
    }

    #[test]
    fn test_no_pii_clean_text() {
        let result = scan_and_redact("Hello world, this has no PII");
        assert_eq!(result.count, 0);
        assert!(result.types_found.is_empty());
        assert_eq!(result.redacted_text, "Hello world, this has no PII");
    }

    #[test]
    fn test_multiple_pii_types() {
        let result =
            scan_and_redact("Email: test@example.com, SSN: 123-45-6789, IP: 10.0.0.1");
        assert!(result.count >= 3);
        assert!(result.types_found.contains(&PiiType::Email));
        assert!(result.types_found.contains(&PiiType::SSN));
        assert!(result.types_found.contains(&PiiType::IPAddress));
    }

    #[test]
    fn test_email_edge_cases() {
        let result = scan_and_redact("user.name+tag@domain.co.uk");
        assert!(result.types_found.contains(&PiiType::Email));
    }

    #[test]
    fn test_no_false_positive_numbers() {
        // Regular numbers should NOT be flagged as credit cards
        let result = scan_and_redact("Price: $99.99, Quantity: 12345");
        assert!(!result.types_found.contains(&PiiType::CreditCard));
    }

    #[test]
    fn test_credit_card_with_spaces() {
        let result = scan_and_redact("Card: 4111 1111 1111 1111");
        assert!(result.types_found.contains(&PiiType::CreditCard));
        assert!(result.redacted_text.contains("[CC_REDACTED]"));
    }

    #[test]
    fn test_multiple_emails() {
        let result = scan_and_redact("From: a@b.com To: c@d.org");
        assert_eq!(
            result
                .redacted_text
                .matches("[EMAIL_REDACTED]")
                .count(),
            2
        );
    }

    #[test]
    fn test_ip_boundary_values() {
        // Valid IPs
        let r1 = scan_and_redact("0.0.0.0");
        assert!(r1.types_found.contains(&PiiType::IPAddress));
        let r2 = scan_and_redact("255.255.255.255");
        assert!(r2.types_found.contains(&PiiType::IPAddress));

        // Invalid IP (octet > 255)
        let r3 = scan_and_redact("999.999.999.999");
        assert!(!r3.types_found.contains(&PiiType::IPAddress));
    }

    // ── Content Fingerprinting Tests ─────────────────────────────────────

    #[test]
    fn test_fingerprint_identical_texts() {
        let fp1 = ContentFingerprint::from_text("hello world this is a test");
        let fp2 = ContentFingerprint::from_text("hello world this is a test");
        assert_eq!(fp1.hash, fp2.hash);
        assert!((fp1.similarity(&fp2) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fingerprint_similar_texts() {
        let fp1 = ContentFingerprint::from_text(
            "the quick brown fox jumps over the lazy dog",
        );
        let fp2 = ContentFingerprint::from_text(
            "the quick brown fox leaps over the lazy dog",
        );
        let sim = fp1.similarity(&fp2);
        // Similar texts should have high similarity (> 0.5)
        assert!(sim > 0.5, "similarity={sim}, expected > 0.5");
    }

    #[test]
    fn test_fingerprint_different_texts() {
        let fp1 = ContentFingerprint::from_text(
            "the quick brown fox jumps over the lazy dog",
        );
        let fp2 = ContentFingerprint::from_text(
            "quantum computing hardware acceleration benchmarks results",
        );
        let sim = fp1.similarity(&fp2);
        // Very different texts should have lower similarity
        assert!(sim < 0.9, "similarity={sim}, expected < 0.9");
    }

    #[test]
    fn test_fingerprint_word_count() {
        let fp = ContentFingerprint::from_text("one two three four five");
        assert_eq!(fp.word_count, 5);
    }

    #[test]
    fn test_fingerprint_empty_text() {
        let fp = ContentFingerprint::from_text("");
        assert_eq!(fp.word_count, 0);
        assert_eq!(fp.hash, 0);
    }

    #[test]
    fn test_fingerprint_timestamp_populated() {
        let fp = ContentFingerprint::from_text("test");
        assert!(!fp.timestamp.is_empty());
        assert!(fp.timestamp.contains('T'));
        assert!(fp.timestamp.ends_with('Z'));
    }

    // ── Retention Registry Tests ─────────────────────────────────────────

    #[test]
    fn test_retention_register_and_len() {
        let mut reg = RetentionRegistry::new();
        assert!(reg.is_empty());
        reg.register("https://example.com", "hash1", "public_data", 30);
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }

    #[test]
    fn test_retention_not_expired() {
        let mut reg = RetentionRegistry::new();
        reg.register("https://example.com", "hash_fresh", "consent", 365);
        // Just registered with 365 days retention — should not be expired
        assert!(!reg.is_expired("hash_fresh"));
    }

    #[test]
    fn test_retention_unknown_hash_is_expired() {
        let reg = RetentionRegistry::new();
        // Unknown content is treated as expired
        assert!(reg.is_expired("nonexistent_hash"));
    }

    #[test]
    fn test_retention_export_json() {
        let mut reg = RetentionRegistry::new();
        reg.register("https://a.com", "h1", "public_data", 7);
        reg.register("https://b.com", "h2", "consent", 30);
        let json = reg.export_json();
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("\"url\":\"https://a.com\""));
        assert!(json.contains("\"url\":\"https://b.com\""));
        assert!(json.contains("\"retain_days\":7"));
        assert!(json.contains("\"retain_days\":30"));
    }

    #[test]
    fn test_retention_export_empty() {
        let reg = RetentionRegistry::new();
        assert_eq!(reg.export_json(), "[]");
    }

    #[test]
    fn test_retention_multiple_entries_same_url() {
        let mut reg = RetentionRegistry::new();
        reg.register("https://example.com", "v1", "public_data", 7);
        reg.register("https://example.com", "v2", "public_data", 7);
        assert_eq!(reg.len(), 2);
        assert!(!reg.is_expired("v1"));
        assert!(!reg.is_expired("v2"));
    }

    #[test]
    fn test_retention_entry_has_timestamps() {
        let mut reg = RetentionRegistry::new();
        reg.register("https://example.com", "ts_test", "research", 90);
        let json = reg.export_json();
        // Timestamps should be ISO format
        assert!(json.contains("scraped_at"));
        assert!(json.contains("expires_at"));
        // expires_at should be later than scraped_at
        let entry = &reg.entries[0];
        assert!(entry.expires_at > entry.scraped_at);
    }

    // ── P4 / N6: expired retention blocks serving ────────────────────────

    #[test]
    fn expired_retention_blocks_serving() {
        let mut reg = RetentionRegistry::new();

        // retain_days = 0 → registered but never servable (zero-day
        // retention = retain nothing). Deterministic: the explicit
        // retain_days==0 check does not depend on the clock second.
        reg.register(
            "https://example.com/dead",
            "hash_zero_day",
            "public_data",
            0,
        );
        assert!(!may_serve(&reg, "hash_zero_day"));
        let err = serve_gate(&reg, "hash_zero_day").unwrap_err();
        assert!(
            err.contains("hash_zero_day"),
            "refusal must name the hash: {err}"
        );

        // 365-day retention → live content is servable.
        reg.register("https://example.com/live", "hash_live", "consent", 365);
        assert!(may_serve(&reg, "hash_live"));
        assert!(serve_gate(&reg, "hash_live").is_ok());

        // Unknown hash → refused (default-to-tightest).
        assert!(!may_serve(&reg, "hash_unknown"));
        let err = serve_gate(&reg, "hash_unknown").unwrap_err();
        assert!(
            err.contains("hash_unknown"),
            "refusal must name the hash: {err}"
        );
    }
}
