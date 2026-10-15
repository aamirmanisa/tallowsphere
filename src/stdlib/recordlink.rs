//! Standard library: `tallow.recordlink` — record linkage / entity resolution.
//!
//! Pure, offline primitives for deciding whether two records (person or
//! organization names plus optional US-style addresses) refer to the same
//! real-world entity. Used as the scoring/blocking core of research
//! pipelines that merge scraped directories, business registries, and
//! watchlists.
//!
//! # API
//! - `recordlink.normalize_name(s)`      — canonical lowercase, punctuation-stripped name
//! - `recordlink.name_key(s)`            — sorted unique tokens (permutation-invariant)
//! - `recordlink.jaro(a, b)`             — Jaro similarity in [0,1]
//! - `recordlink.jaro_winkler(a, b)`     — Jaro–Winkler similarity in [0,1]
//! - `recordlink.token_set(a, b)`        — token-set similarity in [0,1]
//! - `recordlink.jaccard(a, b)`          — token-set Jaccard in [0,1]
//! - `recordlink.soundex(s)`             — 4-char Soundex code
//! - `recordlink.block_key(name, addr)`  — coarse blocking key (Soundex + ZIP5)
//! - `recordlink.exact(a, b)`            — normalized exact-name equality
//! - `recordlink.name_similarity(a, b)`  — best of Jaro–Winkler / token-set
//! - `recordlink.address_similarity(a, b)` — address similarity in [0,1]
//! - `recordlink.score(name_a, addr_a, name_b, addr_b)` — full pairwise MatchResult

use super::StdlibResult;
use crate::interp::{type_name, Value};
use std::collections::HashSet;

// ── Normalization ──────────────────────────────────────────────────────

/// Lowercase a string and split on every non-alphanumeric character,
/// returning the cleaned words. Unicode-aware (works on `char`s, never
/// indexes raw bytes), so accented names do not panic the runtime.
fn words(s: &str) -> Vec<String> {
    let lower = s.to_lowercase();
    let spaced: String = lower
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    spaced.split_whitespace().map(|t| t.to_string()).collect()
}

/// Canonical name: lowercase, punctuation stripped, whitespace collapsed.
pub fn normalize_name(s: &str) -> String {
    words(s).join(" ")
}

/// Sorted, de-duplicated token set — permutation-invariant name key.
pub fn name_key(s: &str) -> String {
    let mut toks = words(s);
    toks.sort();
    toks.dedup();
    toks.join(" ")
}

// ── Similarity ─────────────────────────────────────────────────────────

/// Jaro similarity in [0,1]. 1.0 for identical strings, 0.0 when no
/// characters match within the sliding match window.
pub fn jaro(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    let ac: Vec<char> = a.chars().collect();
    let bc: Vec<char> = b.chars().collect();
    if ac.is_empty() || bc.is_empty() {
        return 0.0;
    }
    let window = (ac.len().max(bc.len()) / 2).saturating_sub(1);
    let mut a_m = vec![false; ac.len()];
    let mut b_m = vec![false; bc.len()];
    let mut matches = 0usize;
    for (i, ca) in ac.iter().enumerate() {
        let lo = i.saturating_sub(window);
        let hi = (i + window + 1).min(bc.len());
        for j in lo..hi {
            if !b_m[j] && bc[j] == *ca {
                a_m[i] = true;
                b_m[j] = true;
                matches += 1;
                break;
            }
        }
    }
    if matches == 0 {
        return 0.0;
    }
    // Count half-transpositions: matched chars that appear out of order.
    let mut transpositions = 0usize;
    let mut k = 0usize;
    for (i, matched) in a_m.iter().enumerate() {
        if *matched {
            while !b_m[k] {
                k += 1;
            }
            if ac[i] != bc[k] {
                transpositions += 1;
            }
            k += 1;
        }
    }
    let m = matches as f64;
    let t = transpositions as f64 / 2.0;
    (m / ac.len() as f64 + m / bc.len() as f64 + (m - t) / m) / 3.0
}

/// Jaro–Winkler similarity in [0,1]: Jaro boosted for a shared prefix of up
/// to four characters (scaling factor 0.1).
pub fn jaro_winkler(a: &str, b: &str) -> f64 {
    let j = jaro(a, b);
    let prefix = a
        .chars()
        .zip(b.chars())
        .take(4)
        .take_while(|(x, y)| x == y)
        .count() as f64;
    (j + prefix * 0.1 * (1.0 - j)).min(1.0)
}

/// Token-set similarity in [0,1]. Tokenizes both strings, sorts the
/// intersection, and scores it against each side's remaining tokens — so
/// reordered and partially-overlapping token bags still score highly.
/// Comparisons are whitespace-insensitive so word boundaries never
/// inflate the score of unrelated strings.
pub fn token_set(a: &str, b: &str) -> f64 {
    let mut at = words(a);
    let mut bt = words(b);
    at.sort();
    at.dedup();
    bt.sort();
    bt.dedup();
    if at.is_empty() && bt.is_empty() {
        return 1.0;
    }
    if at.is_empty() || bt.is_empty() {
        return 0.0;
    }
    let inter: Vec<String> = at
        .iter()
        .filter(|t| bt.contains(t))
        .cloned()
        .collect();
    if inter.is_empty() {
        return jw_no_space(&at.join(" "), &bt.join(" "));
    }
    let a_rem: Vec<String> = at.iter().filter(|t| !inter.contains(t)).cloned().collect();
    let b_rem: Vec<String> = bt.iter().filter(|t| !inter.contains(t)).cloned().collect();
    let i_join = inter.join(" ");
    let joined_a = if a_rem.is_empty() {
        i_join.clone()
    } else {
        format!("{i_join} {}", a_rem.join(" "))
    };
    let joined_b = if b_rem.is_empty() {
        i_join.clone()
    } else {
        format!("{i_join} {}", b_rem.join(" "))
    };
    let r_a = jw_no_space(&i_join, &joined_a);
    let r_b = jw_no_space(&i_join, &joined_b);
    r_a.max(r_b)
}

/// Jaro–Winkler over whitespace-stripped strings — word boundaries are
/// structure, not signal, for name/address similarity.
fn jw_no_space(a: &str, b: &str) -> f64 {
    let clean = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    jaro_winkler(&clean(a), &clean(b))
}

/// Jaccard index over the token sets, in [0,1]. Both empty → 1.0
/// (nothing to contradict); exactly one empty → 0.0.
pub fn jaccard(a: &str, b: &str) -> f64 {
    let at: HashSet<String> = words(a).into_iter().collect();
    let bt: HashSet<String> = words(b).into_iter().collect();
    if at.is_empty() && bt.is_empty() {
        return 1.0;
    }
    if at.is_empty() || bt.is_empty() {
        return 0.0;
    }
    let inter = at.intersection(&bt).count();
    let union = at.union(&bt).count();
    inter as f64 / union as f64
}

/// Best available name similarity in [0,1]: max(Jaro–Winkler, token-set)
/// over the normalized names. Both measures are whitespace-insensitive.
pub fn name_similarity(a: &str, b: &str) -> f64 {
    let na = normalize_name(a);
    let nb = normalize_name(b);
    if na.is_empty() || nb.is_empty() {
        return 0.0;
    }
    if na == nb {
        return 1.0;
    }
    jw_no_space(&na, &nb).max(token_set(&na, &nb))
}

// ── Address view (record-linkage strength only) ────────────────────────
//
// Full parsing lives in `tallow.geocode`; here we only need a canonical
// comparable form: lowercase, expanded street suffixes, canonicalized
// directionals, ZIP preserved, unit markers normalized.

const STREET_SUFFIXES: &[(&str, &str)] = &[
    ("st", "street"), ("str", "street"), ("street", "street"),
    ("ave", "avenue"), ("av", "avenue"), ("avenue", "avenue"),
    ("blvd", "boulevard"), ("boul", "boulevard"), ("boulevard", "boulevard"),
    ("rd", "road"), ("road", "road"),
    ("dr", "drive"), ("drv", "drive"), ("drive", "drive"),
    ("ln", "lane"), ("lane", "lane"),
    ("ct", "court"), ("crt", "court"), ("court", "court"),
    ("cir", "circle"), ("circ", "circle"), ("circle", "circle"),
    ("pkwy", "parkway"), ("parkway", "parkway"),
    ("hwy", "highway"), ("highway", "highway"),
    ("trl", "trail"), ("trail", "trail"),
    ("pl", "place"), ("place", "place"),
    ("sq", "square"), ("square", "square"),
    ("ter", "terrace"), ("terrace", "terrace"),
    ("expy", "expressway"), ("expressway", "expressway"),
    ("fwy", "freeway"), ("freeway", "freeway"),
    ("pky", "pike"), ("pike", "pike"),
    ("way", "way"),
];

const DIRECTIONALS: &[(&str, &str)] = &[
    ("north", "n"), ("n", "n"),
    ("south", "s"), ("s", "s"),
    ("east", "e"), ("e", "e"),
    ("west", "w"), ("w", "w"),
    ("northeast", "ne"), ("ne", "ne"),
    ("northwest", "nw"), ("nw", "nw"),
    ("southeast", "se"), ("se", "se"),
    ("southwest", "sw"), ("sw", "sw"),
];

fn expand_token(tok: &str) -> String {
    for (k, v) in STREET_SUFFIXES {
        if *k == tok {
            return v.to_string();
        }
    }
    for (k, v) in DIRECTIONALS {
        if *k == tok {
            return v.to_string();
        }
    }
    match tok {
        "apt" | "unit" | "suite" | "ste" | "#" => "apt".to_string(),
        _ => tok.to_string(),
    }
}

/// Canonical comparable address: "123 Main St #4" → "123 main street apt 4".
pub fn normalize_address(s: &str) -> String {
    // Keep '#' as its own token so unit numbers survive ("#4" → "# 4").
    let lower = s.to_lowercase().replace('#', " # ");
    let spaced: String = lower
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '#' { c } else { ' ' })
        .collect();
    let mut out: Vec<String> = Vec::new();
    for tok in spaced.split_whitespace() {
        let canon = expand_token(tok);
        // Collapse duplicate unit markers ("Apt #4" → "apt 4").
        if canon == "apt" && out.last().is_some_and(|p| p == "apt") {
            continue;
        }
        out.push(canon);
    }
    out.join(" ")
}

/// ZIP5 of a US address/string: the *last* run of 5+ consecutive digits
/// (house numbers precede the ZIP in address strings).
fn zip5_of(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut best: Option<String> = None;
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let run: String = chars[start..i].iter().collect();
            if run.len() >= 5 {
                best = Some(run[..5].to_string());
            }
        } else {
            i += 1;
        }
    }
    best
}

/// Address similarity in [0,1] over canonical forms. Two blank addresses
/// score 0.5 (neutral — no evidence either way); one blank scores 0.0.
pub fn address_similarity(a: &str, b: &str) -> f64 {
    let na = normalize_address(a);
    let nb = normalize_address(b);
    if na.is_empty() && nb.is_empty() {
        return 0.5;
    }
    if na.is_empty() || nb.is_empty() {
        return 0.0;
    }
    if na == nb {
        return 1.0;
    }
    jw_no_space(&na, &nb).max(token_set(&na, &nb))
}

// ── Soundex / blocking ─────────────────────────────────────────────────

fn soundex_code(c: char) -> char {
    match c.to_ascii_uppercase() {
        'B' | 'F' | 'P' | 'V' => '1',
        'C' | 'G' | 'J' | 'K' | 'Q' | 'S' | 'X' | 'Z' => '2',
        'D' | 'T' => '3',
        'L' => '4',
        'M' | 'N' => '5',
        'R' => '6',
        _ => '0',
    }
}

fn is_vowel(c: char) -> bool {
    matches!(c.to_ascii_uppercase(), 'A' | 'E' | 'I' | 'O' | 'U' | 'Y')
}

/// Classic 4-character Soundex code ("Miller" → "M460").
pub fn soundex(s: &str) -> String {
    let mut out = String::new();
    let mut last = '0';
    for (i, c) in s.chars().enumerate() {
        if !c.is_alphabetic() {
            continue;
        }
        if i == 0 {
            out.push(c.to_ascii_uppercase());
            last = soundex_code(c); // initial letter's code suppresses its own duplicate
            continue;
        }
        let code = soundex_code(c);
        if code == '0' {
            if is_vowel(c) {
                last = '0'; // vowel separates repeated codes
            }
            // H/W keep `last` so identical codes on either side collapse
        } else if code != last {
            if out.len() < 4 {
                out.push(code);
            }
            last = code;
        }
    }
    while out.len() < 4 {
        out.push('0');
    }
    out
}

/// Coarse blocking key for grouping candidate duplicates before pairwise
/// scoring: Soundex of the first name token + ZIP5 of the address.
/// Deliberately over-inclusive ("Acme Corp" and "Acme Corporation" share
/// the first-token Soundex) — precision is recovered by `score`.
pub fn block_key(name: &str, address: &str) -> String {
    let first = words(name).into_iter().next().unwrap_or_default();
    let code = soundex(&first);
    let zip = zip5_of(address).unwrap_or_default();
    format!("{code}|{zip}")
}

/// Normalized exact-equality test for names.
pub fn exact(a: &str, b: &str) -> bool {
    let na = normalize_name(a);
    !na.is_empty() && na == normalize_name(b)
}

// ── Pairwise scoring ───────────────────────────────────────────────────

/// Full pairwise record score with a Fellegi–Sunter-style weighted
/// combination (0.7 name / 0.3 address) and human verdict thresholds.
pub fn score_pair(name_a: &str, addr_a: &str, name_b: &str, addr_b: &str) -> (f64, f64, f64, String, String) {
    let na = normalize_name(name_a);
    let nb = normalize_name(name_b);
    let name_exact = exact(name_a, name_b);
    let name_sim = if name_exact {
        1.0
    } else if na.is_empty() || nb.is_empty() {
        0.0
    } else {
        name_similarity(&na, &nb)
    };
    let aa = normalize_address(addr_a);
    let ab = normalize_address(addr_b);
    let addr_exact = !aa.is_empty() && aa == ab;
    let addr_sim = if addr_exact {
        1.0
    } else if aa.is_empty() && ab.is_empty() {
        0.5
    } else if aa.is_empty() || ab.is_empty() {
        0.0
    } else {
        address_similarity(&aa, &ab)
    };

    // Strongest signal, for downstream audit trails.
    let best_signal = if name_exact {
        "exact_name"
    } else if addr_exact {
        "exact_address"
    } else if name_sim > addr_sim {
        "name_similarity"
    } else {
        "address_similarity"
    };

    let combined = 0.7 * name_sim + 0.3 * addr_sim;
    let verdict = if name_exact && (addr_exact || (aa.is_empty() && ab.is_empty())) {
        "match"
    } else if combined >= 0.90 {
        "match"
    } else if combined >= 0.78 {
        "probable"
    } else if combined >= 0.62 {
        "possible"
    } else if combined >= 0.40 {
        "weak"
    } else {
        "no"
    };
    (name_sim, addr_sim, combined, verdict.to_string(), best_signal.to_string())
}

// ── Dispatch ───────────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "normalize_name" => Some(unary_str(args, "normalize_name", normalize_name)),
        "name_key" => Some(unary_str(args, "name_key", name_key)),
        "soundex" => Some(unary_str(args, "soundex", soundex)),
        "jaro" => Some(binary_str(args, "jaro", jaro)),
        "jaro_winkler" => Some(binary_str(args, "jaro_winkler", jaro_winkler)),
        "token_set" => Some(binary_str(args, "token_set", token_set)),
        "jaccard" => Some(binary_str(args, "jaccard", jaccard)),
        "name_similarity" => Some(binary_str(args, "name_similarity", name_similarity)),
        "address_similarity" => Some(binary_str(args, "address_similarity", address_similarity)),
        "exact" => Some(exact_dispatch(args)),
        "block_key" => Some(block_key_dispatch(args)),
        "score" => Some(score_dispatch(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(
        function,
        "normalize_name"
            | "name_key"
            | "soundex"
            | "jaro"
            | "jaro_winkler"
            | "token_set"
            | "jaccard"
            | "name_similarity"
            | "address_similarity"
            | "exact"
            | "block_key"
            | "score"
    )
}

fn str_arg<'a>(args: &'a [Value], idx: usize, fname: &str) -> Result<&'a str, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(other) => Err(format!(
            "{fname}: argument {} expected String, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("{fname}: missing argument {}", idx + 1)),
    }
}

fn unary_str(args: Vec<Value>, fname: &str, f: fn(&str) -> String) -> StdlibResult {
    let a = str_arg(&args, 0, fname)?;
    Ok(Value::String(f(a)))
}

fn binary_str(args: Vec<Value>, fname: &str, f: fn(&str, &str) -> f64) -> StdlibResult {
    let a = str_arg(&args, 0, fname)?;
    let b = str_arg(&args, 1, fname)?;
    Ok(Value::Float(f(a, b)))
}

fn exact_dispatch(args: Vec<Value>) -> StdlibResult {
    let a = str_arg(&args, 0, "exact")?;
    let b = str_arg(&args, 1, "exact")?;
    Ok(Value::Bool(exact(a, b)))
}

fn block_key_dispatch(args: Vec<Value>) -> StdlibResult {
    let name = str_arg(&args, 0, "block_key")?;
    let address = str_arg(&args, 1, "block_key")?;
    Ok(Value::String(block_key(name, address)))
}

fn score_dispatch(args: Vec<Value>) -> StdlibResult {
    let na = str_arg(&args, 0, "score")?;
    let aa = str_arg(&args, 1, "score")?;
    let nb = str_arg(&args, 2, "score")?;
    let ab = str_arg(&args, 3, "score")?;
    let (name_score, addr_score, combined, verdict, best_signal) = score_pair(na, aa, nb, ab);
    Ok(Value::Struct {
        name: "MatchResult".into(),
        fields: vec![
            ("name_score".into(), Value::Float(name_score)),
            ("addr_score".into(), Value::Float(addr_score)),
            ("combined".into(), Value::Float(combined)),
            ("verdict".into(), Value::String(verdict)),
            ("best_signal".into(), Value::String(best_signal)),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-6
    }

    #[test]
    fn jaro_winkler_known_pairs() {
        // Canonical test vectors from the Jaro–Winkler literature.
        assert!(close(jaro_winkler("martha", "marhta"), 0.9611111111111111));
        assert!(close(jaro_winkler("dwayne", "duane"), 0.84));
        assert!(close(jaro_winkler("dixon", "dicksonx"), 0.8133333333333332));
        assert!(close(jaro("martha", "marhta"), 0.9444444444444445));
        assert!(close(jaro("dixon", "dicksonx"), 0.7666666666666666));
    }

    #[test]
    fn jaro_winkler_bounds() {
        assert_eq!(jaro_winkler("Acme Corp", "Acme Corp"), 1.0);
        assert_eq!(jaro_winkler("", "anything"), 0.0);
        assert_eq!(jaro_winkler("a", "b"), 0.0);
        // Same length, single substitution far from prefix: jw ≈ 0.8889.
        assert!(jaro_winkler("kitten", "sitten") > 0.85);
        // Boosting must never exceed 1.0.
        assert!(jaro_winkler("abcde", "abcdx") <= 1.0);
    }

    #[test]
    fn normalize_and_keys() {
        assert_eq!(normalize_name("Acme Corporation, Inc."), "acme corporation inc");
        assert_eq!(normalize_name("  O'Reilly  & Sons  "), "o reilly sons");
        // name_key is permutation-invariant.
        assert_eq!(name_key("Acme Corporation"), name_key("Corporation Acme"));
        assert_ne!(name_key("Acme Corp"), name_key("Acme Corporation"));
    }

    #[test]
    fn soundex_vectors() {
        assert_eq!(soundex("Miller"), "M460");
        assert_eq!(soundex("Robert"), "R163");
        assert_eq!(soundex("Rupert"), "R163"); // classic collision
        assert_eq!(soundex("Ashcraft"), "A261");
        assert_eq!(soundex("Tymczak"), "T522");
        assert_eq!(soundex("Pfister"), "P236");
        assert_eq!(soundex(""), "0000");
    }

    #[test]
    fn token_set_and_jaccard() {
        // Reordered + missing token still scores high.
        let s = token_set("Acme Corporation Inc", "Corporation Acme");
        assert!(s > 0.8, "token_set scored {s}");
        // Shared subset dominates when one side is a suffix-laden variant.
        let s2 = token_set("Main Street Market", "Main Street Market LLC");
        assert!(s2 > 0.9, "token_set scored {s2}");
        assert!(close(jaccard("a b c", "a b d"), 0.5));
        assert_eq!(jaccard("", ""), 1.0);
        assert_eq!(jaccard("x", ""), 0.0);
        assert!(jaccard("a b", "b a") > 0.99);
    }

    #[test]
    fn address_normalization_makes_variants_equal() {
        assert_eq!(
            normalize_address("123 Main St"),
            normalize_address("123 MAIN STREET")
        );
        assert_eq!(
            normalize_address("4500 Parmer Ln, Apt #4"),
            normalize_address("4500 parmer lane apt 4")
        );
        // Directional canonicalization.
        assert_eq!(
            normalize_address("1600 Pennsylvania Ave NW"),
            "1600 pennsylvania avenue nw"
        );
    }

    #[test]
    fn address_similarity_neutral_on_blanks() {
        assert!(close(address_similarity("", ""), 0.5));
        assert!(close(address_similarity("123 Main St", ""), 0.0));
        assert!(close(address_similarity("123 Main St", "123 Main Street"), 1.0));
    }

    #[test]
    fn block_key_groups_suffix_variants() {
        // First-token Soundex of "Acme" collides across suffix variants.
        assert_eq!(block_key("Acme Corp", "123 Main St Austin TX 78701"), "A250|78701");
        assert_eq!(
            block_key("Acme Corporation", "123 Main Street Austin Texas 78701"),
            "A250|78701"
        );
        assert_ne!(block_key("Zebra LLC", ""), block_key("Acme LLC", ""));
    }

    #[test]
    fn exact_matches_normalized_equality() {
        assert!(exact("Acme Corp", "ACME CORP"));
        assert!(!exact("Acme Corp", "Acme Corporation"));
        assert!(!exact("", ""));
    }

    #[test]
    fn score_verdicts() {
        // Identical records → match.
        let (ns, as_, c, v, sig) = score_pair(
            "Acme Corporation",
            "123 Main St Austin TX 78701",
            "ACME CORP",
            "123 Main Street Austin, TX 78701",
        );
        assert_eq!(v, "match");
        assert_eq!(sig, "exact_address");
        assert!(ns > 0.9 && as_ == 1.0 && c > 0.9);

        // Entirely different entities → no.
        let (_, _, _, v2, _) = score_pair("Acme Corp", "", "Zzzz Qqq", "");
        assert_eq!(v2, "no");

        // Transposed tokens + same street → probable/possible territory.
        let (_, _, c3, v3, _) = score_pair("Smith Jane M", "88 Oak Dr", "Jane Smith", "88 Oak Drive");
        assert!(v3 == "match" || v3 == "probable" || v3 == "possible");
        assert!(c3 > 0.7, "combined {c3}");
    }

    #[test]
    fn dispatch_routes() {
        let r = dispatch("normalize_name", vec![Value::String("  Acme Corp. ".into())]);
        assert!(matches!(r.unwrap().unwrap(), Value::String(s) if s == "acme corp"));
        let r = dispatch("score", vec![
            Value::String("Acme".into()),
            Value::String("".into()),
            Value::String("Acme".into()),
            Value::String("".into()),
        ]);
        match r.unwrap().unwrap() {
            Value::Struct { name, fields } => {
                assert_eq!(name, "MatchResult");
                let verdict = fields.iter().find(|(k, _)| k == "verdict").unwrap().1.clone();
                assert!(matches!(verdict, Value::String(s) if s == "match"));
            }
            other => panic!("expected MatchResult struct, got {:?}", type_name(&other)),
        }
        // Wrong arity → honest Err, not panic.
        let r = dispatch("score", vec![Value::String("a".into())]);
        assert!(r.unwrap().is_err());
        // Unknown function → None.
        assert!(dispatch("not_a_function", vec![]).is_none());
    }

    #[test]
    fn interp_end_to_end() {
        // Full lex→parse→interpret path, proving module-namespace routing
        // (bare `recordlink` ident → __module_recordlink__ → dispatch).
        let src = r#"
        fn main() {
            let m = recordlink.score("Acme Corporation", "123 Main St Austin TX 78701", "ACME CORP", "123 Main Street Austin TX 78701")
            print(m.verdict)
            print(m.combined.to_string())
            print(recordlink.soundex("Miller"))
            print(recordlink.jaro_winkler("martha", "marhta").to_string())
        }
        "#;
        let (tokens, lex_errs) = crate::lexer::tokenize(src);
        assert!(lex_errs.is_empty(), "lex errors: {lex_errs:?}");
        let program = crate::parser::Parser::parse(tokens).expect("parse error");
        let mut interp = crate::interp::Interpreter::new();
        interp.run(&program).expect("interp run failed");
        assert_eq!(interp.output[0], "match");
        assert_eq!(interp.output[2], "M460");
        let jw: f64 = interp.output[3].parse().unwrap();
        // The interpreter's float formatter is C-compatible `%g` at 6 SIGNIFICANT
        // digits (`format_float_c`, P = 6), so a float round-tripped through
        // printed output cannot carry more precision than that. The previous
        // 1e-9 tolerance demanded 16 significant digits from a 6-digit string and
        // was unachievable by construction — it was never a jaro_winkler defect.
        assert!((jw - 0.961111).abs() < 1e-6, "got {jw}");
        // Pin the formatter contract this test's tolerance is derived from, so a
        // precision change to format_float_c fails here loudly instead of
        // silently loosening what the tolerance above actually proves.
        assert_eq!(interp.output[3], "0.961111", "6-significant-digit %g");
    }
}
