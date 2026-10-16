//! Standard library: `tallow.geocode` — offline address normalization and
//! geocode-style join keys.
//!
//! Pure, offline US-address utilities for research pipelines that must join
//! or deduplicate records across sources without a geocoding service:
//! canonical street/state expansion, house-number + street + ZIP5 parse
//! keys, ZIP validation, and state name ⇄ abbreviation lookup.
//!
//! # API
//! - `geocode.normalize_address(addr)` — canonical form ("123 Main St #4" → "123 main street apt 4")
//! - `geocode.parse_address(addr)`     — GeoParts { house, street, city, state, zip }
//! - `geocode.address_key(addr)`       — "house|street|zip" join key
//! - `geocode.join_key(house, street, zip)` — explicit join key from parts
//! - `geocode.zip5(s)`                 — first 5-digit run, else ""
//! - `geocode.is_zip5(s)`              — valid 5-digit (or ZIP+4) check
//! - `geocode.state_from_name(name)`   — "Texas" → "TX", "" if unknown
//! - `geocode.state_from_abbrev(abbrev)` — "TX" → "Texas", "" if unknown

use super::StdlibResult;
use crate::interp::{type_name, Value};

// ── Static tables ──────────────────────────────────────────────────────

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
    ("byp", "bypass"), ("bypass", "bypass"),
    ("br", "bridge"), ("bridge", "bridge"),
    ("cswy", "causeway"), ("causeway", "causeway"),
    ("plz", "plaza"), ("plaza", "plaza"),
    ("cres", "crescent"), ("crescent", "crescent"),
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

/// Street-suffix vocabulary — a token that IS a suffix (either spelling).
fn is_street_suffix(tok: &str) -> bool {
    STREET_SUFFIXES.iter().any(|(k, _)| *k == tok)
}

/// Unit keywords that terminate the street portion.
fn is_unit_keyword(tok: &str) -> bool {
    matches!(
        tok,
        "apt" | "unit" | "suite" | "ste" | "rm" | "bldg" | "fl" | "floor" | "#"
    )
}

/// Expand a street suffix / directional token to its canonical spelling.
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
    tok.to_string()
}

const STATE_NAMES: &[(&str, &str)] = &[
    ("alabama", "AL"), ("alaska", "AK"), ("arizona", "AZ"), ("arkansas", "AR"),
    ("california", "CA"), ("colorado", "CO"), ("connecticut", "CT"),
    ("delaware", "DE"), ("district of columbia", "DC"), ("florida", "FL"),
    ("georgia", "GA"), ("hawaii", "HI"), ("idaho", "ID"), ("illinois", "IL"),
    ("indiana", "IN"), ("iowa", "IA"), ("kansas", "KS"), ("kentucky", "KY"),
    ("louisiana", "LA"), ("maine", "ME"), ("maryland", "MD"),
    ("massachusetts", "MA"), ("michigan", "MI"), ("minnesota", "MN"),
    ("mississippi", "MS"), ("missouri", "MO"), ("montana", "MT"),
    ("nebraska", "NE"), ("nevada", "NV"), ("new hampshire", "NH"),
    ("new jersey", "NJ"), ("new mexico", "NM"), ("new york", "NY"),
    ("north carolina", "NC"), ("north dakota", "ND"), ("ohio", "OH"),
    ("oklahoma", "OK"), ("oregon", "OR"), ("pennsylvania", "PA"),
    ("rhode island", "RI"), ("south carolina", "SC"), ("south dakota", "SD"),
    ("tennessee", "TN"), ("texas", "TX"), ("utah", "UT"), ("vermont", "VT"),
    ("virginia", "VA"), ("washington", "WA"), ("west virginia", "WV"),
    ("wisconsin", "WI"), ("wyoming", "WY"),
    ("puerto rico", "PR"), ("guam", "GU"), ("virgin islands", "VI"),
    ("american samoa", "AS"), ("northern mariana islands", "MP"),
];

const STATE_ABBREVS: &[(&str, &str)] = &[
    ("al", "Alabama"), ("ak", "Alaska"), ("az", "Arizona"), ("ar", "Arkansas"),
    ("ca", "California"), ("co", "Colorado"), ("ct", "Connecticut"),
    ("de", "Delaware"), ("dc", "District of Columbia"), ("fl", "Florida"),
    ("ga", "Georgia"), ("hi", "Hawaii"), ("id", "Idaho"), ("il", "Illinois"),
    ("in", "Indiana"), ("ia", "Iowa"), ("ks", "Kansas"), ("ky", "Kentucky"),
    ("la", "Louisiana"), ("me", "Maine"), ("md", "Maryland"),
    ("ma", "Massachusetts"), ("mi", "Michigan"), ("mn", "Minnesota"),
    ("ms", "Mississippi"), ("mo", "Missouri"), ("mt", "Montana"),
    ("ne", "Nebraska"), ("nv", "Nevada"), ("nh", "New Hampshire"),
    ("nj", "New Jersey"), ("nm", "New Mexico"), ("ny", "New York"),
    ("nc", "North Carolina"), ("nd", "North Dakota"), ("oh", "Ohio"),
    ("ok", "Oklahoma"), ("or", "Oregon"), ("pa", "Pennsylvania"),
    ("ri", "Rhode Island"), ("sc", "South Carolina"), ("sd", "South Dakota"),
    ("tn", "Tennessee"), ("tx", "Texas"), ("ut", "Utah"), ("vt", "Vermont"),
    ("va", "Virginia"), ("wa", "Washington"), ("wv", "West Virginia"),
    ("wi", "Wisconsin"), ("wy", "Wyoming"),
    ("pr", "Puerto Rico"), ("gu", "Guam"), ("vi", "Virgin Islands"),
    ("as", "American Samoa"), ("mp", "Northern Mariana Islands"),
];

fn state_abbrev_of_name(name: &str) -> Option<String> {
    let key = name.trim().to_lowercase();
    STATE_NAMES
        .iter()
        .find(|(n, _)| *n == key)
        .map(|(_, ab)| ab.to_string())
}

fn state_name_of_abbrev(abbrev: &str) -> Option<String> {
    let key = abbrev.trim().to_lowercase();
    STATE_ABBREVS
        .iter()
        .find(|(a, _)| *a == key)
        .map(|(_, name)| name.to_string())
}

// ── Tokenization ───────────────────────────────────────────────────────

/// Unicode-safe word split; '#' is kept as its own token so "#4" survives
/// as a unit marker ("… st # 4").
fn address_tokens(s: &str) -> Vec<String> {
    let lower = s.to_lowercase().replace('#', " # ");
    let spaced: String = lower
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '#' { c } else { ' ' })
        .collect();
    spaced.split_whitespace().map(|t| t.to_string()).collect()
}

fn is_zip5_token(tok: &str) -> bool {
    tok.len() == 5 && tok.chars().all(|c| c.is_ascii_digit())
}

fn is_zip4_token(tok: &str) -> bool {
    tok.len() == 4 && tok.chars().all(|c| c.is_ascii_digit())
}

fn starts_with_digit(tok: &str) -> bool {
    tok.chars().next().is_some_and(|c| c.is_ascii_digit())
}

// ── Public primitives ──────────────────────────────────────────────────

/// ZIP5 of a string: the *last* run of 5+ consecutive digits — in a full
/// US address the house number precedes the ZIP, so "first run" would
/// wrongly return digits from the house number. "" if none.
pub fn zip5(s: &str) -> String {
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
    best.unwrap_or_default()
}

/// True when the trimmed input is exactly 5 digits or ZIP+4 ("78701-1234").
pub fn is_zip5(s: &str) -> bool {
    let t = s.trim();
    if let Some(idx) = t.find('-') {
        let (a, b) = t.split_at(idx);
        let b = &b[1..];
        return a.len() == 5
            && a.chars().all(|c| c.is_ascii_digit())
            && b.len() == 4
            && b.chars().all(|c| c.is_ascii_digit());
    }
    t.len() == 5 && t.chars().all(|c| c.is_ascii_digit())
}

/// Canonical full-address form with expanded suffixes and directionals:
/// "123 Main St #4" → "123 main street apt 4".
pub fn normalize_address(addr: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for tok in address_tokens(addr) {
        let canon = if is_unit_keyword(&tok) {
            "apt".to_string()
        } else {
            expand_token(&tok)
        };
        // Collapse duplicate unit markers ("Apt #4" → "apt 4").
        if canon == "apt" && out.last().is_some_and(|p| p == "apt") {
            continue;
        }
        out.push(canon);
    }
    out.join(" ")
}

/// Split a US-format address into parts. Deterministic heuristic:
/// ZIP5 and state (abbrev or full name) are located first; the house
/// number is the first digit-leading token; the street runs from there to
/// the first unit keyword or (when the street has a suffix) to that suffix;
/// the remainder before the state is the city. Streets without a suffix
/// token assume a one-word city — multi-word cities need the suffix.
pub fn parse_address(addr: &str) -> (String, String, String, String, String) {
    let mut toks = address_tokens(addr);

    // 1. ZIP5 (and optional ZIP+4 tail).
    let mut zip = String::new();
    if let Some(zi) = toks.iter().position(|t| is_zip5_token(t)) {
        zip = toks[zi].clone();
        toks.remove(zi);
        if zi < toks.len() && is_zip4_token(&toks[zi]) {
            toks.remove(zi);
        }
    }

    // 2. State — last state-like token (abbrev or full name).
    let mut state = String::new();
    let mut state_idx = None;
    for (i, t) in toks.iter().enumerate() {
        if let Some(ab) = state_abbrev_of_name(t) {
            state_idx = Some(i);
            state = ab;
        } else if let Some(name) = state_name_of_abbrev(t) {
            // 2-letter abbrev that is also a state
            state_idx = Some(i);
            let _ = name;
            state = t.to_uppercase();
        }
    }
    if let Some(si) = state_idx {
        toks.remove(si);
    }

    // 3. House number: first digit-leading token that is not an apt number.
    let mut house = String::new();
    let mut house_idx = None;
    for (i, t) in toks.iter().enumerate() {
        if starts_with_digit(t) {
            let after_unit = i > 0 && is_unit_keyword(&toks[i - 1]);
            if !after_unit {
                house = t.clone();
                house_idx = Some(i);
                break;
            }
        }
    }

    // 4. Unit keyword location.
    let unit_idx = toks.iter().position(|t| is_unit_keyword(t));

    // 5. Street end.
    let start = house_idx.map_or(0, |h| h + 1);
    let street_end = if let Some(u) = unit_idx {
        u
    } else {
        // Extend past the last street-suffix token (and following directionals).
        let mut end = toks.len();
        let mut last_suffix = None;
        for (i, t) in toks.iter().enumerate().skip(start) {
            if is_street_suffix(t) {
                last_suffix = Some(i);
            }
        }
        if let Some(ls) = last_suffix {
            end = ls + 1;
            // Directionals after the suffix belong to the street
            // ("1600 pennsylvania ave nw").
            let mut k = end;
            while k < toks.len() && DIRECTIONALS.iter().any(|(d, _)| *d == toks[k]) {
                end = k + 1;
                k += 1;
            }
            // If a state name sat exactly at `end`+1.. we already removed it;
            // tokens between street end and where state was are the city.
            let _ = k;
            end
        } else if house_idx.is_some() && toks.len() > start + 1 {
            // No suffix: assume the street runs to the last token before the
            // final city word (single-word-city heuristic).
            toks.len() - 1
        } else {
            end
        }
    };

    let street: Vec<String> = toks[start..street_end.min(toks.len())].to_vec();
    let mut city_start = street_end;
    if let Some(u) = unit_idx {
        if u >= start && u < toks.len() {
            city_start = u + 1;
            // Skip the unit number and any further unit markers ("apt # 4").
            while city_start < toks.len()
                && (toks[city_start] == "#"
                    || starts_with_digit(&toks[city_start])
                    || is_unit_keyword(&toks[city_start]))
            {
                city_start += 1;
            }
        }
    }
    let city: Vec<String> = if city_start < toks.len() {
        toks[city_start..].to_vec()
    } else {
        vec![]
    };

    (
        house,
        street.join(" "),
        city.join(" "),
        state,
        zip,
    )
}

/// "house|street|zip" join key from a raw address; the street is
/// canonicalized (suffix/directional expansion) exactly like `join_key`.
/// Falls back to the normalized full address when no house or street is
/// present.
pub fn address_key(addr: &str) -> String {
    let (house, street, _city, _state, zip) = parse_address(addr);
    if house.is_empty() || street.is_empty() {
        return normalize_address(addr);
    }
    let street_norm: Vec<String> = street
        .split_whitespace()
        .map(|t| {
            if is_unit_keyword(t) {
                "apt".to_string()
            } else {
                expand_token(t)
            }
        })
        .collect();
    format!("{house}|{}|{zip}", street_norm.join(" "))
}

/// Explicit "house|street|zip" join key built from user-supplied parts.
/// The street is normalized (suffix/directional expansion) and the ZIP is
/// reduced to ZIP5, so variants of the same address collapse to one key.
pub fn join_key(house: &str, street: &str, zip: &str) -> String {
    let mut house_clean = String::new();
    for c in house.trim().chars() {
        if c.is_ascii_digit() {
            house_clean.push(c);
        } else if c.is_ascii_alphabetic() && !house_clean.is_empty() {
            house_clean.push(c.to_ascii_lowercase());
            break; // "12a" — keep one suffix letter
        } else if house_clean.is_empty() {
            continue;
        } else {
            break;
        }
    }
    let street_norm = address_tokens(street)
        .into_iter()
        .map(|t| expand_token(&t))
        .filter(|t| !is_unit_keyword(t) && !starts_with_digit(t))
        .collect::<Vec<_>>()
        .join(" ");
    let z = zip5(zip);
    format!("{house_clean}|{street_norm}|{z}")
}

// ── Dispatch ───────────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "normalize_address" => Some(addr_unary(args, normalize_address)),
        "parse_address" => Some(parse_dispatch(args)),
        "address_key" => Some(addr_unary(args, address_key)),
        "join_key" => Some(join_key_dispatch(args)),
        "zip5" => Some(addr_unary(args, zip5)),
        "is_zip5" => Some(is_zip5_dispatch(args)),
        "state_from_name" => Some(state_lookup(args, "state_from_name", state_abbrev_of_name)),
        "state_from_abbrev" => Some(state_lookup(args, "state_from_abbrev", state_name_of_abbrev)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(
        function,
        "normalize_address"
            | "parse_address"
            | "address_key"
            | "join_key"
            | "zip5"
            | "is_zip5"
            | "state_from_name"
            | "state_from_abbrev"
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

fn addr_unary(args: Vec<Value>, f: fn(&str) -> String) -> StdlibResult {
    let a = str_arg(&args, 0, "address")?;
    Ok(Value::String(f(a)))
}

fn is_zip5_dispatch(args: Vec<Value>) -> StdlibResult {
    let a = str_arg(&args, 0, "is_zip5")?;
    Ok(Value::Bool(is_zip5(a)))
}

fn state_lookup(args: Vec<Value>, fname: &str, f: fn(&str) -> Option<String>) -> StdlibResult {
    let a = str_arg(&args, 0, fname)?;
    Ok(Value::String(f(a).unwrap_or_default()))
}

fn parse_dispatch(args: Vec<Value>) -> StdlibResult {
    let a = str_arg(&args, 0, "parse_address")?;
    let (house, street, city, state, zip) = parse_address(a);
    Ok(Value::Struct {
        name: "GeoParts".into(),
        fields: vec![
            ("house".into(), Value::String(house)),
            ("street".into(), Value::String(street)),
            ("city".into(), Value::String(city)),
            ("state".into(), Value::String(state)),
            ("zip".into(), Value::String(zip)),
        ],
    })
}

fn join_key_dispatch(args: Vec<Value>) -> StdlibResult {
    let house = str_arg(&args, 0, "join_key")?;
    let street = str_arg(&args, 1, "join_key")?;
    let zip = str_arg(&args, 2, "join_key")?;
    Ok(Value::String(join_key(house, street, zip)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_expands_and_collapses() {
        assert_eq!(
            normalize_address("123 Main St, Austin TX 78701"),
            "123 main street austin tx 78701"
        );
        assert_eq!(
            normalize_address("4500 PARMER LN #4"),
            "4500 parmer lane apt 4"
        );
        assert_eq!(
            normalize_address("1600 Pennsylvania Ave NW"),
            "1600 pennsylvania avenue nw"
        );
        assert_eq!(normalize_address("1 Infinite Loop"), "1 infinite loop");
    }

    #[test]
    fn zip_utilities() {
        assert_eq!(zip5("Austin TX 78701"), "78701");
        assert_eq!(zip5("78701-1234"), "78701");
        assert_eq!(zip5("no zip here"), "");
        assert_eq!(zip5("12"), "");
        // House numbers precede the ZIP — the ZIP is the LAST 5+ digit run.
        assert_eq!(zip5("123 Main St Austin TX 78701"), "78701");
        assert_eq!(zip5("4500 Parmer Ln Austin TX 78727"), "78727");
        assert!(is_zip5("78701"));
        assert!(is_zip5(" 78701 "));
        assert!(is_zip5("78701-1234"));
        assert!(!is_zip5("7870"));
        assert!(!is_zip5("787011"));
        assert!(!is_zip5("abcde"));
    }

    #[test]
    fn parse_full_addresses() {
        // Suffix-delimited street + single-word city.
        let (h, s, c, st, z) = parse_address("123 Main St Austin TX 78701");
        assert_eq!((h.as_str(), s.as_str(), c.as_str(), st.as_str(), z.as_str()), ("123", "main st", "austin", "TX", "78701"));
        // Full state name.
        let (h, s, c, st, z) = parse_address("4500 Parmer Ln, Austin, Texas 78727");
        assert_eq!((h.as_str(), s.as_str(), c.as_str(), st.as_str(), z.as_str()), ("4500", "parmer ln", "austin", "TX", "78727"));
        // Directional after suffix stays in street.
        let (h, s, c, st, z) = parse_address("1600 Pennsylvania Ave NW Washington DC 20500");
        assert_eq!((h.as_str(), s.as_str(), c.as_str(), st.as_str(), z.as_str()), ("1600", "pennsylvania ave nw", "washington", "DC", "20500"));
        // No suffix token → one-word city heuristic.
        let (h, s, c, st, z) = parse_address("1 Infinite Loop Cupertino CA 95014");
        assert_eq!((h.as_str(), s.as_str(), c.as_str(), st.as_str(), z.as_str()), ("1", "infinite loop", "cupertino", "CA", "95014"));
        // Unit number is excluded from street and city.
        let (h, s, c, st, z) = parse_address("88 Oak Dr Apt 12 Springfield IL 62701");
        assert_eq!((h.as_str(), s.as_str(), c.as_str(), st.as_str(), z.as_str()), ("88", "oak dr", "springfield", "IL", "62701"));
        // ZIP+4.
        let (h, _s, _c, _st, z) = parse_address("123 Main St Austin TX 78701-1234");
        assert_eq!(z, "78701");
        // No house number → house empty, street starts at token 0.
        let (h, s, _c, _st, z) = parse_address("Main Street Austin TX 78701");
        assert_eq!(h, "");
        assert_eq!(s, "main street");
        assert_eq!(z, "78701");
    }

    #[test]
    fn join_keys_collapse_variants() {
        assert_eq!(
            join_key("123", "Main St", "78701"),
            join_key("123", "MAIN STREET", "78701-1234")
        );
        let k1 = join_key("123A", "Main St", "78701");
        assert_eq!(k1, "123a|main street|78701");
        let k2 = join_key("123", "Main", "78701");
        assert_eq!(k2, "123|main|78701");
        // Address key derived from a raw address matches the parts form.
        let from_raw = address_key("123 Main Street Austin TX 78701");
        assert_eq!(from_raw, "123|main street|78701");
        // Records without ZIP still group on house|street.
        assert_eq!(address_key("123 Main St"), "123|main street|");
        // No parseable street → normalized fallback.
        assert_eq!(address_key("Nowhere Plains"), "nowhere plains");
    }

    #[test]
    fn state_lookups() {
        assert_eq!(state_abbrev_of_name("Texas"), Some("TX".into()));
        assert_eq!(state_abbrev_of_name("NEW YORK"), Some("NY".into()));
        assert_eq!(state_abbrev_of_name("District of Columbia"), Some("DC".into()));
        assert_eq!(state_abbrev_of_name("Atlantis"), None);
        assert_eq!(state_name_of_abbrev("TX"), Some("Texas".into()));
        assert_eq!(state_name_of_abbrev("dc"), Some("District of Columbia".into()));
        assert_eq!(state_name_of_abbrev("XX"), None);
    }

    #[test]
    fn dispatch_routes() {
        // parse_address returns GeoParts struct.
        match dispatch("parse_address", vec![Value::String("1600 Pennsylvania Ave NW Washington DC 20500".into())])
            .unwrap()
            .unwrap()
        {
            Value::Struct { name, fields } => {
                assert_eq!(name, "GeoParts");
                let get = |k: &str| {
                    fields
                        .iter()
                        .find(|(fk, _)| fk == k)
                        .unwrap_or_else(|| panic!("missing {k}"))
                        .1
                        .clone()
                };
                assert!(matches!(get("zip"), Value::String(s) if s == "20500"));
                assert!(matches!(get("house"), Value::String(s) if s == "1600"));
                assert!(matches!(get("street"), Value::String(s) if s == "pennsylvania ave nw"));
                assert!(matches!(get("state"), Value::String(s) if s == "DC"));
            }
            other => panic!("expected GeoParts, got {:?}", type_name(&other)),
        }
        let r = dispatch("state_from_name", vec![Value::String("Texas".into())]);
        assert!(matches!(r.unwrap().unwrap(), Value::String(s) if s == "TX"));
        let r = dispatch("state_from_name", vec![Value::String("Atlantis".into())]);
        assert!(matches!(r.unwrap().unwrap(), Value::String(s) if s.is_empty()));
        // Wrong arity → honest Err.
        assert!(dispatch("join_key", vec![Value::String("a".into())]).unwrap().is_err());
        assert!(matches!(
            dispatch("is_zip5", vec![Value::String("78701".into())]).unwrap().unwrap(),
            Value::Bool(true)
        ));
        // Unknown fn → None.
        assert!(dispatch("warp", vec![]).is_none());
    }

    #[test]
    fn interp_end_to_end() {
        let src = r#"
        fn main() {
            let p = geocode.parse_address("4500 Parmer Ln Apt 4 Austin TX 78727")
            print(p.house)
            print(p.street)
            print(p.city)
            print(p.state)
            print(p.zip)
            print(geocode.normalize_address("88 Oak Dr"))
            print(geocode.join_key("4500", "Parmer Lane", "78727"))
            print(geocode.state_from_name("California"))
            print(geocode.zip5("x 77002 y"))
            print(geocode.is_zip5("77002").to_string())
        }
        "#;
        let (tokens, lex_errs) = crate::lexer::tokenize(src);
        assert!(lex_errs.is_empty(), "lex errors: {lex_errs:?}");
        let program = crate::parser::Parser::parse(tokens).expect("parse error");
        let mut interp = crate::interp::Interpreter::new();
        interp.run(&program).expect("interp run failed");
        assert_eq!(interp.output[0], "4500");
        assert_eq!(interp.output[1], "parmer ln");
        assert_eq!(interp.output[2], "austin");
        assert_eq!(interp.output[3], "TX");
        assert_eq!(interp.output[4], "78727");
        assert_eq!(interp.output[5], "88 oak drive");
        assert_eq!(interp.output[6], "4500|parmer lane|78727");
        assert_eq!(interp.output[7], "CA");
        assert_eq!(interp.output[8], "77002");
        assert_eq!(interp.output[9], "true");
    }
}
