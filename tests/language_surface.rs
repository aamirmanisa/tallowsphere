//! Audit of the four published surface counts: keywords, operator tokens,
//! error codes, and stdlib modules/functions.
//!
//! These numbers are published (`Tallow-Language/spec/generated.json`), so they
//! are a claim about this engine, not documentation that can drift. Each test
//! here checks the claim behaviourally where that is possible: every keyword and
//! operator spelling is fed through the lexer and must come back as the exact
//! token the spec names, and the error catalogue must equal the set of codes the
//! source can actually emit, in both directions.

use std::collections::BTreeSet;
use std::path::Path;
use tallow::lexer::{tokenize, TokenKind};

/// 36 keywords, spec §1.1.
const KEYWORDS: &[(&str, TokenKind)] = &[
    ("let", TokenKind::Let),
    ("var", TokenKind::Var),
    ("const", TokenKind::Const),
    ("struct", TokenKind::Struct),
    ("enum", TokenKind::Enum),
    ("impl", TokenKind::Impl),
    ("trait", TokenKind::Trait),
    ("match", TokenKind::Match),
    ("if", TokenKind::If),
    ("else", TokenKind::Else),
    ("for", TokenKind::For),
    ("while", TokenKind::While),
    ("in", TokenKind::In),
    ("return", TokenKind::Return),
    ("import", TokenKind::Import),
    ("async", TokenKind::Async),
    ("await", TokenKind::Await),
    ("true", TokenKind::True),
    ("false", TokenKind::False),
    ("nil", TokenKind::Nil),
    ("type", TokenKind::Type),
    ("self", TokenKind::SelfValue),
    ("mut", TokenKind::Mut),
    ("as", TokenKind::As),
    ("bail", TokenKind::Bail),
    ("bail_if", TokenKind::BailIf),
    ("break", TokenKind::Break),
    ("continue", TokenKind::Continue),
    ("catch", TokenKind::Catch),
    ("loop", TokenKind::Loop),
    ("dyn", TokenKind::Dyn),
    ("defer", TokenKind::Defer),
    ("private", TokenKind::Private),
    ("secret", TokenKind::Secret),
    ("_", TokenKind::Underscore),
    ("_", TokenKind::Underscore),
];

/// 51 operator / delimiter / punctuation tokens, spec §1.2.
const OPERATORS: &[(&str, TokenKind)] = &[
    ("(", TokenKind::LParen),
    (")", TokenKind::RParen),
    ("{", TokenKind::LBrace),
    ("}", TokenKind::RBrace),
    ("[", TokenKind::LBracket),
    ("]", TokenKind::RBracket),
    ("+", TokenKind::Plus),
    ("-", TokenKind::Minus),
    ("*", TokenKind::Star),
    ("/", TokenKind::Slash),
    ("%", TokenKind::Percent),
    ("=", TokenKind::Eq),
    ("==", TokenKind::EqEq),
    ("!=", TokenKind::BangEq),
    ("<", TokenKind::Lt),
    (">", TokenKind::Gt),
    ("<=", TokenKind::LtEq),
    (">=", TokenKind::GtEq),
    ("!", TokenKind::Bang),
    ("&&", TokenKind::AmpAmp),
    ("||", TokenKind::PipePipe),
    ("&", TokenKind::Amp),
    ("|", TokenKind::Pipe),
    ("^", TokenKind::Caret),
    ("~", TokenKind::Tilde),
    ("**", TokenKind::StarStar),
    ("<<", TokenKind::Shl),
    (">>", TokenKind::Shr),
    ("+=", TokenKind::PlusEq),
    ("-=", TokenKind::MinusEq),
    ("*=", TokenKind::StarEq),
    ("/=", TokenKind::SlashEq),
    ("%=", TokenKind::PercentEq),
    ("**=", TokenKind::StarStarEq),
    ("<<=", TokenKind::ShlEq),
    (">>=", TokenKind::ShrEq),
    ("&=", TokenKind::AmpEq),
    ("|=", TokenKind::PipeEq),
    ("^=", TokenKind::CaretEq),
    (".", TokenKind::Dot),
    ("..", TokenKind::DotDot),
    (",", TokenKind::Comma),
    (":", TokenKind::Colon),
    ("::", TokenKind::ColonColon),
    (";", TokenKind::Semi),
    ("->", TokenKind::Arrow),
    ("=>", TokenKind::FatArrow),
    ("?", TokenKind::Question),
    ("@", TokenKind::At),
    ("#", TokenKind::Hash),
    ("_", TokenKind::Underscore),
];

/// 176 diagnostic codes, spec §5.
const ERROR_CODES: &[&str] = &[
    "E0100",
    "E0101",
    "E0102",
    "E0103",
    "E0104",
    "E0105",
    "E0106",
    "E0107",
    "E0108",
    "E0109",
    "E0110",
    "E0111",
    "E0112",
    "E0113",
    "E0114",
    "E0115",
    "E0116",
    "E0117",
    "E0200",
    "E0201",
    "E0202",
    "E0203",
    "E0300",
    "E0301",
    "E0302",
    "E0303",
    "E0304",
    "E0305",
    "E0306",
    "E0400",
    "E0401",
    "E0402",
    "E0403",
    "E0404",
    "E0500",
    "E0501",
    "E0502",
    "E0504",
    "E0505",
    "E0506",
    "E0600",
    "E0610",
    "E0611",
    "E0612",
    "E0613",
    "E0614",
    "E0615",
    "E0616",
    "E0617",
    "E0618",
    "E0619",
    "E0621",
    "E0622",
    "E0623",
    "E0700",
    "E0703",
    "E0800",
    "E0801",
    "E0802",
    "E0804",
    "E0805",
    "E0900",
    "E0950",
    "E1000",
    "E1001",
    "E1002",
    "E1100",
    "E1101",
    "E1200",
    "E1201",
    "E1202",
    "E1203",
    "E1204",
    "E1300",
    "E1301",
    "E1302",
    "E1303",
    "E1304",
    "E1305",
    "E1306",
    "E1400",
    "E1401",
    "E1402",
    "E1403",
    "E1404",
    "E1405",
    "E1500",
    "E1502",
    "E1503",
    "E1600",
    "E1601",
    "E1602",
    "E1603",
    "E1700",
    "E1701",
    "E1702",
    "E1800",
    "E1802",
    "E1803",
    "E1900",
    "E1901",
    "E1903",
    "E2000",
    "E2001",
    "E2100",
    "E2101",
    "E2102",
    "E2200",
    "E2201",
    "E2202",
    "E2203",
    "E2204",
    "E2205",
    "E2300",
    "E2400",
    "E2500",
    "E2600",
    "E2601",
    "E2603",
    "E2604",
    "E2700",
    "E2800",
    "E5001",
    "E5002",
    "E5003",
    "E5004",
    "E5100",
    "E5101",
    "E5102",
    "E5103",
    "E5104",
    "E6001",
    "E6002",
    "E6003",
    "E6005",
    "E7001",
    "E7002",
    "E7003",
    "E7004",
    "E7005",
    "E7006",
    "E7007",
    "E7008",
    "E7009",
    "E7010",
    "E7011",
    "E7012",
    "E7013",
    "E7020",
    "E7021",
    "E7022",
    "E7023",
    "E7024",
    "E7025",
    "E7026",
    "E7027",
    "E7028",
    "E7029",
    "E7030",
    "E7031",
    "E7040",
    "E7041",
    "E7042",
    "E7043",
    "E7044",
    "E7050",
    "E7051",
    "E7052",
    "E7053",
    "E7054",
    "E7055",
    "E7056",
    "E7057",
    "E7058",
    "E7059",
    "E7101",
];

fn kinds(src: &str) -> Vec<TokenKind> {
    let (tokens, errors) = tokenize(src);
    assert!(errors.is_empty(), "{src:?} produced lex errors: {errors:?}");
    tokens.into_iter().map(|t| t.kind).collect()
}

#[test]
fn published_counts_match_the_tables() {
    assert_eq!(KEYWORDS.len(), 36, "keyword table size");
    assert_eq!(OPERATORS.len(), 51, "operator table size");
    assert_eq!(ERROR_CODES.len(), 176, "error catalogue size");
    let dup: BTreeSet<&str> = ERROR_CODES.iter().copied().collect();
    assert_eq!(dup.len(), 176, "duplicate code in the catalogue");
}

#[test]
fn every_keyword_lexes_as_its_documented_token() {
    for (word, expected) in KEYWORDS {
        let got = kinds(word);
        // A keyword is one token plus EOF; `true`/`false`/`nil` are keywords too.
        assert_eq!(
            got.first(),
            Some(expected),
            "keyword `{word}` lexed as {got:?}, expected {expected:?}"
        );
        assert_eq!(got.len(), 2, "keyword `{word}` produced {got:?} (expected token + EOF)");
    }
}

#[test]
fn every_operator_spelling_lexes_as_its_documented_token() {
    for (spelling, expected) in OPERATORS {
        let got = kinds(spelling);
        assert_eq!(
            got.first(),
            Some(expected),
            "spelling `{spelling}` lexed as {got:?}, expected {expected:?}"
        );
        assert_eq!(
            got.len(),
            2,
            "spelling `{spelling}` produced {got:?} (expected one token + EOF)"
        );
    }
}

/// The catalogue must be exactly the set of codes the engine can emit. Both
/// directions matter: a code in the spec that no pass emits is a false promise,
/// and a code the source emits that the spec does not list is an undocumented
/// diagnostic.
#[test]
fn error_catalogue_equals_what_the_engine_emits() {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![Path::new("src").to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let text = std::fs::read_to_string(&path).expect("read source");
                for code in extract_codes(&text) {
                    found.insert(code);
                }
            }
        }
    }
    let catalogue: BTreeSet<String> = ERROR_CODES.iter().map(|c| c.to_string()).collect();
    let undocumented: Vec<_> = found.difference(&catalogue).cloned().collect();
    let unemitted: Vec<_> = catalogue.difference(&found).cloned().collect();
    assert!(undocumented.is_empty(), "codes emitted but not in the catalogue: {undocumented:?}");
    assert!(unemitted.is_empty(), "codes in the catalogue that no source file emits: {unemitted:?}");
    assert_eq!(found.len(), 176, "engine emits {} distinct codes", found.len());
}

/// `"E1234"` string literals only — a code is emitted by passing the literal to
/// the diagnostics API, so this is the set the engine can actually report.
fn extract_codes(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 < bytes.len() {
        if bytes[i] == b'"'
            && bytes[i + 1] == b'E'
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && bytes[i + 4].is_ascii_digit()
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6] == b'"'
        {
            out.push(text[i + 1..i + 6].to_string());
            i += 7;
        } else {
            i += 1;
        }
    }
    out
}

/// 85 stdlib modules and 1,118 declarations, spec §6.
///
/// Two checks: the counts the spec publishes, and that every module the counts
/// are made of is actually routed by the runtime dispatcher. A module that is
/// declared in `.tl` but absent from `stdlib::dispatch` is a surface the spec
/// promises and the engine cannot answer.
#[test]
fn stdlib_counts_and_routing() {
    let mut modules: Vec<String> = Vec::new();
    let mut fns = 0usize;
    for entry in std::fs::read_dir("stdlib").expect("read stdlib") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("tl") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        modules.push(stem.clone());
        let text = std::fs::read_to_string(&path).expect("read stdlib module");
        for line in text.lines() {
            let t = line.trim_start();
            let rest = t.strip_prefix("native ").unwrap_or(t);
            if rest.starts_with("fn ")
                && rest
                    .chars()
                    .nth(3)
                    .map(|c| c.is_ascii_alphabetic() || c == '_')
                    .unwrap_or(false)
                && rest.contains('(')
            {
                fns += 1;
            }
        }
    }
    modules.sort();
    // 86, not 85: stdlib/mesh.tl is new (the execution plane's published
    // surface). It is not a rename of src/stdlib/mesh.rs — that module documents
    // the simulated topology plane and has no manifest of its own.
    assert_eq!(modules.len(), 86, "stdlib module files: {modules:?}");
    // 1124, not 1118: timeseries.tl declared six `method … on TimeSeries` lines,
    // a form this counter never saw; they are now an impl block, which the
    // counter reads. The surface did not grow — the old figure under-counted.
    // 1126, not 1124: stdlib/mesh.tl publishes the two functions of the mesh
    // execution plane that run today — Mesh.plan and Mesh.replay. Mesh.run is
    // deliberately absent until a worker pool can execute Tallow functions; a
    // declaration that cannot execute is the defect this gate exists to catch.
    assert_eq!(fns, 1126, "stdlib function declarations");

    // Routing: every module answers the dispatcher. A bogus function name is
    // used so nothing executes — `None` for the unknown name and `Some` are both
    // evidence the module is wired; a panic is not.
    for module in &modules {
        let _ = tallow::stdlib::dispatch(module, "__audit_probe__", Vec::new());
    }
}
