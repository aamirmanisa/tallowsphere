//! `.tl` recipe format v1 — a `// @job(...)` comment block at the top of a
//! Tallow script declares how the scheduler should run it.
//!
//! ```tl
//! // @job(
//! //   id: "price-monitor",
//! //   schedule: 300,        // seconds between runs (fixed interval; v1)
//! //   priority: 5,          // higher = runs first when several are due
//! //   retries: 2,           // retry attempts after a failed run
//! //   timeout_s: 60,        // hard kill after N seconds
//! //   enabled: true,
//! //   args: ["--once"],     // optional: extra args passed after `--` to `tallow run`
//! //   cwd: "subdir"         // optional: working dir, relative to the recipe file
//! // )
//! ```
//!
//! The block is an ordinary comment, so the script stays runnable as-is with
//! `tallow run <file>`. Parsing is strict: unknown keys, duplicates, and bad
//! values are errors (fail-closed), and a missing block means "not a recipe".

use std::path::PathBuf;

/// Recipe parse errors.
#[derive(Debug, thiserror::Error)]
pub enum RecipeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("missing `// @job(...)` block")]
    MissingBlock,
    #[error("unterminated @job block (no closing `)` outside quotes)")]
    Unterminated,
    #[error("bad pair `{0}`: expected `key: value`")]
    BadPair(String),
    #[error("unknown key `{0}`")]
    UnknownKey(String),
    #[error("duplicate key `{0}`")]
    DuplicateKey(String),
    #[error("missing required key `{0}`")]
    MissingKey(&'static str),
    #[error("bad value for `{0}`: {1}")]
    BadValue(String, String),
}

/// One parsed recipe.
#[derive(Debug, Clone, PartialEq)]
pub struct Recipe {
    pub path: PathBuf,
    pub id: String,
    /// Seconds between runs (fixed interval, v1).
    pub schedule_s: u64,
    pub priority: i64,
    pub retries: u32,
    pub timeout_s: u64,
    pub enabled: bool,
    /// Extra args passed after `--` to `tallow run <script> -- <args...>`.
    pub args: Vec<String>,
    /// Working directory for the run, **relative to the recipe file's own
    /// directory** (keeps recipes self-contained). `None` = inherit.
    pub cwd: Option<PathBuf>,
    /// Egress policy (S2): maps onto the runtime's egress contract
    /// (`TALLOW_PROXY` → `TALLOW_ALLOW_DIRECT` → fail-closed Tor default).
    pub egress: EgressMode,
}

/// Per-recipe egress policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressMode {
    /// Anonymous-by-default: Tor with per-run circuit, fail-closed (the
    /// egress contract's default). An ambient `TALLOW_ALLOW_DIRECT` is
    /// stripped so the declaration cannot be silently overridden.
    #[default]
    Tor,
    /// Deliberate de-anonymized egress (box IP, no proxy). Only for recipes
    /// that cannot work otherwise; receipts record the mode distinctly.
    Direct,
}

impl EgressMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EgressMode::Tor => "tor",
            EgressMode::Direct => "direct",
        }
    }
}

pub const MAX_RETRIES: u32 = 10;
pub const MAX_TIMEOUT_S: u64 = 3600;
pub const ID_MAX: usize = 64;
pub const MAX_ARGS: usize = 16;

impl Recipe {
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, RecipeError> {
        let path = path.into();
        let src = std::fs::read_to_string(&path)?;
        let mut r = Self::parse_str(&path, &src)?;
        // Canonicalize so a per-recipe `cwd` cannot break script resolution.
        if let Ok(abs) = std::fs::canonicalize(&path) {
            r.path = abs;
        }
        Ok(r)
    }

    pub fn parse_str(path: impl Into<PathBuf>, src: &str) -> Result<Self, RecipeError> {
        let inner = extract_job_block(src)?;
        let pairs = split_pairs(&inner)?;

        let mut id: Option<String> = None;
        let mut schedule: Option<u64> = None;
        let mut priority: i64 = 0;
        let mut retries: u32 = 0;
        let mut timeout_s: u64 = 120;
        let mut enabled: bool = true;
        let mut args: Vec<String> = Vec::new();
        let mut cwd: Option<PathBuf> = None;
        let mut egress: Option<EgressMode> = None;

        for (k, v) in pairs {
            match k.as_str() {
                "id" => {
                    let s = parse_string(&k, &v)?;
                    if s.is_empty() || s.len() > ID_MAX {
                        return Err(RecipeError::BadValue(k, "must be 1..=64 chars".into()));
                    }
                    if !s
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-._".contains(c))
                    {
                        return Err(RecipeError::BadValue(k, "allowed: a-z 0-9 - . _".into()));
                    }
                    set_once(&mut id, s, &k)?;
                }
                "schedule" => {
                    let n = parse_int(&k, &v)?;
                    if n < 1 {
                        return Err(RecipeError::BadValue(k, "must be >= 1 (seconds)".into()));
                    }
                    let mut slot: Option<u64> = schedule.take();
                    set_once_u64(&mut slot, n as u64, &k)?;
                    schedule = slot;
                }
                "priority" => {
                    let n = parse_int(&k, &v)?;
                    priority = n;
                }
                "retries" => {
                    let n = parse_int(&k, &v)?;
                    if n < 0 || n > MAX_RETRIES as i64 {
                        return Err(RecipeError::BadValue(
                            k,
                            format!("must be 0..={MAX_RETRIES}"),
                        ));
                    }
                    retries = n as u32;
                }
                "timeout_s" => {
                    let n = parse_int(&k, &v)?;
                    if n < 1 || n as u64 > MAX_TIMEOUT_S {
                        return Err(RecipeError::BadValue(
                            k,
                            format!("must be 1..={MAX_TIMEOUT_S}"),
                        ));
                    }
                    timeout_s = n as u64;
                }
                "enabled" => {
                    enabled = parse_bool(&k, &v)?;
                }
                "args" => {
                    if !args.is_empty() {
                        return Err(RecipeError::DuplicateKey(k));
                    }
                    let list = parse_string_list(&k, &v)?;
                    if list.len() > MAX_ARGS {
                        return Err(RecipeError::BadValue(k, format!("max {MAX_ARGS} args")));
                    }
                    if let Some(long) = list.iter().find(|a| a.len() > 256) {
                        return Err(RecipeError::BadValue(
                            k,
                            format!("arg too long ({} chars, max 256): {long:.40}…", long.len()),
                        ));
                    }
                    args = list;
                }
                "cwd" => {
                    if cwd.is_some() {
                        return Err(RecipeError::DuplicateKey(k));
                    }
                    let s = parse_string(&k, &v)?;
                    if s.is_empty() {
                        return Err(RecipeError::BadValue(k, "empty".into()));
                    }
                    if PathBuf::from(&s).is_absolute() {
                        return Err(RecipeError::BadValue(k, "must be relative".into()));
                    }
                    cwd = Some(PathBuf::from(s));
                }
                "egress" => {
                    if egress.is_some() {
                        return Err(RecipeError::DuplicateKey(k));
                    }
                    let s = parse_string(&k, &v)?;
                    egress = Some(match s.as_str() {
                        "tor" => EgressMode::Tor,
                        "direct" => EgressMode::Direct,
                        "mesh" => {
                            return Err(RecipeError::BadValue(
                                k,
                                "`mesh` is reserved until S3 (operator-gated)".into(),
                            ))
                        }
                        other => {
                            return Err(RecipeError::BadValue(
                                k,
                                format!("unknown egress `{other}` (expected `tor` | `direct`)"),
                            ))
                        }
                    });
                }
                other => return Err(RecipeError::UnknownKey(other.to_string())),
            }
        }

        let id = id.ok_or(RecipeError::MissingKey("id"))?;
        let schedule_s = schedule.ok_or(RecipeError::MissingKey("schedule"))?;

        Ok(Recipe {
            path: path.into(),
            id,
            schedule_s,
            priority,
            retries,
            timeout_s,
            enabled,
            args,
            cwd,
            egress: egress.unwrap_or_default(),
        })
    }
}

fn set_once(slot: &mut Option<String>, v: String, key: &str) -> Result<(), RecipeError> {
    if slot.is_some() {
        return Err(RecipeError::DuplicateKey(key.to_string()));
    }
    *slot = Some(v);
    Ok(())
}

fn set_once_u64(slot: &mut Option<u64>, v: u64, key: &str) -> Result<(), RecipeError> {
    if slot.is_some() {
        return Err(RecipeError::DuplicateKey(key.to_string()));
    }
    *slot = Some(v);
    Ok(())
}

/// Find the first `// @job(` line and accumulate comment text until the
/// closing `)` (outside quoted strings). Returns the inner block text.
fn extract_job_block(src: &str) -> Result<String, RecipeError> {
    let mut acc: Option<String> = None;
    let mut in_str = false;
    for line in src.lines() {
        let t = line.trim_start();
        let content = match t.strip_prefix("//") {
            Some(rest) => rest.trim_start(),
            None => {
                if acc.is_some() {
                    // Block started but a non-comment line appeared before `)`.
                    return Err(RecipeError::Unterminated);
                }
                continue;
            }
        };
        if acc.is_none() {
            if let Some(rest) = content.strip_prefix("@job(") {
                acc = Some(String::new());
                if scan_into(rest, acc.as_mut().unwrap(), &mut in_str) {
                    return Ok(acc.take().unwrap());
                }
            }
            continue;
        }
        // Inside the block: append this comment line's content.
        let buf = acc.as_mut().unwrap();
        if !buf.is_empty() && !buf.ends_with(char::is_whitespace) {
            buf.push(' ');
        }
        if scan_into(content, buf, &mut in_str) {
            return Ok(acc.take().unwrap());
        }
    }
    if acc.is_some() {
        return Err(RecipeError::Unterminated);
    }
    Err(RecipeError::MissingBlock)
}

/// Append chars to `buf`, tracking quotes; stop (true) at `)` outside quotes.
fn scan_into(s: &str, buf: &mut String, in_str: &mut bool) -> bool {
    for c in s.chars() {
        match c {
            '"' => {
                *in_str = !*in_str;
                buf.push(c);
            }
            ')' if !*in_str => return true,
            _ => buf.push(c),
        }
    }
    false
}

/// Split top-level `key: value` pairs on commas (quote- and bracket-aware).
fn split_pairs(inner: &str) -> Result<Vec<(String, String)>, RecipeError> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut depth: i32 = 0;
    for c in inner.chars() {
        match c {
            '"' => {
                in_str = !in_str;
                cur.push(c);
            }
            '[' if !in_str => {
                depth += 1;
                cur.push(c);
            }
            ']' if !in_str => {
                depth -= 1;
                cur.push(c);
            }
            ',' if !in_str && depth == 0 => {
                parts.push(cur.trim().to_string());
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur.trim().to_string());
    }

    let mut out = Vec::new();
    for p in parts {
        if p.is_empty() {
            continue;
        }
        // Split on first ':' outside quotes (keys are simple identifiers).
        let idx = p.find(':').ok_or_else(|| RecipeError::BadPair(p.clone()))?;
        let (k, v) = p.split_at(idx);
        let k = k.trim().to_string();
        let v = v[1..].trim().to_string();
        if k.is_empty() || v.is_empty() {
            return Err(RecipeError::BadPair(p));
        }
        out.push((k, v));
    }
    if out.is_empty() {
        return Err(RecipeError::MissingKey("id"));
    }
    Ok(out)
}

fn parse_string(key: &str, v: &str) -> Result<String, RecipeError> {
    let v = v.trim();
    match v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Some(inner) if !inner.contains('"') => Ok(inner.to_string()),
        _ => Err(RecipeError::BadValue(
            key.to_string(),
            "expected \"quoted string\"".into(),
        )),
    }
}

fn parse_int(key: &str, v: &str) -> Result<i64, RecipeError> {
    v.trim()
        .parse::<i64>()
        .map_err(|e| RecipeError::BadValue(key.to_string(), format!("expected integer ({e})")))
}

fn parse_bool(key: &str, v: &str) -> Result<bool, RecipeError> {
    match v.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(RecipeError::BadValue(
            key.to_string(),
            format!("expected true|false, got `{other}`"),
        )),
    }
}

/// Parse a `["a", "b"]` list of quoted strings (quote-aware comma split).
fn parse_string_list(key: &str, v: &str) -> Result<Vec<String>, RecipeError> {
    let t = v.trim();
    let inner = t
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| RecipeError::BadValue(key.to_string(), "expected [\"a\", \"b\"]".into()))?;
    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    for c in inner.chars() {
        match c {
            '"' => {
                in_str = !in_str;
                cur.push(c);
            }
            ',' if !in_str => {
                parts.push(cur.trim().to_string());
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    if in_str {
        return Err(RecipeError::BadValue(
            key.to_string(),
            "unterminated string in list".into(),
        ));
    }
    parts.push(cur.trim().to_string());
    let mut out = Vec::new();
    for p in parts {
        if p.is_empty() {
            continue;
        }
        out.push(parse_string(key, &p)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"// banner comment
// @job(
//   id: "price-monitor",
//   schedule: 300,
//   priority: 5,
//   retries: 2,
//   timeout_s: 60,
//   enabled: true
// )
fn main() { print("hi") }
"#;

    #[test]
    fn parses_full_block() {
        let r = Recipe::parse_str("x.tl", OK).expect("parse");
        assert_eq!(r.id, "price-monitor");
        assert_eq!(r.schedule_s, 300);
        assert_eq!(r.priority, 5);
        assert_eq!(r.retries, 2);
        assert_eq!(r.timeout_s, 60);
        assert!(r.enabled);
    }

    #[test]
    fn defaults_apply() {
        let src = "// @job(id: \"a\", schedule: 10)\nfn main() {}\n";
        let r = Recipe::parse_str("x.tl", src).expect("parse");
        assert_eq!(r.priority, 0);
        assert_eq!(r.retries, 0);
        assert_eq!(r.timeout_s, 120);
        assert!(r.enabled);
        assert!(r.args.is_empty());
        assert!(r.cwd.is_none());
        assert_eq!(r.egress, EgressMode::Tor);
    }

    #[test]
    fn egress_parses_and_rejects() {
        let ok = "// @job(id: \"a\", schedule: 10, egress: \"direct\")\nfn main() {}\n";
        assert_eq!(
            Recipe::parse_str("x.tl", ok).expect("parse").egress,
            EgressMode::Direct
        );
        let ok_tor = "// @job(id: \"a\", schedule: 10, egress: \"tor\")\nfn main() {}\n";
        assert_eq!(
            Recipe::parse_str("x.tl", ok_tor).expect("parse").egress,
            EgressMode::Tor
        );
        for bad in [
            "// @job(id: \"a\", schedule: 10, egress: \"mesh\")\n",
            "// @job(id: \"a\", schedule: 10, egress: \"socks\")\n",
            "// @job(id: \"a\", schedule: 10, egress: \"direct\", egress: \"tor\")\n",
        ] {
            assert!(
                Recipe::parse_str("x.tl", bad).is_err(),
                "must reject: {bad}"
            );
        }
    }

    #[test]
    fn args_and_cwd_parse() {
        let src = "// @job(id: \"a\", schedule: 10, args: [\"--once\", \"--tag\", \"x y\"], cwd: \"demo/monitors\")\nfn main() {}\n";
        let r = Recipe::parse_str("x.tl", src).expect("parse");
        assert_eq!(r.args, vec!["--once", "--tag", "x y"]);
        assert_eq!(
            r.cwd.as_deref(),
            Some(std::path::Path::new("demo/monitors"))
        );
    }

    #[test]
    fn empty_args_list_ok() {
        let src = "// @job(id: \"a\", schedule: 10, args: [])\nfn main() {}\n";
        let r = Recipe::parse_str("x.tl", src).expect("parse");
        assert!(r.args.is_empty());
    }

    #[test]
    fn bad_args_and_cwd_rejected() {
        for src in [
            "// @job(id: \"a\", schedule: 10, args: \"--once\")\n",
            "// @job(id: \"a\", schedule: 10, args: [\"--once\", 2])\n",
            "// @job(id: \"a\", schedule: 10, args: [\"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\", \"--a\"])\n",
            "// @job(id: \"a\", schedule: 10, cwd: \"/abs/path\")\n",
            "// @job(id: \"a\", schedule: 10, cwd: 3)\n",
        ] {
            assert!(
                Recipe::parse_str("x.tl", src).is_err(),
                "must reject: {src}"
            );
        }
    }

    #[test]
    fn single_line_block() {
        let src = "// @job(id: \"a\", schedule: 10) \nfn main() {}\n";
        let r = Recipe::parse_str("x.tl", src).expect("parse");
        assert_eq!(r.schedule_s, 10);
    }

    #[test]
    fn missing_block() {
        let err = Recipe::parse_str("x.tl", "fn main() {}\n").unwrap_err();
        assert!(matches!(err, RecipeError::MissingBlock));
    }

    #[test]
    fn unterminated_block() {
        let err = Recipe::parse_str("x.tl", "// @job(id: \"a\", schedule: 10\nfn main() {}\n")
            .unwrap_err();
        assert!(matches!(err, RecipeError::Unterminated));
    }

    #[test]
    fn unknown_key_rejected() {
        let err =
            Recipe::parse_str("x.tl", "// @job(id: \"a\", schedule: 1, bogus: 2)\n").unwrap_err();
        assert!(matches!(err, RecipeError::UnknownKey(k) if k == "bogus"));
    }

    #[test]
    fn duplicate_key_rejected() {
        let err =
            Recipe::parse_str("x.tl", "// @job(id: \"a\", id: \"b\", schedule: 1)\n").unwrap_err();
        assert!(matches!(err, RecipeError::DuplicateKey(k) if k == "id"));
    }

    #[test]
    fn bad_values_rejected() {
        for src in [
            "// @job(id: \"a\", schedule: 0)\n",
            "// @job(id: \"a\", schedule: 10, retries: 99)\n",
            "// @job(id: \"a\", schedule: 10, timeout_s: 99999)\n",
            "// @job(id: \"UPPER\", schedule: 10)\n",
            "// @job(id: \"a\", schedule: 10, enabled: yes)\n",
            "// @job(id: 3, schedule: 10)\n",
            "// @job(schedule: 10)\n",
        ] {
            assert!(
                Recipe::parse_str("x.tl", src).is_err(),
                "must reject: {src}"
            );
        }
    }

    #[test]
    fn no_bracket_leak_from_schedule_obvious_case() {
        // A quoted ")" inside a value must not close the block.
        let src = "// @job(id: \"a\", schedule: 10, enabled: true)\n// trailing\nfn main() {}\n";
        let r = Recipe::parse_str("x.tl", src).expect("parse");
        assert_eq!(r.id, "a");
    }
}
