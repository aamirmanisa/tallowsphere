use anyhow::Result;
use pubgrub::Ranges;
use semver::Version;

/// A parsed version requirement supporting ^, ~, =, * and bare version strings.
#[derive(Debug, Clone)]
pub enum VersionReq {
    /// `^1.2.3` or bare `1.2.3` — compatible updates (Cargo/npm default)
    Caret(semver::VersionReq),
    /// `~1.2.3` — patch-level updates only
    Tilde(semver::VersionReq),
    /// `=1.2.3` — exact version
    Exact(Version),
    /// `*` — any version
    Wildcard,
}

/// Parse a version requirement string into a typed VersionReq.
///
/// Supported formats:
/// - `"^1.2"` or `"^1.2.3"` -> Caret
/// - `"~1.2"` or `"~1.2.3"` -> Tilde
/// - `"=1.2.3"` -> Exact
/// - `"*"` -> Wildcard
/// - `"1.2.3"` (bare) -> Caret (default, same as Cargo)
pub fn parse_version_req(s: &str) -> Result<VersionReq> {
    let s = s.trim();

    if s == "*" {
        return Ok(VersionReq::Wildcard);
    }

    if let Some(rest) = s.strip_prefix('=') {
        let v = rest.trim().parse::<Version>()
            .map_err(|e| anyhow::anyhow!("invalid exact version '{}': {}", rest.trim(), e))?;
        return Ok(VersionReq::Exact(v));
    }

    if s.starts_with('~') {
        let req = semver::VersionReq::parse(s)
            .map_err(|e| anyhow::anyhow!("invalid tilde requirement '{}': {}", s, e))?;
        return Ok(VersionReq::Tilde(req));
    }

    if s.starts_with('^') {
        let req = semver::VersionReq::parse(s)
            .map_err(|e| anyhow::anyhow!("invalid caret requirement '{}': {}", s, e))?;
        return Ok(VersionReq::Caret(req));
    }

    // Bare version like "1.2.3" or "1.2" — treat as caret
    // semver::VersionReq::parse already handles bare versions as ^
    let req_str = format!("^{}", s);
    let req = semver::VersionReq::parse(&req_str)
        .map_err(|e| anyhow::anyhow!("invalid version requirement '{}': {}", s, e))?;
    Ok(VersionReq::Caret(req))
}

impl VersionReq {
    /// Check if a specific version matches this requirement.
    pub fn matches(&self, version: &Version) -> bool {
        match self {
            VersionReq::Caret(req) | VersionReq::Tilde(req) => req.matches(version),
            VersionReq::Exact(v) => v == version,
            VersionReq::Wildcard => true,
        }
    }

    /// Convert to PubGrub's Ranges type for the resolver.
    ///
    /// This is the critical bridge between our semver representation and PubGrub's
    /// internal range-based constraint system.
    pub fn to_pubgrub_range(&self) -> Ranges<Version> {
        match self {
            VersionReq::Wildcard => Ranges::full(),
            VersionReq::Exact(v) => Ranges::singleton(v.clone()),
            VersionReq::Caret(req) => semver_req_to_range(req),
            VersionReq::Tilde(req) => semver_req_to_range(req),
        }
    }
}

/// Convert a semver::VersionReq into a pubgrub::Ranges<Version>.
///
/// For a VersionReq with one comparator set, we compute the [lower, upper) range.
/// For multi-comparator sets (e.g., `>=1.0, <2.0`), we intersect all ranges.
fn semver_req_to_range(req: &semver::VersionReq) -> Ranges<Version> {
    // semver crate doesn't expose comparators directly in a stable way,
    // so we use a brute-force approach: given the requirement, compute the
    // effective lower and upper bounds by parsing the requirement string.
    //
    // However, we can use the fact that semver::VersionReq::matches() works
    // correctly, and compute the range from the requirement's string representation.
    let s = req.to_string();

    // Handle caret requirements: ^X.Y.Z
    if let Some(rest) = s.strip_prefix('^') {
        return caret_range(rest);
    }

    // Handle tilde requirements: ~X.Y.Z
    if let Some(rest) = s.strip_prefix('~') {
        return tilde_range(rest);
    }

    // Handle >=X.Y.Z, <X.Y.Z compound requirements
    if s.contains(',') {
        return compound_range(&s);
    }

    // Handle bare >=X.Y.Z
    if let Some(rest) = s.strip_prefix(">=") {
        let v = rest.trim().parse::<Version>().unwrap_or_else(|_| Version::new(0, 0, 0));
        return Ranges::higher_than(v);
    }

    // Fallback: full range
    Ranges::full()
}

/// Compute range for caret requirement: ^X.Y.Z
/// ^1.2.3 := >=1.2.3, <2.0.0  (major > 0)
/// ^0.2.3 := >=0.2.3, <0.3.0  (major == 0, minor > 0)
/// ^0.0.3 := >=0.0.3, <0.0.4  (major == 0, minor == 0)
fn caret_range(version_str: &str) -> Ranges<Version> {
    let parts: Vec<&str> = version_str.trim().split('.').collect();
    let major: u64 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let lower = Version::new(major, minor, patch);

    let upper = if major > 0 {
        Version::new(major + 1, 0, 0)
    } else if minor > 0 {
        Version::new(0, minor + 1, 0)
    } else {
        Version::new(0, 0, patch + 1)
    };

    Ranges::between(lower, upper)
}

/// Compute range for tilde requirement: ~X.Y.Z
/// ~1.2.3 := >=1.2.3, <1.3.0
/// ~1.2   := >=1.2.0, <1.3.0
fn tilde_range(version_str: &str) -> Ranges<Version> {
    let parts: Vec<&str> = version_str.trim().split('.').collect();
    let major: u64 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let lower = Version::new(major, minor, patch);
    let upper = Version::new(major, minor + 1, 0);

    Ranges::between(lower, upper)
}

/// Parse compound requirements like ">=1.0.0, <2.0.0"
fn compound_range(s: &str) -> Ranges<Version> {
    let mut lower = Version::new(0, 0, 0);
    let mut upper: Option<Version> = None;

    for part in s.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(">=") {
            if let Ok(v) = rest.trim().parse::<Version>() {
                lower = v;
            }
        } else if let Some(rest) = part.strip_prefix('<') {
            if let Ok(v) = rest.trim().parse::<Version>() {
                upper = Some(v);
            }
        }
    }

    match upper {
        Some(u) => Ranges::between(lower, u),
        None => Ranges::higher_than(lower),
    }
}

impl std::fmt::Display for VersionReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionReq::Caret(req) => write!(f, "{}", req),
            VersionReq::Tilde(req) => write!(f, "{}", req),
            VersionReq::Exact(v) => write!(f, "={}", v),
            VersionReq::Wildcard => write!(f, "*"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_caret() {
        let req = parse_version_req("^1.2.3").unwrap();
        assert!(matches!(req, VersionReq::Caret(_)));
        assert!(req.matches(&Version::new(1, 2, 3)));
        assert!(req.matches(&Version::new(1, 9, 0)));
        assert!(!req.matches(&Version::new(2, 0, 0)));
        assert!(!req.matches(&Version::new(1, 2, 2)));
    }

    #[test]
    fn test_parse_caret_zero_major() {
        let req = parse_version_req("^0.2.3").unwrap();
        assert!(req.matches(&Version::new(0, 2, 3)));
        assert!(req.matches(&Version::new(0, 2, 9)));
        assert!(!req.matches(&Version::new(0, 3, 0)));
    }

    #[test]
    fn test_parse_tilde() {
        let req = parse_version_req("~1.2.3").unwrap();
        assert!(matches!(req, VersionReq::Tilde(_)));
        assert!(req.matches(&Version::new(1, 2, 3)));
        assert!(req.matches(&Version::new(1, 2, 9)));
        assert!(!req.matches(&Version::new(1, 3, 0)));
    }

    #[test]
    fn test_parse_exact() {
        let req = parse_version_req("=1.2.3").unwrap();
        assert!(matches!(req, VersionReq::Exact(_)));
        assert!(req.matches(&Version::new(1, 2, 3)));
        assert!(!req.matches(&Version::new(1, 2, 4)));
    }

    #[test]
    fn test_parse_wildcard() {
        let req = parse_version_req("*").unwrap();
        assert!(matches!(req, VersionReq::Wildcard));
        assert!(req.matches(&Version::new(0, 0, 1)));
        assert!(req.matches(&Version::new(99, 99, 99)));
    }

    #[test]
    fn test_parse_bare_version() {
        // Bare version treated as caret
        let req = parse_version_req("1.2.3").unwrap();
        assert!(matches!(req, VersionReq::Caret(_)));
        assert!(req.matches(&Version::new(1, 2, 3)));
        assert!(req.matches(&Version::new(1, 9, 0)));
        assert!(!req.matches(&Version::new(2, 0, 0)));
    }

    #[test]
    fn test_pubgrub_range_caret() {
        let req = parse_version_req("^1.2.0").unwrap();
        let range = req.to_pubgrub_range();
        assert!(range.contains(&Version::new(1, 2, 0)));
        assert!(range.contains(&Version::new(1, 9, 9)));
        assert!(!range.contains(&Version::new(2, 0, 0)));
        assert!(!range.contains(&Version::new(1, 1, 9)));
    }

    #[test]
    fn test_pubgrub_range_tilde() {
        let req = parse_version_req("~1.2.0").unwrap();
        let range = req.to_pubgrub_range();
        assert!(range.contains(&Version::new(1, 2, 0)));
        assert!(range.contains(&Version::new(1, 2, 9)));
        assert!(!range.contains(&Version::new(1, 3, 0)));
    }

    #[test]
    fn test_pubgrub_range_exact() {
        let req = parse_version_req("=1.2.3").unwrap();
        let range = req.to_pubgrub_range();
        assert!(range.contains(&Version::new(1, 2, 3)));
        assert!(!range.contains(&Version::new(1, 2, 4)));
    }

    #[test]
    fn test_pubgrub_range_wildcard() {
        let req = parse_version_req("*").unwrap();
        let range = req.to_pubgrub_range();
        assert!(range.contains(&Version::new(0, 0, 1)));
        assert!(range.contains(&Version::new(99, 0, 0)));
    }

    #[test]
    fn test_partial_version_caret() {
        // ^1.2 should be treated as ^1.2.0
        let req = parse_version_req("^1.2").unwrap();
        assert!(req.matches(&Version::new(1, 2, 0)));
        assert!(req.matches(&Version::new(1, 9, 0)));
        assert!(!req.matches(&Version::new(2, 0, 0)));
    }

    #[test]
    fn test_invalid_version() {
        assert!(parse_version_req("=not.a.version").is_err());
        assert!(parse_version_req("^abc").is_err());
    }
}
