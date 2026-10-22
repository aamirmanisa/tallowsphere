// tallow.regex — Regular expressions

/// Compiled regex pattern
struct Regex {
    // internal: compiled regex
}

/// Compile a regex pattern
// native: compiles regex pattern
native fn compile(pattern: String) -> Result<Regex>

/// Match result
struct Match {
    text:  String,
    start: usize,
    end:   usize,
}

impl Regex {
    /// Test if string matches pattern
    // native: returns true if any match
    native fn is_match(self, input: String) -> bool

    /// Find first match
    // native: returns first match or nil
    native fn find(self, input: String) -> Match?

    /// Find all non-overlapping matches
    // native: returns all matches
    native fn find_all(self, input: String) -> []Match

    /// Replace first match
    // native: replaces first match
    native fn replace(self, input: String, replacement: String) -> String

    /// Replace all matches
    // native: replaces all matches
    native fn replace_all(self, input: String, replacement: String) -> String

    /// Split string by pattern
    // native: splits at matches
    native fn split(self, input: String) -> []String

    /// Capture groups from first match
    // native: returns capture groups or nil
    native fn captures(self, input: String) -> []String?
}
