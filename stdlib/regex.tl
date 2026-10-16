// tallow.regex — Regular expressions

/// Compiled regex pattern
struct Regex {
    // internal: compiled regex
}

/// Compile a regex pattern
fn compile(pattern: String) -> Result<Regex> {
    // native: compiles regex pattern
}

/// Match result
struct Match {
    text:  String,
    start: usize,
    end:   usize,
}

impl Regex {
    /// Test if string matches pattern
    fn is_match(self, input: String) -> bool {
        // native: returns true if any match
    }

    /// Find first match
    fn find(self, input: String) -> Match? {
        // native: returns first match or nil
    }

    /// Find all non-overlapping matches
    fn find_all(self, input: String) -> []Match {
        // native: returns all matches
    }

    /// Replace first match
    fn replace(self, input: String, replacement: String) -> String {
        // native: replaces first match
    }

    /// Replace all matches
    fn replace_all(self, input: String, replacement: String) -> String {
        // native: replaces all matches
    }

    /// Split string by pattern
    fn split(self, input: String) -> []String {
        // native: splits at matches
    }

    /// Capture groups from first match
    fn captures(self, input: String) -> []String? {
        // native: returns capture groups or nil
    }
}
