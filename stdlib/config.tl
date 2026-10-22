// tallow.config — Config file parsing (TOML/YAML/JSON)

/// Parse TOML string into typed struct
// native: deserializes TOML into T
native fn parse_toml<T>(input: String) -> Result<T>

/// Parse YAML string into typed struct
// native: deserializes YAML into T
native fn parse_yaml<T>(input: String) -> Result<T>

/// Parse JSON string into typed struct
// native: deserializes JSON into T
native fn parse_json<T>(input: String) -> Result<T>

/// Load config from file (auto-detects format by extension)
// native: reads file, detects .toml/.yaml/.json, parses
native fn load<T>(path: String) -> Result<T>

/// Serialize to TOML string
fn to_toml<T>(value: T) -> Result<String> {
    // native
}

/// Serialize to YAML string
fn to_yaml<T>(value: T) -> Result<String> {
    // native
}
