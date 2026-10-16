// tallow.config — Config file parsing (TOML/YAML/JSON)

/// Parse TOML string into typed struct
fn parse_toml<T>(input: String) -> Result<T> {
    // native: deserializes TOML into T
}

/// Parse YAML string into typed struct
fn parse_yaml<T>(input: String) -> Result<T> {
    // native: deserializes YAML into T
}

/// Parse JSON string into typed struct
fn parse_json<T>(input: String) -> Result<T> {
    // native: deserializes JSON into T
}

/// Load config from file (auto-detects format by extension)
fn load<T>(path: String) -> Result<T> {
    // native: reads file, detects .toml/.yaml/.json, parses
}

/// Serialize to TOML string
fn to_toml<T>(value: T) -> Result<String> {
    // native
}

/// Serialize to YAML string
fn to_yaml<T>(value: T) -> Result<String> {
    // native
}
