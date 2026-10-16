// tallow.env — Environment variables
//
// Safe environment variable access. Values from env are treated
// as untrusted input and must be validated before use.

/// Get environment variable (returns nil if not set)
fn get(name: String) -> String? {
    // native: reads env var
}

/// Get environment variable with default
fn get_or(name: String, default: String) -> String {
    // native: reads env var, returns default if unset
}

/// Get required environment variable (error if not set)
fn require(name: String) -> Result<String> {
    // native: reads env var, errors if missing
}

/// Set environment variable (current process only)
fn set(name: String, value: String) {
    // native: sets env var for current process
}

/// Remove environment variable
fn remove(name: String) {
    // native: unsets env var
}

/// Get all environment variables
fn all() -> Map<String, String> {
    // native: returns all env vars as map
}

/// Check if environment variable is set
fn has(name: String) -> bool {
    // native: true if env var exists
}

/// Get current working directory
fn cwd() -> String {
    // native: returns current working directory
}

/// Get home directory
fn home() -> String {
    // native: returns user home directory
}

/// Get home directory (platform-aware: USERPROFILE on Windows, HOME on Unix)
fn home_dir() -> String {
    // native: returns user home directory
}

/// Get config directory (platform-aware: APPDATA on Windows, ~/Library/Application Support on macOS, XDG_CONFIG_HOME or ~/.config on Linux)
fn config_dir() -> String {
    // native: returns platform config directory
}

/// Get data directory (platform-aware: LOCALAPPDATA on Windows, ~/Library/Application Support on macOS, XDG_DATA_HOME or ~/.local/share on Linux)
fn data_dir() -> String {
    // native: returns platform data directory
}

/// Get temporary directory
fn temp_dir() -> String {
    // native: returns system temp directory path
}

/// Get cache directory (platform-aware: LOCALAPPDATA/Temp on Windows, ~/Library/Caches on macOS, XDG_CACHE_HOME or ~/.cache on Linux)
fn cache_dir() -> String {
    // native: returns platform cache directory
}

/// Get executable path
fn exe_path() -> String {
    // native: returns path to current executable
}

/// Get command line arguments
fn args() -> []String {
    // native: returns CLI arguments
}
