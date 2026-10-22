// tallow.env — Environment variables
//
// Safe environment variable access. Values from env are treated
// as untrusted input and must be validated before use.

/// Get environment variable (returns nil if not set)
// native: reads env var
native fn get(name: String) -> String?

/// Get environment variable with default
// native: reads env var, returns default if unset
native fn get_or(name: String, default: String) -> String

/// Get required environment variable (error if not set)
// native: reads env var, errors if missing
native fn require(name: String) -> Result<String>

/// Set environment variable (current process only)
// native: sets env var for current process
native fn set(name: String, value: String)

/// Remove environment variable
// native: unsets env var
native fn remove(name: String)

/// Get all environment variables
// native: returns all env vars as map
native fn all() -> Map<String, String>

/// Check if environment variable is set
// native: true if env var exists
native fn has(name: String) -> bool

/// Get current working directory
// native: returns current working directory
native fn cwd() -> String

/// Get home directory
// native: returns user home directory
native fn home() -> String

/// Get home directory (platform-aware: USERPROFILE on Windows, HOME on Unix)
// native: returns user home directory
native fn home_dir() -> String

/// Get config directory (platform-aware: APPDATA on Windows, ~/Library/Application Support on macOS, XDG_CONFIG_HOME or ~/.config on Linux)
// native: returns platform config directory
native fn config_dir() -> String

/// Get data directory (platform-aware: LOCALAPPDATA on Windows, ~/Library/Application Support on macOS, XDG_DATA_HOME or ~/.local/share on Linux)
// native: returns platform data directory
native fn data_dir() -> String

/// Get temporary directory
// native: returns system temp directory path
native fn temp_dir() -> String

/// Get cache directory (platform-aware: LOCALAPPDATA/Temp on Windows, ~/Library/Caches on macOS, XDG_CACHE_HOME or ~/.cache on Linux)
// native: returns platform cache directory
native fn cache_dir() -> String

/// Get executable path
// native: returns path to current executable
native fn exe_path() -> String

/// Get command line arguments
// native: returns CLI arguments
native fn args() -> []String
