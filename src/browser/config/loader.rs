//! Generic TOML configuration loader with defaults and pretty-printing.

use std::fs;
use std::path::{Path, PathBuf};

/// Load a TOML file into `T`, falling back to `T::default()` if the file
/// doesn't exist or can't be parsed. Fields missing from the file get their
/// default values thanks to `#[serde(default)]` on every struct.
pub fn load_toml<T: serde::de::DeserializeOwned + Default>(path: &Path) -> T {
    match fs::read_to_string(path) {
        Ok(contents) => match toml::from_str::<T>(&contents) {
            Ok(config) => config,
            Err(e) => {
                eprintln!(
                    "warn: failed to parse config file {:?}: {}. Using defaults.",
                    path, e
                );
                T::default()
            }
        },
        Err(_) => T::default(),
    }
}

/// Save `T` to a TOML file with pretty formatting.
pub fn save_toml<T: serde::Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let content = toml::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

/// Set a dotted key path in a TOML file (e.g., "plugins.adblock" = "true").
/// Preserves comments and formatting via `toml_edit`.
pub fn set_toml_value(path: &Path, key: &str, value: &str) -> Result<(), String> {
    let content = fs::read_to_string(path).unwrap_or_default();
    let mut doc = content
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("parse error: {e}"))?;

    let parts: Vec<&str> = key.split('.').collect();
    if parts.is_empty() {
        return Err("empty key".into());
    }

    // Navigate to the parent table, creating intermediate tables as needed
    let mut table = doc.as_table_mut();
    for &segment in &parts[..parts.len() - 1] {
        if !table.contains_key(segment) {
            table.insert(segment, toml_edit::Item::Table(toml_edit::Table::new()));
        }
        table = table[segment]
            .as_table_mut()
            .ok_or_else(|| format!("{segment} is not a table"))?;
    }

    let leaf = parts[parts.len() - 1];

    // Try to parse the value as bool, integer, float, or fall back to string
    let toml_value = if value == "true" || value == "false" {
        toml_edit::value(value == "true")
    } else if let Ok(i) = value.parse::<i64>() {
        toml_edit::value(i)
    } else if let Ok(f) = value.parse::<f64>() {
        toml_edit::value(f)
    } else {
        toml_edit::value(value)
    };

    table.insert(leaf, toml_value);

    fs::write(path, doc.to_string()).map_err(|e| format!("write error: {e}"))
}

/// Resolve the browser config directory, cross-platform.
///
/// Windows: `%LOCALAPPDATA%\tallow\browser\config\`
/// Others:  `~/.tallow/browser/config/`
pub fn config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("tallow").join("browser").join("config"))
            .unwrap_or_else(|_| PathBuf::from(".tallow").join("browser").join("config"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .map(|p| {
                PathBuf::from(p)
                    .join(".tallow")
                    .join("browser")
                    .join("config")
            })
            .unwrap_or_else(|_| PathBuf::from(".tallow").join("browser").join("config"))
    }
}

/// All config file names in the config directory.
pub const CONFIG_FILES: &[&str] = &[
    "browser.toml",
    "plugins.toml",
    "stealth.toml",
    "privacy.toml",
    "network.toml",
    "recording.toml",
    "search.toml",
    "emulation.toml",
    "accessibility.toml",
    "session.toml",
    "captcha.toml",
    "pool.toml",
    "tor.toml",
    "scheduler.toml",
    "retry.toml",
];
