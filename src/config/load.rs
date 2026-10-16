//! KB-1 strict fail-closed loading.
//!
//! [`load_from_str`] never guesses: unknown keys, type mismatches, bad
//! versions and literal secrets become typed [`ConfigDiagnostic`]s with
//! reserved `E70xx` codes. The result ([`ConfigLoad`]) keeps **per-section**
//! outcomes so a strict failure refuses only the subsystem bound to the
//! affected section (parent decision D3, §7.3 rule 6):
//!
//! - `core` — root scalars (`schema_version`, `profile`, `format`, `no_color`,
//!   `telemetry`);
//! - `secrets` — the `[secrets]` table (reference-only values);
//! - any other top-level table (`[browser]`, …) is reported as a refusal for
//!   *that* subsystem only ([`ConfigLoad::unknown_sections`]) while core and
//!   secrets keep validating.
//!
//! An absent file is not an error: it yields in-memory defaults and —
//! critically — no file is created by loading.
//!
//! The kernel write path uses [`ConfigLoad::into_strict`]: a kernel-managed
//! artifact must be *strictly* clean (no diagnostics at all, foreign tables
//! included) before the kernel replaces it.

use std::fmt;
use std::path::{Path, PathBuf};

use toml::Value;

use crate::config::schema::{
    CODE_ARTIFACT, CODE_LITERAL_SECRET, CODE_READ_IO, CODE_SCHEMA_VERSION, CODE_TYPE_MISMATCH,
    CODE_UNKNOWN_KEY, Config, ConfigDiagnostic, ConfigError, ConfigSection, CoreSettings,
    EXPECTED_FORMAT, EXPECTED_PROFILE, OutputFormat, Profile, SCHEMA_VERSION, SCHEMA_VERSION_KEY,
    SECRETS_KEY, SecretRef, SecretSettings, SectionRefusal,
};

/// User config file name under the Tallow config directory.
pub const CONFIG_FILE_NAME: &str = "config.toml";
/// Tallow directory under the platform config dir.
pub const CONFIG_DIR_NAME: &str = "tallow";

/// Resolve `dirs::config_dir()/tallow/config.toml`.
///
/// A missing platform config directory is a refusal (`E7012`) — the kernel
/// never falls back to `"."` (U-202 anomaly A4: the old CLI silently wrote
/// `./tallow/config.toml`).
pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    let dir = dirs::config_dir().ok_or_else(|| ConfigError::PathUnresolved {
        what: "user config directory (dirs::config_dir())".to_string(),
    })?;
    Ok(dir.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME))
}

/// Outcome of validating one section (D3: a `Refused` section refuses only the
/// subsystem bound to it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionResult<T> {
    /// The section validated cleanly.
    Valid(T),
    /// The section has ≥1 diagnostics; see [`ConfigLoad::diagnostics`].
    Refused,
}

impl<T> SectionResult<T> {
    /// True when the section validated.
    pub fn is_valid(&self) -> bool {
        matches!(self, SectionResult::Valid(_))
    }

    /// The validated value, when the section is valid.
    pub fn valid(&self) -> Option<&T> {
        match self {
            SectionResult::Valid(v) => Some(v),
            SectionResult::Refused => None,
        }
    }
}

/// Result of loading one config artifact: sectioned, diagnostic-carrying,
/// never `panic`ing and never silently defaulting over a broken file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLoad {
    source: Option<PathBuf>,
    file_error: Option<ConfigError>,
    core: SectionResult<CoreSettings>,
    secrets: SectionResult<SecretSettings>,
    unknown_sections: Vec<String>,
    diagnostics: Vec<ConfigDiagnostic>,
}

impl ConfigLoad {
    /// In-memory defaults for an absent file. Loading defaults never creates
    /// or touches a file.
    pub fn defaults() -> Self {
        ConfigLoad {
            source: None,
            file_error: None,
            core: SectionResult::Valid(CoreSettings::default()),
            secrets: SectionResult::Valid(SecretSettings::default()),
            unknown_sections: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    fn refuse_all(source: Option<PathBuf>, error: ConfigError, diagnostic: ConfigDiagnostic) -> Self {
        ConfigLoad {
            source,
            file_error: Some(error),
            core: SectionResult::Refused,
            secrets: SectionResult::Refused,
            unknown_sections: Vec::new(),
            diagnostics: vec![diagnostic],
        }
    }

    /// Where the artifact came from (`None` for in-memory defaults).
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    /// File-level failure (syntax/read), if the artifact could not be parsed
    /// at all. When `Some`, every section is refused.
    pub fn file_error(&self) -> Option<&ConfigError> {
        self.file_error.as_ref()
    }

    /// Every diagnostic found, in deterministic (sorted) order.
    pub fn diagnostics(&self) -> &[ConfigDiagnostic] {
        &self.diagnostics
    }

    /// Top-level tables outside the KB-1 subset. Each previously caused an
    /// isolated `E7002` refusal for the subsystem that would consume it; core
    /// and secrets are unaffected (D3).
    pub fn unknown_sections(&self) -> &[String] {
        &self.unknown_sections
    }

    /// Raw core-section outcome.
    pub fn core_result(&self) -> &SectionResult<CoreSettings> {
        &self.core
    }

    /// Raw secrets-section outcome.
    pub fn secrets_result(&self) -> &SectionResult<SecretSettings> {
        &self.secrets
    }

    /// Core settings or a typed refusal scoped to the core subsystem (D3).
    pub fn core(&self) -> Result<&CoreSettings, SectionRefusal> {
        match &self.core {
            SectionResult::Valid(v) => Ok(v),
            SectionResult::Refused => Err(self.refusal_for(ConfigSection::Core)),
        }
    }

    /// Secret settings or a typed refusal scoped to the secrets subsystem (D3).
    pub fn secrets(&self) -> Result<&SecretSettings, SectionRefusal> {
        match &self.secrets {
            SectionResult::Valid(v) => Ok(v),
            SectionResult::Refused => Err(self.refusal_for(ConfigSection::Secrets)),
        }
    }

    /// All diagnostics for one section, gathered into a [`SectionRefusal`].
    pub fn refusal_for(&self, section: ConfigSection) -> SectionRefusal {
        let diagnostics: Vec<ConfigDiagnostic> = self
            .diagnostics
            .iter()
            .filter(|d| d.section == section)
            .cloned()
            .collect();
        SectionRefusal::new(section, diagnostics)
    }

    /// True when the KB-1-governed sections (core + secrets) validate. Foreign
    /// tables do not affect this (D3); they refuse their own subsystem.
    pub fn is_whole_file_valid(&self) -> bool {
        self.file_error.is_none() && self.core.is_valid() && self.secrets.is_valid()
    }

    /// True when *every* key in the artifact validated — no diagnostics at
    /// all, foreign tables included. This is the kernel write-path bar: the
    /// kernel only replaces a file it owns completely.
    pub fn is_strictly_valid(&self) -> bool {
        self.file_error.is_none() && self.diagnostics.is_empty()
    }

    /// The strict refusal for this artifact, if any (`None` when strictly valid).
    pub fn strict_error(&self) -> Option<ConfigError> {
        if self.is_strictly_valid() {
            return None;
        }
        if let Some(err) = &self.file_error {
            return Some(err.clone());
        }
        Some(self.aggregate_refusal())
    }

    fn aggregate_refusal(&self) -> ConfigError {
        // Deterministic: diagnostics were pushed in sorted key order, so the
        // first diagnostic names the section whose refusal dominates.
        let section = self
            .diagnostics
            .first()
            .map(|d| d.section.clone())
            .unwrap_or(ConfigSection::File);
        ConfigError::Refused(Box::new(self.refusal_for(section)))
    }

    /// Whole-artifact strict view: the typed [`Config`] when the file is
    /// strictly clean, else the typed refusal (file error first, then the
    /// dominant section refusal).
    pub fn into_strict(self) -> Result<Config, ConfigError> {
        if !self.is_strictly_valid() {
            return Err(self.strict_error().unwrap_or(ConfigError::Refused(Box::new(
                SectionRefusal::new(ConfigSection::File, Vec::new()),
            ))));
        }
        let core = match self.core {
            SectionResult::Valid(c) => c,
            // A section that is Refused while the whole artifact reads strictly
            // valid is a contradiction in `is_strictly_valid`. Return the coded
            // refusal instead of panicking: the caller gets a ConfigError, never a
            // crash in the middle of config resolution.
            SectionResult::Refused => {
                return Err(ConfigError::Refused(Box::new(SectionRefusal::new(
                    ConfigSection::Core,
                    Vec::new(),
                ))))
            }
        };
        let secrets = match self.secrets {
            SectionResult::Valid(s) => s,
            SectionResult::Refused => {
                return Err(ConfigError::Refused(Box::new(SectionRefusal::new(
                    ConfigSection::Secrets,
                    Vec::new(),
                ))))
            }
        };
        Ok(Config::from_sections(core, secrets))
    }
}

/// Parse + strictly validate one artifact string. Never fails: every issue is
/// a typed diagnostic on the returned [`ConfigLoad`].
pub fn load_from_str(text: &str, source: impl Into<Option<PathBuf>>) -> ConfigLoad {
    let source: Option<PathBuf> = source.into();

    // 1. Artifact-level: TOML syntax. A syntax error refuses the whole file.
    let table: toml::Table = match toml::from_str(text) {
        Ok(t) => t,
        Err(e) => {
            let message = format!(
                "{}{}",
                source
                    .as_ref()
                    .map(|p| format!("in {}: ", p.display()))
                    .unwrap_or_default(),
                e
            );
            let error = ConfigError::Artifact { message };
            let diagnostic = ConfigDiagnostic::new(
                CODE_ARTIFACT,
                ConfigSection::File,
                None,
                format!("artifact is not valid TOML: {}", e.message()),
            );
            return ConfigLoad::refuse_all(source, error, diagnostic);
        }
    };

    let mut diagnostics: Vec<ConfigDiagnostic> = Vec::new();
    let mut unknown_sections: Vec<String> = Vec::new();
    let mut core_ok = true;
    let mut secrets_ok = true;
    let mut core_settings = CoreSettings::default();
    let mut secret_settings = SecretSettings::default();

    // 2. Core scalars. `toml::Table` is BTreeMap-backed → sorted, deterministic
    // diagnostics.
    for (key, value) in table.iter() {
        match key.as_str() {
            SCHEMA_VERSION_KEY => {
                // Handled below in one place (a missing key is also a finding).
            }
            "profile" => match value.as_str().and_then(Profile::parse) {
                Some(p) => core_settings.profile = Some(p),
                None => {
                    core_ok = false;
                    diagnostics.push(ConfigDiagnostic::new(
                        CODE_TYPE_MISMATCH,
                        ConfigSection::Core,
                        Some(key.clone()),
                        format!(
                            "`profile` expects {EXPECTED_PROFILE}, found {}",
                            describe_value(value)
                        ),
                    ));
                }
            },
            "format" => match value.as_str().and_then(OutputFormat::parse) {
                Some(f) => core_settings.format = f,
                None => {
                    core_ok = false;
                    diagnostics.push(ConfigDiagnostic::new(
                        CODE_TYPE_MISMATCH,
                        ConfigSection::Core,
                        Some(key.clone()),
                        format!(
                            "`format` expects {EXPECTED_FORMAT}, found {}",
                            describe_value(value)
                        ),
                    ));
                }
            },
            "no_color" | "telemetry" => match value.as_bool() {
                Some(b) => {
                    if key == "no_color" {
                        core_settings.no_color = b;
                    } else {
                        core_settings.telemetry = b;
                    }
                }
                None => {
                    core_ok = false;
                    diagnostics.push(ConfigDiagnostic::new(
                        CODE_TYPE_MISMATCH,
                        ConfigSection::Core,
                        Some(key.clone()),
                        format!("`{key}` expects a boolean, found {}", describe_value(value)),
                    ));
                }
            },
            SECRETS_KEY => {
                // Handled in the secrets pass below.
            }
            _ => {
                if value.is_table() {
                    // Unknown *section*: refuse only its own subsystem (D3) —
                    // core and secrets keep validating.
                    unknown_sections.push(key.clone());
                    diagnostics.push(ConfigDiagnostic::new(
                        CODE_UNKNOWN_KEY,
                        ConfigSection::Other(key.clone()),
                        Some(key.clone()),
                        format!(
                            "unknown config table `{key}` — the `{key}` subsystem is refused (D3 isolation); \
                             core/secrets keys still validate"
                        ),
                    ));
                } else {
                    core_ok = false;
                    diagnostics.push(ConfigDiagnostic::new(
                        CODE_UNKNOWN_KEY,
                        ConfigSection::Core,
                        Some(key.clone()),
                        format!(
                            "unknown key `{key}` (strict config: unknown keys are refused, never ignored)"
                        ),
                    ));
                }
            }
        }
    }

    // 2a. Version gate (downgrade guard + migration boundary).
    match table.get(SCHEMA_VERSION_KEY) {
        None => {
            core_ok = false;
            diagnostics.push(ConfigDiagnostic::new(
                CODE_SCHEMA_VERSION,
                ConfigSection::Core,
                Some(SCHEMA_VERSION_KEY.to_string()),
                format!(
                    "missing required key `{SCHEMA_VERSION_KEY}` — every kernel artifact is versioned (KB-1)"
                ),
            ));
        }
        Some(value) => match value.as_integer() {
            None => {
                core_ok = false;
                diagnostics.push(ConfigDiagnostic::new(
                    CODE_SCHEMA_VERSION,
                    ConfigSection::Core,
                    Some(SCHEMA_VERSION_KEY.to_string()),
                    format!(
                        "`{SCHEMA_VERSION_KEY}` must be an integer, found {}",
                        describe_value(value)
                    ),
                ));
            }
            Some(n) => match u32::try_from(n) {
                Ok(0) | Err(_) => {
                    core_ok = false;
                    diagnostics.push(ConfigDiagnostic::new(
                        CODE_SCHEMA_VERSION,
                        ConfigSection::Core,
                        Some(SCHEMA_VERSION_KEY.to_string()),
                        format!("`{SCHEMA_VERSION_KEY}` {n} is not a valid version (must be >= 1)"),
                    ));
                }
                Ok(v) if v > SCHEMA_VERSION => {
                    core_ok = false;
                    diagnostics.push(ConfigDiagnostic::new(
                        CODE_SCHEMA_VERSION,
                        ConfigSection::Core,
                        Some(SCHEMA_VERSION_KEY.to_string()),
                        format!(
                            "`{SCHEMA_VERSION_KEY}` {v} is newer than this kernel supports ({SCHEMA_VERSION}) — \
                             refusing (downgrade guard): upgrade tallow or remove the key"
                        ),
                    ));
                }
                Ok(v) if v < SCHEMA_VERSION => {
                    core_ok = false;
                    diagnostics.push(ConfigDiagnostic::new(
                        CODE_SCHEMA_VERSION,
                        ConfigSection::Core,
                        Some(SCHEMA_VERSION_KEY.to_string()),
                        format!(
                            "`{SCHEMA_VERSION_KEY}` {v} predates the current schema ({SCHEMA_VERSION}) and no \
                             migration is registered (KB-3) — refusing instead of guessing"
                        ),
                    ));
                }
                Ok(v) => core_settings.schema_version = v,
            },
        },
    }

    // 3. Secrets section: reference-only, no recursion.
    match table.get(SECRETS_KEY) {
        None => {}
        Some(value) => match value.as_table() {
            None => {
                secrets_ok = false;
                diagnostics.push(ConfigDiagnostic::new(
                    CODE_TYPE_MISMATCH,
                    ConfigSection::Secrets,
                    Some(SECRETS_KEY.to_string()),
                    format!(
                        "`{SECRETS_KEY}` must be a table of secret references, found {}",
                        describe_value(value)
                    ),
                ));
            }
            Some(entries) => {
                for (name, entry) in entries.iter() {
                    let path = format!("{SECRETS_KEY}.{name}");
                    match entry.as_str() {
                        None => {
                            secrets_ok = false;
                            diagnostics.push(ConfigDiagnostic::new(
                                CODE_TYPE_MISMATCH,
                                ConfigSection::Secrets,
                                Some(path.clone()),
                                format!(
                                    "`{path}` expects a secret reference string (`env:NAME`, `file:PATH`, `vault://…`), found {}",
                                    describe_value(entry)
                                ),
                            ));
                        }
                        Some(raw) => match SecretRef::parse(raw, &path) {
                            Ok(reference) => {
                                secret_settings.entries.insert(name.clone(), reference);
                            }
                            Err(e) => {
                                secrets_ok = false;
                                // The parse error never echoes the value; reuse its
                                // typed detail in the diagnostic.
                                diagnostics.push(ConfigDiagnostic::new(
                                    e.code(),
                                    ConfigSection::Secrets,
                                    Some(path),
                                    e.to_string(),
                                ));
                            }
                        },
                    }
                }
            }
        },
    }

    ConfigLoad {
        source,
        file_error: None,
        core: if core_ok {
            SectionResult::Valid(core_settings)
        } else {
            SectionResult::Refused
        },
        secrets: if secrets_ok {
            SectionResult::Valid(secret_settings)
        } else {
            SectionResult::Refused
        },
        unknown_sections,
        diagnostics,
    }
}

/// Load a config file. An absent file is *not* an error: defaults are
/// returned and no file is created. Other read failures refuse everything
/// with `E7006`.
pub fn load_file(path: &Path) -> ConfigLoad {
    match std::fs::read_to_string(path) {
        Ok(text) => load_from_str(&text, Some(path.to_path_buf())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ConfigLoad::defaults(),
        Err(e) => {
            let error = ConfigError::Read {
                path: path.to_path_buf(),
                message: e.to_string(),
            };
            let diagnostic = ConfigDiagnostic::new(
                CODE_READ_IO,
                ConfigSection::File,
                None,
                format!("cannot read {}: {e}", path.display()),
            );
            ConfigLoad::refuse_all(Some(path.to_path_buf()), error, diagnostic)
        }
    }
}

/// Load the default user config (`dirs::config_dir()/tallow/config.toml`).
/// Path resolution failures are hard errors (`E7012`) — never a silent `"."`.
pub fn load_default() -> Result<ConfigLoad, ConfigError> {
    let path = default_config_path()?;
    Ok(load_file(&path))
}

/// Human description of a TOML value's kind (never its content — secret-adjacent
/// keys must not leak values into diagnostics).
fn describe_value(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "a string",
        Value::Integer(_) => "an integer",
        Value::Float(_) => "a float",
        Value::Boolean(_) => "a boolean",
        Value::Datetime(_) => "a datetime",
        Value::Array(_) => "an array",
        Value::Table(_) => "a table",
    }
}

impl fmt::Display for ConfigLoad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "config load ({}): core={}, secrets={}, {} diagnostic(s)",
            self.source
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "in-memory defaults".to_string()),
            if self.core.is_valid() { "valid" } else { "refused" },
            if self.secrets.is_valid() {
                "valid"
            } else {
                "refused"
            },
            self.diagnostics.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{CODE_PATH_UNRESOLVED, SecretRef};

    const CLEAN: &str = r#"
schema_version = 1
profile = "privacy"
format = "json"
no_color = true
telemetry = false

[secrets]
registry_token = "env:TALLOW_REGISTRY_TOKEN"
keyfile = "file:/run/secrets/tallow-key"
"#;

    #[test]
    fn absent_file_is_defaults_and_creates_nothing() {
        let tmp = crate::config::test_support::TempDir::new("absent");
        let path = tmp.join("config.toml");
        let loaded = load_file(&path);
        assert!(loaded.is_whole_file_valid(), "{loaded}");
        assert!(loaded.is_strictly_valid());
        assert!(loaded.source().is_none(), "no artifact → no source");
        assert!(loaded.file_error().is_none());
        assert_eq!(loaded.core().unwrap(), &CoreSettings::default());
        assert!(loaded.secrets().unwrap().entries.is_empty());
        assert!(!path.exists(), "loading must never create the file");
        assert_eq!(loaded.diagnostics(), &[]);
    }

    #[test]
    fn clean_file_validates_sections() {
        let loaded = load_from_str(CLEAN, None);
        assert!(loaded.is_strictly_valid(), "{loaded}");
        let core = loaded.core().expect("core valid");
        assert_eq!(core.schema_version, SCHEMA_VERSION);
        assert_eq!(core.profile, Some(Profile::Privacy));
        assert_eq!(core.format, OutputFormat::Json);
        assert!(core.no_color);
        let secrets = loaded.secrets().expect("secrets valid");
        assert_eq!(secrets.entries.len(), 2);
        assert_eq!(
            secrets.entries["registry_token"],
            SecretRef::Env {
                name: "TALLOW_REGISTRY_TOKEN".to_string()
            }
        );
        // Strict round-trip through the whole-file typed view.
        let cfg = loaded.into_strict().expect("strict");
        let text = cfg.to_toml_string().expect("serialize");
        let back = Config::from_toml_str_strict(&text).expect("strict parse");
        assert_eq!(cfg, back);
    }

    #[test]
    fn unknown_root_key_refuses_core_only_naming_key() {
        let loaded = load_from_str("schema_version = 1\ntelemetri = true\n", None);
        assert!(!loaded.core_result().is_valid());
        assert!(loaded.secrets_result().is_valid(), "secrets unaffected");
        assert!(!loaded.is_whole_file_valid());
        let refusal = loaded.core().expect_err("core refused");
        assert_eq!(refusal.codes(), vec![CODE_UNKNOWN_KEY]);
        assert!(
            refusal.to_string().contains("telemetri"),
            "refusal must name the key: {refusal}"
        );
        assert!(
            loaded
                .diagnostics()
                .iter()
                .any(|d| d.key.as_deref() == Some("telemetri") && d.code == CODE_UNKNOWN_KEY)
        );
    }

    #[test]
    fn wrong_type_refuses_core_with_typed_code() {
        let loaded = load_from_str("schema_version = 1\nno_color = \"yes\"\n", None);
        let refusal = loaded.core().expect_err("core refused");
        assert_eq!(refusal.codes(), vec![CODE_TYPE_MISMATCH]);
        assert!(refusal.to_string().contains("no_color"), "{refusal}");
        assert!(refusal.to_string().contains("a boolean"), "{refusal}");
    }

    #[test]
    fn bad_enum_word_refuses_core() {
        for (key, raw) in [("profile", "stealth"), ("format", "yaml")] {
            let loaded = load_from_str(&format!("schema_version = 1\n{key} = \"{raw}\"\n"), None);
            let refusal = loaded.core().expect_err(key);
            assert_eq!(refusal.codes(), vec![CODE_TYPE_MISMATCH], "{key}");
            assert!(refusal.to_string().contains(key), "{refusal}");
        }
    }

    #[test]
    fn version_newer_refused_downgrade_guard() {
        let loaded = load_from_str("schema_version = 99\n", None);
        let refusal = loaded.core().expect_err("version gate");
        assert_eq!(refusal.codes(), vec![CODE_SCHEMA_VERSION]);
        assert!(refusal.to_string().contains("99"), "{refusal}");
        assert!(refusal.to_string().contains("newer"), "{refusal}");
    }

    #[test]
    fn version_missing_refused() {
        let loaded = load_from_str("telemetry = false\n", None);
        let refusal = loaded.core().expect_err("missing version");
        assert_eq!(refusal.codes(), vec![CODE_SCHEMA_VERSION]);
        assert!(refusal.to_string().contains("schema_version"), "{refusal}");
    }

    #[test]
    fn version_zero_and_wrong_kind_refused() {
        for raw in ["0", "\"1\"", "1.5", "-3"] {
            let loaded = load_from_str(&format!("schema_version = {raw}\n"), None);
            let refusal = loaded.core().expect_err(raw);
            assert_eq!(refusal.codes(), vec![CODE_SCHEMA_VERSION], "raw={raw}");
        }
    }

    #[test]
    fn older_version_refused_without_migration() {
        // Only v0 can be "older" today; it is also invalid, so the gate fires
        // with the not-a-valid-version message. Pin the code either way.
        let loaded = load_from_str("schema_version = 0\n", None);
        assert_eq!(
            loaded.core().expect_err("gate").codes(),
            vec![CODE_SCHEMA_VERSION]
        );
    }

    #[test]
    fn foreign_table_refused_in_isolation() {
        let loaded = load_from_str(
            "schema_version = 1\n\n[browser]\nnav_timeout_ms = 10\n",
            None,
        );
        assert!(loaded.core_result().is_valid(), "core untouched (D3)");
        assert!(loaded.secrets_result().is_valid(), "secrets untouched (D3)");
        assert_eq!(loaded.unknown_sections(), &["browser".to_string()]);
        let refusal = loaded.refusal_for(ConfigSection::Other("browser".to_string()));
        assert_eq!(refusal.codes(), vec![CODE_UNKNOWN_KEY]);
        assert!(
            loaded.diagnostics().iter().any(|d| d.section
                == ConfigSection::Other("browser".to_string())),
            "diagnostic carries the subsystem section"
        );
        // But the kernel write path requires strict cleanliness.
        assert!(!loaded.is_strictly_valid());
        assert!(loaded.into_strict().is_err());
    }

    #[test]
    fn two_foreign_tables_are_named_individually() {
        let loaded = load_from_str(
            "schema_version = 1\n\n[zeta]\nx = 1\n\n[alpha]\ny = 2\n",
            None,
        );
        assert!(loaded.core_result().is_valid());
        // BTreeMap-backed tables and sorted iteration → deterministic order.
        assert_eq!(loaded.unknown_sections(), &["alpha".to_string(), "zeta".to_string()]);
        assert_eq!(loaded.diagnostics().len(), 2);
    }

    #[test]
    fn literal_secret_refuses_secrets_section_only_and_never_echoes() {
        let loaded = load_from_str(
            "schema_version = 1\n[secrets]\napi_key = \"hunter2\"\n",
            None,
        );
        assert!(loaded.core_result().is_valid(), "core unaffected (D3)");
        let refusal = loaded.secrets().expect_err("secrets refused");
        assert_eq!(refusal.codes(), vec![CODE_LITERAL_SECRET]);
        let text = refusal.to_string();
        assert!(text.contains("secrets.api_key"), "{text}");
        assert!(!text.contains("hunter2"), "never echo secret material: {text}");
    }

    #[test]
    fn secret_entry_wrong_type_refused() {
        let loaded = load_from_str("schema_version = 1\n[secrets]\ntok = 42\n", None);
        let refusal = loaded.secrets().expect_err("secrets refused");
        assert_eq!(refusal.codes(), vec![CODE_TYPE_MISMATCH]);
        assert!(refusal.to_string().contains("secrets.tok"), "{refusal}");
    }

    #[test]
    fn secrets_key_not_a_table_refused() {
        let loaded = load_from_str("schema_version = 1\nsecrets = \"nope\"\n", None);
        let refusal = loaded.secrets().expect_err("secrets refused");
        assert_eq!(refusal.codes(), vec![CODE_TYPE_MISMATCH]);
    }

    #[test]
    fn syntax_error_refuses_whole_file() {
        let loaded = load_from_str("schema_version = [1,\n", Some(PathBuf::from("/x/config.toml")));
        assert!(!loaded.is_whole_file_valid());
        assert!(loaded.core_result().is_valid() == false);
        assert!(loaded.secrets_result().is_valid() == false);
        assert_eq!(loaded.file_error().expect("file error").code(), CODE_ARTIFACT);
        assert_eq!(loaded.diagnostics().len(), 1);
        assert_eq!(loaded.diagnostics()[0].section, ConfigSection::File);
        assert!(loaded.into_strict().is_err());
    }

    #[test]
    fn read_error_refuses_whole_file() {
        let tmp = crate::config::test_support::TempDir::new("readdir");
        let dir = tmp.join("config.toml");
        std::fs::create_dir(&dir).expect("make dir in place of file");
        let loaded = load_file(&dir);
        assert_eq!(loaded.file_error().expect("read error").code(), CODE_READ_IO);
        assert!(loaded.core().is_err());
    }

    #[test]
    fn multiple_findings_are_all_reported_deterministically() {
        let text = "schema_version = 1\ntypo_b = 1\ntypo_a = 2\nno_color = \"x\"\n[secrets]\nk = \"lit\"\n";
        let a = load_from_str(text, None);
        let b = load_from_str(text, None);
        assert_eq!(a.diagnostics(), b.diagnostics(), "deterministic");
        let codes: Vec<&str> = a.diagnostics().iter().map(|d| d.code).collect();
        // Sorted root keys → typo_a, no_color issues? no: typo_a/typo_b unknown,
        // no_color type, secrets literal — all four findings present.
        assert!(codes.contains(&CODE_UNKNOWN_KEY));
        assert!(codes.contains(&CODE_TYPE_MISMATCH));
        assert!(codes.contains(&CODE_LITERAL_SECRET));
        assert_eq!(a.diagnostics().len(), 4);
        let keys: Vec<&str> = a
            .diagnostics()
            .iter()
            .filter(|d| d.code == CODE_UNKNOWN_KEY)
            .map(|d| d.key.as_deref().unwrap())
            .collect();
        assert_eq!(keys, vec!["typo_a", "typo_b"], "sorted key order");
    }

    #[test]
    fn defaults_are_secure_in_memory() {
        let c = CoreSettings::default();
        assert_eq!(c.schema_version, SCHEMA_VERSION);
        assert_eq!(c.profile, None);
        assert_eq!(c.format, OutputFormat::Text);
        assert!(!c.no_color);
        assert!(!c.telemetry, "telemetry defaults off (§7.5.1)");
        let cfg = Config::default();
        assert!(!cfg.has_secret_values());
    }

    #[test]
    fn default_config_path_is_absolute_and_typed_on_failure() {
        match default_config_path() {
            Ok(p) => {
                assert!(p.is_absolute(), "{p:?}");
                assert!(p.ends_with("tallow/config.toml"), "{p:?}");
            }
            Err(e) => assert_eq!(e.code(), CODE_PATH_UNRESOLVED),
        }
        // The A4 fix: never a `"."` fallback.
        if let Ok(p) = default_config_path() {
            assert!(!p.to_string_lossy().starts_with("./"));
        }
    }

    #[test]
    fn load_default_never_panics_and_is_typed() {
        match load_default() {
            Ok(loaded) => {
                // Whatever the developer's box holds, the result is a typed
                // verdict, never a guess.
                let _ = loaded.strict_error();
            }
            Err(e) => assert_eq!(e.code(), CODE_PATH_UNRESOLVED),
        }
    }

    #[test]
    fn core_settings_projection_matches_tree() {
        let cfg = Config {
            schema_version: 1,
            profile: Some(Profile::Server),
            format: OutputFormat::Json,
            no_color: true,
            telemetry: true,
            secrets: Default::default(),
        };
        assert_eq!(cfg.core_settings().schema_version, 1);
        assert_eq!(cfg.core_settings().profile, Some(Profile::Server));
        let rebuilt = Config::from_sections(cfg.core_settings(), cfg.secret_settings());
        assert_eq!(cfg, rebuilt);
    }
}
