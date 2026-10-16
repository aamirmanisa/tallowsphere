//! Auto-Type — process credential entry sequences for automated typing.
//! Sequences like: {USERNAME}{TAB}{PASSWORD}{ENTER}
//! Supports: {DELAY N}, {CLEARFIELD}, custom sequences per entry.
//!
//! # Desktop input backend
//!
//! [`execute_keystrokes`] / [`run_autotype`] inject a processed plan on the
//! live desktop through `xdotool` (X11 / XWayland). Invocation is explicit
//! only — nothing here runs on program start — and when the backend is
//! absent the executor returns an honest `Err` instead of simulating input.
//! Secret-derived text is always fed to subprocesses via stdin (never argv,
//! which every local process can read), and `Debug` for [`AutoTypeResult`] /
//! [`Keystroke`] is hand-written to redact values (see
//! `docs/ops/zeroization.md`, `docs/ops/autotype-backend.md`).
//!
//! Status: library-only. No CLI command drives the executor yet — the
//! `vault auto-type` arm prints the plan (`src/main.rs`, owned elsewhere).

use super::entry::{EntryData, VaultEntry};
use serde::{Deserialize, Serialize};
use std::fmt;

// ── Types ───────────────────────────────────────────────────────────────────

/// A parsed auto-type action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AutoTypeAction {
    TypeText(String),
    TypeUsername,
    TypePassword,
    TypeTotp,
    TypeUrl,
    TypeCustomField(String),
    PressTab,
    PressEnter,
    PressEscape,
    Delay(u32),
    ClearField,
}

/// A complete auto-type sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTypeSequence {
    pub actions: Vec<AutoTypeAction>,
    pub window_match: Option<String>,
}

/// Result of processing an auto-type sequence against an entry.
///
/// `Debug` is hand-written (not derived): the keystroke vector is
/// secret-derived (typed passwords, clipboard chunks) and must never reach
/// logs or panic messages — see `docs/ops/zeroization.md`.
#[derive(Clone, Serialize, Deserialize)]
pub struct AutoTypeResult {
    pub keystrokes: Vec<Keystroke>,
    pub total_chars: usize,
    pub has_delay: bool,
}

/// A single keystroke event.
///
/// `Debug` is hand-written (not derived): `type` / `clipboard_paste` values
/// are secret-derived and print as a redacted length only; `key` names and
/// `delay` values are structural metadata and print normally.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Keystroke {
    pub action: String, // "type", "key", "delay"
    pub value: String,  // text to type, key name, or delay ms
}

impl fmt::Debug for Keystroke {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.action.as_str() {
            // Structural metadata only — never secret-bearing.
            "key" | "delay" => write!(
                f,
                "Keystroke {{ action: {:?}, value: {:?} }}",
                self.action, self.value
            ),
            // Everything else (notably "type" and "clipboard_paste") carries
            // secret-derived text; print a redacted byte count, mirroring
            // `SecretBytes`' convention in `crate::zeroize_util`.
            _ => write!(
                f,
                "Keystroke {{ action: {:?}, value: [redacted; {} bytes] }}",
                self.action,
                self.value.len()
            ),
        }
    }
}

impl fmt::Debug for AutoTypeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the keystroke vector: it holds typed passwords and
        // clipboard chunks. Counts and flags only.
        write!(
            f,
            "AutoTypeResult {{ keystrokes: [redacted; {} items], total_chars: {}, has_delay: {} }}",
            self.keystrokes.len(),
            self.total_chars,
            self.has_delay
        )
    }
}

// ── Parsing ─────────────────────────────────────────────────────────────────

/// Parse a pattern string like "{USERNAME}{TAB}{PASSWORD}{ENTER}" into actions.
///
/// Supported placeholders:
///   {USERNAME}, {PASSWORD}, {TOTP}, {URL}, {TITLE}, {NOTES},
///   {TAB}, {ENTER}, {ESCAPE}, {DELAY N}, {CLEARFIELD}, {FIELD:name}
///
/// Any text outside braces is treated as literal TypeText.
pub fn parse_sequence(pattern: &str) -> Result<AutoTypeSequence, String> {
    let mut actions = Vec::new();
    let mut chars = pattern.chars().peekable();
    let mut text_buf = String::new();

    while let Some(&ch) = chars.peek() {
        if ch == '{' {
            // Flush any accumulated literal text
            if !text_buf.is_empty() {
                actions.push(AutoTypeAction::TypeText(text_buf.clone()));
                text_buf.clear();
            }

            chars.next(); // consume '{'
            let mut placeholder = String::new();
            let mut found_close = false;
            for c in chars.by_ref() {
                if c == '}' {
                    found_close = true;
                    break;
                }
                placeholder.push(c);
            }
            if !found_close {
                return Err(format!("unclosed placeholder '{{{placeholder}'"));
            }

            let upper = placeholder.to_uppercase();
            let action = if upper == "USERNAME" {
                AutoTypeAction::TypeUsername
            } else if upper == "PASSWORD" {
                AutoTypeAction::TypePassword
            } else if upper == "TOTP" {
                AutoTypeAction::TypeTotp
            } else if upper == "URL" {
                AutoTypeAction::TypeUrl
            } else if upper == "TAB" {
                AutoTypeAction::PressTab
            } else if upper == "ENTER" {
                AutoTypeAction::PressEnter
            } else if upper == "ESCAPE" {
                AutoTypeAction::PressEscape
            } else if upper == "CLEARFIELD" {
                AutoTypeAction::ClearField
            } else if upper == "TITLE" || upper == "NOTES" {
                // Title/Notes are resolved from the entry at processing time
                AutoTypeAction::TypeCustomField(upper.to_lowercase())
            } else if upper.starts_with("DELAY ") || upper.starts_with("DELAY\t") {
                let ms_str = placeholder[6..].trim();
                let ms: u32 = ms_str
                    .parse()
                    .map_err(|_| format!("invalid delay value: '{ms_str}'"))?;
                AutoTypeAction::Delay(ms)
            } else if upper.starts_with("FIELD:") {
                let field_name = placeholder[6..].to_string();
                if field_name.is_empty() {
                    return Err("empty field name in {FIELD:}".into());
                }
                AutoTypeAction::TypeCustomField(field_name)
            } else {
                return Err(format!("unknown placeholder: '{{{placeholder}}}'"));
            };
            actions.push(action);
        } else {
            text_buf.push(ch);
            chars.next();
        }
    }

    // Flush trailing literal text
    if !text_buf.is_empty() {
        actions.push(AutoTypeAction::TypeText(text_buf));
    }

    Ok(AutoTypeSequence {
        actions,
        window_match: None,
    })
}

/// Returns the default auto-type sequence: {USERNAME}{TAB}{PASSWORD}{ENTER}.
pub fn default_sequence() -> AutoTypeSequence {
    AutoTypeSequence {
        actions: vec![
            AutoTypeAction::TypeUsername,
            AutoTypeAction::PressTab,
            AutoTypeAction::TypePassword,
            AutoTypeAction::PressEnter,
        ],
        window_match: None,
    }
}

// ── Processing ──────────────────────────────────────────────────────────────

/// Resolve placeholders against a VaultEntry and produce keystrokes.
pub fn process_sequence(
    seq: &AutoTypeSequence,
    entry: &VaultEntry,
) -> Result<AutoTypeResult, String> {
    let mut keystrokes = Vec::new();
    let mut total_chars = 0usize;
    let mut has_delay = false;

    // Extract login data fields (fall back to empty strings for non-login entries)
    let (username, password, urls, totp_secret) = match &entry.data {
        EntryData::Login(d) => (
            d.username.clone(),
            d.password.clone(),
            d.urls.clone(),
            d.totp_secret.clone(),
        ),
        _ => (String::new(), String::new(), Vec::new(), None),
    };

    for action in &seq.actions {
        match action {
            AutoTypeAction::TypeText(text) => {
                total_chars += text.len();
                keystrokes.push(Keystroke {
                    action: "type".into(),
                    value: text.clone(),
                });
            }
            AutoTypeAction::TypeUsername => {
                total_chars += username.len();
                keystrokes.push(Keystroke {
                    action: "type".into(),
                    value: username.clone(),
                });
            }
            AutoTypeAction::TypePassword => {
                total_chars += password.len();
                keystrokes.push(Keystroke {
                    action: "type".into(),
                    value: password.clone(),
                });
            }
            AutoTypeAction::TypeTotp => {
                if let Some(secret) = totp_secret.as_deref() {
                    let digits = match &entry.data {
                        EntryData::Login(d) => d.totp_digits.unwrap_or(6),
                        _ => 6,
                    };
                    let period = match &entry.data {
                        EntryData::Login(d) => d.totp_period.unwrap_or(30),
                        _ => 30,
                    };
                    let algorithm = match &entry.data {
                        EntryData::Login(d) => d.totp_algorithm.as_deref().unwrap_or("SHA1"),
                        _ => "SHA1",
                    };
                    match super::totp::generate_totp(secret, digits, period, algorithm) {
                        Ok(code) => {
                            total_chars += code.len();
                            keystrokes.push(Keystroke {
                                action: "type".into(),
                                value: code,
                            });
                        }
                        Err(e) => {
                            return Err(format!("TOTP generation failed: {e}"));
                        }
                    }
                } else {
                    return Err("No TOTP secret configured for this entry".into());
                }
            }
            AutoTypeAction::TypeUrl => {
                let url = urls.first().cloned().unwrap_or_default();
                total_chars += url.len();
                keystrokes.push(Keystroke {
                    action: "type".into(),
                    value: url,
                });
            }
            AutoTypeAction::TypeCustomField(name) => {
                let lower = name.to_lowercase();
                let value = if lower == "title" {
                    entry.name.clone()
                } else if lower == "notes" {
                    entry.notes.clone().unwrap_or_default()
                } else {
                    // Look up in custom_fields
                    entry
                        .custom_fields
                        .iter()
                        .find(|f| f.name.eq_ignore_ascii_case(name))
                        .map(|f| f.value.clone())
                        .unwrap_or_default()
                };
                total_chars += value.len();
                keystrokes.push(Keystroke {
                    action: "type".into(),
                    value,
                });
            }
            AutoTypeAction::PressTab => {
                keystrokes.push(Keystroke {
                    action: "key".into(),
                    value: "Tab".into(),
                });
            }
            AutoTypeAction::PressEnter => {
                keystrokes.push(Keystroke {
                    action: "key".into(),
                    value: "Enter".into(),
                });
            }
            AutoTypeAction::PressEscape => {
                keystrokes.push(Keystroke {
                    action: "key".into(),
                    value: "Escape".into(),
                });
            }
            AutoTypeAction::Delay(ms) => {
                has_delay = true;
                keystrokes.push(Keystroke {
                    action: "delay".into(),
                    value: ms.to_string(),
                });
            }
            AutoTypeAction::ClearField => {
                // Ctrl+A then Delete — select all and clear
                keystrokes.push(Keystroke {
                    action: "key".into(),
                    value: "Ctrl+A".into(),
                });
                keystrokes.push(Keystroke {
                    action: "key".into(),
                    value: "Delete".into(),
                });
            }
        }
    }

    Ok(AutoTypeResult {
        keystrokes,
        total_chars,
        has_delay,
    })
}

// ── Window Matching ─────────────────────────────────────────────────────────

/// Match a window title against a pattern.
///
/// - Patterns starting and ending with `/` are treated as regex.
/// - Otherwise, `*` wildcards are supported (case-insensitive).
pub fn match_window_title(title: &str, pattern: &str) -> bool {
    // Regex mode: /pattern/
    if pattern.len() >= 2 && pattern.starts_with('/') && pattern.ends_with('/') {
        let regex_str = &pattern[1..pattern.len() - 1];
        if let Ok(re) = regex::Regex::new(regex_str) {
            return re.is_match(title);
        }
        return false;
    }

    // Wildcard mode: convert * to regex .*, case-insensitive
    let title_lower = title.to_lowercase();
    let pattern_lower = pattern.to_lowercase();

    // Split on * and check that the parts appear in order
    let parts: Vec<&str> = pattern_lower.split('*').collect();
    if parts.len() == 1 {
        // No wildcard — exact match (case-insensitive)
        return title_lower == pattern_lower;
    }

    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // First part must appear at the start
            if !title_lower.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Last part must appear at the end
            if !title_lower[pos..].ends_with(part) {
                return false;
            }
        } else {
            // Middle part — must appear somewhere after pos
            if let Some(found) = title_lower[pos..].find(part) {
                pos += found + part.len();
            } else {
                return false;
            }
        }
    }
    true
}

/// Find vault entries whose URL domain matches the given window title.
/// Extracts domains from login entry URLs and checks if any appear in the title.
pub fn find_matching_entry<'a>(
    entries: &'a [VaultEntry],
    window_title: &str,
) -> Vec<&'a VaultEntry> {
    let title_lower = window_title.to_lowercase();
    entries
        .iter()
        .filter(|entry| {
            if let EntryData::Login(login) = &entry.data {
                for url_str in &login.urls {
                    // Extract domain from URL
                    if let Some(domain) = extract_domain(url_str) {
                        let domain_lower = domain.to_lowercase();
                        // Strip leading "www."
                        let bare = domain_lower.strip_prefix("www.").unwrap_or(&domain_lower);
                        if title_lower.contains(bare) {
                            return true;
                        }
                        // Also try matching just the domain name without TLD
                        // e.g. "github.com" -> "github", "gitlab.co.uk" -> "gitlab"
                        if let Some(name) = bare.split('.').next() {
                            if !name.is_empty() && name.len() >= 3 && title_lower.contains(name) {
                                return true;
                            }
                        }
                    }
                }
            }
            false
        })
        .collect()
}

/// Extract the domain from a URL string (best-effort, no url crate needed).
fn extract_domain(url: &str) -> Option<String> {
    let s = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = s.split('/').next()?;
    let host = host.split(':').next()?; // remove port
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

// ── Obfuscation (Anti-Keylogger) ────────────────────────────────────────────

/// Two-channel obfuscation: split typing into two interleaved streams.
///
/// The password text in "type" keystrokes is split into random chunks.
/// Odd chunks go into stream A, even chunks into stream B, each interspersed
/// with clipboard-paste operations. Neither stream alone reveals the full password.
///
/// Returns exactly 2 AutoTypeResult streams that, when executed together
/// on the same text field, produce the original text.
pub fn obfuscate_keystrokes(result: &AutoTypeResult) -> Vec<AutoTypeResult> {
    use rand::Rng;
    let mut rng = rand::rng();

    let mut stream_a = Vec::new();
    let mut stream_b = Vec::new();
    let mut total_a = 0usize;
    let mut total_b = 0usize;

    for ks in &result.keystrokes {
        if ks.action == "type" && !ks.value.is_empty() {
            // Split the value into random-length chunks
            let text = &ks.value;
            let mut offset = 0;
            let mut chunk_index = 0u32;
            while offset < text.len() {
                let remaining = text.len() - offset;
                let chunk_len = if remaining <= 3 {
                    remaining
                } else {
                    rng.random_range(1..=remaining.min(5))
                };
                let chunk = &text[offset..offset + chunk_len];
                offset += chunk_len;

                // Alternate chunks between streams
                let keystroke = Keystroke {
                    action: "clipboard_paste".into(),
                    value: chunk.to_string(),
                };
                if chunk_index % 2 == 0 {
                    total_a += chunk.len();
                    stream_a.push(keystroke);
                } else {
                    total_b += chunk.len();
                    stream_b.push(keystroke);
                }
                chunk_index += 1;
            }
        } else {
            // Non-text keystrokes go into both streams
            stream_a.push(ks.clone());
            stream_b.push(ks.clone());
        }
    }

    vec![
        AutoTypeResult {
            keystrokes: stream_a,
            total_chars: total_a,
            has_delay: result.has_delay,
        },
        AutoTypeResult {
            keystrokes: stream_b,
            total_chars: total_b,
            has_delay: result.has_delay,
        },
    ]
}

// ── Desktop Input Execution ────────────────────────────────────────────────

/// Outcome of one desktop-input subprocess invocation — the subset the
/// executor consumes (`status.success()` + stderr for diagnostics).
struct RunnerOutput {
    success: bool,
    stderr: Vec<u8>,
}

/// Minimal injectable seam for the desktop-input subprocess backend.
///
/// Production always uses [`ShellRunner`]; tests inject a recording mock so
/// execution order, argv/stdin placement, and error shaping are verifiable
/// without a live X11 session. The seam sits at the process boundary, so the
/// code exercised by tests is the same code that runs in production.
trait CommandRunner {
    /// Run `program` with `args`, optionally feeding `stdin_bytes` to the
    /// child's stdin (used so secret text never appears in argv / `ps`).
    fn run(
        &mut self,
        program: &str,
        args: &[&str],
        stdin_bytes: Option<&[u8]>,
    ) -> std::io::Result<RunnerOutput>;
}

/// Production runner: executes real subprocesses.
struct ShellRunner;

impl CommandRunner for ShellRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[&str],
        stdin_bytes: Option<&[u8]>,
    ) -> std::io::Result<RunnerOutput> {
        match stdin_bytes {
            None => {
                let out = std::process::Command::new(program).args(args).output()?;
                Ok(RunnerOutput {
                    success: out.status.success(),
                    stderr: out.stderr,
                })
            }
            Some(bytes) => {
                use std::io::Write;
                let mut child = std::process::Command::new(program)
                    .args(args)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;
                if let Some(mut pipe) = child.stdin.take() {
                    let _ = pipe.write_all(bytes);
                }
                let out = child.wait_with_output()?;
                Ok(RunnerOutput {
                    success: out.status.success(),
                    stderr: out.stderr,
                })
            }
        }
    }
}

/// Check whether the `xdotool` desktop-automation binary is available,
/// probing through the given runner (tests simulate a missing backend with a
/// mock; production uses [`ShellRunner`]).
fn xdotool_available_with(runner: &mut dyn CommandRunner) -> Result<(), String> {
    match runner.run("xdotool", &["--version"], None) {
        Ok(out) if out.success => Ok(()),
        Ok(_) => Err("autotype requires desktop input backend 'xdotool' — xdotool reported an error (is X11 available?)".into()),
        Err(e) => Err(format!(
            "autotype requires desktop input backend 'xdotool' — not available: {e}"
        )),
    }
}

/// Check whether the `xdotool` desktop-automation binary is available.
///
/// Returns an honest `Err` when the backend is missing (e.g. no X11 tooling
/// installed, or a Wayland-only session where xdotool cannot inject input).
pub fn xdotool_available() -> Result<(), String> {
    xdotool_available_with(&mut ShellRunner)
}

/// Map a keystroke `key` name to an xdotool key sequence.
///
/// Accepts the names produced by `process_sequence` (Tab, Enter, Escape,
/// Ctrl+A, Delete) plus any xdotool key name (e.g. "Return", "ctrl+shift+t").
fn map_key_name(key: &str) -> String {
    match key {
        "Tab" => "Tab".to_string(),
        "Enter" => "Return".to_string(),
        "Escape" => "Escape".to_string(),
        "Delete" => "Delete".to_string(),
        "Ctrl+A" => "ctrl+a".to_string(),
        other => other.to_lowercase(),
    }
}

/// Execute a keystroke plan on the live desktop via `xdotool`.
///
/// This is the REAL input-injection backend: it drives the focused window
/// through the X11 test extension. It is not a print-only simulator, and
/// callers must invoke it explicitly — nothing is typed automatically.
///
/// Supported keystroke actions:
///   - `"type"`            → `xdotool type --clearmodifiers --delay 12 --file -`
///                            (the text is fed via stdin, never argv)
///   - `"key"`             → `xdotool key <mapped-name>`
///   - `"delay"`           → sleep for the given milliseconds
///   - `"clipboard_paste"` → set the clipboard with xclip/xsel (chunk via
///                            stdin), then `xdotool key ctrl+v` (obfuscation
///                            streams use this action; requires a clipboard tool)
///
/// Fails with an honest `Err` when `xdotool` (or xclip/xsel for clipboard
/// pastes) is unavailable, or when an injection command fails. Error strings
/// carry tool names, key names and tool stderr only — never keystroke values.
pub fn execute_keystrokes(keystrokes: &[Keystroke]) -> Result<u32, String> {
    execute_keystrokes_with(&mut ShellRunner, keystrokes)
}

/// Executor body, parameterised over the injectable subprocess runner.
///
/// Production always passes [`ShellRunner`]; tests inject a recording mock.
/// Gating is identical on both paths: an explicit call, an honest probe of
/// the `xdotool` backend, and nothing injected when the probe fails.
fn execute_keystrokes_with(
    runner: &mut dyn CommandRunner,
    keystrokes: &[Keystroke],
) -> Result<u32, String> {
    xdotool_available_with(runner)?;

    let mut executed = 0u32;
    for ks in keystrokes {
        match ks.action.as_str() {
            "type" => {
                // The text is fed via STDIN (`--file -`), never argv:
                // keystroke text is secret-derived and argv is readable by
                // every local process through /proc.
                let out = runner
                    .run(
                        "xdotool",
                        &["type", "--clearmodifiers", "--delay", "12", "--file", "-"],
                        Some(ks.value.as_bytes()),
                    )
                    .map_err(|e| format!("autotype: xdotool type failed to spawn: {e}"))?;
                if !out.success {
                    return Err(format!(
                        "autotype: xdotool type failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
                executed += 1;
            }
            "key" => {
                let key = map_key_name(&ks.value);
                let out = runner
                    .run("xdotool", &["key", key.as_str()], None)
                    .map_err(|e| format!("autotype: xdotool key failed to spawn: {e}"))?;
                if !out.success {
                    return Err(format!(
                        "autotype: xdotool key '{}' failed: {}",
                        key,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
                executed += 1;
            }
            "delay" => {
                let ms = ks.value.parse::<u64>().map_err(|_| {
                    format!(
                        "autotype: invalid delay value '{}' (expected milliseconds)",
                        ks.value
                    )
                })?;
                std::thread::sleep(std::time::Duration::from_millis(ms));
                executed += 1;
            }
            "clipboard_paste" => {
                // Set the clipboard (chunk piped via STDIN, never argv),
                // then paste with Ctrl+V. Requires a clipboard tool (xclip
                // or xsel); without one this is an honest error — we never
                // fake a paste.
                let value = ks.value.as_bytes();
                let clipboard_ok =
                    set_clipboard(runner, "xclip", &["-selection", "clipboard"], value).or_else(
                        |_| set_clipboard(runner, "xsel", &["--clipboard", "--input"], value),
                    );
                if let Err(e) = clipboard_ok {
                    return Err(format!(
                        "autotype: clipboard_paste action requires xclip or xsel — {e}"
                    ));
                }
                let out = runner
                    .run("xdotool", &["key", "ctrl+v"], None)
                    .map_err(|e| format!("autotype: xdotool key ctrl+v failed to spawn: {e}"))?;
                if !out.success {
                    return Err(format!(
                        "autotype: xdotool key ctrl+v failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
                executed += 1;
            }
            other => {
                return Err(format!(
                    "autotype: unsupported keystroke action '{other}' (supported: type, key, delay, clipboard_paste)"
                ));
            }
        }
    }
    Ok(executed)
}

/// Set an X clipboard selection by piping `value` to `tool`'s stdin.
///
/// Both xclip and xsel are supported; a missing binary is reported as
/// "not available" so the caller can fall back to the other tool.
fn set_clipboard(
    runner: &mut dyn CommandRunner,
    tool: &str,
    args: &[&str],
    value: &[u8],
) -> Result<(), String> {
    match runner.run(tool, args, Some(value)) {
        Ok(out) if out.success => Ok(()),
        Ok(out) => Err(format!(
            "autotype: {tool} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("autotype: clipboard tool '{tool}' not available"))
        }
        Err(e) => Err(format!("autotype: {tool} failed: {e}")),
    }
}

/// Process an auto-type sequence against an entry AND execute it on the live
/// desktop. This is the real end-to-end executor — the CLI's plan preview is
/// print-only and does not call this; wiring it in is a follow-up. Returns
/// the processed result plus the number of keystrokes actually injected.
pub fn run_autotype(
    seq: &AutoTypeSequence,
    entry: &VaultEntry,
) -> Result<(AutoTypeResult, u32), String> {
    let result = process_sequence(seq, entry)?;
    let executed = execute_keystrokes(&result.keystrokes)?;
    Ok((result, executed))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::{CustomField, VaultEntry};

    fn make_login_entry() -> VaultEntry {
        let mut entry =
            VaultEntry::new_login("GitHub", "octocat", "s3cret!", vec!["https://github.com/login".into()]);
        entry.notes = Some("my notes".into());
        entry.custom_fields.push(CustomField {
            name: "OrgID".into(),
            value: "12345".into(),
            hidden: false,
            field_type: "text".into(),
        });
        entry
    }

    /// Parse the default sequence pattern string.
    #[test]
    fn test_parse_default() {
        let seq = parse_sequence("{USERNAME}{TAB}{PASSWORD}{ENTER}").unwrap();
        assert_eq!(seq.actions.len(), 4);
        assert_eq!(seq.actions[0], AutoTypeAction::TypeUsername);
        assert_eq!(seq.actions[1], AutoTypeAction::PressTab);
        assert_eq!(seq.actions[2], AutoTypeAction::TypePassword);
        assert_eq!(seq.actions[3], AutoTypeAction::PressEnter);
    }

    /// Parse a custom sequence with delay, clearfield, and literal text.
    #[test]
    fn test_parse_custom() {
        let seq = parse_sequence("{CLEARFIELD}admin{TAB}{DELAY 500}{PASSWORD}{ENTER}").unwrap();
        assert_eq!(seq.actions.len(), 6);
        assert_eq!(seq.actions[0], AutoTypeAction::ClearField);
        assert_eq!(seq.actions[1], AutoTypeAction::TypeText("admin".into()));
        assert_eq!(seq.actions[2], AutoTypeAction::PressTab);
        assert_eq!(seq.actions[3], AutoTypeAction::Delay(500));
        assert_eq!(seq.actions[4], AutoTypeAction::TypePassword);
        assert_eq!(seq.actions[5], AutoTypeAction::PressEnter);
    }

    /// Process the default sequence against a login entry.
    #[test]
    fn test_process_login() {
        let entry = make_login_entry();
        let seq = default_sequence();
        let result = process_sequence(&seq, &entry).unwrap();

        // Should produce: type "octocat", key Tab, type "s3cret!", key Enter
        assert_eq!(result.keystrokes.len(), 4);
        assert_eq!(result.keystrokes[0].value, "octocat");
        assert_eq!(result.keystrokes[1].value, "Tab");
        assert_eq!(result.keystrokes[2].value, "s3cret!");
        assert_eq!(result.keystrokes[3].value, "Enter");
        assert_eq!(result.total_chars, 7 + 7); // "octocat" + "s3cret!"
        assert!(!result.has_delay);
    }

    /// Wildcard and regex window matching.
    #[test]
    fn test_window_matching() {
        // Wildcard
        assert!(match_window_title(
            "GitHub - Login - Mozilla Firefox",
            "*github*"
        ));
        assert!(match_window_title(
            "GitHub - Login - Mozilla Firefox",
            "*GitHub*Firefox"
        ));
        assert!(!match_window_title(
            "GitLab - Dashboard",
            "*github*"
        ));

        // Exact (no wildcard)
        assert!(match_window_title("Login Page", "Login Page"));
        assert!(match_window_title("login page", "Login Page")); // case-insensitive
        assert!(!match_window_title("Login Page Extra", "Login Page"));

        // Regex
        assert!(match_window_title(
            "GitHub - octocat/repo",
            "/[Gg]it[Hh]ub.*octocat/"
        ));
        assert!(!match_window_title(
            "GitLab - octocat/repo",
            "/GitHub.*octocat/"
        ));
    }

    /// Find matching entries by domain in window title.
    #[test]
    fn test_find_matching_entries() {
        let gh = make_login_entry();
        let gl = VaultEntry::new_login(
            "GitLab",
            "user",
            "pass",
            vec!["https://gitlab.com/login".into()],
        );
        let note = VaultEntry::new_note("Secret", "content");

        let entries = vec![gh, gl, note];

        let matches = find_matching_entry(&entries, "GitHub - Login - Firefox");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "GitHub");

        let matches = find_matching_entry(&entries, "gitlab.com / Dashboard");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "GitLab");

        let matches = find_matching_entry(&entries, "Slack - Messages");
        assert!(matches.is_empty());
    }

    /// Obfuscation splits text across two streams; combined they equal the original.
    #[test]
    fn test_obfuscation_completeness() {
        let entry = make_login_entry();
        let seq = default_sequence();
        let result = process_sequence(&seq, &entry).unwrap();

        let streams = obfuscate_keystrokes(&result);
        assert_eq!(streams.len(), 2);

        // Collect all clipboard_paste text from both streams
        let a_text: Vec<String> = streams[0]
            .keystrokes
            .iter()
            .filter(|k| k.action == "clipboard_paste")
            .map(|k| k.value.clone())
            .collect();
        let b_text: Vec<String> = streams[1]
            .keystrokes
            .iter()
            .filter(|k| k.action == "clipboard_paste")
            .map(|k| k.value.clone())
            .collect();

        // Interleave chunks: even-indexed from A, odd-indexed from B
        let mut combined = String::new();
        let max_len = a_text.len().max(b_text.len());
        for i in 0..max_len {
            if i < a_text.len() {
                combined.push_str(&a_text[i]);
            }
            if i < b_text.len() {
                combined.push_str(&b_text[i]);
            }
        }

        // Total chars across both streams must equal original total
        let total = streams[0].total_chars + streams[1].total_chars;
        assert_eq!(total, result.total_chars);

        // All original characters must be present in the union of chunks
        let a_all: String = a_text.concat();
        let b_all: String = b_text.concat();
        let all_chars: String = format!("{a_all}{b_all}");
        // Every char from username and password must appear in the combined chunks
        for c in "octocat".chars() {
            assert!(all_chars.contains(c), "missing char '{c}' from username");
        }
        for c in "s3cret!".chars() {
            assert!(all_chars.contains(c), "missing char '{c}' from password");
        }

        // At least one stream should NOT contain the full password
        // (with 7 chars and max chunk size 5, guaranteed to split)
        let neither_complete = !a_all.contains("s3cret!") || !b_all.contains("s3cret!");
        assert!(
            neither_complete,
            "obfuscation should split password across streams"
        );
    }

    /// Delay handling in sequences.
    #[test]
    fn test_delay_handling() {
        let seq = parse_sequence("{USERNAME}{DELAY 200}{PASSWORD}").unwrap();
        assert_eq!(seq.actions[1], AutoTypeAction::Delay(200));

        let entry = make_login_entry();
        let result = process_sequence(&seq, &entry).unwrap();
        assert!(result.has_delay);

        let delay_ks: Vec<&Keystroke> = result
            .keystrokes
            .iter()
            .filter(|k| k.action == "delay")
            .collect();
        assert_eq!(delay_ks.len(), 1);
        assert_eq!(delay_ks[0].value, "200");
    }

    /// Custom field resolution via {FIELD:name}.
    #[test]
    fn test_custom_field() {
        let entry = make_login_entry();
        let seq = parse_sequence("{USERNAME}{TAB}{FIELD:OrgID}{TAB}{PASSWORD}{ENTER}").unwrap();
        let result = process_sequence(&seq, &entry).unwrap();

        // keystrokes: type "octocat", Tab, type "12345", Tab, type "s3cret!", Enter
        assert_eq!(result.keystrokes.len(), 6);
        assert_eq!(result.keystrokes[2].value, "12345");
    }

    /// Parse error on unclosed placeholder.
    #[test]
    fn test_parse_error_unclosed() {
        let err = parse_sequence("{USERNAME}{TAB{PASSWORD}").unwrap_err();
        assert!(err.contains("unknown placeholder"));
    }

    /// {TITLE} and {NOTES} resolve from entry metadata.
    #[test]
    fn test_title_and_notes() {
        let entry = make_login_entry();
        let seq = parse_sequence("{TITLE}{TAB}{NOTES}").unwrap();
        let result = process_sequence(&seq, &entry).unwrap();

        assert_eq!(result.keystrokes[0].value, "GitHub");
        assert_eq!(result.keystrokes[2].value, "my notes");
    }

    /// The xdotool backend probe is honest: Ok when the backend exists,
    /// a descriptive Err naming the missing backend otherwise. Never a
    /// print-only fake.
    #[test]
    fn test_xdotool_available_is_honest() {
        match xdotool_available() {
            Ok(()) => {}
            Err(e) => assert!(
                e.contains("autotype requires"),
                "unexpected error shape: {e}"
            ),
        }
    }

    /// Key-name mapping for the xdotool backend.
    #[test]
    fn test_map_key_name() {
        assert_eq!(map_key_name("Tab"), "Tab");
        assert_eq!(map_key_name("Enter"), "Return");
        assert_eq!(map_key_name("Escape"), "Escape");
        assert_eq!(map_key_name("Ctrl+A"), "ctrl+a");
        assert_eq!(map_key_name("Delete"), "Delete");
        assert_eq!(map_key_name("ctrl+shift+t"), "ctrl+shift+t");
    }

    /// Unsupported keystroke actions yield an honest Err before any input is
    /// injected (never silent, never a fake success).
    #[test]
    fn test_execute_rejects_unknown_action() {
        let ks = vec![Keystroke {
            action: "paste".into(),
            value: "x".into(),
        }];
        let err = execute_keystrokes(&ks).unwrap_err();
        // On a box without the backend the probe error comes first; with the
        // backend present the unsupported action is rejected. Both are
        // honest "autotype…" errors and nothing is injected either way.
        assert!(err.starts_with("autotype"), "unexpected error shape: {err}");
    }

    // ── Desktop-input backend (mocked) ──────────────────────────────────

    /// Recording runner: captures every subprocess invocation (program,
    /// argv, stdin) and replays scripted responses in call order. The
    /// default response is a successful run with empty stderr.
    #[derive(Default)]
    struct MockRunner {
        calls: Vec<(String, Vec<String>, Option<Vec<u8>>)>,
        responses: std::collections::VecDeque<std::io::Result<RunnerOutput>>,
    }

    impl MockRunner {
        fn new() -> Self {
            Self::default()
        }

        /// Script the response for the next subprocess call.
        fn respond(mut self, r: std::io::Result<RunnerOutput>) -> Self {
            self.responses.push_back(r);
            self
        }

        /// Space-joined argv of call `i` (program name excluded).
        fn argv(&self, i: usize) -> String {
            self.calls[i].1.join(" ")
        }
    }

    impl CommandRunner for MockRunner {
        fn run(
            &mut self,
            program: &str,
            args: &[&str],
            stdin_bytes: Option<&[u8]>,
        ) -> std::io::Result<RunnerOutput> {
            self.calls.push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
                stdin_bytes.map(|b| b.to_vec()),
            ));
            match self.responses.pop_front() {
                Some(r) => r,
                None => Ok(ok_out()),
            }
        }
    }

    fn ok_out() -> RunnerOutput {
        RunnerOutput {
            success: true,
            stderr: Vec::new(),
        }
    }

    fn fail_out(stderr: &str) -> RunnerOutput {
        RunnerOutput {
            success: false,
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn not_found() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory")
    }

    /// Missing backend: the honest `Err` names the missing backend and
    /// nothing is injected (the probe is the only call attempted).
    #[test]
    fn test_execute_missing_backend_is_honest_err() {
        let mut runner = MockRunner::new().respond(Err(not_found()));
        let plan = vec![Keystroke {
            action: "type".into(),
            value: "s3cret!".into(),
        }];
        let err = execute_keystrokes_with(&mut runner, &plan).unwrap_err();
        assert!(
            err.contains("autotype requires desktop input backend 'xdotool'"),
            "unexpected: {err}"
        );
        assert!(err.contains("not available"), "unexpected: {err}");
        assert_eq!(
            runner.calls.len(),
            1,
            "no injection may be attempted without the backend"
        );
        assert_eq!(runner.argv(0), "--version");
    }

    /// A backend that exists but errors (e.g. no usable X display) is also
    /// an honest Err, not a fake success.
    #[test]
    fn test_execute_backend_probe_error_is_honest_err() {
        let mut runner = MockRunner::new().respond(Ok(fail_out("xdotool: X11 unavailable")));
        let err = execute_keystrokes_with(&mut runner, &[]).unwrap_err();
        assert!(err.contains("xdotool reported an error"), "unexpected: {err}");
        assert_eq!(runner.calls.len(), 1);
    }

    /// Full plan → execution ordering: the executor runs the plan in order,
    /// maps key names to xdotool names, and feeds typed text via stdin
    /// (`--file -`) so it can never leak through argv/`ps`.
    #[test]
    fn test_execute_ordering_and_key_mapping() {
        let entry = make_login_entry();
        let seq = parse_sequence("{CLEARFIELD}{USERNAME}{TAB}{PASSWORD}{ENTER}").unwrap();
        let plan = process_sequence(&seq, &entry).unwrap().keystrokes;

        let mut runner = MockRunner::new();
        let executed = execute_keystrokes_with(&mut runner, &plan).unwrap();
        assert_eq!(executed, 6);

        // Call 0 is the backend probe, then the plan in order:
        // Ctrl+A, Delete, type "octocat", Tab, type "s3cret!", Enter.
        assert_eq!(runner.calls.len(), 7);
        assert_eq!(runner.calls[0].0, "xdotool");
        assert_eq!(runner.argv(0), "--version");
        assert_eq!(runner.argv(1), "key ctrl+a");
        assert_eq!(runner.argv(2), "key Delete");
        assert_eq!(runner.argv(3), "type --clearmodifiers --delay 12 --file -");
        assert_eq!(runner.argv(4), "key Tab");
        assert_eq!(runner.argv(5), "type --clearmodifiers --delay 12 --file -");
        assert_eq!(runner.argv(6), "key Return");

        // Secret-derived text travels via stdin, never argv.
        assert_eq!(runner.calls[3].2.as_deref(), Some("octocat".as_bytes()));
        assert_eq!(runner.calls[5].2.as_deref(), Some("s3cret!".as_bytes()));
        let all_argv: String = runner
            .calls
            .iter()
            .map(|c| c.1.join(" "))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            !all_argv.contains("octocat"),
            "username leaked into argv: {all_argv}"
        );
        assert!(
            !all_argv.contains("s3cret!"),
            "password leaked into argv: {all_argv}"
        );
    }

    /// Clipboard action: set the clipboard (chunk via stdin), then Ctrl+V —
    /// in that order, chunk never in argv.
    #[test]
    fn test_execute_clipboard_paste_order() {
        let plan = vec![Keystroke {
            action: "clipboard_paste".into(),
            value: "s3cret!".into(),
        }];
        let mut runner = MockRunner::new();
        let executed = execute_keystrokes_with(&mut runner, &plan).unwrap();
        assert_eq!(executed, 1);
        assert_eq!(runner.calls.len(), 3);
        assert_eq!(runner.calls[1].0, "xclip");
        assert_eq!(runner.argv(1), "-selection clipboard");
        assert_eq!(runner.calls[1].2.as_deref(), Some("s3cret!".as_bytes()));
        assert_eq!(runner.calls[2].0, "xdotool");
        assert_eq!(runner.argv(2), "key ctrl+v");
    }

    /// xclip missing → xsel is tried before giving up; the paste still works.
    #[test]
    fn test_execute_clipboard_falls_back_to_xsel() {
        let mut runner = MockRunner::new()
            .respond(Ok(ok_out())) // probe
            .respond(Err(not_found())); // xclip missing
        let plan = vec![Keystroke {
            action: "clipboard_paste".into(),
            value: "chunk".into(),
        }];
        let executed = execute_keystrokes_with(&mut runner, &plan).unwrap();
        assert_eq!(executed, 1);
        let programs: Vec<&str> = runner.calls.iter().map(|c| c.0.as_str()).collect();
        assert_eq!(programs, ["xdotool", "xclip", "xsel", "xdotool"]);
        assert_eq!(runner.argv(2), "--clipboard --input");
        assert_eq!(runner.calls[2].2.as_deref(), Some("chunk".as_bytes()));
        assert_eq!(runner.argv(3), "key ctrl+v");
    }

    /// Neither clipboard tool available → honest Err and no Ctrl+V is sent.
    #[test]
    fn test_execute_clipboard_requires_a_tool() {
        let mut runner = MockRunner::new()
            .respond(Ok(ok_out())) // probe
            .respond(Err(not_found())) // xclip missing
            .respond(Err(not_found())); // xsel missing
        let plan = vec![Keystroke {
            action: "clipboard_paste".into(),
            value: "x".into(),
        }];
        let err = execute_keystrokes_with(&mut runner, &plan).unwrap_err();
        assert!(err.contains("requires xclip or xsel"), "unexpected: {err}");
        let programs: Vec<&str> = runner.calls.iter().map(|c| c.0.as_str()).collect();
        assert_eq!(
            programs,
            ["xdotool", "xclip", "xsel"],
            "no paste may follow a failed clipboard set"
        );
    }

    /// Delay keystrokes sleep locally and spawn nothing.
    #[test]
    fn test_execute_delay_spawns_no_backend_call() {
        let mut runner = MockRunner::new();
        let plan = vec![Keystroke {
            action: "delay".into(),
            value: "0".into(),
        }];
        assert_eq!(execute_keystrokes_with(&mut runner, &plan).unwrap(), 1);
        assert_eq!(runner.calls.len(), 1); // probe only
    }

    /// A malformed delay is an honest Err (never a silent timing change).
    #[test]
    fn test_execute_invalid_delay_is_honest_err() {
        let mut runner = MockRunner::new();
        let plan = vec![Keystroke {
            action: "delay".into(),
            value: "soon".into(),
        }];
        let err = execute_keystrokes_with(&mut runner, &plan).unwrap_err();
        assert!(err.contains("invalid delay"), "unexpected: {err}");
        assert_eq!(runner.calls.len(), 1);
    }

    /// Unsupported actions are rejected before any input is injected.
    #[test]
    fn test_execute_rejects_unknown_action_mocked() {
        let mut runner = MockRunner::new();
        let plan = vec![Keystroke {
            action: "paste".into(),
            value: "x".into(),
        }];
        let err = execute_keystrokes_with(&mut runner, &plan).unwrap_err();
        assert!(
            err.contains("unsupported keystroke action 'paste'"),
            "unexpected: {err}"
        );
        assert_eq!(runner.calls.len(), 1, "rejected before any injection");
    }

    /// End-to-end with `obfuscate_keystrokes`: both streams execute through
    /// the backend, every clipboard chunk is followed by Ctrl+V, interleaving
    /// the two streams reproduces the password exactly, and no chunk ever
    /// appears in argv.
    #[test]
    fn test_obfuscated_streams_execute_and_reassemble() {
        let entry = make_login_entry();
        let seq = parse_sequence("{PASSWORD}").unwrap();
        let result = process_sequence(&seq, &entry).unwrap();
        let streams = obfuscate_keystrokes(&result);
        assert_eq!(streams.len(), 2);

        let mut runners = Vec::new();
        for stream in &streams {
            let mut runner = MockRunner::new();
            let executed = execute_keystrokes_with(&mut runner, &stream.keystrokes).unwrap();
            assert_eq!(executed as usize, stream.keystrokes.len());
            runners.push(runner);
        }

        let chunks = |runner: &MockRunner| -> Vec<String> {
            runner
                .calls
                .iter()
                .filter(|c| c.0 == "xclip")
                .map(|c| String::from_utf8(c.2.clone().unwrap()).unwrap())
                .collect()
        };
        let a = chunks(&runners[0]);
        let b = chunks(&runners[1]);
        assert!(
            !a.is_empty() && !b.is_empty(),
            "both obfuscation streams must carry chunks"
        );

        // Even chunks (stream A) and odd chunks (stream B) interleave back
        // into the exact original text.
        let mut reassembled = String::new();
        for i in 0..a.len().max(b.len()) {
            if i < a.len() {
                reassembled.push_str(&a[i]);
            }
            if i < b.len() {
                reassembled.push_str(&b[i]);
            }
        }
        assert_eq!(reassembled, "s3cret!");

        for runner in &runners {
            for (i, call) in runner.calls.iter().enumerate() {
                let argv = call.1.join(" ");
                assert!(!argv.contains("s3cret!"), "chunk leaked into argv: {argv}");
                if call.0 == "xclip" {
                    assert_eq!(
                        runner.argv(i + 1),
                        "key ctrl+v",
                        "every chunk paste must be followed by Ctrl+V"
                    );
                }
            }
        }
    }

    /// `Debug` never prints secret-derived keystroke values (zeroization
    /// rules): typed text and clipboard chunks are redacted, structural
    /// metadata (key names, delays) stays visible for debugging.
    #[test]
    fn test_debug_output_redacts_secret_values() {
        let entry = make_login_entry();
        let result = process_sequence(&default_sequence(), &entry).unwrap();

        let result_dbg = format!("{result:?}");
        assert!(
            !result_dbg.contains("s3cret!"),
            "password leaked into Debug: {result_dbg}"
        );
        assert!(
            !result_dbg.contains("octocat"),
            "username leaked into Debug: {result_dbg}"
        );
        assert!(
            result_dbg.contains("redacted"),
            "redaction marker missing: {result_dbg}"
        );

        let typed = Keystroke {
            action: "type".into(),
            value: "s3cret!".into(),
        };
        let typed_dbg = format!("{typed:?}");
        assert!(
            !typed_dbg.contains("s3cret!"),
            "password leaked into Debug: {typed_dbg}"
        );
        assert!(
            typed_dbg.contains("redacted"),
            "redaction marker missing: {typed_dbg}"
        );

        let paste = Keystroke {
            action: "clipboard_paste".into(),
            value: "chunk".into(),
        };
        assert!(!format!("{paste:?}").contains("chunk"));

        // Structural metadata is not secret and remains printable.
        let key = Keystroke {
            action: "key".into(),
            value: "Tab".into(),
        };
        assert!(format!("{key:?}").contains("Tab"));
    }

    /// `run_autotype` plans first: a sequence that cannot be resolved (no
    /// TOTP secret) fails honestly before any backend probe or injection.
    #[test]
    fn test_run_autotype_process_error_precedes_backend() {
        let entry = make_login_entry();
        let seq = parse_sequence("{TOTP}").unwrap();
        let err = run_autotype(&seq, &entry).unwrap_err();
        assert!(err.contains("No TOTP secret"), "unexpected: {err}");
    }

    /// On a box without the backend, `run_autotype` returns the honest
    /// no-backend error instead of pretending to type. Skipped when xdotool
    /// is present — the live path is not exercised by the unit suite.
    #[test]
    fn test_run_autotype_reports_missing_backend() {
        if xdotool_available().is_ok() {
            return;
        }
        let entry = make_login_entry();
        let err = run_autotype(&default_sequence(), &entry).unwrap_err();
        assert!(
            err.contains("autotype requires desktop input backend 'xdotool'"),
            "unexpected: {err}"
        );
    }
}
