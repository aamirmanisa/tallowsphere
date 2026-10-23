//! Chrome for Testing download, extraction, and version management.
//!
//! Provides managed Chromium binary downloads via the Chrome for Testing (CfT)
//! JSON API. Supports platform detection, version discovery, zip extraction,
//! installed version listing/removal, and auto-detection of system Chrome.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::browser::error::BrowserError;

// ── CfT JSON API Endpoints ─────────────────────────────────────────────────

const CFT_LAST_KNOWN_GOOD_URL: &str =
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";

// ── Platform Detection ──────────────────────────────────────────────────────

/// Browser platform variants matching Chrome for Testing naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserPlatform {
    Linux64,
    LinuxArm64,
    LinuxRiscV64,
    MacArm64,
    MacX64,
    Win32,
    Win64,
}

impl BrowserPlatform {
    /// Detect the current platform from `std::env::consts`.
    pub fn detect() -> Result<Self, BrowserError> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => Ok(BrowserPlatform::Linux64),
            ("linux", "aarch64") => Ok(BrowserPlatform::LinuxArm64),
            ("linux", "riscv64") => Ok(BrowserPlatform::LinuxRiscV64),
            ("macos", "aarch64") => Ok(BrowserPlatform::MacArm64),
            ("macos", "x86_64") => Ok(BrowserPlatform::MacX64),
            ("windows", "x86_64") => Ok(BrowserPlatform::Win64),
            ("windows", "x86") => Ok(BrowserPlatform::Win32),
            (os, arch) => Err(BrowserError::DownloadFailed(format!(
                "unsupported platform: {os}/{arch}"
            ))),
        }
    }

    /// Returns the CfT API platform string.
    ///
    /// RISC-V returns a sentinel value because Chrome for Testing does not
    /// ship RISC-V binaries. Callers that depend on this string to select a
    /// CfT download should check `is_cft_supported()` first.
    pub fn as_cft_str(&self) -> &'static str {
        match self {
            BrowserPlatform::Linux64 => "linux64",
            BrowserPlatform::LinuxArm64 => "linux-arm64",
            BrowserPlatform::LinuxRiscV64 => "linux-riscv64",
            BrowserPlatform::MacArm64 => "mac-arm64",
            BrowserPlatform::MacX64 => "mac-x64",
            BrowserPlatform::Win32 => "win32",
            BrowserPlatform::Win64 => "win64",
        }
    }

    /// Whether this platform has Chrome for Testing binaries available.
    ///
    /// Returns `false` for RISC-V — Google does not ship CfT binaries for
    /// RISC-V. On RISC-V, install Chromium from your distribution:
    ///   Debian/Ubuntu:  `sudo apt install chromium`
    ///   Fedora/openSUSE: `sudo dnf install chromium`
    ///   Arch Linux:     `sudo pacman -S chromium`
    pub fn is_cft_supported(&self) -> bool {
        !matches!(self, BrowserPlatform::LinuxRiscV64)
    }

    /// Returns a human-readable hint for platforms without CfT support.
    pub fn cft_unsupported_hint(&self) -> Option<&'static str> {
        match self {
            BrowserPlatform::LinuxRiscV64 => Some(
                "Chrome for Testing does not ship RISC-V binaries. \
                 Install Chromium from your distribution package manager:\n\
                 \n  Debian/Ubuntu:     sudo apt install chromium\
                 \n  Fedora/openSUSE:  sudo dnf install chromium\
                 \n  Arch Linux:       sudo pacman -S chromium\
                 \n\nThen pass the path with `--chrome-path /usr/bin/chromium`."
            ),
            _ => None,
        }
    }

    /// Returns the relative path to the chrome-headless-shell executable within
    /// the extracted zip archive.
    pub fn chrome_executable(&self) -> &'static str {
        match self {
            BrowserPlatform::Linux64 => {
                "chrome-headless-shell-linux64/chrome-headless-shell"
            }
            BrowserPlatform::LinuxArm64 => {
                "chrome-headless-shell-linux-arm64/chrome-headless-shell"
            }
            BrowserPlatform::LinuxRiscV64 => {
                // No managed install — must use system Chromium
                "chromium"
            }
            BrowserPlatform::MacArm64 => {
                "chrome-headless-shell-mac-arm64/chrome-headless-shell"
            }
            BrowserPlatform::MacX64 => {
                "chrome-headless-shell-mac-x64/chrome-headless-shell"
            }
            BrowserPlatform::Win32 => {
                "chrome-headless-shell-win32/chrome-headless-shell.exe"
            }
            BrowserPlatform::Win64 => {
                "chrome-headless-shell-win64/chrome-headless-shell.exe"
            }
        }
    }

    /// Returns the relative path to the full Chrome executable within the
    /// extracted zip archive.
    pub fn chrome_full_executable(&self) -> &'static str {
        match self {
            BrowserPlatform::Linux64 => "chrome-linux64/chrome",
            BrowserPlatform::LinuxArm64 => "chrome-linux-arm64/chrome",
            BrowserPlatform::LinuxRiscV64 => "chromium",
            BrowserPlatform::MacArm64 => {
                "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
            }
            BrowserPlatform::MacX64 => {
                "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
            }
            BrowserPlatform::Win32 => "chrome-win32/chrome.exe",
            BrowserPlatform::Win64 => "chrome-win64/chrome.exe",
        }
    }
}

impl std::fmt::Display for BrowserPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_cft_str())
    }
}

// ── CfT Version Info ────────────────────────────────────────────────────────

/// A download entry from the CfT JSON response.
#[derive(Debug, Clone)]
pub struct CfTDownload {
    pub platform: String,
    pub url: String,
}

/// Version info from the CfT JSON API.
#[derive(Debug, Clone)]
pub struct CfTVersionInfo {
    pub version: String,
    pub downloads_headless: Vec<CfTDownload>,
    pub downloads_chrome: Vec<CfTDownload>,
}

// ── Install Directory ───────────────────────────────────────────────────────

/// Returns the browser install directory: `<data_dir>/tallow/browsers/`.
/// Creates the directory if it does not exist.
pub fn browser_install_dir() -> Result<PathBuf, BrowserError> {
    // `dirs::data_dir()` is platform-shaped: XDG_DATA_HOME on Linux, but
    // ~/Library/Application Support on macOS and %APPDATA% on Windows, which
    // ignore XDG entirely. TALLOW_DATA_HOME is the cross-platform override --
    // needed by the test harness, and useful to an operator who wants browser
    // installs on a different volume.
    let base = match std::env::var_os("TALLOW_DATA_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => dirs::data_dir().ok_or_else(|| {
            BrowserError::DownloadFailed("cannot determine data directory".to_string())
        })?,
    };
    let dir = base.join("tallow").join("browsers");
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| {
            BrowserError::DownloadFailed(format!(
                "cannot create browser directory {}: {e}",
                dir.display()
            ))
        })?;
    }
    Ok(dir)
}

// ── Version Discovery ───────────────────────────────────────────────────────

/// Fetches the latest stable Chrome for Testing version info from the CfT API.
pub fn fetch_latest_stable_version() -> Result<CfTVersionInfo, BrowserError> {
    let body: String = crate::runtime::egress_http::get(CFT_LAST_KNOWN_GOOD_URL)
        .call()
        .map_err(|e| BrowserError::DownloadFailed(format!("HTTP request failed: {e}")))?
        .into_body()
        .read_to_string()
        .map_err(|e| BrowserError::DownloadFailed(format!("failed to read response: {e}")))?;

    parse_cft_response(&body)
}

/// Parse a CfT last-known-good-versions JSON response.
pub fn parse_cft_response(json: &str) -> Result<CfTVersionInfo, BrowserError> {
    let root: serde_json::Value = serde_json::from_str(json)?;

    let stable = root
        .get("channels")
        .and_then(|c| c.get("Stable"))
        .ok_or_else(|| {
            BrowserError::DownloadFailed(
                "CfT response missing channels.Stable".to_string(),
            )
        })?;

    let version = stable
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            BrowserError::DownloadFailed("CfT response missing version".to_string())
        })?
        .to_string();

    let downloads_headless = parse_download_array(
        stable
            .get("downloads")
            .and_then(|d| d.get("chrome-headless-shell"))
            .and_then(|a| a.as_array()),
    );

    let downloads_chrome = parse_download_array(
        stable
            .get("downloads")
            .and_then(|d| d.get("chrome"))
            .and_then(|a| a.as_array()),
    );

    Ok(CfTVersionInfo {
        version,
        downloads_headless,
        downloads_chrome,
    })
}

fn parse_download_array(arr: Option<&Vec<serde_json::Value>>) -> Vec<CfTDownload> {
    let Some(arr) = arr else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|entry| {
            let platform = entry.get("platform")?.as_str()?.to_string();
            let url = entry.get("url")?.as_str()?.to_string();
            Some(CfTDownload { platform, url })
        })
        .collect()
}

/// Find the download URL for the given platform and variant.
pub fn find_download_url(
    info: &CfTVersionInfo,
    platform: &BrowserPlatform,
    full: bool,
) -> Result<String, BrowserError> {
    let cft_str = platform.as_cft_str();
    let downloads = if full {
        &info.downloads_chrome
    } else {
        &info.downloads_headless
    };
    let variant_name = if full {
        "chrome"
    } else {
        "chrome-headless-shell"
    };

    downloads
        .iter()
        .find(|d| d.platform == cft_str)
        .map(|d| d.url.clone())
        .ok_or_else(|| {
            BrowserError::DownloadFailed(format!(
                "no {variant_name} download found for platform {cft_str}"
            ))
        })
}

// ── Checksum Helpers ───────────────────────────────────────────────────────

/// Compute SHA-256 hex digest of the given bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

/// Try to fetch the expected SHA-256 checksum from `{url}.sha256`.
/// Returns `None` if the checksum file is not available.
fn fetch_sha256_checksum(url: &str) -> Option<String> {
    let checksum_url = format!("{url}.sha256");
    let resp = crate::runtime::egress_http::get(&checksum_url).call().ok()?;
    let body = resp.into_body().read_to_string().ok()?;
    // Checksum files may contain just the hash or "hash  filename"
    let hash = body.trim().split_whitespace().next()?;
    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hash.to_lowercase())
    } else {
        None
    }
}

/// Locate the extracted Chrome binary inside `install_dir` (one level deep).
///
/// Shared by the BLAKE3 write/verify pair so they always address the same
/// file.
fn find_installed_binary(install_dir: &Path) -> Option<PathBuf> {
    // Candidate binary names within the extracted tree
    let candidates = [
        "chrome-headless-shell",
        "chrome-headless-shell.exe",
        "chrome",
        "chrome.exe",
        "Google Chrome for Testing",
    ];

    fs::read_dir(install_dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .flat_map(|subdir| {
            candidates.iter().filter_map(move |name| {
                let p = subdir.path().join(name);
                if p.exists() {
                    Some(p)
                } else {
                    None
                }
            })
        })
        .next()
}

/// Write a BLAKE3 hash of the extracted Chrome binary to `checksum.blake3`.
///
/// Fails (not warns) when the binary cannot be located, read, or hashed:
/// after this change the digest is read back by
/// [`verify_blake3_checksum`] before the install is announced, so a silent
/// write failure would defeat the read-back.
fn write_blake3_checksum(install_dir: &Path) -> Result<(), BrowserError> {
    let binary_path = find_installed_binary(install_dir).ok_or_else(|| {
        BrowserError::FileNotFound(format!(
            "no Chrome binary found under {} for BLAKE3 hashing",
            install_dir.display()
        ))
    })?;
    let bytes = fs::read(&binary_path).map_err(|e| {
        BrowserError::DownloadFailed(format!(
            "cannot read {} for BLAKE3 hash: {e}",
            binary_path.display()
        ))
    })?;
    let hash = blake3::hash(&bytes);
    let checksum_path = binary_path.with_file_name("checksum.blake3");
    let content = format!(
        "{}  {}\n",
        hash.to_hex(),
        binary_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    );
    fs::write(&checksum_path, content).map_err(|e| {
        BrowserError::DownloadFailed(format!(
            "could not write BLAKE3 checksum {}: {e}",
            checksum_path.display()
        ))
    })?;
    eprintln!("BLAKE3 checksum stored at {}", checksum_path.display());
    Ok(())
}

/// Verify the extracted Chrome binary against its recorded
/// `checksum.blake3` digest (audit-05 F-3: BLAKE3 was write-only).
///
/// Fails closed on every missing/invalid state — a missing checksum file, an
/// unparseable one, a missing binary, or a digest mismatch. A digest file
/// that predates the extraction (or a tampered binary) must never read as
/// "verified". This is the **full** path (always re-hashes); the cheap
/// re-check used by `list`/launch is [`verify_blake3_checksum_cached`].
pub fn verify_blake3_checksum(install_dir: &Path) -> Result<(), BrowserError> {
    let binary_path = find_installed_binary(install_dir).ok_or_else(|| {
        BrowserError::FileNotFound(format!(
            "no Chrome binary found under {} for BLAKE3 verification",
            install_dir.display()
        ))
    })?;
    let expected = read_recorded_blake3(&binary_path)?;
    verify_hash(&binary_path, &expected)?;
    eprintln!(
        "BLAKE3 verified: {}",
        binary_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    );
    Ok(())
}

/// Read and validate the digest recorded in `checksum.blake3` next to
/// `binary_path` (format: `"<64 hex chars>  <filename>"`, sha256sum style).
fn read_recorded_blake3(binary_path: &Path) -> Result<String, BrowserError> {
    let checksum_path = binary_path.with_file_name("checksum.blake3");
    let recorded = fs::read_to_string(&checksum_path).map_err(|e| {
        BrowserError::FileNotFound(format!(
            "missing BLAKE3 checksum {}: {e}",
            checksum_path.display()
        ))
    })?;
    let expected = recorded
        .trim()
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_lowercase();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BrowserError::DownloadFailed(format!(
            "malformed BLAKE3 checksum file {}: {recorded:?}",
            checksum_path.display()
        )));
    }
    Ok(expected)
}

/// Hash `binary_path` and compare against `expected` (fails closed).
fn verify_hash(binary_path: &Path, expected: &str) -> Result<(), BrowserError> {
    let bytes = fs::read(binary_path).map_err(|e| {
        BrowserError::DownloadFailed(format!(
            "cannot read {} for BLAKE3 verify: {e}",
            binary_path.display()
        ))
    })?;
    let actual = blake3::hash(&bytes).to_hex().to_string();
    if actual != expected {
        return Err(BrowserError::ChecksumMismatch {
            expected: expected.to_string(),
            actual,
            file: binary_path.display().to_string(),
        });
    }
    Ok(())
}

// ── S1: cheap re-verify (size + mtime stamp) ────────────────────────────────

/// Stamp file written beside `checksum.blake3` after a successful full
/// verification: records the verified binary's `(size, mtime_ns)` key plus
/// the digest it was verified against, so [`verify_blake3_checksum_cached`]
/// can skip re-reading ~200 MB per `list`/launch when the key is unchanged
/// (cycle-02 §3.1 S1 cost note: a full re-hash per launch is not an
/// acceptable default).
///
/// Trust note: the stamp is a **cost optimization inside the install's own
/// trust domain**, not a security boundary — a writer who can rewrite the
/// binary can also rewrite the stamp. It never *substitutes* for the digest:
/// the fast path still requires `checksum.blake3` to agree, and any key
/// movement (content change, size change, touch) forces the full re-hash.
const BLAKE3_STAMP_FILE: &str = "checksum.blake3.stamp";
const BLAKE3_STAMP_PREFIX: &str = "blake3-ok-v1";

fn blake3_stamp_path(binary_path: &Path) -> PathBuf {
    binary_path.with_file_name(BLAKE3_STAMP_FILE)
}

/// `(size, mtime_ns)` verification key of a file. Coarse filesystems give
/// coarser keys — that only ever costs an extra full re-hash, never a
/// false verification.
fn stat_key(meta: &fs::Metadata) -> (u64, u128) {
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (meta.len(), mtime_ns)
}

/// Record the verification stamp for `install_dir` — best-effort: a
/// read-only install dir simply loses the fast path; it must never fail the
/// install (the stamp is an optimization, unlike the checksum file itself).
fn record_blake3_stamp(install_dir: &Path) {
    let Some(binary_path) = find_installed_binary(install_dir) else {
        return;
    };
    let Ok(meta) = fs::metadata(&binary_path) else {
        return;
    };
    let Ok(expected) = read_recorded_blake3(&binary_path) else {
        return;
    };
    let (size, mtime_ns) = stat_key(&meta);
    let line = format!("{BLAKE3_STAMP_PREFIX} {size} {mtime_ns} {expected}\n");
    let _ = fs::write(blake3_stamp_path(&binary_path), line);
}

/// Re-verify an installed Chrome binary cheaply: when the `(size, mtime)`
/// key and the recorded digest both match the stamp left by the last full
/// verification, skip the re-hash; otherwise run the full
/// [`verify_blake3_checksum`] and refresh the stamp.
///
/// Used by [`list_installed`] — and therefore by the launch-path detection
/// [`find_installed_chrome`] — so a ~200 MB re-hash does not run on every
/// invocation (cycle-02 §3.1 S1).
pub fn verify_blake3_checksum_cached(install_dir: &Path) -> Result<(), BrowserError> {
    let binary_path = find_installed_binary(install_dir).ok_or_else(|| {
        BrowserError::FileNotFound(format!(
            "no Chrome binary found under {} for BLAKE3 verification",
            install_dir.display()
        ))
    })?;
    let expected = read_recorded_blake3(&binary_path)?;

    // Fast path: stamp agrees with the current key AND the checksum file.
    if let Ok(meta) = fs::metadata(&binary_path) {
        let (size, mtime_ns) = stat_key(&meta);
        if let Ok(stamp) = fs::read_to_string(blake3_stamp_path(&binary_path)) {
            let mut parts = stamp.split_whitespace();
            let matches = parts.next() == Some(BLAKE3_STAMP_PREFIX)
                && parts.next().and_then(|v| v.parse::<u64>().ok()) == Some(size)
                && parts.next().and_then(|v| v.parse::<u128>().ok()) == Some(mtime_ns)
                && parts.next() == Some(expected.as_str());
            if matches {
                return Ok(());
            }
        }
    }

    // Key moved (or no stamp yet): full re-hash, then refresh the stamp.
    verify_hash(&binary_path, &expected)?;
    record_blake3_stamp(install_dir);
    Ok(())
}

// ── CfT pin verification (S1, fail-closed) ──────────────────────────────────

/// Identity of one CfT artifact — the pin-table key (see
/// [`crate::browser::cft_pins`]).
#[derive(Debug, Clone, Copy)]
pub struct CftArtifact<'a> {
    pub version: &'a str,
    pub platform: BrowserPlatform,
    /// `"chrome"` (full) or `"chrome-headless-shell"`.
    pub variant: &'a str,
}

/// Outcome of comparing a downloaded artifact against expected digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumOutcome {
    /// An in-repo pin exists for this artifact and the SHA-256 matched.
    Pinned,
    /// No in-repo pin for this artifact. The remote sidecar may have been
    /// present and matched, but a same-origin sidecar is not a pin — the
    /// install requires the audited [`crate::browser::cft_pins::allow_unpinned`]
    /// override.
    Unpinned,
}

/// Pure verification core: SHA-256 of `zip_bytes` against the in-repo pin
/// table (authoritative) and an optional remote `.sha256` sidecar
/// (cross-check only — its absence never permits an unverified install).
///
/// Refusals are `ChecksumMismatch` errors; a pin miss is reported as
/// [`ChecksumOutcome::Unpinned`] and decided by [`cft_install_decision`].
pub fn verify_cft_checksum(
    zip_bytes: &[u8],
    artifact: &CftArtifact<'_>,
    remote_expected: Option<&str>,
    pins: &[crate::browser::cft_pins::CftPin],
) -> Result<ChecksumOutcome, BrowserError> {
    let actual = sha256_hex(zip_bytes);
    let file = format!(
        "{} {} ({})",
        artifact.variant, artifact.version, artifact.platform
    );
    match crate::browser::cft_pins::pinned_sha256_in(
        pins,
        artifact.version,
        artifact.platform,
        artifact.variant,
    ) {
        Some(pinned) => {
            if actual != pinned {
                return Err(BrowserError::ChecksumMismatch {
                    expected: pinned.to_string(),
                    actual,
                    file,
                });
            }
            if let Some(remote) = remote_expected {
                if actual != remote {
                    return Err(BrowserError::ChecksumMismatch {
                        expected: remote.to_string(),
                        actual,
                        file,
                    });
                }
            }
            Ok(ChecksumOutcome::Pinned)
        }
        None => {
            if let Some(remote) = remote_expected {
                if actual != remote {
                    return Err(BrowserError::ChecksumMismatch {
                        expected: remote.to_string(),
                        actual,
                        file,
                    });
                }
            }
            Ok(ChecksumOutcome::Unpinned)
        }
    }
}

/// Map a checksum outcome to the install decision — fail-closed on unpinned.
pub fn cft_install_decision(
    outcome: ChecksumOutcome,
    artifact: &CftArtifact<'_>,
    allow_unpinned: bool,
) -> Result<(), BrowserError> {
    match outcome {
        ChecksumOutcome::Pinned => Ok(()),
        ChecksumOutcome::Unpinned if allow_unpinned => Ok(()),
        ChecksumOutcome::Unpinned => Err(BrowserError::UnpinnedArtifact {
            version: artifact.version.to_string(),
            platform: artifact.platform.as_cft_str().to_string(),
            variant: artifact.variant.to_string(),
        }),
    }
}

/// The unpinned-install override is operator-chosen and leak-by-design, like
/// the browser-zone `TALLOW_ALLOW_DIRECT` opt-in — never silent: one audit
/// record per install decision (R-6.13 pattern via the observability
/// emitter).
///
/// Class note: reuses [`crate::observability::EventClass::DirectEgress`]
/// (audit plane) as the closest existing "operator bypassed a security
/// default" class — a dedicated `SupplyChainOverride` class is an
/// `observability.rs` follow-up (recorded in the E-2-05 log).
fn emit_cft_unpinned_override(artifact: &CftArtifact<'_>) {
    let detail = format!(
        "TALLOW_CFT_ALLOW_UNPINNED=1 — installing {} {} ({}) with no in-repo SHA-256 pin",
        artifact.variant, artifact.version, artifact.platform
    );
    let _ = crate::observability::emit_to_default_journal(&crate::observability::SecurityEvent {
        class: crate::observability::EventClass::DirectEgress,
        actor: "browser.cft".to_string(),
        target: Some(detail.clone()),
        size: detail.len(),
        at_ms: crate::observability::now_ms(),
    });
}

/// File-level verification stage used by [`download_browser`]: reads the
/// downloaded zip, runs [`verify_cft_checksum`] + [`cft_install_decision`],
/// and — on any refusal — removes the temp zip **and** the install dir so a
/// failed install leaves no trace (and is never announced as installed).
///
/// `pins` is injected so the offline unit tests can exercise pin
/// hit/miss/mismatch without a network fetch; call sites pass
/// [`crate::browser::cft_pins::CFT_PINS`].
fn verify_artifact_or_cleanup(
    tmp_zip: &Path,
    install_dir: &Path,
    artifact: &CftArtifact<'_>,
    remote_expected: Option<&str>,
    allow_unpinned: bool,
    pins: &[crate::browser::cft_pins::CftPin],
) -> Result<ChecksumOutcome, BrowserError> {
    let zip_bytes = match fs::read(tmp_zip) {
        Ok(b) => b,
        Err(e) => {
            let _ = fs::remove_dir_all(install_dir);
            return Err(BrowserError::DownloadFailed(format!(
                "cannot read zip for checksum: {e}"
            )));
        }
    };
    let actual_hash = sha256_hex(&zip_bytes);
    eprintln!("SHA-256: {actual_hash}");

    match verify_cft_checksum(&zip_bytes, artifact, remote_expected, pins)
        .and_then(|outcome| cft_install_decision(outcome, artifact, allow_unpinned).map(|()| outcome))
    {
        Ok(outcome) => Ok(outcome),
        Err(e) => {
            // Fail closed: refusal leaves no partial state behind.
            let _ = fs::remove_file(tmp_zip);
            let _ = fs::remove_dir_all(install_dir);
            Err(e)
        }
    }
}

// ── Download and Extraction ─────────────────────────────────────────────────

/// Download a CfT zip from `url` and extract it to `install_dir`.
///
/// `version`, `platform`, and `variant` identify the artifact for the
/// fail-closed pin check (S1): the downloaded zip's SHA-256 must match the
/// in-repo pin in [`crate::browser::cft_pins`], or the install refuses
/// unless the audited `TALLOW_CFT_ALLOW_UNPINNED=1` override is set. After
/// extraction the extracted binary is verified against its freshly written
/// `checksum.blake3` before returning.
pub fn download_browser(
    url: &str,
    install_dir: &Path,
    version: &str,
    platform: BrowserPlatform,
    variant: &str,
) -> Result<(), BrowserError> {
    // Create install dir
    fs::create_dir_all(install_dir).map_err(|e| {
        BrowserError::DownloadFailed(format!(
            "cannot create directory {}: {e}",
            install_dir.display()
        ))
    })?;

    let tmp_zip = install_dir.with_extension("tmp.zip");

    // Download
    eprintln!("Downloading from {url}...");
    let mut reader = crate::runtime::egress_http::get(url)
        .call()
        .map_err(|e| BrowserError::DownloadFailed(format!("download failed: {e}")))?
        .into_body()
        .into_with_config()
        .limit(500_000_000) // 500 MB limit
        .reader();

    {
        let mut file = fs::File::create(&tmp_zip).map_err(|e| {
            BrowserError::DownloadFailed(format!(
                "cannot create temp file {}: {e}",
                tmp_zip.display()
            ))
        })?;

        let mut buf = vec![0u8; 8192];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(|e| {
                BrowserError::DownloadFailed(format!("download read error: {e}"))
            })?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).map_err(|e| {
                BrowserError::DownloadFailed(format!("write error: {e}"))
            })?;
            total += n as u64;
        }
        eprintln!("Downloaded {:.1} MB", total as f64 / 1_048_576.0);
    }

    // SHA-256 verification — pin first (fail-closed); the remote `.sha256`
    // sidecar is only an additional cross-check (audit-05 F-3). The tmp zip
    // and install dir are removed on refusal.
    let artifact = CftArtifact {
        version,
        platform,
        variant,
    };
    let remote_expected = fetch_sha256_checksum(url);
    let outcome = verify_artifact_or_cleanup(
        &tmp_zip,
        install_dir,
        &artifact,
        remote_expected.as_deref(),
        crate::browser::cft_pins::allow_unpinned(),
        crate::browser::cft_pins::CFT_PINS,
    )?;
    match outcome {
        ChecksumOutcome::Pinned => {
            eprintln!("SHA-256 pin verified for {variant} {version} ({platform}).");
        }
        ChecksumOutcome::Unpinned => {
            emit_cft_unpinned_override(&artifact);
            eprintln!(
                "Warning: TALLOW_CFT_ALLOW_UNPINNED=1 — no in-repo SHA-256 pin for \
                 {variant} {version} ({platform}); installing WITHOUT pin verification \
                 (override recorded in the audit journal)."
            );
        }
    }

    // Extract
    eprintln!("Extracting...");
    let zip_file = fs::File::open(&tmp_zip).map_err(|e| {
        BrowserError::DownloadFailed(format!(
            "cannot open zip {}: {e}",
            tmp_zip.display()
        ))
    })?;
    let mut archive = zip::ZipArchive::new(zip_file).map_err(|e| {
        BrowserError::DownloadFailed(format!("invalid zip file: {e}"))
    })?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            BrowserError::DownloadFailed(format!("zip entry error: {e}"))
        })?;

        let out_path = match entry.enclosed_name() {
            Some(name) => install_dir.join(name),
            None => continue,
        };

        if entry.is_dir() {
            fs::create_dir_all(&out_path).map_err(|e| {
                BrowserError::DownloadFailed(format!(
                    "cannot create dir {}: {e}",
                    out_path.display()
                ))
            })?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    BrowserError::DownloadFailed(format!(
                        "cannot create dir {}: {e}",
                        parent.display()
                    ))
                })?;
            }
            let mut outfile = fs::File::create(&out_path).map_err(|e| {
                BrowserError::DownloadFailed(format!(
                    "cannot create file {}: {e}",
                    out_path.display()
                ))
            })?;
            std::io::copy(&mut entry, &mut outfile).map_err(|e| {
                BrowserError::DownloadFailed(format!("extraction error: {e}"))
            })?;

            // Set executable permission on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = entry.unix_mode() {
                    fs::set_permissions(&out_path, fs::Permissions::from_mode(mode))
                        .ok();
                }
            }
        }
    }

    // Clean up temp zip
    let _ = fs::remove_file(&tmp_zip);

    // Record the extracted binary's BLAKE3 digest and immediately read it
    // back (audit-05 F-3) — before the version dir is announced as
    // installed. A write or verification failure fails the install. The
    // (size, mtime) stamp is refreshed so later `list`/launch re-checks are
    // cheap (S1); the extraction path itself always runs the full hash.
    write_blake3_checksum(install_dir)?;
    verify_blake3_checksum(install_dir)?;
    record_blake3_stamp(install_dir);

    eprintln!("Extraction complete.");
    Ok(())
}

// ── Version Management ──────────────────────────────────────────────────────

/// An installed browser version entry.
#[derive(Debug, Clone)]
pub struct InstalledVersion {
    pub version: String,
    pub path: PathBuf,
    pub variant: String,
    pub installed_at: String,
}

/// List all installed browser versions, sorted newest first.
pub fn list_installed() -> Result<Vec<InstalledVersion>, BrowserError> {
    let dir = browser_install_dir()?;
    let mut versions = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return Ok(versions), // No directory = no installs
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();

        // Match directories like "chrome-headless-shell-<version>"
        // or "chrome-<version>" (version is the CfT release, e.g. 151.0.7922.173)
        let (variant, version) = if let Some(v) = name.strip_prefix("chrome-headless-shell-") {
            ("chrome-headless-shell".to_string(), v.to_string())
        } else if let Some(v) = name.strip_prefix("chrome-") {
            ("chrome".to_string(), v.to_string())
        } else {
            continue;
        };

        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // S1 fail-closed re-verify (cheap via the (size, mtime) stamp): a
        // tampered or unverifiable install is not listed — and therefore not
        // launchable from the managed path (`find_installed_chrome` walks
        // this list) — until it is re-installed.
        if let Err(e) = verify_blake3_checksum_cached(&path) {
            eprintln!(
                "warning: ignoring {} — BLAKE3 verification failed ({e})",
                path.display()
            );
            continue;
        }

        // Get modification time as a rough "installed_at"
        let installed_at = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| {
                let elapsed = t
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                // Format as ISO-ish date
                let secs = elapsed.as_secs();
                let days = secs / 86400;
                let years = 1970 + days / 365;
                format!("{years}")
            })
            .unwrap_or_else(|| "unknown".to_string());

        versions.push(InstalledVersion {
            version,
            path,
            variant,
            installed_at,
        });
    }

    // Sort by version descending (newest first)
    versions.sort_by(|a, b| b.version.cmp(&a.version));
    Ok(versions)
}

/// Remove an installed browser version by version string.
pub fn remove_version(version: &str) -> Result<(), BrowserError> {
    let dir = browser_install_dir()?;

    // Try both variant prefixes
    let candidates = [
        dir.join(format!("chrome-headless-shell-{version}")),
        dir.join(format!("chrome-{version}")),
    ];

    let mut removed = false;
    for candidate in &candidates {
        if candidate.exists() {
            fs::remove_dir_all(candidate).map_err(|e| {
                BrowserError::DownloadFailed(format!(
                    "cannot remove {}: {e}",
                    candidate.display()
                ))
            })?;
            removed = true;
        }
    }

    if !removed {
        return Err(BrowserError::DownloadFailed(format!(
            "no installed browser with version '{version}' found"
        )));
    }

    Ok(())
}

// ── Auto-Detection ──────────────────────────────────────────────────────────

/// Find an installed Chrome binary.
///
/// Search order:
/// 1. Managed installs under `~/.tallow/browsers/` (newest first)
/// 2. System Chrome at standard OS-specific locations
pub fn find_installed_chrome() -> Option<PathBuf> {
    // Check managed installs first
    if let Ok(versions) = list_installed() {
        for v in &versions {
            // Determine the executable within the managed directory
            let platform = BrowserPlatform::detect().ok()?;
            let exec_rel = if v.variant == "chrome-headless-shell" {
                platform.chrome_executable()
            } else {
                platform.chrome_full_executable()
            };
            let exec_path = v.path.join(exec_rel);
            if exec_path.exists() {
                return Some(exec_path);
            }
        }
    }

    // Check system Chrome locations
    find_system_chrome()
}

/// Find the installed binary for a given browser backend.
///
/// Dispatches to engine-specific discovery so a non-Chromium backend never
/// accidentally launches Chrome (which would fail to speak Juggler). Falls
/// back to [`find_installed_chrome`] for the Chromium backend.
pub fn find_browser_for_backend(
    backend: &crate::browser::process::BrowserBackend,
) -> Option<PathBuf> {
    use crate::browser::process::BrowserBackend;
    match backend {
        BrowserBackend::Chromium => find_installed_chrome(),
        BrowserBackend::Camoufox => find_camoufox(),
        BrowserBackend::Firefox => find_firefox(),
    }
}

/// Locate a Camoufox (Firefox-ESR stealth rebuild) binary.
///
/// Search order: `$CAMOUFOX_PATH`, managed install dir, then common system
/// paths and `$PATH` lookups for the `camoufox` / `camoufox-esr` executables.
pub fn find_camoufox() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CAMOUFOX_PATH") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    // Managed install location
    if let Some(dir) = managed_browser_dir() {
        let candidates = [
            dir.join("camoufox").join("camoufox"),
            dir.join("camoufox").join("camoufox-esr"),
            dir.join("camoufox"),
        ];
        if let Some(p) = candidates.into_iter().find(|p| p.exists()) {
            return Some(p);
        }
    }
    // Camoufox Python default install (~/.cache/camoufox/browsers/official/<ver>/camoufox).
    // This is the Juggler-enabled Firefox the Camoufox pip package fetches; prefer
    // it over stock firefox so Firefox-family backends actually speak Juggler.
    if let Some(home) = std::env::var_os("HOME") {
        let official = PathBuf::from(home).join(".cache/camoufox/browsers/official");
        if let Ok(entries) = std::fs::read_dir(&official) {
            for e in entries.flatten() {
                let b = e.path().join("camoufox");
                if b.is_file() {
                    return Some(b);
                }
            }
        }
    }
    // System / PATH lookup
    let sys = ["/usr/local/bin/camoufox", "/usr/bin/camoufox", "/opt/camoufox/camoufox"];
    sys.into_iter().map(PathBuf::from).find(|p| p.exists())
        .or_else(|| find_on_path(&["camoufox", "camoufox-esr"]))
}

/// Locate a stock Firefox binary (Firefox-family backend).
pub fn find_firefox() -> Option<PathBuf> {
    let sys: Vec<PathBuf> = if cfg!(target_os = "windows") {
        vec![PathBuf::from(
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
        )]
    } else if cfg!(target_os = "macos") {
        vec![PathBuf::from(
            "/Applications/Firefox.app/Contents/MacOS/firefox",
        )]
    } else {
        vec![
            PathBuf::from("/usr/bin/firefox"),
            PathBuf::from("/usr/bin/firefox-esr"),
            PathBuf::from("/snap/bin/firefox"),
            PathBuf::from("/opt/firefox/firefox"),
        ]
    };
    sys.into_iter().find(|p| p.exists()).or_else(|| find_on_path(&["firefox", "firefox-esr"]))
}

/// Look up an executable by name on `$PATH`.
fn find_on_path(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in names {
            let p = dir.join(name);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

/// The managed (self-hosted) browser install directory, if configured.
fn managed_browser_dir() -> Option<PathBuf> {
    use std::path::Path;
    let home = std::env::var_os("HOME")?;
    let dir = Path::new(&home).join(".tallow").join("browsers");
    dir.exists().then_some(dir)
}

/// Check standard system Chrome install locations.
fn find_system_chrome() -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = if cfg!(target_os = "windows") {
        vec![
            PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            PathBuf::from(
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            ),
        ]
    } else if cfg!(target_os = "macos") {
        vec![PathBuf::from(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        )]
    } else {
        // Linux (including RISC-V — uses distribution-provided Chromium)
        vec![
            PathBuf::from("/usr/bin/google-chrome"),
            PathBuf::from("/usr/bin/chromium-browser"),
            PathBuf::from("/usr/bin/chromium"),
            PathBuf::from("/usr/bin/chromium-browser-stable"),
        ]
    };

    candidates.into_iter().find(|p| p.exists())
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Install Chrome for Testing (headless-shell by default, full Chrome with `full=true`).
///
/// Returns the path to the installed Chrome executable.
pub fn install_browser(full: bool) -> Result<PathBuf, BrowserError> {
    let platform = BrowserPlatform::detect()?;

    // RISC-V has no Chrome for Testing binaries — return a helpful error
    if !platform.is_cft_supported() {
        let hint = platform.cft_unsupported_hint().unwrap_or("No CfT binaries available for this platform.");
        return Err(BrowserError::DownloadFailed(hint.to_string()));
    }

    let variant = if full { "chrome" } else { "chrome-headless-shell" };

    // Prefer the pinned build. "Latest stable" is a moving target: it turned the
    // CI browser job into an unpinned install the moment Google published a new
    // channel version, and the runner and this box would then test different
    // binaries. A pin table exists so the gate has a fixed subject.
    let dir = browser_install_dir()?;
    let (version, url) = match crate::browser::cft_pins::newest_pinned(platform, variant) {
        Some(pinned) => {
            let cft = platform.as_cft_str();
            eprintln!("Using pinned Chrome for Testing {pinned} ({variant}, {cft})");
            (
                pinned.to_string(),
                format!(
                    "https://storage.googleapis.com/chrome-for-testing-public/{pinned}/{cft}/{variant}-{cft}.zip"
                ),
            )
        }
        None => {
            eprintln!("No pin for {variant} on {}; fetching latest stable version...", platform.as_cft_str());
            let info = fetch_latest_stable_version()?;
            eprintln!("Latest stable: Chrome {}", info.version);
            let url = find_download_url(&info, &platform, full)?;
            (info.version.clone(), url)
        }
    };

    let install_dir = dir.join(format!("{variant}-{version}"));
    let exec_rel = if full {
        platform.chrome_full_executable()
    } else {
        platform.chrome_executable()
    };
    let exec_path = install_dir.join(exec_rel);

    if exec_path.exists() {
        eprintln!("Chrome {version} already installed at {}", exec_path.display());
        return Ok(exec_path);
    }

    // Download and extract
    download_browser(&url, &install_dir, &version, platform, variant)?;

    // Verify the executable exists
    if !exec_path.exists() {
        return Err(BrowserError::DownloadFailed(format!(
            "extraction succeeded but executable not found at {}",
            exec_path.display()
        )));
    }

    eprintln!(
        "Chrome {} installed to {}",
        version,
        exec_path.display()
    );
    Ok(exec_path)
}

/// Ensure a browser binary is available, downloading one if necessary.
///
/// Search order:
/// 1. Managed installs under `~/.tallow/browsers/`
/// 2. System Chrome at standard locations
/// 3. Auto-download chrome-headless-shell (transparent first-use download)
///
/// This is the primary entry point for BrowserConfig when no explicit
/// `chrome_path` is set.
pub fn ensure_browser_available() -> Result<PathBuf, BrowserError> {
    if let Some(path) = find_installed_chrome() {
        return Ok(path);
    }

    eprintln!("No Chrome found. Downloading chrome-headless-shell...");
    install_browser(false)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detect_returns_valid() {
        // Should succeed on any supported CI/dev machine
        let platform = BrowserPlatform::detect();
        assert!(platform.is_ok(), "platform detection failed: {platform:?}");
    }

    #[test]
    fn test_as_cft_str_all_variants() {
        assert_eq!(BrowserPlatform::Linux64.as_cft_str(), "linux64");
        assert_eq!(BrowserPlatform::LinuxArm64.as_cft_str(), "linux-arm64");
        assert_eq!(BrowserPlatform::LinuxRiscV64.as_cft_str(), "linux-riscv64");
        assert_eq!(BrowserPlatform::MacArm64.as_cft_str(), "mac-arm64");
        assert_eq!(BrowserPlatform::MacX64.as_cft_str(), "mac-x64");
        assert_eq!(BrowserPlatform::Win32.as_cft_str(), "win32");
        assert_eq!(BrowserPlatform::Win64.as_cft_str(), "win64");
    }

    #[test]
    fn test_riscv_not_cft_supported() {
        assert!(!BrowserPlatform::LinuxRiscV64.is_cft_supported());
        assert!(BrowserPlatform::Linux64.is_cft_supported());
        assert!(BrowserPlatform::Win64.is_cft_supported());
        assert!(BrowserPlatform::MacArm64.is_cft_supported());
    }

    #[test]
    fn test_riscv_hint_contains_package_manager_instructions() {
        let hint = BrowserPlatform::LinuxRiscV64.cft_unsupported_hint();
        assert!(hint.is_some());
        let h = hint.unwrap();
        assert!(h.contains("RISC-V"));
        assert!(h.contains("apt") || h.contains("dnf") || h.contains("pacman"));
        assert!(h.contains("chromium"));
    }

    #[test]
    fn test_non_riscv_platforms_have_no_hint() {
        assert!(BrowserPlatform::Linux64.cft_unsupported_hint().is_none());
        assert!(BrowserPlatform::Win64.cft_unsupported_hint().is_none());
        assert!(BrowserPlatform::MacArm64.cft_unsupported_hint().is_none());
    }

    #[test]
    fn test_chrome_executable_all_variants() {
        assert_eq!(
            BrowserPlatform::Linux64.chrome_executable(),
            "chrome-headless-shell-linux64/chrome-headless-shell"
        );
        assert_eq!(
            BrowserPlatform::LinuxRiscV64.chrome_executable(),
            "chromium"
        );
        assert_eq!(
            BrowserPlatform::MacArm64.chrome_executable(),
            "chrome-headless-shell-mac-arm64/chrome-headless-shell"
        );
        assert_eq!(
            BrowserPlatform::MacX64.chrome_executable(),
            "chrome-headless-shell-mac-x64/chrome-headless-shell"
        );
        assert_eq!(
            BrowserPlatform::Win32.chrome_executable(),
            "chrome-headless-shell-win32/chrome-headless-shell.exe"
        );
        assert_eq!(
            BrowserPlatform::Win64.chrome_executable(),
            "chrome-headless-shell-win64/chrome-headless-shell.exe"
        );
    }

    #[test]
    fn test_chrome_full_executable_all_variants() {
        assert_eq!(
            BrowserPlatform::Linux64.chrome_full_executable(),
            "chrome-linux64/chrome"
        );
        assert!(BrowserPlatform::MacArm64
            .chrome_full_executable()
            .contains("Google Chrome for Testing"));
        assert!(BrowserPlatform::Win64
            .chrome_full_executable()
            .ends_with("chrome.exe"));
    }

    #[test]
    fn test_browser_install_dir_returns_path() {
        let dir = browser_install_dir();
        assert!(dir.is_ok(), "browser_install_dir failed: {dir:?}");
        let path = dir.unwrap();
        assert!(!path.as_os_str().is_empty());
        assert!(path.ends_with("browsers"));
    }

    #[test]
    fn test_parse_cft_response_fixture() {
        // Version-agnostic fixture: the version literal is only used to prove
        // the parser round-trips whatever version the CfT API reports. The
        // value mirrors the current stable channel (151.0.7922.173 at the
        // time of writing) but the test does not depend on it — update the
        // literal when the fixture is refreshed, nothing else changes.
        let fixture = r#"{
            "timestamp": "2026-03-01T00:00:00.000Z",
            "channels": {
                "Stable": {
                    "channel": "Stable",
                    "version": "151.0.7922.173",
                    "revision": "1440019",
                    "downloads": {
                        "chrome": [
                            { "platform": "linux64", "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.173/linux64/chrome-linux64.zip" },
                            { "platform": "win64", "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.173/win64/chrome-win64.zip" }
                        ],
                        "chrome-headless-shell": [
                            { "platform": "linux64", "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.173/linux64/chrome-headless-shell-linux64.zip" },
                            { "platform": "win64", "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.173/win64/chrome-headless-shell-win64.zip" },
                            { "platform": "mac-arm64", "url": "https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.173/mac-arm64/chrome-headless-shell-mac-arm64.zip" }
                        ]
                    }
                }
            }
        }"#;

        let info = parse_cft_response(fixture).unwrap();
        assert_eq!(info.version, "151.0.7922.173");
        assert_eq!(info.downloads_headless.len(), 3);
        assert_eq!(info.downloads_chrome.len(), 2);

        // Verify we can find a specific platform
        let url = find_download_url(&info, &BrowserPlatform::Win64, false).unwrap();
        assert!(url.contains("chrome-headless-shell-win64.zip"));

        let url = find_download_url(&info, &BrowserPlatform::Linux64, true).unwrap();
        assert!(url.contains("chrome-linux64.zip"));
    }

    #[test]
    fn test_find_download_url_missing_platform() {
        let info = CfTVersionInfo {
            version: "151.0.0.0".to_string(),
            downloads_headless: vec![CfTDownload {
                platform: "linux64".to_string(),
                url: "https://example.com/linux.zip".to_string(),
            }],
            downloads_chrome: vec![],
        };

        // Win64 headless should fail (only linux64 available)
        let result = find_download_url(&info, &BrowserPlatform::Win64, false);
        assert!(result.is_err());

        // Full chrome should fail (no chrome downloads)
        let result = find_download_url(&info, &BrowserPlatform::Linux64, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_ensure_browser_available_signature() {
        // Verify the function compiles with the correct signature.
        // We can't test actual download in unit tests, but we verify it returns
        // Result<PathBuf, BrowserError>.
        let _: fn() -> Result<PathBuf, BrowserError> = ensure_browser_available;
    }

    #[test]
    fn test_platform_display() {
        let p = BrowserPlatform::Win64;
        assert_eq!(format!("{p}"), "win64");
    }

    #[test]
    fn test_list_installed_empty() {
        // Should return Ok with possibly empty vec (no crash)
        let result = list_installed();
        assert!(result.is_ok());
    }

    #[test]
    fn test_remove_version_nonexistent() {
        let result = remove_version("99.99.9999.99");
        assert!(result.is_err());
    }

    #[test]
    fn verify_sha256_correct_hash() {
        // SHA-256 of "hello world" is well-known
        let data = b"hello world";
        let hash = sha256_hex(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn verify_sha256_mismatch_detected() {
        let data = b"hello world";
        let hash = sha256_hex(data);
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_ne!(hash, wrong, "SHA-256 should not match a bogus hash");
    }

    #[test]
    fn test_find_browser_dispatches_by_backend() {
        use crate::browser::process::BrowserBackend;
        // Chromium dispatch must resolve (system Chrome or PATH chrome), never panic
        let _ = find_browser_for_backend(&BrowserBackend::Chromium);
        // Firefox-family dispatch must never fall through to a Chrome binary.
        // find_camoufox() only returns a path under camoufox-specific names, so
        // whatever it returns is legitimately a Camoufox (never Chrome).
        if let Some(path) = find_browser_for_backend(&BrowserBackend::Camoufox) {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            assert!(
                name.contains("camoufox"),
                "Camoufox backend must resolve to a camoufox binary, got {name}"
            );
        }
    }

    #[test]
    fn test_find_on_path_honors_path() {
        // Build a temp dir, drop a fake executable in it, and confirm find_on_path
        // locates it when that dir is prepended to PATH.
        let tmp = std::env::temp_dir().join(format!("tallow-dl-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).ok();
        let fake = tmp.join("fake-browser-xyz");
        std::fs::write(&fake, b"#!/bin/sh\n").ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).ok();
        }
        let found = {
            let old = std::env::var_os("PATH").unwrap_or_default();
            // join_paths uses the platform separator (';' on Windows, ':' on
            // Unix); a hard-coded ':' made the entry part of the previous path
            // element and find_on_path returned None.
            let combined = std::env::join_paths(
                std::iter::once(tmp.clone()).chain(std::env::split_paths(&old)),
            )
            .expect("join PATH")
            .to_string_lossy()
            .to_string();
            // SAFETY: single-threaded test; restoring PATH before returning.
            unsafe { std::env::set_var("PATH", &combined) };
            let r = find_on_path(&["fake-browser-xyz"]);
            unsafe { std::env::set_var("PATH", &old) };
            r
        };
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(found, Some(fake));
    }

    // ── S1: CfT pin verification (offline fixtures, no network) ─────────────

    use crate::browser::cft_pins::CftPin;

    fn fixture_pin(sha256: &'static str) -> CftPin {
        CftPin {
            version: "999.0.0.1",
            platform: "linux-arm64",
            variant: "chrome-headless-shell",
            sha256,
        }
    }

    fn fixture_artifact<'a>(version: &'a str) -> CftArtifact<'a> {
        CftArtifact {
            version,
            platform: BrowserPlatform::LinuxArm64,
            variant: "chrome-headless-shell",
        }
    }

    #[test]
    fn cft_pin_hit_and_match_is_pinned() {
        let zip = b"fake-cft-zip-bytes";
        let digest: &'static str = Box::leak(sha256_hex(zip).into_boxed_str());
        let pins = [fixture_pin(digest)];
        let outcome = verify_cft_checksum(zip, &fixture_artifact("999.0.0.1"), None, &pins)
            .expect("pin match must verify");
        assert_eq!(outcome, ChecksumOutcome::Pinned);
        // A matching sidecar cross-check keeps it Pinned.
        let outcome = verify_cft_checksum(zip, &fixture_artifact("999.0.0.1"), Some(digest), &pins)
            .expect("pin + sidecar match must verify");
        assert_eq!(outcome, ChecksumOutcome::Pinned);
    }

    #[test]
    fn cft_pin_mismatch_refuses() {
        let zip = b"tampered-bytes";
        let pins = [fixture_pin(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )];
        let err = verify_cft_checksum(zip, &fixture_artifact("999.0.0.1"), None, &pins)
            .expect_err("pin mismatch must refuse");
        match err {
            BrowserError::ChecksumMismatch { expected, actual, .. } => {
                assert_eq!(expected, "0000000000000000000000000000000000000000000000000000000000000000");
                assert_eq!(actual, sha256_hex(zip));
            }
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn cft_sidecar_mismatch_refuses_even_without_a_pin() {
        // No pin for this artifact, but the sidecar disagrees → refuse.
        let zip = b"some-bytes";
        let err = verify_cft_checksum(zip, &fixture_artifact("999.0.0.1"), Some("deadbeef"), &[])
            .expect_err("sidecar mismatch must refuse");
        assert!(matches!(err, BrowserError::ChecksumMismatch { .. }));
    }

    #[test]
    fn cft_pin_miss_is_unpinned_never_silently_verified() {
        // No pin: even a matching sidecar is only a cross-check, never a pin.
        let zip = b"some-bytes";
        let digest = sha256_hex(zip);
        let outcome = verify_cft_checksum(zip, &fixture_artifact("999.0.0.1"), Some(&digest), &[])
            .expect("pin miss with sidecar match is Unpinned, not an error");
        assert_eq!(outcome, ChecksumOutcome::Unpinned);
        let outcome = verify_cft_checksum(zip, &fixture_artifact("999.0.0.1"), None, &[])
            .expect("pin miss with no sidecar is Unpinned");
        assert_eq!(outcome, ChecksumOutcome::Unpinned);
        // A pin for a different (version, platform, variant) is a miss too.
        let pins = [fixture_pin("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")];
        let outcome = verify_cft_checksum(zip, &fixture_artifact("999.0.0.2"), Some(&digest), &pins)
            .expect("other-version pin is a miss");
        assert_eq!(outcome, ChecksumOutcome::Unpinned);
    }

    #[test]
    fn cft_unpinned_decision_fails_closed_and_names_the_override() {
        let artifact = fixture_artifact("999.0.0.1");
        let err = cft_install_decision(ChecksumOutcome::Unpinned, &artifact, false)
            .expect_err("unpinned without override must refuse");
        match err {
            BrowserError::UnpinnedArtifact { version, platform, variant } => {
                assert_eq!(version, "999.0.0.1");
                assert_eq!(platform, "linux-arm64");
                assert_eq!(variant, "chrome-headless-shell");
            }
            other => panic!("expected UnpinnedArtifact, got {other:?}"),
        }
        let msg = err_text(&cft_install_decision(ChecksumOutcome::Unpinned, &artifact, false).unwrap_err());
        assert!(
            msg.contains("TALLOW_CFT_ALLOW_UNPINNED"),
            "refusal must carry the remediation override: {msg}"
        );
        // The audited override allows the install; a pin needs no override.
        assert!(cft_install_decision(ChecksumOutcome::Unpinned, &artifact, true).is_ok());
        assert!(cft_install_decision(ChecksumOutcome::Pinned, &artifact, false).is_ok());
    }

    fn err_text(e: &BrowserError) -> String {
        e.to_string()
    }

    fn fixture_dirs(tag: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "tallow-cft-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture root");
        let install_dir = root.join("chrome-headless-shell-999.0.0.1");
        std::fs::create_dir_all(&install_dir).expect("create install dir");
        let tmp_zip = root.join("artifact.tmp.zip");
        (install_dir, tmp_zip)
    }

    #[test]
    fn pin_mismatch_refusal_leaves_no_install_dir() {
        let (install_dir, tmp_zip) = fixture_dirs("pin-mismatch");
        std::fs::write(&tmp_zip, b"tampered-zip").expect("write fake zip");
        let pins = [fixture_pin(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )];
        let err = verify_artifact_or_cleanup(
            &tmp_zip,
            &install_dir,
            &fixture_artifact("999.0.0.1"),
            None,
            false,
            &pins,
        )
        .expect_err("pin mismatch must refuse");
        assert!(matches!(err, BrowserError::ChecksumMismatch { .. }));
        assert!(
            !install_dir.exists(),
            "a refused install must leave no install dir"
        );
        assert!(!tmp_zip.exists(), "the tmp zip must be removed on refusal");
        let _ = std::fs::remove_dir_all(install_dir.parent().unwrap());
    }

    #[test]
    fn unpinned_refusal_also_cleans_up() {
        let (install_dir, tmp_zip) = fixture_dirs("unpinned-refusal");
        std::fs::write(&tmp_zip, b"unpinned-zip").expect("write fake zip");
        let err = verify_artifact_or_cleanup(
            &tmp_zip,
            &install_dir,
            &fixture_artifact("999.0.0.1"),
            None,
            false,
            &[],
        )
        .expect_err("unpinned without override must refuse");
        assert!(matches!(err, BrowserError::UnpinnedArtifact { .. }));
        assert!(!install_dir.exists(), "refusal must leave no install dir");
        assert!(!tmp_zip.exists(), "refusal must remove the tmp zip");
        let _ = std::fs::remove_dir_all(install_dir.parent().unwrap());
    }

    #[test]
    fn unpinned_override_proceeds_to_extraction_state_intact() {
        let (install_dir, tmp_zip) = fixture_dirs("unpinned-override");
        std::fs::write(&tmp_zip, b"unpinned-zip").expect("write fake zip");
        let outcome = verify_artifact_or_cleanup(
            &tmp_zip,
            &install_dir,
            &fixture_artifact("999.0.0.1"),
            None,
            true,
            &[],
        )
        .expect("the audited override must allow the install");
        assert_eq!(outcome, ChecksumOutcome::Unpinned);
        assert!(tmp_zip.exists(), "the zip must survive for extraction");
        assert!(install_dir.exists(), "the install dir must survive for extraction");
        let _ = std::fs::remove_dir_all(install_dir.parent().unwrap());
    }

    #[test]
    fn unpinned_override_is_recorded_as_an_audit_event() {
        // Mirror of the zone direct-bypass audit test: the override must
        // never be silent — one journal record carrying the audit-plane
        // bypass class, actor hashed by minimization.
        let _guard = crate::runtime::egress_http::env_lock();
        let dir = std::env::temp_dir().join(format!(
            "tallow-cft-audit-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create journal dir");
        let journal = dir.join("security-events.jsonl");
        let prior = std::env::var("TALLOW_SECURITY_EVENTS").ok();
        unsafe { std::env::set_var("TALLOW_SECURITY_EVENTS", &journal) };
        emit_cft_unpinned_override(&fixture_artifact("999.0.0.1"));
        match prior {
            Some(v) => unsafe { std::env::set_var("TALLOW_SECURITY_EVENTS", v) },
            None => unsafe { std::env::remove_var("TALLOW_SECURITY_EVENTS") },
        }
        let body = std::fs::read_to_string(&journal)
            .expect("the unpinned override must have been journaled");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            body.contains("\"class\":\"direct_egress\""),
            "record must carry the audit-plane bypass class: {body}"
        );
        assert!(
            body.contains("\"plane\":\"audit\""),
            "the override is a security-posture record: {body}"
        );
        assert!(
            body.contains("\"actor_hash\""),
            "the actor must be hashed, never raw: {body}"
        );
    }

    // ── S1: BLAKE3 read-back (write → verify → tamper) ──────────────────────

    fn blake3_fixture(tag: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "tallow-blake3-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        // Platform-correct layout: find_installed_binary() looks for the host
        // platform's directory and binary name (.exe on Windows), so a
        // hard-coded linux-arm64 fixture is invisible off Linux.
        let platform = BrowserPlatform::detect().expect("host platform");
        let subdir = root.join(format!("chrome-headless-shell-{}", platform.as_cft_str()));
        std::fs::create_dir_all(&subdir).expect("create fixture subdir");
        let binary = subdir.join(if cfg!(windows) {
            "chrome-headless-shell.exe"
        } else {
            "chrome-headless-shell"
        });
        std::fs::write(&binary, b"#!/bin/sh\necho fake-chrome\n").expect("write fake binary");
        (root, binary)
    }

    #[test]
    fn blake3_write_then_verify_roundtrips() {
        let (root, _binary) = blake3_fixture("roundtrip");
        write_blake3_checksum(&root).expect("write must succeed for a real binary");
        verify_blake3_checksum(&root).expect("read-back must verify the digest it wrote");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn blake3_tamper_detection_fails_closed() {
        let (root, binary) = blake3_fixture("tamper");
        write_blake3_checksum(&root).expect("write must succeed");
        // Flip one byte — exactly the audit-05 F-3 scenario.
        let mut bytes = std::fs::read(&binary).expect("read fake binary");
        bytes.push(b'!');
        std::fs::write(&binary, &bytes).expect("tamper with fake binary");
        let err = verify_blake3_checksum(&root).expect_err("a tampered binary must fail");
        assert!(matches!(err, BrowserError::ChecksumMismatch { .. }));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn blake3_missing_checksum_fails_closed() {
        let (root, binary) = blake3_fixture("missing-checksum");
        // No checksum written at all → verification must refuse, not pass.
        let err = verify_blake3_checksum(&root).expect_err("missing checksum must fail");
        assert!(matches!(err, BrowserError::FileNotFound(_)), "got {err:?}");
        // Malformed checksum file (not a digest) → refuse.
        std::fs::write(binary.with_file_name("checksum.blake3"), b"not-a-digest\n")
            .expect("write malformed checksum");
        let err = verify_blake3_checksum(&root).expect_err("malformed checksum must fail");
        assert!(matches!(err, BrowserError::DownloadFailed(_)), "got {err:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn blake3_missing_binary_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "tallow-blake3-empty-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create empty root");
        let err = verify_blake3_checksum(&root).expect_err("no binary must fail");
        assert!(matches!(err, BrowserError::FileNotFound(_)), "got {err:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── S1: cheap re-verify — (size, mtime) stamp ───────────────────────────

    #[test]
    fn blake3_cached_verify_rehashes_when_the_key_changes() {
        let (root, binary) = blake3_fixture("cached-rehash");
        write_blake3_checksum(&root).expect("write must succeed");
        verify_blake3_checksum_cached(&root).expect("first verify (full) must pass");
        assert!(
            binary.with_file_name("checksum.blake3.stamp").exists(),
            "a successful full verify must leave the (size, mtime) stamp"
        );

        // Same-size tamper with a moved mtime: the key changed, so the full
        // re-hash must run and catch it.
        let len = std::fs::metadata(&binary).expect("stat").len() as usize;
        std::fs::write(&binary, vec![b'X'; len]).expect("tamper");
        let touched = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&binary)
            .expect("open for set_modified")
            .set_modified(touched)
            .expect("touch mtime");
        let err = verify_blake3_checksum_cached(&root)
            .expect_err("a moved key must re-hash and fail on the tampered bytes");
        assert!(
            matches!(err, BrowserError::ChecksumMismatch { .. }),
            "got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn blake3_cached_verify_fast_paths_on_an_unchanged_key() {
        // Pins the DOCUMENTED semantics: the stamp is a cost optimization
        // inside the install's trust domain, not a security boundary — a
        // same-size + same-mtime rewrite is not re-hashed (restoring the
        // original mtime after tampering keeps the key unchanged). The full
        // path still catches it, as asserted at the end.
        let (root, binary) = blake3_fixture("cached-fastpath");
        write_blake3_checksum(&root).expect("write must succeed");
        verify_blake3_checksum_cached(&root).expect("first verify must pass");
        let original_mtime = std::fs::metadata(&binary)
            .expect("stat")
            .modified()
            .expect("mtime");

        let len = std::fs::metadata(&binary).expect("stat").len() as usize;
        std::fs::write(&binary, vec![b'Y'; len]).expect("same-size tamper");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&binary)
            .expect("open")
            .set_modified(original_mtime)
            .expect("restore original mtime");

        verify_blake3_checksum_cached(&root)
            .expect("unchanged (size, mtime) key → fast path skips the re-hash (documented)");
        let err = verify_blake3_checksum(&root).expect_err("the full path must catch the tamper");
        assert!(
            matches!(err, BrowserError::ChecksumMismatch { .. }),
            "got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_installed_skips_installs_that_fail_the_checksum_reeverify() {
        // The managed path re-verifies each install (S1, cheap via the
        // stamp); a tampered install must not be listed — and therefore not
        // launchable via find_installed_chrome, which walks this list.
        let _guard = crate::runtime::egress_http::env_lock();
        let root = std::env::temp_dir().join(format!("tallow-list-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fake XDG root");
        let prior = std::env::var("XDG_DATA_HOME").ok();
        let prior_tallow = std::env::var("TALLOW_DATA_HOME").ok();
        unsafe {
            std::env::set_var("XDG_DATA_HOME", &root);
            // macOS/Windows ignore XDG_DATA_HOME; TALLOW_DATA_HOME is the
            // override browser_install_dir() actually reads there.
            std::env::set_var("TALLOW_DATA_HOME", &root);
        }

        let browsers = root.join("tallow").join("browsers");
        // The fixture must be built under the HOST platform's directory name:
        // list_installed() filters by the running platform, so a hard-coded
        // "linux-arm64" made this test unpassable on macOS and Windows.
        let host_dir = format!(
            "chrome-headless-shell-{}",
            BrowserPlatform::detect().expect("host platform").as_cft_str()
        );
        let exe = if cfg!(windows) { "chrome-headless-shell.exe" } else { "chrome-headless-shell" };
        let good = browsers.join("chrome-headless-shell-999.0.0.2");
        std::fs::create_dir_all(good.join(&host_dir)).expect("good dir");
        std::fs::write(
            good.join(&host_dir).join(exe),
            b"#!/bin/sh\necho fake\n",
        )
        .expect("good binary");
        write_blake3_checksum(&good).expect("good checksum");

        let tampered = browsers.join("chrome-headless-shell-999.0.0.1");
        std::fs::create_dir_all(tampered.join(&host_dir))
            .expect("tampered dir");
        let tampered_bin = tampered.join(&host_dir).join(exe);
        std::fs::write(&tampered_bin, b"#!/bin/sh\necho fake\n").expect("tampered binary");
        write_blake3_checksum(&tampered).expect("tampered checksum");
        std::fs::write(&tampered_bin, b"#!/bin/sh\necho OWNED\n").expect("tamper after checksum");

        let listed = list_installed().expect("list_installed must not fail on a bad entry");
        let versions: Vec<String> = listed.iter().map(|v| v.version.clone()).collect();
        assert!(
            versions.contains(&"999.0.0.2".to_string()),
            "verified install must be listed: {versions:?}"
        );
        assert!(
            !versions.contains(&"999.0.0.1".to_string()),
            "tampered install must not be listed: {versions:?}"
        );

        match prior {
            Some(v) => unsafe { std::env::set_var("XDG_DATA_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_DATA_HOME") },
        }
        match prior_tallow {
            Some(v) => unsafe { std::env::set_var("TALLOW_DATA_HOME", v) },
            None => unsafe { std::env::remove_var("TALLOW_DATA_HOME") },
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
