//! Pinned SHA-256 digests for Chrome-for-Testing (CfT) artifacts.
//!
//! Supply-chain policy (security audit-05 F-3; cycle-02 §3.1 S1): a CfT
//! download is installed only when its SHA-256 matches an **in-repo pin**
//! for the exact `(version, platform, variant)` triple. A missing pin is a
//! refusal, not a skip — [`crate::browser::download::download_browser`]
//! fails closed on a pin miss unless the operator sets the documented
//! `TALLOW_CFT_ALLOW_UNPINNED=1` override, which is logged and recorded as
//! one audit event (never silent — same posture as the browser-zone
//! `TALLOW_ALLOW_DIRECT` opt-in). The remote `.sha256` sidecar is only an
//! additional cross-check; its absence does not permit an unverified
//! install.
//!
//! # Table status: **empty — fail-closed by default**
//!
//! This workspace runs offline; seeding requires fetching a verified CfT
//! release and recording Google's published digests (see the re-pin
//! procedure). Until then every fresh CfT install refuses unless the
//! audited override is set. This is deliberate: an unverified browser
//! binary is a supply-chain risk, not a skipped nicety.
//!
//! # Re-pin procedure (deliberate, same discipline as the U-102 JA4 re-pin)
//!
//! 1. On a network-enabled machine, download the zip from
//!    `https://storage.googleapis.com/chrome-for-testing-public/<version>/<platform>/<variant>.zip`
//!    and cross-check its SHA-256 against Google's published
//!    `…/<variant>.zip.sha256` sidecar (`sha256sum -c`).
//! 2. Add one [`CftPin`] row per `(version, platform, variant)` below —
//!    `linux64` **and** `linux-arm64` are mandatory (this box is aarch64),
//!    plus `win64` / `mac-*` where installs are supported.
//! 3. Keep old rows until the versions are removed from the box; a pin is a
//!    historical record, not a moving target. Never edit an existing row —
//!    a re-pin is a new row plus a code review.
//! 4. Run `cargo test --lib browser::cft_pins` (offline) — the lookup tests
//!    assert table shape (unique keys, well-formed digests).

use crate::browser::download::BrowserPlatform;

/// One pinned `(version, platform, variant)` → SHA-256 row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CftPin {
    /// CfT release version, e.g. `"151.0.7922.173"` (matches the directory
    /// name `chrome-headless-shell-<version>` created by the installer).
    pub version: &'static str,
    /// CfT platform string ([`BrowserPlatform::as_cft_str`]).
    pub platform: &'static str,
    /// `"chrome"` (full) or `"chrome-headless-shell"`.
    pub variant: &'static str,
    /// Lowercase hex SHA-256 of the **zip** (the same digest Google
    /// publishes as `<variant>.zip.sha256`).
    pub sha256: &'static str,
}

/// The in-repo pin table. Empty until the first verified re-pin (see module
/// docs); with an empty table every install requires the audited override —
/// fail-closed, never fail-open.
pub const CFT_PINS: &[CftPin] = &[
    // 156.0.8078.47 — the first populated pin set (2026-10-23).
    //
    // Provenance, stated exactly: Google publishes no `.sha256` sidecar for these
    // artifacts (the `<variant>-<platform>.zip.sha256` path returns NoSuchKey), so
    // the digests below were computed from the zip downloaded over TLS from
    // storage.googleapis.com on 2026-10-23 and recorded here. That is
    // trust-on-first-use against Google's bucket, not an independent attestation:
    // it makes future installs reproducible and any silent CDN change visible, and
    // it does not claim more than that.
    CftPin {
        version: "156.0.8078.47",
        platform: "linux64",
        variant: "chrome-headless-shell",
        sha256: "0d5acc62c3e213f8c87d3c298d66ffcf9a236d12ea4b9f85318bf85dbc279daa",
    },
    CftPin {
        version: "156.0.8078.47",
        platform: "linux-arm64",
        variant: "chrome-headless-shell",
        sha256: "955059fa7020d7be85eb503e21339fd4d718f51f5996d3b60633fbf908bda132",
    },
];

/// The newest pinned version for `(platform, variant)`, if any.
///
/// The installer prefers a pinned build over "latest stable": a browser that
/// changes under the test suite turns a reproducible gate into a moving target,
/// and the CI runner and this box must exercise the same binary.
pub fn newest_pinned(platform: BrowserPlatform, variant: &str) -> Option<&'static str> {
    let platform = platform.as_cft_str();
    CFT_PINS
        .iter()
        .filter(|p| p.platform == platform && p.variant == variant)
        .max_by_key(|p| {
            let mut it = p.version.split('.').map(|n| n.parse::<u64>().unwrap_or(0));
            (
                it.next().unwrap_or(0),
                it.next().unwrap_or(0),
                it.next().unwrap_or(0),
                it.next().unwrap_or(0),
            )
        })
        .map(|p| p.version)
}

/// Look up the pinned SHA-256 for one artifact inside `pins`.
///
/// Exact match on all three key fields — a pin for `linux64` never covers
/// `linux-arm64`, and `chrome-headless-shell` never covers `chrome`.
pub fn pinned_sha256_in(
    pins: &[CftPin],
    version: &str,
    platform: BrowserPlatform,
    variant: &str,
) -> Option<&'static str> {
    let platform = platform.as_cft_str();
    pins.iter()
        .find(|p| p.version == version && p.platform == platform && p.variant == variant)
        .map(|p| p.sha256)
}

/// Look up the pinned SHA-256 for one artifact in [`CFT_PINS`].
pub fn pinned_sha256(
    version: &str,
    platform: BrowserPlatform,
    variant: &str,
) -> Option<&'static str> {
    pinned_sha256_in(CFT_PINS, version, platform, variant)
}

/// Whether the audited unpinned-install override is set.
///
/// `TALLOW_CFT_ALLOW_UNPINNED=1` (exactly `"1"`; any other value, typo, or
/// empty string must NOT open the supply-chain hole — mirrors the
/// `TALLOW_ALLOW_DIRECT` semantics in `runtime::egress_http`).
pub fn allow_unpinned() -> bool {
    matches!(std::env::var("TALLOW_CFT_ALLOW_UNPINNED"), Ok(v) if v == "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_shape_is_well_formed_and_keys_unique() {
        for pin in CFT_PINS {
            assert_eq!(
                pin.sha256.len(),
                64,
                "pin digest must be 64 hex chars: {pin:?}"
            );
            assert!(
                pin.sha256.chars().all(|c| c.is_ascii_hexdigit())
                    && pin.sha256.chars().all(|c| !c.is_ascii_uppercase()),
                "pin digest must be lowercase hex: {pin:?}"
            );
            assert!(!pin.version.is_empty() && !pin.variant.is_empty());
            assert!(
                matches!(
                    pin.platform,
                    "linux64" | "linux-arm64" | "linux-riscv64" | "mac-arm64" | "mac-x64"
                        | "win32" | "win64"
                ),
                "pin platform must be a CfT platform string: {pin:?}"
            );
        }
        for (i, a) in CFT_PINS.iter().enumerate() {
            for b in CFT_PINS.iter().skip(i + 1) {
                assert!(
                    !(a.version == b.version && a.platform == b.platform && a.variant == b.variant),
                    "duplicate pin key for {a:?}"
                );
            }
        }
    }

    #[test]
    fn pinned_lookup_is_exact_on_all_three_fields() {
        let pins = [
            CftPin {
                version: "999.0.0.1",
                platform: "linux-arm64",
                variant: "chrome-headless-shell",
                sha256: "aa",
            },
            CftPin {
                version: "999.0.0.1",
                platform: "linux64",
                variant: "chrome",
                sha256: "bb",
            },
        ];
        assert_eq!(
            pinned_sha256_in(&pins, "999.0.0.1", BrowserPlatform::LinuxArm64, "chrome-headless-shell"),
            Some("aa")
        );
        assert_eq!(
            pinned_sha256_in(&pins, "999.0.0.1", BrowserPlatform::Linux64, "chrome"),
            Some("bb")
        );
        // Platform is part of the key — linux64 must not borrow the arm64 pin.
        assert_eq!(
            pinned_sha256_in(&pins, "999.0.0.1", BrowserPlatform::Linux64, "chrome-headless-shell"),
            None
        );
        // Variant is part of the key.
        assert_eq!(
            pinned_sha256_in(&pins, "999.0.0.1", BrowserPlatform::LinuxArm64, "chrome"),
            None
        );
        // Version is part of the key.
        assert_eq!(
            pinned_sha256_in(&pins, "999.0.0.2", BrowserPlatform::LinuxArm64, "chrome-headless-shell"),
            None
        );
    }

    #[test]
    fn unpinned_lookup_misses_are_none_not_panic() {
        // The shipped table may be empty (offline workspace) — lookups must
        // resolve to None and be refused by the caller, never panic.
        let _ = pinned_sha256("151.0.7922.173", BrowserPlatform::LinuxArm64, "chrome-headless-shell");
        assert_eq!(
            pinned_sha256_in(&[], "1.2.3.4", BrowserPlatform::Win64, "chrome"),
            None
        );
    }

    #[test]
    fn allow_unpinned_requires_exactly_the_literal_one() {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = crate::runtime::egress_http::env_lock();
        let prior = std::env::var("TALLOW_CFT_ALLOW_UNPINNED").ok();

        unsafe { std::env::remove_var("TALLOW_CFT_ALLOW_UNPINNED") };
        assert!(!allow_unpinned(), "unset must not allow unpinned installs");
        for junk in ["nope", "0", "false", "", "no", "true", "yes", "2"] {
            unsafe { std::env::set_var("TALLOW_CFT_ALLOW_UNPINNED", junk) };
            assert!(
                !allow_unpinned(),
                "TALLOW_CFT_ALLOW_UNPINNED={junk:?} must not open the supply-chain hole"
            );
        }
        unsafe { std::env::set_var("TALLOW_CFT_ALLOW_UNPINNED", "1") };
        assert!(allow_unpinned(), "the explicit literal 1 is the only opt-in");

        match prior {
            Some(v) => unsafe { std::env::set_var("TALLOW_CFT_ALLOW_UNPINNED", v) },
            None => unsafe { std::env::remove_var("TALLOW_CFT_ALLOW_UNPINNED") },
        }
    }
}
