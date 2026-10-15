/// Spotify APK modding pipeline (decompile → patch → rebuild → sign).
///
/// Registered + dispatched (FIX13, 2026-08-27): src/stdlib/spotify.rs now
/// compiles (walkdir dependency added) and routes
/// decompile / patch / rebuild / verify / mod_apk.
/// Requires Java JRE + apktool (bundled at /tmp/apktool.jar).
module tallow.spotify

/// Decompile an APK with apktool into /tmp/spotify_src
native fn decompile(apk_path: String) -> Bool

/// Run the smali/manifest patcher (/tmp/spotify_patcher.py)
native fn patch() -> Bool

/// Rebuild the patched APK with apktool
native fn rebuild() -> Bool

/// Verify the output APK (/tmp/spotify_mod.apk) — size + path map
native fn verify() -> Map<String, Value>

/// Full pipeline: decompile → patch → rebuild → sign
native fn mod_apk(apk_path: String) -> String
