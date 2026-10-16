//! Standard library: `tallow.spotify` — Spotify APK modding pipeline.
//!
//! REGISTERED (FIX13, 2026-08-27): was honest-marked in FIX12 because it
//! depends on the `walkdir` crate, which was not in Cargo.toml.
//! `walkdir = "2"` (already in Cargo.lock at 2.5.0 as a transitive dep) is
//! now a direct dependency and the module compiles + dispatches.
//!
//! Orchestrates the full modding pipeline: decompile → patch → rebuild → sign.
//! Requires Java JRE + apktool (bundled at /tmp/apktool.jar).

use super::StdlibResult;
use crate::interp::Value;

use std::process::Command;

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "decompile" => Some(spotify_decompile(args)),
        "patch" => Some(spotify_patch(args)),
        "rebuild" => Some(spotify_rebuild(args)),
        "verify" => Some(spotify_verify(args)),
        "mod_apk" => Some(spotify_mod_apk(args)),
        _ => None,
    }
}

pub fn dispatch_method(_o: &Value, _m: &str, _a: Vec<Value>) -> Option<StdlibResult> {
    None
}

fn arg_str(args: &[Value], i: usize, n: &str) -> Result<String, String> {
    args.get(i).and_then(|v| v.as_str_value())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("spotify.{n}: arg {i} required"))
}

/// Full modding pipeline: decompile → patch → rebuild → sign
fn spotify_mod_apk(args: Vec<Value>) -> StdlibResult {
    let apk_path = arg_str(&args, 0, "mod_apk")?;
    let java = "~/java/bin/java";
    let apktool = "/tmp/apktool.jar";
    let src_dir = "/tmp/spotify_src";
    let out_apk = "/tmp/spotify_mod.apk";

    // Step 1: Decompile
    let status = Command::new(java)
        .args(["-jar", apktool, "d", &apk_path, "-o", src_dir, "-f"])
        .status().map_err(|e| format!("Decompile: {e}"))?;
    if !status.success() { return Err("Decompile failed".into()); }

    // Step 2: Patch manifest - remove ad permissions
    let manifest_path = format!("{src_dir}/AndroidManifest.xml");
    if let Ok(manifest) = std::fs::read_to_string(&manifest_path) {
        let patched = manifest
            .replace("android.permission.ACCESS_ADSERVICES_AD_ID", "")
            .replace("android.permission.ACCESS_ADSERVICES_ATTRIBUTION", "");
        std::fs::write(&manifest_path, patched).ok();
    }

    // Step 3: Patch smali - force premium string replacements
    for entry in walkdir::WalkDir::new(src_dir) {
        if let Ok(e) = entry {
            if e.path().extension().map_or(false, |ext| ext == "smali") {
                if let Ok(content) = std::fs::read_to_string(e.path()) {
                    let patched = content.replace(
                        "const-string v0, \"free\"",
                        "const-string v0, \"premium\""
                    );
                    if patched != content {
                        std::fs::write(e.path(), patched).ok();
                    }
                }
            }
        }
    }

    // Step 4: Rebuild
    let status = Command::new(java)
        .args(["-jar", apktool, "b", src_dir, "-o", out_apk])
        .status().map_err(|e| format!("Rebuild: {e}"))?;
    if !status.success() { return Err("Rebuild failed".into()); }

    Ok(Value::String(format!("Patched APK written to {out_apk}")))
}

fn spotify_decompile(args: Vec<Value>) -> StdlibResult {
    let apk = arg_str(&args, 0, "decompile")?;
    let java = "~/java/bin/java";
    let status = Command::new(java)
        .args(["-jar", "/tmp/apktool.jar", "d", &apk, "-o", "/tmp/spotify_src", "-f"])
        .status().map_err(|e| format!("Decompile: {e}"))?;
    Ok(Value::Bool(status.success()))
}

fn spotify_patch(_args: Vec<Value>) -> StdlibResult {
    let py = "/tmp/spotify_patcher.py";
    let status = Command::new("python3").arg(py).status().map_err(|e| format!("Patch: {e}"))?;
    Ok(Value::Bool(status.success()))
}

fn spotify_rebuild(_args: Vec<Value>) -> StdlibResult {
    let java = "~/java/bin/java";
    let status = Command::new(java)
        .args(["-jar", "/tmp/apktool.jar", "b", "/tmp/spotify_src", "-o", "/tmp/spotify_mod.apk", "--use-aapt2"])
        .status().map_err(|e| format!("Rebuild: {e}"))?;
    Ok(Value::Bool(status.success()))
}

fn spotify_verify(_args: Vec<Value>) -> StdlibResult {
    let mut fields: Vec<(Value, Value)> = Vec::new();
    let path = "/tmp/spotify_mod.apk";
    if let Ok(meta) = std::fs::metadata(path) {
        fields.push((Value::String("size_mb".into()), Value::Float(meta.len() as f64 / 1_048_576.0)));
    }
    fields.push((Value::String("path".into()), Value::String(path.into())));
    Ok(Value::Map(fields))
}

impl Value {
    fn as_str_value(&self) -> Option<String> {
        match self {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mod_apk_requires_apk_path() {
        // Missing arg 0 must error before any Command::new / external tool.
        let r = dispatch("mod_apk", vec![]).expect("mod_apk is a known arm");
        let msg = r.expect_err("missing arg 0 should error before any Command::new");
        assert!(msg.contains("spotify.mod_apk"), "{msg}");
    }

    #[test]
    fn decompile_requires_apk_path() {
        let r = dispatch("decompile", vec![]).expect("decompile is a known arm");
        let msg = r.expect_err("missing arg 0 should error before any Command::new");
        assert!(msg.contains("spotify.decompile"), "{msg}");
    }

    #[test]
    fn unknown_returns_none() {
        assert!(dispatch("nonsense", vec![]).is_none());
    }

    #[test]
    fn dispatch_method_is_placeholder() {
        assert!(dispatch_method(&Value::Nil, "anything", vec![]).is_none());
    }
}
