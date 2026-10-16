//! Standard library: `tallow.fingerprint` — browser fingerprint randomization.
//!
//! **DEPRECATED (P1 W6-H1) — legacy informational-only engine.** The random
//! draws here are not a coherent identity (time-based entropy, `Math.random()`
//! audio) and any code path invoking them undermines the deterministic stealth
//! engine (`src/browser/stealth*.rs`, `@fingerprint_policy`,
//! `tallow fingerprint-audit`). The module is **gated off by default**:
//! dispatch refuses unless `TALLOW_LEGACY_FINGERPRINT=1` is set (explicit
//! opt-in for offline tooling). Browser/network paths must use the stealth
//! engine instead.
//!
//! Inspired by Browserbase's stealth model and puppeteer-extra-stealth.
//! Randomizes WebGL, canvas, audio, navigator, screen, and font fingerprints
//! to evade browser fingerprinting detection.
//!
//! # API
//! - `Fingerprint.generate()` — generate a random fingerprint profile
//! - `Fingerprint.inject_js(profile)` — get JS to inject into a page
//! - `Fingerprint.rotate()` — generate a new random fingerprint for rotation
//! - `profile.to_headers()` — generate matching HTTP headers

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::collections::HashMap;

/// A browser fingerprint profile
#[derive(Debug, Clone)]
#[allow(dead_code)] // fingerprint fields kept for future profile introspection
struct Fingerprint {
    user_agent: String,
    platform: String,
    vendor: String,
    language: String,
    languages: Vec<String>,
    screen_width: u32,
    screen_height: u32,
    color_depth: u32,
    pixel_ratio: f64,
    timezone: String,
    timezone_offset: i32,
    hardware_concurrency: u32,
    device_memory: u32,
    canvas_noise: u32,       // seed for canvas fingerprint randomization
    webgl_vendor: String,
    webgl_renderer: String,
    audio_noise: f64,        // audio context distortion factor
    fonts: Vec<String>,
    platform_version: String,
    architecture: String,
}

impl Fingerprint {
    fn generate_random() -> Self {
        let (ua, platform, vendor, platform_version) = random_platform();
        let (sw, sh) = random_screen();
        let lang = random_language();
        
        Fingerprint {
            user_agent: ua,
            platform,
            vendor,
            language: lang.0.clone(),
            languages: lang.1,
            screen_width: sw,
            screen_height: sh,
            color_depth: random_color_depth(),
            pixel_ratio: random_pixel_ratio(),
            timezone: random_timezone().0,
            timezone_offset: random_timezone().1,
            hardware_concurrency: random_concurrency(),
            device_memory: random_memory(),
            canvas_noise: fast_random(),
            webgl_vendor: random_webgl_vendor(),
            webgl_renderer: random_webgl_renderer(),
            audio_noise: random_audio_noise(),
            fonts: random_fonts(),
            platform_version,
            architecture: random_arch(),
        }
    }

    fn to_value(&self) -> Value {
        Value::Struct {
            name: "Fingerprint".into(),
            fields: vec![
                ("user_agent".into(), Value::String(self.user_agent.clone())),
                ("platform".into(), Value::String(self.platform.clone())),
                ("language".into(), Value::String(self.language.clone())),
                ("screen_width".into(), Value::Int(self.screen_width as i128)),
                ("screen_height".into(), Value::Int(self.screen_height as i128)),
                ("timezone".into(), Value::String(self.timezone.clone())),
            ],
        }
    }

    fn to_headers(&self) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("User-Agent".into(), self.user_agent.clone());
        h.insert("Accept-Language".into(), self.language.clone());
        h.insert("Sec-Ch-Ua".into(), format!(r#""Chromium";v="131", "Google Chrome";v="131""#));
        h.insert("Sec-Ch-Ua-Platform".into(), format!(r#""{}""#, self.platform));
        h.insert("Sec-Ch-Ua-Mobile".into(), "?0".into());
        h.insert("Sec-Ch-Ua-Arch".into(), format!(r#""{}""#, self.architecture));
        h
    }

    fn inject_js(&self) -> String {
        let mut js = String::new();

        // Override navigator properties
        js.push_str(&format!(
            r#"Object.defineProperty(navigator,'platform',{{get:()=>'{}',configurable:true}});"#,
            self.platform
        ));
        js.push_str(&format!(
            r#"Object.defineProperty(navigator,'vendor',{{get:()=>'{}',configurable:true}});"#,
            self.vendor
        ));
        js.push_str(&format!(
            r#"Object.defineProperty(navigator,'language',{{get:()=>'{}',configurable:true}});"#,
            self.language
        ));
        js.push_str(&format!(
            "Object.defineProperty(navigator,'languages',{{get:()=>[{}],configurable:true}});",
            self.languages.iter().map(|l| format!("'{}'", l)).collect::<Vec<_>>().join(",")
        ));
        js.push_str(&format!(
            r#"Object.defineProperty(navigator,'hardwareConcurrency',{{get:()=>{},configurable:true}});"#,
            self.hardware_concurrency
        ));
        js.push_str(&format!(
            r#"Object.defineProperty(navigator,'deviceMemory',{{get:()=>{},configurable:true}});"#,
            self.device_memory
        ));

        // Override screen
        js.push_str(&format!(
            r#"Object.defineProperty(screen,'width',{{get:()=>{},configurable:true}});"#,
            self.screen_width
        ));
        js.push_str(&format!(
            r#"Object.defineProperty(screen,'height',{{get:()=>{},configurable:true}});"#,
            self.screen_height
        ));
        js.push_str(&format!(
            r#"Object.defineProperty(screen,'colorDepth',{{get:()=>{},configurable:true}});"#,
            self.color_depth
        ));
        js.push_str(&format!(
            r#"Object.defineProperty(screen,'pixelDepth',{{get:()=>{},configurable:true}});"#,
            self.color_depth
        ));

        // Canvas fingerprint noise
        js.push_str(&format!(r#"
            const origToDataURL=HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL=function(...args){{
                if(this.width>0&&this.height>0){{
                    const ctx=this.getContext('2d');
                    if(ctx){{
                        const img=ctx.getImageData(0,0,this.width,this.height);
                        const noise={};
                        for(let i=0;i<img.data.length;i+=4){{
                            img.data[i]^=(noise>>(i%8))&1;
                        }}
                        ctx.putImageData(img,0,0);
                    }}
                }}
                return origToDataURL.apply(this,args);
            }};
        "#, self.canvas_noise));

        // WebGL fingerprint noise
        js.push_str(&format!(r#"
            const origGetParam=WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter=function(p){{
                if(p===37445)return'{}';
                if(p===37446)return'{}';
                return origGetParam.call(this,p);
            }};
            const origGetExt=WebGLRenderingContext.prototype.getExtension;
            WebGLRenderingContext.prototype.getExtension=function(name){{
                if(name==='WEBGL_debug_renderer_info')return null;
                return origGetExt.call(this,name);
            }};
        "#, self.webgl_vendor, self.webgl_renderer));

        // Audio fingerprint noise
        js.push_str(&format!(r#"
            const origGetChannelData=AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData=function(channel){{
                const data=origGetChannelData.call(this,channel);
                const f={:.6};
                for(let i=0;i<Math.min(data.length,100);i++){{
                    data[i]+=f*(Math.random()-0.5)*1e-6;
                }}
                return data;
            }};
        "#, self.audio_noise));

        // Font enumeration blocking
        js.push_str(r#"
            if(document.fonts&&document.fonts.check){
                const origCheck=document.fonts.check.bind(document.fonts);
                document.fonts.check=function(){return true};
            }
        "#);

        js
    }
}

// ── Randomization helpers ──

fn fast_random() -> u32 {
    use std::time::SystemTime;
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(42)
}

fn random_platform() -> (String, String, String, String) {
    let platforms = [
        ("Windows", "Google Inc.", "Win32", "10.0"),
        ("MacIntel", "Apple Computer, Inc.", "MacIntel", "15.0"),
        ("Linux x86_64", "Google Inc.", "Linux x86_64", ""),
    ];
    let idx = fast_random() as usize % platforms.len();
    let (p, v, _pa, pv) = platforms[idx];
    (get_ua_for_platform(p), p.to_string(), v.to_string(), pv.to_string())
}

fn get_ua_for_platform(platform: &str) -> String {
    match platform {
        "Windows" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
        "MacIntel" => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
        _ => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
    }
}

fn random_screen() -> (u32, u32) {
    let screens = [(1920, 1080), (2560, 1440), (1366, 768), (1440, 900), (1536, 864), (3840, 2160)];
    screens[fast_random() as usize % screens.len()]
}

fn random_color_depth() -> u32 {
    [24, 30, 24, 24, 24, 30, 24, 24][fast_random() as usize % 8]
}

fn random_pixel_ratio() -> f64 {
    [1.0, 1.0, 1.25, 1.5, 2.0, 1.0, 1.0, 2.0][fast_random() as usize % 8]
}

fn random_language() -> (String, Vec<String>) {
    let langs = [
        ("en-US", vec!["en-US", "en"]),
        ("en-GB", vec!["en-GB", "en"]),
        ("de-DE", vec!["de-DE", "de", "en-US", "en"]),
        ("fr-FR", vec!["fr-FR", "fr", "en-US", "en"]),
    ];
    let idx = fast_random() as usize % langs.len();
    (langs[idx].0.into(), langs[idx].1.iter().map(|s| s.to_string()).collect())
}

fn random_timezone() -> (String, i32) {
    let zones = [
        ("America/New_York", -300),
        ("America/Chicago", -360),
        ("America/Denver", -420),
        ("America/Los_Angeles", -480),
        ("Europe/London", 0),
        ("Europe/Berlin", 60),
    ];
    let idx = fast_random() as usize % zones.len();
    (zones[idx].0.into(), zones[idx].1)
}

fn random_concurrency() -> u32 {
    [4, 8, 8, 12, 16, 8, 8, 4][fast_random() as usize % 8]
}

fn random_memory() -> u32 {
    [4, 8, 8, 16, 8, 8, 4, 16][fast_random() as usize % 8]
}

fn random_webgl_vendor() -> String {
    ["Google Inc. (Intel)", "Google Inc. (NVIDIA)", "Google Inc. (AMD)", "Google Inc. (Apple)"]
        [fast_random() as usize % 4].into()
}

fn random_webgl_renderer() -> String {
    [
        "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0)",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
        "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)",
        "ANGLE (Apple, Apple M1 Pro)",
    ][fast_random() as usize % 4].into()
}

fn random_audio_noise() -> f64 {
    [0.001, 0.002, 0.0015, 0.0008, 0.0012, 0.0018][fast_random() as usize % 6]
}

fn random_fonts() -> Vec<String> {
    let base = ["Arial", "Times New Roman", "Courier New", "Verdana", "Georgia"];
    let extras = ["Helvetica", "Trebuchet MS", "Comic Sans MS", "Impact", "Lucida Console"];
    let mut fonts: Vec<String> = base.iter().map(|s| s.to_string()).collect();
    let extra_count = (fast_random() as usize % 3) + 1;
    for i in 0..extra_count {
        fonts.push(extras[(fast_random() as usize + i) % extras.len()].to_string());
    }
    fonts
}

fn random_arch() -> String {
    ["x86", "arm", "x86"][fast_random() as usize % 3].into()
}

// ── Legacy gate (P1 W6-H1) ──

/// Env var that opts back into the legacy engine (explicit, loud, opt-in).
pub const LEGACY_GATE_ENV: &str = "TALLOW_LEGACY_FINGERPRINT";

/// Gate body: `Some(refusal)` unless the caller opted in with exactly `"1"`.
///
/// Pure on purpose (the env read stays at the call sites) so the gate is
/// unit-testable without mutating process-wide env.
fn legacy_gate(opt_in: Option<&str>) -> Option<StdlibResult> {
    match opt_in {
        Some("1") => None,
        _ => Some(Err(format!(
            "tallow.fingerprint is DEPRECATED (legacy informational-only engine, no isolation \
             guarantees) and gated off by default; set {LEGACY_GATE_ENV}=1 to opt in for offline \
             tooling. Browser and network paths must use the stealth engine \
             (`@fingerprint_policy` + `tallow fingerprint-audit`) instead."
        ))),
    }
}

fn legacy_gate_env() -> Option<StdlibResult> {
    legacy_gate(std::env::var(LEGACY_GATE_ENV).ok().as_deref())
}

// ── Dispatch ──

pub fn dispatch(function: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    if let Some(refused) = legacy_gate_env() {
        return Some(refused);
    }
    match function {
        "generate" => Some(Ok(Fingerprint::generate_random().to_value())),
        "rotate" => Some(Ok(Fingerprint::generate_random().to_value())),
        "from_profile" => Some(fp_from_profile(_args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "Fingerprint") {
        return None;
    }
    if let Some(refused) = legacy_gate_env() {
        return Some(refused);
    }
    match method {
        "inject_js" => {
            let fp = match extract_fingerprint(object) {
                Ok(fp) => fp,
                Err(_) => return None,
            };
            Some(Ok(Value::String(fp.inject_js())))
        }
        "to_headers" => {
            let fp = match extract_fingerprint(object) {
                Ok(fp) => fp,
                Err(_) => return None,
            };
            let headers: Vec<(Value, Value)> = fp.to_headers().into_iter()
                .map(|(k, v)| (Value::String(k), Value::String(v)))
                .collect();
            Some(Ok(Value::Map(headers)))
        }
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "generate" | "rotate" | "from_profile")
}

fn extract_fingerprint(value: &Value) -> Result<Fingerprint, String> {
    let fields = match value {
        Value::Struct { name, fields } if name == "Fingerprint" => fields,
        _ => return Err(format!("Expected Fingerprint, got {}", type_name(value))),
    };
    let ua = field_str(fields, "user_agent");
    let platform = field_str(fields, "platform");
    let lang = field_str(fields, "language");
    let mut fp = Fingerprint::generate_random();
    if !ua.is_empty() { fp.user_agent = ua; }
    if !platform.is_empty() { fp.platform = platform; }
    if !lang.is_empty() { fp.language = lang; }
    Ok(fp)
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}

fn fp_from_profile(args: Vec<Value>) -> StdlibResult {
    let name = args.first().and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("windows_desktop");
    let fp = match name {
        "macbook_m1" => Fingerprint {
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
            platform: "MacIntel".into(), vendor: "Apple Computer, Inc.".into(),
            language: "en-US".into(), languages: vec!["en-US".into(), "en".into()],
            screen_width: 3456, screen_height: 2234, color_depth: 30,
            pixel_ratio: 2.0, timezone: "America/Los_Angeles".into(), timezone_offset: -480,
            hardware_concurrency: 10, device_memory: 16,
            canvas_noise: 42, audio_noise: 0.001,
            webgl_vendor: "Apple".into(), webgl_renderer: "Apple M1 Pro".into(),
            fonts: vec!["Helvetica".into(), "Arial".into(), "Times".into()],
            platform_version: "14.0".into(), architecture: "arm".into(),
        },
        "windows_desktop" => Fingerprint {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
            platform: "Win32".into(), vendor: "Google Inc.".into(),
            language: "en-US".into(), languages: vec!["en-US".into(), "en".into()],
            screen_width: 1920, screen_height: 1080, color_depth: 24,
            pixel_ratio: 1.0, timezone: "America/Chicago".into(), timezone_offset: -360,
            hardware_concurrency: 8, device_memory: 16,
            canvas_noise: 17, audio_noise: 0.0015,
            webgl_vendor: "Google Inc. (NVIDIA)".into(),
            webgl_renderer: "ANGLE (NVIDIA GeForce RTX 3060)".into(),
            fonts: vec!["Arial".into(), "Times New Roman".into(), "Courier New".into()],
            platform_version: "10.0".into(), architecture: "x86".into(),
        },
        "linux_laptop" => Fingerprint {
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
            platform: "Linux x86_64".into(), vendor: "Google Inc.".into(),
            language: "en-US".into(), languages: vec!["en-US".into(), "en".into()],
            screen_width: 1920, screen_height: 1080, color_depth: 24,
            pixel_ratio: 1.0, timezone: "America/New_York".into(), timezone_offset: -300,
            hardware_concurrency: 8, device_memory: 8,
            canvas_noise: 99, audio_noise: 0.0012,
            webgl_vendor: "Google Inc. (Intel)".into(),
            webgl_renderer: "ANGLE (Intel UHD Graphics 620)".into(),
            fonts: vec!["DejaVu Sans".into(), "Arial".into(), "Liberation Sans".into()],
            platform_version: "".into(), architecture: "x86".into(),
        },
        "windows_laptop" => Fingerprint {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
            platform: "Win32".into(), vendor: "Google Inc.".into(),
            language: "en-US".into(), languages: vec!["en-US".into(), "en".into()],
            screen_width: 1366, screen_height: 768, color_depth: 24,
            pixel_ratio: 1.25, timezone: "America/Denver".into(), timezone_offset: -420,
            hardware_concurrency: 4, device_memory: 8,
            canvas_noise: 55, audio_noise: 0.0008,
            webgl_vendor: "Google Inc. (AMD)".into(),
            webgl_renderer: "ANGLE (AMD Radeon RX 580)".into(),
            fonts: vec!["Arial".into(), "Verdana".into(), "Georgia".into()],
            platform_version: "10.0".into(), architecture: "x86".into(),
        },
        _ => return Err(format!("Unknown profile: {name}. Available: macbook_m1, windows_desktop, linux_laptop, windows_laptop")),
    };
    Ok(fp.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_gate_refuses_unless_explicitly_opted_in() {
        for unset in [None, Some(""), Some("0"), Some("true")] {
            assert!(
                legacy_gate(unset).is_some(),
                "gate must refuse for opt-in value {unset:?}"
            );
        }
        assert!(legacy_gate(Some("1")).is_none(), "explicit \"1\" opts in");
    }

    #[test]
    fn legacy_gate_refusal_names_the_env_and_successor() {
        let msg = match legacy_gate(None) {
            Some(Err(m)) => m,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert!(msg.contains(LEGACY_GATE_ENV), "names the env: {msg}");
        assert!(msg.contains("fingerprint-audit"), "names the successor: {msg}");
    }
}
