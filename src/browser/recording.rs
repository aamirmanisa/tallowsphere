//! 4K video recording via CDP `Page.startScreencast` / `Page.stopScreencast`.
//!
//! Captures JPEG frames from Chrome's screencast protocol and encodes them to
//! video. Three strategies are attempted in order:
//!
//! 1. **ffmpeg** — best quality MP4/WebM output (requires ffmpeg on PATH).
//! 2. **AVI MJPEG** — pure-Rust AVI container with JPEG frames; no extra deps,
//!    plays in VLC, ffplay, and most media players.
//! 3. **JPEG sequence** — frame_00001.jpg, frame_00002.jpg, …, with an ffmpeg
//!    command printed for manual conversion.
//!
//! # Memory management
//! For long recordings at 4K/30fps each JPEG is ~200–500 KB. Frames are held
//! in a `Vec<Vec<u8>>` protected by `Arc<Mutex<…>>` on the `CdpClient`.
//! `RecordingConfig::max_frames_in_memory` (default 900 = 30s at 30fps) caps
//! in-memory buffering; once the limit is hit, older frames are silently
//! dropped and the recording continues from that point.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Video codec for ffmpeg-based recording.
#[derive(Debug, Clone, PartialEq)]
pub enum RecordingCodec {
    /// H.264 / AVC — widely compatible, fast encoding.
    H264,
    /// VP9 — royalty-free, good compression, slower encoding.
    VP9,
    /// AV1 — next-gen royalty-free, best compression, slowest encoding.
    AV1,
}

impl RecordingCodec {
    /// Return the ffmpeg encoder name for this codec.
    pub fn ffmpeg_codec(&self) -> &'static str {
        match self {
            RecordingCodec::H264 => "libx264",
            RecordingCodec::VP9 => "libvpx-vp9",
            RecordingCodec::AV1 => "libaom-av1",
        }
    }

    /// Return the default file extension for this codec.
    pub fn file_extension(&self) -> &'static str {
        match self {
            RecordingCodec::H264 => "mp4",
            RecordingCodec::VP9 => "webm",
            RecordingCodec::AV1 => "mp4",
        }
    }
}

/// Configuration for a screencast recording session.
#[derive(Debug, Clone)]
pub struct RecordingConfig {
    /// Frame width in pixels. Default: 3840 (4K UHD).
    pub width: u32,
    /// Frame height in pixels. Default: 2160 (4K UHD).
    pub height: u32,
    /// Target frame-rate. Used for container metadata and ffmpeg encoding.
    /// Default: 30.
    pub fps: u32,
    /// JPEG quality sent to Chrome (1–100). Default: 90.
    pub quality: u32,
    /// Output format: `"mp4"`, `"webm"`, `"avi"`, or `"frames"`.
    /// Default: `"mp4"`.
    pub format: String,
    /// Maximum frames to keep in memory at once. Older frames are dropped when
    /// this limit is exceeded. Default: 1800 (60 s at 30 fps).
    pub max_frames_in_memory: usize,
    /// Video codec for ffmpeg encoding. Default: `RecordingCodec::H264`.
    pub codec: RecordingCodec,
    /// Constant Rate Factor (quality). Lower = better quality, larger file.
    /// Valid range: 0–51 for H264, 0–63 for VP9/AV1. Default: 18.
    pub crf: u32,
    /// Whether to capture system audio (requires ffmpeg and platform support).
    /// Default: `false`.
    pub capture_audio: bool,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            width: 3840,
            height: 2160,
            fps: 30,
            quality: 90,
            format: "mp4".to_string(),
            max_frames_in_memory: 1800,
            codec: RecordingCodec::H264,
            crf: 18,
            capture_audio: false,
        }
    }
}

/// Result returned by `stop_recording`.
#[derive(Debug, Clone)]
pub struct RecordingResult {
    /// Number of JPEG frames captured.
    pub frame_count: usize,
    /// Wall-clock duration of the recording.
    pub duration_secs: f64,
    /// Size of the output file in bytes (0 if writing failed).
    pub file_size: u64,
    /// Absolute path to the output file or directory.
    pub output_path: String,
    /// Human-readable resolution string, e.g. `"3840x2160"`.
    pub resolution: String,
    /// Encoding strategy that was used: `"ffmpeg"`, `"avi_mjpeg"`, or `"frames"`.
    pub encoding: String,
}

// ---------------------------------------------------------------------------
// Resolution presets
// ---------------------------------------------------------------------------

/// Parse a resolution preset name or `"WxH"` string into `(width, height)`.
///
/// Recognised presets: `"4k"`, `"2k"`, `"1080p"`, `"720p"`, `"480p"`.
pub fn parse_resolution(s: &str) -> (u32, u32) {
    match s.to_lowercase().as_str() {
        "4k" | "uhd" | "2160p" => (3840, 2160),
        "2k" | "qhd" | "1440p" => (2560, 1440),
        "1080p" | "fhd" => (1920, 1080),
        "720p" | "hd" => (1280, 720),
        "480p" | "sd" => (854, 480),
        other => {
            // Try "WxH" format
            if let Some((w, h)) = other.split_once('x') {
                let pw = w.trim().parse().unwrap_or(1920);
                let ph = h.trim().parse().unwrap_or(1080);
                (pw, ph)
            } else {
                (1920, 1080) // safe default
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding: Strategy A — ffmpeg
// ---------------------------------------------------------------------------

/// Return the name or absolute path of a working `ffmpeg` binary, or `None`.
///
/// Checks PATH first (via `"ffmpeg"`), then falls back to well-known install
/// locations used by `tallow ffmpeg install` on each platform.
pub fn find_ffmpeg() -> Option<&'static str> {
    #[cfg(target_os = "windows")]
    const CANDIDATES: &[&str] = &[
        "ffmpeg",
        r"C:\ProgramData\chocolatey\bin\ffmpeg.exe",
        r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
    ];
    #[cfg(target_os = "macos")]
    const CANDIDATES: &[&str] = &[
        "ffmpeg",
        "/usr/local/bin/ffmpeg",
        "/opt/homebrew/bin/ffmpeg",
    ];
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    const CANDIDATES: &[&str] = &[
        "ffmpeg",
        "/usr/bin/ffmpeg",
        "/usr/local/bin/ffmpeg",
    ];

    for &candidate in CANDIDATES {
        let ok = Command::new(candidate)
            .arg("-version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(candidate);
        }
    }
    None
}

/// Check whether `ffmpeg` is available (PATH or known install locations).
pub fn ffmpeg_available() -> bool {
    find_ffmpeg().is_some()
}

/// Write `frames` as individual JPEG files to `frame_dir`, then invoke ffmpeg
/// to encode them into `output_path`.
///
/// Returns `Ok(())` if ffmpeg succeeds.
pub fn encode_with_ffmpeg(
    frames: &[Vec<u8>],
    config: &RecordingConfig,
    output_path: &str,
) -> Result<(), String> {
    use std::fs;

    // Create a temp directory for the JPEG sequence
    let tmp_dir = tempfile::Builder::new()
        .prefix("tallow_rec_")
        .tempdir()
        .map_err(|e| format!("failed to create temp dir: {e}"))?;

    write_jpeg_sequence(frames, tmp_dir.path())?;

    let input_pattern = tmp_dir
        .path()
        .join("frame_%05d.jpg")
        .to_string_lossy()
        .into_owned();

    // Use codec from config instead of guessing from file extension
    let vcodec = config.codec.ffmpeg_codec();
    let crf_str = config.crf.to_string();

    let ffmpeg_bin = find_ffmpeg()
        .ok_or_else(|| "ffmpeg not found; run `tallow ffmpeg install`".to_string())?;

    let status = Command::new(ffmpeg_bin)
        .args([
            "-y", // overwrite without asking
            "-framerate",
            &config.fps.to_string(),
            "-i",
            &input_pattern,
            "-c:v",
            vcodec,
            "-crf",
            &crf_str,
            "-pix_fmt",
            "yuv420p",
            "-s",
            &format!("{}x{}", config.width, config.height),
            output_path,
        ])
        .status()
        .map_err(|e| format!("failed to run ffmpeg: {e}"))?;

    if !status.success() {
        return Err(format!(
            "ffmpeg exited with code {}",
            status.code().unwrap_or(-1)
        ));
    }

    // Retrieve output size — we need it before tmp_dir is dropped
    let size = fs::metadata(output_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let _ = size; // caller reads it separately; just verify file exists

    Ok(())
}

// ---------------------------------------------------------------------------
// Encoding: Strategy B — pure-Rust AVI MJPEG
// ---------------------------------------------------------------------------

/// Write `frames` into an AVI container with MJPEG compression.
///
/// No external dependencies. The resulting `.avi` file plays in VLC, ffplay,
/// Windows Media Player, and most modern media players.
pub fn encode_as_avi_mjpeg(
    frames: &[Vec<u8>],
    config: &RecordingConfig,
    output_path: &str,
) -> Result<(), String> {
    use std::fs::File;
    use std::io::BufWriter;

    if frames.is_empty() {
        return Err("no frames to encode".to_string());
    }

    let file = File::create(output_path)
        .map_err(|e| format!("cannot create output file: {e}"))?;
    let mut w = BufWriter::new(file);

    // ── Compute sizes up front ────────────────────────────────────────────

    let frame_count = frames.len() as u32;
    let width = config.width;
    let height = config.height;
    let fps = config.fps.max(1);
    let micros_per_frame: u32 = 1_000_000 / fps;

    // Total size of all "00dc" movi chunks (4-byte size + JPEG data each)
    let movi_data_size: u32 = frames
        .iter()
        .map(|f| 8u32 + f.len() as u32)
        .sum();

    // idx1 size: 16 bytes per frame
    let idx1_data_size: u32 = frame_count * 16;

    // hdrl size: avih(56) + LIST strl(strh(56) + strf(40)) + list headers
    // LIST strl = 4 (b"strl") + 8+56 (strh chunk) + 8+40 (strf chunk) = 116
    let strl_list_size: u32 = 4 + 8 + 56 + 8 + 40; // 116
    let hdrl_list_size: u32 = 4 + 8 + 56 + 8 + strl_list_size; // 4+8+56+8+116 = 192
    // RIFF AVI = 4 (b"AVI ") + LIST hdrl + JUNK pad + LIST movi + idx1
    // We skip JUNK; total RIFF size = 4 + (8+hdrl_list_size) + (8+4+movi_data_size) + (8+idx1_data_size)
    let riff_size: u32 = 4
        + 8
        + hdrl_list_size
        + 8
        + 4
        + movi_data_size
        + 8
        + idx1_data_size;

    // ── RIFF AVI header ───────────────────────────────────────────────────
    w.write_all(b"RIFF").map_err(|e| e.to_string())?;
    write_u32_le(&mut w, riff_size)?;
    w.write_all(b"AVI ").map_err(|e| e.to_string())?;

    // ── LIST hdrl ─────────────────────────────────────────────────────────
    w.write_all(b"LIST").map_err(|e| e.to_string())?;
    write_u32_le(&mut w, hdrl_list_size)?;
    w.write_all(b"hdrl").map_err(|e| e.to_string())?;

    // avih chunk (56 bytes payload)
    w.write_all(b"avih").map_err(|e| e.to_string())?;
    write_u32_le(&mut w, 56)?;
    write_u32_le(&mut w, micros_per_frame)?; // dwMicroSecPerFrame
    write_u32_le(&mut w, 0)?; // dwMaxBytesPerSec (0 = unknown)
    write_u32_le(&mut w, 0)?; // dwPaddingGranularity
    write_u32_le(&mut w, 0x0010)?; // dwFlags: AVIF_HASINDEX
    write_u32_le(&mut w, frame_count)?; // dwTotalFrames
    write_u32_le(&mut w, 0)?; // dwInitialFrames
    write_u32_le(&mut w, 1)?; // dwStreams
    write_u32_le(&mut w, 0)?; // dwSuggestedBufferSize
    write_u32_le(&mut w, width)?; // dwWidth
    write_u32_le(&mut w, height)?; // dwHeight
    write_u32_le(&mut w, 0)?; // dwReserved[0]
    write_u32_le(&mut w, 0)?; // dwReserved[1]
    write_u32_le(&mut w, 0)?; // dwReserved[2]
    write_u32_le(&mut w, 0)?; // dwReserved[3]

    // LIST strl
    w.write_all(b"LIST").map_err(|e| e.to_string())?;
    write_u32_le(&mut w, strl_list_size)?;
    w.write_all(b"strl").map_err(|e| e.to_string())?;

    // strh chunk — video stream header (56 bytes)
    w.write_all(b"strh").map_err(|e| e.to_string())?;
    write_u32_le(&mut w, 56)?;
    w.write_all(b"vids").map_err(|e| e.to_string())?; // fccType
    w.write_all(b"MJPG").map_err(|e| e.to_string())?; // fccHandler
    write_u32_le(&mut w, 0)?; // dwFlags
    write_u16_le(&mut w, 0)?; // wPriority
    write_u16_le(&mut w, 0)?; // wLanguage
    write_u32_le(&mut w, 0)?; // dwInitialFrames
    write_u32_le(&mut w, 1)?; // dwScale
    write_u32_le(&mut w, fps)?; // dwRate  (fps = rate/scale)
    write_u32_le(&mut w, 0)?; // dwStart
    write_u32_le(&mut w, frame_count)?; // dwLength
    write_u32_le(&mut w, 0)?; // dwSuggestedBufferSize
    write_u32_le(&mut w, u32::MAX)?; // dwQuality (-1 = default)
    write_u32_le(&mut w, 0)?; // dwSampleSize (0 for video)
    // rcFrame: short[4]
    write_u16_le(&mut w, 0)?;
    write_u16_le(&mut w, 0)?;
    write_u16_le(&mut w, width as u16)?;
    write_u16_le(&mut w, height as u16)?;

    // strf chunk — BITMAPINFOHEADER (40 bytes)
    w.write_all(b"strf").map_err(|e| e.to_string())?;
    write_u32_le(&mut w, 40)?;
    write_u32_le(&mut w, 40)?; // biSize
    write_u32_le(&mut w, width)?; // biWidth
    // biHeight: negative = top-down, positive = bottom-up. Use positive for
    // MJPEG (Chrome delivers top-down JPEGs; players handle either sign).
    write_i32_le(&mut w, height as i32)?;
    write_u16_le(&mut w, 1)?; // biPlanes
    write_u16_le(&mut w, 24)?; // biBitCount (24 bpp for MJPEG placeholder)
    w.write_all(b"MJPG").map_err(|e| e.to_string())?; // biCompression
    write_u32_le(&mut w, width * height * 3)?; // biSizeImage (max uncompressed)
    write_u32_le(&mut w, 0)?; // biXPelsPerMeter
    write_u32_le(&mut w, 0)?; // biYPelsPerMeter
    write_u32_le(&mut w, 0)?; // biClrUsed
    write_u32_le(&mut w, 0)?; // biClrImportant

    // ── LIST movi ─────────────────────────────────────────────────────────
    w.write_all(b"LIST").map_err(|e| e.to_string())?;
    write_u32_le(&mut w, 4 + movi_data_size)?;
    w.write_all(b"movi").map_err(|e| e.to_string())?;

    // Write each frame as a "00dc" (stream 0, compressed video) chunk.
    // Offsets relative to start-of-movi-data (i.e. after the "movi" tag).
    let mut frame_offsets: Vec<u32> = Vec::with_capacity(frames.len());
    let mut offset_cursor: u32 = 4; // 4 for "movi" fourcc

    for frame in frames {
        frame_offsets.push(offset_cursor);
        w.write_all(b"00dc").map_err(|e| e.to_string())?;
        let frame_len = frame.len() as u32;
        write_u32_le(&mut w, frame_len)?;
        w.write_all(frame).map_err(|e| e.to_string())?;
        // AVI requires WORD alignment padding
        if frame_len % 2 != 0 {
            w.write_all(&[0u8]).map_err(|e| e.to_string())?;
            offset_cursor += 8 + frame_len + 1;
        } else {
            offset_cursor += 8 + frame_len;
        }
    }

    // ── idx1 index ────────────────────────────────────────────────────────
    w.write_all(b"idx1").map_err(|e| e.to_string())?;
    write_u32_le(&mut w, idx1_data_size)?;

    for (i, frame) in frames.iter().enumerate() {
        w.write_all(b"00dc").map_err(|e| e.to_string())?;
        write_u32_le(&mut w, 0x10)?; // AVIIF_KEYFRAME
        write_u32_le(&mut w, frame_offsets[i])?; // offset from movi start
        write_u32_le(&mut w, frame.len() as u32)?; // chunk size
    }

    w.flush().map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Encoding: Strategy C — JPEG frame sequence
// ---------------------------------------------------------------------------

/// Save `frames` as individual JPEG files in `output_dir`.
///
/// Also prints an ffmpeg command the user can run manually.
pub fn save_as_frames(
    frames: &[Vec<u8>],
    config: &RecordingConfig,
    output_dir: &str,
) -> Result<(), String> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("cannot create output dir: {e}"))?;
    write_jpeg_sequence(frames, Path::new(output_dir))?;
    eprintln!(
        "Saved {} frames to {}/\n\
         Convert to video: ffmpeg -framerate {} -i frame_%05d.jpg \
         -c:v libx264 -pix_fmt yuv420p output.mp4",
        frames.len(),
        output_dir,
        config.fps
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Top-level encoder dispatcher
// ---------------------------------------------------------------------------

/// Encode `frames` to `output_path` using the best available strategy.
///
/// Strategy order:
/// 1. ffmpeg (if `format` is `"mp4"` or `"webm"` and ffmpeg is on PATH)
/// 2. AVI MJPEG (if `format` is `"mp4"`, `"avi"`, or `"webm"` and ffmpeg unavailable)
/// 3. JPEG frame sequence (`format == "frames"` or all else fails)
///
/// Returns a `(encoding_name, file_size)` tuple on success.
pub fn encode_frames(
    frames: &[Vec<u8>],
    config: &RecordingConfig,
    output_path: &str,
) -> Result<(String, u64), String> {
    if frames.is_empty() {
        return Err("no frames captured".to_string());
    }

    let fmt = config.format.to_lowercase();

    // Frames-only mode
    if fmt == "frames" {
        save_as_frames(frames, config, output_path)?;
        let size = dir_size(Path::new(output_path));
        return Ok(("frames".to_string(), size));
    }

    // Try ffmpeg first for mp4/webm
    if (fmt == "mp4" || fmt == "webm") && ffmpeg_available() {
        match encode_with_ffmpeg(frames, config, output_path) {
            Ok(()) => {
                let size = std::fs::metadata(output_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                return Ok(("ffmpeg".to_string(), size));
            }
            Err(e) => {
                eprintln!("tallow recording: ffmpeg failed ({e}), falling back to AVI MJPEG");
            }
        }
    }

    // Strategy B: AVI MJPEG (works for mp4/avi/webm requests when ffmpeg absent)
    // Use .avi extension regardless of requested format
    let avi_path = if fmt == "avi" {
        output_path.to_string()
    } else {
        // Replace extension with .avi
        let p = PathBuf::from(output_path);
        p.with_extension("avi").to_string_lossy().into_owned()
    };

    match encode_as_avi_mjpeg(frames, config, &avi_path) {
        Ok(()) => {
            let size = std::fs::metadata(&avi_path)
                .map(|m| m.len())
                .unwrap_or(0);
            return Ok(("avi_mjpeg".to_string(), size));
        }
        Err(e) => {
            eprintln!("tallow recording: AVI MJPEG failed ({e}), falling back to JPEG sequence");
        }
    }

    // Strategy C: JPEG sequence fallback
    // Output dir = output_path without extension
    let dir = PathBuf::from(output_path)
        .with_extension("")
        .to_string_lossy()
        .into_owned();
    save_as_frames(frames, config, &dir)?;
    let size = dir_size(Path::new(&dir));
    Ok(("frames".to_string(), size))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Write `frames` as frame_00001.jpg, frame_00002.jpg, … into `dir`.
fn write_jpeg_sequence(frames: &[Vec<u8>], dir: &Path) -> Result<(), String> {
    for (i, frame) in frames.iter().enumerate() {
        let path = dir.join(format!("frame_{:05}.jpg", i + 1));
        std::fs::write(&path, frame)
            .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Compute total byte size of all files in `dir` (non-recursive).
fn dir_size(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .ok()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

// ── Little-endian write helpers ───────────────────────────────────────────

#[inline]
fn write_u16_le(w: &mut impl Write, v: u16) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

#[inline]
fn write_u32_le(w: &mut impl Write, v: u32) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

#[inline]
fn write_i32_le(w: &mut impl Write, v: i32) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid JPEG bytes for testing (2x2 gray JPEG, ~300 bytes).
    // These are real JPEG magic bytes so parsers accept them.
    fn tiny_jpeg() -> Vec<u8> {
        // SOI + minimal JFIF APP0 + SOF0 + EOI
        vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00,
            0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0xFF, 0xD9, // EOI
        ]
    }

    #[test]
    fn test_recording_config_defaults() {
        let cfg = RecordingConfig::default();
        assert_eq!(cfg.width, 3840);
        assert_eq!(cfg.height, 2160);
        assert_eq!(cfg.fps, 30);
        assert_eq!(cfg.quality, 90);
        assert_eq!(cfg.format, "mp4");
        assert_eq!(cfg.max_frames_in_memory, 1800);
    }

    #[test]
    fn test_parse_resolution_presets() {
        assert_eq!(parse_resolution("4k"), (3840, 2160));
        assert_eq!(parse_resolution("uhd"), (3840, 2160));
        assert_eq!(parse_resolution("2160p"), (3840, 2160));
        assert_eq!(parse_resolution("2k"), (2560, 1440));
        assert_eq!(parse_resolution("1080p"), (1920, 1080));
        assert_eq!(parse_resolution("fhd"), (1920, 1080));
        assert_eq!(parse_resolution("720p"), (1280, 720));
        assert_eq!(parse_resolution("hd"), (1280, 720));
        assert_eq!(parse_resolution("480p"), (854, 480));
    }

    #[test]
    fn test_parse_resolution_wxh() {
        assert_eq!(parse_resolution("2560x1440"), (2560, 1440));
        assert_eq!(parse_resolution("640x480"), (640, 480));
    }

    #[test]
    fn test_parse_resolution_unknown_falls_back() {
        assert_eq!(parse_resolution("nonsense"), (1920, 1080));
    }

    #[test]
    fn test_recording_result_fields() {
        let r = RecordingResult {
            frame_count: 300,
            duration_secs: 10.0,
            file_size: 1_234_567,
            output_path: "/tmp/out.avi".to_string(),
            resolution: "3840x2160".to_string(),
            encoding: "avi_mjpeg".to_string(),
        };
        assert_eq!(r.frame_count, 300);
        assert!((r.duration_secs - 10.0).abs() < f64::EPSILON);
        assert_eq!(r.file_size, 1_234_567);
        assert_eq!(r.resolution, "3840x2160");
        assert_eq!(r.encoding, "avi_mjpeg");
    }

    #[test]
    fn test_avi_mjpeg_produces_valid_riff_header() {
        let frames = vec![tiny_jpeg(), tiny_jpeg(), tiny_jpeg()];
        let cfg = RecordingConfig {
            width: 320,
            height: 240,
            fps: 30,
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("tallow_avi_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("test.avi").to_string_lossy().into_owned();

        encode_as_avi_mjpeg(&frames, &cfg, &output).unwrap();

        let data = std::fs::read(&output).unwrap();
        // RIFF magic
        assert_eq!(&data[0..4], b"RIFF");
        // AVI type
        assert_eq!(&data[8..12], b"AVI ");
        // hdrl LIST
        assert_eq!(&data[12..16], b"LIST");
        // movi chunk must contain our JPEG data
        let movi_pos = data
            .windows(4)
            .position(|w| w == b"movi")
            .expect("movi chunk not found");
        assert!(movi_pos > 0);
        // idx1 must follow
        let idx1_pos = data
            .windows(4)
            .position(|w| w == b"idx1")
            .expect("idx1 not found");
        assert!(idx1_pos > movi_pos);
        // Correct frame count in idx1: 3 frames × 16 bytes = 48 bytes
        let idx1_size = u32::from_le_bytes([
            data[idx1_pos + 4],
            data[idx1_pos + 5],
            data[idx1_pos + 6],
            data[idx1_pos + 7],
        ]);
        assert_eq!(idx1_size, 3 * 16);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_avi_mjpeg_empty_frames_error() {
        let cfg = RecordingConfig::default();
        let result = encode_as_avi_mjpeg(&[], &cfg, "/tmp/empty.avi");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no frames"));
    }

    #[test]
    fn test_save_as_frames_creates_files() {
        let frames = vec![tiny_jpeg(), tiny_jpeg()];
        let cfg = RecordingConfig::default();
        let dir = std::env::temp_dir()
            .join("tallow_frames_test")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_dir_all(&dir);

        save_as_frames(&frames, &cfg, &dir).unwrap();

        assert!(std::fs::metadata(format!("{dir}/frame_00001.jpg")).is_ok());
        assert!(std::fs::metadata(format!("{dir}/frame_00002.jpg")).is_ok());
        assert!(std::fs::metadata(format!("{dir}/frame_00003.jpg")).is_err()); // only 2

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_encode_frames_avi_when_no_ffmpeg_available() {
        // Simulate no ffmpeg: request "avi" format directly (always goes to AVI path)
        let frames = vec![tiny_jpeg()];
        let cfg = RecordingConfig {
            width: 160,
            height: 120,
            fps: 24,
            format: "avi".to_string(),
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("tallow_encode_test_avi");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.avi").to_string_lossy().into_owned();

        let (encoding, size) = encode_frames(&frames, &cfg, &out).unwrap();
        // Either ffmpeg or avi_mjpeg depending on system
        assert!(encoding == "ffmpeg" || encoding == "avi_mjpeg");
        assert!(size > 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_encode_frames_frames_mode() {
        let frames = vec![tiny_jpeg(), tiny_jpeg()];
        let cfg = RecordingConfig {
            format: "frames".to_string(),
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("tallow_encode_frames_mode");
        let _ = std::fs::remove_dir_all(&dir);

        let (encoding, _size) = encode_frames(&frames, &cfg, &dir.to_string_lossy()).unwrap();
        assert_eq!(encoding, "frames");
        assert!(dir.join("frame_00001.jpg").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_encode_frames_empty_error() {
        let cfg = RecordingConfig::default();
        let result = encode_frames(&[], &cfg, "/tmp/out.mp4");
        assert!(result.is_err());
    }

    #[test]
    fn test_ffmpeg_available_returns_bool() {
        // We can't assert either way, just verify it doesn't panic
        let _ = ffmpeg_available();
    }

    #[test]
    fn recording_codec_ffmpeg_names() {
        assert_eq!(RecordingCodec::H264.ffmpeg_codec(), "libx264");
        assert_eq!(RecordingCodec::VP9.ffmpeg_codec(), "libvpx-vp9");
        assert_eq!(RecordingCodec::AV1.ffmpeg_codec(), "libaom-av1");
    }

    #[test]
    fn recording_codec_extensions() {
        assert_eq!(RecordingCodec::H264.file_extension(), "mp4");
        assert_eq!(RecordingCodec::VP9.file_extension(), "webm");
        assert_eq!(RecordingCodec::AV1.file_extension(), "mp4");
    }

    #[test]
    fn test_recording_config_new_fields_defaults() {
        let cfg = RecordingConfig::default();
        assert_eq!(cfg.codec, RecordingCodec::H264);
        assert_eq!(cfg.crf, 18);
        assert!(!cfg.capture_audio);
    }
}
