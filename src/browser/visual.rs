//! Visual testing: screenshots, PDF generation, pixel diff comparison, and baseline management.
//!
//! Provides CDP-based screenshot capture (full-page, viewport, element), PDF export,
//! pixel-level image comparison with configurable threshold, and a baseline manifest
//! system for visual regression testing.

use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::cdp::CdpClient;
use super::error::BrowserError;

// ---------------------------------------------------------------------------
// Screenshot capture
// ---------------------------------------------------------------------------

/// Capture a full-page screenshot (entire scrollable area) as PNG bytes.
///
/// Uses `Page.captureScreenshot` with `captureBeyondViewport: true` so the
/// resulting image includes content below the fold.
pub async fn capture_screenshot(
    client: &CdpClient,
    session_id: &str,
) -> Result<Vec<u8>, BrowserError> {
    let result = client
        .send_command_with_session(
            "Page.captureScreenshot",
            Some(json!({
                "format": "png",
                "captureBeyondViewport": true,
                "fromSurface": true,
            })),
            session_id,
        )
        .await?;

    let b64 = result
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BrowserError::CdpError {
            code: -1,
            message: "missing data in captureScreenshot response".to_string(),
        })?;

    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("base64 decode error: {e}"),
        })
}

/// Capture a viewport-only screenshot as PNG bytes.
///
/// Smaller than a full-page screenshot -- useful for trace recording where
/// we want quick snapshots of the visible area only.
pub async fn capture_viewport_screenshot(
    client: &CdpClient,
    session_id: &str,
) -> Result<Vec<u8>, BrowserError> {
    let result = client
        .send_command_with_session(
            "Page.captureScreenshot",
            Some(json!({
                "format": "png",
                "fromSurface": true,
            })),
            session_id,
        )
        .await?;

    let b64 = result
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BrowserError::CdpError {
            code: -1,
            message: "missing data in captureScreenshot response".to_string(),
        })?;

    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("base64 decode error: {e}"),
        })
}

/// Capture a screenshot of a specific element identified by its remote object ID.
///
/// Retrieves the element's bounding box via `DOM.getBoxModel`, then clips
/// `Page.captureScreenshot` to that region.
pub async fn capture_element_screenshot(
    client: &CdpClient,
    session_id: &str,
    object_id: &str,
) -> Result<Vec<u8>, BrowserError> {
    // Enable DOM domain (idempotent)
    let _ = client
        .send_command_with_session("DOM.enable", None, session_id)
        .await;

    // Get bounding box via DOM.getBoxModel
    let box_result = client
        .send_command_with_session(
            "DOM.getBoxModel",
            Some(json!({ "objectId": object_id })),
            session_id,
        )
        .await?;

    let content = box_result
        .get("model")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
        .ok_or_else(|| BrowserError::CdpError {
            code: -1,
            message: "missing content quad in getBoxModel response".to_string(),
        })?;

    // content quad: [x1,y1, x2,y2, x3,y3, x4,y4]
    let x = content
        .first()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let y = content
        .get(1)
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let x2 = content
        .get(2)
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let y3 = content
        .get(5)
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let width = x2 - x;
    let height = y3 - y;

    let result = client
        .send_command_with_session(
            "Page.captureScreenshot",
            Some(json!({
                "format": "png",
                "fromSurface": true,
                "clip": {
                    "x": x,
                    "y": y,
                    "width": width,
                    "height": height,
                    "scale": 1.0,
                }
            })),
            session_id,
        )
        .await?;

    let b64 = result
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BrowserError::CdpError {
            code: -1,
            message: "missing data in captureScreenshot response".to_string(),
        })?;

    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("base64 decode error: {e}"),
        })
}

// ---------------------------------------------------------------------------
// PDF generation
// ---------------------------------------------------------------------------

/// Options for PDF generation via `Page.printToPDF`.
#[derive(Debug, Clone)]
pub struct PdfOptions {
    /// Landscape orientation. Default: false.
    pub landscape: bool,
    /// Print background graphics. Default: true.
    pub print_background: bool,
    /// Paper width in inches. Default: 8.5 (US Letter).
    pub paper_width: f64,
    /// Paper height in inches. Default: 11.0 (US Letter).
    pub paper_height: f64,
    /// Top margin in inches. Default: 0.4.
    pub margin_top: f64,
    /// Bottom margin in inches. Default: 0.4.
    pub margin_bottom: f64,
    /// Left margin in inches. Default: 0.4.
    pub margin_left: f64,
    /// Right margin in inches. Default: 0.4.
    pub margin_right: f64,
    /// Scale of the content. Default: 1.0.
    pub scale: f64,
}

impl Default for PdfOptions {
    fn default() -> Self {
        Self {
            landscape: false,
            print_background: true,
            paper_width: 8.5,
            paper_height: 11.0,
            margin_top: 0.4,
            margin_bottom: 0.4,
            margin_left: 0.4,
            margin_right: 0.4,
            scale: 1.0,
        }
    }
}

/// Generate a PDF document from the current page.
///
/// Returns raw PDF bytes decoded from the base64 CDP response.
pub async fn print_to_pdf(
    client: &CdpClient,
    session_id: &str,
    options: &PdfOptions,
) -> Result<Vec<u8>, BrowserError> {
    let result = client
        .send_command_with_session(
            "Page.printToPDF",
            Some(json!({
                "landscape": options.landscape,
                "printBackground": options.print_background,
                "paperWidth": options.paper_width,
                "paperHeight": options.paper_height,
                "marginTop": options.margin_top,
                "marginBottom": options.margin_bottom,
                "marginLeft": options.margin_left,
                "marginRight": options.margin_right,
                "scale": options.scale,
            })),
            session_id,
        )
        .await?;

    let b64 = result
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BrowserError::CdpError {
            code: -1,
            message: "missing data in printToPDF response".to_string(),
        })?;

    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("base64 decode error: {e}"),
        })
}

// ---------------------------------------------------------------------------
// Pixel diff comparison
// ---------------------------------------------------------------------------

/// Result of comparing two screenshots pixel by pixel.
#[derive(Debug, Clone)]
pub struct DiffResult {
    /// Total number of pixels in the image.
    pub total_pixels: u64,
    /// Number of pixels that differ beyond the threshold.
    pub different_pixels: u64,
    /// Percentage of pixels that differ (0.0 -- 100.0).
    pub diff_percentage: f64,
    /// Whether the two images have the same dimensions.
    pub dimensions_match: bool,
    /// Dimensions of the baseline image (width, height).
    pub baseline_size: (u32, u32),
    /// Dimensions of the current image (width, height).
    pub current_size: (u32, u32),
}

/// Decode a PNG byte buffer into (width, height, RGBA pixel data).
fn decode_png(data: &[u8]) -> Result<(u32, u32, Vec<u8>), BrowserError> {
    let decoder = png::Decoder::new(data);
    let mut reader = decoder
        .read_info()
        .map_err(|e| BrowserError::CdpError {
            code: -1,
            message: format!("PNG decode error: {e}"),
        })?;

    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).map_err(|e| BrowserError::CdpError {
        code: -1,
        message: format!("PNG frame read error: {e}"),
    })?;

    let bytes = &buf[..info.buffer_size()];

    // Convert to RGBA if needed
    let rgba = match info.color_type {
        png::ColorType::Rgba => bytes.to_vec(),
        png::ColorType::Rgb => {
            let mut rgba_buf = Vec::with_capacity((info.width * info.height * 4) as usize);
            for chunk in bytes.chunks(3) {
                rgba_buf.push(chunk[0]);
                rgba_buf.push(chunk[1]);
                rgba_buf.push(chunk[2]);
                rgba_buf.push(255); // fully opaque
            }
            rgba_buf
        }
        png::ColorType::Grayscale => {
            let mut rgba_buf = Vec::with_capacity((info.width * info.height * 4) as usize);
            for &g in bytes {
                rgba_buf.push(g);
                rgba_buf.push(g);
                rgba_buf.push(g);
                rgba_buf.push(255);
            }
            rgba_buf
        }
        png::ColorType::GrayscaleAlpha => {
            let mut rgba_buf = Vec::with_capacity((info.width * info.height * 4) as usize);
            for chunk in bytes.chunks(2) {
                rgba_buf.push(chunk[0]);
                rgba_buf.push(chunk[0]);
                rgba_buf.push(chunk[0]);
                rgba_buf.push(chunk[1]);
            }
            rgba_buf
        }
        _ => {
            return Err(BrowserError::CdpError {
                code: -1,
                message: format!("unsupported PNG color type: {:?}", info.color_type),
            });
        }
    };

    Ok((info.width, info.height, rgba))
}

/// Compare two PNG screenshots pixel by pixel.
///
/// For each pixel, the per-channel absolute difference is computed. If any
/// channel (R, G, B, A) differs by more than `threshold`, the pixel is
/// counted as different.
///
/// If the images have different dimensions, returns `DiffResult` with
/// `dimensions_match: false` and `diff_percentage: 100.0`.
pub fn compare_screenshots(
    baseline: &[u8],
    current: &[u8],
    threshold: u8,
) -> Result<DiffResult, BrowserError> {
    let (bw, bh, bpix) = decode_png(baseline)?;
    let (cw, ch, cpix) = decode_png(current)?;

    if bw != cw || bh != ch {
        return Ok(DiffResult {
            total_pixels: (bw as u64) * (bh as u64),
            different_pixels: (bw as u64) * (bh as u64),
            diff_percentage: 100.0,
            dimensions_match: false,
            baseline_size: (bw, bh),
            current_size: (cw, ch),
        });
    }

    let total = (bw as u64) * (bh as u64);
    let mut diff_count = 0u64;

    // Compare RGBA pixel data (4 bytes per pixel)
    for i in (0..bpix.len()).step_by(4) {
        if i + 3 >= bpix.len() || i + 3 >= cpix.len() {
            break;
        }
        let dr = (bpix[i] as i16 - cpix[i] as i16).unsigned_abs() as u8;
        let dg = (bpix[i + 1] as i16 - cpix[i + 1] as i16).unsigned_abs() as u8;
        let db = (bpix[i + 2] as i16 - cpix[i + 2] as i16).unsigned_abs() as u8;
        let da = (bpix[i + 3] as i16 - cpix[i + 3] as i16).unsigned_abs() as u8;

        if dr > threshold || dg > threshold || db > threshold || da > threshold {
            diff_count += 1;
        }
    }

    let pct = if total == 0 {
        0.0
    } else {
        (diff_count as f64 / total as f64) * 100.0
    };

    Ok(DiffResult {
        total_pixels: total,
        different_pixels: diff_count,
        diff_percentage: pct,
        dimensions_match: true,
        baseline_size: (bw, bh),
        current_size: (cw, ch),
    })
}

// ---------------------------------------------------------------------------
// Baseline management
// ---------------------------------------------------------------------------

/// A single entry in the baseline manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Logical name of the baseline (e.g. "homepage-header").
    pub name: String,
    /// SHA-256 hex digest of the PNG bytes.
    pub hash: String,
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// ISO 8601 timestamp when the baseline was first created.
    pub created_at: String,
    /// ISO 8601 timestamp when the baseline was last updated.
    pub updated_at: String,
}

/// Manifest file (`baselines.json`) tracking all visual baselines in a directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineManifest {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// All baseline entries.
    pub entries: Vec<BaselineEntry>,
}

impl BaselineManifest {
    fn new() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

/// Compute the SHA-256 hex digest of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Save a PNG screenshot as a named baseline.
///
/// Writes the PNG to `{dir}/{name}.png` and upserts the entry in
/// `{dir}/baselines.json` with the SHA-256 content hash.
pub fn save_baseline(dir: &Path, name: &str, png_data: &[u8]) -> Result<(), BrowserError> {
    // Ensure directory exists
    std::fs::create_dir_all(dir).map_err(|e| {
        BrowserError::FileNotFound(format!("cannot create baseline dir {}: {e}", dir.display()))
    })?;

    // Write PNG file
    let png_path = dir.join(format!("{name}.png"));
    std::fs::write(&png_path, png_data).map_err(|e| {
        BrowserError::FileNotFound(format!("cannot write {}: {e}", png_path.display()))
    })?;

    // Decode PNG dimensions
    let (w, h, _) = decode_png(png_data)?;

    // Compute hash
    let hash = sha256_hex(png_data);

    // Read or create manifest
    let manifest_path = dir.join("baselines.json");
    let mut manifest = if manifest_path.exists() {
        let data = std::fs::read_to_string(&manifest_path).map_err(|e| {
            BrowserError::FileNotFound(format!(
                "cannot read {}: {e}",
                manifest_path.display()
            ))
        })?;
        serde_json::from_str::<BaselineManifest>(&data)?
    } else {
        BaselineManifest::new()
    };

    let now = chrono::Utc::now().to_rfc3339();

    // Upsert entry
    if let Some(entry) = manifest.entries.iter_mut().find(|e| e.name == name) {
        entry.hash = hash;
        entry.width = w;
        entry.height = h;
        entry.updated_at = now;
    } else {
        manifest.entries.push(BaselineEntry {
            name: name.to_string(),
            hash,
            width: w,
            height: h,
            created_at: now.clone(),
            updated_at: now,
        });
    }

    // Write manifest
    let json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&manifest_path, json).map_err(|e| {
        BrowserError::FileNotFound(format!(
            "cannot write {}: {e}",
            manifest_path.display()
        ))
    })?;

    Ok(())
}

/// Load a previously saved baseline PNG by name.
///
/// Returns the raw PNG bytes, or `BrowserError::FileNotFound` if it
/// does not exist.
pub fn load_baseline(dir: &Path, name: &str) -> Result<Vec<u8>, BrowserError> {
    let png_path = dir.join(format!("{name}.png"));
    std::fs::read(&png_path)
        .map_err(|e| BrowserError::FileNotFound(format!("{}: {e}", png_path.display())))
}

/// Compare a current screenshot against a saved baseline.
///
/// Loads the baseline from disk and runs `compare_screenshots`.
pub fn compare_with_baseline(
    dir: &Path,
    name: &str,
    current: &[u8],
    threshold: u8,
) -> Result<DiffResult, BrowserError> {
    let baseline = load_baseline(dir, name)?;
    compare_screenshots(&baseline, current, threshold)
}

/// Update (overwrite) a baseline -- alias for `save_baseline`.
pub fn update_baseline(dir: &Path, name: &str, png_data: &[u8]) -> Result<(), BrowserError> {
    save_baseline(dir, name, png_data)
}

/// List all baselines in a directory by reading the manifest.
pub fn list_baselines(dir: &Path) -> Result<Vec<BaselineEntry>, BrowserError> {
    let manifest_path = dir.join("baselines.json");
    if !manifest_path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&manifest_path)
        .map_err(|e| BrowserError::FileNotFound(format!("{}: {e}", manifest_path.display())))?;
    let manifest: BaselineManifest = serde_json::from_str(&data)?;
    Ok(manifest.entries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a minimal RGBA PNG in memory using the `png` crate encoder.
    fn create_test_png(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut buf, width, height);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(rgba).unwrap();
        }
        buf
    }

    #[test]
    fn test_pdf_options_defaults() {
        let opts = PdfOptions::default();
        assert!(!opts.landscape);
        assert!(opts.print_background);
        assert!((opts.paper_width - 8.5).abs() < f64::EPSILON);
        assert!((opts.paper_height - 11.0).abs() < f64::EPSILON);
        assert!((opts.margin_top - 0.4).abs() < f64::EPSILON);
        assert!((opts.margin_bottom - 0.4).abs() < f64::EPSILON);
        assert!((opts.margin_left - 0.4).abs() < f64::EPSILON);
        assert!((opts.margin_right - 0.4).abs() < f64::EPSILON);
        assert!((opts.scale - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_diff_result_identical_images() {
        // 2x2 solid red image
        let rgba = [
            255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255,
        ];
        let img = create_test_png(2, 2, &rgba);

        let result = compare_screenshots(&img, &img, 0).unwrap();
        assert!(result.dimensions_match);
        assert_eq!(result.total_pixels, 4);
        assert_eq!(result.different_pixels, 0);
        assert!((result.diff_percentage - 0.0).abs() < f64::EPSILON);
        assert_eq!(result.baseline_size, (2, 2));
        assert_eq!(result.current_size, (2, 2));
    }

    #[test]
    fn test_diff_result_completely_different_images() {
        // 2x2 solid red
        let red = [
            255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255,
        ];
        // 2x2 solid blue
        let blue = [
            0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255,
        ];

        let img_red = create_test_png(2, 2, &red);
        let img_blue = create_test_png(2, 2, &blue);

        let result = compare_screenshots(&img_red, &img_blue, 0).unwrap();
        assert!(result.dimensions_match);
        assert_eq!(result.total_pixels, 4);
        assert_eq!(result.different_pixels, 4);
        assert!((result.diff_percentage - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_diff_result_dimension_mismatch() {
        let small = create_test_png(2, 2, &[0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255]);
        let big = create_test_png(
            3,
            2,
            &[0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255],
        );

        let result = compare_screenshots(&small, &big, 0).unwrap();
        assert!(!result.dimensions_match);
        assert!((result.diff_percentage - 100.0).abs() < f64::EPSILON);
        assert_eq!(result.baseline_size, (2, 2));
        assert_eq!(result.current_size, (3, 2));
    }

    #[test]
    fn test_compare_threshold_exact_vs_lenient() {
        // 2x2 almost-red (254 instead of 255 on red channel)
        let exact_red = [
            255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255,
        ];
        let almost_red = [
            254, 0, 0, 255, 254, 0, 0, 255, 254, 0, 0, 255, 254, 0, 0, 255,
        ];

        let img_exact = create_test_png(2, 2, &exact_red);
        let img_almost = create_test_png(2, 2, &almost_red);

        // threshold=0: every pixel differs (diff of 1 on red channel)
        let strict = compare_screenshots(&img_exact, &img_almost, 0).unwrap();
        assert_eq!(strict.different_pixels, 4);
        assert!((strict.diff_percentage - 100.0).abs() < f64::EPSILON);

        // threshold=10: no pixel differs (diff of 1 <= 10)
        let lenient = compare_screenshots(&img_exact, &img_almost, 10).unwrap();
        assert_eq!(lenient.different_pixels, 0);
        assert!((lenient.diff_percentage - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_baseline_entry_serialization() {
        let entry = BaselineEntry {
            name: "home-header".to_string(),
            hash: "abc123".to_string(),
            width: 1920,
            height: 1080,
            created_at: "2026-03-01T00:00:00Z".to_string(),
            updated_at: "2026-03-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deser: BaselineEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.name, "home-header");
        assert_eq!(deser.hash, "abc123");
        assert_eq!(deser.width, 1920);
        assert_eq!(deser.height, 1080);
    }

    #[test]
    fn test_baseline_manifest_serialization() {
        let manifest = BaselineManifest {
            version: 1,
            entries: vec![BaselineEntry {
                name: "test".to_string(),
                hash: "deadbeef".to_string(),
                width: 100,
                height: 50,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let deser: BaselineManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.version, 1);
        assert_eq!(deser.entries.len(), 1);
        assert_eq!(deser.entries[0].name, "test");
    }

    #[test]
    fn test_save_and_load_baseline() {
        let dir = std::env::temp_dir().join("tallow_visual_test_baseline");
        let _ = std::fs::remove_dir_all(&dir);

        let rgba = [255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 0, 255];
        let png_data = create_test_png(2, 2, &rgba);

        // Save baseline
        save_baseline(&dir, "test-shot", &png_data).unwrap();

        // Verify PNG file exists
        assert!(dir.join("test-shot.png").exists());

        // Verify manifest
        let manifest_data =
            std::fs::read_to_string(dir.join("baselines.json")).unwrap();
        let manifest: BaselineManifest = serde_json::from_str(&manifest_data).unwrap();
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].name, "test-shot");
        assert_eq!(manifest.entries[0].width, 2);
        assert_eq!(manifest.entries[0].height, 2);
        // Hash should be a 64-char hex string
        assert_eq!(manifest.entries[0].hash.len(), 64);

        // Load baseline
        let loaded = load_baseline(&dir, "test-shot").unwrap();
        assert_eq!(loaded, png_data);

        // Clean up
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_save_baseline_upserts_existing() {
        let dir = std::env::temp_dir().join("tallow_visual_test_upsert");
        let _ = std::fs::remove_dir_all(&dir);

        let red = [255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255];
        let blue = [0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255];

        let png_red = create_test_png(2, 2, &red);
        let png_blue = create_test_png(2, 2, &blue);

        save_baseline(&dir, "shot", &png_red).unwrap();
        let hash1 = {
            let m: BaselineManifest =
                serde_json::from_str(&std::fs::read_to_string(dir.join("baselines.json")).unwrap())
                    .unwrap();
            m.entries[0].hash.clone()
        };

        // Update with different image
        save_baseline(&dir, "shot", &png_blue).unwrap();
        let m: BaselineManifest =
            serde_json::from_str(&std::fs::read_to_string(dir.join("baselines.json")).unwrap())
                .unwrap();
        assert_eq!(m.entries.len(), 1); // still one entry
        assert_ne!(m.entries[0].hash, hash1); // hash changed

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compare_with_baseline_same() {
        let dir = std::env::temp_dir().join("tallow_visual_test_cmp");
        let _ = std::fs::remove_dir_all(&dir);

        let rgba = [128, 128, 128, 255, 128, 128, 128, 255, 128, 128, 128, 255, 128, 128, 128, 255];
        let png = create_test_png(2, 2, &rgba);

        save_baseline(&dir, "gray", &png).unwrap();
        let result = compare_with_baseline(&dir, "gray", &png, 0).unwrap();
        assert!(result.dimensions_match);
        assert_eq!(result.different_pixels, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_list_baselines_empty_dir() {
        let dir = std::env::temp_dir().join("tallow_visual_test_list_empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let entries = list_baselines(&dir).unwrap();
        assert!(entries.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_list_baselines_with_entries() {
        let dir = std::env::temp_dir().join("tallow_visual_test_list_entries");
        let _ = std::fs::remove_dir_all(&dir);

        let rgba = [0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255];
        let png = create_test_png(2, 2, &rgba);

        save_baseline(&dir, "a", &png).unwrap();
        save_baseline(&dir, "b", &png).unwrap();

        let entries = list_baselines(&dir).unwrap();
        assert_eq!(entries.len(), 2);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_baseline_not_found() {
        let dir = std::env::temp_dir().join("tallow_visual_test_not_found");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let err = load_baseline(&dir, "nonexistent").unwrap_err();
        assert!(matches!(err, BrowserError::FileNotFound(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sha256_hex_consistency() {
        let data = b"hello visual testing";
        let h1 = sha256_hex(data);
        let h2 = sha256_hex(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_decode_png_roundtrip() {
        let rgba = [10, 20, 30, 255, 40, 50, 60, 128, 70, 80, 90, 200, 100, 110, 120, 255];
        let encoded = create_test_png(2, 2, &rgba);
        let (w, h, pixels) = decode_png(&encoded).unwrap();
        assert_eq!(w, 2);
        assert_eq!(h, 2);
        assert_eq!(pixels, rgba);
    }
}
