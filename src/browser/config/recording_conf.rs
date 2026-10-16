//! Video recording configuration (recording.toml).

use serde::{Deserialize, Serialize};

/// Screen recording and video capture settings.
///
/// ```toml
/// # recording.toml
/// width = 1920
/// height = 1080
/// fps = 30
/// quality = 90                   # JPEG quality 1-100
/// format = "mp4"                 # mp4 | webm | avi | frames
/// codec = "h264"                 # h264 | vp9 | av1
/// crf = 18                       # 0 (lossless) to 51/63
/// capture_audio = false
/// max_frames_in_memory = 1800    # ~60s at 30fps
/// output_dir = "recordings/"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RecordingToml {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Frames per second.
    pub fps: u32,
    /// JPEG quality (1-100).
    pub quality: u32,
    /// Output format: "mp4", "webm", "avi", "frames".
    pub format: String,
    /// Video codec: "h264", "vp9", "av1".
    pub codec: String,
    /// Constant Rate Factor (quality). Lower = better. H264: 0-51, VP9/AV1: 0-63.
    pub crf: u32,
    /// Capture system audio (requires PulseAudio/WASAPI).
    pub capture_audio: bool,
    /// Max frames held in memory before flushing.
    pub max_frames_in_memory: usize,
    /// Output directory for recordings.
    pub output_dir: String,
}

impl Default for RecordingToml {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 30,
            quality: 90,
            format: "mp4".into(),
            codec: "h264".into(),
            crf: 18,
            capture_audio: false,
            max_frames_in_memory: 1800,
            output_dir: "recordings/".into(),
        }
    }
}
