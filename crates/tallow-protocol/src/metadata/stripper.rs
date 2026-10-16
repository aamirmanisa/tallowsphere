//! Metadata stripping for privacy
//!
//! Strips EXIF data from images and metadata from other file types
//! to prevent leaking GPS coordinates, device identifiers, timestamps, etc.

use crate::Result;

/// Known image magic bytes
const JPEG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF];
const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47];

/// Strip EXIF data from JPEG images
///
/// Removes all APP1 (EXIF), APP2 (ICC profile), and APP13 (IPTC) segments
/// while preserving the image data itself.
pub fn strip_exif(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 3 {
        return Ok(data.to_vec());
    }

    // Only process JPEG files
    if !data.starts_with(JPEG_MAGIC) {
        return Ok(data.to_vec());
    }

    let mut output = Vec::with_capacity(data.len());

    // Copy SOI marker
    output.extend_from_slice(&data[..2]);
    let mut i = 2;

    while i < data.len() - 1 {
        if data[i] != 0xFF {
            // We've hit the scan data — copy the rest verbatim
            output.extend_from_slice(&data[i..]);
            break;
        }

        let marker = data[i + 1];

        match marker {
            // APP1 (EXIF/XMP), APP2 (ICC), APP3-APP15 (vendor metadata, XMP extended, IPTC)
            // Strip all APPn markers except APP0 (JFIF — required for baseline JPEG rendering)
            0xE1..=0xEF => {
                if i + 3 < data.len() {
                    let seg_len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
                    i += 2 + seg_len;
                } else {
                    // Malformed — copy rest
                    output.extend_from_slice(&data[i..]);
                    break;
                }
            }
            // SOS (Start of Scan) — copy everything from here to end
            0xDA => {
                output.extend_from_slice(&data[i..]);
                break;
            }
            // All other markers — keep them
            _ => {
                output.push(data[i]);
                output.push(data[i + 1]);
                i += 2;

                // Most markers have a length field (except standalone markers)
                if marker != 0xD8
                    && marker != 0xD9
                    && !(0xD0..=0xD7).contains(&marker)
                    && marker != 0x00
                    && i + 1 < data.len()
                {
                    let seg_len = ((data[i] as usize) << 8) | (data[i + 1] as usize);
                    if i + seg_len <= data.len() {
                        output.extend_from_slice(&data[i..i + seg_len]);
                        i += seg_len;
                    } else {
                        output.extend_from_slice(&data[i..]);
                        break;
                    }
                }
            }
        }
    }

    Ok(output)
}

/// Strip metadata from a file based on its type
///
/// Detects file type from magic bytes and strips appropriate metadata.
pub fn strip_metadata(data: &[u8], file_extension: &str) -> Result<Vec<u8>> {
    let ext = file_extension.to_lowercase();

    match ext.as_str() {
        "jpg" | "jpeg" => strip_exif(data),
        "png" => strip_png_metadata(data),
        _ => {
            // For unknown types, return data unchanged
            Ok(data.to_vec())
        }
    }
}

/// Strip metadata chunks from PNG files
///
/// Removes tEXt, zTXt, iTXt, and eXIf chunks that may contain
/// metadata like GPS coordinates, camera info, etc.
fn strip_png_metadata(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 8 || !data.starts_with(PNG_MAGIC) {
        return Ok(data.to_vec());
    }

    let mut output = Vec::with_capacity(data.len());

    // Copy PNG signature (8 bytes)
    output.extend_from_slice(&data[..8]);
    let mut i = 8;

    while i + 12 <= data.len() {
        // Read chunk: 4-byte length + 4-byte type + data + 4-byte CRC
        let chunk_len =
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let chunk_type = &data[i + 4..i + 8];
        let total_chunk_size = 12 + chunk_len; // 4 len + 4 type + data + 4 CRC

        if i + total_chunk_size > data.len() {
            // Malformed — copy rest
            output.extend_from_slice(&data[i..]);
            break;
        }

        // Check if this is a metadata chunk to strip
        let should_strip = matches!(chunk_type, b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"tIME");

        if !should_strip {
            output.extend_from_slice(&data[i..i + total_chunk_size]);
        }

        i += total_chunk_size;
    }

    // Copy any remaining data
    if i < data.len() {
        output.extend_from_slice(&data[i..]);
    }

    Ok(output)
}

/// Check if a file contains EXIF data
pub fn has_exif(data: &[u8]) -> bool {
    if data.len() < 12 || !data.starts_with(JPEG_MAGIC) {
        return false;
    }

    // Look for APP1 marker (0xFF 0xE1) followed by "Exif\0\0"
    for window in data.windows(8) {
        if window[0] == 0xFF && window[1] == 0xE1 {
            // Check if payload starts with "Exif"
            if window.len() >= 6 && &window[4..8] == b"Exif" {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_exif_non_jpeg() {
        let data = b"not a jpeg file";
        let result = strip_exif(data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_exif_minimal_jpeg() {
        // Minimal JPEG: SOI + APP1(EXIF) + SOS + image data + EOI
        let mut jpeg = vec![0xFF, 0xD8]; // SOI
                                         // APP1 (EXIF) segment
        jpeg.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x08]); // APP1, length=8
        jpeg.extend_from_slice(&[0x45, 0x78, 0x69, 0x66, 0x00, 0x00]); // "Exif\0\0"
                                                                       // SOS marker + some data
        jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]); // SOS
        jpeg.extend_from_slice(&[0x01, 0x02, 0x03]); // Image data
        jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI

        let stripped = strip_exif(&jpeg).unwrap();

        // APP1 should be removed, but SOS and image data preserved
        assert!(stripped.len() < jpeg.len());
        assert!(stripped.starts_with(&[0xFF, 0xD8])); // SOI preserved
    }

    #[test]
    fn test_strip_metadata_unknown_type() {
        let data = b"some random data";
        let result = strip_metadata(data, "txt").unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_png_non_png() {
        let data = b"not a png";
        let result = strip_png_metadata(data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_has_exif_no_exif() {
        let data = b"not a jpeg at all";
        assert!(!has_exif(data));
    }
}
