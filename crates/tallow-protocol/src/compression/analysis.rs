//! File analysis for compression heuristics

/// Calculate Shannon entropy of data
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Detect file type from magic bytes
pub fn detect_file_type(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    match &data[..4] {
        [0x89, 0x50, 0x4E, 0x47] => Some("png"),
        [0xFF, 0xD8, 0xFF, _] => Some("jpeg"),
        [0x50, 0x4B, 0x03, 0x04] => Some("zip"),
        [0x1F, 0x8B, _, _] => Some("gzip"),
        _ => None,
    }
}

/// Check if data is compressible
pub fn is_compressible(data: &[u8]) -> bool {
    // High entropy data (> 7.5) is likely already compressed
    shannon_entropy(data) < 7.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let entropy = shannon_entropy(&data);
        assert!(entropy > 7.9 && entropy < 8.1); // Should be ~8 bits
    }

    #[test]
    fn test_entropy_zeros() {
        let data = vec![0u8; 256];
        assert_eq!(shannon_entropy(&data), 0.0);
    }
}
