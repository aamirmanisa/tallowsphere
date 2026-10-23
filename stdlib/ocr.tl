// Tallow standard library: OCR (Optical Character Recognition)
// Powered by Tesseract CLI.

struct OcrResult {
    text: String,
    confidence: f64,
    blocks: []OcrBlock,
}

struct OcrBlock {
    text: String,
    confidence: f64,
    bbox: OcrBBox,
}

struct OcrBBox {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

struct OcrTable {
    headers: []String,
    rows: [][]String,
    confidence: f64,
}

/// Extract text from image bytes using Tesseract OCR.
/// Returns an OcrResult with full text, confidence, and block-level details.
native fn ocr_extract(image_data: Bytes) -> OcrResult

/// Parse OCR text output into a structured table using whitespace heuristics.
native fn ocr_parse_table(ocr_text: String) -> OcrTable
