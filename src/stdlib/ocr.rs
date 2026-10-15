//! Standard library: `tallow.ocr` — OCR extraction via Tesseract CLI.
//!
//! Shells out to `tesseract` with stdin/stdout pipes for image-to-text.
//! Includes table parsing via whitespace heuristics.

use super::StdlibResult;
use crate::interp::{type_name, Value};
use std::process::{Command, Stdio};

/// Dispatch static function calls: ocr.ocr_extract, ocr.ocr_parse_table
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "ocr_extract" => Some(ocr_extract(args)),
        "ocr_parse_table" => Some(ocr_parse_table(args)),
        _ => None,
    }
}

/// Dispatch method calls on OcrResult, OcrBlock, OcrBBox, OcrTable structs.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, .. } = object else {
        return None;
    };
    match name.as_str() {
        "OcrResult" | "OcrBlock" | "OcrTable" => match method {
            _ => None,
        },
        _ => None,
    }
}

/// Run tesseract OCR on image bytes, returning structured OcrResult.
fn ocr_extract(args: Vec<Value>) -> StdlibResult {
    let image_data = match args.first() {
        Some(Value::Bytes(data)) => data.clone(),
        Some(other) => {
            return Err(format!(
                "ocr.ocr_extract: expected Bytes argument, got {}",
                type_name(other)
            ));
        }
        None => {
            return Err("ocr.ocr_extract: missing image data argument".to_string());
        }
    };

    // Write image data to a temp file (tesseract needs a file path)
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!("tallow_ocr_{}.png", std::process::id()));
    std::fs::write(&tmp_path, &image_data)
        .map_err(|e| format!("ocr.ocr_extract: failed to write temp file: {e}"))?;

    // Run tesseract
    let output = Command::new("tesseract")
        .arg(&tmp_path)
        .arg("stdout")
        .arg("-l")
        .arg("eng")
        .arg("--psm")
        .arg("3")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    // Clean up temp file
    let _ = std::fs::remove_file(&tmp_path);

    match output {
        Ok(out) => {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout).to_string();
                let text_trimmed = text.trim().to_string();

                // Parse Tesseract output into blocks
                let blocks = parse_tesseract_blocks(&text_trimmed);

                // Calculate average confidence (Tesseract doesn't give per-run confidence
                // without TSV output, so estimate from block structure)
                let confidence = if blocks.is_empty() {
                    if text_trimmed.is_empty() {
                        0.0
                    } else {
                        80.0 // heuristic: non-empty output without structured blocks
                    }
                } else {
                    let avg: f64 =
                        blocks.iter().map(|b| b.confidence).sum::<f64>() / blocks.len() as f64;
                    avg
                };

                Ok(make_ocr_result(&text_trimmed, confidence, &blocks))
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if stderr.contains("not found") || stderr.contains("No such file") {
                    Err(
                        "ocr.ocr_extract: tesseract not found — install tesseract-ocr package"
                            .to_string(),
                    )
                } else {
                    Err(format!(
                        "ocr.ocr_extract: tesseract failed: {}",
                        stderr.trim()
                    ))
                }
            }
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                Err("ocr.ocr_extract: tesseract not found — install tesseract-ocr package"
                    .to_string())
            } else {
                Err(format!("ocr.ocr_extract: failed to run tesseract: {e}"))
            }
        }
    }
}

/// Parse OCR text into a structured table using whitespace heuristics.
fn ocr_parse_table(args: Vec<Value>) -> StdlibResult {
    let ocr_text = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(other) => {
            return Err(format!(
                "ocr.ocr_parse_table: expected String argument, got {}",
                type_name(other)
            ));
        }
        None => {
            return Err("ocr.ocr_parse_table: missing text argument".to_string());
        }
    };

    let lines: Vec<&str> = ocr_text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return Ok(make_ocr_table(&[], &[], 0.0));
    }

    // Split each line into columns by whitespace (2+ spaces or tab)
    let mut rows: Vec<Vec<String>> = Vec::new();
    for line in &lines {
        let cols: Vec<String> = line
            .split(|c: char| c == '\t' || c == '|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if cols.is_empty() {
            // Fall back to splitting on 2+ spaces
            let parts: Vec<String> = split_on_multispace(line);
            if !parts.is_empty() {
                rows.push(parts);
            }
        } else {
            rows.push(cols);
        }
    }

    if rows.is_empty() {
        return Ok(make_ocr_table(&[], &[], 0.0));
    }

    // First row is headers
    let headers = rows[0].clone();
    let data_rows: Vec<Vec<String>> = if rows.len() > 1 {
        rows[1..].to_vec()
    } else {
        vec![]
    };

    // Heuristic confidence: normalized by column alignment
    let max_cols = headers.len().max(data_rows.iter().map(|r| r.len()).max().unwrap_or(0));
    let alignment_score = if max_cols > 0 {
        let aligned = data_rows.iter().filter(|r| r.len() == max_cols).count();
        if data_rows.is_empty() {
            95.0
        } else {
            (aligned as f64 / data_rows.len() as f64) * 95.0
        }
    } else {
        50.0
    };

    Ok(make_ocr_table(&headers, &data_rows, alignment_score))
}

/// Split a string on 2+ consecutive spaces.
fn split_on_multispace(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut space_count = 0usize;

    for ch in s.chars() {
        if ch == ' ' {
            space_count += 1;
            if space_count >= 2 && !current.trim().is_empty() {
                parts.push(current.trim().to_string());
                current = String::new();
                space_count = 0;
            } else if space_count < 2 {
                current.push(' ');
            }
        } else {
            if space_count >= 2 && !current.trim().is_empty() {
                parts.push(current.trim().to_string());
                current = String::new();
            }
            space_count = 0;
            current.push(ch);
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

/// Parse Tesseract stdout into OcrBlock values.
fn parse_tesseract_blocks(_text: &str) -> Vec<OcrBlockData> {
    // Tesseract stdout mode gives plain text, not structured block data.
    // For block-level data, TSV output would be needed. Return a single block
    // containing the full text as a reasonable default.
    if _text.is_empty() {
        return vec![];
    }
    vec![OcrBlockData {
        text: _text.to_string(),
        confidence: 85.0,
        bbox: OcrBBoxData {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        },
    }]
}

// ── Internal data structs (not Value, used for construction) ──────────────

struct OcrBlockData {
    text: String,
    confidence: f64,
    bbox: OcrBBoxData,
}

struct OcrBBoxData {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

// ── Value constructors ────────────────────────────────────────────────────

fn make_ocr_result(text: &str, confidence: f64, blocks: &[OcrBlockData]) -> Value {
    let block_values: Vec<Value> = blocks
        .iter()
        .map(|b| {
            Value::Struct {
                name: "OcrBlock".to_string(),
                fields: vec![
                    ("text".to_string(), Value::String(b.text.clone())),
                    ("confidence".to_string(), Value::Float(b.confidence)),
                    (
                        "bbox".to_string(),
                        Value::Struct {
                            name: "OcrBBox".to_string(),
                            fields: vec![
                                ("x".to_string(), Value::Int(b.bbox.x as i128)),
                                ("y".to_string(), Value::Int(b.bbox.y as i128)),
                                ("width".to_string(), Value::Int(b.bbox.width as i128)),
                                ("height".to_string(), Value::Int(b.bbox.height as i128)),
                            ],
                        },
                    ),
                ],
            }
        })
        .collect();

    Value::Struct {
        name: "OcrResult".to_string(),
        fields: vec![
            ("text".to_string(), Value::String(text.to_string())),
            ("confidence".to_string(), Value::Float(confidence)),
            ("blocks".to_string(), Value::Array(block_values)),
        ],
    }
}

fn make_ocr_table(headers: &[String], rows: &[Vec<String>], confidence: f64) -> Value {
    let header_values: Vec<Value> = headers.iter().map(|h| Value::String(h.clone())).collect();
    let row_values: Vec<Value> = rows
        .iter()
        .map(|r| {
            Value::Array(r.iter().map(|c| Value::String(c.clone())).collect())
        })
        .collect();

    Value::Struct {
        name: "OcrTable".to_string(),
        fields: vec![
            ("headers".to_string(), Value::Array(header_values)),
            ("rows".to_string(), Value::Array(row_values)),
            ("confidence".to_string(), Value::Float(confidence)),
        ],
    }
}
