//! Standard library: `tallow.pdf` — PDF text extraction.
//!
//! Uses `pdftotext` CLI (poppler-utils) for extraction, with metadata
//! parsing from the PDF binary header.

use super::StdlibResult;
use crate::interp::{type_name, Value};
use std::process::{Command, Stdio};

/// Dispatch static function calls: pdf.pdf_extract_text, pdf.pdf_count_pages
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "pdf_extract_text" => Some(pdf_extract_text(args)),
        "pdf_count_pages" => Some(pdf_count_pages(args)),
        _ => None,
    }
}

/// Dispatch method calls on PdfDocument, PdfPage structs.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, .. } = object else {
        return None;
    };
    match name.as_str() {
        "PdfDocument" | "PdfPage" => match method {
            _ => None,
        },
        _ => None,
    }
}

/// Extract text from all pages of a PDF document.
fn pdf_extract_text(args: Vec<Value>) -> StdlibResult {
    let pdf_data = match args.first() {
        Some(Value::Bytes(data)) => data.clone(),
        Some(other) => {
            return Err(format!(
                "pdf.pdf_extract_text: expected Bytes argument, got {}",
                type_name(other)
            ));
        }
        None => {
            return Err("pdf.pdf_extract_text: missing PDF data argument".to_string());
        }
    };

    // Write PDF data to temp file
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!("tallow_pdf_{}.pdf", std::process::id()));
    std::fs::write(&tmp_path, &pdf_data)
        .map_err(|e| format!("pdf.pdf_extract_text: failed to write temp file: {e}"))?;

    // Get page count first
    let page_count = get_page_count_inner(&tmp_path).unwrap_or(0);

    // Extract text page by page
    let mut pages: Vec<Value> = Vec::new();
    for page_num in 1..=page_count {
        let output = Command::new("pdftotext")
            .arg("-f")
            .arg(page_num.to_string())
            .arg("-l")
            .arg(page_num.to_string())
            .arg("-layout")
            .arg(&tmp_path)
            .arg("-")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match output {
            Ok(out) => {
                let page_text = String::from_utf8_lossy(&out.stdout).to_string();
                pages.push(Value::Struct {
                    name: "PdfPage".to_string(),
                    fields: vec![
                        ("page_number".to_string(), Value::Int(page_num as i128)),
                        ("text".to_string(), Value::String(page_text)),
                        ("images".to_string(), Value::Array(vec![])), // images not extracted
                    ],
                });
            }
            Err(_) => {
                // If page extraction fails, add empty page
                pages.push(Value::Struct {
                    name: "PdfPage".to_string(),
                    fields: vec![
                        ("page_number".to_string(), Value::Int(page_num as i128)),
                        ("text".to_string(), Value::String(String::new())),
                        ("images".to_string(), Value::Array(vec![])),
                    ],
                });
            }
        }
    }

    // Parse metadata from PDF header
    let metadata = parse_pdf_metadata(&pdf_data);

    // Clean up
    let _ = std::fs::remove_file(&tmp_path);

    Ok(Value::Struct {
        name: "PdfDocument".to_string(),
        fields: vec![
            ("pages".to_string(), Value::Array(pages)),
            ("page_count".to_string(), Value::Int(page_count as i128)),
            ("metadata".to_string(), metadata),
        ],
    })
}

/// Count pages in a PDF document.
fn pdf_count_pages(args: Vec<Value>) -> StdlibResult {
    let pdf_data = match args.first() {
        Some(Value::Bytes(data)) => data.clone(),
        Some(other) => {
            return Err(format!(
                "pdf.pdf_count_pages: expected Bytes argument, got {}",
                type_name(other)
            ));
        }
        None => {
            return Err("pdf.pdf_count_pages: missing PDF data argument".to_string());
        }
    };

    // Write PDF data to temp file
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!("tallow_pdf_count_{}.pdf", std::process::id()));
    std::fs::write(&tmp_path, &pdf_data)
        .map_err(|e| format!("pdf.pdf_count_pages: failed to write temp file: {e}"))?;

    let count = get_page_count_inner(&tmp_path).unwrap_or(0);

    let _ = std::fs::remove_file(&tmp_path);

    Ok(Value::Int(count as i128))
}

/// Get page count using pdftotext or pdfinfo.
fn get_page_count_inner(path: &std::path::Path) -> Result<i32, String> {
    // Try pdfinfo first (more reliable for page count)
    if let Ok(output) = Command::new("pdfinfo")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(val) = line.strip_prefix("Pages:") {
                    if let Ok(n) = val.trim().parse::<i32>() {
                        return Ok(n);
                    }
                }
            }
        }
    }

    // Fallback: count pages from PDF binary (count /Type /Page entries)
    // Simple heuristic: count "Page" objects in the PDF
    let data = std::fs::read(path).map_err(|e| format!("failed to read PDF: {e}"))?;
    let text = String::from_utf8_lossy(&data);
    let count = text.matches("/Type /Page").count() as i32;
    if count > 0 {
        return Ok(count);
    }
    let count2 = text.matches("/Type/Page").count() as i32;
    if count2 > 0 {
        return Ok(count2);
    }

    Ok(1) // Assume at least 1 page
}

/// Parse basic metadata from PDF binary.
fn parse_pdf_metadata(data: &[u8]) -> Value {
    let mut entries: Vec<(Value, Value)> = Vec::new();
    let text = String::from_utf8_lossy(data);

    // PDF version from header
    if let Some(ver) = text.lines().next() {
        if ver.starts_with("%PDF-") {
            entries.push((Value::String("version".to_string()), Value::String(ver.to_string())));
        }
    }

    // Title
    if let Some(title) = extract_pdf_meta_field(&text, "/Title") {
        entries.push((Value::String("title".to_string()), Value::String(title)));
    }

    // Author
    if let Some(author) = extract_pdf_meta_field(&text, "/Author") {
        entries.push((Value::String("author".to_string()), Value::String(author)));
    }

    // Subject
    if let Some(subject) = extract_pdf_meta_field(&text, "/Subject") {
        entries.push((Value::String("subject".to_string()), Value::String(subject)));
    }

    // Creator
    if let Some(creator) = extract_pdf_meta_field(&text, "/Creator") {
        entries.push((Value::String("creator".to_string()), Value::String(creator)));
    }

    // Producer
    if let Some(producer) = extract_pdf_meta_field(&text, "/Producer") {
        entries.push((Value::String("producer".to_string()), Value::String(producer)));
    }

    // Creation date
    if let Some(date) = extract_pdf_meta_field(&text, "/CreationDate") {
        entries.push((Value::String("creation_date".to_string()), Value::String(date)));
    }

    Value::Map(entries)
}

/// Extract a PDF metadata field value. Handles both plain and parenthesized values.
fn extract_pdf_meta_field(text: &str, field: &str) -> Option<String> {
    // Find the field
    let pos = text.find(field)?;
    let after = &text[pos + field.len()..];

    // Skip whitespace
    let after = after.trim_start();

    // Check for parenthesized string
    if after.starts_with('(') {
        let mut depth = 1u32;
        let mut end = 1usize;
        for (i, ch) in after.char_indices().skip(1) {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                '\\' => {
                    // Skip escaped char
                }
                _ => {}
            }
        }
        return Some(after[1..end].to_string());
    }

    // Check for hex string
    if after.starts_with('<') {
        if let Some(end) = after.find('>') {
            return Some(after[..=end].to_string());
        }
    }

    // Plain token (up to whitespace or delimiter)
    let end = after
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(after.len());
    if end > 0 {
        Some(after[..end].to_string())
    } else {
        None
    }
}
