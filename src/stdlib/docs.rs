//! Document generator — Excel (.xlsx) and Word (.docx) from Tallow data.
//! Uses ZIP + XML (no external office libraries needed).
//!
//! Both XLSX and DOCX are ZIP archives containing XML files conforming to
//! the Office Open XML (OOXML) standard (ECMA-376 / ISO/IEC 29500).

use super::StdlibResult;
use crate::interp::Value;

use std::collections::HashMap;
use std::io::{Cursor, Write as IoWrite};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

// ═══════════════════════════════════════════════════════════════════════════
// XML escaping
// ═══════════════════════════════════════════════════════════════════════════

/// Escape XML special characters in text content.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// Column reference helper (A, B, ..., Z, AA, AB, ...)
// ═══════════════════════════════════════════════════════════════════════════

/// Convert a 0-based column index to an Excel column reference (A, B, ..., Z, AA, AB, ...).
pub fn col_ref(index: usize) -> String {
    let mut result = String::new();
    let mut n = index;
    loop {
        result.insert(0, (b'A' + (n % 26) as u8) as char);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    result
}

/// Convert a 0-based (row, col) pair to an Excel cell reference like "A1", "BC42".
fn cell_ref(row: usize, col: usize) -> String {
    format!("{}{}", col_ref(col), row + 1)
}

/// Parse a cell reference like "A1" into 0-based (row, col).
fn parse_cell_ref(cell: &str) -> Option<(usize, usize)> {
    let mut col_str = String::new();
    let mut row_str = String::new();
    for c in cell.chars() {
        if c.is_ascii_alphabetic() {
            col_str.push(c.to_ascii_uppercase());
        } else if c.is_ascii_digit() {
            row_str.push(c);
        }
    }
    if col_str.is_empty() || row_str.is_empty() {
        return None;
    }
    let mut col: usize = 0;
    for c in col_str.chars() {
        col = col * 26 + (c as usize - 'A' as usize + 1);
    }
    col -= 1; // 0-based
    let row = row_str.parse::<usize>().ok()? - 1; // 0-based
    Some((row, col))
}

// ═══════════════════════════════════════════════════════════════════════════
// Part 1: Excel (.xlsx) Generator
// ═══════════════════════════════════════════════════════════════════════════

/// Cell formatting options for Excel cells.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct CellFormat {
    pub bold: bool,
    pub font_size: Option<u16>,       // in points (11 default)
    pub font_color: Option<String>,   // hex "FF0000" for red
    pub font_name: Option<String>,    // "Arial", "Calibri", etc.
    pub bg_color: Option<String>,     // hex "FFFF00" for yellow
    pub alignment: Option<String>,    // "left", "center", "right"
    pub wrap_text: bool,
    pub number_format: Option<String>, // "$#,##0.00", "0%", "MM/DD/YYYY"
    pub border: Option<String>,       // "thin", "thick", "double", "dashed"
}

/// A single cell value in an Excel spreadsheet.
#[derive(Debug, Clone)]
pub enum ExcelCell {
    Text(String),
    Number(f64),
    Integer(i64),
    Bool(bool),
    Empty,
    /// A formula cell. Excel evaluates the formula when the file opens.
    /// The cached value is always 0.
    Formula(String),
    /// A date cell. The string should be in ISO format (YYYY-MM-DD).
    /// Stored as an Excel serial date number.
    Date(String),
    /// A hyperlink cell: (display_text, url).
    Hyperlink(String, String),
}

/// A single worksheet within an Excel workbook.
#[derive(Debug, Clone)]
pub struct ExcelSheet {
    pub name: String,
    pub rows: Vec<Vec<ExcelCell>>,
    /// Row indices that should use the bold (header) style.
    header_rows: Vec<usize>,
    /// Per-cell formatting: (row, col) -> CellFormat
    pub cell_formats: Vec<((usize, usize), CellFormat)>,
    /// Column widths: (col_index, width)
    pub col_widths: Vec<(usize, f64)>,
    /// Row heights: (row_index, height)
    pub row_heights: Vec<(usize, f64)>,
    /// Freeze panes: freeze rows above this row index
    pub freeze_row: Option<usize>,
    /// Freeze panes: freeze columns left of this col index
    pub freeze_col: Option<usize>,
    /// Merged cell ranges: (start_ref, end_ref) e.g. ("A1", "C1")
    pub merges: Vec<(String, String)>,
    /// Auto-filter range e.g. "A1:F100"
    pub auto_filter: Option<String>,
    /// Hyperlinks: (cell_ref, url)
    pub hyperlinks: Vec<(String, String)>,
}

/// An Excel workbook containing one or more sheets.
#[derive(Debug, Clone)]
pub struct ExcelWorkbook {
    pub sheets: Vec<ExcelSheet>,
}

impl ExcelSheet {
    pub fn new(name: &str) -> Self {
        ExcelSheet {
            name: name.to_string(),
            rows: Vec::new(),
            header_rows: Vec::new(),
            cell_formats: Vec::new(),
            col_widths: Vec::new(),
            row_heights: Vec::new(),
            freeze_row: None,
            freeze_col: None,
            merges: Vec::new(),
            auto_filter: None,
            hyperlinks: Vec::new(),
        }
    }

    /// Add a row of cells.
    pub fn add_row(&mut self, cells: Vec<ExcelCell>) {
        self.rows.push(cells);
    }

    /// Add a header row (bold style). Convenience wrapper that adds a row of
    /// `ExcelCell::Text` values and marks the row as bold.
    pub fn add_header(&mut self, headers: &[&str]) {
        let idx = self.rows.len();
        self.rows
            .push(headers.iter().map(|h| ExcelCell::Text(h.to_string())).collect());
        self.header_rows.push(idx);
    }

    /// Number of rows in this sheet.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Maximum number of columns across all rows.
    pub fn col_count(&self) -> usize {
        self.rows.iter().map(|r| r.len()).max().unwrap_or(0)
    }

    /// Set formatting for a specific cell.
    pub fn set_cell_format(&mut self, row: usize, col: usize, fmt: CellFormat) {
        // Remove existing format for this cell if any
        self.cell_formats.retain(|((r, c), _)| !(*r == row && *c == col));
        self.cell_formats.push(((row, col), fmt));
    }

    /// Add a formula at a specific row and column.
    pub fn add_formula(&mut self, row: usize, col: usize, formula: &str) {
        // Ensure we have enough rows
        while self.rows.len() <= row {
            self.rows.push(Vec::new());
        }
        // Ensure the row has enough columns
        while self.rows[row].len() <= col {
            self.rows[row].push(ExcelCell::Empty);
        }
        self.rows[row][col] = ExcelCell::Formula(formula.to_string());
    }

    /// Set a cell formula by cell reference (e.g., "A3" = "SUM(A1:A2)").
    pub fn set_cell_formula(&mut self, cell: &str, formula: &str) {
        if let Some((row, col)) = parse_cell_ref(cell) {
            self.add_formula(row, col, formula);
        }
    }
}

impl ExcelWorkbook {
    pub fn new() -> Self {
        ExcelWorkbook { sheets: Vec::new() }
    }

    /// Add a new sheet and return a mutable reference to it.
    pub fn add_sheet(&mut self, name: &str) -> &mut ExcelSheet {
        self.sheets.push(ExcelSheet::new(name));
        self.sheets.last_mut().unwrap()
    }

    /// Save the workbook to a file.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let bytes = self.to_bytes()?;
        std::fs::write(path, bytes).map_err(|e| format!("docs.excel_save: {e}"))
    }

    /// Generate the XLSX file as an in-memory byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let buf = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(buf);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        // Collect shared strings across all sheets.
        let mut shared_strings: Vec<String> = Vec::new();
        let mut string_index = std::collections::HashMap::<String, usize>::new();

        for sheet in &self.sheets {
            for row in &sheet.rows {
                for cell in row {
                    match cell {
                        ExcelCell::Text(s) => {
                            if !string_index.contains_key(s) {
                                string_index.insert(s.clone(), shared_strings.len());
                                shared_strings.push(s.clone());
                            }
                        }
                        ExcelCell::Hyperlink(text, _) => {
                            if !string_index.contains_key(text) {
                                string_index.insert(text.clone(), shared_strings.len());
                                shared_strings.push(text.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // ── Build dynamic styles ──
        // Collect all unique CellFormat combinations used across all sheets.
        let mut format_registry: Vec<CellFormat> = Vec::new();
        // Map from (sheet_idx, row, col) -> style index
        let mut cell_style_map = std::collections::HashMap::<(usize, usize, usize), usize>::new();

        // Style 0: Normal, Style 1: Bold (header)
        // Custom styles start at index 2.

        // Also collect unique number formats. Built-in format IDs:
        // 0 = General, 1 = "0", 2 = "0.00", 3 = "#,##0", 4 = "#,##0.00",
        // 9 = "0%", 10 = "0.00%", 14 = "MM/DD/YYYY", 11 = "0.00E+00"
        // Custom formats start at 164.
        let mut custom_num_fmts: Vec<String> = Vec::new();
        let mut num_fmt_map = std::collections::HashMap::<String, u32>::new();

        // Pre-register built-in number formats
        let builtin_fmts: &[(&str, u32)] = &[
            ("0", 1),
            ("0.00", 2),
            ("#,##0", 3),
            ("#,##0.00", 4),
            ("$#,##0.00", 4), // close enough to built-in 4
            ("0%", 9),
            ("0.00%", 10),
            ("0.00E+00", 11),
            ("MM/DD/YYYY", 14),
            ("mm/dd/yyyy", 14),
        ];
        for (fmt_str, id) in builtin_fmts {
            num_fmt_map.insert(fmt_str.to_string(), *id);
        }

        // Date format for Date cells
        let _date_num_fmt_id: u32 = 14; // MM/DD/YYYY built-in

        for (si, sheet) in self.sheets.iter().enumerate() {
            for &((row, col), ref fmt) in &sheet.cell_formats {
                // Register number format if custom
                if let Some(ref nf) = fmt.number_format {
                    if !num_fmt_map.contains_key(nf) {
                        let id = 164 + custom_num_fmts.len() as u32;
                        num_fmt_map.insert(nf.clone(), id);
                        custom_num_fmts.push(nf.clone());
                    }
                }
                // Find or insert format
                let pos = format_registry.iter().position(|f| f == fmt);
                let idx = match pos {
                    Some(i) => i + 2, // offset by 2 (Normal + Bold)
                    None => {
                        format_registry.push(fmt.clone());
                        format_registry.len() + 1 // offset by 2, but len is already +1
                    }
                };
                cell_style_map.insert((si, row, col), idx);
            }
        }

        // ── [Content_Types].xml ──
        let mut ct = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
             <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
             <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
             <Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>\
             <Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>\
             <Override PartName=\"/xl/sharedStrings.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml\"/>"
        );
        for (i, _) in self.sheets.iter().enumerate() {
            ct.push_str(&format!(
                "<Override PartName=\"/xl/worksheets/sheet{}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>",
                i + 1
            ));
        }
        ct.push_str("</Types>");

        zip.start_file("[Content_Types].xml", opts)
            .map_err(|e| format!("docs.xlsx: zip error: {e}"))?;
        zip.write_all(ct.as_bytes())
            .map_err(|e| format!("docs.xlsx: write error: {e}"))?;

        // ── _rels/.rels ──
        let rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>\
            </Relationships>";

        zip.start_file("_rels/.rels", opts)
            .map_err(|e| format!("docs.xlsx: zip error: {e}"))?;
        zip.write_all(rels.as_bytes())
            .map_err(|e| format!("docs.xlsx: write error: {e}"))?;

        // ── xl/_rels/workbook.xml.rels ──
        let mut wb_rels = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        );
        for (i, _) in self.sheets.iter().enumerate() {
            wb_rels.push_str(&format!(
                "<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet{}.xml\"/>",
                i + 1, i + 1
            ));
        }
        wb_rels.push_str(&format!(
            "<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>",
            self.sheets.len() + 1
        ));
        wb_rels.push_str(&format!(
            "<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings\" Target=\"sharedStrings.xml\"/>",
            self.sheets.len() + 2
        ));
        wb_rels.push_str("</Relationships>");

        zip.start_file("xl/_rels/workbook.xml.rels", opts)
            .map_err(|e| format!("docs.xlsx: zip error: {e}"))?;
        zip.write_all(wb_rels.as_bytes())
            .map_err(|e| format!("docs.xlsx: write error: {e}"))?;

        // ── xl/workbook.xml ──
        let mut wb = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" \
             xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">\
             <sheets>"
        );
        for (i, sheet) in self.sheets.iter().enumerate() {
            wb.push_str(&format!(
                "<sheet name=\"{}\" sheetId=\"{}\" r:id=\"rId{}\"/>",
                xml_escape(&sheet.name),
                i + 1,
                i + 1
            ));
        }
        wb.push_str("</sheets></workbook>");

        zip.start_file("xl/workbook.xml", opts)
            .map_err(|e| format!("docs.xlsx: zip error: {e}"))?;
        zip.write_all(wb.as_bytes())
            .map_err(|e| format!("docs.xlsx: write error: {e}"))?;

        // ── xl/styles.xml (dynamic) ──
        let styles = build_xlsx_styles(&format_registry, &custom_num_fmts, &num_fmt_map);

        zip.start_file("xl/styles.xml", opts)
            .map_err(|e| format!("docs.xlsx: zip error: {e}"))?;
        zip.write_all(styles.as_bytes())
            .map_err(|e| format!("docs.xlsx: write error: {e}"))?;

        // ── xl/sharedStrings.xml ──
        let mut ss = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" \
             count=\"{}\" uniqueCount=\"{}\">",
            shared_strings.len(),
            shared_strings.len()
        );
        for s in &shared_strings {
            ss.push_str(&format!("<si><t>{}</t></si>", xml_escape(s)));
        }
        ss.push_str("</sst>");

        zip.start_file("xl/sharedStrings.xml", opts)
            .map_err(|e| format!("docs.xlsx: zip error: {e}"))?;
        zip.write_all(ss.as_bytes())
            .map_err(|e| format!("docs.xlsx: write error: {e}"))?;

        // ── xl/worksheets/sheetN.xml + rels ──
        for (si, sheet) in self.sheets.iter().enumerate() {
            // Collect hyperlinks for this sheet (from cells + sheet.hyperlinks)
            let mut sheet_hyperlinks: Vec<(String, String)> = sheet.hyperlinks.clone();
            for (ri, row) in sheet.rows.iter().enumerate() {
                for (ci, cell) in row.iter().enumerate() {
                    if let ExcelCell::Hyperlink(_, url) = cell {
                        let cr = cell_ref(ri, ci);
                        sheet_hyperlinks.push((cr, url.clone()));
                    }
                }
            }

            // Build sheet rels if there are hyperlinks
            if !sheet_hyperlinks.is_empty() {
                let mut sheet_rels = String::from(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
                     <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
                );
                for (hi, (_, url)) in sheet_hyperlinks.iter().enumerate() {
                    sheet_rels.push_str(&format!(
                        "<Relationship Id=\"hId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"{}\" TargetMode=\"External\"/>",
                        hi + 1, xml_escape(url)
                    ));
                }
                sheet_rels.push_str("</Relationships>");

                zip.start_file(format!("xl/worksheets/_rels/sheet{}.xml.rels", si + 1), opts)
                    .map_err(|e| format!("docs.xlsx: zip error: {e}"))?;
                zip.write_all(sheet_rels.as_bytes())
                    .map_err(|e| format!("docs.xlsx: write error: {e}"))?;
            }

            // Build row height map
            let row_ht_map: std::collections::HashMap<usize, f64> =
                sheet.row_heights.iter().cloned().collect();

            let mut ws = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
                 <worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" \
                 xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">"
            );

            // ── sheetViews with freeze panes ──
            if sheet.freeze_row.is_some() || sheet.freeze_col.is_some() {
                let fr = sheet.freeze_row.unwrap_or(0);
                let fc = sheet.freeze_col.unwrap_or(0);
                let top_left = cell_ref(fr, fc);
                ws.push_str("<sheetViews><sheetView tabSelected=\"1\" workbookViewId=\"0\">");
                ws.push_str(&format!(
                    "<pane{}{}{}state=\"frozen\"/>",
                    if fc > 0 { format!(" xSplit=\"{}\"", fc) } else { String::new() },
                    if fr > 0 { format!(" ySplit=\"{}\"", fr) } else { String::new() },
                    format!(" topLeftCell=\"{}\" ", top_left),
                ));
                ws.push_str("</sheetView></sheetViews>");
            }

            // ── cols (column widths) ──
            if !sheet.col_widths.is_empty() {
                ws.push_str("<cols>");
                for &(col_idx, width) in &sheet.col_widths {
                    let col_num = col_idx + 1; // 1-based
                    ws.push_str(&format!(
                        "<col min=\"{}\" max=\"{}\" width=\"{:.2}\" customWidth=\"1\"/>",
                        col_num, col_num, width
                    ));
                }
                ws.push_str("</cols>");
            }

            ws.push_str("<sheetData>");

            for (ri, row) in sheet.rows.iter().enumerate() {
                // Check for custom row height
                if let Some(&ht) = row_ht_map.get(&ri) {
                    ws.push_str(&format!(
                        "<row r=\"{}\" ht=\"{:.2}\" customHeight=\"1\">",
                        ri + 1, ht
                    ));
                } else {
                    ws.push_str(&format!("<row r=\"{}\">", ri + 1));
                }

                let is_header = sheet.header_rows.contains(&ri);

                for (ci, cell) in row.iter().enumerate() {
                    let cr = cell_ref(ri, ci);

                    // Determine style: check cell_style_map first, then header
                    let style_id = if let Some(&sid) = cell_style_map.get(&(si, ri, ci)) {
                        sid
                    } else if is_header {
                        1
                    } else {
                        // Check if this is a Date cell — needs date format style
                        if matches!(cell, ExcelCell::Date(_)) {
                            // Find or create a date style — we'll use a special index
                            // The date style is always the last format_registry entry + 2
                            // Actually, we need a dedicated style for date cells.
                            // We'll handle this below when emitting — use numFmtId=14 inline
                            // For now, style 0 and we rely on the date num fmt.
                            0
                        } else {
                            0
                        }
                    };

                    let style_attr = if style_id > 0 {
                        format!(" s=\"{}\"", style_id)
                    } else {
                        String::new()
                    };

                    match cell {
                        ExcelCell::Text(s) => {
                            let idx = string_index[s];
                            ws.push_str(&format!(
                                "<c r=\"{}\" t=\"s\"{}><v>{}</v></c>",
                                cr, style_attr, idx
                            ));
                        }
                        ExcelCell::Number(n) => {
                            ws.push_str(&format!(
                                "<c r=\"{}\"{}><v>{}</v></c>",
                                cr, style_attr, n
                            ));
                        }
                        ExcelCell::Integer(n) => {
                            ws.push_str(&format!(
                                "<c r=\"{}\"{}><v>{}</v></c>",
                                cr, style_attr, n
                            ));
                        }
                        ExcelCell::Bool(b) => {
                            ws.push_str(&format!(
                                "<c r=\"{}\" t=\"b\"{}><v>{}</v></c>",
                                cr,
                                style_attr,
                                if *b { 1 } else { 0 }
                            ));
                        }
                        ExcelCell::Empty => {
                            // Omit empty cells entirely — Excel handles missing cells.
                        }
                        ExcelCell::Formula(formula) => {
                            // No cached value — Excel calculates on open.
                            // Omitting <v> tells Excel the formula result is unknown.
                            ws.push_str(&format!(
                                "<c r=\"{}\" t=\"str\"{}><f>{}</f></c>",
                                cr, style_attr, xml_escape(formula)
                            ));
                        }
                        ExcelCell::Date(date_str) => {
                            let serial = date_to_serial(date_str);
                            // Use date numFmtId=14 style. We need a style with numFmtId=14.
                            // Check if we have one already assigned, otherwise use inline.
                            // We add date style at a known index during style building.
                            let date_style_id = format_registry.len() + 2; // date style is appended last
                            ws.push_str(&format!(
                                "<c r=\"{}\" s=\"{}\"><v>{}</v></c>",
                                cr, date_style_id, serial
                            ));
                        }
                        ExcelCell::Hyperlink(text, _url) => {
                            let idx = string_index[text];
                            // The cell holds the display text as a shared string.
                            // The actual URL link is established by the <hyperlinks>
                            // section below, which maps this cell ref to an r:id
                            // that points to the external URL in the rels file.
                            ws.push_str(&format!(
                                "<c r=\"{}\" t=\"s\"{}><v>{}</v></c>",
                                cr, style_attr, idx
                            ));
                        }
                    }
                }

                ws.push_str("</row>");
            }

            ws.push_str("</sheetData>");

            // ── Merge cells ──
            if !sheet.merges.is_empty() {
                ws.push_str(&format!("<mergeCells count=\"{}\">", sheet.merges.len()));
                for (start, end) in &sheet.merges {
                    ws.push_str(&format!("<mergeCell ref=\"{}:{}\"/>", start, end));
                }
                ws.push_str("</mergeCells>");
            }

            // ── Auto filter ──
            if let Some(ref range) = sheet.auto_filter {
                ws.push_str(&format!("<autoFilter ref=\"{}\"/>", xml_escape(range)));
            }

            // ── Hyperlinks ──
            if !sheet_hyperlinks.is_empty() {
                ws.push_str("<hyperlinks>");
                for (hi, (cr, _)) in sheet_hyperlinks.iter().enumerate() {
                    ws.push_str(&format!(
                        "<hyperlink ref=\"{}\" r:id=\"hId{}\"/>",
                        cr, hi + 1
                    ));
                }
                ws.push_str("</hyperlinks>");
            }

            ws.push_str("</worksheet>");

            zip.start_file(format!("xl/worksheets/sheet{}.xml", si + 1), opts)
                .map_err(|e| format!("docs.xlsx: zip error: {e}"))?;
            zip.write_all(ws.as_bytes())
                .map_err(|e| format!("docs.xlsx: write error: {e}"))?;
        }

        let cursor = zip
            .finish()
            .map_err(|e| format!("docs.xlsx: zip finish error: {e}"))?;
        Ok(cursor.into_inner())
    }
}

/// Convert an ISO date string (YYYY-MM-DD) to an Excel serial date number.
/// Excel serial date: 1 = 1900-01-01, with the Lotus 1-2-3 leap year bug
/// (1900 is treated as a leap year, so dates from 1900-03-01 onward are offset by 1).
fn date_to_serial(date_str: &str) -> i64 {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return 0;
    }
    let year: i64 = parts[0].parse().unwrap_or(1900);
    let month: i64 = parts[1].parse().unwrap_or(1);
    let day: i64 = parts[2].parse().unwrap_or(1);

    // Calculate days from 1900-01-01 using a simplified algorithm
    // This handles the Excel leap year bug (Feb 29, 1900 doesn't exist but Excel counts it)
    let mut serial: i64 = 0;

    // Years
    for y in 1900..year {
        if is_leap_year(y) {
            serial += 366;
        } else {
            serial += 365;
        }
    }

    // Months in current year
    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        serial += days_in_month[(m - 1) as usize] as i64;
        if m == 2 && is_leap_year(year) {
            serial += 1;
        }
    }

    // Days
    serial += day;

    // Excel Lotus bug: add 1 for dates after Feb 28, 1900
    if serial > 59 {
        serial += 1;
    }

    serial
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Build a dynamic styles.xml for Excel based on the formats used.
fn build_xlsx_styles(
    format_registry: &[CellFormat],
    custom_num_fmts: &[String],
    num_fmt_map: &std::collections::HashMap<String, u32>,
) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
    );

    // ── numFmts (custom number formats) ──
    if !custom_num_fmts.is_empty() {
        s.push_str(&format!("<numFmts count=\"{}\">", custom_num_fmts.len()));
        for nf in custom_num_fmts {
            let id = num_fmt_map[nf];
            s.push_str(&format!(
                "<numFmt numFmtId=\"{}\" formatCode=\"{}\"/>",
                id, xml_escape(nf)
            ));
        }
        s.push_str("</numFmts>");
    }

    // ── fonts ──
    // Font 0: Normal (Calibri 11)
    // Font 1: Bold (Calibri 11)
    // Fonts 2+: custom fonts from format_registry
    let mut fonts_xml = Vec::new();
    fonts_xml.push("<font><sz val=\"11\"/><name val=\"Calibri\"/></font>".to_string());
    fonts_xml.push("<font><b/><sz val=\"11\"/><name val=\"Calibri\"/></font>".to_string());

    // Track which fonts we've already added to dedup
    let mut font_idx_map: Vec<usize> = Vec::new(); // for each format in registry, which font index

    for fmt in format_registry {
        let font_size = fmt.font_size.unwrap_or(11);
        let font_name = fmt.font_name.as_deref().unwrap_or("Calibri");
        let mut font_xml = String::from("<font>");
        if fmt.bold {
            font_xml.push_str("<b/>");
        }
        font_xml.push_str(&format!("<sz val=\"{}\"/>", font_size));
        if let Some(ref color) = fmt.font_color {
            font_xml.push_str(&format!("<color rgb=\"FF{}\"/>", color));
        }
        font_xml.push_str(&format!("<name val=\"{}\"/>", xml_escape(font_name)));
        font_xml.push_str("</font>");

        // Check if this font already exists
        if let Some(pos) = fonts_xml.iter().position(|f| f == &font_xml) {
            font_idx_map.push(pos);
        } else {
            font_idx_map.push(fonts_xml.len());
            fonts_xml.push(font_xml);
        }
    }

    s.push_str(&format!("<fonts count=\"{}\">", fonts_xml.len()));
    for f in &fonts_xml {
        s.push_str(f);
    }
    s.push_str("</fonts>");

    // ── fills ──
    // Fill 0: none, Fill 1: gray125 (required by Excel)
    // Fills 2+: custom bg colors
    let mut fills_xml = Vec::new();
    fills_xml.push("<fill><patternFill patternType=\"none\"/></fill>".to_string());
    fills_xml.push("<fill><patternFill patternType=\"gray125\"/></fill>".to_string());

    let mut fill_idx_map: Vec<usize> = Vec::new();

    for fmt in format_registry {
        if let Some(ref bg) = fmt.bg_color {
            let fill_xml = format!(
                "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF{}\"/></patternFill></fill>",
                bg
            );
            if let Some(pos) = fills_xml.iter().position(|f| f == &fill_xml) {
                fill_idx_map.push(pos);
            } else {
                fill_idx_map.push(fills_xml.len());
                fills_xml.push(fill_xml);
            }
        } else {
            fill_idx_map.push(0);
        }
    }

    s.push_str(&format!("<fills count=\"{}\">", fills_xml.len()));
    for f in &fills_xml {
        s.push_str(f);
    }
    s.push_str("</fills>");

    // ── borders ──
    // Border 0: none
    // Borders 1+: custom borders
    let mut borders_xml = Vec::new();
    borders_xml.push("<border><left/><right/><top/><bottom/><diagonal/></border>".to_string());

    let mut border_idx_map: Vec<usize> = Vec::new();

    for fmt in format_registry {
        if let Some(ref border_style) = fmt.border {
            let bs = match border_style.as_str() {
                "thick" => "thick",
                "double" => "double",
                "dashed" => "dashed",
                "thin" | _ => "thin",
            };
            let border_xml = format!(
                "<border>\
                 <left style=\"{bs}\"><color auto=\"1\"/></left>\
                 <right style=\"{bs}\"><color auto=\"1\"/></right>\
                 <top style=\"{bs}\"><color auto=\"1\"/></top>\
                 <bottom style=\"{bs}\"><color auto=\"1\"/></bottom>\
                 <diagonal/></border>"
            );
            if let Some(pos) = borders_xml.iter().position(|b| b == &border_xml) {
                border_idx_map.push(pos);
            } else {
                border_idx_map.push(borders_xml.len());
                borders_xml.push(border_xml);
            }
        } else {
            border_idx_map.push(0);
        }
    }

    s.push_str(&format!("<borders count=\"{}\">", borders_xml.len()));
    for b in &borders_xml {
        s.push_str(b);
    }
    s.push_str("</borders>");

    // ── cellStyleXfs ──
    s.push_str(
        "<cellStyleXfs count=\"1\">\
         <xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/>\
         </cellStyleXfs>"
    );

    // ── cellXfs ──
    // xf 0: Normal
    // xf 1: Bold (header)
    // xf 2+: custom formats
    // xf last: date format
    let total_xf = 2 + format_registry.len() + 1; // +1 for date style
    s.push_str(&format!("<cellXfs count=\"{}\">", total_xf));

    // xf 0: Normal
    s.push_str("<xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>");
    // xf 1: Bold (header)
    s.push_str("<xf numFmtId=\"0\" fontId=\"1\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyFont=\"1\"/>");

    // xf 2+: custom formats
    for (i, fmt) in format_registry.iter().enumerate() {
        let font_id = font_idx_map[i];
        let fill_id = fill_idx_map[i];
        let border_id = border_idx_map[i];
        let num_fmt_id = fmt.number_format.as_ref()
            .and_then(|nf| num_fmt_map.get(nf))
            .copied()
            .unwrap_or(0);

        let mut apply_attrs = String::new();
        if font_id > 0 || fmt.bold || fmt.font_size.is_some() || fmt.font_color.is_some() || fmt.font_name.is_some() {
            apply_attrs.push_str(" applyFont=\"1\"");
        }
        if fill_id > 0 {
            apply_attrs.push_str(" applyFill=\"1\"");
        }
        if border_id > 0 {
            apply_attrs.push_str(" applyBorder=\"1\"");
        }
        if num_fmt_id > 0 {
            apply_attrs.push_str(" applyNumberFormat=\"1\"");
        }
        if fmt.alignment.is_some() || fmt.wrap_text {
            apply_attrs.push_str(" applyAlignment=\"1\"");
        }

        if fmt.alignment.is_some() || fmt.wrap_text {
            let mut align_attrs = String::new();
            if let Some(ref align) = fmt.alignment {
                align_attrs.push_str(&format!(" horizontal=\"{}\"", align));
            }
            if fmt.wrap_text {
                align_attrs.push_str(" wrapText=\"1\"");
            }
            s.push_str(&format!(
                "<xf numFmtId=\"{}\" fontId=\"{}\" fillId=\"{}\" borderId=\"{}\" xfId=\"0\"{}>\
                 <alignment{}/></xf>",
                num_fmt_id, font_id, fill_id, border_id, apply_attrs, align_attrs
            ));
        } else {
            s.push_str(&format!(
                "<xf numFmtId=\"{}\" fontId=\"{}\" fillId=\"{}\" borderId=\"{}\" xfId=\"0\"{}/>\n",
                num_fmt_id, font_id, fill_id, border_id, apply_attrs
            ));
        }
    }

    // Date style (always last xf)
    s.push_str(&format!(
        "<xf numFmtId=\"{}\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyNumberFormat=\"1\"/>",
        14 // MM/DD/YYYY built-in
    ));

    s.push_str("</cellXfs>");
    s.push_str("</styleSheet>");
    s
}

// ── Excel convenience functions ──

/// Create an Excel workbook from CSV content.
///
/// Parses comma-separated values and puts them into a single sheet. Numeric
/// values are stored as numbers; everything else as text.
pub fn create_excel_from_csv(csv_content: &str, sheet_name: &str) -> Result<Vec<u8>, String> {
    let mut wb = ExcelWorkbook::new();
    let sheet = wb.add_sheet(sheet_name);

    for line in csv_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let cells: Vec<ExcelCell> = parse_csv_line(line)
            .into_iter()
            .map(|field| {
                let trimmed = field.trim();
                if trimmed.is_empty() {
                    ExcelCell::Empty
                } else if let Ok(i) = trimmed.parse::<i64>() {
                    ExcelCell::Integer(i)
                } else if let Ok(f) = trimmed.parse::<f64>() {
                    ExcelCell::Number(f)
                } else if trimmed.eq_ignore_ascii_case("true") || trimmed.eq_ignore_ascii_case("false") {
                    ExcelCell::Bool(trimmed.eq_ignore_ascii_case("true"))
                } else {
                    ExcelCell::Text(field.to_string())
                }
            })
            .collect();
        sheet.add_row(cells);
    }

    wb.to_bytes()
}

/// Parse a single CSV line, respecting quoted fields.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    // Escaped quote
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    fields.push(std::mem::take(&mut current));
                }
                _ => current.push(c),
            }
        }
    }
    fields.push(current);
    fields
}

/// Create an Excel workbook from a JSON array of objects.
///
/// Each object becomes a row. Keys from the first object become column headers.
pub fn create_excel_from_json(json_array: &str, sheet_name: &str) -> Result<Vec<u8>, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(json_array).map_err(|e| format!("docs.json_to_excel: {e}"))?;

    let arr = parsed
        .as_array()
        .ok_or_else(|| "docs.json_to_excel: input must be a JSON array".to_string())?;

    if arr.is_empty() {
        let mut wb = ExcelWorkbook::new();
        wb.add_sheet(sheet_name);
        return wb.to_bytes();
    }

    // Collect all keys from the first object to use as headers.
    let headers: Vec<String> = if let Some(obj) = arr[0].as_object() {
        obj.keys().cloned().collect()
    } else {
        return Err("docs.json_to_excel: array elements must be objects".to_string());
    };

    let mut wb = ExcelWorkbook::new();
    let sheet = wb.add_sheet(sheet_name);

    let header_refs: Vec<&str> = headers.iter().map(|s| s.as_str()).collect();
    sheet.add_header(&header_refs);

    for item in arr {
        let obj = item
            .as_object()
            .ok_or_else(|| "docs.json_to_excel: all elements must be objects".to_string())?;
        let cells: Vec<ExcelCell> = headers
            .iter()
            .map(|key| match obj.get(key) {
                None | Some(serde_json::Value::Null) => ExcelCell::Empty,
                Some(serde_json::Value::Bool(b)) => ExcelCell::Bool(*b),
                Some(serde_json::Value::Number(n)) => {
                    if let Some(i) = n.as_i64() {
                        ExcelCell::Integer(i)
                    } else if let Some(f) = n.as_f64() {
                        ExcelCell::Number(f)
                    } else {
                        ExcelCell::Text(n.to_string())
                    }
                }
                Some(serde_json::Value::String(s)) => ExcelCell::Text(s.clone()),
                Some(other) => ExcelCell::Text(other.to_string()),
            })
            .collect();
        sheet.add_row(cells);
    }

    wb.to_bytes()
}

/// Create a multi-section Excel report.
///
/// Each section becomes a block with a title row followed by the section's data
/// rows, all within a single sheet called "Report".
pub fn create_excel_report(
    title: &str,
    sections: &[(String, Vec<Vec<String>>)],
) -> Result<Vec<u8>, String> {
    let mut wb = ExcelWorkbook::new();
    let sheet = wb.add_sheet("Report");

    // Title row
    sheet.add_header(&[title]);
    // Blank row
    sheet.add_row(vec![ExcelCell::Empty]);

    for (section_title, rows) in sections {
        // Section header
        sheet.add_header(&[section_title.as_str()]);
        for row in rows {
            let cells: Vec<ExcelCell> = row.iter().map(|s| ExcelCell::Text(s.clone())).collect();
            sheet.add_row(cells);
        }
        // Blank separator row
        sheet.add_row(vec![ExcelCell::Empty]);
    }

    wb.to_bytes()
}

// ═══════════════════════════════════════════════════════════════════════════
// Report Template Data Types
// ═══════════════════════════════════════════════════════════════════════════

/// A product with prices across multiple stores, for price comparison reports.
#[derive(Debug, Clone)]
pub struct PriceProduct {
    pub name: String,
    pub category: String,
    pub brand: String,
    pub prices: HashMap<String, f64>, // store_name -> price
}

/// A product for catalog export.
#[derive(Debug, Clone)]
pub struct CatalogProduct {
    pub name: String,
    pub brand: String,
    pub category: String,
    pub price: f64,
    pub unit_price: Option<f64>,
    pub size: String,
    pub upc: String,
    pub snap_eligible: bool,
    pub store: String,
}

/// A section in a competitive intelligence report.
#[derive(Debug, Clone)]
pub struct IntelSection {
    pub title: String,
    pub content: String,
    pub table: Option<(Vec<String>, Vec<Vec<String>>)>, // (headers, rows)
}

/// Statistics for a product category.
#[derive(Debug, Clone)]
pub struct CategoryStats {
    pub name: String,
    pub product_count: usize,
    pub avg_price: f64,
    pub min_price: f64,
    pub max_price: f64,
    pub median_price: f64,
}

/// Data for a market research report.
#[derive(Debug, Clone)]
pub struct MarketReportData {
    pub title: String,
    pub date_range: String,
    pub methodology: String,
    pub stores: Vec<String>,
    pub total_products: usize,
    pub categories: Vec<CategoryStats>,
    pub findings: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Report Template: Price Comparison (Excel)
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a price comparison Excel report.
///
/// Creates a Summary sheet and one sheet per product category. Each category
/// sheet lists products with per-store prices, best price, and savings %.
/// Cheapest prices are highlighted green/bold, most expensive in red.
pub fn create_price_comparison_report(
    path: &str,
    title: &str,
    stores: &[String],
    products: &[PriceProduct],
) -> Result<(), String> {
    let mut wb = ExcelWorkbook::new();
    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // ── Compute summary stats ──
    let mut store_totals: HashMap<String, (f64, usize)> = HashMap::new(); // sum, count
    for p in products {
        for (store, price) in &p.prices {
            let entry = store_totals.entry(store.clone()).or_insert((0.0, 0));
            entry.0 += price;
            entry.1 += 1;
        }
    }

    let cheapest_store = store_totals
        .iter()
        .filter(|(_, (_, c))| *c > 0)
        .min_by(|(_, (sa, ca)), (_, (sb, cb))| {
            let avg_a = sa / *ca as f64;
            let avg_b = sb / *cb as f64;
            avg_a.partial_cmp(&avg_b).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(name, _)| name.clone())
        .unwrap_or_else(|| "N/A".to_string());

    let most_expensive_store = store_totals
        .iter()
        .filter(|(_, (_, c))| *c > 0)
        .max_by(|(_, (sa, ca)), (_, (sb, cb))| {
            let avg_a = sa / *ca as f64;
            let avg_b = sb / *cb as f64;
            avg_a.partial_cmp(&avg_b).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(name, _)| name.clone())
        .unwrap_or_else(|| "N/A".to_string());

    // Collect unique categories
    let mut categories: Vec<String> = Vec::new();
    {
        let mut seen = std::collections::HashSet::new();
        for p in products {
            if seen.insert(p.category.clone()) {
                categories.push(p.category.clone());
            }
        }
    }

    // ── Summary sheet ──
    {
        let summary = wb.add_sheet("Summary");
        let header_fmt = CellFormat { bold: true, bg_color: Some("D9D9D9".to_string()), ..Default::default() };

        summary.add_row(vec![ExcelCell::Text(title.to_string())]);
        summary.set_cell_format(0, 0, CellFormat { bold: true, font_size: Some(16), ..Default::default() });
        summary.add_row(vec![ExcelCell::Empty]);

        let info_rows = [
            ("Report Date", now.as_str()),
            ("Stores Compared", &stores.len().to_string()),
            ("Total Products", &products.len().to_string()),
            ("Categories", &categories.len().to_string()),
            ("Cheapest Store (avg)", &cheapest_store),
            ("Most Expensive Store (avg)", &most_expensive_store),
        ];
        summary.add_header(&["Metric", "Value"]);
        let header_row = summary.row_count() - 1;
        summary.set_cell_format(header_row, 0, header_fmt.clone());
        summary.set_cell_format(header_row, 1, header_fmt.clone());
        summary.freeze_row = Some(header_row + 1);

        for (label, val) in &info_rows {
            summary.add_row(vec![
                ExcelCell::Text(label.to_string()),
                ExcelCell::Text(val.to_string()),
            ]);
        }

        summary.add_row(vec![ExcelCell::Empty]);
        summary.add_header(&["Store", "Products", "Avg Price"]);
        let store_header_row = summary.row_count() - 1;
        summary.set_cell_format(store_header_row, 0, header_fmt.clone());
        summary.set_cell_format(store_header_row, 1, header_fmt.clone());
        summary.set_cell_format(store_header_row, 2, header_fmt.clone());

        for store in stores {
            let (total, count) = store_totals.get(store).copied().unwrap_or((0.0, 0));
            let avg = if count > 0 { total / count as f64 } else { 0.0 };
            summary.add_row(vec![
                ExcelCell::Text(store.clone()),
                ExcelCell::Integer(count as i64),
                ExcelCell::Number((avg * 100.0).round() / 100.0),
            ]);
            let r = summary.row_count() - 1;
            summary.set_cell_format(r, 2, CellFormat { number_format: Some("$#,##0.00".to_string()), ..Default::default() });
        }

        summary.col_widths.push((0, 30.0));
        summary.col_widths.push((1, 15.0));
        summary.col_widths.push((2, 15.0));
    }

    // ── Per-category sheets ──
    for cat in &categories {
        let cat_products: Vec<&PriceProduct> = products.iter().filter(|p| p.category == *cat).collect();
        // Truncate sheet name to 31 chars (Excel limit)
        let sheet_name = if cat.len() > 31 { &cat[..31] } else { cat.as_str() };
        let sheet = wb.add_sheet(sheet_name);

        let header_fmt = CellFormat { bold: true, bg_color: Some("D9D9D9".to_string()), ..Default::default() };
        let price_fmt = CellFormat { number_format: Some("$#,##0.00".to_string()), ..Default::default() };
        let green_fmt = CellFormat { bold: true, font_color: Some("006100".to_string()), bg_color: Some("C6EFCE".to_string()), number_format: Some("$#,##0.00".to_string()), ..Default::default() };
        let red_fmt = CellFormat { font_color: Some("9C0006".to_string()), bg_color: Some("FFC7CE".to_string()), number_format: Some("$#,##0.00".to_string()), ..Default::default() };
        let pct_fmt = CellFormat { number_format: Some("0.0%".to_string()), ..Default::default() };

        // Build header: Product | Brand | Store1 | Store2 | ... | Best Price | Savings %
        let mut headers: Vec<&str> = vec!["Product", "Brand"];
        let store_refs: Vec<&str> = stores.iter().map(|s| s.as_str()).collect();
        headers.extend_from_slice(&store_refs);
        headers.push("Best Price");
        headers.push("Savings %");
        sheet.add_header(&headers);

        let header_row_idx = 0;
        for col in 0..headers.len() {
            sheet.set_cell_format(header_row_idx, col, header_fmt.clone());
        }
        sheet.freeze_row = Some(1);

        let num_store_cols = stores.len();
        let best_col = 2 + num_store_cols;
        let savings_col = best_col + 1;

        for product in &cat_products {
            let mut row_cells: Vec<ExcelCell> = vec![
                ExcelCell::Text(product.name.clone()),
                ExcelCell::Text(product.brand.clone()),
            ];

            let mut min_price = f64::MAX;
            let mut max_price = f64::MIN;
            let mut has_any = false;

            for store in stores {
                if let Some(&price) = product.prices.get(store) {
                    row_cells.push(ExcelCell::Number(price));
                    if price < min_price { min_price = price; }
                    if price > max_price { max_price = price; }
                    has_any = true;
                } else {
                    row_cells.push(ExcelCell::Empty);
                }
            }

            if has_any {
                row_cells.push(ExcelCell::Number(min_price));
                let savings = if max_price > 0.0 { (max_price - min_price) / max_price } else { 0.0 };
                row_cells.push(ExcelCell::Number(savings));
            } else {
                row_cells.push(ExcelCell::Empty);
                row_cells.push(ExcelCell::Empty);
            }

            sheet.add_row(row_cells);
            let r = sheet.row_count() - 1;

            // Format price columns
            for (si, store) in stores.iter().enumerate() {
                let col = 2 + si;
                if let Some(&price) = product.prices.get(store) {
                    if has_any && (price - min_price).abs() < 0.001 && min_price < max_price {
                        sheet.set_cell_format(r, col, green_fmt.clone());
                    } else if has_any && (price - max_price).abs() < 0.001 && min_price < max_price {
                        sheet.set_cell_format(r, col, red_fmt.clone());
                    } else {
                        sheet.set_cell_format(r, col, price_fmt.clone());
                    }
                }
            }
            if has_any {
                sheet.set_cell_format(r, best_col, green_fmt.clone());
                sheet.set_cell_format(r, savings_col, pct_fmt.clone());
            }
        }

        // Summary row with averages
        let data_start = 2; // row 1 is header (0-indexed), data starts at row 2 (1-indexed in Excel)
        let data_end = sheet.row_count(); // exclusive in Rust, but in Excel formulas it's the last data row
        if cat_products.len() > 0 {
            let mut avg_row: Vec<ExcelCell> = vec![
                ExcelCell::Text("AVERAGE".to_string()),
                ExcelCell::Empty,
            ];
            for si in 0..num_store_cols {
                let c = col_ref(2 + si);
                avg_row.push(ExcelCell::Formula(format!("AVERAGE({c}{data_start}:{c}{data_end})")));
            }
            let best_c = col_ref(best_col);
            avg_row.push(ExcelCell::Formula(format!("AVERAGE({best_c}{data_start}:{best_c}{data_end})")));
            let sav_c = col_ref(savings_col);
            avg_row.push(ExcelCell::Formula(format!("AVERAGE({sav_c}{data_start}:{sav_c}{data_end})")));
            sheet.add_row(avg_row);

            let avg_r = sheet.row_count() - 1;
            sheet.set_cell_format(avg_r, 0, CellFormat { bold: true, ..Default::default() });
            for ci in 2..(2 + num_store_cols) {
                sheet.set_cell_format(avg_r, ci, CellFormat { bold: true, number_format: Some("$#,##0.00".to_string()), ..Default::default() });
            }
            sheet.set_cell_format(avg_r, best_col, CellFormat { bold: true, number_format: Some("$#,##0.00".to_string()), ..Default::default() });
            sheet.set_cell_format(avg_r, savings_col, CellFormat { bold: true, number_format: Some("0.0%".to_string()), ..Default::default() });
        }

        // Auto-filter on all data
        let last_col = col_ref(headers.len() - 1);
        let last_row = sheet.row_count();
        sheet.auto_filter = Some(format!("A1:{last_col}{last_row}"));

        // Column widths
        sheet.col_widths.push((0, 35.0));
        sheet.col_widths.push((1, 20.0));
        for si in 0..num_store_cols {
            sheet.col_widths.push((2 + si, 14.0));
        }
        sheet.col_widths.push((best_col, 14.0));
        sheet.col_widths.push((savings_col, 12.0));
    }

    wb.save(path)
}

// ═══════════════════════════════════════════════════════════════════════════
// Report Template: Product Catalog (Excel)
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a product catalog Excel export.
///
/// Columns: Name | Brand | Category | Price | Unit Price | Size | UPC | SNAP Eligible | Store
/// Sorted by category then name, with header formatting, price number formatting,
/// auto-filter, and a summary row.
pub fn create_product_catalog(
    path: &str,
    products: &[CatalogProduct],
) -> Result<(), String> {
    let mut wb = ExcelWorkbook::new();
    let sheet = wb.add_sheet("Catalog");

    let header_fmt = CellFormat { bold: true, bg_color: Some("D9D9D9".to_string()), ..Default::default() };
    let price_fmt = CellFormat { number_format: Some("$#,##0.00".to_string()), ..Default::default() };

    let headers = ["Name", "Brand", "Category", "Price", "Unit Price", "Size", "UPC", "SNAP Eligible", "Store"];
    sheet.add_header(&headers);
    for col in 0..headers.len() {
        sheet.set_cell_format(0, col, header_fmt.clone());
    }
    sheet.freeze_row = Some(1);

    // Sort by category then name
    let mut sorted: Vec<&CatalogProduct> = products.iter().collect();
    sorted.sort_by(|a, b| {
        a.category.cmp(&b.category).then_with(|| a.name.cmp(&b.name))
    });

    let mut total_price = 0.0;
    let mut price_count = 0usize;

    for p in &sorted {
        let unit_price_cell = match p.unit_price {
            Some(up) => ExcelCell::Number(up),
            None => ExcelCell::Empty,
        };
        sheet.add_row(vec![
            ExcelCell::Text(p.name.clone()),
            ExcelCell::Text(p.brand.clone()),
            ExcelCell::Text(p.category.clone()),
            ExcelCell::Number(p.price),
            unit_price_cell,
            ExcelCell::Text(p.size.clone()),
            ExcelCell::Text(p.upc.clone()),
            ExcelCell::Text(if p.snap_eligible { "Yes" } else { "No" }.to_string()),
            ExcelCell::Text(p.store.clone()),
        ]);
        let r = sheet.row_count() - 1;
        sheet.set_cell_format(r, 3, price_fmt.clone());
        sheet.set_cell_format(r, 4, price_fmt.clone());

        total_price += p.price;
        price_count += 1;
    }

    // Summary row
    let avg_price = if price_count > 0 { total_price / price_count as f64 } else { 0.0 };
    sheet.add_row(vec![ExcelCell::Empty]);
    sheet.add_row(vec![
        ExcelCell::Text("TOTAL".to_string()),
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Empty,
    ]);
    let summary_r = sheet.row_count() - 1;
    sheet.set_cell_format(summary_r, 0, CellFormat { bold: true, ..Default::default() });

    sheet.add_row(vec![
        ExcelCell::Text(format!("Products: {price_count}")),
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Text(format!("Avg: ${avg_price:.2}")),
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Empty,
        ExcelCell::Empty,
    ]);
    let info_r = sheet.row_count() - 1;
    sheet.set_cell_format(info_r, 0, CellFormat { bold: true, ..Default::default() });
    sheet.set_cell_format(info_r, 3, CellFormat { bold: true, ..Default::default() });

    // Auto-filter on data rows (excluding summary)
    let data_last_row = summary_r; // row before summary blank
    let last_col = col_ref(headers.len() - 1);
    sheet.auto_filter = Some(format!("A1:{last_col}{data_last_row}"));

    // Column widths
    sheet.col_widths.push((0, 40.0)); // Name
    sheet.col_widths.push((1, 20.0)); // Brand
    sheet.col_widths.push((2, 20.0)); // Category
    sheet.col_widths.push((3, 12.0)); // Price
    sheet.col_widths.push((4, 12.0)); // Unit Price
    sheet.col_widths.push((5, 12.0)); // Size
    sheet.col_widths.push((6, 16.0)); // UPC
    sheet.col_widths.push((7, 14.0)); // SNAP
    sheet.col_widths.push((8, 16.0)); // Store

    wb.save(path)
}

// ═══════════════════════════════════════════════════════════════════════════
// Part 2: Word (.docx) Generator
// ═══════════════════════════════════════════════════════════════════════════

/// A table within a Word document.
#[derive(Debug, Clone)]
pub struct DocTable {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// An element within a Word document body.
#[derive(Debug, Clone)]
pub enum DocElement {
    Heading(String, u8),
    Paragraph(String),
    Bold(String),
    Italic(String),
    Underline(String),
    Strikethrough(String),
    Superscript(String),
    Subscript(String),
    Aligned(String, String), // (text, alignment: "left"/"center"/"right"/"justify")
    BulletList(Vec<String>),
    NumberedList(Vec<String>),
    /// Nested bullet list: each item is (indent_level, text). Level 0 = top-level.
    NestedBulletList(Vec<(u8, String)>),
    /// Nested numbered list: each item is (indent_level, text). Level 0 = top-level.
    NestedNumberedList(Vec<(u8, String)>),
    Table(DocTable),
    PageBreak,
    HorizontalRule,
    /// A hyperlink: (display_text, url).
    Link(String, String),
    /// An embedded image.
    Image {
        data: Vec<u8>,
        width_cm: f64,
        height_cm: f64,
        alt_text: String,
    },
    /// Table of Contents (auto-generated from headings).
    TableOfContents,
}

/// A Word document composed of sequential elements.
#[derive(Debug, Clone)]
pub struct WordDocument {
    pub elements: Vec<DocElement>,
    /// Page width in twips (12240 = 8.5 inches).
    pub page_width: u32,
    /// Page height in twips (15840 = 11 inches).
    pub page_height: u32,
    /// Top margin in twips (1440 = 1 inch).
    pub margin_top: u32,
    /// Bottom margin in twips.
    pub margin_bottom: u32,
    /// Left margin in twips.
    pub margin_left: u32,
    /// Right margin in twips.
    pub margin_right: u32,
    /// Header text (appears at top of every page).
    pub header_text: Option<String>,
    /// Footer text (appears at bottom of every page).
    pub footer_text: Option<String>,
}

impl WordDocument {
    pub fn new() -> Self {
        WordDocument {
            elements: Vec::new(),
            page_width: 12240,   // 8.5 inches
            page_height: 15840,  // 11 inches
            margin_top: 1440,    // 1 inch
            margin_bottom: 1440,
            margin_left: 1440,
            margin_right: 1440,
            header_text: None,
            footer_text: None,
        }
    }

    pub fn add_heading(&mut self, text: &str, level: u8) {
        let level = level.clamp(1, 6);
        self.elements.push(DocElement::Heading(text.to_string(), level));
    }

    pub fn add_paragraph(&mut self, text: &str) {
        self.elements.push(DocElement::Paragraph(text.to_string()));
    }

    pub fn add_bold(&mut self, text: &str) {
        self.elements.push(DocElement::Bold(text.to_string()));
    }

    pub fn add_italic(&mut self, text: &str) {
        self.elements.push(DocElement::Italic(text.to_string()));
    }

    pub fn add_underline(&mut self, text: &str) {
        self.elements.push(DocElement::Underline(text.to_string()));
    }

    pub fn add_strikethrough(&mut self, text: &str) {
        self.elements.push(DocElement::Strikethrough(text.to_string()));
    }

    pub fn add_superscript(&mut self, text: &str) {
        self.elements.push(DocElement::Superscript(text.to_string()));
    }

    pub fn add_subscript(&mut self, text: &str) {
        self.elements.push(DocElement::Subscript(text.to_string()));
    }

    pub fn add_aligned(&mut self, text: &str, alignment: &str) {
        self.elements.push(DocElement::Aligned(text.to_string(), alignment.to_string()));
    }

    pub fn add_table(&mut self, headers: &[&str], rows: &[Vec<String>]) {
        self.elements.push(DocElement::Table(DocTable {
            headers: headers.iter().map(|h| h.to_string()).collect(),
            rows: rows.to_vec(),
        }));
    }

    pub fn add_bullet_list(&mut self, items: &[&str]) {
        self.elements.push(DocElement::BulletList(
            items.iter().map(|s| s.to_string()).collect(),
        ));
    }

    pub fn add_numbered_list(&mut self, items: &[&str]) {
        self.elements.push(DocElement::NumberedList(
            items.iter().map(|s| s.to_string()).collect(),
        ));
    }

    pub fn add_nested_bullet_list(&mut self, items: &[(u8, String)]) {
        self.elements.push(DocElement::NestedBulletList(items.to_vec()));
    }

    pub fn add_nested_numbered_list(&mut self, items: &[(u8, String)]) {
        self.elements.push(DocElement::NestedNumberedList(items.to_vec()));
    }

    pub fn add_page_break(&mut self) {
        self.elements.push(DocElement::PageBreak);
    }

    pub fn add_horizontal_rule(&mut self) {
        self.elements.push(DocElement::HorizontalRule);
    }

    pub fn add_link(&mut self, text: &str, url: &str) {
        self.elements.push(DocElement::Link(text.to_string(), url.to_string()));
    }

    pub fn add_image(&mut self, data: Vec<u8>, width_cm: f64, height_cm: f64, alt_text: &str) {
        self.elements.push(DocElement::Image {
            data,
            width_cm,
            height_cm,
            alt_text: alt_text.to_string(),
        });
    }

    pub fn add_table_of_contents(&mut self) {
        self.elements.push(DocElement::TableOfContents);
    }

    /// Save the document to a file.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let bytes = self.to_bytes()?;
        std::fs::write(path, bytes).map_err(|e| format!("docs.word_save: {e}"))
    }

    /// Generate the DOCX file as an in-memory byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let buf = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(buf);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        // Collect all images and links for relationship tracking
        let mut images: Vec<(&[u8], String)> = Vec::new(); // (data, content_type)
        let mut links: Vec<String> = Vec::new(); // urls

        for elem in &self.elements {
            match elem {
                DocElement::Image { data, alt_text: _, .. } => {
                    // Detect image type from magic bytes
                    let ct = if data.starts_with(b"\x89PNG") {
                        "image/png"
                    } else if data.starts_with(b"\xFF\xD8") {
                        "image/jpeg"
                    } else if data.starts_with(b"GIF") {
                        "image/gif"
                    } else {
                        "image/png" // default
                    };
                    images.push((data, ct.to_string()));
                }
                DocElement::Link(_, url) => {
                    links.push(url.clone());
                }
                _ => {}
            }
        }

        let has_header = self.header_text.is_some();
        let has_footer = self.footer_text.is_some();

        // ── [Content_Types].xml ──
        let mut content_types = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
            <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
            <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
            <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
            <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
            <Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/>\
            <Override PartName=\"/word/numbering.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml\"/>"
        );

        if has_header {
            content_types.push_str(
                "<Override PartName=\"/word/header1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml\"/>"
            );
        }
        if has_footer {
            content_types.push_str(
                "<Override PartName=\"/word/footer1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml\"/>"
            );
        }

        // Image content types
        let mut has_png = false;
        let mut has_jpeg = false;
        let mut has_gif = false;
        for (_, ct) in &images {
            match ct.as_str() {
                "image/png" => has_png = true,
                "image/jpeg" => has_jpeg = true,
                "image/gif" => has_gif = true,
                _ => {}
            }
        }
        if has_png {
            content_types.push_str("<Default Extension=\"png\" ContentType=\"image/png\"/>");
        }
        if has_jpeg {
            content_types.push_str("<Default Extension=\"jpeg\" ContentType=\"image/jpeg\"/>");
        }
        if has_gif {
            content_types.push_str("<Default Extension=\"gif\" ContentType=\"image/gif\"/>");
        }

        content_types.push_str("</Types>");

        zip.start_file("[Content_Types].xml", opts)
            .map_err(|e| format!("docs.docx: zip error: {e}"))?;
        zip.write_all(content_types.as_bytes())
            .map_err(|e| format!("docs.docx: write error: {e}"))?;

        // ── _rels/.rels ──
        let rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
            </Relationships>";

        zip.start_file("_rels/.rels", opts)
            .map_err(|e| format!("docs.docx: zip error: {e}"))?;
        zip.write_all(rels.as_bytes())
            .map_err(|e| format!("docs.docx: write error: {e}"))?;

        // ── word/_rels/document.xml.rels ──
        let mut doc_rels = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>\
            <Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering\" Target=\"numbering.xml\"/>"
        );

        let mut next_rid = 3;

        // Header/footer rels
        let header_rid;
        let footer_rid;
        if has_header {
            header_rid = next_rid;
            doc_rels.push_str(&format!(
                "<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/header\" Target=\"header1.xml\"/>",
                header_rid
            ));
            next_rid += 1;
        } else {
            header_rid = 0;
        }
        if has_footer {
            footer_rid = next_rid;
            doc_rels.push_str(&format!(
                "<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer\" Target=\"footer1.xml\"/>",
                footer_rid
            ));
            next_rid += 1;
        } else {
            footer_rid = 0;
        }

        // Image rels
        let mut image_rids = Vec::new();
        for (ii, (_, ct)) in images.iter().enumerate() {
            let ext = match ct.as_str() {
                "image/jpeg" => "jpeg",
                "image/gif" => "gif",
                _ => "png",
            };
            let rid = next_rid;
            doc_rels.push_str(&format!(
                "<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"media/image{}.{}\"/>",
                rid, ii + 1, ext
            ));
            image_rids.push(rid);
            next_rid += 1;
        }

        // Link rels
        let mut link_rids = Vec::new();
        for url in &links {
            let rid = next_rid;
            doc_rels.push_str(&format!(
                "<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"{}\" TargetMode=\"External\"/>",
                rid, xml_escape(url)
            ));
            link_rids.push(rid);
            next_rid += 1;
        }

        doc_rels.push_str("</Relationships>");

        zip.start_file("word/_rels/document.xml.rels", opts)
            .map_err(|e| format!("docs.docx: zip error: {e}"))?;
        zip.write_all(doc_rels.as_bytes())
            .map_err(|e| format!("docs.docx: write error: {e}"))?;

        // ── word/numbering.xml ──
        let numbering = build_docx_numbering();

        zip.start_file("word/numbering.xml", opts)
            .map_err(|e| format!("docs.docx: zip error: {e}"))?;
        zip.write_all(numbering.as_bytes())
            .map_err(|e| format!("docs.docx: write error: {e}"))?;

        // ── word/styles.xml ──
        let styles = build_docx_styles();

        zip.start_file("word/styles.xml", opts)
            .map_err(|e| format!("docs.docx: zip error: {e}"))?;
        zip.write_all(styles.as_bytes())
            .map_err(|e| format!("docs.docx: write error: {e}"))?;

        // ── word/header1.xml ──
        if let Some(ref header_text) = self.header_text {
            let header_xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
                 <w:hdr xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
                 <w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr>\
                 <w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>\
                 </w:hdr>",
                xml_escape(header_text)
            );
            zip.start_file("word/header1.xml", opts)
                .map_err(|e| format!("docs.docx: zip error: {e}"))?;
            zip.write_all(header_xml.as_bytes())
                .map_err(|e| format!("docs.docx: write error: {e}"))?;
        }

        // ── word/footer1.xml ──
        if let Some(ref footer_text) = self.footer_text {
            let footer_xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
                 <w:ftr xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
                 <w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr>\
                 <w:r><w:t xml:space=\"preserve\">{}</w:t></w:r>\
                 <w:r><w:t xml:space=\"preserve\"> - Page </w:t></w:r>\
                 <w:r><w:fldChar w:fldCharType=\"begin\"/></w:r>\
                 <w:r><w:instrText xml:space=\"preserve\"> PAGE </w:instrText></w:r>\
                 <w:r><w:fldChar w:fldCharType=\"end\"/></w:r>\
                 </w:p></w:ftr>",
                xml_escape(footer_text)
            );
            zip.start_file("word/footer1.xml", opts)
                .map_err(|e| format!("docs.docx: zip error: {e}"))?;
            zip.write_all(footer_xml.as_bytes())
                .map_err(|e| format!("docs.docx: write error: {e}"))?;
        }

        // ── word/media/imageN.ext ──
        for (ii, (data, ct)) in images.iter().enumerate() {
            let ext = match ct.as_str() {
                "image/jpeg" => "jpeg",
                "image/gif" => "gif",
                _ => "png",
            };
            zip.start_file(format!("word/media/image{}.{}", ii + 1, ext), opts)
                .map_err(|e| format!("docs.docx: zip error: {e}"))?;
            zip.write_all(data)
                .map_err(|e| format!("docs.docx: write error: {e}"))?;
        }

        // ── word/document.xml ──
        let document = self.build_document_xml(header_rid, footer_rid, &image_rids, &link_rids);

        zip.start_file("word/document.xml", opts)
            .map_err(|e| format!("docs.docx: zip error: {e}"))?;
        zip.write_all(document.as_bytes())
            .map_err(|e| format!("docs.docx: write error: {e}"))?;

        let cursor = zip
            .finish()
            .map_err(|e| format!("docs.docx: zip finish error: {e}"))?;
        Ok(cursor.into_inner())
    }

    /// Build the `word/document.xml` content from self.elements.
    fn build_document_xml(
        &self,
        header_rid: usize,
        footer_rid: usize,
        image_rids: &[usize],
        link_rids: &[usize],
    ) -> String {
        let mut body = String::new();
        let mut image_counter = 0usize;
        let mut link_counter = 0usize;

        for elem in &self.elements {
            match elem {
                DocElement::Heading(text, level) => {
                    body.push_str(&format!(
                        "<w:p><w:pPr><w:pStyle w:val=\"Heading{}\"/></w:pPr>\
                         <w:r><w:t>{}</w:t></w:r></w:p>",
                        level,
                        xml_escape(text)
                    ));
                }
                DocElement::Paragraph(text) => {
                    body.push_str(&format!(
                        "<w:p><w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                        xml_escape(text)
                    ));
                }
                DocElement::Bold(text) => {
                    body.push_str(&format!(
                        "<w:p><w:r><w:rPr><w:b/></w:rPr>\
                         <w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                        xml_escape(text)
                    ));
                }
                DocElement::Italic(text) => {
                    body.push_str(&format!(
                        "<w:p><w:r><w:rPr><w:i/></w:rPr>\
                         <w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                        xml_escape(text)
                    ));
                }
                DocElement::Underline(text) => {
                    body.push_str(&format!(
                        "<w:p><w:r><w:rPr><w:u w:val=\"single\"/></w:rPr>\
                         <w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                        xml_escape(text)
                    ));
                }
                DocElement::Strikethrough(text) => {
                    body.push_str(&format!(
                        "<w:p><w:r><w:rPr><w:strike/></w:rPr>\
                         <w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                        xml_escape(text)
                    ));
                }
                DocElement::Superscript(text) => {
                    body.push_str(&format!(
                        "<w:p><w:r><w:rPr><w:vertAlign w:val=\"superscript\"/></w:rPr>\
                         <w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                        xml_escape(text)
                    ));
                }
                DocElement::Subscript(text) => {
                    body.push_str(&format!(
                        "<w:p><w:r><w:rPr><w:vertAlign w:val=\"subscript\"/></w:rPr>\
                         <w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                        xml_escape(text)
                    ));
                }
                DocElement::Aligned(text, alignment) => {
                    let jc = match alignment.as_str() {
                        "center" => "center",
                        "right" => "right",
                        "justify" => "both",
                        _ => "left",
                    };
                    body.push_str(&format!(
                        "<w:p><w:pPr><w:jc w:val=\"{}\"/></w:pPr>\
                         <w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                        jc, xml_escape(text)
                    ));
                }
                DocElement::BulletList(items) => {
                    for item in items {
                        body.push_str(&format!(
                            "<w:p><w:pPr><w:pStyle w:val=\"ListParagraph\"/>\
                             <w:numPr><w:ilvl w:val=\"0\"/><w:numId w:val=\"1\"/></w:numPr>\
                             </w:pPr>\
                             <w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                            xml_escape(item)
                        ));
                    }
                }
                DocElement::NumberedList(items) => {
                    for item in items {
                        body.push_str(&format!(
                            "<w:p><w:pPr><w:pStyle w:val=\"ListParagraph\"/>\
                             <w:numPr><w:ilvl w:val=\"0\"/><w:numId w:val=\"2\"/></w:numPr>\
                             </w:pPr>\
                             <w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                            xml_escape(item)
                        ));
                    }
                }
                DocElement::NestedBulletList(items) => {
                    for (level, text) in items {
                        body.push_str(&format!(
                            "<w:p><w:pPr><w:pStyle w:val=\"ListParagraph\"/>\
                             <w:numPr><w:ilvl w:val=\"{}\"/><w:numId w:val=\"1\"/></w:numPr>\
                             </w:pPr>\
                             <w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                            level, xml_escape(text)
                        ));
                    }
                }
                DocElement::NestedNumberedList(items) => {
                    for (level, text) in items {
                        body.push_str(&format!(
                            "<w:p><w:pPr><w:pStyle w:val=\"ListParagraph\"/>\
                             <w:numPr><w:ilvl w:val=\"{}\"/><w:numId w:val=\"2\"/></w:numPr>\
                             </w:pPr>\
                             <w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                            level, xml_escape(text)
                        ));
                    }
                }
                DocElement::Table(table) => {
                    body.push_str("<w:tbl>\
                        <w:tblPr>\
                        <w:tblStyle w:val=\"TableGrid\"/>\
                        <w:tblW w:w=\"0\" w:type=\"auto\"/>\
                        <w:tblBorders>\
                        <w:top w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
                        <w:left w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
                        <w:bottom w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
                        <w:right w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
                        <w:insideH w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
                        <w:insideV w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
                        </w:tblBorders>\
                        </w:tblPr>");

                    // Header row
                    if !table.headers.is_empty() {
                        body.push_str("<w:tr>");
                        for hdr in &table.headers {
                            body.push_str(&format!(
                                "<w:tc><w:p><w:r><w:rPr><w:b/></w:rPr>\
                                 <w:t xml:space=\"preserve\">{}</w:t></w:r></w:p></w:tc>",
                                xml_escape(hdr)
                            ));
                        }
                        body.push_str("</w:tr>");
                    }

                    // Data rows
                    for row in &table.rows {
                        body.push_str("<w:tr>");
                        for cell in row {
                            body.push_str(&format!(
                                "<w:tc><w:p><w:r>\
                                 <w:t xml:space=\"preserve\">{}</w:t></w:r></w:p></w:tc>",
                                xml_escape(cell)
                            ));
                        }
                        body.push_str("</w:tr>");
                    }

                    body.push_str("</w:tbl>");
                }
                DocElement::PageBreak => {
                    // A page break character forces a new page within the current
                    // section. We follow it with an empty paragraph that carries
                    // a <w:sectPr> to begin a new section (nextPage type).
                    // This lets Word treat content after the break as an
                    // independent section with its own page-layout settings.
                    body.push_str(
                        "<w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>\
                         <w:p><w:pPr><w:sectPr>\
                         <w:type w:val=\"nextPage\"/>\
                         </w:sectPr></w:pPr></w:p>",
                    );
                }
                DocElement::HorizontalRule => {
                    body.push_str(
                        "<w:p><w:pPr><w:pBdr>\
                         <w:bottom w:val=\"single\" w:sz=\"12\" w:space=\"1\" w:color=\"000000\"/>\
                         </w:pBdr></w:pPr></w:p>",
                    );
                }
                DocElement::Link(text, _url) => {
                    if link_counter < link_rids.len() {
                        let rid = link_rids[link_counter];
                        body.push_str(&format!(
                            "<w:p><w:hyperlink r:id=\"rId{}\">\
                             <w:r><w:rPr><w:rStyle w:val=\"Hyperlink\"/>\
                             <w:color w:val=\"0563C1\"/><w:u w:val=\"single\"/></w:rPr>\
                             <w:t xml:space=\"preserve\">{}</w:t></w:r>\
                             </w:hyperlink></w:p>",
                            rid, xml_escape(text)
                        ));
                        link_counter += 1;
                    }
                }
                DocElement::Image { width_cm, height_cm, alt_text, .. } => {
                    if image_counter < image_rids.len() {
                        let rid = image_rids[image_counter];
                        // Convert cm to EMUs (1 cm = 360000 EMUs)
                        let cx = (*width_cm * 360000.0) as i64;
                        let cy = (*height_cm * 360000.0) as i64;
                        let img_id = image_counter + 1;

                        body.push_str(&format!(
                            "<w:p><w:r><w:drawing>\
                             <wp:inline distT=\"0\" distB=\"0\" distL=\"0\" distR=\"0\" \
                             xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\">\
                             <wp:extent cx=\"{}\" cy=\"{}\"/>\
                             <wp:docPr id=\"{}\" name=\"Image{}\" descr=\"{}\"/>\
                             <a:graphic xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\">\
                             <a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">\
                             <pic:pic xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">\
                             <pic:nvPicPr><pic:cNvPr id=\"{}\" name=\"Image{}\"/><pic:cNvPicPr/></pic:nvPicPr>\
                             <pic:blipFill>\
                             <a:blip r:embed=\"rId{}\"/>\
                             <a:stretch><a:fillRect/></a:stretch>\
                             </pic:blipFill>\
                             <pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"{}\" cy=\"{}\"/></a:xfrm>\
                             <a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></pic:spPr>\
                             </pic:pic>\
                             </a:graphicData>\
                             </a:graphic>\
                             </wp:inline>\
                             </w:drawing></w:r></w:p>",
                            cx, cy, img_id, img_id, xml_escape(alt_text),
                            img_id, img_id,
                            rid,
                            cx, cy
                        ));
                        image_counter += 1;
                    }
                }
                DocElement::TableOfContents => {
                    // TOC complex field — all fldChar/instrText runs must live inside
                    // one <w:p>. Word re-calculates the TOC on open / Ctrl+A F9.
                    // \o "1-3" = include outline levels 1-3
                    // \h        = make entries hyperlinks
                    // \z        = hide tab leaders in Web Layout view
                    // \u        = use applied paragraph outline level
                    body.push_str(
                        "<w:p>\
                         <w:r><w:fldChar w:fldCharType=\"begin\"/></w:r>\
                         <w:r><w:instrText xml:space=\"preserve\"> TOC \\o &quot;1-3&quot; \\h \\z \\u </w:instrText></w:r>\
                         <w:r><w:fldChar w:fldCharType=\"separate\"/></w:r>\
                         <w:r><w:t>[Table of Contents - Update to populate]</w:t></w:r>\
                         <w:r><w:fldChar w:fldCharType=\"end\"/></w:r>\
                         </w:p>"
                    );
                }
            }
        }

        // ── Section properties (page size, margins, header/footer references) ──
        let mut sect_pr = String::from("<w:sectPr>");
        if header_rid > 0 {
            sect_pr.push_str(&format!(
                "<w:headerReference w:type=\"default\" r:id=\"rId{}\"/>",
                header_rid
            ));
        }
        if footer_rid > 0 {
            sect_pr.push_str(&format!(
                "<w:footerReference w:type=\"default\" r:id=\"rId{}\"/>",
                footer_rid
            ));
        }
        sect_pr.push_str(&format!(
            "<w:pgSz w:w=\"{}\" w:h=\"{}\"/>",
            self.page_width, self.page_height
        ));
        sect_pr.push_str(&format!(
            "<w:pgMar w:top=\"{}\" w:right=\"{}\" w:bottom=\"{}\" w:left=\"{}\" \
             w:header=\"720\" w:footer=\"720\" w:gutter=\"0\"/>",
            self.margin_top, self.margin_right, self.margin_bottom, self.margin_left
        ));
        sect_pr.push_str("</w:sectPr>");

        body.push_str(&sect_pr);

        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" \
             xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
             xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" \
             xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
             xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">\
             <w:body>{}</w:body></w:document>",
            body
        )
    }
}

/// Build the `word/numbering.xml` content with support for nested lists (levels 0-8).
fn build_docx_numbering() -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <w:numbering xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
    );

    // Abstract numbering 0: bullet list with 9 levels
    s.push_str("<w:abstractNum w:abstractNumId=\"0\">");
    let bullet_chars = [
        "\u{2022}", // bullet
        "\u{25E6}", // white bullet
        "\u{25AA}", // small black square
        "\u{2022}", // bullet
        "\u{25E6}", // white bullet
        "\u{25AA}", // small black square
        "\u{2022}", // bullet
        "\u{25E6}", // white bullet
        "\u{25AA}", // small black square
    ];
    for lvl in 0..9u8 {
        let indent = (lvl as u32 + 1) * 720;
        s.push_str(&format!(
            "<w:lvl w:ilvl=\"{}\">\
             <w:start w:val=\"1\"/>\
             <w:numFmt w:val=\"bullet\"/>\
             <w:lvlText w:val=\"{}\"/>\
             <w:lvlJc w:val=\"left\"/>\
             <w:pPr><w:ind w:left=\"{}\" w:hanging=\"360\"/></w:pPr>\
             </w:lvl>",
            lvl, bullet_chars[lvl as usize], indent
        ));
    }
    s.push_str("</w:abstractNum>");

    // Abstract numbering 1: decimal numbered list with 9 levels
    s.push_str("<w:abstractNum w:abstractNumId=\"1\">");
    let num_fmts = ["decimal", "lowerLetter", "lowerRoman", "decimal", "lowerLetter",
                    "lowerRoman", "decimal", "lowerLetter", "lowerRoman"];
    for lvl in 0..9u8 {
        let indent = (lvl as u32 + 1) * 720;
        let fmt_text = match num_fmts[lvl as usize] {
            "lowerLetter" => format!("%{})", lvl + 1),
            "lowerRoman" => format!("(%{}.)", lvl + 1),
            _ => format!("%{}.", lvl + 1),
        };
        s.push_str(&format!(
            "<w:lvl w:ilvl=\"{}\">\
             <w:start w:val=\"1\"/>\
             <w:numFmt w:val=\"{}\"/>\
             <w:lvlText w:val=\"{}\"/>\
             <w:lvlJc w:val=\"left\"/>\
             <w:pPr><w:ind w:left=\"{}\" w:hanging=\"360\"/></w:pPr>\
             </w:lvl>",
            lvl, num_fmts[lvl as usize], fmt_text, indent
        ));
    }
    s.push_str("</w:abstractNum>");

    s.push_str(
        "<w:num w:numId=\"1\"><w:abstractNumId w:val=\"0\"/></w:num>\
         <w:num w:numId=\"2\"><w:abstractNumId w:val=\"1\"/></w:num>"
    );

    s.push_str("</w:numbering>");
    s
}

/// Build the `word/styles.xml` content with standard OOXML styles.
fn build_docx_styles() -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <w:styles xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
    );

    // Default document run properties
    s.push_str(
        "<w:docDefaults><w:rPrDefault><w:rPr>\
         <w:rFonts w:ascii=\"Calibri\" w:hAnsi=\"Calibri\"/>\
         <w:sz w:val=\"22\"/>\
         </w:rPr></w:rPrDefault></w:docDefaults>"
    );

    // Normal style
    s.push_str(
        "<w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\">\
         <w:name w:val=\"Normal\"/>\
         <w:qFormat/>\
         </w:style>"
    );

    // Heading styles 1-6
    let heading_sizes = [32, 26, 24, 22, 20, 18]; // half-points
    for (i, size) in heading_sizes.iter().enumerate() {
        let level = i + 1;
        s.push_str(&format!(
            "<w:style w:type=\"paragraph\" w:styleId=\"Heading{level}\">\
             <w:name w:val=\"heading {level}\"/>\
             <w:basedOn w:val=\"Normal\"/>\
             <w:qFormat/>\
             <w:pPr><w:spacing w:before=\"240\" w:after=\"120\"/>\
             <w:outlineLvl w:val=\"{outline}\"/></w:pPr>\
             <w:rPr><w:b/><w:sz w:val=\"{size}\"/></w:rPr>\
             </w:style>",
            outline = level - 1,
        ));
    }

    // Bold character style
    s.push_str(
        "<w:style w:type=\"character\" w:styleId=\"Bold\">\
         <w:name w:val=\"Bold\"/>\
         <w:rPr><w:b/></w:rPr>\
         </w:style>"
    );

    // Italic character style
    s.push_str(
        "<w:style w:type=\"character\" w:styleId=\"Italic\">\
         <w:name w:val=\"Italic\"/>\
         <w:rPr><w:i/></w:rPr>\
         </w:style>"
    );

    // Hyperlink character style
    s.push_str(
        "<w:style w:type=\"character\" w:styleId=\"Hyperlink\">\
         <w:name w:val=\"Hyperlink\"/>\
         <w:rPr><w:color w:val=\"0563C1\"/><w:u w:val=\"single\"/></w:rPr>\
         </w:style>"
    );

    // ListParagraph style
    s.push_str(
        "<w:style w:type=\"paragraph\" w:styleId=\"ListParagraph\">\
         <w:name w:val=\"List Paragraph\"/>\
         <w:basedOn w:val=\"Normal\"/>\
         <w:qFormat/>\
         <w:pPr><w:ind w:left=\"720\"/></w:pPr>\
         </w:style>"
    );

    // TableGrid style
    s.push_str(
        "<w:style w:type=\"table\" w:styleId=\"TableGrid\">\
         <w:name w:val=\"Table Grid\"/>\
         <w:tblPr>\
         <w:tblBorders>\
         <w:top w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
         <w:left w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
         <w:bottom w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
         <w:right w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
         <w:insideH w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
         <w:insideV w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"000000\"/>\
         </w:tblBorders>\
         </w:tblPr>\
         </w:style>"
    );

    s.push_str("</w:styles>");
    s
}

// ── Word convenience functions ──

/// Create a Word document from title + sections (each section has a title and body text).
pub fn create_word_report(
    title: &str,
    sections: &[(String, String)],
) -> Result<Vec<u8>, String> {
    let mut doc = WordDocument::new();
    doc.add_heading(title, 1);

    for (section_title, body) in sections {
        doc.add_heading(section_title, 2);
        doc.add_paragraph(body);
    }

    doc.to_bytes()
}

// ═══════════════════════════════════════════════════════════════════════════
// Report Template: Competitive Intelligence (Word)
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a competitive intelligence Word report.
///
/// Produces a professional document with title page, table of contents,
/// executive summary, per-section analysis (with optional tables), and
/// a recommendations section.
pub fn create_intel_report(
    path: &str,
    title: &str,
    sections: &[IntelSection],
) -> Result<(), String> {
    let mut doc = WordDocument::new();
    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // Title page
    doc.add_paragraph("");
    doc.add_paragraph("");
    doc.add_heading(title, 1);
    doc.add_paragraph("");
    doc.add_aligned(&format!("Competitive Intelligence Report"), "center");
    doc.add_aligned(&format!("Generated: {now}"), "center");
    doc.add_paragraph("");
    doc.add_aligned("CONFIDENTIAL", "center");
    doc.add_page_break();

    // Table of contents
    doc.add_heading("Table of Contents", 1);
    doc.add_table_of_contents();
    doc.add_page_break();

    // Executive summary
    doc.add_heading("Executive Summary", 1);
    let section_count = sections.len();
    let tables_count = sections.iter().filter(|s| s.table.is_some()).count();
    doc.add_paragraph(&format!(
        "This report covers {section_count} analysis area{}. \
         {tables_count} section{} include{} detailed data tables.",
        if section_count == 1 { "" } else { "s" },
        if tables_count == 1 { "" } else { "s" },
        if tables_count == 1 { "s" } else { "" },
    ));
    doc.add_paragraph("");

    // Summary bullet list of sections
    let section_titles: Vec<&str> = sections.iter().map(|s| s.title.as_str()).collect();
    doc.add_bullet_list(&section_titles);
    doc.add_page_break();

    // Analysis sections
    for section in sections {
        doc.add_heading(&section.title, 2);
        doc.add_paragraph(&section.content);

        if let Some((headers, rows)) = &section.table {
            doc.add_paragraph("");
            let header_refs: Vec<&str> = headers.iter().map(|h| h.as_str()).collect();
            doc.add_table(&header_refs, rows);
        }

        doc.add_paragraph("");
    }

    // Recommendations section
    doc.add_page_break();
    doc.add_heading("Recommendations", 1);
    doc.add_paragraph(
        "Based on the analysis presented in this report, the following recommendations \
         are provided for strategic consideration:"
    );
    let recs: Vec<&str> = vec![
        "Continue monitoring competitor pricing on a weekly basis",
        "Investigate categories where price gaps exceed 15%",
        "Evaluate store-specific promotions and their impact on average pricing",
        "Update data collection methodology as new data sources become available",
    ];
    doc.add_numbered_list(&recs);

    doc.save(path)
}

// ═══════════════════════════════════════════════════════════════════════════
// Report Template: Market Research (Word)
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a market research Word report.
///
/// Sections: Methodology, Market Overview, Price Analysis (table),
/// Store Comparison (table), Key Findings (bullet list), Appendix.
pub fn create_market_report(
    path: &str,
    data: &MarketReportData,
) -> Result<(), String> {
    let mut doc = WordDocument::new();
    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // Title page
    doc.add_paragraph("");
    doc.add_heading(&data.title, 1);
    doc.add_paragraph("");
    doc.add_aligned("Market Research Report", "center");
    doc.add_aligned(&format!("Date Range: {}", data.date_range), "center");
    doc.add_aligned(&format!("Generated: {now}"), "center");
    doc.add_page_break();

    // Table of contents
    doc.add_heading("Table of Contents", 1);
    doc.add_table_of_contents();
    doc.add_page_break();

    // 1. Methodology
    doc.add_heading("1. Methodology", 1);
    doc.add_paragraph(&data.methodology);
    doc.add_paragraph("");
    let method_items: Vec<String> = vec![
        format!("Data sources: {} stores", data.stores.len()),
        format!("Date range: {}", data.date_range),
        format!("Total products analyzed: {}", data.total_products),
        format!("Categories covered: {}", data.categories.len()),
    ];
    let method_refs: Vec<&str> = method_items.iter().map(|s| s.as_str()).collect();
    doc.add_bullet_list(&method_refs);

    // 2. Market Overview
    doc.add_heading("2. Market Overview", 1);
    doc.add_paragraph(&format!(
        "This analysis covers {} products across {} stores and {} categories.",
        data.total_products,
        data.stores.len(),
        data.categories.len(),
    ));
    doc.add_paragraph("");
    doc.add_bold("Stores Covered:");
    let store_refs: Vec<&str> = data.stores.iter().map(|s| s.as_str()).collect();
    doc.add_bullet_list(&store_refs);

    // 3. Price Analysis
    doc.add_heading("3. Price Analysis", 1);
    doc.add_paragraph("The following table summarizes pricing statistics by category:");
    doc.add_paragraph("");

    let price_headers = ["Category", "Products", "Avg Price", "Min Price", "Max Price", "Median Price"];
    let price_rows: Vec<Vec<String>> = data.categories.iter().map(|cat| {
        vec![
            cat.name.clone(),
            cat.product_count.to_string(),
            format!("${:.2}", cat.avg_price),
            format!("${:.2}", cat.min_price),
            format!("${:.2}", cat.max_price),
            format!("${:.2}", cat.median_price),
        ]
    }).collect();
    doc.add_table(&price_headers, &price_rows);

    // Overall stats
    if !data.categories.is_empty() {
        let total_products: usize = data.categories.iter().map(|c| c.product_count).sum();
        let weighted_avg: f64 = if total_products > 0 {
            data.categories.iter().map(|c| c.avg_price * c.product_count as f64).sum::<f64>() / total_products as f64
        } else {
            0.0
        };
        let global_min = data.categories.iter().map(|c| c.min_price).fold(f64::INFINITY, f64::min);
        let global_max = data.categories.iter().map(|c| c.max_price).fold(f64::NEG_INFINITY, f64::max);

        doc.add_paragraph("");
        doc.add_paragraph(&format!(
            "Overall: weighted average price ${weighted_avg:.2}, range ${global_min:.2} - ${global_max:.2}."
        ));
    }

    // 4. Store Comparison
    doc.add_heading("4. Store Comparison", 1);
    doc.add_paragraph("Comparison of product coverage across stores:");
    doc.add_paragraph("");

    // Build a simple store comparison table
    let store_headers = ["Store", "Status"];
    let store_rows: Vec<Vec<String>> = data.stores.iter().map(|store| {
        vec![store.clone(), "Active".to_string()]
    }).collect();
    doc.add_table(&store_headers, &store_rows);

    // 5. Key Findings
    doc.add_heading("5. Key Findings", 1);
    if data.findings.is_empty() {
        doc.add_paragraph("No specific findings have been recorded for this report period.");
    } else {
        doc.add_paragraph("The following key findings emerged from this analysis:");
        doc.add_paragraph("");
        let finding_refs: Vec<&str> = data.findings.iter().map(|s| s.as_str()).collect();
        doc.add_bullet_list(&finding_refs);
    }

    // 6. Appendix
    doc.add_page_break();
    doc.add_heading("6. Appendix", 1);
    doc.add_paragraph("Full category data summary:");
    doc.add_paragraph("");

    let appendix_headers = ["#", "Category", "Count", "Avg", "Min", "Max", "Median"];
    let appendix_rows: Vec<Vec<String>> = data.categories.iter().enumerate().map(|(i, cat)| {
        vec![
            (i + 1).to_string(),
            cat.name.clone(),
            cat.product_count.to_string(),
            format!("${:.2}", cat.avg_price),
            format!("${:.2}", cat.min_price),
            format!("${:.2}", cat.max_price),
            format!("${:.2}", cat.median_price),
        ]
    }).collect();
    doc.add_table(&appendix_headers, &appendix_rows);

    doc.save(path)
}

/// Create a Word document from a subset of Markdown.
///
/// Supports: `#`-`######` headings, `**bold**`, `*italic*`, `__underline__`,
/// `~~strikethrough~~`, `- ` bullet lists, `1. ` numbered lists, `---` horizontal
/// rules, `[text](url)` links, and plain paragraphs.
/// Tables and images are not supported in this simplified parser.
pub fn create_word_from_markdown(markdown: &str) -> Result<Vec<u8>, String> {
    let mut doc = WordDocument::new();
    let lines: Vec<&str> = markdown.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        // Horizontal rule
        if trimmed == "---" || trimmed == "***" || trimmed == "___" {
            doc.add_horizontal_rule();
            i += 1;
            continue;
        }

        // Page break (non-standard: ===)
        if trimmed == "===" {
            doc.add_page_break();
            i += 1;
            continue;
        }

        // Headings
        if trimmed.starts_with('#') {
            let level = trimmed.chars().take_while(|c| *c == '#').count() as u8;
            let text = trimmed[level as usize..].trim();
            doc.add_heading(text, level);
            i += 1;
            continue;
        }

        // Bullet list: collect consecutive lines starting with "- " or "* "
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            let mut items = Vec::new();
            while i < lines.len() {
                let lt = lines[i].trim();
                if let Some(rest) = lt.strip_prefix("- ").or_else(|| lt.strip_prefix("* ")) {
                    items.push(rest.to_string());
                    i += 1;
                } else {
                    break;
                }
            }
            let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
            doc.add_bullet_list(&refs);
            continue;
        }

        // Numbered list: collect consecutive lines matching N. pattern
        if trimmed.len() > 2 && trimmed.chars().next().unwrap_or(' ').is_ascii_digit() {
            if let Some(dot_pos) = trimmed.find(". ") {
                let prefix = &trimmed[..dot_pos];
                if prefix.chars().all(|c| c.is_ascii_digit()) {
                    let mut items = Vec::new();
                    while i < lines.len() {
                        let lt = lines[i].trim();
                        if let Some(dp) = lt.find(". ") {
                            let pfx = &lt[..dp];
                            if pfx.chars().all(|c| c.is_ascii_digit()) {
                                items.push(lt[dp + 2..].to_string());
                                i += 1;
                                continue;
                            }
                        }
                        break;
                    }
                    let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
                    doc.add_numbered_list(&refs);
                    continue;
                }
            }
        }

        // Strikethrough paragraph: ~~text~~
        if trimmed.starts_with("~~") && trimmed.ends_with("~~") && trimmed.len() > 4 {
            doc.add_strikethrough(&trimmed[2..trimmed.len() - 2]);
            i += 1;
            continue;
        }

        // Underline paragraph: __text__
        if trimmed.starts_with("__") && trimmed.ends_with("__") && trimmed.len() > 4 {
            doc.add_underline(&trimmed[2..trimmed.len() - 2]);
            i += 1;
            continue;
        }

        // Bold paragraph: **text**
        if trimmed.starts_with("**") && trimmed.ends_with("**") && trimmed.len() > 4 {
            doc.add_bold(&trimmed[2..trimmed.len() - 2]);
            i += 1;
            continue;
        }

        // Italic paragraph: *text*
        if trimmed.starts_with('*') && trimmed.ends_with('*') && !trimmed.starts_with("**") && trimmed.len() > 2 {
            doc.add_italic(&trimmed[1..trimmed.len() - 1]);
            i += 1;
            continue;
        }

        // Link: [text](url) — entire line is a link
        if trimmed.starts_with('[') && trimmed.contains("](") && trimmed.ends_with(')') {
            if let Some(bracket_end) = trimmed.find("](") {
                let text = &trimmed[1..bracket_end];
                let url = &trimmed[bracket_end + 2..trimmed.len() - 1];
                doc.add_link(text, url);
                i += 1;
                continue;
            }
        }

        // Plain paragraph
        doc.add_paragraph(trimmed);
        i += 1;
    }

    doc.to_bytes()
}

// ═══════════════════════════════════════════════════════════════════════════
// Part 2.5: PDF (.pdf) Generator — raw PDF syntax, zero dependencies
// ═══════════════════════════════════════════════════════════════════════════

/// Escape special characters for a PDF text string (parenthesis-delimited).
fn pdf_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// An element within a PDF document body.
#[derive(Debug, Clone)]
pub enum PdfElement {
    Heading { text: String, level: u8 },
    Paragraph(String),
    BulletList(Vec<String>),
    NumberedList(Vec<String>),
    Table { headers: Vec<String>, rows: Vec<Vec<String>> },
    HorizontalRule,
    Spacer(f64),
    Bold(String),
    PageBreak,
}

/// A single page of PDF content (built during rendering).
#[derive(Debug, Clone)]
pub struct PdfPage {
    pub elements: Vec<PdfElement>,
}

/// A PDF document composed of sequential elements.
#[derive(Debug, Clone)]
pub struct PdfDocument {
    pub pages: Vec<PdfPage>,
    pub title: String,
    pub author: String,
    pub page_width: f64,
    pub page_height: f64,
    pub margin: f64,
    elements: Vec<PdfElement>,
}

fn helvetica_char_width(font_size: f64) -> f64 {
    font_size * 0.5
}

fn wrap_text(text: &str, font_size: f64, max_width: f64) -> Vec<String> {
    let char_w = helvetica_char_width(font_size);
    let max_chars = (max_width / char_w).floor() as usize;
    if max_chars == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    for raw_line in text.split('\n') {
        if raw_line.is_empty() {
            lines.push(String::new());
            continue;
        }
        let words: Vec<&str> = raw_line.split_whitespace().collect();
        if words.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut current_line = String::new();
        for word in &words {
            if current_line.is_empty() {
                if word.len() > max_chars {
                    let mut remaining = *word;
                    while remaining.len() > max_chars {
                        let (a, b) = remaining.split_at(max_chars);
                        lines.push(a.to_string());
                        remaining = b;
                    }
                    current_line = remaining.to_string();
                } else {
                    current_line = word.to_string();
                }
            } else if current_line.len() + 1 + word.len() > max_chars {
                lines.push(current_line);
                current_line = word.to_string();
            } else {
                current_line.push(' ');
                current_line.push_str(word);
            }
        }
        if !current_line.is_empty() {
            lines.push(current_line);
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn pdf_emit_text(stream: &mut Vec<u8>, x: f64, y: f64, font: &str, size: f64, text: &str) {
    use std::io::Write as _;
    let _ = write!(stream, "BT /{} {} Tf {} {} Td ({}) Tj ET\n", font, size, x, y, pdf_escape(text));
}

fn pdf_emit_line(stream: &mut Vec<u8>, x1: f64, y1: f64, x2: f64, y2: f64, w: f64) {
    use std::io::Write as _;
    let _ = write!(stream, "{} w {} {} m {} {} l S\n", w, x1, y1, x2, y2);
}

fn pdf_emit_rect(stream: &mut Vec<u8>, x: f64, y: f64, w: f64, h: f64, lw: f64) {
    use std::io::Write as _;
    let _ = write!(stream, "{} w {} {} {} {} re S\n", lw, x, y, w, h);
}

fn pdf_emit_rect_fill(stream: &mut Vec<u8>, x: f64, y: f64, w: f64, h: f64, r: f64, g: f64, b: f64) {
    use std::io::Write as _;
    let _ = write!(stream, "{} {} {} rg {} {} {} {} re f\n0 0 0 rg\n", r, g, b, x, y, w, h);
}

impl PdfDocument {
    pub fn new() -> Self {
        PdfDocument {
            pages: Vec::new(),
            title: String::new(),
            author: String::new(),
            page_width: 612.0,
            page_height: 792.0,
            margin: 72.0,
            elements: Vec::new(),
        }
    }

    pub fn set_title(&mut self, title: &str) { self.title = title.to_string(); }
    pub fn set_author(&mut self, author: &str) { self.author = author.to_string(); }

    pub fn add_heading(&mut self, text: &str, level: u8) {
        self.elements.push(PdfElement::Heading { text: text.to_string(), level: level.clamp(1, 3) });
    }

    pub fn add_paragraph(&mut self, text: &str) {
        self.elements.push(PdfElement::Paragraph(text.to_string()));
    }

    pub fn add_bold(&mut self, text: &str) {
        self.elements.push(PdfElement::Bold(text.to_string()));
    }

    pub fn add_bullet_list(&mut self, items: &[&str]) {
        self.elements.push(PdfElement::BulletList(items.iter().map(|s| s.to_string()).collect()));
    }

    pub fn add_numbered_list(&mut self, items: &[&str]) {
        self.elements.push(PdfElement::NumberedList(items.iter().map(|s| s.to_string()).collect()));
    }

    pub fn add_table(&mut self, headers: Vec<String>, rows: Vec<Vec<String>>) {
        self.elements.push(PdfElement::Table { headers, rows });
    }

    pub fn add_horizontal_rule(&mut self) { self.elements.push(PdfElement::HorizontalRule); }
    pub fn add_spacer(&mut self, points: f64) { self.elements.push(PdfElement::Spacer(points)); }
    pub fn add_page_break(&mut self) { self.elements.push(PdfElement::PageBreak); }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let bytes = self.to_bytes()?;
        std::fs::write(path, bytes).map_err(|e| format!("docs.pdf_save: {e}"))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        use std::io::Write as _;

        let cw = self.page_width - 2.0 * self.margin;
        let ct = self.page_height - self.margin;
        let cb = self.margin;

        let mut pages: Vec<Vec<u8>> = Vec::new();
        let mut s: Vec<u8> = Vec::new();
        let mut y = ct;

        macro_rules! page_break {
            () => {
                if !s.is_empty() { pages.push(std::mem::take(&mut s)); }
                y = ct;
            };
        }
        macro_rules! need {
            ($h:expr) => {
                if y - $h < cb { page_break!(); }
            };
        }

        for el in &self.elements {
            match el {
                PdfElement::PageBreak => { page_break!(); }
                PdfElement::Spacer(pts) => {
                    y -= pts;
                    if y < cb { page_break!(); }
                }
                PdfElement::HorizontalRule => {
                    need!(12.0);
                    y -= 6.0;
                    pdf_emit_line(&mut s, self.margin, y, self.page_width - self.margin, y, 0.5);
                    y -= 6.0;
                }
                PdfElement::Heading { text, level } => {
                    let fs = match level { 1 => 24.0, 2 => 18.0, _ => 14.0 };
                    let lh = fs * 1.4;
                    let lines = wrap_text(text, fs, cw);
                    y -= 4.0;
                    for line in &lines {
                        need!(lh);
                        y -= lh;
                        pdf_emit_text(&mut s, self.margin, y, "F2", fs, line);
                    }
                    y -= 2.0;
                }
                PdfElement::Paragraph(text) => {
                    let fs = 12.0;
                    let lh = fs * 1.4;
                    let lines = wrap_text(text, fs, cw);
                    for line in &lines {
                        need!(lh);
                        y -= lh;
                        pdf_emit_text(&mut s, self.margin, y, "F1", fs, line);
                    }
                    y -= 4.0;
                }
                PdfElement::Bold(text) => {
                    let fs = 12.0;
                    let lh = fs * 1.4;
                    let lines = wrap_text(text, fs, cw);
                    for line in &lines {
                        need!(lh);
                        y -= lh;
                        pdf_emit_text(&mut s, self.margin, y, "F2", fs, line);
                    }
                    y -= 4.0;
                }
                PdfElement::BulletList(items) => {
                    let fs = 12.0;
                    let lh = fs * 1.4;
                    let indent = 18.0;
                    for item in items {
                        let lines = wrap_text(item, fs, cw - indent);
                        for (i, line) in lines.iter().enumerate() {
                            need!(lh);
                            y -= lh;
                            if i == 0 {
                                pdf_emit_text(&mut s, self.margin, y, "F1", fs, "\u{2022}");
                            }
                            pdf_emit_text(&mut s, self.margin + indent, y, "F1", fs, line);
                        }
                    }
                    y -= 4.0;
                }
                PdfElement::NumberedList(items) => {
                    let fs = 12.0;
                    let lh = fs * 1.4;
                    let indent = 24.0;
                    for (idx, item) in items.iter().enumerate() {
                        let lines = wrap_text(item, fs, cw - indent);
                        for (i, line) in lines.iter().enumerate() {
                            need!(lh);
                            y -= lh;
                            if i == 0 {
                                let num = format!("{}.", idx + 1);
                                pdf_emit_text(&mut s, self.margin, y, "F1", fs, &num);
                            }
                            pdf_emit_text(&mut s, self.margin + indent, y, "F1", fs, line);
                        }
                    }
                    y -= 4.0;
                }
                PdfElement::Table { headers, rows } => {
                    let fs = 10.0;
                    let lh = fs * 1.4;
                    let cp = 4.0;
                    let nc = headers.len().max(rows.iter().map(|r| r.len()).max().unwrap_or(0));
                    if nc == 0 { continue; }

                    let col_w = cw / nc as f64;
                    let ccw = col_w - 2.0 * cp;

                    let hl: Vec<Vec<String>> = headers.iter().map(|h| wrap_text(h, fs, ccw)).collect();
                    let hml = hl.iter().map(|l| l.len()).max().unwrap_or(1);
                    let hrh = hml as f64 * lh + 2.0 * cp;

                    let dri: Vec<(Vec<Vec<String>>, f64)> = rows.iter().map(|row| {
                        let cl: Vec<Vec<String>> = (0..nc).map(|c| {
                            let t = row.get(c).map(|v| v.as_str()).unwrap_or("");
                            wrap_text(t, fs, ccw)
                        }).collect();
                        let ml = cl.iter().map(|l| l.len()).max().unwrap_or(1);
                        let rh = ml as f64 * lh + 2.0 * cp;
                        (cl, rh)
                    }).collect();

                    let mth = hrh + dri.first().map(|(_, h)| *h).unwrap_or(0.0);
                    need!(mth);

                    let tx = self.margin;

                    // Draw header
                    pdf_emit_rect_fill(&mut s, tx, y - hrh, cw, hrh, 0.9, 0.9, 0.9);
                    for (ci, lines) in hl.iter().enumerate() {
                        let cx = tx + ci as f64 * col_w;
                        pdf_emit_rect(&mut s, cx, y - hrh, col_w, hrh, 0.5);
                        for (li, line) in lines.iter().enumerate() {
                            let ty = y - cp - lh * (li as f64 + 0.8);
                            pdf_emit_text(&mut s, cx + cp, ty, "F2", fs, line);
                        }
                    }
                    y -= hrh;

                    // Draw data rows
                    for (cl, rh) in &dri {
                        if y - rh < cb {
                            page_break!();
                            // Re-draw header on new page
                            pdf_emit_rect_fill(&mut s, tx, y - hrh, cw, hrh, 0.9, 0.9, 0.9);
                            for (ci, lines) in hl.iter().enumerate() {
                                let cx = tx + ci as f64 * col_w;
                                pdf_emit_rect(&mut s, cx, y - hrh, col_w, hrh, 0.5);
                                for (li, line) in lines.iter().enumerate() {
                                    let ty = y - cp - lh * (li as f64 + 0.8);
                                    pdf_emit_text(&mut s, cx + cp, ty, "F2", fs, line);
                                }
                            }
                            y -= hrh;
                        }
                        for (ci, lines) in cl.iter().enumerate() {
                            let cx = tx + ci as f64 * col_w;
                            pdf_emit_rect(&mut s, cx, y - rh, col_w, *rh, 0.5);
                            for (li, line) in lines.iter().enumerate() {
                                let ty = y - cp - lh * (li as f64 + 0.8);
                                pdf_emit_text(&mut s, cx + cp, ty, "F1", fs, line);
                            }
                        }
                        y -= rh;
                    }
                    y -= 6.0;
                }
            }
        }

        // Flush last page
        if !s.is_empty() || pages.is_empty() {
            pages.push(s);
        }

        // Build PDF byte stream
        let np = pages.len();
        let fpo = 6usize;
        let total = 5 + np * 2;
        let mut pdf = Vec::<u8>::new();
        let mut off: Vec<usize> = vec![0; total + 1];

        pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

        off[1] = pdf.len();
        write!(pdf, "1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n").unwrap();

        off[2] = pdf.len();
        let kids: Vec<String> = (0..np).map(|i| format!("{} 0 R", fpo + i * 2)).collect();
        write!(pdf, "2 0 obj <</Type /Pages /Kids [{}] /Count {}>> endobj\n", kids.join(" "), np).unwrap();

        off[3] = pdf.len();
        write!(pdf, "3 0 obj <</Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding>> endobj\n").unwrap();

        off[4] = pdf.len();
        write!(pdf, "4 0 obj <</Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding>> endobj\n").unwrap();

        off[5] = pdf.len();
        let cd = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        write!(pdf, "5 0 obj <</Title ({}) /Author ({}) /Producer (Tallow PDF Generator) /CreationDate (D:{})>> endobj\n",
            pdf_escape(&self.title), pdf_escape(&self.author), cd).unwrap();

        let res = "<</Font <</F1 3 0 R /F2 4 0 R>>>>";
        for (i, sd) in pages.iter().enumerate() {
            let po = fpo + i * 2;
            let co = po + 1;
            off[po] = pdf.len();
            write!(pdf, "{} 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Contents {} 0 R /Resources {}>> endobj\n",
                po, self.page_width as i32, self.page_height as i32, co, res).unwrap();
            off[co] = pdf.len();
            write!(pdf, "{} 0 obj <</Length {}>> stream\n", co, sd.len()).unwrap();
            pdf.extend_from_slice(sd);
            write!(pdf, "\nendstream endobj\n").unwrap();
        }

        let xref_off = pdf.len();
        write!(pdf, "xref\n0 {}\n", total + 1).unwrap();
        write!(pdf, "0000000000 65535 f \n").unwrap();
        for o in 1..=total {
            write!(pdf, "{:010} 00000 n \n", off[o]).unwrap();
        }
        write!(pdf, "trailer <</Size {} /Root 1 0 R /Info 5 0 R>>\nstartxref\n{}\n%%EOF\n", total + 1, xref_off).unwrap();

        Ok(pdf)
    }
}

/// Create a PDF report from title + sections.
fn create_pdf_report(title: &str, sections: &[(String, String)]) -> Result<Vec<u8>, String> {
    let mut doc = PdfDocument::new();
    doc.set_title(title);
    doc.add_heading(title, 1);
    doc.add_spacer(8.0);
    for (st, sb) in sections {
        doc.add_heading(st, 2);
        if !sb.is_empty() { doc.add_paragraph(sb); }
    }
    doc.to_bytes()
}

// ═══════════════════════════════════════════════════════════════════════════
// Part 2b: PowerPoint (.pptx) Generator
// ═══════════════════════════════════════════════════════════════════════════

/// Slide layout types for PowerPoint slides.
#[derive(Debug, Clone)]
pub enum SlideLayout {
    TitleSlide,
    TitleContent,
    Blank,
    TwoColumn,
}

/// An element within a PowerPoint slide.
#[derive(Debug, Clone)]
pub enum SlideElement {
    Title(String),
    Subtitle(String),
    TextBox {
        text: String,
        x: i64,
        y: i64,
        width: i64,
        height: i64,
        font_size: u32,
        bold: bool,
        color: String,
    },
    BulletList(Vec<String>),
    NumberedList(Vec<String>),
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
        x: i64,
        y: i64,
        width: i64,
        height: i64,
    },
    Image {
        data: Vec<u8>,
        x: i64,
        y: i64,
        width: i64,
        height: i64,
        format: String,
    },
}

/// A single slide in a PowerPoint presentation.
#[derive(Debug, Clone)]
pub struct PptxSlide {
    pub elements: Vec<SlideElement>,
    pub layout: SlideLayout,
}

/// A PowerPoint presentation containing one or more slides.
#[derive(Debug, Clone)]
pub struct PptxPresentation {
    pub slides: Vec<PptxSlide>,
    pub title: String,
    /// Slide width in EMU (default 12192000 = 10 inches).
    pub width_emu: i64,
    /// Slide height in EMU (default 6858000 = 7.5 inches).
    pub height_emu: i64,
}

impl PptxSlide {
    pub fn new(layout: SlideLayout) -> Self {
        PptxSlide { elements: Vec::new(), layout }
    }

    pub fn add_title(&mut self, text: &str) {
        self.elements.push(SlideElement::Title(text.to_string()));
    }

    pub fn add_subtitle(&mut self, text: &str) {
        self.elements.push(SlideElement::Subtitle(text.to_string()));
    }

    pub fn add_text_box(&mut self, text: &str, x: i64, y: i64, width: i64, height: i64, font_size: u32, bold: bool, color: &str) {
        self.elements.push(SlideElement::TextBox {
            text: text.to_string(), x, y, width, height, font_size, bold, color: color.to_string(),
        });
    }

    pub fn add_bullet_list(&mut self, items: &[String]) {
        self.elements.push(SlideElement::BulletList(items.to_vec()));
    }

    pub fn add_numbered_list(&mut self, items: &[String]) {
        self.elements.push(SlideElement::NumberedList(items.to_vec()));
    }

    pub fn add_table(&mut self, headers: &[String], rows: &[Vec<String>], x: i64, y: i64, width: i64, height: i64) {
        self.elements.push(SlideElement::Table {
            headers: headers.to_vec(), rows: rows.to_vec(), x, y, width, height,
        });
    }

    pub fn add_image(&mut self, data: Vec<u8>, x: i64, y: i64, width: i64, height: i64, format: &str) {
        self.elements.push(SlideElement::Image {
            data, x, y, width, height, format: format.to_string(),
        });
    }
}

impl PptxPresentation {
    pub fn new(title: &str) -> Self {
        PptxPresentation {
            slides: Vec::new(), title: title.to_string(),
            width_emu: 12_192_000, height_emu: 6_858_000,
        }
    }

    pub fn add_slide(&mut self, layout: SlideLayout) -> &mut PptxSlide {
        self.slides.push(PptxSlide::new(layout));
        self.slides.last_mut().unwrap()
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let bytes = self.to_bytes()?;
        std::fs::write(path, bytes).map_err(|e| format!("docs.pptx_save: {e}"))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let buf = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(buf);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        let mut has_png = false;
        let mut has_jpeg = false;
        let mut has_gif = false;
        for slide in &self.slides {
            for elem in &slide.elements {
                if let SlideElement::Image { data, format, .. } = elem {
                    match pptx_image_ext(format, data) {
                        "jpeg" => has_jpeg = true,
                        "gif" => has_gif = true,
                        _ => has_png = true,
                    }
                }
            }
        }

        // [Content_Types].xml
        let mut ct = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
             <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
             <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
             <Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/>\
             <Override PartName=\"/ppt/slideMasters/slideMaster1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml\"/>\
             <Override PartName=\"/ppt/slideLayouts/slideLayout1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml\"/>\
             <Override PartName=\"/ppt/theme/theme1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.theme+xml\"/>");
        for (i, _) in self.slides.iter().enumerate() {
            ct.push_str(&format!("<Override PartName=\"/ppt/slides/slide{}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/>", i + 1));
        }
        if has_png { ct.push_str("<Default Extension=\"png\" ContentType=\"image/png\"/>"); }
        if has_jpeg { ct.push_str("<Default Extension=\"jpeg\" ContentType=\"image/jpeg\"/>"); }
        if has_gif { ct.push_str("<Default Extension=\"gif\" ContentType=\"image/gif\"/>"); }
        ct.push_str("</Types>");
        zip.start_file("[Content_Types].xml", opts).map_err(|e| format!("docs.pptx: {e}"))?;
        zip.write_all(ct.as_bytes()).map_err(|e| format!("docs.pptx: {e}"))?;

        // _rels/.rels
        zip.start_file("_rels/.rels", opts).map_err(|e| format!("docs.pptx: {e}"))?;
        zip.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"ppt/presentation.xml\"/></Relationships>").map_err(|e| format!("docs.pptx: {e}"))?;

        // ppt/theme/theme1.xml
        zip.start_file("ppt/theme/theme1.xml", opts).map_err(|e| format!("docs.pptx: {e}"))?;
        zip.write_all(build_pptx_theme().as_bytes()).map_err(|e| format!("docs.pptx: {e}"))?;

        // ppt/slideMasters/slideMaster1.xml
        zip.start_file("ppt/slideMasters/slideMaster1.xml", opts).map_err(|e| format!("docs.pptx: {e}"))?;
        zip.write_all(build_pptx_slide_master().as_bytes()).map_err(|e| format!("docs.pptx: {e}"))?;

        // ppt/slideMasters/_rels/slideMaster1.xml.rels
        zip.start_file("ppt/slideMasters/_rels/slideMaster1.xml.rels", opts).map_err(|e| format!("docs.pptx: {e}"))?;
        zip.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme\" Target=\"../theme/theme1.xml\"/></Relationships>").map_err(|e| format!("docs.pptx: {e}"))?;

        // ppt/slideLayouts/slideLayout1.xml
        zip.start_file("ppt/slideLayouts/slideLayout1.xml", opts).map_err(|e| format!("docs.pptx: {e}"))?;
        zip.write_all(build_pptx_slide_layout().as_bytes()).map_err(|e| format!("docs.pptx: {e}"))?;

        // ppt/slideLayouts/_rels/slideLayout1.xml.rels
        zip.start_file("ppt/slideLayouts/_rels/slideLayout1.xml.rels", opts).map_err(|e| format!("docs.pptx: {e}"))?;
        zip.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster\" Target=\"../slideMasters/slideMaster1.xml\"/></Relationships>").map_err(|e| format!("docs.pptx: {e}"))?;

        // ppt/presentation.xml
        let mut pres = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<p:presentation xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"><p:sldMasterIdLst><p:sldMasterId id=\"2147483648\" r:id=\"rId1\"/></p:sldMasterIdLst><p:sldIdLst>");
        for (i, _) in self.slides.iter().enumerate() {
            pres.push_str(&format!("<p:sldId id=\"{}\" r:id=\"rId{}\"/>", 256 + i, i + 2));
        }
        pres.push_str(&format!("</p:sldIdLst><p:sldSz cx=\"{}\" cy=\"{}\"/><p:notesSz cx=\"{}\" cy=\"{}\"/></p:presentation>", self.width_emu, self.height_emu, self.height_emu, self.width_emu));
        zip.start_file("ppt/presentation.xml", opts).map_err(|e| format!("docs.pptx: {e}"))?;
        zip.write_all(pres.as_bytes()).map_err(|e| format!("docs.pptx: {e}"))?;

        // ppt/_rels/presentation.xml.rels
        let mut prels = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster\" Target=\"slideMasters/slideMaster1.xml\"/>");
        for (i, _) in self.slides.iter().enumerate() {
            prels.push_str(&format!("<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide\" Target=\"slides/slide{}.xml\"/>", i + 2, i + 1));
        }
        prels.push_str(&format!("<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme\" Target=\"theme/theme1.xml\"/></Relationships>", self.slides.len() + 2));
        zip.start_file("ppt/_rels/presentation.xml.rels", opts).map_err(|e| format!("docs.pptx: {e}"))?;
        zip.write_all(prels.as_bytes()).map_err(|e| format!("docs.pptx: {e}"))?;

        // Per-slide files
        let mut global_img = 0usize;
        for (si, slide) in self.slides.iter().enumerate() {
            let mut slide_imgs: Vec<(usize, &[u8], &str)> = Vec::new();
            for (ei, elem) in slide.elements.iter().enumerate() {
                if let SlideElement::Image { data, format, .. } = elem {
                    slide_imgs.push((ei, data, format));
                }
            }
            let mut srels = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/>");
            let mut img_rid_map: Vec<(usize, usize)> = Vec::new();
            let mut next_rid = 2usize;
            for (ei, data, fmt) in &slide_imgs {
                global_img += 1;
                let ext = pptx_image_ext(fmt, data);
                zip.start_file(format!("ppt/media/image{}.{}", global_img, ext), opts).map_err(|e| format!("docs.pptx: {e}"))?;
                zip.write_all(data).map_err(|e| format!("docs.pptx: {e}"))?;
                srels.push_str(&format!("<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"../media/image{}.{}\"/>", next_rid, global_img, ext));
                img_rid_map.push((*ei, next_rid));
                next_rid += 1;
            }
            srels.push_str("</Relationships>");
            zip.start_file(format!("ppt/slides/_rels/slide{}.xml.rels", si + 1), opts).map_err(|e| format!("docs.pptx: {e}"))?;
            zip.write_all(srels.as_bytes()).map_err(|e| format!("docs.pptx: {e}"))?;

            let sxml = build_pptx_slide_xml(slide, &img_rid_map, self.width_emu, self.height_emu);
            zip.start_file(format!("ppt/slides/slide{}.xml", si + 1), opts).map_err(|e| format!("docs.pptx: {e}"))?;
            zip.write_all(sxml.as_bytes()).map_err(|e| format!("docs.pptx: {e}"))?;
        }

        let cursor = zip.finish().map_err(|e| format!("docs.pptx: zip finish: {e}"))?;
        Ok(cursor.into_inner())
    }
}

fn pptx_image_ext<'a>(fmt: &'a str, data: &[u8]) -> &'static str {
    match fmt {
        "png" => "png", "jpg" | "jpeg" => "jpeg", "gif" => "gif",
        _ => if data.starts_with(b"\x89PNG") { "png" } else if data.starts_with(b"\xFF\xD8") { "jpeg" } else if data.starts_with(b"GIF") { "gif" } else { "png" },
    }
}

fn build_pptx_slide_xml(slide: &PptxSlide, img_rid_map: &[(usize, usize)], sw: i64, sh: i64) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<p:sld xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/><a:chOff x=\"0\" y=\"0\"/><a:chExt cx=\"0\" cy=\"0\"/></a:xfrm></p:grpSpPr>");
    let mut sid = 2u32;
    for (ei, elem) in slide.elements.iter().enumerate() {
        match elem {
            SlideElement::Title(text) => {
                xml.push_str(&build_pptx_text_sp(sid, "Title", sw/12, sh/8, sw*10/12, sh/4, &xml_escape(text), 4400, true, "000000", "ctr"));
                sid += 1;
            }
            SlideElement::Subtitle(text) => {
                xml.push_str(&build_pptx_text_sp(sid, "Subtitle", sw/6, sh*45/100, sw*4/6, sh/5, &xml_escape(text), 2400, false, "595959", "ctr"));
                sid += 1;
            }
            SlideElement::TextBox { text, x, y, width, height, font_size, bold, color } => {
                xml.push_str(&build_pptx_text_sp(sid, "TextBox", *x, *y, *width, *height, &xml_escape(text), (*font_size as i64)*100, *bold, color, "t"));
                sid += 1;
            }
            SlideElement::BulletList(items) => {
                xml.push_str(&build_pptx_list_sp(sid, "BulletList", sw/12, sh/4, sw*10/12, sh*5/8, items, false));
                sid += 1;
            }
            SlideElement::NumberedList(items) => {
                xml.push_str(&build_pptx_list_sp(sid, "NumberedList", sw/12, sh/4, sw*10/12, sh*5/8, items, true));
                sid += 1;
            }
            SlideElement::Table { headers, rows, x, y, width, height } => {
                xml.push_str(&build_pptx_table_sp(sid, *x, *y, *width, *height, headers, rows));
                sid += 1;
            }
            SlideElement::Image { x, y, width, height, .. } => {
                if let Some(&(_, rid)) = img_rid_map.iter().find(|(idx, _)| *idx == ei) {
                    xml.push_str(&build_pptx_pic_sp(sid, *x, *y, *width, *height, rid));
                    sid += 1;
                }
            }
        }
    }
    xml.push_str("</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>");
    xml
}

fn build_pptx_text_sp(id: u32, name: &str, x: i64, y: i64, cx: i64, cy: i64, text: &str, sz: i64, bold: bool, color: &str, anchor: &str) -> String {
    let algn = match anchor { "ctr" => "ctr", "r" => "r", _ => "l" };
    let rpr = if bold {
        format!("<a:rPr lang=\"en-US\" sz=\"{}\" b=\"1\" dirty=\"0\"><a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill></a:rPr>", sz, color)
    } else {
        format!("<a:rPr lang=\"en-US\" sz=\"{}\" dirty=\"0\"><a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill></a:rPr>", sz, color)
    };
    format!("<p:sp><p:nvSpPr><p:cNvPr id=\"{id}\" name=\"{n}\"/><p:cNvSpPr><a:spLocks noGrp=\"1\"/></p:cNvSpPr><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x=\"{x}\" y=\"{y}\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom><a:noFill/></p:spPr><p:txBody><a:bodyPr anchor=\"{anchor}\"/><a:lstStyle/><a:p><a:pPr algn=\"{algn}\"/><a:r>{rpr}<a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp>", id=id, n=xml_escape(name), x=x, y=y, cx=cx, cy=cy, anchor=anchor, algn=algn, rpr=rpr, text=text)
}

fn build_pptx_list_sp(id: u32, name: &str, x: i64, y: i64, cx: i64, cy: i64, items: &[String], numbered: bool) -> String {
    let mut xml = format!("<p:sp><p:nvSpPr><p:cNvPr id=\"{id}\" name=\"{n}\"/><p:cNvSpPr><a:spLocks noGrp=\"1\"/></p:cNvSpPr><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x=\"{x}\" y=\"{y}\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom><a:noFill/></p:spPr><p:txBody><a:bodyPr/><a:lstStyle/>", id=id, n=xml_escape(name), x=x, y=y, cx=cx, cy=cy);
    for item in items {
        let bu = if numbered { "<a:buAutoNum type=\"arabicPeriod\"/>" } else { "<a:buChar char=\"\u{2022}\"/>" };
        xml.push_str(&format!("<a:p><a:pPr marL=\"342900\" indent=\"-342900\">{bu}</a:pPr><a:r><a:rPr lang=\"en-US\" sz=\"2000\" dirty=\"0\"/><a:t>{}</a:t></a:r></a:p>", xml_escape(item)));
    }
    xml.push_str("</p:txBody></p:sp>");
    xml
}

fn build_pptx_table_sp(id: u32, x: i64, y: i64, cx: i64, cy: i64, headers: &[String], rows: &[Vec<String>]) -> String {
    let ncols = if !headers.is_empty() { headers.len() } else if !rows.is_empty() { rows[0].len() } else { 1 };
    let nrows = (if headers.is_empty() { 0 } else { 1 }) + rows.len();
    let cw = if ncols > 0 { cx / ncols as i64 } else { cx };
    let rh = if nrows > 0 { cy / nrows as i64 } else { cy };
    let bdr = "<a:lnL w=\"12700\"><a:solidFill><a:srgbClr val=\"000000\"/></a:solidFill></a:lnL><a:lnR w=\"12700\"><a:solidFill><a:srgbClr val=\"000000\"/></a:solidFill></a:lnR><a:lnT w=\"12700\"><a:solidFill><a:srgbClr val=\"000000\"/></a:solidFill></a:lnT><a:lnB w=\"12700\"><a:solidFill><a:srgbClr val=\"000000\"/></a:solidFill></a:lnB>";
    let mut xml = format!("<p:graphicFrame><p:nvGraphicFramePr><p:cNvPr id=\"{id}\" name=\"Table{id}\"/><p:cNvGraphicFramePr><a:graphicFrameLocks noGrp=\"1\"/></p:cNvGraphicFramePr><p:nvPr/></p:nvGraphicFramePr><p:xfrm><a:off x=\"{x}\" y=\"{y}\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></p:xfrm><a:graphic><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/table\"><a:tbl><a:tblPr firstRow=\"1\" bandRow=\"1\"><a:noFill/></a:tblPr><a:tblGrid>", id=id, x=x, y=y, cx=cx, cy=cy);
    for _ in 0..ncols { xml.push_str(&format!("<a:gridCol w=\"{cw}\"/>")); }
    xml.push_str("</a:tblGrid>");
    if !headers.is_empty() {
        xml.push_str(&format!("<a:tr h=\"{rh}\">"));
        for h in headers {
            xml.push_str(&format!("<a:tc><a:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang=\"en-US\" sz=\"1800\" b=\"1\" dirty=\"0\"/><a:t>{}</a:t></a:r></a:p></a:txBody><a:tcPr><a:solidFill><a:srgbClr val=\"D9E2F3\"/></a:solidFill>{bdr}</a:tcPr></a:tc>", xml_escape(h)));
        }
        xml.push_str("</a:tr>");
    }
    for row in rows {
        xml.push_str(&format!("<a:tr h=\"{rh}\">"));
        for c in row {
            xml.push_str(&format!("<a:tc><a:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang=\"en-US\" sz=\"1600\" dirty=\"0\"/><a:t>{}</a:t></a:r></a:p></a:txBody><a:tcPr>{bdr}</a:tcPr></a:tc>", xml_escape(c)));
        }
        xml.push_str("</a:tr>");
    }
    xml.push_str("</a:tbl></a:graphicData></a:graphic></p:graphicFrame>");
    xml
}

fn build_pptx_pic_sp(id: u32, x: i64, y: i64, cx: i64, cy: i64, rid: usize) -> String {
    format!("<p:pic><p:nvPicPr><p:cNvPr id=\"{id}\" name=\"Image{id}\"/><p:cNvPicPr><a:picLocks noChangeAspect=\"1\"/></p:cNvPicPr><p:nvPr/></p:nvPicPr><p:blipFill><a:blip r:embed=\"rId{rid}\"/><a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr><a:xfrm><a:off x=\"{x}\" y=\"{y}\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></p:spPr></p:pic>", id=id, rid=rid, x=x, y=y, cx=cx, cy=cy)
}

fn build_pptx_theme() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<a:theme xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" name=\"TallowTheme\"><a:themeElements><a:clrScheme name=\"Tallow\"><a:dk1><a:srgbClr val=\"000000\"/></a:dk1><a:lt1><a:srgbClr val=\"FFFFFF\"/></a:lt1><a:dk2><a:srgbClr val=\"1F497D\"/></a:dk2><a:lt2><a:srgbClr val=\"EEECE1\"/></a:lt2><a:accent1><a:srgbClr val=\"4472C4\"/></a:accent1><a:accent2><a:srgbClr val=\"ED7D31\"/></a:accent2><a:accent3><a:srgbClr val=\"A5A5A5\"/></a:accent3><a:accent4><a:srgbClr val=\"FFC000\"/></a:accent4><a:accent5><a:srgbClr val=\"5B9BD5\"/></a:accent5><a:accent6><a:srgbClr val=\"70AD47\"/></a:accent6><a:hlink><a:srgbClr val=\"0563C1\"/></a:hlink><a:folHlink><a:srgbClr val=\"954F72\"/></a:folHlink></a:clrScheme><a:fontScheme name=\"Tallow\"><a:majorFont><a:latin typeface=\"Calibri\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:majorFont><a:minorFont><a:latin typeface=\"Calibri\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:minorFont></a:fontScheme><a:fmtScheme name=\"Tallow\"><a:fillStyleLst><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w=\"9525\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln><a:ln w=\"25400\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln><a:ln w=\"38100\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements></a:theme>".to_string()
}

fn build_pptx_slide_master() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<p:sldMaster xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"><p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val=\"FFFFFF\"/></a:solidFill><a:effectLst/></p:bgPr></p:bg><p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/><a:chOff x=\"0\" y=\"0\"/><a:chExt cx=\"0\" cy=\"0\"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld><p:clrMap bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" accent1=\"accent1\" accent2=\"accent2\" accent3=\"accent3\" accent4=\"accent4\" accent5=\"accent5\" accent6=\"accent6\" hlink=\"hlink\" folHlink=\"folHlink\"/><p:sldLayoutIdLst><p:sldLayoutId id=\"2147483649\" r:id=\"rId1\"/></p:sldLayoutIdLst></p:sldMaster>".to_string()
}

fn build_pptx_slide_layout() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<p:sldLayout xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" type=\"blank\"><p:cSld name=\"Blank\"><p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/><a:chOff x=\"0\" y=\"0\"/><a:chExt cx=\"0\" cy=\"0\"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>".to_string()
}

/// Create a PPTX report from structured data.
pub fn create_pptx_report(title: &str, slides_data: &[(String, Vec<String>)]) -> Result<Vec<u8>, String> {
    let mut pres = PptxPresentation::new(title);
    let ts = pres.add_slide(SlideLayout::TitleSlide);
    ts.add_title(title);
    for (stitle, items) in slides_data {
        let s = pres.add_slide(SlideLayout::TitleContent);
        s.add_title(stitle);
        if !items.is_empty() { s.add_bullet_list(items); }
    }
    pres.to_bytes()
}


// ═══════════════════════════════════════════════════════════════════════════
// Part 3: Dispatch Integration
// ═══════════════════════════════════════════════════════════════════════════

/// Dispatch a `tallow.docs.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // ── Excel ──
        "excel_create" => Some(dispatch_excel_create(args)),
        "excel_add_sheet" => Some(dispatch_excel_add_sheet(args)),
        "excel_add_header" => Some(dispatch_excel_add_header(args)),
        "excel_add_row" => Some(dispatch_excel_add_row(args)),
        "excel_add_formula" => Some(dispatch_excel_add_formula(args)),
        "excel_set_cell_format" => Some(dispatch_excel_set_cell_format(args)),
        "excel_set_col_width" => Some(dispatch_excel_set_col_width(args)),
        "excel_set_row_height" => Some(dispatch_excel_set_row_height(args)),
        "excel_freeze_panes" => Some(dispatch_excel_freeze_panes(args)),
        "excel_merge_cells" => Some(dispatch_excel_merge_cells(args)),
        "excel_auto_filter" => Some(dispatch_excel_auto_filter(args)),
        "excel_add_hyperlink" => Some(dispatch_excel_add_hyperlink(args)),
        "excel_save" => Some(dispatch_excel_save(args)),
        "excel_to_bytes" => Some(dispatch_excel_to_bytes(args)),

        // ── Word ──
        "word_create" => Some(dispatch_word_create(args)),
        "word_add_heading" => Some(dispatch_word_add_heading(args)),
        "word_add_paragraph" => Some(dispatch_word_add_paragraph(args)),
        "word_add_bold" => Some(dispatch_word_add_bold(args)),
        "word_add_italic" => Some(dispatch_word_add_italic(args)),
        "word_add_underline" => Some(dispatch_word_add_underline(args)),
        "word_add_strikethrough" => Some(dispatch_word_add_strikethrough(args)),
        "word_add_superscript" => Some(dispatch_word_add_superscript(args)),
        "word_add_subscript" => Some(dispatch_word_add_subscript(args)),
        "word_add_aligned" => Some(dispatch_word_add_aligned(args)),
        "word_add_table" => Some(dispatch_word_add_table(args)),
        "word_add_bullet_list" => Some(dispatch_word_add_bullet_list(args)),
        "word_add_numbered_list" => Some(dispatch_word_add_numbered_list(args)),
        "word_add_page_break" => Some(dispatch_word_add_page_break(args)),
        "word_add_link" => Some(dispatch_word_add_link(args)),
        "word_add_image" => Some(dispatch_word_add_image(args)),
        "word_add_toc" => Some(dispatch_word_add_toc(args)),
        "word_set_margins" => Some(dispatch_word_set_margins(args)),
        "word_set_page_size" => Some(dispatch_word_set_page_size(args)),
        "word_set_header" => Some(dispatch_word_set_header(args)),
        "word_set_footer" => Some(dispatch_word_set_footer(args)),
        "word_save" => Some(dispatch_word_save(args)),
        "word_to_bytes" => Some(dispatch_word_to_bytes(args)),

        // ── Convenience ──
        "csv_to_excel" => Some(dispatch_csv_to_excel(args)),
        "json_to_excel" => Some(dispatch_json_to_excel(args)),
        "excel_report" => Some(dispatch_excel_report(args)),
        "markdown_to_word" => Some(dispatch_markdown_to_word(args)),
        "word_report" => Some(dispatch_word_report(args)),

        // ── Report Templates ──
        "price_comparison_report" => Some(dispatch_price_comparison_report(args)),
        "product_catalog" => Some(dispatch_product_catalog(args)),
        "intel_report" => Some(dispatch_intel_report(args)),
        "market_report" => Some(dispatch_market_report(args)),

        // ── CSV ──
        "csv_write" => Some(dispatch_csv_write(args)),
        "csv_from_json" => Some(dispatch_csv_from_json(args)),
        "csv_from_records" => Some(dispatch_csv_from_records(args)),
        "csv_append" => Some(dispatch_csv_append(args)),
        "csv_to_string" => Some(dispatch_csv_to_string(args)),

        // ── PowerPoint ──
        "pptx_create" => Some(dispatch_pptx_create(args)),
        "pptx_add_slide" => Some(dispatch_pptx_add_slide(args)),
        "pptx_add_title" => Some(dispatch_pptx_add_title(args)),
        "pptx_add_subtitle" => Some(dispatch_pptx_add_subtitle(args)),
        "pptx_add_text" => Some(dispatch_pptx_add_text(args)),
        "pptx_add_bullets" => Some(dispatch_pptx_add_bullets(args)),
        "pptx_add_table" => Some(dispatch_pptx_add_table(args)),
        "pptx_save" => Some(dispatch_pptx_save(args)),
        "pptx_to_bytes" => Some(dispatch_pptx_to_bytes(args)),
        "pptx_report" => Some(dispatch_pptx_report(args)),

        // ── PDF ──
        "pdf_create" => Some(dispatch_pdf_create(args)),
        "pdf_add_heading" => Some(dispatch_pdf_add_heading(args)),
        "pdf_add_paragraph" => Some(dispatch_pdf_add_paragraph(args)),
        "pdf_add_bold" => Some(dispatch_pdf_add_bold(args)),
        "pdf_add_table" => Some(dispatch_pdf_add_table(args)),
        "pdf_add_bullets" => Some(dispatch_pdf_add_bullets(args)),
        "pdf_add_numbered_list" => Some(dispatch_pdf_add_numbered_list(args)),
        "pdf_add_horizontal_rule" => Some(dispatch_pdf_add_horizontal_rule(args)),
        "pdf_add_spacer" => Some(dispatch_pdf_add_spacer(args)),
        "pdf_add_page_break" => Some(dispatch_pdf_add_page_break(args)),
        "pdf_save" => Some(dispatch_pdf_save(args)),
        "pdf_to_bytes" => Some(dispatch_pdf_to_bytes(args)),
        "pdf_report" => Some(dispatch_pdf_report(args)),

        _ => None,
    }
}

/// Dispatch a method call on a docs object.
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

// ── Helper: convert Value to a Vec<String> ──

fn value_to_string_vec(val: &Value) -> Vec<String> {
    match val {
        Value::Array(items) => items.iter().map(|v| v.as_string()).collect(),
        _ => vec![val.as_string()],
    }
}

fn value_to_string_vec_vec(val: &Value) -> Vec<Vec<String>> {
    match val {
        Value::Array(items) => items.iter().map(value_to_string_vec).collect(),
        _ => vec![value_to_string_vec(val)],
    }
}

fn require_string(args: &[Value], index: usize, fn_name: &str) -> Result<String, String> {
    args.get(index)
        .map(|v| v.as_string())
        .ok_or_else(|| format!("docs.{fn_name}: missing string argument at position {index}"))
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ── Excel dispatch functions ──

/// `docs.excel_create()` -> ExcelWorkbook as a struct
fn dispatch_excel_create(_args: Vec<Value>) -> StdlibResult {
    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(vec![]))],
    })
}

/// `docs.excel_add_sheet(workbook, name)` -> updated workbook
fn dispatch_excel_add_sheet(args: Vec<Value>) -> StdlibResult {
    let name = require_string(&args, 1, "excel_add_sheet")?;
    let wb = args.first().ok_or("docs.excel_add_sheet: missing workbook")?;

    let mut sheets = extract_sheets(wb);
    sheets.push(Value::Struct {
        name: "ExcelSheet".to_string(),
        fields: vec![
            ("name".to_string(), Value::String(name)),
            ("rows".to_string(), Value::Array(vec![])),
            ("header_rows".to_string(), Value::Array(vec![])),
            ("cell_formats".to_string(), Value::Array(vec![])),
            ("col_widths".to_string(), Value::Array(vec![])),
            ("row_heights".to_string(), Value::Array(vec![])),
            ("freeze_row".to_string(), Value::Nil),
            ("freeze_col".to_string(), Value::Nil),
            ("merges".to_string(), Value::Array(vec![])),
            ("auto_filter".to_string(), Value::Nil),
            ("hyperlinks".to_string(), Value::Array(vec![])),
        ],
    });

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_add_header(workbook, sheet_index, headers_array)` -> updated workbook
fn dispatch_excel_add_header(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let headers = args.get(2).map(value_to_string_vec).unwrap_or_default();

    let wb = args.first().ok_or("docs.excel_add_header: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_add_header: sheet index {sheet_idx} out of range"));
    }

    // Get current rows and header_rows from the sheet
    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        let row_idx = get_rows(fields).len();
        // Add the row
        let row_value = Value::Array(
            headers.iter().map(|h| Value::String(h.clone())).collect(),
        );
        push_row(fields, row_value);
        // Mark as header row
        push_header_row(fields, Value::Int(row_idx as i128));
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_add_row(workbook, sheet_index, cells_array)` -> updated workbook
fn dispatch_excel_add_row(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let cells = args.get(2).cloned().unwrap_or(Value::Array(vec![]));

    let wb = args.first().ok_or("docs.excel_add_row: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_add_row: sheet index {sheet_idx} out of range"));
    }

    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        let row_value = match &cells {
            Value::Array(items) => Value::Array(items.clone()),
            _ => Value::Array(vec![cells]),
        };
        push_row(fields, row_value);
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_add_formula(workbook, sheet_index, cell_ref, formula)` -> updated workbook
fn dispatch_excel_add_formula(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let cell = require_string(&args, 2, "excel_add_formula")?;
    let formula = require_string(&args, 3, "excel_add_formula")?;

    let wb = args.first().ok_or("docs.excel_add_formula: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_add_formula: sheet index {sheet_idx} out of range"));
    }

    // Parse cell ref to row/col
    let (row, col) = parse_cell_ref(&cell)
        .ok_or_else(|| format!("docs.excel_add_formula: invalid cell ref '{cell}'"))?;

    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        // Ensure enough rows exist
        let current_rows = get_rows(fields);
        let needed = row + 1;
        if current_rows.len() < needed {
            for _ in current_rows.len()..needed {
                push_row(fields, Value::Array(vec![]));
            }
        }

        // Set the cell value with a formula marker
        // We store formulas as a struct with type="formula"
        for (k, v) in fields.iter_mut() {
            if k == "rows" {
                if let Value::Array(rows) = v {
                    if row < rows.len() {
                        if let Value::Array(cells) = &mut rows[row] {
                            while cells.len() <= col {
                                cells.push(Value::Nil);
                            }
                            cells[col] = Value::Struct {
                                name: "Formula".to_string(),
                                fields: vec![("formula".to_string(), Value::String(formula.clone()))],
                            };
                        }
                    }
                }
                break;
            }
        }
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_set_cell_format(workbook, sheet_index, row, col, format_struct)` -> updated workbook
fn dispatch_excel_set_cell_format(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let row = args.get(2).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let col = args.get(3).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let fmt_val = args.get(4).cloned().unwrap_or(Value::Nil);

    let wb = args.first().ok_or("docs.excel_set_cell_format: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_set_cell_format: sheet index {sheet_idx} out of range"));
    }

    // Store the format as a struct in cell_formats
    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        let fmt_entry = Value::Array(vec![
            Value::Int(row as i128),
            Value::Int(col as i128),
            fmt_val,
        ]);
        for (k, v) in fields.iter_mut() {
            if k == "cell_formats" {
                if let Value::Array(fmts) = v {
                    fmts.push(fmt_entry);
                }
                break;
            }
        }
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_set_col_width(workbook, sheet_index, col, width)` -> updated workbook
fn dispatch_excel_set_col_width(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let col = args.get(2).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let width = args.get(3).map(|v| match v { Value::Float(f) => *f, Value::Int(i) => *i as f64, _ => v.as_string().parse::<f64>().unwrap_or(10.0) }).unwrap_or(10.0);

    let wb = args.first().ok_or("docs.excel_set_col_width: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_set_col_width: sheet index {sheet_idx} out of range"));
    }

    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        let entry = Value::Array(vec![Value::Int(col as i128), Value::Float(width)]);
        for (k, v) in fields.iter_mut() {
            if k == "col_widths" {
                if let Value::Array(widths) = v {
                    widths.push(entry);
                }
                break;
            }
        }
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_set_row_height(workbook, sheet_index, row, height)` -> updated workbook
fn dispatch_excel_set_row_height(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let row = args.get(2).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let height = args.get(3).map(|v| match v { Value::Float(f) => *f, Value::Int(i) => *i as f64, _ => v.as_string().parse::<f64>().unwrap_or(15.0) }).unwrap_or(15.0);

    let wb = args.first().ok_or("docs.excel_set_row_height: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_set_row_height: sheet index {sheet_idx} out of range"));
    }

    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        let entry = Value::Array(vec![Value::Int(row as i128), Value::Float(height)]);
        for (k, v) in fields.iter_mut() {
            if k == "row_heights" {
                if let Value::Array(heights) = v {
                    heights.push(entry);
                }
                break;
            }
        }
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_freeze_panes(workbook, sheet_index, freeze_row, freeze_col)` -> updated workbook
fn dispatch_excel_freeze_panes(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let fr = args.get(2).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let fc = args.get(3).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);

    let wb = args.first().ok_or("docs.excel_freeze_panes: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_freeze_panes: sheet index {sheet_idx} out of range"));
    }

    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        for (k, v) in fields.iter_mut() {
            if k == "freeze_row" {
                *v = if fr > 0 { Value::Int(fr as i128) } else { Value::Nil };
            }
            if k == "freeze_col" {
                *v = if fc > 0 { Value::Int(fc as i128) } else { Value::Nil };
            }
        }
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_merge_cells(workbook, sheet_index, start_ref, end_ref)` -> updated workbook
fn dispatch_excel_merge_cells(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let start = require_string(&args, 2, "excel_merge_cells")?;
    let end = require_string(&args, 3, "excel_merge_cells")?;

    let wb = args.first().ok_or("docs.excel_merge_cells: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_merge_cells: sheet index {sheet_idx} out of range"));
    }

    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        let merge = Value::Array(vec![Value::String(start), Value::String(end)]);
        for (k, v) in fields.iter_mut() {
            if k == "merges" {
                if let Value::Array(merges) = v {
                    merges.push(merge);
                }
                break;
            }
        }
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_auto_filter(workbook, sheet_index, range)` -> updated workbook
fn dispatch_excel_auto_filter(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let range = require_string(&args, 2, "excel_auto_filter")?;

    let wb = args.first().ok_or("docs.excel_auto_filter: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_auto_filter: sheet index {sheet_idx} out of range"));
    }

    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        for (k, v) in fields.iter_mut() {
            if k == "auto_filter" {
                *v = Value::String(range.clone());
                break;
            }
        }
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_add_hyperlink(workbook, sheet_index, cell_ref, display_text, url)` -> updated workbook
fn dispatch_excel_add_hyperlink(args: Vec<Value>) -> StdlibResult {
    let sheet_idx = args.get(1).map(|v| v.as_string().parse::<usize>().unwrap_or(0)).unwrap_or(0);
    let cell = require_string(&args, 2, "excel_add_hyperlink")?;
    let display = require_string(&args, 3, "excel_add_hyperlink")?;
    let url = require_string(&args, 4, "excel_add_hyperlink")?;

    let wb = args.first().ok_or("docs.excel_add_hyperlink: missing workbook")?;
    let mut sheets = extract_sheets(wb);

    if sheet_idx >= sheets.len() {
        return Err(format!("docs.excel_add_hyperlink: sheet index {sheet_idx} out of range"));
    }

    // Set the cell text and add hyperlink
    let (row, col) = parse_cell_ref(&cell)
        .ok_or_else(|| format!("docs.excel_add_hyperlink: invalid cell ref '{cell}'"))?;

    if let Value::Struct { fields, .. } = &mut sheets[sheet_idx] {
        // Ensure enough rows
        let current_rows_len = get_rows(fields).len();
        if current_rows_len <= row {
            for _ in current_rows_len..=row {
                push_row(fields, Value::Array(vec![]));
            }
        }

        // Set cell text
        for (k, v) in fields.iter_mut() {
            if k == "rows" {
                if let Value::Array(rows) = v {
                    if row < rows.len() {
                        if let Value::Array(cells) = &mut rows[row] {
                            while cells.len() <= col {
                                cells.push(Value::Nil);
                            }
                            cells[col] = Value::String(display.clone());
                        }
                    }
                }
            }
            if k == "hyperlinks" {
                if let Value::Array(links) = v {
                    links.push(Value::Array(vec![
                        Value::String(cell.clone()),
                        Value::String(url.clone()),
                    ]));
                }
            }
        }
    }

    Ok(Value::Struct {
        name: "ExcelWorkbook".to_string(),
        fields: vec![("sheets".to_string(), Value::Array(sheets))],
    })
}

/// `docs.excel_save(workbook, path)` -> Ok or Err
fn dispatch_excel_save(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 1, "excel_save")?;
    let wb = args.first().ok_or("docs.excel_save: missing workbook")?;
    let workbook = value_to_excel_workbook(wb)?;
    workbook.save(&path)?;
    Ok(Value::String(format!("saved to {path}")))
}

/// `docs.excel_to_bytes(workbook)` -> base64 string
fn dispatch_excel_to_bytes(args: Vec<Value>) -> StdlibResult {
    let wb = args.first().ok_or("docs.excel_to_bytes: missing workbook")?;
    let workbook = value_to_excel_workbook(wb)?;
    let bytes = workbook.to_bytes()?;
    Ok(Value::String(b64_encode(&bytes)))
}

// ── Word dispatch functions ──

/// `docs.word_create()` -> WordDocument as a struct
fn dispatch_word_create(_args: Vec<Value>) -> StdlibResult {
    Ok(Value::Struct {
        name: "WordDocument".to_string(),
        fields: vec![
            ("elements".to_string(), Value::Array(vec![])),
            ("page_width".to_string(), Value::Int(12240)),
            ("page_height".to_string(), Value::Int(15840)),
            ("margin_top".to_string(), Value::Int(1440)),
            ("margin_bottom".to_string(), Value::Int(1440)),
            ("margin_left".to_string(), Value::Int(1440)),
            ("margin_right".to_string(), Value::Int(1440)),
            ("header_text".to_string(), Value::Nil),
            ("footer_text".to_string(), Value::Nil),
        ],
    })
}

/// `docs.word_add_heading(doc, text, level)` -> updated doc
fn dispatch_word_add_heading(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_heading")?;
    let level = args.get(2).map(|v| v.as_string().parse::<u8>().unwrap_or(1)).unwrap_or(1);

    let doc = args.first().ok_or("docs.word_add_heading: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("heading".to_string())),
            ("text".to_string(), Value::String(text)),
            ("level".to_string(), Value::Int(level as i128)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_paragraph(doc, text)` -> updated doc
fn dispatch_word_add_paragraph(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_paragraph")?;
    let doc = args.first().ok_or("docs.word_add_paragraph: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("paragraph".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_bold(doc, text)` -> updated doc
fn dispatch_word_add_bold(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_bold")?;
    let doc = args.first().ok_or("docs.word_add_bold: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("bold".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_italic(doc, text)` -> updated doc
fn dispatch_word_add_italic(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_italic")?;
    let doc = args.first().ok_or("docs.word_add_italic: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("italic".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_underline(doc, text)` -> updated doc
fn dispatch_word_add_underline(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_underline")?;
    let doc = args.first().ok_or("docs.word_add_underline: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("underline".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_strikethrough(doc, text)` -> updated doc
fn dispatch_word_add_strikethrough(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_strikethrough")?;
    let doc = args.first().ok_or("docs.word_add_strikethrough: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("strikethrough".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_superscript(doc, text)` -> updated doc
fn dispatch_word_add_superscript(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_superscript")?;
    let doc = args.first().ok_or("docs.word_add_superscript: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("superscript".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_subscript(doc, text)` -> updated doc
fn dispatch_word_add_subscript(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_subscript")?;
    let doc = args.first().ok_or("docs.word_add_subscript: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("subscript".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_aligned(doc, text, alignment)` -> updated doc
fn dispatch_word_add_aligned(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_aligned")?;
    let alignment = require_string(&args, 2, "word_add_aligned")?;
    let doc = args.first().ok_or("docs.word_add_aligned: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("aligned".to_string())),
            ("text".to_string(), Value::String(text)),
            ("alignment".to_string(), Value::String(alignment)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_table(doc, headers_array, rows_array)` -> updated doc
fn dispatch_word_add_table(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.word_add_table: missing document")?;
    let headers = args.get(1).map(value_to_string_vec).unwrap_or_default();
    let rows = args.get(2).map(value_to_string_vec_vec).unwrap_or_default();

    let mut elements = extract_elements(doc);

    let rows_value = Value::Array(
        rows.into_iter()
            .map(|r| Value::Array(r.into_iter().map(Value::String).collect()))
            .collect(),
    );

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("table".to_string())),
            (
                "headers".to_string(),
                Value::Array(headers.into_iter().map(Value::String).collect()),
            ),
            ("rows".to_string(), rows_value),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_bullet_list(doc, items_array)` -> updated doc
fn dispatch_word_add_bullet_list(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.word_add_bullet_list: missing document")?;
    let items = args.get(1).map(value_to_string_vec).unwrap_or_default();
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("bullet_list".to_string())),
            (
                "items".to_string(),
                Value::Array(items.into_iter().map(Value::String).collect()),
            ),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_numbered_list(doc, items_array)` -> updated doc
fn dispatch_word_add_numbered_list(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.word_add_numbered_list: missing document")?;
    let items = args.get(1).map(value_to_string_vec).unwrap_or_default();
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("numbered_list".to_string())),
            (
                "items".to_string(),
                Value::Array(items.into_iter().map(Value::String).collect()),
            ),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_page_break(doc)` -> updated doc
fn dispatch_word_add_page_break(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.word_add_page_break: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![("type".to_string(), Value::String("page_break".to_string()))],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_link(doc, text, url)` -> updated doc
fn dispatch_word_add_link(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "word_add_link")?;
    let url = require_string(&args, 2, "word_add_link")?;
    let doc = args.first().ok_or("docs.word_add_link: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("link".to_string())),
            ("text".to_string(), Value::String(text)),
            ("url".to_string(), Value::String(url)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_image(doc, base64_data, width_cm, height_cm, alt_text)` -> updated doc
fn dispatch_word_add_image(args: Vec<Value>) -> StdlibResult {
    let data_b64 = require_string(&args, 1, "word_add_image")?;
    let width = args.get(2).map(|v| match v { Value::Float(f) => *f, Value::Int(i) => *i as f64, _ => v.as_string().parse::<f64>().unwrap_or(10.0) }).unwrap_or(10.0);
    let height = args.get(3).map(|v| match v { Value::Float(f) => *f, Value::Int(i) => *i as f64, _ => v.as_string().parse::<f64>().unwrap_or(10.0) }).unwrap_or(10.0);
    let alt = args.get(4).map(|v| v.as_string()).unwrap_or_default();

    let doc = args.first().ok_or("docs.word_add_image: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("image".to_string())),
            ("data".to_string(), Value::String(data_b64)),
            ("width_cm".to_string(), Value::Float(width)),
            ("height_cm".to_string(), Value::Float(height)),
            ("alt_text".to_string(), Value::String(alt)),
        ],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_add_toc(doc)` -> updated doc
fn dispatch_word_add_toc(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.word_add_toc: missing document")?;
    let mut elements = extract_elements(doc);

    elements.push(Value::Struct {
        name: "DocElement".to_string(),
        fields: vec![("type".to_string(), Value::String("toc".to_string()))],
    });

    Ok(rebuild_word_doc(doc, elements))
}

/// `docs.word_set_margins(doc, top, right, bottom, left)` -> updated doc
fn dispatch_word_set_margins(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.word_set_margins: missing document")?;
    let top = args.get(1).map(|v| v.as_string().parse::<i128>().unwrap_or(1440)).unwrap_or(1440);
    let right = args.get(2).map(|v| v.as_string().parse::<i128>().unwrap_or(1440)).unwrap_or(1440);
    let bottom = args.get(3).map(|v| v.as_string().parse::<i128>().unwrap_or(1440)).unwrap_or(1440);
    let left = args.get(4).map(|v| v.as_string().parse::<i128>().unwrap_or(1440)).unwrap_or(1440);

    let elements = extract_elements(doc);
    let mut new_doc = rebuild_word_doc(doc, elements);
    if let Value::Struct { fields, .. } = &mut new_doc {
        for (k, v) in fields.iter_mut() {
            match k.as_str() {
                "margin_top" => *v = Value::Int(top),
                "margin_right" => *v = Value::Int(right),
                "margin_bottom" => *v = Value::Int(bottom),
                "margin_left" => *v = Value::Int(left),
                _ => {}
            }
        }
    }
    Ok(new_doc)
}

/// `docs.word_set_page_size(doc, width, height)` -> updated doc
fn dispatch_word_set_page_size(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.word_set_page_size: missing document")?;
    let width = args.get(1).map(|v| v.as_string().parse::<i128>().unwrap_or(12240)).unwrap_or(12240);
    let height = args.get(2).map(|v| v.as_string().parse::<i128>().unwrap_or(15840)).unwrap_or(15840);

    let elements = extract_elements(doc);
    let mut new_doc = rebuild_word_doc(doc, elements);
    if let Value::Struct { fields, .. } = &mut new_doc {
        for (k, v) in fields.iter_mut() {
            match k.as_str() {
                "page_width" => *v = Value::Int(width),
                "page_height" => *v = Value::Int(height),
                _ => {}
            }
        }
    }
    Ok(new_doc)
}

/// `docs.word_set_header(doc, text)` -> updated doc
fn dispatch_word_set_header(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.word_set_header: missing document")?;
    let text = require_string(&args, 1, "word_set_header")?;

    let elements = extract_elements(doc);
    let mut new_doc = rebuild_word_doc(doc, elements);
    if let Value::Struct { fields, .. } = &mut new_doc {
        for (k, v) in fields.iter_mut() {
            if k == "header_text" {
                *v = Value::String(text.clone());
            }
        }
    }
    Ok(new_doc)
}

/// `docs.word_set_footer(doc, text)` -> updated doc
fn dispatch_word_set_footer(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.word_set_footer: missing document")?;
    let text = require_string(&args, 1, "word_set_footer")?;

    let elements = extract_elements(doc);
    let mut new_doc = rebuild_word_doc(doc, elements);
    if let Value::Struct { fields, .. } = &mut new_doc {
        for (k, v) in fields.iter_mut() {
            if k == "footer_text" {
                *v = Value::String(text.clone());
            }
        }
    }
    Ok(new_doc)
}

/// `docs.word_save(doc, path)` -> Ok or Err
fn dispatch_word_save(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 1, "word_save")?;
    let doc_val = args.first().ok_or("docs.word_save: missing document")?;
    let doc = value_to_word_document(doc_val)?;
    doc.save(&path)?;
    Ok(Value::String(format!("saved to {path}")))
}

/// `docs.word_to_bytes(doc)` -> base64 string
fn dispatch_word_to_bytes(args: Vec<Value>) -> StdlibResult {
    let doc_val = args.first().ok_or("docs.word_to_bytes: missing document")?;
    let doc = value_to_word_document(doc_val)?;
    let bytes = doc.to_bytes()?;
    Ok(Value::String(b64_encode(&bytes)))
}

/// `docs.csv_to_excel(csv_string, sheet_name)` -> base64 xlsx bytes
fn dispatch_csv_to_excel(args: Vec<Value>) -> StdlibResult {
    let csv = require_string(&args, 0, "csv_to_excel")?;
    let name = args.get(1).map(|v| v.as_string()).unwrap_or_else(|| "Sheet1".to_string());
    let bytes = create_excel_from_csv(&csv, &name)?;
    Ok(Value::String(b64_encode(&bytes)))
}

/// `docs.json_to_excel(json_array_string, sheet_name)` -> base64 xlsx bytes
fn dispatch_json_to_excel(args: Vec<Value>) -> StdlibResult {
    let json = require_string(&args, 0, "json_to_excel")?;
    let name = args.get(1).map(|v| v.as_string()).unwrap_or_else(|| "Sheet1".to_string());
    let bytes = create_excel_from_json(&json, &name)?;
    Ok(Value::String(b64_encode(&bytes)))
}

/// `docs.excel_report(title, sections)` -> base64 xlsx bytes
fn dispatch_excel_report(args: Vec<Value>) -> StdlibResult {
    let title = require_string(&args, 0, "excel_report")?;
    let sections_val = args.get(1).ok_or("docs.excel_report: missing sections")?;

    let sections: Vec<(String, Vec<Vec<String>>)> = match sections_val {
        Value::Array(items) => {
            items
                .iter()
                .map(|item| match item {
                    Value::Array(pair) if pair.len() >= 2 => {
                        let name = pair[0].as_string();
                        let rows = value_to_string_vec_vec(&pair[1]);
                        (name, rows)
                    }
                    Value::Struct { fields, .. } => {
                        let name = fields
                            .iter()
                            .find(|(k, _)| k == "name" || k == "title")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        let rows = fields
                            .iter()
                            .find(|(k, _)| k == "rows" || k == "data")
                            .map(|(_, v)| value_to_string_vec_vec(v))
                            .unwrap_or_default();
                        (name, rows)
                    }
                    _ => (item.as_string(), vec![]),
                })
                .collect()
        }
        _ => return Err("docs.excel_report: sections must be an array".to_string()),
    };

    let bytes = create_excel_report(&title, &sections)?;
    Ok(Value::String(b64_encode(&bytes)))
}

/// `docs.markdown_to_word(markdown_string)` -> base64 docx bytes
fn dispatch_markdown_to_word(args: Vec<Value>) -> StdlibResult {
    let md = require_string(&args, 0, "markdown_to_word")?;
    let bytes = create_word_from_markdown(&md)?;
    Ok(Value::String(b64_encode(&bytes)))
}

/// `docs.word_report(title, sections)` -> base64 docx bytes
fn dispatch_word_report(args: Vec<Value>) -> StdlibResult {
    let title = require_string(&args, 0, "word_report")?;
    let sections_val = args.get(1).ok_or("docs.word_report: missing sections")?;

    let sections: Vec<(String, String)> = match sections_val {
        Value::Array(items) => {
            items
                .iter()
                .map(|item| match item {
                    Value::Array(pair) if pair.len() >= 2 => {
                        (pair[0].as_string(), pair[1].as_string())
                    }
                    _ => (item.as_string(), String::new()),
                })
                .collect()
        }
        _ => return Err("docs.word_report: sections must be an array".to_string()),
    };

    let bytes = create_word_report(&title, &sections)?;
    Ok(Value::String(b64_encode(&bytes)))
}

// ── Report template dispatch functions ──

/// Extract a float from a Value.
fn value_to_f64(val: &Value) -> f64 {
    match val {
        Value::Float(f) => *f,
        Value::Int(i) => *i as f64,
        _ => val.as_string().parse::<f64>().unwrap_or(0.0),
    }
}

/// Extract a HashMap<String, f64> from a Value::Map or Value::Struct.
fn value_to_price_map(val: &Value) -> HashMap<String, f64> {
    let mut map = HashMap::new();
    match val {
        Value::Map(pairs) => {
            for (k, v) in pairs {
                map.insert(k.as_string(), value_to_f64(v));
            }
        }
        Value::Struct { fields, .. } => {
            for (k, v) in fields {
                map.insert(k.clone(), value_to_f64(v));
            }
        }
        _ => {}
    }
    map
}

/// Convert a Value (struct or map) into a PriceProduct.
fn value_to_price_product(val: &Value) -> PriceProduct {
    let mut name = String::new();
    let mut category = String::new();
    let mut brand = String::new();
    let mut prices = HashMap::new();

    let extract = |k: &str, v: &Value, name: &mut String, category: &mut String, brand: &mut String, prices: &mut HashMap<String, f64>| {
        match k {
            "name" => *name = v.as_string(),
            "category" => *category = v.as_string(),
            "brand" => *brand = v.as_string(),
            "prices" => *prices = value_to_price_map(v),
            _ => {}
        }
    };

    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            extract(k.as_str(), v, &mut name, &mut category, &mut brand, &mut prices);
        }
    }
    if let Value::Map(pairs) = val {
        for (k, v) in pairs {
            let key = k.as_string();
            extract(&key, v, &mut name, &mut category, &mut brand, &mut prices);
        }
    }

    PriceProduct { name, category, brand, prices }
}

/// Convert a Value (struct or map) into a CatalogProduct.
fn value_to_catalog_product(val: &Value) -> CatalogProduct {
    let mut p = CatalogProduct {
        name: String::new(),
        brand: String::new(),
        category: String::new(),
        price: 0.0,
        unit_price: None,
        size: String::new(),
        upc: String::new(),
        snap_eligible: false,
        store: String::new(),
    };

    let extract = |k: &str, v: &Value, p: &mut CatalogProduct| {
        match k {
            "name" => p.name = v.as_string(),
            "brand" => p.brand = v.as_string(),
            "category" => p.category = v.as_string(),
            "price" => p.price = value_to_f64(v),
            "unit_price" => match v {
                Value::Nil => p.unit_price = None,
                _ => p.unit_price = Some(value_to_f64(v)),
            },
            "size" => p.size = v.as_string(),
            "upc" => p.upc = v.as_string(),
            "snap_eligible" | "snap" => p.snap_eligible = matches!(v, Value::Bool(true)) || v.as_string() == "true",
            "store" => p.store = v.as_string(),
            _ => {}
        }
    };

    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            extract(k.as_str(), v, &mut p);
        }
    }
    if let Value::Map(pairs) = val {
        for (k, v) in pairs {
            let key = k.as_string();
            extract(&key, v, &mut p);
        }
    }

    p
}

/// Convert a Value (struct or map) into an IntelSection.
fn value_to_intel_section(val: &Value) -> IntelSection {
    let mut title = String::new();
    let mut content = String::new();
    let mut table: Option<(Vec<String>, Vec<Vec<String>>)> = None;

    let process = |k: &str, v: &Value, title: &mut String, content: &mut String, table: &mut Option<(Vec<String>, Vec<Vec<String>>)>| {
        match k {
            "title" => *title = v.as_string(),
            "content" => *content = v.as_string(),
            "table" => {
                // Expected: [headers_array, rows_array] or nil
                if !matches!(v, Value::Nil) {
                    if let Value::Array(pair) = v {
                        if pair.len() >= 2 {
                            let headers = value_to_string_vec(&pair[0]);
                            let rows = value_to_string_vec_vec(&pair[1]);
                            *table = Some((headers, rows));
                        }
                    }
                }
            }
            _ => {}
        }
    };

    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            process(k.as_str(), v, &mut title, &mut content, &mut table);
        }
    }
    if let Value::Map(pairs) = val {
        for (k, v) in pairs {
            let key = k.as_string();
            process(&key, v, &mut title, &mut content, &mut table);
        }
    }

    IntelSection { title, content, table }
}

/// Convert a Value (struct or map) into a CategoryStats.
fn value_to_category_stats(val: &Value) -> CategoryStats {
    let mut s = CategoryStats {
        name: String::new(),
        product_count: 0,
        avg_price: 0.0,
        min_price: 0.0,
        max_price: 0.0,
        median_price: 0.0,
    };

    let extract = |k: &str, v: &Value, s: &mut CategoryStats| {
        match k {
            "name" => s.name = v.as_string(),
            "product_count" | "count" => s.product_count = match v { Value::Int(n) => *n as usize, _ => v.as_string().parse().unwrap_or(0) },
            "avg_price" | "avg" => s.avg_price = value_to_f64(v),
            "min_price" | "min" => s.min_price = value_to_f64(v),
            "max_price" | "max" => s.max_price = value_to_f64(v),
            "median_price" | "median" => s.median_price = value_to_f64(v),
            _ => {}
        }
    };

    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            extract(k.as_str(), v, &mut s);
        }
    }
    if let Value::Map(pairs) = val {
        for (k, v) in pairs {
            let key = k.as_string();
            extract(&key, v, &mut s);
        }
    }

    s
}

/// Convert a Value (struct or map) into a MarketReportData.
fn value_to_market_report_data(val: &Value) -> MarketReportData {
    let mut d = MarketReportData {
        title: String::new(),
        date_range: String::new(),
        methodology: String::new(),
        stores: Vec::new(),
        total_products: 0,
        categories: Vec::new(),
        findings: Vec::new(),
    };

    let extract = |k: &str, v: &Value, d: &mut MarketReportData| {
        match k {
            "title" => d.title = v.as_string(),
            "date_range" => d.date_range = v.as_string(),
            "methodology" => d.methodology = v.as_string(),
            "stores" => d.stores = value_to_string_vec(v),
            "total_products" => d.total_products = match v { Value::Int(n) => *n as usize, _ => v.as_string().parse().unwrap_or(0) },
            "categories" => {
                if let Value::Array(items) = v {
                    d.categories = items.iter().map(value_to_category_stats).collect();
                }
            }
            "findings" => d.findings = value_to_string_vec(v),
            _ => {}
        }
    };

    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            extract(k.as_str(), v, &mut d);
        }
    }
    if let Value::Map(pairs) = val {
        for (k, v) in pairs {
            let key = k.as_string();
            extract(&key, v, &mut d);
        }
    }

    d
}

/// `docs.price_comparison_report(path, title, stores, products)` -> Ok or Err
///
/// - path: output file path (.xlsx)
/// - title: report title string
/// - stores: array of store name strings
/// - products: array of structs/maps with {name, category, brand, prices: {store: price}}
fn dispatch_price_comparison_report(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 0, "price_comparison_report")?;
    let title = require_string(&args, 1, "price_comparison_report")?;
    let stores = args.get(2).map(value_to_string_vec)
        .ok_or_else(|| "docs.price_comparison_report: missing stores argument".to_string())?;
    let products_val = args.get(3)
        .ok_or_else(|| "docs.price_comparison_report: missing products argument".to_string())?;

    let products: Vec<PriceProduct> = match products_val {
        Value::Array(items) => items.iter().map(value_to_price_product).collect(),
        _ => return Err("docs.price_comparison_report: products must be an array".to_string()),
    };

    create_price_comparison_report(&path, &title, &stores, &products)?;
    Ok(Value::String(format!("saved to {path}")))
}

/// `docs.product_catalog(path, products)` -> Ok or Err
///
/// - path: output file path (.xlsx)
/// - products: array of structs/maps with catalog product fields
fn dispatch_product_catalog(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 0, "product_catalog")?;
    let products_val = args.get(1)
        .ok_or_else(|| "docs.product_catalog: missing products argument".to_string())?;

    let products: Vec<CatalogProduct> = match products_val {
        Value::Array(items) => items.iter().map(value_to_catalog_product).collect(),
        _ => return Err("docs.product_catalog: products must be an array".to_string()),
    };

    create_product_catalog(&path, &products)?;
    Ok(Value::String(format!("saved to {path}")))
}

/// `docs.intel_report(path, title, sections)` -> Ok or Err
///
/// - path: output file path (.docx)
/// - title: report title string
/// - sections: array of structs/maps with {title, content, table?}
fn dispatch_intel_report(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 0, "intel_report")?;
    let title = require_string(&args, 1, "intel_report")?;
    let sections_val = args.get(2)
        .ok_or_else(|| "docs.intel_report: missing sections argument".to_string())?;

    let sections: Vec<IntelSection> = match sections_val {
        Value::Array(items) => items.iter().map(value_to_intel_section).collect(),
        _ => return Err("docs.intel_report: sections must be an array".to_string()),
    };

    create_intel_report(&path, &title, &sections)?;
    Ok(Value::String(format!("saved to {path}")))
}

/// `docs.market_report(path, data)` -> Ok or Err
///
/// - path: output file path (.docx)
/// - data: struct/map with MarketReportData fields
fn dispatch_market_report(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 0, "market_report")?;
    let data_val = args.get(1)
        .ok_or_else(|| "docs.market_report: missing data argument".to_string())?;

    let data = value_to_market_report_data(data_val);
    create_market_report(&path, &data)?;
    Ok(Value::String(format!("saved to {path}")))
}

// ═══════════════════════════════════════════════════════════════════════════
// Value <-> native type converters
// ═══════════════════════════════════════════════════════════════════════════

/// Extract the `sheets` array from an ExcelWorkbook Value.
fn extract_sheets(val: &Value) -> Vec<Value> {
    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            if k == "sheets" {
                if let Value::Array(items) = v {
                    return items.clone();
                }
            }
        }
    }
    vec![]
}

/// Extract the `elements` array from a WordDocument Value.
fn extract_elements(val: &Value) -> Vec<Value> {
    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            if k == "elements" {
                if let Value::Array(items) = v {
                    return items.clone();
                }
            }
        }
    }
    vec![]
}

/// Rebuild a WordDocument Value with new elements, preserving page settings.
fn rebuild_word_doc(original: &Value, elements: Vec<Value>) -> Value {
    let mut fields = vec![("elements".to_string(), Value::Array(elements))];

    if let Value::Struct { fields: orig_fields, .. } = original {
        for (k, v) in orig_fields {
            if k != "elements" {
                fields.push((k.clone(), v.clone()));
            }
        }
    } else {
        // defaults
        fields.push(("page_width".to_string(), Value::Int(12240)));
        fields.push(("page_height".to_string(), Value::Int(15840)));
        fields.push(("margin_top".to_string(), Value::Int(1440)));
        fields.push(("margin_bottom".to_string(), Value::Int(1440)));
        fields.push(("margin_left".to_string(), Value::Int(1440)));
        fields.push(("margin_right".to_string(), Value::Int(1440)));
        fields.push(("header_text".to_string(), Value::Nil));
        fields.push(("footer_text".to_string(), Value::Nil));
    }

    Value::Struct {
        name: "WordDocument".to_string(),
        fields,
    }
}

/// Get rows from sheet fields (read-only reference for counting).
fn get_rows(fields: &[(String, Value)]) -> Vec<Value> {
    for (k, v) in fields {
        if k == "rows" {
            if let Value::Array(items) = v {
                return items.clone();
            }
        }
    }
    vec![]
}

/// Push a row to the sheet fields.
fn push_row(fields: &mut Vec<(String, Value)>, row: Value) {
    for (k, v) in fields.iter_mut() {
        if k == "rows" {
            if let Value::Array(items) = v {
                items.push(row);
                return;
            }
        }
    }
}

/// Push a header row index to the sheet fields.
fn push_header_row(fields: &mut Vec<(String, Value)>, idx: Value) {
    for (k, v) in fields.iter_mut() {
        if k == "header_rows" {
            if let Value::Array(items) = v {
                items.push(idx);
                return;
            }
        }
    }
}

/// Convert a CellFormat Value struct to a native CellFormat.
fn value_to_cell_format(val: &Value) -> CellFormat {
    let mut fmt = CellFormat::default();
    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            match k.as_str() {
                "bold" => fmt.bold = matches!(v, Value::Bool(true)),
                "font_size" => if let Value::Int(n) = v { fmt.font_size = Some(*n as u16); },
                "font_color" => if let Value::String(s) = v { fmt.font_color = Some(s.clone()); },
                "font_name" => if let Value::String(s) = v { fmt.font_name = Some(s.clone()); },
                "bg_color" => if let Value::String(s) = v { fmt.bg_color = Some(s.clone()); },
                "alignment" => if let Value::String(s) = v { fmt.alignment = Some(s.clone()); },
                "wrap_text" => fmt.wrap_text = matches!(v, Value::Bool(true)),
                "number_format" => if let Value::String(s) = v { fmt.number_format = Some(s.clone()); },
                "border" => if let Value::String(s) = v { fmt.border = Some(s.clone()); },
                _ => {}
            }
        }
    }
    // Also handle Map-based formats
    if let Value::Map(pairs) = val {
        for (k, v) in pairs {
            let key = k.as_string();
            match key.as_str() {
                "bold" => fmt.bold = matches!(v, Value::Bool(true)),
                "font_size" => if let Value::Int(n) = v { fmt.font_size = Some(*n as u16); },
                "font_color" => if let Value::String(s) = v { fmt.font_color = Some(s.clone()); },
                "font_name" => if let Value::String(s) = v { fmt.font_name = Some(s.clone()); },
                "bg_color" => if let Value::String(s) = v { fmt.bg_color = Some(s.clone()); },
                "alignment" => if let Value::String(s) = v { fmt.alignment = Some(s.clone()); },
                "wrap_text" => fmt.wrap_text = matches!(v, Value::Bool(true)),
                "number_format" => if let Value::String(s) = v { fmt.number_format = Some(s.clone()); },
                "border" => if let Value::String(s) = v { fmt.border = Some(s.clone()); },
                _ => {}
            }
        }
    }
    fmt
}

/// Convert a Value-based ExcelWorkbook into a native ExcelWorkbook.
fn value_to_excel_workbook(val: &Value) -> Result<ExcelWorkbook, String> {
    let sheets = extract_sheets(val);
    let mut wb = ExcelWorkbook::new();

    for sheet_val in &sheets {
        if let Value::Struct { fields, .. } = sheet_val {
            let name = fields
                .iter()
                .find(|(k, _)| k == "name")
                .map(|(_, v)| v.as_string())
                .unwrap_or_else(|| "Sheet".to_string());

            let rows_val = fields
                .iter()
                .find(|(k, _)| k == "rows")
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Array(vec![]));

            let header_rows_val = fields
                .iter()
                .find(|(k, _)| k == "header_rows")
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Array(vec![]));

            let mut sheet = ExcelSheet::new(&name);

            // Parse header row indices
            if let Value::Array(indices) = &header_rows_val {
                for idx in indices {
                    if let Value::Int(i) = idx {
                        sheet.header_rows.push(*i as usize);
                    }
                }
            }

            // Parse rows
            if let Value::Array(rows) = &rows_val {
                for row in rows {
                    if let Value::Array(cells) = row {
                        let excel_cells: Vec<ExcelCell> = cells
                            .iter()
                            .map(|cell| match cell {
                                Value::Nil => ExcelCell::Empty,
                                Value::Bool(b) => ExcelCell::Bool(*b),
                                Value::Int(n) => ExcelCell::Integer(*n as i64),
                                Value::Float(f) => ExcelCell::Number(*f),
                                Value::String(s) => ExcelCell::Text(s.clone()),
                                Value::Struct { name, fields, .. } if name == "Formula" => {
                                    let formula = fields
                                        .iter()
                                        .find(|(k, _)| k == "formula")
                                        .map(|(_, v)| v.as_string())
                                        .unwrap_or_default();
                                    ExcelCell::Formula(formula)
                                }
                                _ => ExcelCell::Text(cell.as_string()),
                            })
                            .collect();
                        sheet.add_row(excel_cells);
                    }
                }
            }

            // Parse cell_formats
            if let Some((_, fmts_val)) = fields.iter().find(|(k, _)| k == "cell_formats") {
                if let Value::Array(fmts) = fmts_val {
                    for fmt_entry in fmts {
                        if let Value::Array(parts) = fmt_entry {
                            if parts.len() >= 3 {
                                let row = match &parts[0] { Value::Int(n) => *n as usize, _ => 0 };
                                let col = match &parts[1] { Value::Int(n) => *n as usize, _ => 0 };
                                let fmt = value_to_cell_format(&parts[2]);
                                sheet.set_cell_format(row, col, fmt);
                            }
                        }
                    }
                }
            }

            // Parse col_widths
            if let Some((_, cw_val)) = fields.iter().find(|(k, _)| k == "col_widths") {
                if let Value::Array(cws) = cw_val {
                    for cw in cws {
                        if let Value::Array(pair) = cw {
                            if pair.len() >= 2 {
                                let col = match &pair[0] { Value::Int(n) => *n as usize, _ => 0 };
                                let width = match &pair[1] { Value::Float(f) => *f, Value::Int(n) => *n as f64, _ => 10.0 };
                                sheet.col_widths.push((col, width));
                            }
                        }
                    }
                }
            }

            // Parse row_heights
            if let Some((_, rh_val)) = fields.iter().find(|(k, _)| k == "row_heights") {
                if let Value::Array(rhs) = rh_val {
                    for rh in rhs {
                        if let Value::Array(pair) = rh {
                            if pair.len() >= 2 {
                                let row = match &pair[0] { Value::Int(n) => *n as usize, _ => 0 };
                                let height = match &pair[1] { Value::Float(f) => *f, Value::Int(n) => *n as f64, _ => 15.0 };
                                sheet.row_heights.push((row, height));
                            }
                        }
                    }
                }
            }

            // Parse freeze_row/freeze_col
            if let Some((_, fr_val)) = fields.iter().find(|(k, _)| k == "freeze_row") {
                if let Value::Int(n) = fr_val {
                    sheet.freeze_row = Some(*n as usize);
                }
            }
            if let Some((_, fc_val)) = fields.iter().find(|(k, _)| k == "freeze_col") {
                if let Value::Int(n) = fc_val {
                    sheet.freeze_col = Some(*n as usize);
                }
            }

            // Parse merges
            if let Some((_, merges_val)) = fields.iter().find(|(k, _)| k == "merges") {
                if let Value::Array(merges) = merges_val {
                    for merge in merges {
                        if let Value::Array(pair) = merge {
                            if pair.len() >= 2 {
                                sheet.merges.push((pair[0].as_string(), pair[1].as_string()));
                            }
                        }
                    }
                }
            }

            // Parse auto_filter
            if let Some((_, af_val)) = fields.iter().find(|(k, _)| k == "auto_filter") {
                if let Value::String(range) = af_val {
                    sheet.auto_filter = Some(range.clone());
                }
            }

            // Parse hyperlinks
            if let Some((_, hl_val)) = fields.iter().find(|(k, _)| k == "hyperlinks") {
                if let Value::Array(hls) = hl_val {
                    for hl in hls {
                        if let Value::Array(pair) = hl {
                            if pair.len() >= 2 {
                                sheet.hyperlinks.push((pair[0].as_string(), pair[1].as_string()));
                            }
                        }
                    }
                }
            }

            wb.sheets.push(sheet);
        }
    }

    Ok(wb)
}

/// Convert a Value-based WordDocument into a native WordDocument.
fn value_to_word_document(val: &Value) -> Result<WordDocument, String> {
    let elements = extract_elements(val);
    let mut doc = WordDocument::new();

    // Extract page settings
    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            match k.as_str() {
                "page_width" => if let Value::Int(n) = v { doc.page_width = *n as u32; },
                "page_height" => if let Value::Int(n) = v { doc.page_height = *n as u32; },
                "margin_top" => if let Value::Int(n) = v { doc.margin_top = *n as u32; },
                "margin_bottom" => if let Value::Int(n) = v { doc.margin_bottom = *n as u32; },
                "margin_left" => if let Value::Int(n) = v { doc.margin_left = *n as u32; },
                "margin_right" => if let Value::Int(n) = v { doc.margin_right = *n as u32; },
                "header_text" => if let Value::String(s) = v { doc.header_text = Some(s.clone()); },
                "footer_text" => if let Value::String(s) = v { doc.footer_text = Some(s.clone()); },
                _ => {}
            }
        }
    }

    for elem_val in &elements {
        if let Value::Struct { fields, .. } = elem_val {
            let elem_type = fields
                .iter()
                .find(|(k, _)| k == "type")
                .map(|(_, v)| v.as_string())
                .unwrap_or_default();

            let text = fields
                .iter()
                .find(|(k, _)| k == "text")
                .map(|(_, v)| v.as_string())
                .unwrap_or_default();

            match elem_type.as_str() {
                "heading" => {
                    let level = fields
                        .iter()
                        .find(|(k, _)| k == "level")
                        .and_then(|(_, v)| match v {
                            Value::Int(n) => Some(*n as u8),
                            _ => v.as_string().parse::<u8>().ok(),
                        })
                        .unwrap_or(1);
                    doc.add_heading(&text, level);
                }
                "paragraph" => doc.add_paragraph(&text),
                "bold" => doc.add_bold(&text),
                "italic" => doc.add_italic(&text),
                "underline" => doc.add_underline(&text),
                "strikethrough" => doc.add_strikethrough(&text),
                "superscript" => doc.add_superscript(&text),
                "subscript" => doc.add_subscript(&text),
                "aligned" => {
                    let alignment = fields
                        .iter()
                        .find(|(k, _)| k == "alignment")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_else(|| "left".to_string());
                    doc.add_aligned(&text, &alignment);
                }
                "bullet_list" => {
                    let items = fields
                        .iter()
                        .find(|(k, _)| k == "items")
                        .map(|(_, v)| value_to_string_vec(v))
                        .unwrap_or_default();
                    let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
                    doc.add_bullet_list(&refs);
                }
                "numbered_list" => {
                    let items = fields
                        .iter()
                        .find(|(k, _)| k == "items")
                        .map(|(_, v)| value_to_string_vec(v))
                        .unwrap_or_default();
                    let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
                    doc.add_numbered_list(&refs);
                }
                "table" => {
                    let headers = fields
                        .iter()
                        .find(|(k, _)| k == "headers")
                        .map(|(_, v)| value_to_string_vec(v))
                        .unwrap_or_default();
                    let rows = fields
                        .iter()
                        .find(|(k, _)| k == "rows")
                        .map(|(_, v)| value_to_string_vec_vec(v))
                        .unwrap_or_default();
                    let header_refs: Vec<&str> = headers.iter().map(|s| s.as_str()).collect();
                    doc.add_table(&header_refs, &rows);
                }
                "page_break" => doc.add_page_break(),
                "horizontal_rule" => doc.add_horizontal_rule(),
                "link" => {
                    let url = fields
                        .iter()
                        .find(|(k, _)| k == "url")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    doc.add_link(&text, &url);
                }
                "image" => {
                    let data_b64 = fields
                        .iter()
                        .find(|(k, _)| k == "data")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let width = fields
                        .iter()
                        .find(|(k, _)| k == "width_cm")
                        .and_then(|(_, v)| match v {
                            Value::Float(f) => Some(*f),
                            Value::Int(n) => Some(*n as f64),
                            _ => v.as_string().parse::<f64>().ok(),
                        })
                        .unwrap_or(10.0);
                    let height = fields
                        .iter()
                        .find(|(k, _)| k == "height_cm")
                        .and_then(|(_, v)| match v {
                            Value::Float(f) => Some(*f),
                            Value::Int(n) => Some(*n as f64),
                            _ => v.as_string().parse::<f64>().ok(),
                        })
                        .unwrap_or(10.0);
                    let alt = fields
                        .iter()
                        .find(|(k, _)| k == "alt_text")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    // Decode base64 to bytes
                    use base64::Engine;
                    let data = base64::engine::general_purpose::STANDARD
                        .decode(&data_b64)
                        .unwrap_or_default();
                    doc.add_image(data, width, height, &alt);
                }
                "toc" => doc.add_table_of_contents(),
                _ => {} // unknown element type — skip
            }
        }
    }

    Ok(doc)
}

// ═══════════════════════════════════════════════════════════════════════════
// Part 3: CSV Export
// ═══════════════════════════════════════════════════════════════════════════

/// UTF-8 BOM bytes for Excel compatibility.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// Build CSV bytes (with BOM) from headers and rows using the `csv` crate.
fn build_csv_bytes(headers: &[String], rows: &[Vec<String>]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    buf.extend_from_slice(UTF8_BOM);

    let mut wtr = csv::WriterBuilder::new().from_writer(buf);
    wtr.write_record(headers)
        .map_err(|e| format!("csv: failed to write headers: {e}"))?;
    for row in rows {
        wtr.write_record(row)
            .map_err(|e| format!("csv: failed to write row: {e}"))?;
    }
    wtr.into_inner().map_err(|e| format!("csv: flush error: {e}"))
}

/// `docs.csv_write(path, headers, rows)` -> Ok("saved to <path>")
///
/// Write a CSV file from a headers array and a rows array-of-arrays.
fn dispatch_csv_write(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 0, "csv_write")?;
    let headers = args
        .get(1)
        .map(value_to_string_vec)
        .ok_or_else(|| "docs.csv_write: missing headers argument".to_string())?;
    let rows = args
        .get(2)
        .map(value_to_string_vec_vec)
        .ok_or_else(|| "docs.csv_write: missing rows argument".to_string())?;

    let bytes = build_csv_bytes(&headers, &rows)?;
    std::fs::write(&path, &bytes)
        .map_err(|e| format!("docs.csv_write: failed to write {path}: {e}"))?;
    Ok(Value::String(format!("saved to {path}")))
}

/// Extract ordered keys from a JSON array of objects (union of all keys,
/// preserving first-seen order).
fn json_array_keys(arr: &[serde_json::Value]) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for obj in arr {
        if let serde_json::Value::Object(map) = obj {
            for k in map.keys() {
                if seen.insert(k.clone()) {
                    keys.push(k.clone());
                }
            }
        }
    }
    keys
}

/// Convert a serde_json::Value to a CSV-friendly string.
fn json_value_to_csv_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `docs.csv_from_json(path, json_array_string)` -> Ok("saved to <path>")
///
/// Parse a JSON array of objects, auto-detect headers from keys, and write CSV.
fn dispatch_csv_from_json(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 0, "csv_from_json")?;
    let json_str = require_string(&args, 1, "csv_from_json")?;

    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("docs.csv_from_json: invalid JSON: {e}"))?;

    let arr = parsed
        .as_array()
        .ok_or_else(|| "docs.csv_from_json: JSON must be an array".to_string())?;

    let headers = json_array_keys(arr);
    let rows: Vec<Vec<String>> = arr
        .iter()
        .map(|obj| {
            headers
                .iter()
                .map(|k| {
                    obj.get(k)
                        .map(json_value_to_csv_string)
                        .unwrap_or_default()
                })
                .collect()
        })
        .collect();

    let bytes = build_csv_bytes(&headers, &rows)?;
    std::fs::write(&path, &bytes)
        .map_err(|e| format!("docs.csv_from_json: failed to write {path}: {e}"))?;
    Ok(Value::String(format!("saved to {path}")))
}

/// `docs.csv_from_records(path, records)` -> Ok("saved to <path>")
///
/// Write CSV from an array of maps (Value::Map or Value::Struct).
fn dispatch_csv_from_records(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 0, "csv_from_records")?;
    let records_val = args
        .get(1)
        .ok_or_else(|| "docs.csv_from_records: missing records argument".to_string())?;

    let records = match records_val {
        Value::Array(items) => items,
        _ => return Err("docs.csv_from_records: records must be an array".to_string()),
    };

    // Collect headers (union of all keys, first-seen order).
    let mut headers: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for rec in records {
        match rec {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    let key = k.as_string();
                    if seen.insert(key.clone()) {
                        headers.push(key);
                    }
                }
            }
            Value::Struct { fields, .. } => {
                for (k, _) in fields {
                    if seen.insert(k.clone()) {
                        headers.push(k.clone());
                    }
                }
            }
            _ => {}
        }
    }

    // Build rows.
    let rows: Vec<Vec<String>> = records
        .iter()
        .map(|rec| {
            headers
                .iter()
                .map(|h| match rec {
                    Value::Map(pairs) => pairs
                        .iter()
                        .find(|(k, _)| k.as_string() == *h)
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default(),
                    Value::Struct { fields, .. } => fields
                        .iter()
                        .find(|(k, _)| k == h)
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default(),
                    _ => String::new(),
                })
                .collect()
        })
        .collect();

    let bytes = build_csv_bytes(&headers, &rows)?;
    std::fs::write(&path, &bytes)
        .map_err(|e| format!("docs.csv_from_records: failed to write {path}: {e}"))?;
    Ok(Value::String(format!("saved to {path}")))
}

/// `docs.csv_append(path, row)` -> Ok("appended to <path>")
///
/// Append a single row to an existing CSV file (or create it if missing).
fn dispatch_csv_append(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 0, "csv_append")?;
    let row = args
        .get(1)
        .map(value_to_string_vec)
        .ok_or_else(|| "docs.csv_append: missing row argument".to_string())?;

    let file_exists = std::path::Path::new(&path).exists();

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("docs.csv_append: failed to open {path}: {e}"))?;

    // If the file is brand-new (empty), prepend BOM.
    if !file_exists {
        // Re-open in write mode to prepend BOM, then append.
        drop(file);
        let mut f = std::fs::File::create(&path)
            .map_err(|e| format!("docs.csv_append: failed to create {path}: {e}"))?;
        f.write_all(UTF8_BOM)
            .map_err(|e| format!("docs.csv_append: failed to write BOM: {e}"))?;
        let mut wtr = csv::WriterBuilder::new().from_writer(f);
        wtr.write_record(&row)
            .map_err(|e| format!("docs.csv_append: failed to write row: {e}"))?;
        wtr.flush()
            .map_err(|e| format!("docs.csv_append: flush error: {e}"))?;
    } else {
        let mut wtr = csv::WriterBuilder::new().from_writer(file);
        wtr.write_record(&row)
            .map_err(|e| format!("docs.csv_append: failed to write row: {e}"))?;
        wtr.flush()
            .map_err(|e| format!("docs.csv_append: flush error: {e}"))?;
    }

    Ok(Value::String(format!("appended to {path}")))
}

/// `docs.csv_to_string(headers, rows)` -> CSV content as a String
///
/// Returns CSV data as a string (with BOM) instead of writing to a file.
fn dispatch_csv_to_string(args: Vec<Value>) -> StdlibResult {
    let headers = args
        .get(0)
        .map(value_to_string_vec)
        .ok_or_else(|| "docs.csv_to_string: missing headers argument".to_string())?;
    let rows = args
        .get(1)
        .map(value_to_string_vec_vec)
        .ok_or_else(|| "docs.csv_to_string: missing rows argument".to_string())?;

    let bytes = build_csv_bytes(&headers, &rows)?;
    let s = String::from_utf8(bytes)
        .map_err(|e| format!("docs.csv_to_string: UTF-8 error: {e}"))?;
    Ok(Value::String(s))
}

// ═══════════════════════════════════════════════════════════════════════════
// PPTX dispatch functions
// ═══════════════════════════════════════════════════════════════════════════

/// `docs.pptx_create(title)` -> PptxPresentation as a struct
fn dispatch_pptx_create(args: Vec<Value>) -> StdlibResult {
    let title = args.first().map(|v| v.as_string()).unwrap_or_else(|| "Untitled".to_string());
    Ok(Value::Struct {
        name: "PptxPresentation".to_string(),
        fields: vec![
            ("slides".to_string(), Value::Array(vec![])),
            ("title".to_string(), Value::String(title)),
            ("width_emu".to_string(), Value::Int(12_192_000)),
            ("height_emu".to_string(), Value::Int(6_858_000)),
        ],
    })
}

/// `docs.pptx_add_slide(pptx, layout)` -> updated pptx
fn dispatch_pptx_add_slide(args: Vec<Value>) -> StdlibResult {
    let pptx = args.first().ok_or("docs.pptx_add_slide: missing presentation")?;
    let layout = args.get(1).map(|v| v.as_string()).unwrap_or_else(|| "blank".to_string());
    let mut slides = extract_pptx_slides(pptx);
    slides.push(Value::Struct {
        name: "PptxSlide".to_string(),
        fields: vec![
            ("elements".to_string(), Value::Array(vec![])),
            ("layout".to_string(), Value::String(layout)),
        ],
    });
    Ok(rebuild_pptx(pptx, slides))
}

/// `docs.pptx_add_title(pptx, text)` -> updated pptx (adds title to last slide)
fn dispatch_pptx_add_title(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "pptx_add_title")?;
    let pptx = args.first().ok_or("docs.pptx_add_title: missing presentation")?;
    let elem = Value::Struct {
        name: "SlideElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("title".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    };
    Ok(push_pptx_element(pptx, elem))
}

/// `docs.pptx_add_subtitle(pptx, text)` -> updated pptx
fn dispatch_pptx_add_subtitle(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "pptx_add_subtitle")?;
    let pptx = args.first().ok_or("docs.pptx_add_subtitle: missing presentation")?;
    let elem = Value::Struct {
        name: "SlideElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("subtitle".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    };
    Ok(push_pptx_element(pptx, elem))
}

/// `docs.pptx_add_text(pptx, text, x, y, width, height)` -> updated pptx
fn dispatch_pptx_add_text(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "pptx_add_text")?;
    let pptx = args.first().ok_or("docs.pptx_add_text: missing presentation")?;
    let x = args.get(2).map(|v| match v { Value::Int(n) => *n as i64, _ => 914400 }).unwrap_or(914400);
    let y = args.get(3).map(|v| match v { Value::Int(n) => *n as i64, _ => 1714500 }).unwrap_or(1714500);
    let w = args.get(4).map(|v| match v { Value::Int(n) => *n as i64, _ => 10363200 }).unwrap_or(10363200);
    let h = args.get(5).map(|v| match v { Value::Int(n) => *n as i64, _ => 3429000 }).unwrap_or(3429000);
    let elem = Value::Struct {
        name: "SlideElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("textbox".to_string())),
            ("text".to_string(), Value::String(text)),
            ("x".to_string(), Value::Int(x as i128)),
            ("y".to_string(), Value::Int(y as i128)),
            ("width".to_string(), Value::Int(w as i128)),
            ("height".to_string(), Value::Int(h as i128)),
            ("font_size".to_string(), Value::Int(18)),
            ("bold".to_string(), Value::Bool(false)),
            ("color".to_string(), Value::String("000000".to_string())),
        ],
    };
    Ok(push_pptx_element(pptx, elem))
}

/// `docs.pptx_add_bullets(pptx, items_array)` -> updated pptx
fn dispatch_pptx_add_bullets(args: Vec<Value>) -> StdlibResult {
    let pptx = args.first().ok_or("docs.pptx_add_bullets: missing presentation")?;
    let items = args.get(1).map(value_to_string_vec).unwrap_or_default();
    let elem = Value::Struct {
        name: "SlideElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("bullet_list".to_string())),
            ("items".to_string(), Value::Array(items.into_iter().map(Value::String).collect())),
        ],
    };
    Ok(push_pptx_element(pptx, elem))
}

/// `docs.pptx_add_table(pptx, headers, rows)` -> updated pptx
fn dispatch_pptx_add_table(args: Vec<Value>) -> StdlibResult {
    let pptx = args.first().ok_or("docs.pptx_add_table: missing presentation")?;
    let headers = args.get(1).map(value_to_string_vec).unwrap_or_default();
    let rows = args.get(2).map(value_to_string_vec_vec).unwrap_or_default();
    let rows_val = Value::Array(rows.into_iter().map(|r| Value::Array(r.into_iter().map(Value::String).collect())).collect());
    let elem = Value::Struct {
        name: "SlideElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("table".to_string())),
            ("headers".to_string(), Value::Array(headers.into_iter().map(Value::String).collect())),
            ("rows".to_string(), rows_val),
            ("x".to_string(), Value::Int(914400)),
            ("y".to_string(), Value::Int(1714500)),
            ("width".to_string(), Value::Int(10363200)),
            ("height".to_string(), Value::Int(4000000)),
        ],
    };
    Ok(push_pptx_element(pptx, elem))
}

/// `docs.pptx_save(pptx, path)` -> success message
fn dispatch_pptx_save(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 1, "pptx_save")?;
    let pptx_val = args.first().ok_or("docs.pptx_save: missing presentation")?;
    let pres = value_to_pptx_presentation(pptx_val)?;
    pres.save(&path)?;
    Ok(Value::String(format!("saved to {path}")))
}

/// `docs.pptx_to_bytes(pptx)` -> base64 string
fn dispatch_pptx_to_bytes(args: Vec<Value>) -> StdlibResult {
    let pptx_val = args.first().ok_or("docs.pptx_to_bytes: missing presentation")?;
    let pres = value_to_pptx_presentation(pptx_val)?;
    let bytes = pres.to_bytes()?;
    Ok(Value::String(b64_encode(&bytes)))
}

/// `docs.pptx_report(title, slides_data)` -> base64 pptx bytes
fn dispatch_pptx_report(args: Vec<Value>) -> StdlibResult {
    let title = require_string(&args, 0, "pptx_report")?;
    let slides_val = args.get(1).ok_or("docs.pptx_report: missing slides data")?;
    let slides_data: Vec<(String, Vec<String>)> = match slides_val {
        Value::Array(items) => {
            items.iter().map(|item| match item {
                Value::Array(pair) if pair.len() >= 2 => {
                    let name = pair[0].as_string();
                    let items = value_to_string_vec(&pair[1]);
                    (name, items)
                }
                Value::Struct { fields, .. } => {
                    let name = fields.iter().find(|(k, _)| k == "title" || k == "name").map(|(_, v)| v.as_string()).unwrap_or_default();
                    let items = fields.iter().find(|(k, _)| k == "items" || k == "bullets" || k == "content").map(|(_, v)| value_to_string_vec(v)).unwrap_or_default();
                    (name, items)
                }
                _ => (item.as_string(), vec![]),
            }).collect()
        }
        _ => return Err("docs.pptx_report: slides_data must be an array".to_string()),
    };
    let bytes = create_pptx_report(&title, &slides_data)?;
    Ok(Value::String(b64_encode(&bytes)))
}

// ── PPTX Value helpers ──

fn extract_pptx_slides(val: &Value) -> Vec<Value> {
    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            if k == "slides" {
                if let Value::Array(items) = v {
                    return items.clone();
                }
            }
        }
    }
    vec![]
}

fn rebuild_pptx(original: &Value, slides: Vec<Value>) -> Value {
    let mut fields = vec![("slides".to_string(), Value::Array(slides))];
    if let Value::Struct { fields: orig, .. } = original {
        for (k, v) in orig {
            if k != "slides" {
                fields.push((k.clone(), v.clone()));
            }
        }
    } else {
        fields.push(("title".to_string(), Value::String("Untitled".to_string())));
        fields.push(("width_emu".to_string(), Value::Int(12_192_000)));
        fields.push(("height_emu".to_string(), Value::Int(6_858_000)));
    }
    Value::Struct { name: "PptxPresentation".to_string(), fields }
}

fn push_pptx_element(pptx: &Value, elem: Value) -> Value {
    let mut slides = extract_pptx_slides(pptx);
    if let Some(last) = slides.last_mut() {
        if let Value::Struct { fields, .. } = last {
            for (k, v) in fields.iter_mut() {
                if k == "elements" {
                    if let Value::Array(elems) = v {
                        elems.push(elem);
                        return rebuild_pptx(pptx, slides);
                    }
                }
            }
        }
    }
    // No slides yet — create one
    slides.push(Value::Struct {
        name: "PptxSlide".to_string(),
        fields: vec![
            ("elements".to_string(), Value::Array(vec![elem])),
            ("layout".to_string(), Value::String("blank".to_string())),
        ],
    });
    rebuild_pptx(pptx, slides)
}

fn value_to_pptx_presentation(val: &Value) -> Result<PptxPresentation, String> {
    let slides_val = extract_pptx_slides(val);
    let mut pres = PptxPresentation::new("Untitled");

    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            match k.as_str() {
                "title" => if let Value::String(s) = v { pres.title = s.clone(); },
                "width_emu" => if let Value::Int(n) = v { pres.width_emu = *n as i64; },
                "height_emu" => if let Value::Int(n) = v { pres.height_emu = *n as i64; },
                _ => {}
            }
        }
    }

    for slide_val in &slides_val {
        if let Value::Struct { fields, .. } = slide_val {
            let layout_str = fields.iter().find(|(k, _)| k == "layout").map(|(_, v)| v.as_string()).unwrap_or_else(|| "blank".to_string());
            let layout = match layout_str.as_str() {
                "title_slide" => SlideLayout::TitleSlide,
                "title_content" => SlideLayout::TitleContent,
                "two_column" => SlideLayout::TwoColumn,
                _ => SlideLayout::Blank,
            };
            let slide = pres.add_slide(layout);

            let elements = fields.iter().find(|(k, _)| k == "elements").map(|(_, v)| {
                if let Value::Array(items) = v { items.clone() } else { vec![] }
            }).unwrap_or_default();

            for elem_val in &elements {
                if let Value::Struct { fields: ef, .. } = elem_val {
                    let etype = ef.iter().find(|(k, _)| k == "type").map(|(_, v)| v.as_string()).unwrap_or_default();
                    let text = ef.iter().find(|(k, _)| k == "text").map(|(_, v)| v.as_string()).unwrap_or_default();

                    match etype.as_str() {
                        "title" => slide.add_title(&text),
                        "subtitle" => slide.add_subtitle(&text),
                        "textbox" => {
                            let x = ef.iter().find(|(k,_)| k=="x").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as i64) } else { None }).unwrap_or(914400);
                            let y = ef.iter().find(|(k,_)| k=="y").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as i64) } else { None }).unwrap_or(1714500);
                            let w = ef.iter().find(|(k,_)| k=="width").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as i64) } else { None }).unwrap_or(10363200);
                            let h = ef.iter().find(|(k,_)| k=="height").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as i64) } else { None }).unwrap_or(3429000);
                            let fs = ef.iter().find(|(k,_)| k=="font_size").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as u32) } else { None }).unwrap_or(18);
                            let bold = ef.iter().find(|(k,_)| k=="bold").map(|(_, v)| matches!(v, Value::Bool(true))).unwrap_or(false);
                            let color = ef.iter().find(|(k,_)| k=="color").map(|(_, v)| v.as_string()).unwrap_or_else(|| "000000".to_string());
                            slide.add_text_box(&text, x, y, w, h, fs, bold, &color);
                        }
                        "bullet_list" => {
                            let items = ef.iter().find(|(k, _)| k == "items").map(|(_, v)| value_to_string_vec(v)).unwrap_or_default();
                            slide.add_bullet_list(&items);
                        }
                        "numbered_list" => {
                            let items = ef.iter().find(|(k, _)| k == "items").map(|(_, v)| value_to_string_vec(v)).unwrap_or_default();
                            slide.add_numbered_list(&items);
                        }
                        "table" => {
                            let headers = ef.iter().find(|(k, _)| k == "headers").map(|(_, v)| value_to_string_vec(v)).unwrap_or_default();
                            let rows = ef.iter().find(|(k, _)| k == "rows").map(|(_, v)| value_to_string_vec_vec(v)).unwrap_or_default();
                            let x = ef.iter().find(|(k,_)| k=="x").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as i64) } else { None }).unwrap_or(914400);
                            let y = ef.iter().find(|(k,_)| k=="y").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as i64) } else { None }).unwrap_or(1714500);
                            let w = ef.iter().find(|(k,_)| k=="width").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as i64) } else { None }).unwrap_or(10363200);
                            let h = ef.iter().find(|(k,_)| k=="height").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as i64) } else { None }).unwrap_or(4000000);
                            slide.add_table(&headers, &rows, x, y, w, h);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(pres)
}

// ═══════════════════════════════════════════════════════════════════════════
// PDF dispatch functions
// ═══════════════════════════════════════════════════════════════════════════

/// `docs.pdf_create(title)` -> PdfDocument as a struct
fn dispatch_pdf_create(args: Vec<Value>) -> StdlibResult {
    let title = args.first().map(|v| v.as_string()).unwrap_or_default();
    Ok(Value::Struct {
        name: "PdfDocument".to_string(),
        fields: vec![
            ("elements".to_string(), Value::Array(vec![])),
            ("title".to_string(), Value::String(title)),
            ("author".to_string(), Value::String(String::new())),
            ("page_width".to_string(), Value::Float(612.0)),
            ("page_height".to_string(), Value::Float(792.0)),
            ("margin".to_string(), Value::Float(72.0)),
        ],
    })
}

/// Extract the `elements` array from a PdfDocument Value.
fn extract_pdf_elements(val: &Value) -> Vec<Value> {
    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            if k == "elements" {
                if let Value::Array(items) = v {
                    return items.clone();
                }
            }
        }
    }
    vec![]
}

/// Rebuild a PdfDocument Value with new elements, preserving settings.
fn rebuild_pdf_doc(original: &Value, elements: Vec<Value>) -> Value {
    let mut fields = vec![("elements".to_string(), Value::Array(elements))];
    if let Value::Struct { fields: orig, .. } = original {
        for (k, v) in orig {
            if k != "elements" {
                fields.push((k.clone(), v.clone()));
            }
        }
    } else {
        fields.push(("title".to_string(), Value::String(String::new())));
        fields.push(("author".to_string(), Value::String(String::new())));
        fields.push(("page_width".to_string(), Value::Float(612.0)));
        fields.push(("page_height".to_string(), Value::Float(792.0)));
        fields.push(("margin".to_string(), Value::Float(72.0)));
    }
    Value::Struct { name: "PdfDocument".to_string(), fields }
}

/// Convert a Value-based PdfDocument into a native PdfDocument.
fn value_to_pdf_document(val: &Value) -> Result<PdfDocument, String> {
    let elements = extract_pdf_elements(val);
    let mut doc = PdfDocument::new();

    if let Value::Struct { fields, .. } = val {
        for (k, v) in fields {
            match k.as_str() {
                "title" => if let Value::String(s) = v { doc.title = s.clone(); },
                "author" => if let Value::String(s) = v { doc.author = s.clone(); },
                "page_width" => match v {
                    Value::Float(f) => doc.page_width = *f,
                    Value::Int(n) => doc.page_width = *n as f64,
                    _ => {}
                },
                "page_height" => match v {
                    Value::Float(f) => doc.page_height = *f,
                    Value::Int(n) => doc.page_height = *n as f64,
                    _ => {}
                },
                "margin" => match v {
                    Value::Float(f) => doc.margin = *f,
                    Value::Int(n) => doc.margin = *n as f64,
                    _ => {}
                },
                _ => {}
            }
        }
    }

    for elem_val in &elements {
        if let Value::Struct { fields, .. } = elem_val {
            let elem_type = fields.iter()
                .find(|(k, _)| k == "type")
                .map(|(_, v)| v.as_string())
                .unwrap_or_default();

            let text = fields.iter()
                .find(|(k, _)| k == "text")
                .map(|(_, v)| v.as_string())
                .unwrap_or_default();

            match elem_type.as_str() {
                "heading" => {
                    let level = fields.iter()
                        .find(|(k, _)| k == "level")
                        .and_then(|(_, v)| match v {
                            Value::Int(n) => Some(*n as u8),
                            _ => v.as_string().parse::<u8>().ok(),
                        })
                        .unwrap_or(1);
                    doc.add_heading(&text, level);
                }
                "paragraph" => doc.add_paragraph(&text),
                "bold" => doc.add_bold(&text),
                "bullet_list" => {
                    let items = fields.iter()
                        .find(|(k, _)| k == "items")
                        .map(|(_, v)| value_to_string_vec(v))
                        .unwrap_or_default();
                    let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
                    doc.add_bullet_list(&refs);
                }
                "numbered_list" => {
                    let items = fields.iter()
                        .find(|(k, _)| k == "items")
                        .map(|(_, v)| value_to_string_vec(v))
                        .unwrap_or_default();
                    let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
                    doc.add_numbered_list(&refs);
                }
                "table" => {
                    let headers = fields.iter()
                        .find(|(k, _)| k == "headers")
                        .map(|(_, v)| value_to_string_vec(v))
                        .unwrap_or_default();
                    let rows = fields.iter()
                        .find(|(k, _)| k == "rows")
                        .map(|(_, v)| value_to_string_vec_vec(v))
                        .unwrap_or_default();
                    doc.add_table(headers, rows);
                }
                "horizontal_rule" => doc.add_horizontal_rule(),
                "spacer" => {
                    let pts = fields.iter()
                        .find(|(k, _)| k == "points")
                        .and_then(|(_, v)| match v {
                            Value::Float(f) => Some(*f),
                            Value::Int(n) => Some(*n as f64),
                            _ => v.as_string().parse::<f64>().ok(),
                        })
                        .unwrap_or(12.0);
                    doc.add_spacer(pts);
                }
                "page_break" => doc.add_page_break(),
                _ => {}
            }
        }
    }

    Ok(doc)
}

/// `docs.pdf_add_heading(doc, text, level)` -> updated doc
fn dispatch_pdf_add_heading(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "pdf_add_heading")?;
    let level = args.get(2).map(|v| v.as_string().parse::<u8>().unwrap_or(1)).unwrap_or(1);
    let doc = args.first().ok_or("docs.pdf_add_heading: missing document")?;
    let mut elements = extract_pdf_elements(doc);

    elements.push(Value::Struct {
        name: "PdfElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("heading".to_string())),
            ("text".to_string(), Value::String(text)),
            ("level".to_string(), Value::Int(level as i128)),
        ],
    });

    Ok(rebuild_pdf_doc(doc, elements))
}

/// `docs.pdf_add_paragraph(doc, text)` -> updated doc
fn dispatch_pdf_add_paragraph(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "pdf_add_paragraph")?;
    let doc = args.first().ok_or("docs.pdf_add_paragraph: missing document")?;
    let mut elements = extract_pdf_elements(doc);

    elements.push(Value::Struct {
        name: "PdfElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("paragraph".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    });

    Ok(rebuild_pdf_doc(doc, elements))
}

/// `docs.pdf_add_bold(doc, text)` -> updated doc
fn dispatch_pdf_add_bold(args: Vec<Value>) -> StdlibResult {
    let text = require_string(&args, 1, "pdf_add_bold")?;
    let doc = args.first().ok_or("docs.pdf_add_bold: missing document")?;
    let mut elements = extract_pdf_elements(doc);

    elements.push(Value::Struct {
        name: "PdfElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("bold".to_string())),
            ("text".to_string(), Value::String(text)),
        ],
    });

    Ok(rebuild_pdf_doc(doc, elements))
}

/// `docs.pdf_add_table(doc, headers_array, rows_array)` -> updated doc
fn dispatch_pdf_add_table(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.pdf_add_table: missing document")?;
    let headers = args.get(1).map(value_to_string_vec).unwrap_or_default();
    let rows = args.get(2).map(value_to_string_vec_vec).unwrap_or_default();

    let mut elements = extract_pdf_elements(doc);

    let rows_value = Value::Array(
        rows.into_iter()
            .map(|r| Value::Array(r.into_iter().map(Value::String).collect()))
            .collect(),
    );

    elements.push(Value::Struct {
        name: "PdfElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("table".to_string())),
            ("headers".to_string(), Value::Array(headers.into_iter().map(Value::String).collect())),
            ("rows".to_string(), rows_value),
        ],
    });

    Ok(rebuild_pdf_doc(doc, elements))
}

/// `docs.pdf_add_bullets(doc, items_array)` -> updated doc
fn dispatch_pdf_add_bullets(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.pdf_add_bullets: missing document")?;
    let items = args.get(1).map(value_to_string_vec).unwrap_or_default();
    let mut elements = extract_pdf_elements(doc);

    elements.push(Value::Struct {
        name: "PdfElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("bullet_list".to_string())),
            ("items".to_string(), Value::Array(items.into_iter().map(Value::String).collect())),
        ],
    });

    Ok(rebuild_pdf_doc(doc, elements))
}

/// `docs.pdf_add_numbered_list(doc, items_array)` -> updated doc
fn dispatch_pdf_add_numbered_list(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.pdf_add_numbered_list: missing document")?;
    let items = args.get(1).map(value_to_string_vec).unwrap_or_default();
    let mut elements = extract_pdf_elements(doc);

    elements.push(Value::Struct {
        name: "PdfElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("numbered_list".to_string())),
            ("items".to_string(), Value::Array(items.into_iter().map(Value::String).collect())),
        ],
    });

    Ok(rebuild_pdf_doc(doc, elements))
}

/// `docs.pdf_add_horizontal_rule(doc)` -> updated doc
fn dispatch_pdf_add_horizontal_rule(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.pdf_add_horizontal_rule: missing document")?;
    let mut elements = extract_pdf_elements(doc);

    elements.push(Value::Struct {
        name: "PdfElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("horizontal_rule".to_string())),
        ],
    });

    Ok(rebuild_pdf_doc(doc, elements))
}

/// `docs.pdf_add_spacer(doc, points)` -> updated doc
fn dispatch_pdf_add_spacer(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.pdf_add_spacer: missing document")?;
    let pts = args.get(1).and_then(|v| match v {
        Value::Float(f) => Some(*f),
        Value::Int(n) => Some(*n as f64),
        _ => v.as_string().parse::<f64>().ok(),
    }).unwrap_or(12.0);
    let mut elements = extract_pdf_elements(doc);

    elements.push(Value::Struct {
        name: "PdfElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("spacer".to_string())),
            ("points".to_string(), Value::Float(pts)),
        ],
    });

    Ok(rebuild_pdf_doc(doc, elements))
}

/// `docs.pdf_add_page_break(doc)` -> updated doc
fn dispatch_pdf_add_page_break(args: Vec<Value>) -> StdlibResult {
    let doc = args.first().ok_or("docs.pdf_add_page_break: missing document")?;
    let mut elements = extract_pdf_elements(doc);

    elements.push(Value::Struct {
        name: "PdfElement".to_string(),
        fields: vec![
            ("type".to_string(), Value::String("page_break".to_string())),
        ],
    });

    Ok(rebuild_pdf_doc(doc, elements))
}

/// `docs.pdf_save(doc, path)` -> status string
fn dispatch_pdf_save(args: Vec<Value>) -> StdlibResult {
    let path = require_string(&args, 1, "pdf_save")?;
    let doc_val = args.first().ok_or("docs.pdf_save: missing document")?;
    let doc = value_to_pdf_document(doc_val)?;
    doc.save(&path)?;
    Ok(Value::String(format!("saved to {path}")))
}

/// `docs.pdf_to_bytes(doc)` -> base64 string
fn dispatch_pdf_to_bytes(args: Vec<Value>) -> StdlibResult {
    let doc_val = args.first().ok_or("docs.pdf_to_bytes: missing document")?;
    let doc = value_to_pdf_document(doc_val)?;
    let bytes = doc.to_bytes()?;
    Ok(Value::String(b64_encode(&bytes)))
}

/// `docs.pdf_report(title, sections)` -> base64 pdf bytes
fn dispatch_pdf_report(args: Vec<Value>) -> StdlibResult {
    let title = require_string(&args, 0, "pdf_report")?;
    let sections_val = args.get(1).ok_or("docs.pdf_report: missing sections")?;

    let sections: Vec<(String, String)> = match sections_val {
        Value::Array(items) => {
            items.iter().map(|item| match item {
                Value::Array(pair) if pair.len() >= 2 => {
                    (pair[0].as_string(), pair[1].as_string())
                }
                _ => (item.as_string(), String::new()),
            }).collect()
        }
        _ => return Err("docs.pdf_report: sections must be an array".to_string()),
    };

    let bytes = create_pdf_report(&title, &sections)?;
    Ok(Value::String(b64_encode(&bytes)))
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Column reference tests ──

    #[test]
    fn test_col_ref_single_letters() {
        assert_eq!(col_ref(0), "A");
        assert_eq!(col_ref(1), "B");
        assert_eq!(col_ref(25), "Z");
    }

    #[test]
    fn test_col_ref_double_letters() {
        assert_eq!(col_ref(26), "AA");
        assert_eq!(col_ref(27), "AB");
        assert_eq!(col_ref(51), "AZ");
        assert_eq!(col_ref(52), "BA");
        assert_eq!(col_ref(701), "ZZ");
    }

    #[test]
    fn test_col_ref_triple_letters() {
        assert_eq!(col_ref(702), "AAA");
    }

    #[test]
    fn test_cell_ref() {
        assert_eq!(cell_ref(0, 0), "A1");
        assert_eq!(cell_ref(9, 2), "C10");
        assert_eq!(cell_ref(0, 26), "AA1");
    }

    #[test]
    fn test_parse_cell_ref() {
        assert_eq!(parse_cell_ref("A1"), Some((0, 0)));
        assert_eq!(parse_cell_ref("C10"), Some((9, 2)));
        assert_eq!(parse_cell_ref("AA1"), Some((0, 26)));
        assert_eq!(parse_cell_ref("B3"), Some((2, 1)));
        assert_eq!(parse_cell_ref(""), None);
    }

    // ── Excel tests ──

    #[test]
    fn test_empty_workbook() {
        let wb = ExcelWorkbook::new();
        assert!(wb.sheets.is_empty());
    }

    #[test]
    fn test_add_sheet() {
        let mut wb = ExcelWorkbook::new();
        wb.add_sheet("Sales");
        wb.add_sheet("Inventory");
        assert_eq!(wb.sheets.len(), 2);
        assert_eq!(wb.sheets[0].name, "Sales");
        assert_eq!(wb.sheets[1].name, "Inventory");
    }

    #[test]
    fn test_add_rows() {
        let mut sheet = ExcelSheet::new("Data");
        sheet.add_row(vec![
            ExcelCell::Text("hello".to_string()),
            ExcelCell::Number(3.14),
            ExcelCell::Integer(42),
            ExcelCell::Bool(true),
            ExcelCell::Empty,
        ]);
        assert_eq!(sheet.row_count(), 1);
        assert_eq!(sheet.col_count(), 5);
    }

    #[test]
    fn test_add_header() {
        let mut sheet = ExcelSheet::new("Report");
        sheet.add_header(&["Name", "Value", "Count"]);
        assert_eq!(sheet.row_count(), 1);
        assert_eq!(sheet.col_count(), 3);
        assert!(sheet.header_rows.contains(&0));
    }

    #[test]
    fn test_xlsx_generation() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Test");
        sheet.add_header(&["Name", "Age", "Active"]);
        sheet.add_row(vec![
            ExcelCell::Text("Alice".to_string()),
            ExcelCell::Integer(30),
            ExcelCell::Bool(true),
        ]);
        sheet.add_row(vec![
            ExcelCell::Text("Bob".to_string()),
            ExcelCell::Integer(25),
            ExcelCell::Bool(false),
        ]);

        let bytes = wb.to_bytes().expect("xlsx generation should succeed");
        // Verify it's a valid ZIP (PK header)
        assert!(bytes.len() > 100, "xlsx should have substantial content");
        assert_eq!(&bytes[0..2], b"PK", "xlsx must start with PK (ZIP magic)");

        // Verify we can read it back as a zip
        let reader = Cursor::new(&bytes);
        let archive = zip::ZipArchive::new(reader).expect("should be valid ZIP");
        let expected_files = [
            "[Content_Types].xml",
            "_rels/.rels",
            "xl/workbook.xml",
            "xl/_rels/workbook.xml.rels",
            "xl/styles.xml",
            "xl/sharedStrings.xml",
            "xl/worksheets/sheet1.xml",
        ];
        for name in &expected_files {
            assert!(
                archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == *name)),
                "xlsx should contain {name}"
            );
        }
    }

    #[test]
    fn test_xlsx_xml_escaping() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Test");
        sheet.add_row(vec![
            ExcelCell::Text("a < b & c > d \"e\" 'f'".to_string()),
        ]);

        let bytes = wb.to_bytes().expect("xlsx with special chars should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        // Read sharedStrings.xml and verify escaping
        let mut ss_content = String::new();
        {
            use std::io::Read;
            let mut file = archive
                .by_name("xl/sharedStrings.xml")
                .expect("sharedStrings.xml must exist");
            file.read_to_string(&mut ss_content).unwrap();
        }
        assert!(ss_content.contains("a &lt; b &amp; c &gt; d &quot;e&quot; &apos;f&apos;"));
    }

    #[test]
    fn test_csv_to_excel() {
        let csv = "Name,Age,Score\nAlice,30,95.5\nBob,25,88.0";
        let bytes = create_excel_from_csv(csv, "Import").expect("csv_to_excel should succeed");
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn test_csv_quoted_fields() {
        let csv = "Name,Description\n\"Smith, John\",\"He said \"\"hello\"\"\"";
        let bytes = create_excel_from_csv(csv, "Quoted").expect("quoted csv should succeed");
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn test_json_to_excel() {
        let json = r#"[
            {"name": "Alice", "age": 30, "active": true},
            {"name": "Bob", "age": 25, "active": false}
        ]"#;
        let bytes =
            create_excel_from_json(json, "People").expect("json_to_excel should succeed");
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn test_json_to_excel_empty_array() {
        let json = "[]";
        let bytes =
            create_excel_from_json(json, "Empty").expect("empty json should succeed");
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn test_excel_report() {
        let sections = vec![
            (
                "Sales".to_string(),
                vec![
                    vec!["Q1".to_string(), "100".to_string()],
                    vec!["Q2".to_string(), "200".to_string()],
                ],
            ),
            (
                "Expenses".to_string(),
                vec![vec!["Rent".to_string(), "500".to_string()]],
            ),
        ];
        let bytes = create_excel_report("Annual Report", &sections)
            .expect("excel_report should succeed");
        assert_eq!(&bytes[0..2], b"PK");
    }

    // ── Excel new feature tests ──

    #[test]
    fn test_excel_formula() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Formulas");
        sheet.add_row(vec![ExcelCell::Integer(10)]);
        sheet.add_row(vec![ExcelCell::Integer(20)]);
        sheet.add_row(vec![ExcelCell::Formula("SUM(A1:A2)".to_string())]);

        let bytes = wb.to_bytes().expect("formula xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut sheet_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/worksheets/sheet1.xml").unwrap();
            file.read_to_string(&mut sheet_content).unwrap();
        }
        assert!(sheet_content.contains("<f>SUM(A1:A2)</f>"), "should contain formula");
        // No cached <v> — Excel recalculates on open (Gap 9 fix)
        assert!(!sheet_content.contains("<v>0</v>"), "should NOT contain cached value — forces Excel to recalculate");
    }

    #[test]
    fn test_excel_add_formula_method() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Test");
        sheet.add_row(vec![ExcelCell::Integer(5)]);
        sheet.add_row(vec![ExcelCell::Integer(15)]);
        sheet.add_formula(2, 0, "SUM(A1:A2)");

        assert_eq!(sheet.row_count(), 3);
        if let ExcelCell::Formula(f) = &sheet.rows[2][0] {
            assert_eq!(f, "SUM(A1:A2)");
        } else {
            panic!("expected Formula cell");
        }
    }

    #[test]
    fn test_excel_set_cell_formula() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Test");
        sheet.add_row(vec![ExcelCell::Integer(1)]);
        sheet.add_row(vec![ExcelCell::Integer(2)]);
        sheet.set_cell_formula("A3", "A1+A2");

        assert_eq!(sheet.row_count(), 3);
        if let ExcelCell::Formula(f) = &sheet.rows[2][0] {
            assert_eq!(f, "A1+A2");
        } else {
            panic!("expected Formula cell");
        }
    }

    #[test]
    fn test_excel_date_cell() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Dates");
        sheet.add_row(vec![ExcelCell::Date("2024-01-15".to_string())]);

        let bytes = wb.to_bytes().expect("date xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut sheet_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/worksheets/sheet1.xml").unwrap();
            file.read_to_string(&mut sheet_content).unwrap();
        }
        // Should contain a numeric value (serial date) not a text value
        assert!(sheet_content.contains("<v>"), "should contain a value element");
        // The date style should reference numFmtId=14
        let mut styles_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/styles.xml").unwrap();
            file.read_to_string(&mut styles_content).unwrap();
        }
        assert!(styles_content.contains("numFmtId=\"14\""), "should have date number format");
    }

    #[test]
    fn test_excel_hyperlink() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Links");
        sheet.add_row(vec![ExcelCell::Hyperlink(
            "Click here".to_string(),
            "https://example.com".to_string(),
        )]);

        let bytes = wb.to_bytes().expect("hyperlink xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut sheet_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/worksheets/sheet1.xml").unwrap();
            file.read_to_string(&mut sheet_content).unwrap();
        }
        assert!(sheet_content.contains("<hyperlinks>"), "should contain hyperlinks section");
    }

    #[test]
    fn test_excel_merge_cells() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Merge");
        sheet.add_row(vec![
            ExcelCell::Text("Merged Title".to_string()),
            ExcelCell::Empty,
            ExcelCell::Empty,
        ]);
        sheet.merges.push(("A1".to_string(), "C1".to_string()));

        let bytes = wb.to_bytes().expect("merge xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut sheet_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/worksheets/sheet1.xml").unwrap();
            file.read_to_string(&mut sheet_content).unwrap();
        }
        assert!(sheet_content.contains("<mergeCells"), "should contain mergeCells");
        assert!(sheet_content.contains("A1:C1"), "should contain merge range");
    }

    #[test]
    fn test_excel_auto_filter() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Filter");
        sheet.add_header(&["Name", "Age"]);
        sheet.add_row(vec![ExcelCell::Text("Alice".to_string()), ExcelCell::Integer(30)]);
        sheet.auto_filter = Some("A1:B2".to_string());

        let bytes = wb.to_bytes().expect("autofilter xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut sheet_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/worksheets/sheet1.xml").unwrap();
            file.read_to_string(&mut sheet_content).unwrap();
        }
        assert!(sheet_content.contains("<autoFilter ref=\"A1:B2\"/>"), "should contain autoFilter");
    }

    #[test]
    fn test_excel_freeze_panes() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Freeze");
        sheet.add_header(&["Col1", "Col2"]);
        sheet.add_row(vec![ExcelCell::Integer(1), ExcelCell::Integer(2)]);
        sheet.freeze_row = Some(1);

        let bytes = wb.to_bytes().expect("freeze panes xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut sheet_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/worksheets/sheet1.xml").unwrap();
            file.read_to_string(&mut sheet_content).unwrap();
        }
        assert!(sheet_content.contains("<pane"), "should contain pane element");
        assert!(sheet_content.contains("frozen"), "should have frozen state");
    }

    #[test]
    fn test_excel_col_width_row_height() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Sizing");
        sheet.add_row(vec![ExcelCell::Text("Wide column".to_string())]);
        sheet.col_widths.push((0, 25.0));
        sheet.row_heights.push((0, 30.0));

        let bytes = wb.to_bytes().expect("sizing xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut sheet_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/worksheets/sheet1.xml").unwrap();
            file.read_to_string(&mut sheet_content).unwrap();
        }
        assert!(sheet_content.contains("<cols>"), "should contain cols element");
        assert!(sheet_content.contains("width=\"25.00\""), "should have column width");
        assert!(sheet_content.contains("ht=\"30.00\""), "should have row height");
        assert!(sheet_content.contains("customHeight=\"1\""), "should have customHeight");
    }

    #[test]
    fn test_excel_cell_format() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Formatted");
        sheet.add_row(vec![ExcelCell::Text("Red bold".to_string())]);
        sheet.set_cell_format(0, 0, CellFormat {
            bold: true,
            font_color: Some("FF0000".to_string()),
            font_size: Some(14),
            ..Default::default()
        });

        let bytes = wb.to_bytes().expect("formatted xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut styles_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/styles.xml").unwrap();
            file.read_to_string(&mut styles_content).unwrap();
        }
        assert!(styles_content.contains("<b/>"), "should have bold in font");
        assert!(styles_content.contains("FFFF0000"), "should have red font color");
        assert!(styles_content.contains("val=\"14\""), "should have font size 14");
    }

    #[test]
    fn test_excel_number_format() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("NumFmt");
        sheet.add_row(vec![ExcelCell::Number(1234.56)]);
        sheet.set_cell_format(0, 0, CellFormat {
            number_format: Some("$#,##0.00".to_string()),
            ..Default::default()
        });

        let bytes = wb.to_bytes().expect("numfmt xlsx should succeed");
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn test_excel_border() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Borders");
        sheet.add_row(vec![ExcelCell::Text("Bordered".to_string())]);
        sheet.set_cell_format(0, 0, CellFormat {
            border: Some("thin".to_string()),
            ..Default::default()
        });

        let bytes = wb.to_bytes().expect("border xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut styles_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/styles.xml").unwrap();
            file.read_to_string(&mut styles_content).unwrap();
        }
        assert!(styles_content.contains("style=\"thin\""), "should have thin border style");
    }

    #[test]
    fn test_excel_bg_color() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("BgColor");
        sheet.add_row(vec![ExcelCell::Text("Yellow bg".to_string())]);
        sheet.set_cell_format(0, 0, CellFormat {
            bg_color: Some("FFFF00".to_string()),
            ..Default::default()
        });

        let bytes = wb.to_bytes().expect("bgcolor xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut styles_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/styles.xml").unwrap();
            file.read_to_string(&mut styles_content).unwrap();
        }
        assert!(styles_content.contains("FFFFFF00"), "should have yellow fill color");
    }

    #[test]
    fn test_excel_alignment_wrap() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Align");
        sheet.add_row(vec![ExcelCell::Text("Centered".to_string())]);
        sheet.set_cell_format(0, 0, CellFormat {
            alignment: Some("center".to_string()),
            wrap_text: true,
            ..Default::default()
        });

        let bytes = wb.to_bytes().expect("alignment xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut styles_content = String::new();
        {
            use std::io::Read;
            let mut file = archive.by_name("xl/styles.xml").unwrap();
            file.read_to_string(&mut styles_content).unwrap();
        }
        assert!(styles_content.contains("horizontal=\"center\""), "should have center alignment");
        assert!(styles_content.contains("wrapText=\"1\""), "should have wrap text");
    }

    // ── Word tests ──

    #[test]
    fn test_empty_word_document() {
        let doc = WordDocument::new();
        assert!(doc.elements.is_empty());
    }

    #[test]
    fn test_word_add_elements() {
        let mut doc = WordDocument::new();
        doc.add_heading("Title", 1);
        doc.add_paragraph("Some text");
        doc.add_bold("Bold text");
        doc.add_italic("Italic text");
        doc.add_bullet_list(&["item 1", "item 2"]);
        doc.add_numbered_list(&["first", "second"]);
        doc.add_page_break();
        doc.add_horizontal_rule();
        assert_eq!(doc.elements.len(), 8);
    }

    #[test]
    fn test_word_add_table() {
        let mut doc = WordDocument::new();
        doc.add_table(
            &["Header A", "Header B"],
            &[
                vec!["r1c1".to_string(), "r1c2".to_string()],
                vec!["r2c1".to_string(), "r2c2".to_string()],
            ],
        );
        assert_eq!(doc.elements.len(), 1);
        if let DocElement::Table(ref t) = doc.elements[0] {
            assert_eq!(t.headers.len(), 2);
            assert_eq!(t.rows.len(), 2);
        } else {
            panic!("expected Table element");
        }
    }

    #[test]
    fn test_docx_generation() {
        let mut doc = WordDocument::new();
        doc.add_heading("Test Document", 1);
        doc.add_paragraph("This is a paragraph.");
        doc.add_bold("Bold text here.");
        doc.add_table(
            &["Col1", "Col2"],
            &[vec!["a".to_string(), "b".to_string()]],
        );
        doc.add_bullet_list(&["bullet one", "bullet two"]);

        let bytes = doc.to_bytes().expect("docx generation should succeed");
        assert!(bytes.len() > 100, "docx should have substantial content");
        assert_eq!(&bytes[0..2], b"PK", "docx must start with PK (ZIP magic)");

        // Verify ZIP structure
        let reader = Cursor::new(&bytes);
        let archive = zip::ZipArchive::new(reader).expect("should be valid ZIP");
        let expected_files = [
            "[Content_Types].xml",
            "_rels/.rels",
            "word/document.xml",
            "word/_rels/document.xml.rels",
            "word/styles.xml",
            "word/numbering.xml",
        ];
        for name in &expected_files {
            assert!(
                archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == *name)),
                "docx should contain {name}"
            );
        }
    }

    #[test]
    fn test_docx_xml_escaping() {
        let mut doc = WordDocument::new();
        doc.add_paragraph("5 < 10 & 20 > 15 \"quoted\" 'apos'");

        let bytes = doc.to_bytes().expect("docx with special chars should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut doc_content = String::new();
        {
            use std::io::Read;
            let mut file = archive
                .by_name("word/document.xml")
                .expect("document.xml must exist");
            file.read_to_string(&mut doc_content).unwrap();
        }
        assert!(doc_content.contains("5 &lt; 10 &amp; 20 &gt; 15 &quot;quoted&quot; &apos;apos&apos;"));
    }

    #[test]
    fn test_word_report() {
        let sections = vec![
            ("Introduction".to_string(), "This is the intro.".to_string()),
            ("Conclusion".to_string(), "This is the conclusion.".to_string()),
        ];
        let bytes = create_word_report("My Report", &sections)
            .expect("word_report should succeed");
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn test_markdown_to_word() {
        let md = "# Main Title\n\n\
                  ## Section One\n\n\
                  This is a paragraph.\n\n\
                  **Bold statement**\n\n\
                  *Italic note*\n\n\
                  - bullet one\n\
                  - bullet two\n\n\
                  1. first\n\
                  2. second\n\n\
                  ---\n\n\
                  Another paragraph.";
        let bytes = create_word_from_markdown(md).expect("markdown_to_word should succeed");
        assert_eq!(&bytes[0..2], b"PK");

        // Verify the content has the expected elements
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut doc_content = String::new();
        {
            use std::io::Read;
            let mut file = archive
                .by_name("word/document.xml")
                .expect("document.xml must exist");
            file.read_to_string(&mut doc_content).unwrap();
        }
        assert!(doc_content.contains("Heading1"), "should have Heading1 style");
        assert!(doc_content.contains("Heading2"), "should have Heading2 style");
        assert!(doc_content.contains("Main Title"), "should have title text");
        assert!(doc_content.contains("<w:b/>"), "should have bold runs");
        assert!(doc_content.contains("<w:i/>"), "should have italic runs");
        assert!(doc_content.contains("numId"), "should have list numbering");
    }

    #[test]
    fn test_xlsx_multiple_sheets() {
        let mut wb = ExcelWorkbook::new();
        let s1 = wb.add_sheet("Sheet1");
        s1.add_row(vec![ExcelCell::Text("a".to_string())]);
        let s2 = wb.add_sheet("Sheet2");
        s2.add_row(vec![ExcelCell::Integer(42)]);
        let s3 = wb.add_sheet("Sheet3");
        s3.add_row(vec![ExcelCell::Number(3.14)]);

        let bytes = wb.to_bytes().expect("multi-sheet xlsx should succeed");
        let reader = Cursor::new(&bytes);
        let archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        for i in 1..=3 {
            let name = format!("xl/worksheets/sheet{i}.xml");
            assert!(
                archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == name)),
                "should contain {name}"
            );
        }
    }

    #[test]
    fn test_xlsx_shared_strings_dedup() {
        let mut wb = ExcelWorkbook::new();
        let sheet = wb.add_sheet("Test");
        // Add the same string multiple times
        sheet.add_row(vec![
            ExcelCell::Text("hello".to_string()),
            ExcelCell::Text("world".to_string()),
            ExcelCell::Text("hello".to_string()), // duplicate
        ]);

        let bytes = wb.to_bytes().expect("dedup test should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut ss_content = String::new();
        {
            use std::io::Read;
            let mut file = archive
                .by_name("xl/sharedStrings.xml")
                .expect("sharedStrings.xml must exist");
            file.read_to_string(&mut ss_content).unwrap();
        }
        // "hello" should appear only once as <si><t>hello</t></si>
        let count = ss_content.matches("<si><t>hello</t></si>").count();
        assert_eq!(count, 1, "shared strings should deduplicate 'hello'");
    }

    // ── Word new feature tests ──

    #[test]
    fn test_word_underline() {
        let mut doc = WordDocument::new();
        doc.add_underline("Underlined text");

        let bytes = doc.to_bytes().expect("underline docx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("<w:u w:val=\"single\"/>"), "should have underline");
        assert!(content.contains("Underlined text"), "should have text");
    }

    #[test]
    fn test_word_strikethrough() {
        let mut doc = WordDocument::new();
        doc.add_strikethrough("Struck text");

        let bytes = doc.to_bytes().expect("strikethrough docx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("<w:strike/>"), "should have strikethrough");
    }

    #[test]
    fn test_word_superscript_subscript() {
        let mut doc = WordDocument::new();
        doc.add_superscript("sup");
        doc.add_subscript("sub");

        let bytes = doc.to_bytes().expect("super/subscript docx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("vertAlign w:val=\"superscript\""), "should have superscript");
        assert!(content.contains("vertAlign w:val=\"subscript\""), "should have subscript");
    }

    #[test]
    fn test_word_aligned() {
        let mut doc = WordDocument::new();
        doc.add_aligned("Centered text", "center");
        doc.add_aligned("Right text", "right");
        doc.add_aligned("Justified text", "justify");

        let bytes = doc.to_bytes().expect("aligned docx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("w:jc w:val=\"center\""), "should have center alignment");
        assert!(content.contains("w:jc w:val=\"right\""), "should have right alignment");
        assert!(content.contains("w:jc w:val=\"both\""), "should have justify alignment (both)");
    }

    #[test]
    fn test_word_page_margins() {
        let mut doc = WordDocument::new();
        doc.margin_top = 720;
        doc.margin_bottom = 720;
        doc.margin_left = 1080;
        doc.margin_right = 1080;
        doc.add_paragraph("Custom margins");

        let bytes = doc.to_bytes().expect("margins docx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("w:top=\"720\""), "should have top margin 720");
        assert!(content.contains("w:bottom=\"720\""), "should have bottom margin 720");
        assert!(content.contains("w:left=\"1080\""), "should have left margin 1080");
    }

    #[test]
    fn test_word_page_size() {
        let mut doc = WordDocument::new();
        doc.page_width = 15840;  // 11 inches (landscape)
        doc.page_height = 12240; // 8.5 inches
        doc.add_paragraph("Landscape page");

        let bytes = doc.to_bytes().expect("page size docx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("w:w=\"15840\""), "should have page width 15840");
        assert!(content.contains("w:h=\"12240\""), "should have page height 12240");
    }

    #[test]
    fn test_word_header_footer() {
        let mut doc = WordDocument::new();
        doc.header_text = Some("My Document Header".to_string());
        doc.footer_text = Some("My Document Footer".to_string());
        doc.add_paragraph("Body content");

        let bytes = doc.to_bytes().expect("header/footer docx should succeed");
        let reader = Cursor::new(&bytes);
        let archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        assert!(archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == "word/header1.xml")), "should have header file");
        assert!(archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == "word/footer1.xml")), "should have footer file");

        // Read header
        let reader2 = Cursor::new(&bytes);
        let mut archive2 = zip::ZipArchive::new(reader2).unwrap();
        let mut header_content = String::new();
        {
            use std::io::Read;
            let mut f = archive2.by_name("word/header1.xml").unwrap();
            f.read_to_string(&mut header_content).unwrap();
        }
        assert!(header_content.contains("My Document Header"), "header should contain text");

        let reader3 = Cursor::new(&bytes);
        let mut archive3 = zip::ZipArchive::new(reader3).unwrap();
        let mut footer_content = String::new();
        {
            use std::io::Read;
            let mut f = archive3.by_name("word/footer1.xml").unwrap();
            f.read_to_string(&mut footer_content).unwrap();
        }
        assert!(footer_content.contains("My Document Footer"), "footer should contain text");
        assert!(footer_content.contains("PAGE"), "footer should contain page number field");
    }

    #[test]
    fn test_word_link() {
        let mut doc = WordDocument::new();
        doc.add_link("Visit Example", "https://example.com");

        let bytes = doc.to_bytes().expect("link docx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("hyperlink"), "should contain hyperlink element");
        assert!(content.contains("Visit Example"), "should contain display text");

        let reader2 = Cursor::new(&bytes);
        let mut archive2 = zip::ZipArchive::new(reader2).unwrap();
        let mut rels_content = String::new();
        {
            use std::io::Read;
            let mut f = archive2.by_name("word/_rels/document.xml.rels").unwrap();
            f.read_to_string(&mut rels_content).unwrap();
        }
        assert!(rels_content.contains("https://example.com"), "rels should contain URL");
    }

    #[test]
    fn test_word_image() {
        let mut doc = WordDocument::new();
        // Create a minimal 1x1 PNG
        let png_data: Vec<u8> = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG magic
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
            0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
            0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x01, 0xE2, 0x21, 0xBC,
            0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
            0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        doc.add_image(png_data, 5.0, 3.0, "Test image");

        let bytes = doc.to_bytes().expect("image docx should succeed");
        let reader = Cursor::new(&bytes);
        let archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        assert!(archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == "word/media/image1.png")), "should have image file");

        let reader2 = Cursor::new(&bytes);
        let mut archive2 = zip::ZipArchive::new(reader2).unwrap();
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive2.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("w:drawing"), "should contain drawing element");
        assert!(content.contains("a:blip"), "should contain blip (image reference)");
        assert!(content.contains("Test image"), "should contain alt text");
    }

    #[test]
    fn test_word_toc() {
        let mut doc = WordDocument::new();
        doc.add_table_of_contents();
        doc.add_heading("Chapter 1", 1);
        doc.add_paragraph("Content here.");

        let bytes = doc.to_bytes().expect("toc docx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("TOC"), "should contain TOC field code");
    }

    #[test]
    fn test_word_nested_bullet_list() {
        let mut doc = WordDocument::new();
        doc.add_nested_bullet_list(&[
            (0, "Top level".to_string()),
            (1, "Sub item".to_string()),
            (2, "Sub-sub item".to_string()),
            (0, "Back to top".to_string()),
        ]);

        let bytes = doc.to_bytes().expect("nested bullet docx should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("w:ilvl w:val=\"0\""), "should have level 0");
        assert!(content.contains("w:ilvl w:val=\"1\""), "should have level 1");
        assert!(content.contains("w:ilvl w:val=\"2\""), "should have level 2");
    }

    #[test]
    fn test_markdown_strikethrough_underline_link() {
        let md = "~~struck~~\n\n__underlined__\n\n[Google](https://google.com)";
        let bytes = create_word_from_markdown(md).expect("markdown extras should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("word/document.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("<w:strike/>"), "should have strikethrough from markdown");
        assert!(content.contains("<w:u w:val=\"single\"/>"), "should have underline from markdown");
        assert!(content.contains("hyperlink"), "should have hyperlink from markdown");
    }

    // ── Dispatch tests ──

    #[test]
    fn test_dispatch_unknown_returns_none() {
        let result = dispatch("unknown_function", vec![]);
        assert!(result.is_none());
    }

    #[test]
    fn test_dispatch_excel_create() {
        let result = dispatch("excel_create", vec![]);
        assert!(result.is_some());
        let val = result.unwrap().expect("excel_create should succeed");
        if let Value::Struct { name, .. } = val {
            assert_eq!(name, "ExcelWorkbook");
        } else {
            panic!("expected Struct");
        }
    }

    #[test]
    fn test_dispatch_word_create() {
        let result = dispatch("word_create", vec![]);
        assert!(result.is_some());
        let val = result.unwrap().expect("word_create should succeed");
        if let Value::Struct { name, .. } = val {
            assert_eq!(name, "WordDocument");
        } else {
            panic!("expected Struct");
        }
    }

    #[test]
    fn test_dispatch_csv_to_excel() {
        let csv = "a,b,c\n1,2,3";
        let result = dispatch("csv_to_excel", vec![Value::String(csv.to_string())]);
        assert!(result.is_some());
        let val = result.unwrap().expect("csv_to_excel should succeed");
        if let Value::String(b64) = val {
            assert!(!b64.is_empty(), "should return non-empty base64");
        } else {
            panic!("expected String");
        }
    }

    #[test]
    fn test_dispatch_json_to_excel() {
        let json = r#"[{"x": 1}]"#;
        let result = dispatch(
            "json_to_excel",
            vec![
                Value::String(json.to_string()),
                Value::String("Data".to_string()),
            ],
        );
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_dispatch_markdown_to_word() {
        let md = "# Hello\n\nWorld";
        let result = dispatch("markdown_to_word", vec![Value::String(md.to_string())]);
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_dispatch_excel_formula() {
        // Create workbook, add sheet, then add formula
        let wb = dispatch("excel_create", vec![]).unwrap().unwrap();
        let wb = dispatch("excel_add_sheet", vec![wb, Value::String("Test".to_string())]).unwrap().unwrap();
        let wb = dispatch("excel_add_row", vec![
            wb,
            Value::String("0".to_string()),
            Value::Array(vec![Value::Int(10)]),
        ]).unwrap().unwrap();
        let wb = dispatch("excel_add_formula", vec![
            wb,
            Value::String("0".to_string()),
            Value::String("A2".to_string()),
            Value::String("A1*2".to_string()),
        ]).unwrap().unwrap();

        // Save should work
        let result = dispatch("excel_to_bytes", vec![wb]);
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_dispatch_word_new_features() {
        let doc = dispatch("word_create", vec![]).unwrap().unwrap();
        let doc = dispatch("word_add_underline", vec![doc, Value::String("test".to_string())]).unwrap().unwrap();
        let doc = dispatch("word_add_strikethrough", vec![doc, Value::String("test".to_string())]).unwrap().unwrap();
        let doc = dispatch("word_add_superscript", vec![doc, Value::String("2".to_string())]).unwrap().unwrap();
        let doc = dispatch("word_add_subscript", vec![doc, Value::String("i".to_string())]).unwrap().unwrap();
        let doc = dispatch("word_add_aligned", vec![doc, Value::String("centered".to_string()), Value::String("center".to_string())]).unwrap().unwrap();
        let doc = dispatch("word_add_link", vec![doc, Value::String("Link".to_string()), Value::String("https://example.com".to_string())]).unwrap().unwrap();
        let doc = dispatch("word_add_toc", vec![doc]).unwrap().unwrap();
        let doc = dispatch("word_set_header", vec![doc, Value::String("Header".to_string())]).unwrap().unwrap();
        let doc = dispatch("word_set_footer", vec![doc, Value::String("Footer".to_string())]).unwrap().unwrap();
        let doc = dispatch("word_set_margins", vec![doc, Value::Int(720), Value::Int(720), Value::Int(720), Value::Int(720)]).unwrap().unwrap();
        let doc = dispatch("word_set_page_size", vec![doc, Value::Int(15840), Value::Int(12240)]).unwrap().unwrap();

        let result = dispatch("word_to_bytes", vec![doc]);
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    // ── XML escape tests ──

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("hello"), "hello");
        assert_eq!(xml_escape("<>&\"'"), "&lt;&gt;&amp;&quot;&apos;");
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape(""), "");
    }

    // ── Date serial tests ──

    #[test]
    fn test_date_to_serial() {
        // 2024-01-01 should be a positive number > 45000
        let serial = date_to_serial("2024-01-01");
        assert!(serial > 45000, "2024-01-01 serial should be > 45000, got {serial}");
        // 1900-01-01 should be 1 (plus the Lotus bug offset)
        let serial1 = date_to_serial("1900-01-01");
        assert_eq!(serial1, 1, "1900-01-01 should be serial 1");
    }

    // ── PDF tests ──

    #[test]
    fn test_pdf_escape() {
        assert_eq!(pdf_escape("hello"), "hello");
        assert_eq!(pdf_escape("a(b)c"), "a\\(b\\)c");
        assert_eq!(pdf_escape("back\\slash"), "back\\\\slash");
        assert_eq!(pdf_escape("new\nline"), "new\\nline");
    }

    #[test]
    fn test_wrap_text() {
        let lines = wrap_text("hello world", 12.0, 60.0); // 60pt = ~10 chars at 12pt
        assert!(!lines.is_empty());

        let lines = wrap_text("short", 12.0, 200.0);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "short");

        let lines = wrap_text("line1\nline2", 12.0, 200.0);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_pdf_empty_document() {
        let doc = PdfDocument::new();
        let bytes = doc.to_bytes().expect("empty PDF should succeed");
        assert!(bytes.len() > 50, "PDF should have header + structure");
        let header = String::from_utf8_lossy(&bytes[..9]);
        assert!(header.starts_with("%PDF-1.4"), "must start with PDF header");
        let tail = String::from_utf8_lossy(&bytes);
        assert!(tail.contains("%%EOF"), "must end with EOF marker");
    }

    #[test]
    fn test_pdf_with_content() {
        let mut doc = PdfDocument::new();
        doc.set_title("Test Report");
        doc.set_author("Tallow");
        doc.add_heading("Main Title", 1);
        doc.add_paragraph("This is a paragraph of body text.");
        doc.add_bold("Bold text here");
        doc.add_horizontal_rule();
        doc.add_bullet_list(&["Item A", "Item B", "Item C"]);
        doc.add_numbered_list(&["First", "Second", "Third"]);
        doc.add_table(
            vec!["Name".to_string(), "Value".to_string()],
            vec![
                vec!["alpha".to_string(), "100".to_string()],
                vec!["beta".to_string(), "200".to_string()],
            ],
        );

        let bytes = doc.to_bytes().expect("PDF with content should succeed");
        assert!(bytes.len() > 200, "PDF should have substantial content");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Test Report"), "title should appear in info dict");
        assert!(text.contains("/Helvetica"), "should reference Helvetica font");
        assert!(text.contains("/Helvetica-Bold"), "should reference Helvetica-Bold font");
        assert!(text.contains("xref"), "must have xref table");
        assert!(text.contains("trailer"), "must have trailer");
    }

    #[test]
    fn test_pdf_page_break() {
        let mut doc = PdfDocument::new();
        doc.add_heading("Page 1", 1);
        doc.add_page_break();
        doc.add_heading("Page 2", 1);

        let bytes = doc.to_bytes().expect("PDF with page break should succeed");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("/Count 2"), "should have 2 pages");
    }

    #[test]
    fn test_pdf_auto_pagination() {
        let mut doc = PdfDocument::new();
        // Add enough paragraphs to force multiple pages
        for i in 0..100 {
            doc.add_paragraph(&format!(
                "Paragraph {} with enough text to take up space on the page and eventually cause a page break to occur.",
                i
            ));
        }

        let bytes = doc.to_bytes().expect("PDF with many paragraphs should succeed");
        let text = String::from_utf8_lossy(&bytes);
        // Should have more than 1 page
        assert!(!text.contains("/Count 1"), "100 paragraphs should span multiple pages");
    }

    #[test]
    fn test_pdf_table_with_wrapping() {
        let mut doc = PdfDocument::new();
        doc.add_table(
            vec!["Column A".to_string(), "Column B".to_string(), "Column C".to_string()],
            vec![
                vec!["short".to_string(), "medium length text".to_string(), "this is a longer cell value that should wrap".to_string()],
                vec!["x".to_string(), "y".to_string(), "z".to_string()],
            ],
        );

        let bytes = doc.to_bytes().expect("PDF table should succeed");
        assert!(bytes.len() > 100);
    }

    #[test]
    fn test_pdf_special_chars() {
        let mut doc = PdfDocument::new();
        doc.add_paragraph("Parentheses (like this) and backslash \\ test");
        doc.add_heading("Title with (parens)", 1);

        let bytes = doc.to_bytes().expect("PDF with special chars should succeed");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("\\(like this\\)"), "parens should be escaped");
    }

    #[test]
    fn test_pdf_report_convenience() {
        let sections = vec![
            ("Introduction".to_string(), "This is the intro.".to_string()),
            ("Methods".to_string(), "We did things.".to_string()),
            ("Results".to_string(), "Things happened.".to_string()),
        ];
        let bytes = create_pdf_report("My Report", &sections).expect("pdf report should succeed");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("My Report"));
        assert!(text.contains("%PDF-1.4"));
    }

    #[test]
    fn test_dispatch_pdf_lifecycle() {
        // Create
        let doc = dispatch("pdf_create", vec![Value::String("Test".to_string())]).unwrap().unwrap();
        if let Value::Struct { name, .. } = &doc {
            assert_eq!(name, "PdfDocument");
        } else {
            panic!("pdf_create should return a Struct");
        }

        // Add elements
        let doc = dispatch("pdf_add_heading", vec![doc, Value::String("Title".to_string()), Value::Int(1)]).unwrap().unwrap();
        let doc = dispatch("pdf_add_paragraph", vec![doc, Value::String("Body text.".to_string())]).unwrap().unwrap();
        let doc = dispatch("pdf_add_bold", vec![doc, Value::String("Bold.".to_string())]).unwrap().unwrap();
        let doc = dispatch("pdf_add_bullets", vec![
            doc,
            Value::Array(vec![Value::String("A".to_string()), Value::String("B".to_string())]),
        ]).unwrap().unwrap();
        let doc = dispatch("pdf_add_numbered_list", vec![
            doc,
            Value::Array(vec![Value::String("One".to_string()), Value::String("Two".to_string())]),
        ]).unwrap().unwrap();
        let doc = dispatch("pdf_add_table", vec![
            doc,
            Value::Array(vec![Value::String("H1".to_string()), Value::String("H2".to_string())]),
            Value::Array(vec![
                Value::Array(vec![Value::String("a".to_string()), Value::String("b".to_string())]),
            ]),
        ]).unwrap().unwrap();
        let doc = dispatch("pdf_add_horizontal_rule", vec![doc]).unwrap().unwrap();
        let doc = dispatch("pdf_add_spacer", vec![doc, Value::Float(20.0)]).unwrap().unwrap();
        let doc = dispatch("pdf_add_page_break", vec![doc]).unwrap().unwrap();
        let doc = dispatch("pdf_add_heading", vec![doc, Value::String("Page 2".to_string()), Value::Int(2)]).unwrap().unwrap();

        // Convert to bytes
        let result = dispatch("pdf_to_bytes", vec![doc]);
        assert!(result.is_some());
        let b64 = result.unwrap().unwrap();
        if let Value::String(s) = b64 {
            assert!(!s.is_empty(), "base64 output should not be empty");
            // Decode and verify PDF header
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD.decode(&s).expect("valid base64");
            assert!(decoded.len() > 100);
            assert_eq!(&decoded[..5], b"%PDF-");
        } else {
            panic!("pdf_to_bytes should return a String");
        }
    }

    #[test]
    fn test_dispatch_pdf_report() {
        let sections = Value::Array(vec![
            Value::Array(vec![
                Value::String("Section 1".to_string()),
                Value::String("Content of section 1.".to_string()),
            ]),
            Value::Array(vec![
                Value::String("Section 2".to_string()),
                Value::String("Content of section 2.".to_string()),
            ]),
        ]);

        let result = dispatch("pdf_report", vec![Value::String("Report Title".to_string()), sections]);
        assert!(result.is_some());
        let val = result.unwrap().unwrap();
        if let Value::String(s) = val {
            assert!(!s.is_empty());
        } else {
            panic!("pdf_report should return base64 string");
        }
    }

    // ── PPTX tests ──

    #[test]
    fn test_pptx_empty_presentation() {
        let pres = PptxPresentation::new("Test");
        assert!(pres.slides.is_empty());
        assert_eq!(pres.title, "Test");
        assert_eq!(pres.width_emu, 12_192_000);
        assert_eq!(pres.height_emu, 6_858_000);
    }

    #[test]
    fn test_pptx_add_slide() {
        let mut pres = PptxPresentation::new("Test");
        pres.add_slide(SlideLayout::TitleSlide);
        pres.add_slide(SlideLayout::Blank);
        assert_eq!(pres.slides.len(), 2);
    }

    #[test]
    fn test_pptx_slide_elements() {
        let mut pres = PptxPresentation::new("Test");
        let slide = pres.add_slide(SlideLayout::TitleContent);
        slide.add_title("My Title");
        slide.add_subtitle("My Subtitle");
        slide.add_bullet_list(&["item1".to_string(), "item2".to_string()]);
        assert_eq!(slide.elements.len(), 3);
    }

    #[test]
    fn test_pptx_generation() {
        let mut pres = PptxPresentation::new("Test Presentation");
        let slide = pres.add_slide(SlideLayout::TitleSlide);
        slide.add_title("Hello World");
        slide.add_subtitle("A test presentation");

        let slide2 = pres.add_slide(SlideLayout::TitleContent);
        slide2.add_title("Content Slide");
        slide2.add_bullet_list(&["Point 1".to_string(), "Point 2".to_string(), "Point 3".to_string()]);

        let bytes = pres.to_bytes().expect("pptx generation should succeed");
        assert!(bytes.len() > 100, "pptx should have substantial content");
        assert_eq!(&bytes[0..2], b"PK", "pptx must start with PK (ZIP magic)");

        let reader = Cursor::new(&bytes);
        let archive = zip::ZipArchive::new(reader).expect("should be valid ZIP");
        let expected = [
            "[Content_Types].xml",
            "_rels/.rels",
            "ppt/presentation.xml",
            "ppt/_rels/presentation.xml.rels",
            "ppt/slideMasters/slideMaster1.xml",
            "ppt/slideLayouts/slideLayout1.xml",
            "ppt/theme/theme1.xml",
            "ppt/slides/slide1.xml",
            "ppt/slides/slide2.xml",
        ];
        for name in &expected {
            assert!(archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == *name)), "pptx should contain {name}");
        }
    }

    #[test]
    fn test_pptx_xml_escaping() {
        let mut pres = PptxPresentation::new("Test <&>");
        let slide = pres.add_slide(SlideLayout::Blank);
        slide.add_title("Title with <special> & \"chars\"");

        let bytes = pres.to_bytes().expect("pptx with special chars should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("ppt/slides/slide1.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("&lt;special&gt;"), "should escape angle brackets");
        assert!(content.contains("&amp;"), "should escape ampersand");
        assert!(content.contains("&quot;chars&quot;"), "should escape quotes");
    }

    #[test]
    fn test_pptx_table() {
        let mut pres = PptxPresentation::new("Table Test");
        let slide = pres.add_slide(SlideLayout::Blank);
        slide.add_table(
            &["Name".to_string(), "Value".to_string()],
            &[vec!["Alice".to_string(), "100".to_string()], vec!["Bob".to_string(), "200".to_string()]],
            914400, 1714500, 10363200, 4000000,
        );

        let bytes = pres.to_bytes().expect("pptx with table should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("ppt/slides/slide1.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("<a:tbl>"), "should contain table element");
        assert!(content.contains("Alice"), "should contain cell data");
    }

    #[test]
    fn test_pptx_numbered_list() {
        let mut pres = PptxPresentation::new("List Test");
        let slide = pres.add_slide(SlideLayout::Blank);
        slide.add_numbered_list(&["First".to_string(), "Second".to_string()]);

        let bytes = pres.to_bytes().expect("pptx with numbered list should succeed");
        let reader = Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(reader).expect("valid ZIP");

        let mut content = String::new();
        {
            use std::io::Read;
            let mut f = archive.by_name("ppt/slides/slide1.xml").unwrap();
            f.read_to_string(&mut content).unwrap();
        }
        assert!(content.contains("arabicPeriod"), "should contain numbered list");
    }

    #[test]
    fn test_pptx_report() {
        let slides = vec![
            ("Overview".to_string(), vec!["Key finding 1".to_string(), "Key finding 2".to_string()]),
            ("Details".to_string(), vec!["Detail A".to_string(), "Detail B".to_string()]),
        ];
        let bytes = create_pptx_report("Quarterly Report", &slides).expect("pptx_report should succeed");
        assert_eq!(&bytes[0..2], b"PK");

        let reader = Cursor::new(&bytes);
        let archive = zip::ZipArchive::new(reader).expect("valid ZIP");
        // Title slide + 2 content slides = 3
        assert!(archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == "ppt/slides/slide1.xml")));
        assert!(archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == "ppt/slides/slide2.xml")));
        assert!(archive.file_names().any(|f| f.is_ok_and(|n| n.as_ref() == "ppt/slides/slide3.xml")));
    }

    #[test]
    fn test_dispatch_pptx_create() {
        let result = dispatch("pptx_create", vec![Value::String("My Pres".to_string())]);
        assert!(result.is_some());
        let val = result.unwrap().expect("pptx_create should succeed");
        if let Value::Struct { name, .. } = val {
            assert_eq!(name, "PptxPresentation");
        } else {
            panic!("expected Struct");
        }
    }

    #[test]
    fn test_dispatch_pptx_lifecycle() {
        let pptx = dispatch("pptx_create", vec![Value::String("Test".to_string())]).unwrap().unwrap();
        let pptx = dispatch("pptx_add_slide", vec![pptx, Value::String("title_slide".to_string())]).unwrap().unwrap();
        let pptx = dispatch("pptx_add_title", vec![pptx, Value::String("Hello".to_string())]).unwrap().unwrap();
        let pptx = dispatch("pptx_add_subtitle", vec![pptx, Value::String("World".to_string())]).unwrap().unwrap();
        let pptx = dispatch("pptx_add_slide", vec![pptx, Value::String("blank".to_string())]).unwrap().unwrap();
        let pptx = dispatch("pptx_add_bullets", vec![pptx, Value::Array(vec![Value::String("A".to_string()), Value::String("B".to_string())])]).unwrap().unwrap();

        let result = dispatch("pptx_to_bytes", vec![pptx]);
        assert!(result.is_some());
        let val = result.unwrap().unwrap();
        if let Value::String(b64) = val {
            assert!(!b64.is_empty(), "should return non-empty base64");
        } else {
            panic!("expected String");
        }
    }

    #[test]
    fn test_dispatch_pptx_report() {
        let slides = Value::Array(vec![
            Value::Array(vec![
                Value::String("Slide 1".to_string()),
                Value::Array(vec![Value::String("Bullet A".to_string()), Value::String("Bullet B".to_string())]),
            ]),
        ]);
        let result = dispatch("pptx_report", vec![Value::String("Report".to_string()), slides]);
        assert!(result.is_some());
        let val = result.unwrap().unwrap();
        if let Value::String(s) = val {
            assert!(!s.is_empty());
        } else {
            panic!("pptx_report should return base64 string");
        }
    }

    // ── CSV tests ──

    #[test]
    fn test_csv_to_string_basic() {
        let result = dispatch(
            "csv_to_string",
            vec![
                Value::Array(vec![
                    Value::String("name".into()),
                    Value::String("age".into()),
                ]),
                Value::Array(vec![
                    Value::Array(vec![Value::String("Alice".into()), Value::String("30".into())]),
                    Value::Array(vec![Value::String("Bob".into()), Value::String("25".into())]),
                ]),
            ],
        );
        let result = result.unwrap().unwrap();
        let csv_str = match result {
            Value::String(s) => s,
            _ => panic!("expected String"),
        };
        // Should start with UTF-8 BOM
        assert!(csv_str.starts_with('\u{FEFF}'), "CSV should start with BOM");
        assert!(csv_str.contains("name,age"));
        assert!(csv_str.contains("Alice,30"));
        assert!(csv_str.contains("Bob,25"));
    }

    #[test]
    fn test_csv_to_string_escaping() {
        let result = dispatch(
            "csv_to_string",
            vec![
                Value::Array(vec![Value::String("field".into())]),
                Value::Array(vec![
                    Value::Array(vec![Value::String("has, comma".into())]),
                    Value::Array(vec![Value::String("has \"quote\"".into())]),
                    Value::Array(vec![Value::String("has\nnewline".into())]),
                ]),
            ],
        );
        let csv_str = match result.unwrap().unwrap() {
            Value::String(s) => s,
            _ => panic!("expected String"),
        };
        // csv crate should quote fields containing commas, quotes, newlines
        assert!(csv_str.contains("\"has, comma\""), "commas should be quoted");
        assert!(csv_str.contains("\"has \"\"quote\"\"\""), "quotes should be doubled");
        assert!(csv_str.contains("\"has\nnewline\""), "newlines should be quoted");
    }

    #[test]
    fn test_csv_write_and_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.csv");
        let path_str = path.to_string_lossy().to_string();

        // Write initial CSV
        let result = dispatch(
            "csv_write",
            vec![
                Value::String(path_str.clone()),
                Value::Array(vec![Value::String("x".into()), Value::String("y".into())]),
                Value::Array(vec![
                    Value::Array(vec![Value::String("1".into()), Value::String("2".into())]),
                ]),
            ],
        );
        assert!(result.unwrap().is_ok());

        // Append a row
        let result = dispatch(
            "csv_append",
            vec![
                Value::String(path_str.clone()),
                Value::Array(vec![Value::String("3".into()), Value::String("4".into())]),
            ],
        );
        assert!(result.unwrap().is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("x,y"));
        assert!(content.contains("1,2"));
        assert!(content.contains("3,4"));
    }

    #[test]
    fn test_csv_from_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("from_json.csv");
        let path_str = path.to_string_lossy().to_string();

        let json = r#"[{"name":"Alice","age":30},{"name":"Bob","age":25,"city":"NYC"}]"#;
        let result = dispatch(
            "csv_from_json",
            vec![Value::String(path_str.clone()), Value::String(json.into())],
        );
        assert!(result.unwrap().is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("name"));
        assert!(content.contains("age"));
        assert!(content.contains("city"));
        assert!(content.contains("Alice"));
        assert!(content.contains("NYC"));
    }

    #[test]
    fn test_csv_from_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("from_records.csv");
        let path_str = path.to_string_lossy().to_string();

        let records = Value::Array(vec![
            Value::Map(vec![
                (Value::String("name".into()), Value::String("Alice".into())),
                (Value::String("score".into()), Value::Int(95)),
            ]),
            Value::Map(vec![
                (Value::String("name".into()), Value::String("Bob".into())),
                (Value::String("score".into()), Value::Int(87)),
            ]),
        ]);

        let result = dispatch(
            "csv_from_records",
            vec![Value::String(path_str.clone()), records],
        );
        assert!(result.unwrap().is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("name"));
        assert!(content.contains("score"));
        assert!(content.contains("Alice"));
        assert!(content.contains("87"));
    }
}
