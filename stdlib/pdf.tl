// Tallow standard library: PDF extraction
// Powered by pdftotext CLI or pdf-extract crate.

struct PdfPage {
    page_number: i32,
    text: String,
    images: []Bytes,
}

struct PdfDocument {
    pages: []PdfPage,
    page_count: i32,
    metadata: Map<String, String>,
}

/// Extract text from all pages of a PDF document.
fn pdf_extract_text(pdf_data: Bytes) -> PdfDocument

/// Count the number of pages in a PDF document without extracting text.
fn pdf_count_pages(pdf_data: Bytes) -> i32
