/// SEC filing parser: 10-K, 10-Q, 8-K structured extraction.
module tallow.filings

/// Parse SEC filing HTML into structured sections
native fn parse(html: String, form_type: String) -> Filing
/// List section names from a parsed filing
native fn sections(filing: Filing) -> []String
/// Get text of a specific section
native fn section_text(filing: Filing, section_name: String) -> String
/// Extract key financial metrics from filing HTML
native fn extract_metrics(html: String) -> FilingMetrics
/// Extract risk factors from filing
native fn risk_factors(html: String) -> []String

struct Filing {
    form_type: String,
    section_count: Int,
    sections: []FilingSection,
}

struct FilingSection {
    name: String,
    text: String,
    length: Int,
}

struct FilingMetrics {
    revenue: Float,
    net_income: Float,
    eps: Float,
    total_assets: Float,
    total_liabilities: Float,
    operating_income: Float,
}
