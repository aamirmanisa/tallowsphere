//! Standard library: `tallow.filings` — SEC filing parser.
//!
//! Parses 10-K, 10-Q, and 8-K SEC filings into structured sections.
//! Extracts key metrics, risk factors, MD&A, and financial statements.
//!
//! # API
//! - `Filings.parse(html, form_type)` — parse SEC filing HTML
//! - `Filings.sections(filing)` — get section names
//! - `Filings.section_text(filing, section_name)` — get section text
//! - `Filings.extract_metrics(filing)` — extract key financial metrics
//! - `Filings.risk_factors(filing)` — extract risk factors

use super::StdlibResult;
use crate::interp::{type_name, Value};
use regex::Regex;

/// Parse an SEC filing HTML into structured sections
pub fn parse_filing(html: &str, form_type: &str) -> Value {
    let sections = extract_sections(html);

    let mut fields = vec![
        ("form_type".into(), Value::String(form_type.to_string())),
        ("section_count".into(), Value::Int(sections.len() as i128)),
    ];

    let section_values: Vec<Value> = sections.iter().map(|(name, text)| {
        Value::Struct {
            name: "FilingSection".into(),
            fields: vec![
                ("name".into(), Value::String(name.clone())),
                ("text".into(), Value::String(text.chars().take(1000).collect())),
                ("length".into(), Value::Int(text.len() as i128)),
            ],
        }
    }).collect();
    fields.push(("sections".into(), Value::Array(section_values)));

    Value::Struct {
        name: "Filing".into(),
        fields,
    }
}

fn extract_sections(html: &str) -> Vec<(String, String)> {
    // Clean HTML — strip tags for text
    let clean = strip_html_tags(html);
    let mut sections = Vec::new();

    // Common SEC filing section headers
    let section_patterns = [
        (r"(?i)(?:Item\s*1[\.\s]*Business|PART\s*I)", "Business"),
        (r"(?i)(?:Item\s*1A[\.\s]*Risk\s*Factors)", "Risk Factors"),
        (r"(?i)(?:Item\s*2[\.\s]*Properties)", "Properties"),
        (r"(?i)(?:Item\s*3[\.\s]*Legal\s*Proceedings)", "Legal Proceedings"),
        (r"(?i)(?:Item\s*5[\.\s]*Market\s*for\s*Registrant)", "Market Information"),
        (r"(?i)(?:Item\s*6[\.\s]*(?:Selected\s*)?Financial\s*Data)", "Selected Financial Data"),
        (r"(?i)(?:Item\s*7[\.\s]*Management.*Discussion.*Analysis|MD&A)", "MD&A"),
        (r"(?i)(?:Item\s*7A[\.\s]*Quantitative.*Market\s*Risk)", "Market Risk"),
        (r"(?i)(?:Item\s*8[\.\s]*Financial\s*Statements)", "Financial Statements"),
        (r"(?i)(?:Item\s*9[\.\s]*Changes.*Disagreements.*Accountants)", "Accountant Changes"),
        (r"(?i)(?:Item\s*9A[\.\s]*Controls.*Procedures)", "Controls and Procedures"),
    ];

    for (pattern, name) in &section_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(mat) = re.find(&clean) {
                let start = mat.start();
                let end = clean[start..].find("\n\n").map(|p| start + p).unwrap_or(clean.len().min(start + 50000));
                let text = clean[start..end].trim().to_string();
                if !text.is_empty() {
                    sections.push((name.to_string(), text));
                }
            }
        }
    }
    sections
}

pub fn section_text(filing: &Value, name: &str) -> Option<String> {
    match filing {
        Value::Struct { fields, .. } => {
            let sections = fields.iter().find(|(n, _)| n == "sections")
                .and_then(|(_, v)| if let Value::Array(a) = v { Some(a) } else { None })?;
            for section in sections {
                if let Value::Struct { fields, .. } = section {
                    let sec_name = fields.iter().find(|(n,_)| n == "name")
                        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.as_str()) } else { None });
                    if sec_name == Some(name) {
                        return fields.iter().find(|(n,_)| n == "text")
                            .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None });
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract key financial metrics from filing text
pub fn extract_metrics(html: &str) -> Value {
    let clean = strip_html_tags(html);

    let metrics = [
        ("revenue", r"(?i)(?:total\s+revenue|revenue)\s*(?:was|of|:)?\s*\$?([\d,.]+)\s*(?:million|billion|M|B)?"),
        ("net_income", r"(?i)(?:net\s+income|net\s+earnings)\s*(?:was|of|:)?\s*\$?([\d,.]+)\s*(?:million|billion|M|B)?"),
        ("eps", r"(?i)(?:diluted\s+)?earnings\s+per\s+share.*?\$?([\d.]+)"),
        ("total_assets", r"(?i)total\s+assets\s*(?:was|of|:)?\s*\$?([\d,.]+)\s*(?:million|billion|M|B)?"),
        ("total_liabilities", r"(?i)total\s+liabilities\s*(?:was|of|:)?\s*\$?([\d,.]+)\s*(?:million|billion|M|B)?"),
        ("operating_income", r"(?i)(?:operating\s+income|income\s+from\s+operations)\s*(?:was|of|:)?\s*\$?([\d,.]+)\s*(?:million|billion|M|B)?"),
    ];

    let mut fields = Vec::new();
    for (name, pattern) in &metrics {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(&clean) {
                if let Some(m) = caps.get(1) {
                    let val_str = m.as_str().replace(",", "");
                    if let Ok(val) = val_str.parse::<f64>() {
                        fields.push((name.to_string(), Value::Float(val)));
                    }
                }
            }
        }
    }
    Value::Struct {
        name: "FilingMetrics".into(),
        fields,
    }
}

/// Extract risk factors section from filing
pub fn risk_factors(html: &str) -> Vec<String> {
    let clean = strip_html_tags(html);
    let re = Regex::new(r"(?is)(?:Item\s*1A|Risk\s*Factors)[\.\s:]*(.*?)(?:Item\s*1B|Item\s*2)").unwrap();
    if let Some(caps) = re.captures(&clean) {
        let text = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        // Split into individual risk factors (typically numbered or bulleted)
        let factors: Vec<String> = text.split('\n')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .take(50)
            .collect();
        return factors;
    }
    Vec::new()
}

pub fn sections_list(filing: &Value) -> Vec<String> {
    match filing {
        Value::Struct { fields, .. } => {
            let sections = fields.iter().find(|(n, _)| n == "sections")
                .and_then(|(_, v)| if let Value::Array(a) = v { Some(a) } else { None });
            match sections {
                Some(arr) => arr.iter().filter_map(|s| {
                    if let Value::Struct { fields, .. } = s {
                        fields.iter().find(|(n,_)| n == "name")
                            .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
                    } else { None }
                }).collect(),
                None => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

fn strip_html_tags(html: &str) -> String {
    let re_tag = Regex::new(r"<[^>]+>").unwrap();
    let re_entity = Regex::new(r"&[a-zA-Z]+;").unwrap();
    let text = re_tag.replace_all(html, " ");
    let text = re_entity.replace_all(&text, " ");
    // Collapse whitespace
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "parse" => Some(fil_parse(args)),
        "sections" => Some(fil_sections(args)),
        "section_text" => Some(fil_section_text(args)),
        "extract_metrics" => Some(fil_metrics(args)),
        "risk_factors" => Some(fil_risk(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "parse" | "sections" | "section_text" | "extract_metrics" | "risk_factors")
}

fn fil_parse(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    let form = args.get(1).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("10-K");
    Ok(parse_filing(html, form))
}

fn fil_sections(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Filings.sections: requires (filing)".into());
    }
    let filing = &args[0];
    let names = sections_list(filing);
    Ok(Value::Array(names.into_iter().map(Value::String).collect()))
}

fn fil_section_text(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Filings.section_text: requires (filing)".into());
    }
    let filing = &args[0];
    let name = expect_str_at(args.get(1), "section_name")?;
    match section_text(filing, &name) {
        Some(text) => Ok(Value::String(text)),
        None => Ok(Value::Nil),
    }
}

fn fil_metrics(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    Ok(extract_metrics(html))
}

fn fil_risk(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    let factors = risk_factors(html);
    Ok(Value::Array(factors.into_iter().map(Value::String).collect()))
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        _ => Err(format!("Expected String {name}, got something else")),
    }
}

fn expect_str_at(val: Option<&Value>, name: &str) -> Result<String, String> {
    match val {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(format!("Missing {name}")),
    }
}