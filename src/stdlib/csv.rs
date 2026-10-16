//! Standard library: `tallow.csv` — CSV reading and writing.
//!
//! Reads CSV files into arrays of maps/structs and writes structured data
//! back to CSV. Uses the `csv` crate for RFC 4180 compliance.
//!
//! # API
//! - `CSV.read(path, has_headers?)` — read CSV file to array of rows
//! - `CSV.read_to_map(path)` — read CSV with headers to array of maps
//! - `CSV.write(path, headers, rows)` — write structured data to CSV
//! - `CSV.parse_string(text, has_headers?)` — parse CSV string

use super::StdlibResult;
use crate::interp::{type_name, Value};



pub fn read_csv(path: &str, has_headers: bool) -> StdlibResult {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(has_headers)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_path(path)
        .map_err(|e| format!("CSV open: {e}"))?;

    if has_headers {
        let headers: Vec<String> = reader.headers()
            .map_err(|e| format!("CSV headers: {e}"))?
            .iter()
            .map(|h| h.to_string())
            .collect();

        let mut rows = Vec::new();
        for result in reader.records() {
            let record = result.map_err(|e| format!("CSV row: {e}"))?;
            let mut map = Vec::new();
            for (i, field) in record.iter().enumerate() {
                let key = headers.get(i).cloned().unwrap_or_else(|| format!("col_{}", i));
                let val = parse_csv_field(field);
                map.push((Value::String(key), val));
            }
            rows.push(Value::Map(map));
        }
        Ok(Value::Array(rows))
    } else {
        let mut rows = Vec::new();
        for result in reader.records() {
            let record = result.map_err(|e| format!("CSV row: {e}"))?;
            let fields: Vec<Value> = record.iter()
                .map(|f| parse_csv_field(f))
                .collect();
            rows.push(Value::Array(fields));
        }
        Ok(Value::Array(rows))
    }
}

pub fn parse_csv_string(text: &str, has_headers: bool) -> StdlibResult {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(has_headers)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(text.as_bytes());

    if has_headers {
        let headers: Vec<String> = reader.headers()
            .map_err(|e| format!("CSV headers: {e}"))?
            .iter()
            .map(|h| h.to_string())
            .collect();

        let mut rows = Vec::new();
        for result in reader.records() {
            let record = result.map_err(|e| format!("CSV row: {e}"))?;
            let mut map = Vec::new();
            for (i, field) in record.iter().enumerate() {
                let key = headers.get(i).cloned().unwrap_or_else(|| format!("col_{}", i));
                let val = parse_csv_field(field);
                map.push((Value::String(key), val));
            }
            rows.push(Value::Map(map));
        }
        Ok(Value::Array(rows))
    } else {
        let mut rows = Vec::new();
        for result in reader.records() {
            let record = result.map_err(|e| format!("CSV row: {e}"))?;
            let fields: Vec<Value> = record.iter()
                .map(|f| parse_csv_field(f))
                .collect();
            rows.push(Value::Array(fields));
        }
        Ok(Value::Array(rows))
    }
}

pub fn write_csv(path: &str, headers: &[String], rows: &[Vec<String>]) -> StdlibResult {
    let mut writer = csv::Writer::from_path(path)
        .map_err(|e| format!("CSV write open: {e}"))?;

    if !headers.is_empty() {
        writer.write_record(headers)
            .map_err(|e| format!("CSV write headers: {e}"))?;
    }

    for row in rows {
        writer.write_record(row)
            .map_err(|e| format!("CSV write row: {e}"))?;
    }

    writer.flush().map_err(|e| format!("CSV flush: {e}"))?;
    Ok(Value::Bool(true))
}

fn parse_csv_field(s: &str) -> Value {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Value::String(String::new());
    }
    // Try parsing as integer
    if let Ok(i) = trimmed.parse::<i64>() {
        return Value::Int(i as i128);
    }
    // Try parsing as float (has a decimal point)
    if trimmed.contains('.') {
        if let Ok(f) = trimmed.parse::<f64>() {
            return Value::Float(f);
        }
    }
    // Try parsing as boolean
    match trimmed.to_lowercase().as_str() {
        "true" | "yes" | "y" => return Value::Bool(true),
        "false" | "no" | "n" => return Value::Bool(false),
        _ => {}
    }
    Value::String(trimmed.to_string())
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "read" => Some(csv_read(args)),
        "read_to_map" => Some(csv_read_map(args)),
        "write" => Some(csv_write(args)),
        "parse_string" => Some(csv_parse(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "read" | "read_to_map" | "write" | "parse_string")
}

fn csv_read(args: Vec<Value>) -> StdlibResult {
    let path = expect_first_str(&args, "path")?;
    let has_headers = args.get(1).and_then(|v| if let Value::Bool(b) = v { Some(*b) } else { None }).unwrap_or(true);
    read_csv(path, has_headers)
}

fn csv_read_map(args: Vec<Value>) -> StdlibResult {
    let path = expect_first_str(&args, "path")?;
    read_csv(path, true)
}

fn csv_write(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("CSV.write: requires (path, rows, headers?)".into());
    }
    let path = expect_first_str(&args, "path")?;

    let headers: Vec<String> = if args.len() > 2 {
        match &args[2] {
            Value::Array(arr) => arr.iter().filter_map(|v| {
                if let Value::String(s) = v { Some(s.clone()) } else { None }
            }).collect(),
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let rows_data = match &args[1] {
        Value::Array(arr) => {
            arr.iter().map(|row| {
                match row {
                    Value::Array(fields) => {
                        fields.iter().map(|f| match f {
                            Value::String(s) => s.clone(),
                            Value::Int(i) => i.to_string(),
                            Value::Float(fl) => fl.to_string(),
                            Value::Bool(b) => b.to_string(),
                            _ => String::new(),
                        }).collect::<Vec<String>>()
                    }
                    Value::Map(entries) => {
                        if headers.is_empty() {
                            entries.iter().map(|(_, v)| match v {
                                Value::String(s) => s.clone(),
                                Value::Int(i) => i.to_string(),
                                Value::Float(fl) => fl.to_string(),
                                Value::Bool(b) => b.to_string(),
                                _ => String::new(),
                            }).collect()
                        } else {
                            headers.iter().map(|h| {
                                entries.iter()
                                    .find(|(k, _)| match k { Value::String(s) => s == h, _ => false })
                                    .map(|(_, v)| match v {
                                        Value::String(s) => s.clone(),
                                        Value::Int(i) => i.to_string(),
                                        Value::Float(fl) => fl.to_string(),
                                        Value::Bool(b) => b.to_string(),
                                        _ => String::new(),
                                    })
                                    .unwrap_or_default()
                            }).collect()
                        }
                    }
                    _ => Vec::new(),
                }
            }).collect::<Vec<Vec<String>>>()
        }
        _ => return Err("CSV.write: second argument must be an array of rows".into()),
    };

    write_csv(path, &headers, &rows_data)
}

fn csv_parse(args: Vec<Value>) -> StdlibResult {
    let text = expect_first_str(&args, "text")?;
    let has_headers = args.get(1).and_then(|v| if let Value::Bool(b) = v { Some(*b) } else { None }).unwrap_or(true);
    parse_csv_string(text, has_headers)
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}
