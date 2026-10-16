//! Standard library: `tallow.decimal` — fixed-point decimal arithmetic for finance.
//!
//! Provides exact decimal arithmetic with user-configurable precision.
//! Avoids floating-point imprecision essential for financial calculations.
//!
//! # API
//! - `Decimal.new(value, scale?)` — create from string or number with scale (default 4)
//! - `decimal.add(other)` — exact addition
//! - `decimal.sub(other)` — exact subtraction
//! - `decimal.mul(other)` — exact multiplication
//! - `decimal.div(other)` — exact division
//! - `decimal.round(places)` — round to N decimal places
//! - `decimal.to_string()` — formatted output
//! - `decimal.cmp(other)` — comparison (-1, 0, 1)

use super::StdlibResult;
use crate::interp::{type_name, Value};

/// A fixed-point decimal number stored as an integer with a scale factor.
/// e.g., 123.45 with scale 2 is stored as 12345_i128.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields kept for display/debug; constructed by dispatch
struct Decimal {
    value: i128,
    scale: u32,   // number of decimal places
    name: String,  // for Struct representation
}

impl Decimal {
    fn new(value: i128, scale: u32) -> Self {
        Decimal { value, scale, name: "Decimal".into() }
    }

    fn from_str(s: &str, scale: u32) -> Result<Self, String> {
        let s = s.trim();
        if let Some(dot_pos) = s.find('.') {
            let int_part = &s[..dot_pos];
            let frac_part = &s[dot_pos+1..];
            let sign = if s.starts_with('-') { -1i128 } else { 1i128 };
            let abs_int: i128 = int_part.trim_start_matches('-').parse().map_err(|e| format!("invalid number: {e}"))?;
            let frac_padded = format!("{:0<width$}", frac_part, width = scale as usize);
            let frac_val: i128 = frac_padded[..scale as usize].parse().map_err(|e| format!("invalid decimal: {e}"))?;
            Ok(Decimal {
                value: sign * (abs_int * 10i128.pow(scale) + frac_val),
                scale,
                name: "Decimal".into(),
            })
        } else {
            let val: i128 = s.parse().map_err(|e| format!("invalid number: {e}"))?;
            Ok(Decimal {
                value: val * 10i128.pow(scale),
                scale,
                name: "Decimal".into(),
            })
        }
    }

    fn to_value(&self) -> Value {
        Value::Struct {
            name: "Decimal".into(),
            fields: vec![
                ("value".into(), Value::Int(self.value)),
                ("scale".into(), Value::Int(self.scale as i128)),
                ("formatted".into(), Value::String(self.to_formatted())),
            ],
        }
    }

    fn to_formatted(&self) -> String {
        let abs = self.value.abs();
        let int_part = abs / 10i128.pow(self.scale);
        let frac_part = abs % 10i128.pow(self.scale);
        let sign = if self.value < 0 { "-" } else { "" };
        if self.scale == 0 {
            format!("{}{}", sign, int_part)
        } else {
            format!("{}{}.{:0>width$}", sign, int_part, frac_part, width = self.scale as usize)
        }
    }

    fn to_f64(&self) -> f64 {
        (self.value as f64) / 10f64.powi(self.scale as i32)
    }

    fn add(&self, other: &Decimal) -> Decimal {
        let (a, b, scale) = align(self, other);
        Decimal { value: a + b, scale, name: "Decimal".into() }
    }

    fn sub(&self, other: &Decimal) -> Decimal {
        let (a, b, scale) = align(self, other);
        Decimal { value: a - b, scale, name: "Decimal".into() }
    }

    fn mul(&self, other: &Decimal) -> Decimal {
        let result_scale = self.scale + other.scale;
        Decimal {
            value: self.value * other.value,
            scale: result_scale,
            name: "Decimal".into(),
        }
    }

    fn div(&self, other: &Decimal) -> StdlibResult {
        if other.value == 0 {
            return Err("Decimal: division by zero".into());
        }
        let max_scale = self.scale.max(other.scale) + 6; // extra precision
        let scaled_value = self.value * 10i128.pow(max_scale);
        Decimal {
            value: scaled_value / other.value,
            scale: max_scale,
            name: "Decimal".into(),
        }.to_value_ok()
    }

    fn to_value_ok(&self) -> StdlibResult {
        Ok(self.to_value())
    }

    fn round(&self, places: u32) -> Decimal {
        if places >= self.scale {
            return self.clone();
        }
        let divisor = 10i128.pow(self.scale - places);
        let half = divisor / 2;
        let mut rounded = (self.value + half) / divisor;
        rounded *= 10i128.pow(self.scale - places);
        Decimal { value: rounded, scale: self.scale, name: "Decimal".into() }
    }

    fn cmp(&self, other: &Decimal) -> i32 {
        let (a, b, _) = align(self, other);
        a.cmp(&b) as i32
    }
}

fn align(a: &Decimal, b: &Decimal) -> (i128, i128, u32) {
    let scale = a.scale.max(b.scale);
    let a_val = a.value * 10i128.pow(scale - a.scale);
    let b_val = b.value * 10i128.pow(scale - b.scale);
    (a_val, b_val, scale)
}

// Financial-specific constants and helpers
fn decimal_from_value(val: &Value) -> Result<Decimal, String> {
    match val {
        Value::String(s) => Decimal::from_str(s, 10),
        Value::Int(i) => Ok(Decimal::new(*i, 0)),
        Value::Float(f) => Decimal::from_str(&format!("{:.10}", f), 10),
        Value::Struct { name, fields } if name == "Decimal" => {
            let value = get_i128(fields, "value")?;
            let scale = get_i128(fields, "scale")? as u32;
            Ok(Decimal { value, scale, name: "Decimal".into() })
        }
        _ => Err(format!("Expected Decimal, Int, Float, or String, got {}", type_name(val))),
    }
}

fn get_i128(fields: &[(String, Value)], name: &str) -> Result<i128, String> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::Int(i) = v { Some(*i) } else { None })
        .ok_or_else(|| format!("Decimal: missing field '{}'", name))
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "new" => Some(dec_new(args)),
        // ── Contract parity with stdlib/decimal.tl (2026-08-27) ──
        // The .tl declarations expose flat string functions
        // (decimal_add(a,b,scale) -> String, etc.). Implement them here so
        // code written against the documented API dispatches for real.
        "decimal_add" => Some(dec_flat_binop(args, FlatOp::Add)),
        "decimal_sub" => Some(dec_flat_binop(args, FlatOp::Sub)),
        "decimal_mul" => Some(dec_flat_binop(args, FlatOp::Mul)),
        "decimal_div" => Some(dec_flat_binop(args, FlatOp::Div)),
        "decimal_round" => Some(dec_flat_round(args)),
        "decimal_cmp" => Some(dec_flat_cmp(args)),
        _ => None,
    }
}

// ── Flat API helpers (match stdlib/decimal.tl) ──────────────────────────────

#[derive(Clone, Copy)]
enum FlatOp {
    Add,
    Sub,
    Mul,
    Div,
}

fn dec_flat_binop(args: Vec<Value>, op: FlatOp) -> StdlibResult {
    let a = expect_first_str(&args, "a")?;
    let b = match args.get(1) {
        Some(Value::String(s)) => s,
        Some(o) => return Err(format!("Expected String b, got {}", type_name(o))),
        None => return Err("Missing b argument".into()),
    };
    let scale = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i as u32) } else { None }).unwrap_or(10);
    let da = Decimal::from_str(a, scale)?;
    let db = Decimal::from_str(b, scale)?;
    let result = match op {
        FlatOp::Add => da.add(&db).to_value_ok()?,
        FlatOp::Sub => da.sub(&db).to_value_ok()?,
        FlatOp::Mul => da.mul(&db).to_value_ok()?,
        FlatOp::Div => da.div(&db)?,
    };
    let dec = decimal_from_value(&result)?;
    Ok(Value::String(dec.to_formatted()))
}

fn dec_flat_round(args: Vec<Value>) -> StdlibResult {
    let value = expect_first_str(&args, "value")?;
    let scale = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as u32) } else { None }).unwrap_or(10);
    let new_scale = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i as u32) } else { None }).unwrap_or(2);
    let d = Decimal::from_str(value, scale)?;
    // Re-scale: round to `new_scale` decimals (drop lower digits if new_scale < scale).
    let divisor = 10i128.pow(scale.saturating_sub(new_scale));
    let half = divisor / 2;
    let mut scaled = (d.value + half) / divisor;
    if new_scale > scale {
        scaled *= 10i128.pow(new_scale - scale);
    }
    let rounded = Decimal::new(scaled, new_scale);
    Ok(Value::String(rounded.to_formatted()))
}

fn dec_flat_cmp(args: Vec<Value>) -> StdlibResult {
    let a = expect_first_str(&args, "a")?;
    let b = match args.get(1) {
        Some(Value::String(s)) => s,
        Some(o) => return Err(format!("Expected String b, got {}", type_name(o))),
        None => return Err("Missing b argument".into()),
    };
    let scale = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i as u32) } else { None }).unwrap_or(10);
    let da = Decimal::from_str(a, scale)?;
    let db = Decimal::from_str(b, scale)?;
    Ok(Value::Int(da.cmp(&db) as i128))
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let dec = match decimal_from_value(object) {
        Ok(d) => d,
        Err(_) => return None,
    };
    match method {
        "add" => {
            let other = match args.first().and_then(|v| decimal_from_value(v).ok()) {
                Some(d) => d,
                None => return None,
            };
            Some(dec.add(&other).to_value_ok())
        }
        "sub" => {
            let other = match args.first().and_then(|v| decimal_from_value(v).ok()) {
                Some(d) => d,
                None => return None,
            };
            Some(dec.sub(&other).to_value_ok())
        }
        "mul" => {
            let other = match args.first().and_then(|v| decimal_from_value(v).ok()) {
                Some(d) => d,
                None => return None,
            };
            Some(dec.mul(&other).to_value_ok())
        }
        "div" => {
            let other = match args.first().and_then(|v| decimal_from_value(v).ok()) {
                Some(d) => d,
                None => return None,
            };
            Some(dec.div(&other))
        }
        "round" => {
            let places = args.first().and_then(|v| if let Value::Int(i) = v { Some(*i as u32) } else { None }).unwrap_or(2);
            Some(dec.round(places).to_value_ok())
        }
        "cmp" => {
            let other = match args.first().and_then(|v| decimal_from_value(v).ok()) {
                Some(d) => d,
                None => return None,
            };
            Some(Ok(Value::Int(dec.cmp(&other) as i128)))
        }
        "to_string" => Some(Ok(Value::String(dec.to_formatted()))),
        "to_float" => Some(Ok(Value::Float(dec.to_f64()))),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(
        function,
        "new" | "decimal_add" | "decimal_sub" | "decimal_mul" | "decimal_div" | "decimal_round"
            | "decimal_cmp"
    )
}

fn dec_new(args: Vec<Value>) -> StdlibResult {
    let value_str = expect_first_str(&args, "value")?;
    let scale = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as u32) } else { None }).unwrap_or(10);
    Decimal::from_str(value_str, scale).map(|d| d.to_value())
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}
