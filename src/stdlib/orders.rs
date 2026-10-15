//! Standard library: `tallow.orders` — order management.
//!
//! Order types, lifecycle, and execution tracking.
//! Works with positions module for portfolio state.
//!
//! # API
//! - `Orders.limit(side, qty, price, symbol)` — create limit order
//! - `Orders.market(side, qty, symbol)` — create market order
//! - `Orders.stop(side, qty, stop_price, symbol)` — create stop order
//! - `Orders.oco(side, qty, price, stop, symbol)` — OCO bracket
//! - `Orders.fill(order, fill_price, fill_qty?)` — simulate fill

use super::StdlibResult;
use crate::interp::Value;

pub fn create_limit(side: &str, qty: f64, price: f64, symbol: &str) -> Value {
    Value::Struct {
        name: "Order".into(),
        fields: vec![
            ("type".into(), Value::String("limit".into())),
            ("side".into(), Value::String(side.to_string())),
            ("quantity".into(), Value::Float(qty)),
            ("price".into(), Value::Float(price)),
            ("symbol".into(), Value::String(symbol.to_string())),
            ("status".into(), Value::String("pending".into())),
            ("filled_qty".into(), Value::Float(0.0)),
            ("avg_fill_price".into(), Value::Float(0.0)),
        ],
    }
}

pub fn create_market(side: &str, qty: f64, symbol: &str) -> Value {
    Value::Struct {
        name: "Order".into(),
        fields: vec![
            ("type".into(), Value::String("market".into())),
            ("side".into(), Value::String(side.to_string())),
            ("quantity".into(), Value::Float(qty)),
            ("price".into(), Value::Float(0.0)),
            ("symbol".into(), Value::String(symbol.to_string())),
            ("status".into(), Value::String("pending".into())),
            ("filled_qty".into(), Value::Float(0.0)),
            ("avg_fill_price".into(), Value::Float(0.0)),
        ],
    }
}

pub fn create_stop(side: &str, qty: f64, stop_price: f64, symbol: &str) -> Value {
    Value::Struct {
        name: "Order".into(),
        fields: vec![
            ("type".into(), Value::String("stop".into())),
            ("side".into(), Value::String(side.to_string())),
            ("quantity".into(), Value::Float(qty)),
            ("stop_price".into(), Value::Float(stop_price)),
            ("symbol".into(), Value::String(symbol.to_string())),
            ("status".into(), Value::String("pending".into())),
            ("filled_qty".into(), Value::Float(0.0)),
            ("avg_fill_price".into(), Value::Float(0.0)),
        ],
    }
}

pub fn create_oco(side: &str, qty: f64, price: f64, stop: f64, symbol: &str) -> Value {
    Value::Struct {
        name: "Order".into(),
        fields: vec![
            ("type".into(), Value::String("oco".into())),
            ("side".into(), Value::String(side.to_string())),
            ("quantity".into(), Value::Float(qty)),
            ("price".into(), Value::Float(price)),
            ("stop_price".into(), Value::Float(stop)),
            ("symbol".into(), Value::String(symbol.to_string())),
            ("status".into(), Value::String("pending".into())),
            ("filled_qty".into(), Value::Float(0.0)),
            ("avg_fill_price".into(), Value::Float(0.0)),
        ],
    }
}

/// Simulate a fill event on an order
pub fn fill_order(order: &Value, fill_price: f64, fill_qty: Option<f64>) -> Result<Value, String> {
    match order {
        Value::Struct { fields, .. } => {
            let qty = field_f64(fields, "quantity").unwrap_or(0.0);
            let existing_filled = field_f64(fields, "filled_qty").unwrap_or(0.0);
            let fill_q = fill_qty.unwrap_or(qty);
            let new_filled = (existing_filled + fill_q).min(qty);
            let prev_avg = field_f64(fields, "avg_fill_price").unwrap_or(0.0);
            let new_avg = if new_filled > 0.0 {
                (prev_avg * existing_filled + fill_price * fill_q.min(qty - existing_filled)) / new_filled
            } else { 0.0 };
            let status = if new_filled >= qty { "filled" } else { "partial" };

            Ok(Value::Struct {
                name: "Order".into(),
                fields: vec![
                    ("type".into(), field_val(fields, "type")),
                    ("side".into(), field_val(fields, "side")),
                    ("quantity".into(), Value::Float(qty)),
                    ("price".into(), field_val(fields, "price")),
                    ("stop_price".into(), field_val(fields, "stop_price")),
                    ("symbol".into(), field_val(fields, "symbol")),
                    ("status".into(), Value::String(status.into())),
                    ("filled_qty".into(), Value::Float(new_filled)),
                    ("avg_fill_price".into(), Value::Float(new_avg)),
                ],
            })
        }
        _ => Err("Not an Order".into()),
    }
}

fn field_f64(fields: &[(String, Value)], name: &str) -> Option<f64> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| match v { Value::Float(f) => Some(*f), _ => None })
}

fn field_val(fields: &[(String, Value)], name: &str) -> Value {
    fields.iter().find(|(n,_)| n == name)
        .map(|(_, v)| v.clone())
        .unwrap_or(Value::Nil)
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "limit" => Some(ord_limit(args)),
        "market" => Some(ord_market(args)),
        "stop" => Some(ord_stop(args)),
        "oco" => Some(ord_oco(args)),
        "fill" => Some(ord_fill(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "limit" | "market" | "stop" | "oco" | "fill")
}

fn ord_limit(args: Vec<Value>) -> StdlibResult {
    let side = get_str(&args, 0)?;
    let qty = get_f64(&args, 1)?;
    let price = get_f64(&args, 2)?;
    let symbol = get_str(&args, 3)?;
    Ok(create_limit(&side, qty, price, &symbol))
}

fn ord_market(args: Vec<Value>) -> StdlibResult {
    let side = get_str(&args, 0)?;
    let qty = get_f64(&args, 1)?;
    let symbol = get_str(&args, 2)?;
    Ok(create_market(&side, qty, &symbol))
}

fn ord_stop(args: Vec<Value>) -> StdlibResult {
    let side = get_str(&args, 0)?;
    let qty = get_f64(&args, 1)?;
    let stop = get_f64(&args, 2)?;
    let symbol = get_str(&args, 3)?;
    Ok(create_stop(&side, qty, stop, &symbol))
}

fn ord_oco(args: Vec<Value>) -> StdlibResult {
    let side = get_str(&args, 0)?;
    let qty = get_f64(&args, 1)?;
    let price = get_f64(&args, 2)?;
    let stop = get_f64(&args, 3)?;
    let symbol = get_str(&args, 4)?;
    Ok(create_oco(&side, qty, price, stop, &symbol))
}

fn ord_fill(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Orders.fill: requires (order)".into());
    }
    let order = &args[0];
    let price = get_f64(&args, 1)?;
    let qty = args.get(2).and_then(|v| if let Value::Float(f) = v { Some(*f) } else { None });
    fill_order(order, price, qty)
}

fn get_str(args: &[Value], idx: usize) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(format!("Expected string at {}", idx)),
    }
}

fn get_f64(args: &[Value], idx: usize) -> Result<f64, String> {
    match args.get(idx) {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(i)) => Ok(*i as f64),
        _ => Err(format!("Expected number at {}", idx)),
    }
}
