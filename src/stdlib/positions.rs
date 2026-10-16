//! Standard library: `tallow.positions` — position tracking and P&L.
//!
//! Tracks portfolio positions, computes realized/unrealized P&L,
//! and produces summary statistics.
//!
//! # API
//! - `Positions.new()` — create empty position book
//! - `book.add(symbol, qty, price)` — add/update position
//! - `book.close(symbol, price)` — close position, return realized P&L
//! - `book.pnl(market_prices)` — compute total P&L
//! - `book.summary()` — position summary

use super::StdlibResult;
use crate::interp::Value;

pub fn new_book() -> Value {
    Value::Struct {
        name: "PositionBook".into(),
        fields: vec![
            ("positions".into(), Value::Array(Vec::new())),
            ("realized_pnl".into(), Value::Float(0.0)),
            ("cost_basis".into(), Value::Float(0.0)),
        ],
    }
}

pub fn add_position(book: &Value, symbol: &str, qty: f64, price: f64) -> Result<Value, String> {
    match book {
        Value::Struct { fields, .. } => {
            let positions = field_array(fields, "positions");
            let realized = field_f64(fields, "realized_pnl").unwrap_or(0.0);

            // Check if position exists
            let mut new_positions = positions.clone();
            let mut found = false;
            for pos in new_positions.iter_mut() {
                if let Value::Struct { fields, .. } = pos {
                    let sym = field_str(fields, "symbol").unwrap_or_default();
                    if sym == symbol {
                        let existing_qty = field_f64(fields, "quantity").unwrap_or(0.0);
                        let existing_cost = field_f64(fields, "avg_cost").unwrap_or(0.0);
                        let new_qty = existing_qty + qty;
                        let new_cost = if new_qty > 0.0 {
                            (existing_cost * existing_qty + price * qty) / new_qty
                        } else { 0.0 };
                        *pos = make_position(symbol, new_qty, new_cost);
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                new_positions.push(make_position(symbol, qty, price));
            }

            Ok(Value::Struct {
                name: "PositionBook".into(),
                fields: vec![
                    ("positions".into(), Value::Array(new_positions)),
                    ("realized_pnl".into(), Value::Float(realized)),
                    ("cost_basis".into(), Value::Float(0.0)),
                ],
            })
        }
        _ => Err("Not a PositionBook".into()),
    }
}

pub fn close_position(book: &Value, symbol: &str, price: f64) -> Result<Value, String> {
    match book {
        Value::Struct { fields, .. } => {
            let positions = field_array(fields, "positions");
            let realized = field_f64(fields, "realized_pnl").unwrap_or(0.0);

            let mut new_positions = Vec::new();
            let mut closed_pnl = 0.0;

            for pos in &positions {
                if let Value::Struct { fields, .. } = pos {
                    let sym = field_str(fields, "symbol").unwrap_or_default();
                    if sym == symbol {
                        let qty = field_f64(fields, "quantity").unwrap_or(0.0);
                        let cost = field_f64(fields, "avg_cost").unwrap_or(0.0);
                        closed_pnl = qty * (price - cost);
                        // Don't add this position (it's closed)
                    } else {
                        new_positions.push(pos.clone());
                    }
                }
            }

            Ok(Value::Struct {
                name: "PositionBook".into(),
                fields: vec![
                    ("positions".into(), Value::Array(new_positions)),
                    ("realized_pnl".into(), Value::Float(realized + closed_pnl)),
                    ("cost_basis".into(), Value::Float(0.0)),
                ],
            })
        }
        _ => Err("Not a PositionBook".into()),
    }
}

pub fn compute_pnl(book: &Value, market_prices: &[(String, f64)]) -> f64 {
    match book {
        Value::Struct { fields, .. } => {
            let positions = field_array(fields, "positions");
            let realized = field_f64(fields, "realized_pnl").unwrap_or(0.0);
            let mut unrealized = 0.0;
            for pos in &positions {
                if let Value::Struct { fields, .. } = pos {
                    let sym = field_str(fields, "symbol").unwrap_or_default();
                    let qty = field_f64(fields, "quantity").unwrap_or(0.0);
                    let cost = field_f64(fields, "avg_cost").unwrap_or(0.0);
                    let market = market_prices.iter().find(|(s,_)| s == &sym).map(|(_,p)| *p).unwrap_or(cost);
                    unrealized += qty * (market - cost);
                }
            }
            realized + unrealized
        }
        _ => 0.0,
    }
}

pub fn position_summary(book: &Value) -> Value {
    match book {
        Value::Struct { fields, .. } => {
            let positions = field_array(fields, "positions");
            let realized = field_f64(fields, "realized_pnl").unwrap_or(0.0);
            let n = positions.len();
            let gross = positions.iter().filter_map(|p| {
                if let Value::Struct { fields, .. } = p {
                    let qty = field_f64(fields, "quantity").unwrap_or(0.0);
                    let cost = field_f64(fields, "avg_cost").unwrap_or(0.0);
                    Some((qty * cost).abs())
                } else { None }
            }).sum::<f64>();

            Value::Struct {
                name: "PositionSummary".into(),
                fields: vec![
                    ("count".into(), Value::Int(n as i128)),
                    ("gross_exposure".into(), Value::Float(gross)),
                    ("realized_pnl".into(), Value::Float(realized)),
                ],
            }
        }
        _ => Value::Nil,
    }
}

fn make_position(symbol: &str, qty: f64, cost: f64) -> Value {
    Value::Struct {
        name: "Position".into(),
        fields: vec![
            ("symbol".into(), Value::String(symbol.to_string())),
            ("quantity".into(), Value::Float(qty)),
            ("avg_cost".into(), Value::Float(cost)),
        ],
    }
}

fn field_f64(fields: &[(String, Value)], name: &str) -> Option<f64> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| match v { Value::Float(f) => Some(*f), _ => None })
}

fn field_str(fields: &[(String, Value)], name: &str) -> Option<String> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
}

fn field_array(fields: &[(String, Value)], name: &str) -> Vec<Value> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::Array(a) = v { Some(a.clone()) } else { None })
        .unwrap_or_default()
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "new" => Some(Ok(new_book())),
        "add" => Some(pos_add(args)),
        "close" => Some(pos_close(args)),
        "pnl" => Some(pos_pnl(args)),
        "summary" => Some(pos_summary(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "new" | "add" | "close" | "pnl" | "summary")
}

fn pos_add(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Positions.add: requires (book)".into());
    }
    let book = &args[0];
    let sym = get_str(&args, 1)?;
    let qty = get_f64(&args, 2)?;
    let price = get_f64(&args, 3)?;
    add_position(book, &sym, qty, price)
}

fn pos_close(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Positions.close: requires (book)".into());
    }
    let book = &args[0];
    let sym = get_str(&args, 1)?;
    let price = get_f64(&args, 2)?;
    close_position(book, &sym, price)
}

fn pos_pnl(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Positions.pnl: requires (book, prices)".into());
    }
    let book = &args[0];
    let prices = parse_price_map(&args[1])?;
    Ok(Value::Float(compute_pnl(book, &prices)))
}

fn pos_summary(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Positions.summary: requires (book)".into());
    }
    Ok(position_summary(&args[0]))
}

fn parse_price_map(value: &Value) -> Result<Vec<(String, f64)>, String> {
    match value {
        Value::Map(entries) => {
            entries.iter().map(|(k, v)| {
                let sym = match k { Value::String(s) => s.clone(), _ => return Err("Expected string key".into()) };
                let price = match v { Value::Float(f) => *f, Value::Int(i) => *i as f64, _ => 0.0 };
                Ok((sym, price))
            }).collect::<Result<Vec<_>, _>>()
        }
        Value::Array(arr) => {
            arr.iter().map(|item| {
                if let Value::Array(pair) = item {
                    if pair.len() >= 2 {
                        let sym = match &pair[0] { Value::String(s) => s.clone(), _ => return Err("Expected string".into()) };
                        let price = match &pair[1] { Value::Float(f) => *f, Value::Int(i) => *i as f64, _ => 0.0 };
                        return Ok((sym, price));
                    }
                }
                Err("invalid pair".into())
            }).collect::<Result<Vec<_>, _>>()
        }
        _ => return Err("Expected map or array of [symbol, price] pairs".into()),
    }
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