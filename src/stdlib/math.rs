//! Standard library: `tallow.math` -- Math utilities.

use super::StdlibResult;
use crate::interp::Value;

/// Extract a numeric value from the first argument, converting Int to f64.
fn extract_number(fn_name: &str, args: &[Value]) -> Result<f64, String> {
    match args.first() {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(n)) => Ok(*n as f64),
        _ => Err(format!("{fn_name} expects a number argument")),
    }
}

/// Dispatch a `tallow.math.*` function call.
///
/// Functions already implemented inline in interp.rs (sin, cos, sqrt, pow, abs,
/// floor, ceil, min, max, log, pi, e) return None to fall through. Only newly
/// implemented functions are handled here.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // Implemented inline in interp.rs — fall through
        "sin" | "cos" | "sqrt" | "pow" | "abs" | "floor" | "ceil" | "min" | "max" | "log"
        | "pi" | "e" => None,

        // Trigonometric
        "tan" => {
            let val = extract_number("math.tan", &args);
            Some(val.map(|v| Value::Float(v.tan())))
        }

        // Rounding
        "round" => match args.first() {
            Some(Value::Int(n)) => Some(Ok(Value::Int(*n))),
            Some(Value::Float(f)) => Some(Ok(Value::Int(f.round() as i128))),
            _ => Some(Err("math.round expects a number argument".into())),
        },

        // Logarithms
        "log2" => {
            let val = extract_number("math.log2", &args);
            Some(val.map(|v| Value::Float(v.log2())))
        }
        "log10" => {
            let val = extract_number("math.log10", &args);
            Some(val.map(|v| Value::Float(v.log10())))
        }

        // Constants (no args needed)
        "tau" => Some(Ok(Value::Float(std::f64::consts::TAU))),
        "infinity" => Some(Ok(Value::Float(f64::INFINITY))),
        "nan" => Some(Ok(Value::Float(f64::NAN))),

        _ => None,
    }
}

/// Dispatch a method call on a `tallow.math` object.
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}
