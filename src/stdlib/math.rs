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
        // Inverse trig, cube root — declared in stdlib/math.tl since the surface
        // was first written, but absent from every dispatcher and from the inline
        // set above, so `math.asin(0.5)` died with "undefined function". Added
        // 2026-10-22 as part of the surface audit.
        "asin" => Some(extract_number("math.asin", &args).map(|v| Value::Float(v.asin()))),
        "acos" => Some(extract_number("math.acos", &args).map(|v| Value::Float(v.acos()))),
        "atan" => Some(extract_number("math.atan", &args).map(|v| Value::Float(v.atan()))),
        "atan2" => {
            let y = extract_number("math.atan2", &args);
            let x = match args.get(1) {
                Some(Value::Float(f)) => Ok(*f),
                Some(Value::Int(n)) => Ok(*n as f64),
                _ => Err("math.atan2 expects two numbers".to_string()),
            };
            Some(match (y, x) {
                (Ok(y), Ok(x)) => Ok(Value::Float(y.atan2(x))),
                (Err(e), _) | (_, Err(e)) => Err(e),
            })
        }
        "cbrt" => Some(extract_number("math.cbrt", &args).map(|v| Value::Float(v.cbrt()))),

        // Integer helpers. These are pure .tl in stdlib/math.tl for min_i/max_i/
        // clamp_i, but the file declares them as free functions the runtime must
        // still resolve, so they are answered here rather than left undefined.
        "abs_i" => match args.first() {
            Some(Value::Int(n)) => Some(Ok(Value::Int(n.abs()))),
            _ => Some(Err("math.abs_i expects an Int".into())),
        },
        "min_i" | "max_i" => {
            let (a, b) = match (args.first(), args.get(1)) {
                (Some(Value::Int(a)), Some(Value::Int(b))) => (*a, *b),
                _ => return Some(Err(format!("math.{function} expects two Ints"))),
            };
            Some(Ok(Value::Int(if function == "min_i" { a.min(b) } else { a.max(b) })))
        }
        "clamp_i" => match (args.first(), args.get(1), args.get(2)) {
            (Some(Value::Int(x)), Some(Value::Int(lo)), Some(Value::Int(hi))) => {
                Some(Ok(Value::Int((*x).max(*lo).min(*hi))))
            }
            _ => Some(Err("math.clamp_i expects three Ints".into())),
        },

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
