//! Standard library: `tallow.test` — testing assertions.
//!
//! Real runtime assertions backing the declarations in `stdlib/test.tl`.
//! Each `assert_*` function returns `Ok(Value::Nil)` when the assertion
//! holds and `Err(message)` when it fails. Unrecognized functions and
//! methods return `None` so callers can fall through to other dispatch.

use super::StdlibResult;
use crate::interp::Value;

/// Contract-level dispatch for `tallow.test.*` functions.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "assert" => Some(assert_truthy(&args)),
        "assert_eq" => Some(assert_eq(&args)),
        "assert_ne" => Some(assert_ne(&args)),
        "assert_ok" => Some(assert_ok(&args)),
        "assert_err" => Some(assert_err(&args)),
        "assert_nil" => Some(assert_nil(&args)),
        "assert_not_nil" => Some(assert_not_nil(&args)),
        "assert_approx" => Some(assert_approx(&args)),
        "assert_panics" => Some(Err(
            "test.assert_panics: cannot execute a closure argument in stdlib \
             dispatch; use the language-level panic test harness instead"
                .into(),
        )),
        _ => None,
    }
}

/// Contract-level dispatch for `tallow.test.*` struct methods.
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

fn assert_truthy(args: &[Value]) -> StdlibResult {
    let condition = match args.first() {
        Some(Value::Bool(b)) => *b,
        Some(v) => {
            return Err(format!(
                "test.assert: expected a Bool condition, got {}",
                v.as_string()
            ))
        }
        None => return Err("test.assert: missing condition argument".into()),
    };
    if condition {
        Ok(Value::Nil)
    } else {
        let msg = args
            .get(1)
            .map(|v| v.as_string())
            .unwrap_or_else(|| "assertion failed".to_string());
        Err(format!("test.assert: {msg}"))
    }
}

fn assert_eq(args: &[Value]) -> StdlibResult {
    if args.len() < 2 {
        return Err("test.assert_eq: requires (left, right)".into());
    }
    let (left, right) = (&args[0], &args[1]);
    if values_equal(left, right) {
        Ok(Value::Nil)
    } else {
        Err(format!(
            "test.assert_eq: left != right — left={}, right={}",
            left.as_string(),
            right.as_string()
        ))
    }
}

fn assert_ne(args: &[Value]) -> StdlibResult {
    if args.len() < 2 {
        return Err("test.assert_ne: requires (left, right)".into());
    }
    let (left, right) = (&args[0], &args[1]);
    if !values_equal(left, right) {
        Ok(Value::Nil)
    } else {
        Err(format!(
            "test.assert_ne: left == right — both = {}",
            left.as_string()
        ))
    }
}

fn assert_ok(args: &[Value]) -> StdlibResult {
    match args.first() {
        Some(Value::Ok(v)) => Ok((**v).clone()),
        Some(v) => Err(format!(
            "test.assert_ok: expected Ok(...), got {}",
            v.as_string()
        )),
        None => Err("test.assert_ok: missing Result argument".into()),
    }
}

fn assert_err(args: &[Value]) -> StdlibResult {
    match args.first() {
        Some(Value::Err(_)) => Ok(Value::Nil),
        Some(v) => Err(format!(
            "test.assert_err: expected Err(...), got {}",
            v.as_string()
        )),
        None => Err("test.assert_err: missing Result argument".into()),
    }
}

fn assert_nil(args: &[Value]) -> StdlibResult {
    match args.first() {
        Some(Value::Nil) | None => Ok(Value::Nil),
        Some(v) => Err(format!("test.assert_nil: expected nil, got {}", v.as_string())),
    }
}

fn assert_not_nil(args: &[Value]) -> StdlibResult {
    match args.first() {
        Some(Value::Nil) => Err("test.assert_not_nil: expected non-nil, got nil".into()),
        Some(v) => Ok(v.clone()),
        None => Err("test.assert_not_nil: missing value argument".into()),
    }
}

fn assert_approx(args: &[Value]) -> StdlibResult {
    if args.len() < 3 {
        return Err("test.assert_approx: requires (left, right, epsilon)".into());
    }
    let left = to_f64(&args[0]);
    let right = to_f64(&args[1]);
    let eps = to_f64(&args[2]);
    let (Some(left), Some(right), Some(eps)) = (left, right, eps) else {
        return Err("test.assert_approx: expected numeric arguments".into());
    };
    if (left - right).abs() <= eps {
        Ok(Value::Nil)
    } else {
        Err(format!(
            "test.assert_approx: |{left} - {right}| > {eps}"
        ))
    }
}

fn to_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Int(n) => Some(*n as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
}

/// Structural equality over Tallow values. Handles the common scalar and
/// container variants; anything exotic falls back to string comparison.
fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Nil, Value::Nil) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Float(x), Value::Float(y)) => (x - y).abs() < f64::EPSILON,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Bytes(x), Value::Bytes(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(u, v)| values_equal(u, v))
        }
        (Value::Map(x), Value::Map(y)) => {
            x.len() == y.len()
                && x.iter().all(|(k, v)| {
                    y.iter()
                        .any(|(k2, v2)| values_equal(k, k2) && values_equal(v, v2))
                })
        }
        (Value::Ok(x), Value::Ok(y)) => values_equal(x, y),
        (Value::Err(x), Value::Err(y)) => values_equal(x, y),
        (Value::Private(x), _) => values_equal(x, b),
        (_, Value::Private(y)) => values_equal(a, y),
        _ => a.as_string() == b.as_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_ok() {
        assert!(matches!(
            assert_eq(&[Value::Int(1), Value::Int(1)]),
            Ok(Value::Nil)
        ));
    }

    #[test]
    fn eq_fail_is_err() {
        assert!(assert_eq(&[Value::Int(1), Value::Int(2)]).is_err());
    }

    #[test]
    fn ne_ok() {
        assert!(assert_ne(&[Value::Int(1), Value::Int(2)]).is_ok());
        assert!(assert_ne(&[Value::Int(1), Value::Int(1)]).is_err());
    }

    #[test]
    fn ok_unwraps_value() {
        match assert_ok(&[Value::Ok(Box::new(Value::Int(42)))]) {
            Ok(Value::Int(n)) => assert_eq!(n, 42),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn err_passes() {
        assert!(assert_err(&[Value::Err(Box::new(Value::String("e".into())))])
            .is_ok());
        assert!(assert_err(&[Value::Ok(Box::new(Value::Nil))]).is_err());
    }

    #[test]
    fn nil_checks() {
        assert!(assert_nil(&[Value::Nil]).is_ok());
        assert!(assert_nil(&[Value::Int(1)]).is_err());
        assert!(assert_not_nil(&[Value::Int(1)]).is_ok());
        assert!(assert_not_nil(&[Value::Nil]).is_err());
    }

    #[test]
    fn approx_ok() {
        assert!(assert_approx(&[
            Value::Float(1.0),
            Value::Float(1.0001),
            Value::Float(0.001)
        ])
        .is_ok());
        assert!(assert_approx(&[
            Value::Float(1.0),
            Value::Float(2.0),
            Value::Float(0.5)
        ])
        .is_err());
    }

    #[test]
    fn truthy() {
        assert!(assert_truthy(&[Value::Bool(true)]).is_ok());
        assert!(assert_truthy(&[Value::Bool(false)]).is_err());
        assert!(assert_truthy(&[Value::Bool(false), Value::String("nope".into())])
            .is_err());
    }

    #[test]
    fn dispatch_routing() {
        assert!(dispatch("assert_eq", vec![]).is_some());
        assert!(dispatch("unknown", vec![]).is_none());
    }
}
