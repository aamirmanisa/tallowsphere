//! Standard library: `tallow.rand` -- CSPRNG.

use super::StdlibResult;
use crate::interp::Value;
use base64::Engine;
use rand::Rng;

/// Dispatch a `tallow.rand.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "bytes" => Some(rand_bytes(&args)),
        "u64" => Some(rand_u64()),
        "range" => Some(rand_range(&args)),
        "uuid" => Some(rand_uuid()),
        "token" => Some(rand_token(&args)),
        // `rand.shuffle(items) -> [T]`: an unbiased Fisher-Yates shuffle of the
        // input, returning a new array. Declared in stdlib/rand.tl with an empty
        // body and absent from every dispatcher until the 2026-10-22 audit.
        "shuffle" => {
            let mut items = match args.first() {
                Some(Value::Array(items)) => items.clone(),
                _ => return Some(Err("rand.shuffle expects an array argument".into())),
            };
            use rand::seq::SliceRandom;
            items.shuffle(&mut rand::rng());
            Some(Ok(Value::Array(items)))
        }
        _ => None,
    }
}

/// Dispatch a method call on a `tallow.rand` object.
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

/// `rand.bytes(n)` -- returns a hex string of `n` cryptographically secure random bytes.
fn rand_bytes(args: &[Value]) -> StdlibResult {
    let count = match args.first() {
        Some(Value::Int(n)) => *n as usize,
        _ => return Err("rand.bytes expects an Int argument (byte count)".into()),
    };
    if count == 0 {
        return Ok(Value::String(String::new()));
    }
    let mut buf = vec![0u8; count];
    rand::rng().fill(&mut buf[..]);
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    Ok(Value::String(hex))
}

/// `rand.u64()` -- returns a random u64 as an integer.
fn rand_u64() -> StdlibResult {
    let val = rand::rng().random::<u64>();
    Ok(Value::Int(val as i128))
}

/// `rand.range(min, max)` -- returns a random integer in [min, max).
fn rand_range(args: &[Value]) -> StdlibResult {
    let min = match args.first() {
        Some(Value::Int(n)) => *n as i64,
        _ => return Err("rand.range expects two Int arguments (min, max)".into()),
    };
    let max = match args.get(1) {
        Some(Value::Int(n)) => *n as i64,
        _ => return Err("rand.range expects two Int arguments (min, max)".into()),
    };
    if min >= max {
        return Err(format!("rand.range: min ({min}) must be less than max ({max})"));
    }
    let val = rand::rng().random_range(min..max);
    Ok(Value::Int(val as i128))
}

/// `rand.uuid()` -- returns a UUID v4 string.
fn rand_uuid() -> StdlibResult {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    // Set version 4: byte 6, high nibble = 0100
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    // Set variant: byte 8, high 2 bits = 10
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    let uuid = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    );
    Ok(Value::String(uuid))
}

/// `rand.token(length)` -- returns a URL-safe base64 string of the specified length.
fn rand_token(args: &[Value]) -> StdlibResult {
    let length = match args.first() {
        Some(Value::Int(n)) => *n as usize,
        _ => return Err("rand.token expects an Int argument (length)".into()),
    };
    if length == 0 {
        return Ok(Value::String(String::new()));
    }
    // Generate enough random bytes to produce at least `length` base64 chars
    // base64 produces 4 chars per 3 bytes, so we need ceil(length * 3 / 4) bytes
    let byte_count = (length * 3 + 3) / 4;
    let mut buf = vec![0u8; byte_count];
    rand::rng().fill(&mut buf[..]);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf);
    // Truncate to requested length
    let token: String = encoded.chars().take(length).collect();
    Ok(Value::String(token))
}
