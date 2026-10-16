//! Standard library: `tallow.time` -- Time, duration, timezone.

use super::StdlibResult;
use crate::interp::Value;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Dispatch a `tallow.time.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "now" => Some(time_now()),
        "sleep" => Some(time_sleep(args)),
        "parse" => Some(time_parse(args)),
        "format" => Some(time_format(args)),
        // Declared in stdlib/time.tl with an empty `// native:` body and previously
        // absent from every dispatcher. Implemented 2026-10-12.
        "parse_iso" => Some(time_parse_iso(args)),
        // Implemented inline in interp.rs — fall through
        "monotonic" => None,
        _ => None,
    }
}

/// Dispatch a method call on a `tallow.time` object (e.g., Timestamp, Duration).
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

/// `time.parse_iso(s: String) -> Result<Timestamp>`
///
/// Parses an ISO 8601 / RFC 3339 timestamp and returns **milliseconds since the
/// Unix epoch** — the same representation `time.now` uses, so the two compose.
/// Rejects anything without an explicit offset rather than guessing local time.
fn time_parse_iso(args: Vec<Value>) -> StdlibResult {
    let s = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("time.parse_iso: expected string argument".into()),
    };
    match chrono::DateTime::parse_from_rfc3339(&s) {
        Ok(dt) => Ok(Value::Int(dt.timestamp_millis() as i128)),
        Err(e) => Err(format!("time.parse_iso: {e}")),
    }
}

/// time.now() -> epoch milliseconds
fn time_now() -> StdlibResult {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    Ok(Value::Int(millis as i128))
}

/// time.sleep(ms: Int) -> Nil
fn time_sleep(args: Vec<Value>) -> StdlibResult {
    let ms = match args.first() {
        Some(Value::Int(n)) => *n,
        Some(Value::Float(f)) => *f as i128,
        Some(other) => {
            return Err(format!(
                "time.sleep expects Int milliseconds, got {}",
                other.as_string()
            ))
        }
        None => return Err("time.sleep requires a milliseconds argument".into()),
    };
    if ms < 0 {
        return Err(format!("time.sleep: milliseconds cannot be negative ({ms})"));
    }
    thread::sleep(Duration::from_millis(ms as u64));
    Ok(Value::Nil)
}

/// time.parse(str: String) -> epoch seconds (Int)
/// Supports ISO 8601: "YYYY-MM-DDThh:mm:ssZ" and "YYYY-MM-DD hh:mm:ss"
fn time_parse(args: Vec<Value>) -> StdlibResult {
    let s = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(other) => {
            return Err(format!(
                "time.parse expects a String, got {}",
                other.as_string()
            ))
        }
        None => return Err("time.parse requires a datetime string argument".into()),
    };

    // Strip trailing 'Z' if present
    let s = s.trim_end_matches('Z');

    // Split on 'T' or space
    let parts: Vec<&str> = if s.contains('T') {
        s.splitn(2, 'T').collect()
    } else {
        s.splitn(2, ' ').collect()
    };

    if parts.len() != 2 {
        return Err(format!("invalid ISO 8601 format: expected date and time separated by T or space"));
    }

    let date_parts: Vec<&str> = parts[0].split('-').collect();
    if date_parts.len() != 3 {
        return Err(format!("invalid date format: expected YYYY-MM-DD"));
    }

    let year: i64 = date_parts[0]
        .parse()
        .map_err(|_| format!("invalid year: {}", date_parts[0]))?;
    let month: i64 = date_parts[1]
        .parse()
        .map_err(|_| format!("invalid month: {}", date_parts[1]))?;
    let day: i64 = date_parts[2]
        .parse()
        .map_err(|_| format!("invalid day: {}", date_parts[2]))?;

    if month < 1 || month > 12 {
        return Err(format!("invalid month: {month}"));
    }
    if day < 1 || day > 31 {
        return Err(format!("invalid day: {day}"));
    }

    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if time_parts.len() != 3 {
        return Err(format!("invalid time format: expected hh:mm:ss"));
    }

    let hour: i64 = time_parts[0]
        .parse()
        .map_err(|_| format!("invalid hour: {}", time_parts[0]))?;
    let min: i64 = time_parts[1]
        .parse()
        .map_err(|_| format!("invalid minute: {}", time_parts[1]))?;
    let sec: i64 = time_parts[2]
        .parse()
        .map_err(|_| format!("invalid second: {}", time_parts[2]))?;

    let epoch_secs = datetime_to_epoch(year, month, day, hour, min, sec);
    Ok(Value::Int(epoch_secs as i128))
}

/// time.format(epoch_secs: Int, pattern?: String) -> String
fn time_format(args: Vec<Value>) -> StdlibResult {
    let epoch_secs = match args.first() {
        Some(Value::Int(n)) => *n as i64,
        Some(Value::Float(f)) => *f as i64,
        Some(other) => {
            return Err(format!(
                "time.format expects Int epoch seconds, got {}",
                other.as_string()
            ))
        }
        None => return Err("time.format requires an epoch seconds argument".into()),
    };

    let pattern = match args.get(1) {
        Some(Value::String(s)) => s.clone(),
        Some(_) | None => "%Y-%m-%d %H:%M:%S".to_string(),
    };

    let (year, month, day, hour, min, sec) = epoch_to_datetime(epoch_secs);

    let result = pattern
        .replace("%Y", &format!("{:04}", year))
        .replace("%m", &format!("{:02}", month))
        .replace("%d", &format!("{:02}", day))
        .replace("%H", &format!("{:02}", hour))
        .replace("%M", &format!("{:02}", min))
        .replace("%S", &format!("{:02}", sec));

    Ok(Value::String(result))
}

// ---- Date/time helpers (UTC only, no timezone support in v0.3) ----

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 => 31,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        12 => 31,
        _ => 30,
    }
}

/// Convert a UTC datetime to epoch seconds.
fn datetime_to_epoch(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    // Days from year 1970 to the start of `year`
    let mut days: i64 = 0;
    if year >= 1970 {
        for y in 1970..year {
            days += if is_leap_year(y) { 366 } else { 365 };
        }
    } else {
        for y in year..1970 {
            days -= if is_leap_year(y) { 366 } else { 365 };
        }
    }

    // Days from start of year to start of month
    for m in 1..month {
        days += days_in_month(year, m);
    }

    // Add day-of-month (1-based)
    days += day - 1;

    days * 86400 + hour * 3600 + min * 60 + sec
}

/// Convert epoch seconds to (year, month, day, hour, min, sec) UTC.
fn epoch_to_datetime(mut epoch: i64) -> (i64, i64, i64, i64, i64, i64) {
    let sec = epoch.rem_euclid(60);
    epoch = epoch.div_euclid(60);
    let min = epoch.rem_euclid(60);
    epoch = epoch.div_euclid(60);
    let hour = epoch.rem_euclid(24);
    let mut days = epoch.div_euclid(24);

    // Compute year
    let mut year = 1970i64;
    if days >= 0 {
        loop {
            let year_days = if is_leap_year(year) { 366 } else { 365 };
            if days < year_days {
                break;
            }
            days -= year_days;
            year += 1;
        }
    } else {
        loop {
            year -= 1;
            let year_days = if is_leap_year(year) { 366 } else { 365 };
            days += year_days;
            if days >= 0 {
                break;
            }
        }
    }

    // Compute month and day
    let mut month = 1i64;
    loop {
        let mdays = days_in_month(year, month);
        if days < mdays {
            break;
        }
        days -= mdays;
        month += 1;
    }

    let day = days + 1; // 1-based

    (year, month, day, hour, min, sec)
}

/// Format epoch seconds as ISO 8601 UTC string (used by log module).
pub fn epoch_secs_to_iso(epoch_secs: i64) -> String {
    let (year, month, day, hour, min, sec) = epoch_to_datetime(epoch_secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datetime_to_epoch_2024() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(datetime_to_epoch(2024, 1, 1, 0, 0, 0), 1704067200);
    }

    #[test]
    fn test_epoch_to_datetime_2024() {
        let (y, m, d, h, mi, s) = epoch_to_datetime(1704067200);
        assert_eq!((y, m, d, h, mi, s), (2024, 1, 1, 0, 0, 0));
    }

    #[test]
    fn test_roundtrip() {
        let epoch = datetime_to_epoch(2026, 3, 5, 14, 30, 45);
        let (y, m, d, h, mi, s) = epoch_to_datetime(epoch);
        assert_eq!((y, m, d, h, mi, s), (2026, 3, 5, 14, 30, 45));
    }

    #[test]
    fn test_time_now_returns_millis() {
        let result = time_now().unwrap();
        if let Value::Int(ms) = result {
            assert!(ms > 1_700_000_000_000, "should be millis, not seconds");
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn test_time_parse_iso() {
        let result = time_parse(vec![Value::String("2024-01-01T00:00:00Z".into())]).unwrap();
        match result {
            Value::Int(v) => assert_eq!(v, 1704067200),
            other => panic!("expected Int, got {:?}", other.as_string()),
        }
    }

    #[test]
    fn test_time_parse_space_separated() {
        let result = time_parse(vec![Value::String("2024-01-01 00:00:00".into())]).unwrap();
        match result {
            Value::Int(v) => assert_eq!(v, 1704067200),
            other => panic!("expected Int, got {:?}", other.as_string()),
        }
    }

    #[test]
    fn test_time_format_default() {
        let result = time_format(vec![Value::Int(1704067200)]).unwrap();
        assert_eq!(result.as_string(), "2024-01-01 00:00:00");
    }

    #[test]
    fn test_time_format_custom_pattern() {
        let result = time_format(vec![
            Value::Int(1704067200),
            Value::String("%Y-%m-%d".into()),
        ]).unwrap();
        assert_eq!(result.as_string(), "2024-01-01");
    }

    #[test]
    fn test_time_sleep_negative_error() {
        let result = time_sleep(vec![Value::Int(-1)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_epoch_secs_to_iso() {
        assert_eq!(
            epoch_secs_to_iso(1704067200),
            "2024-01-01T00:00:00Z"
        );
    }
}
