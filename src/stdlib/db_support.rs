//! Support for the `tallow.db` stdlib bridge (FIX13, 2026-08-27).
//!
//! `crate::interp::Value` does not implement `rusqlite::ToSql`, which the
//! db bridge needs to bind Tallow values as SQL parameters. This module
//! provides that impl. interp.rs is read-only in this sprint, so the impl is
//! not yet reachable from `db::dispatch` (connection open/execute return an
//! honest "db bridge requires interp support" error instead); it exists to
//! unblock the bridge and is exercised directly by the unit tests below.
//!
//! Mapping (per the FIX13 spec):
//! - `Value::String`  → SQL `Text`
//! - `Value::Int`     → SQL `Integer` (i64)
//! - `Value::Float`   → SQL `Real`
//! - `Value::Bool`    → SQL `Integer` (1 / 0)
//! - `Value::Nil`     → SQL `Null`
//! - `Value::Bytes`   → SQL `Blob` (natural extension)
//! - anything else    → `ToSqlConversionFailure` (honest error, no coercion)

use crate::interp::Value;

impl rusqlite::ToSql for Value {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, Value as SqlValue};
        match self {
            Value::Nil => Ok(ToSqlOutput::Owned(SqlValue::Null)),
            Value::Bool(b) => Ok(ToSqlOutput::Owned(SqlValue::Integer(if *b { 1 } else { 0 }))),
            Value::Int(i) => Ok(ToSqlOutput::Owned(SqlValue::Integer(*i as i64))),
            Value::Float(f) => Ok(ToSqlOutput::Owned(SqlValue::Real(*f))),
            Value::String(s) => Ok(ToSqlOutput::Owned(SqlValue::Text(s.clone()))),
            Value::Bytes(b) => Ok(ToSqlOutput::Owned(SqlValue::Blob(b.clone()))),
            other => Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
                std::io::Error::other(format!(
                    "cannot bind Tallow value ({}) as an SQL parameter",
                    other.as_string()
                )),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::ToSql;

    #[test]
    fn scalar_variants_map_to_sql_types() {
        use rusqlite::types::Value as SqlValue;
        let cases: Vec<(Value, SqlValue)> = vec![
            (Value::String("hi".into()), SqlValue::Text("hi".into())),
            (Value::Int(42), SqlValue::Integer(42)),
            (Value::Float(1.5), SqlValue::Real(1.5)),
            (Value::Bool(true), SqlValue::Integer(1)),
            (Value::Bool(false), SqlValue::Integer(0)),
            (Value::Nil, SqlValue::Null),
            (Value::Bytes(vec![1, 2, 3]), SqlValue::Blob(vec![1, 2, 3])),
        ];
        for (v, expected) in cases {
            match v.to_sql().expect("scalar should bind") {
                rusqlite::types::ToSqlOutput::Owned(got) => {
                    assert_eq!(got, expected, "mapping for {v:?}");
                }
                other => panic!("unexpected borrowed output {other:?}"),
            }
        }
    }

    #[test]
    fn unsupported_variants_error_honestly() {
        let unsupported = vec![
            Value::Array(vec![]),
            Value::Map(vec![]),
            Value::Struct {
                name: "X".into(),
                fields: vec![],
            },
        ];
        for v in unsupported {
            assert!(
                v.to_sql().is_err(),
                "non-scalar value should refuse to bind: {v:?}"
            );
        }
    }

    #[test]
    fn values_bind_as_real_sqlite_params() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (name TEXT, n INTEGER, x REAL, ok INTEGER);")
            .unwrap();
        conn.execute(
            "INSERT INTO t (name, n, x, ok) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                Value::String("alice".into()),
                Value::Int(7),
                Value::Float(2.5),
                Value::Bool(true),
            ],
        )
        .unwrap();
        let (name, n, x, ok): (String, i64, f64, i64) = conn
            .query_row("SELECT name, n, x, ok FROM t", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap();
        assert_eq!((name.as_str(), n, x, ok), ("alice", 7, 2.5, 1));
    }
}
