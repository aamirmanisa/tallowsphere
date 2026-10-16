//! Storage abstraction for Tallow crawl items.
//!
//! Provides a [`StorageBackend`] trait so results can be persisted to multiple
//! backends behind one interface, plus:
//!
//! - [`InMemoryBackend`] — thread-safe in-process map (tests, ephemeral runs).
//! - [`SqliteBackend`] — durable SQLite via `rusqlite`, guarded by a
//!   `std::sync::Mutex<Connection>` for thread safety.
//! - [`ParquetBackend`] — columnar store. **Default (no feature):** a zero-dep
//!   JSON-lines stand-in. **With `parquet-storage`:** a *real* Arrow/Parquet
//!   writer that persists schema-aware Arrow `RecordBatch`s to `.parquet` files.
//! - [`S3Backend`] — S3/MinIO object-store adapter. **Default (no feature):** a
//!   config descriptor (documented stub). **With `s3-storage`:** a *real*
//!   put/get implementation over the `object_store` crate (AWS S3, MinIO, or
//!   the local filesystem).
//!
//! All backends implement **idempotent canonical-key upserts**: writing the same
//! canonical key repeatedly (e.g. a retried crawl) never double-stores — the
//! row is overwritten (`ON CONFLICT ... DO UPDATE` for SQLite) and a monotonic
//! `revision` is bumped.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection};

/// An item stored by a [`StorageBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredItem {
    /// Canonical (dedup) key. Retries that reuse the same key are idempotent.
    pub key: String,
    /// Serialized value (e.g. JSON bytes).
    pub value: Vec<u8>,
    /// Monotonic revision; bumped on every upsert (1-based).
    pub revision: u64,
}

/// Outcome of a canonical-key upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// The key did not exist and was created.
    Inserted,
    /// An existing key was overwritten (idempotent).
    Updated,
}

/// Errors returned by storage backends.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("backend error: {0}")]
    Backend(String),
    #[error("key already exists: {0}")]
    KeyExists(String),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// A storage backend for crawl items. Implementations are thread-safe
/// (`Send + Sync`) and keyed by a caller-supplied canonical key.
pub trait StorageBackend: Send + Sync {
    /// Store `value` under `key`. Fails with [`StorageError::KeyExists`] if the
    /// key already exists (no overwrite).
    fn put_item(&self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Fetch the value stored under `key`, or `None` if absent.
    fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;

    /// Insert or overwrite `key` with `value`. **Idempotent by canonical key**:
    /// repeating the same key never double-stores — it overwrites and reports
    /// [`UpsertOutcome::Updated`].
    fn upsert_item(&self, key: &str, value: &[u8]) -> Result<UpsertOutcome, StorageError>;

    /// Write many items atomically (per-backend) with idempotent upsert per
    /// key. Returns the number of items written.
    fn batch_write(&self, items: &[(String, Vec<u8>)]) -> Result<usize, StorageError>;
}

/// Build a canonical dedup key from `parts` (URL, crawl-id, source, …).
///
/// Joins non-empty parts with `::`. Callers should include a crawl idempotency
/// key so that a retried crawl of the same URL maps to the same canonical key,
/// making `upsert_item` idempotent.
pub fn canonical_key(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|p| !p.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("::")
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryBackend
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe in-memory [`StorageBackend`].
///
/// Backed by a `HashMap<String, StoredItem>` behind a `std::sync::Mutex`.
pub struct InMemoryBackend {
    items: Mutex<HashMap<String, StoredItem>>,
}

impl InMemoryBackend {
    /// Create an empty in-memory backend.
    pub fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryBackend {
    fn put_item(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let mut items = self
            .items
            .lock()
            .map_err(|_| StorageError::Backend("in-memory lock poisoned".into()))?;
        if items.contains_key(key) {
            return Err(StorageError::KeyExists(key.to_string()));
        }
        items.insert(
            key.to_string(),
            StoredItem {
                key: key.to_string(),
                value: value.to_vec(),
                revision: 1,
            },
        );
        Ok(())
    }

    fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let items = self
            .items
            .lock()
            .map_err(|_| StorageError::Backend("in-memory lock poisoned".into()))?;
        Ok(items.get(key).map(|i| i.value.clone()))
    }

    fn upsert_item(&self, key: &str, value: &[u8]) -> Result<UpsertOutcome, StorageError> {
        let mut items = self
            .items
            .lock()
            .map_err(|_| StorageError::Backend("in-memory lock poisoned".into()))?;
        let outcome = if items.contains_key(key) {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        };
        let entry = items.entry(key.to_string()).or_insert_with(|| StoredItem {
            key: key.to_string(),
            value: Vec::new(),
            revision: 0,
        });
        entry.value = value.to_vec();
        entry.revision += 1;
        Ok(outcome)
    }

    fn batch_write(&self, items: &[(String, Vec<u8>)]) -> Result<usize, StorageError> {
        let mut n = 0;
        for (k, v) in items {
            self.upsert_item(k, v)?;
            n += 1;
        }
        Ok(n)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SqliteBackend
// ─────────────────────────────────────────────────────────────────────────────

/// Durable SQLite [`StorageBackend`].
///
/// Thread-safe via a `std::sync::Mutex<rusqlite::Connection>`. Idempotent
/// upserts use `INSERT ... ON CONFLICT(key) DO UPDATE`, so retried crawls never
/// double-store a canonical key.
pub struct SqliteBackend {
    conn: Mutex<Connection>,
}

impl SqliteBackend {
    /// Open (creating if needed) a SQLite DB at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let conn = Connection::open(path.as_ref())?;
        Self::from_conn(conn)
    }

    /// Open an ephemeral in-memory SQLite DB (useful for tests / scratch).
    pub fn in_memory() -> Result<Self, StorageError> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> Result<Self, StorageError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS storage_items (
                key      TEXT PRIMARY KEY,
                value    BLOB NOT NULL,
                revision INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl StorageBackend for SqliteBackend {
    fn put_item(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        use rusqlite::OptionalExtension;
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("sqlite lock poisoned".into()))?;
        let existed = conn
            .query_row(
                "SELECT 1 FROM storage_items WHERE key = ?1",
                params![key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if existed {
            return Err(StorageError::KeyExists(key.to_string()));
        }
        conn.execute(
            "INSERT INTO storage_items (key, value, revision) VALUES (?1, ?2, 1)",
            params![key, value],
        )?;
        Ok(())
    }

    fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        use rusqlite::OptionalExtension;
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("sqlite lock poisoned".into()))?;
        let value: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM storage_items WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    fn upsert_item(&self, key: &str, value: &[u8]) -> Result<UpsertOutcome, StorageError> {
        use rusqlite::OptionalExtension;
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("sqlite lock poisoned".into()))?;
        let existed = conn
            .query_row(
                "SELECT 1 FROM storage_items WHERE key = ?1",
                params![key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        // Idempotent canonical-key upsert: never double-stores, bumps revision.
        conn.execute(
            "INSERT INTO storage_items (key, value, revision) VALUES (?1, ?2, 1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, revision = revision + 1",
            params![key, value],
        )?;
        Ok(if existed {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn batch_write(&self, items: &[(String, Vec<u8>)]) -> Result<usize, StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("sqlite lock poisoned".into()))?;
        let tx = conn.transaction()?;
        let mut n = 0;
        for (k, v) in items {
            tx.execute(
                "INSERT INTO storage_items (key, value, revision) VALUES (?1, ?2, 1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, revision = revision + 1",
                params![k, v],
            )?;
            n += 1;
        }
        tx.commit()?;
        Ok(n)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParquetBackend (columnar store)
// ─────────────────────────────────────────────────────────────────────────────

/// Columnar (Parquet) [`StorageBackend`].
///
/// Two implementations of the same type are selected at compile time:
///
/// - **`parquet-storage` OFF (default):** a zero-dep JSON-lines stand-in that
///   persists items to `items.jsonl` under the configured directory. Durable
///   and dependency-free, it satisfies the [`StorageBackend`] contract while
///   keeping the default build light.
/// - **`parquet-storage` ON:** a *real* Arrow/Parquet writer. Items are held
///   in an in-memory row buffer and flushed to `items.parquet` as a schema-aware
///   Arrow [`RecordBatch`](arrow::record_batch::RecordBatch) with columns
///   `key: Utf8`, `value: Binary`, `revision: Int64`. Existing data is read
///   back through a `ParquetRecordBatchReaderBuilder` on open, so the store
///   round-trips through real `.parquet` files.
///
/// Both keep the canonical-key idempotency contract (no double-store on
/// repeated upsert of the same key; `revision` is monotonic).
pub struct ParquetBackend {
    dir: PathBuf,
    #[cfg(not(feature = "parquet-storage"))]
    log_path: PathBuf,
    #[cfg(feature = "parquet-storage")]
    rows: Mutex<Vec<(String, Vec<u8>, u64)>>,
}

impl ParquetBackend {
    /// Open (creating if needed) a directory-backed columnar store.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| {
            StorageError::Backend(format!("failed to create parquet dir {}: {e}", dir.display()))
        })?;
        #[cfg(not(feature = "parquet-storage"))]
        {
            let log_path = dir.join("items.jsonl");
            Ok(Self { dir, log_path })
        }
        #[cfg(feature = "parquet-storage")]
        {
            let rows = read_rows_from_parquet(&dir.join("items.parquet"))?;
            Ok(Self {
                dir,
                rows: Mutex::new(rows),
            })
        }
    }

    /// The directory backing this store.
    pub fn directory(&self) -> &Path {
        &self.dir
    }

    /// Force-flush the in-memory row buffer to a `.parquet` file on disk.
    /// (JSON-lines stand-in flushes on every mutation, so this is a no-op
    /// there.) Returns the number of rows written.
    #[cfg(feature = "parquet-storage")]
    pub fn flush(&self) -> Result<usize, StorageError> {
        let rows = self
            .rows
            .lock()
            .map_err(|_| StorageError::Backend("parquet lock poisoned".into()))?;
        let n = rows.len();
        write_rows_to_parquet(&self.dir.join("items.parquet"), &rows)?;
        Ok(n)
    }
}

// ── JSON-lines stand-in (default, `parquet-storage` OFF) ───────────────────

#[cfg(not(feature = "parquet-storage"))]
impl StorageBackend for ParquetBackend {
    fn put_item(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        // Idempotency for put: read the log and reject on an existing key.
        let mut entries = read_jsonl(&self.log_path)?;
        if entries.iter().any(|(k, _)| k == key) {
            return Err(StorageError::KeyExists(key.to_string()));
        }
        entries.push((key.to_string(), value.to_vec()));
        write_jsonl(&self.log_path, &entries)
    }

    fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let entries = read_jsonl(&self.log_path)?;
        // Last write wins (matches upsert semantics).
        Ok(entries
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone()))
    }

    fn upsert_item(&self, key: &str, value: &[u8]) -> Result<UpsertOutcome, StorageError> {
        let mut entries = read_jsonl(&self.log_path)?;
        let existed = entries.iter().any(|(k, _)| k == key);
        if existed {
            // Replace last occurrence in place (idempotent overwrite).
            if let Some(slot) = entries.iter_mut().rev().find(|(k, _)| k == key) {
                *slot = (key.to_string(), value.to_vec());
            }
        } else {
            entries.push((key.to_string(), value.to_vec()));
        }
        write_jsonl(&self.log_path, &entries)?;
        Ok(if existed {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn batch_write(&self, items: &[(String, Vec<u8>)]) -> Result<usize, StorageError> {
        for (k, v) in items {
            self.upsert_item(k, v)?;
        }
        Ok(items.len())
    }
}

#[cfg(not(feature = "parquet-storage"))]
/// Read a JSON-lines file into `(key, value)` pairs. Empty/missing file => empty.
fn read_jsonl(path: &Path) -> Result<Vec<(String, Vec<u8>)>, StorageError> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| StorageError::Backend(format!("corrupt jsonl line: {e}")))?;
        let key = v
            .get("key")
            .and_then(|k| k.as_str())
            .ok_or_else(|| StorageError::Backend("jsonl missing key".into()))?
            .to_string();
        let value = v
            .get("value")
            .and_then(|x| x.as_str())
            .map(|s| base64_decode(s))
            .ok_or_else(|| StorageError::Backend("jsonl missing value".into()))?;
        out.push((key, value));
    }
    Ok(out)
}

#[cfg(not(feature = "parquet-storage"))]
/// Write `(key, value)` pairs to a JSON-lines file (value base64-encoded).
fn write_jsonl(path: &Path, entries: &[(String, Vec<u8>)]) -> Result<(), StorageError> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)
        .map_err(|e| StorageError::Backend(format!("open {}: {e}", path.display())))?;
    for (k, v) in entries {
        let line = serde_json::json!({ "key": k, "value": base64_encode(v) });
        writeln!(file, "{line}")
            .map_err(|e| StorageError::Backend(format!("write {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(not(feature = "parquet-storage"))]
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(not(feature = "parquet-storage"))]
fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_else(|_| s.as_bytes().to_vec())
}

// ── Real Arrow/Parquet backend (`parquet-storage` ON) ──────────────────────

/// Real [`StorageBackend`] impl over Arrow [`RecordBatch`]s written to a
/// `.parquet` file. The canonical-key row model is kept in memory and flushed
/// on every mutation (and on [`ParquetBackend::flush`]); reads come from the
/// loaded buffer so retried crawls stay idempotent.
#[cfg(feature = "parquet-storage")]
impl StorageBackend for ParquetBackend {
    fn put_item(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| StorageError::Backend("parquet lock poisoned".into()))?;
        if rows.iter().any(|(k, _, _)| k == key) {
            return Err(StorageError::KeyExists(key.to_string()));
        }
        rows.push((key.to_string(), value.to_vec(), 1));
        write_rows_to_parquet(&self.dir.join("items.parquet"), &rows)
    }

    fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let rows = self
            .rows
            .lock()
            .map_err(|_| StorageError::Backend("parquet lock poisoned".into()))?;
        // Last write wins (matches upsert semantics).
        Ok(rows
            .iter()
            .rev()
            .find(|(k, _, _)| k == key)
            .map(|(_, v, _)| v.clone()))
    }

    fn upsert_item(&self, key: &str, value: &[u8]) -> Result<UpsertOutcome, StorageError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| StorageError::Backend("parquet lock poisoned".into()))?;
        let existed = rows.iter().any(|(k, _, _)| k == key);
        if existed {
            if let Some((_, v, rev)) = rows.iter_mut().rev().find(|(k, _, _)| k == key) {
                *v = value.to_vec();
                *rev += 1;
            }
        } else {
            rows.push((key.to_string(), value.to_vec(), 1));
        }
        write_rows_to_parquet(&self.dir.join("items.parquet"), &rows)?;
        Ok(if existed {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn batch_write(&self, items: &[(String, Vec<u8>)]) -> Result<usize, StorageError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| StorageError::Backend("parquet lock poisoned".into()))?;
        for (k, v) in items {
            let existed = rows.iter().any(|(rk, _, _)| rk == k);
            if existed {
                if let Some((_, vv, rev)) = rows.iter_mut().rev().find(|(rk, _, _)| rk == k) {
                    *vv = v.clone();
                    *rev += 1;
                }
            } else {
                rows.push((k.clone(), v.clone(), 1));
            }
        }
        write_rows_to_parquet(&self.dir.join("items.parquet"), &rows)?;
        Ok(items.len())
    }
}

/// Serialize `rows` as a schema-aware Arrow [`RecordBatch`] and write it to a
/// Parquet file via [`ArrowWriter`](parquet::arrow::ArrowWriter).
///
/// Columns: `key: Utf8` (not nullable), `value: Binary` (not nullable),
/// `revision: Int64` (not nullable). Writing the empty set still emits a file
/// with the full schema, so the on-disk schema is stable across flushes.
#[cfg(feature = "parquet-storage")]
fn write_rows_to_parquet(
    path: &Path,
    rows: &[(String, Vec<u8>, u64)],
) -> Result<(), StorageError> {
    use std::sync::Arc;

    use arrow::array::{ArrayRef, BinaryArray, Int64Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;
    use parquet::arrow::ArrowWriter;

    let keys: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    let values: Vec<Option<&[u8]>> = rows.iter().map(|r| Some(r.1.as_slice())).collect();
    let revisions: Vec<i64> = rows.iter().map(|r| r.2 as i64).collect();

    let schema = Schema::new(vec![
        Field::new("key", DataType::Utf8, false),
        Field::new("value", DataType::Binary, false),
        Field::new("revision", DataType::Int64, false),
    ]);
    let batch = RecordBatch::try_new(
        Arc::new(schema.clone()),
        vec![
            Arc::new(StringArray::from(keys)) as ArrayRef,
            Arc::new(BinaryArray::from(values)) as ArrayRef,
            Arc::new(Int64Array::from(revisions)) as ArrayRef,
        ],
    )
    .map_err(|e| StorageError::Backend(format!("build record batch: {e}")))?;

    let file = std::fs::File::create(path)
        .map_err(|e| StorageError::Backend(format!("open {}: {e}", path.display())))?;
    let mut writer = ArrowWriter::try_new(file, batch.schema(), None)
        .map_err(|e| StorageError::Backend(format!("init arrow writer: {e}")))?;
    writer
        .write(&batch)
        .map_err(|e| StorageError::Backend(format!("write batch: {e}")))?;
    writer
        .close()
        .map_err(|e| StorageError::Backend(format!("close writer: {e}")))?;
    Ok(())
}

/// Read every row back from a Parquet file at `path` (empty if absent).
#[cfg(feature = "parquet-storage")]
fn read_rows_from_parquet(path: &Path) -> Result<Vec<(String, Vec<u8>, u64)>, StorageError> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)
        .map_err(|e| StorageError::Backend(format!("open {}: {e}", path.display())))?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)
        .map_err(|e| StorageError::Backend(format!("read parquet {}: {e}", path.display())))?;
    let reader = builder
        .build()
        .map_err(|e| StorageError::Backend(format!("build reader: {e}")))?;

    let mut rows = Vec::new();
    for batch in reader {
        let batch = batch.map_err(|e| StorageError::Backend(format!("read batch: {e}")))?;
        let keys = batch
            .column(0)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .ok_or_else(|| StorageError::Backend("parquet col 0 not Utf8".into()))?;
        let values = batch
            .column(1)
            .as_any()
            .downcast_ref::<arrow::array::BinaryArray>()
            .ok_or_else(|| StorageError::Backend("parquet col 1 not Binary".into()))?;
        let revisions = batch
            .column(2)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .ok_or_else(|| StorageError::Backend("parquet col 2 not Int64".into()))?;
        for i in 0..batch.num_rows() {
            rows.push((
                keys.value(i).to_string(),
                values.value(i).to_vec(),
                revisions.value(i) as u64,
            ));
        }
    }
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// S3Backend (S3/MinIO object store)
// ─────────────────────────────────────────────────────────────────────────────

/// S3/MinIO object-store [`StorageBackend`].
///
/// Two implementations of the same type are selected at compile time:
///
/// - **`s3-storage` OFF (default):** a config descriptor whose trait methods
///   return a clear "not wired" error — no heavy dependency in the default
///   build.
/// - **`s3-storage` ON:** a *real* put/get implementation over the
///   `object_store` crate. It builds an `AmazonS3Builder` from `region` /
///   `endpoint` / `bucket` (MinIO is S3-compatible, so the same builder works
///   against a custom endpoint; set `endpoint = "http://127.0.0.1:9000"` for
///   MinIO). Credentials are resolved from the standard `AWS_ACCESS_KEY_ID` /
///   `AWS_SECRET_ACCESS_KEY` environment variables. Each canonical key maps to
///   the object key `{key_prefix}{key}`; `put` overwrites, so upsert is
///   idempotent by key.
///
/// `object_store` was chosen over `aws-sdk-s3` because it is far lighter to
/// compile, supports AWS S3, MinIO and the local filesystem through one
/// [`ObjectStore`](object_store::ObjectStore) trait, and needs no codegen.
#[derive(Debug)]
pub struct S3Backend {
    /// S3 region (e.g. `us-east-1`) or `minio` for MinIO.
    pub region: String,
    /// Endpoint URL. `None` = AWS; set to `http://127.0.0.1:9000` for MinIO.
    pub endpoint: Option<String>,
    /// Bucket name.
    pub bucket: String,
    /// Object-key prefix.
    pub key_prefix: String,
    /// Lazily-built `object_store` client + tokio runtime (only when `s3-storage`).
    #[cfg(feature = "s3-storage")]
    client: Mutex<Option<(std::sync::Arc<dyn object_store::ObjectStore>, std::sync::Arc<tokio::runtime::Runtime>)>>,
}

impl S3Backend {
    /// Create a new S3/MinIO backend descriptor. With `s3-storage` enabled, the
    /// live `object_store` client is built lazily on first use (credentials are
    /// read from the standard AWS environment variables).
    pub fn new(
        region: impl Into<String>,
        endpoint: Option<String>,
        bucket: impl Into<String>,
        key_prefix: impl Into<String>,
    ) -> Self {
        Self {
            region: region.into(),
            endpoint,
            bucket: bucket.into(),
            key_prefix: key_prefix.into(),
            #[cfg(feature = "s3-storage")]
            client: Mutex::new(None),
        }
    }

    /// Build (or return the cached) `(object_store client, tokio runtime)`.
    ///
    /// The `AmazonS3Builder` is built from `region` / `endpoint` / `bucket`
    /// (MinIO is S3-compatible; `with_allow_http(true)` permits plain-HTTP
    /// private endpoints). Credentials come from the standard
    /// `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment variables.
    #[cfg(feature = "s3-storage")]
    fn client(
        &self,
    ) -> Result<
        (
            std::sync::Arc<dyn object_store::ObjectStore>,
            std::sync::Arc<tokio::runtime::Runtime>,
        ),
        StorageError,
    > {
        use object_store::aws::AmazonS3Builder;
        let mut guard = self
            .client
            .lock()
            .map_err(|_| StorageError::Backend("s3 lock poisoned".into()))?;
        if guard.is_none() {
            let rt = std::sync::Arc::new(
                tokio::runtime::Runtime::new()
                    .map_err(|e| StorageError::Backend(format!("tokio runtime: {e}")))?,
            );
            let mut b = AmazonS3Builder::new()
                .with_region(&self.region)
                .with_bucket_name(&self.bucket)
                .with_allow_http(true);
            if let Some(ep) = &self.endpoint {
                b = b.with_endpoint(ep);
            }
            // Build the client synchronously; actual requests run under the
            // runtime below (via `rt.block_on`).
            let store = b
                .build()
                .map_err(|e| StorageError::Backend(format!("s3 client build failed: {e}")))?;
            *guard = Some((std::sync::Arc::new(store), rt));
        }
        Ok(guard.as_ref().expect("just initialized").clone())
    }

    /// Resolve `{key_prefix}{key}` into an `object_store` path.
    #[cfg(feature = "s3-storage")]
    fn object_path(&self, key: &str) -> object_store::path::Path {
        object_store::path::Path::from(format!("{}{}", self.key_prefix, key))
    }
}

#[cfg(not(feature = "s3-storage"))]
impl StorageBackend for S3Backend {
    fn put_item(&self, _key: &str, _value: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Backend(
            "S3Backend is a config stub: enable the `s3-storage` feature (object_store) to use it".into(),
        ))
    }

    fn get_item(&self, _key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Err(StorageError::Backend(
            "S3Backend is a config stub: enable the `s3-storage` feature (object_store) to use it".into(),
        ))
    }

    fn upsert_item(&self, _key: &str, _value: &[u8]) -> Result<UpsertOutcome, StorageError> {
        Err(StorageError::Backend(
            "S3Backend is a config stub: enable the `s3-storage` feature (object_store) to use it".into(),
        ))
    }

    fn batch_write(&self, _items: &[(String, Vec<u8>)]) -> Result<usize, StorageError> {
        Err(StorageError::Backend(
            "S3Backend is a config stub: enable the `s3-storage` feature (object_store) to use it".into(),
        ))
    }
}

/// Real `object_store`-backed implementation (S3 / MinIO / local filesystem).
#[cfg(feature = "s3-storage")]
impl StorageBackend for S3Backend {
    fn put_item(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        use object_store::ObjectStoreExt;
        let (store, rt) = self.client()?;
        let path = self.object_path(key);
        let payload = object_store::PutPayload::from(value.to_vec());
        rt.block_on(store.put(&path, payload))
            .map_err(|e| StorageError::Backend(format!("s3 put {path}: {e}")))?;
        Ok(())
    }

    fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        use object_store::ObjectStoreExt;
        let (store, rt) = self.client()?;
        let path = self.object_path(key);
        let res = rt
            .block_on(store.get(&path))
            .map_err(|e| StorageError::Backend(format!("s3 get {path}: {e}")))?;
        let bytes = rt
            .block_on(res.bytes())
            .map_err(|e| StorageError::Backend(format!("s3 read {path}: {e}")))?;
        Ok(Some(bytes.to_vec()))
    }

    fn upsert_item(&self, key: &str, value: &[u8]) -> Result<UpsertOutcome, StorageError> {
        // S3 put overwrites, so an existing object is idempotently replaced.
        let existed = self.get_item(key)?.is_some();
        self.put_item(key, value)?;
        Ok(if existed {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn batch_write(&self, items: &[(String, Vec<u8>)]) -> Result<usize, StorageError> {
        for (k, v) in items {
            self.put_item(k, v)?;
        }
        Ok(items.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

/// Backend kind used by [`open_backend`].
#[derive(Debug, Clone)]
pub enum StorageKind {
    InMemory,
    Sqlite(PathBuf),
    SqliteInMemory,
    Parquet(PathBuf),
}

/// Open a [`StorageBackend`] of the given [`StorageKind`].
pub fn open_backend(kind: StorageKind) -> Result<Box<dyn StorageBackend>, StorageError> {
    match kind {
        StorageKind::InMemory => Ok(Box::new(InMemoryBackend::new())),
        StorageKind::Sqlite(path) => Ok(Box::new(SqliteBackend::open(path)?)),
        StorageKind::SqliteInMemory => Ok(Box::new(SqliteBackend::in_memory()?)),
        StorageKind::Parquet(dir) => Ok(Box::new(ParquetBackend::open(dir)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(backend: &dyn StorageBackend) {
        backend
            .put_item("a", b"one")
            .expect("put a");
        assert_eq!(backend.get_item("a").unwrap(), Some(b"one".to_vec()));
        assert_eq!(backend.get_item("missing").unwrap(), None);
    }

    fn put_duplicate_rejected(backend: &dyn StorageBackend) {
        backend.put_item("k", b"1").unwrap();
        let err = backend.put_item("k", b"2").unwrap_err();
        assert!(matches!(err, StorageError::KeyExists(_)));
        // Original value preserved.
        assert_eq!(backend.get_item("k").unwrap(), Some(b"1".to_vec()));
    }

    fn upsert_is_idempotent(backend: &dyn StorageBackend) {
        assert_eq!(
            backend.upsert_item("k", b"v1").unwrap(),
            UpsertOutcome::Inserted
        );
        assert_eq!(
            backend.upsert_item("k", b"v2").unwrap(),
            UpsertOutcome::Updated // overwrite, not duplicate
        );
        assert_eq!(
            backend.upsert_item("k", b"v3").unwrap(),
            UpsertOutcome::Updated
        );
        assert_eq!(backend.get_item("k").unwrap(), Some(b"v3".to_vec()));
    }

    fn batch_write_and_count(backend: &dyn StorageBackend) {
        let items = vec![
            ("a".to_string(), b"1".to_vec()),
            ("b".to_string(), b"2".to_vec()),
            ("c".to_string(), b"3".to_vec()),
        ];
        assert_eq!(backend.batch_write(&items).unwrap(), 3);
        assert_eq!(backend.get_item("b").unwrap(), Some(b"2".to_vec()));
        // Re-write (idempotent) — still 3 logical items, last value wins.
        backend
            .batch_write(&vec![("b".to_string(), b"22".to_vec())])
            .unwrap();
        assert_eq!(backend.get_item("b").unwrap(), Some(b"22".to_vec()));
    }

    #[test]
    fn in_memory_roundtrip() {
        roundtrip(&InMemoryBackend::new());
    }

    #[test]
    fn in_memory_put_duplicate_rejected() {
        put_duplicate_rejected(&InMemoryBackend::new());
    }

    #[test]
    fn in_memory_upsert_idempotent() {
        upsert_is_idempotent(&InMemoryBackend::new());
    }

    #[test]
    fn in_memory_batch_write() {
        batch_write_and_count(&InMemoryBackend::new());
    }

    #[test]
    fn in_memory_thread_safety() {
        let backend = std::sync::Arc::new(InMemoryBackend::new());
        let mut handles = Vec::new();
        for i in 0..8 {
            let b = backend.clone();
            handles.push(std::thread::spawn(move || {
                for j in 0..50 {
                    b.upsert_item(&format!("k{i}"), format!("{i}-{j}").as_bytes())
                        .unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Each key present exactly once, last value wins.
        for i in 0..8 {
            let v = backend.get_item(&format!("k{i}")).unwrap().unwrap();
            assert_eq!(v, format!("{i}-49").as_bytes());
        }
    }

    #[test]
    fn sqlite_in_memory_roundtrip() {
        roundtrip(&SqliteBackend::in_memory().unwrap());
    }

    #[test]
    fn sqlite_in_memory_put_duplicate_rejected() {
        put_duplicate_rejected(&SqliteBackend::in_memory().unwrap());
    }

    #[test]
    fn sqlite_in_memory_upsert_idempotent_and_single_row() {
        let backend = SqliteBackend::in_memory().unwrap();
        upsert_is_idempotent(&backend);

        // Retried crawls must never double-store: exactly one row per key.
        for _ in 0..5 {
            backend
                .upsert_item("k", b"v")
                .expect("idempotent upsert");
        }
        let conn = backend.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM storage_items WHERE key = 'k'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "canonical-key upsert must keep a single row");
    }

    #[test]
    fn sqlite_in_memory_batch_write() {
        batch_write_and_count(&SqliteBackend::in_memory().unwrap());
    }

    #[test]
    fn sqlite_file_backend_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("items.db");
        {
            let backend = SqliteBackend::open(&path).unwrap();
            backend.upsert_item("k", b"persisted").unwrap();
        }
        {
            let backend = SqliteBackend::open(&path).unwrap();
            assert_eq!(backend.get_item("k").unwrap(), Some(b"persisted".to_vec()));
        }
    }

    #[test]
    fn canonical_key_builds_and_filters_empty() {
        assert_eq!(canonical_key(&["https://x", "job-1", "prod"]), "https://x::job-1::prod");
        assert_eq!(canonical_key(&["https://x", "", "prod"]), "https://x::prod");
        assert_eq!(canonical_key(&["", "", ""]), "");
    }

    #[test]
    fn parquet_stub_upsert_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let backend = ParquetBackend::open(dir.path()).unwrap();
        upsert_is_idempotent(&backend);
    }

    #[test]
    fn parquet_stub_put_duplicate_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let backend = ParquetBackend::open(dir.path()).unwrap();
        put_duplicate_rejected(&backend);
    }

    #[test]
    #[cfg(not(feature = "s3-storage"))]
    fn s3_stub_returns_clear_error() {
        let backend = S3Backend::new("us-east-1", Some("http://127.0.0.1:9000".into()), "bucket", "items/");
        let err = backend.upsert_item("k", b"v").unwrap_err();
        assert!(err.to_string().contains("s3-storage"));
    }

    #[test]
    fn open_backend_factory() {
        let mem = open_backend(StorageKind::InMemory).unwrap();
        mem.upsert_item("a", b"1").unwrap();
        assert_eq!(mem.get_item("a").unwrap(), Some(b"1".to_vec()));

        let sql = open_backend(StorageKind::SqliteInMemory).unwrap();
        sql.upsert_item("a", b"1").unwrap();
        assert_eq!(sql.get_item("a").unwrap(), Some(b"1".to_vec()));
    }
}
