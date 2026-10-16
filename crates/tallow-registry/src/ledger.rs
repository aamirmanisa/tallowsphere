//! Append-only receipts ledger (JSONL, one canonical receipt per line).
//!
//! `append` enforces sequence + `prev` linkage against the current head, so
//! a buggy signer cannot fork the chain. `verify` re-checks the whole file:
//! parse (strict), sequence, chain linkage, and every signature.

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;

use crate::receipt::{Receipt, ReceiptError};

/// Ledger errors.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("receipt at row {0}: {1}")]
    Receipt(usize, ReceiptError),
    #[error("append refused: seq {got} does not follow {want}")]
    Seq { got: u64, want: u64 },
    #[error("append refused: prev does not match ledger head")]
    Prev,
}

/// Receipt query filter (exact matches; `limit` keeps the LAST n rows).
#[derive(Debug, Default, Clone)]
pub struct Query {
    pub kind: Option<String>,
    pub actor: Option<String>,
    pub subject: Option<String>,
    pub limit: Option<usize>,
}

/// Outcome of a full-ledger verification.
#[derive(Debug, Default)]
pub struct LedgerVerdict {
    pub rows: usize,
    pub errors: Vec<String>,
}

impl LedgerVerdict {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// A ledger file handle.
pub struct Ledger {
    path: PathBuf,
}

impl Ledger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// All rows in order (missing file = empty ledger).
    pub fn iter(&self) -> Result<Vec<Receipt>, LedgerError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&self.path)?;
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let r = Receipt::from_line(line).map_err(|e| LedgerError::Receipt(i + 1, e))?;
            out.push(r);
        }
        Ok(out)
    }

    /// The last row, if any.
    pub fn head(&self) -> Result<Option<Receipt>, LedgerError> {
        let mut rows = self.iter()?;
        Ok(rows.pop())
    }

    /// Append a signed receipt, enforcing seq + `prev` linkage.
    pub fn append(&self, r: &Receipt) -> Result<(), LedgerError> {
        let rows = self.iter()?;
        let (want_seq, want_prev) = match rows.last() {
            None => (1u64, None),
            Some(last) => (last.seq + 1, Some(last.digest_hex())),
        };
        if r.seq != want_seq {
            return Err(LedgerError::Seq {
                got: r.seq,
                want: want_seq,
            });
        }
        if r.prev != want_prev {
            return Err(LedgerError::Prev);
        }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", r.to_line())?;
        f.flush()?;
        Ok(())
    }

    /// Next expected sequence number.
    pub fn next_seq(&self) -> Result<u64, LedgerError> {
        Ok(match self.head()? {
            None => 1,
            Some(last) => last.seq + 1,
        })
    }

    /// Digest the next receipt must reference in `prev`.
    pub fn next_prev(&self) -> Result<Option<String>, LedgerError> {
        Ok(self.head()?.map(|r| r.digest_hex()))
    }

    /// Full verification: parse, sequence, chain, signatures.
    /// A missing file counts as an empty ledger (consistent with `iter`).
    pub fn verify(&self, pubkey: &VerifyingKey) -> LedgerVerdict {
        let mut verdict = LedgerVerdict::default();
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return verdict,
            Err(e) => {
                verdict.errors.push(format!("io: {e}"));
                return verdict;
            }
        };
        let mut prev_digest: Option<String> = None;
        let mut n = 0usize;
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            n += 1;
            let row = match Receipt::from_line(line) {
                Ok(r) => r,
                Err(e) => {
                    verdict.errors.push(format!("row {}: parse: {e}", i + 1));
                    prev_digest = None;
                    continue;
                }
            };
            if row.seq != n as u64 {
                verdict
                    .errors
                    .push(format!("row {}: seq {} != expected {}", i + 1, row.seq, n));
            }
            if row.prev != prev_digest {
                verdict.errors.push(format!(
                    "row {}: chain break (prev != previous digest)",
                    i + 1
                ));
            }
            if let Err(e) = row.verify(pubkey) {
                verdict.errors.push(format!("row {}: sig: {e}", i + 1));
            }
            prev_digest = Some(row.digest_hex());
        }
        verdict.rows = n;
        verdict
    }

    /// Query rows (filters exact; `limit` keeps the LAST n matches).
    pub fn query(&self, q: &Query) -> Result<Vec<Receipt>, LedgerError> {
        let mut rows = self.iter()?;
        rows.retain(|r| {
            q.kind.as_ref().is_none_or(|k| &r.kind == k)
                && q.actor.as_ref().is_none_or(|a| &r.actor == a)
                && q.subject
                    .as_ref()
                    .is_none_or(|s| r.subject.as_deref() == Some(s.as_str()))
        });
        if let Some(limit) = q.limit {
            let skip = rows.len().saturating_sub(limit);
            rows.drain(..skip);
        }
        Ok(rows)
    }
}
