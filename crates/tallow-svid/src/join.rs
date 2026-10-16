//! Single-use join tokens — module owner: U-213 (W3 enrollment, R-5.5 / §5.6, ATK-2.3).
//!
//! A join token authorises exactly one enrollment ceremony:
//!
//! * **32 bytes of OS entropy** ([`JOIN_TOKEN_BYTES`]) — never a human-chosen string.
//! * **Bound to one SPKI**: the token records `SHA-256(SPKI)` of the key that will be
//!   certified, so a stolen token cannot be redeemed for a different key. The enrollment
//!   flow is the only party that knows the CSR/SPKI up front; the caller passes the SPKI
//!   bytes through [`JoinToken::spki_binding`].
//! * **Single-use, consumed atomically**: [`JoinTokenStore::redeem`] transitions the token
//!   out of the outstanding set in one critical section. A second redemption is refused with
//!   [`JoinError::Replayed`] while the (short-lived) tombstone exists, and with
//!   [`JoinError::UnknownToken`] once swept.
//! * **TTL hard-capped at [`JOIN_TOKEN_MAX_TTL_SECS`] (10 minutes)** — the constant is the
//!   policy: longer requests are refused, never silently clamped.
//! * Expiry is strict: a token is valid for `now < expires_at`.
//!
//! Storage is deliberately abstracted behind [`JoinTokenStore`]; the in-memory implementation
//! here is for tests and single-process use (the daemon owns durability and cross-process
//! serialisation).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Token secret length in bytes (256-bit random).
pub const JOIN_TOKEN_BYTES: usize = 32;
/// Hard TTL ceiling for a join token: 10 minutes (§5.4/§5.6; ATK-2.3).
pub const JOIN_TOKEN_MAX_TTL_SECS: i64 = 600;

/// Typed join-token failures — every rejection is explicit and never "assume valid".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JoinError {
    /// Requested TTL exceeds the [`JOIN_TOKEN_MAX_TTL_SECS`] policy ceiling.
    #[error("join token ttl {requested_secs}s exceeds maximum {max_secs}s")]
    TtlTooLong {
        /// Requested TTL.
        requested_secs: i64,
        /// Policy ceiling.
        max_secs: i64,
    },
    /// TTL of zero or less is meaningless (and would be instantly expired).
    #[error("join token ttl must be positive, got {ttl_secs}s")]
    TtlNonPositive {
        /// Requested (non-positive) TTL.
        ttl_secs: i64,
    },
    /// The OS entropy source failed — refuse to mint a weak token.
    #[error("join token mint failed: OS entropy unavailable")]
    Entropy,
    /// Presented token bytes are not the expected length.
    #[error("join token malformed: expected {expected} bytes, got {got}")]
    TokenLength {
        /// Expected byte length (32).
        expected: usize,
        /// Observed byte length.
        got: usize,
    },
    /// No such token was ever issued (or it has been swept after expiry/redemption).
    #[error("join token not recognised (never issued or already swept)")]
    UnknownToken,
    /// The token expired.
    #[error("join token expired at {expires_at} (now {now})")]
    Expired {
        /// Evaluation time (unix seconds).
        now: i64,
        /// Expiry time (unix seconds).
        expires_at: i64,
    },
    /// Replay: the token was already redeemed.
    #[error("join token already redeemed at {redeemed_at} — replay refused")]
    Replayed {
        /// Time of the successful redemption (unix seconds).
        redeemed_at: i64,
    },
    /// The token is bound to a different SPKI than the one presenting it.
    #[error("join token is bound to a different SPKI")]
    SpkiMismatch,
}

/// A freshly minted join token. The secret lives only in memory and is zeroized on drop.
pub struct JoinToken {
    secret: [u8; JOIN_TOKEN_BYTES],
    spki_sha256: [u8; 32],
    issued_at: i64,
    expires_at: i64,
}

impl JoinToken {
    /// Mint a token bound to `spki_sha256`, valid for `ttl_secs` from `now`.
    ///
    /// `ttl_secs` must be in `1..=JOIN_TOKEN_MAX_TTL_SECS`; anything else is a typed refusal.
    pub fn mint(spki_sha256: &[u8; 32], ttl_secs: i64, now: i64) -> Result<Self, JoinError> {
        if ttl_secs <= 0 {
            return Err(JoinError::TtlNonPositive { ttl_secs });
        }
        if ttl_secs > JOIN_TOKEN_MAX_TTL_SECS {
            return Err(JoinError::TtlTooLong {
                requested_secs: ttl_secs,
                max_secs: JOIN_TOKEN_MAX_TTL_SECS,
            });
        }
        let mut secret = [0u8; JOIN_TOKEN_BYTES];
        OsRng
            .try_fill_bytes(&mut secret)
            .map_err(|_| JoinError::Entropy)?;
        Ok(Self {
            secret,
            spki_sha256: *spki_sha256,
            issued_at: now,
            expires_at: now.saturating_add(ttl_secs),
        })
    }

    /// `SHA-256(SPKI)` binding helper: the hash of the SubjectPublicKeyInfo bytes the token is
    /// scoped to. Callers pass DER `SubjectPublicKeyInfo` here (e.g. from a CSR).
    pub fn spki_binding(spki: &[u8]) -> [u8; 32] {
        sha256(spki)
    }

    /// The raw secret (presented to [`JoinTokenStore::redeem`]).
    pub fn secret(&self) -> &[u8; JOIN_TOKEN_BYTES] {
        &self.secret
    }

    /// Hex rendering of the secret, for transport to the enrolling party.
    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret)
    }

    /// Non-secret correlation id: `SHA-256(secret)`. Safe to log/audit.
    pub fn token_id(&self) -> [u8; 32] {
        sha256(&self.secret)
    }

    /// The SPKI digest this token is bound to.
    pub fn spki_sha256(&self) -> &[u8; 32] {
        &self.spki_sha256
    }

    /// Mint time (unix seconds).
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Expiry time (unix seconds); the token is valid strictly before this instant.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Effective TTL in seconds.
    pub fn ttl_secs(&self) -> i64 {
        self.expires_at.saturating_sub(self.issued_at)
    }

    /// Strict expiry test: expired at `now` when `now >= expires_at`.
    pub fn is_expired_at(&self, now: i64) -> bool {
        now >= self.expires_at
    }
}

impl Clone for JoinToken {
    fn clone(&self) -> Self {
        Self {
            secret: self.secret,
            spki_sha256: self.spki_sha256,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }
}

/// Redacting `Debug`: the secret must never reach a log line.
impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinToken")
            .field("secret", &"<redacted>")
            .field("token_id", &hex::encode(self.token_id()))
            .field("spki_sha256", &hex::encode(self.spki_sha256))
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Drop for JoinToken {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Successful redemption of a join token — everything the enrollment ceremony needs to
/// continue, and nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinGrant {
    /// Non-secret correlation id of the consumed token.
    pub token_id: [u8; 32],
    /// The SPKI digest the token was bound to (must equal the presented SPKI).
    pub spki_sha256: [u8; 32],
    /// When the token was minted (unix seconds).
    pub token_issued_at: i64,
    /// When the token was redeemed (unix seconds).
    pub redeemed_at: i64,
}

/// Join-token store contract. Implementations must make [`Self::redeem`] atomic.
pub trait JoinTokenStore {
    /// Mint a token bound to `spki_sha256`. `ttl_secs` is capped by policy
    /// ([`JOIN_TOKEN_MAX_TTL_SECS`]).
    fn mint(&self, spki_sha256: &[u8; 32], ttl_secs: i64, now: i64)
        -> Result<JoinToken, JoinError>;

    /// Redeem `secret` presented by a key with digest `spki_sha256`, at `now`.
    ///
    /// On success the token is consumed exactly once; subsequent attempts fail with
    /// [`JoinError::Replayed`] (tombstone) or [`JoinError::UnknownToken`] (after sweep).
    fn redeem(
        &self,
        secret: &[u8],
        spki_sha256: &[u8; 32],
        now: i64,
    ) -> Result<JoinGrant, JoinError>;

    /// Drop records whose expiry has passed; returns how many were removed.
    fn sweep_expired(&self, now: i64) -> usize;

    /// Number of tokens minted and not yet redeemed (expired-but-unswept still counts).
    fn outstanding(&self) -> usize;

    /// Number of tracked records (outstanding + redeemed tombstones).
    fn tracked(&self) -> usize;

    /// Whether `secret` is currently outstanding.
    fn is_outstanding(&self, secret: &[u8; JOIN_TOKEN_BYTES]) -> bool;
}

#[derive(Debug, Clone, Copy)]
enum Record {
    Outstanding {
        spki_sha256: [u8; 32],
        issued_at: i64,
        expires_at: i64,
    },
    Redeemed {
        redeemed_at: i64,
        expires_at: i64,
    },
}

impl Record {
    fn expires_at(&self) -> i64 {
        match self {
            Record::Outstanding { expires_at, .. } | Record::Redeemed { expires_at, .. } => {
                *expires_at
            }
        }
    }
}

#[derive(Default)]
struct Inner {
    records: HashMap<[u8; JOIN_TOKEN_BYTES], Record>,
}

/// In-memory [`JoinTokenStore`]: a `Mutex`-guarded table, so redemption is atomic across
/// threads. Intended for tests, single-process use, and as the reference implementation.
#[derive(Default)]
pub struct InMemoryJoinTokenStore {
    inner: Mutex<Inner>,
}

impl InMemoryJoinTokenStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock helper that survives a poisoned mutex (the guarded data is a plain map; a panic
    /// while holding the lock must not wedge identity enrollment shut).
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for InMemoryJoinTokenStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.lock();
        let outstanding = inner
            .records
            .values()
            .filter(|r| matches!(r, Record::Outstanding { .. }))
            .count();
        f.debug_struct("InMemoryJoinTokenStore")
            .field("outstanding", &outstanding)
            .field("tracked", &inner.records.len())
            .finish()
    }
}

impl JoinTokenStore for InMemoryJoinTokenStore {
    fn mint(
        &self,
        spki_sha256: &[u8; 32],
        ttl_secs: i64,
        now: i64,
    ) -> Result<JoinToken, JoinError> {
        let token = JoinToken::mint(spki_sha256, ttl_secs, now)?;
        let mut inner = self.lock();
        let mut secret = *token.secret();
        let inserted = inner.records.insert(
            secret,
            Record::Outstanding {
                spki_sha256: *spki_sha256,
                issued_at: token.issued_at(),
                expires_at: token.expires_at(),
            },
        );
        secret.zeroize();
        debug_assert!(inserted.is_none(), "32-byte token collision");
        Ok(token)
    }

    fn redeem(
        &self,
        secret: &[u8],
        spki_sha256: &[u8; 32],
        now: i64,
    ) -> Result<JoinGrant, JoinError> {
        let key: [u8; JOIN_TOKEN_BYTES] =
            secret.try_into().map_err(|_| JoinError::TokenLength {
                expected: JOIN_TOKEN_BYTES,
                got: secret.len(),
            })?;
        // One critical section: lookup + state transition are atomic, so two racing
        // redeemers cannot both consume the same token.
        let mut inner = self.lock();
        let record = match inner.records.get(&key).copied() {
            Some(record) => record,
            None => return Err(JoinError::UnknownToken),
        };
        match record {
            Record::Redeemed { redeemed_at, .. } => Err(JoinError::Replayed { redeemed_at }),
            Record::Outstanding {
                spki_sha256: bound,
                issued_at,
                expires_at,
            } => {
                if now >= expires_at {
                    inner.records.remove(&key);
                    return Err(JoinError::Expired { now, expires_at });
                }
                if bound != *spki_sha256 {
                    // Refuse without consuming: a wrong-SPKI presentation is an attack, and
                    // burning the token would hand the attacker a denial-of-service.
                    return Err(JoinError::SpkiMismatch);
                }
                inner.records.insert(
                    key,
                    Record::Redeemed {
                        redeemed_at: now,
                        expires_at,
                    },
                );
                Ok(JoinGrant {
                    token_id: sha256(&key),
                    spki_sha256: bound,
                    token_issued_at: issued_at,
                    redeemed_at: now,
                })
            }
        }
    }

    fn sweep_expired(&self, now: i64) -> usize {
        let mut inner = self.lock();
        let before = inner.records.len();
        inner.records.retain(|_, record| record.expires_at() > now);
        before - inner.records.len()
    }

    fn outstanding(&self) -> usize {
        self.lock()
            .records
            .values()
            .filter(|r| matches!(r, Record::Outstanding { .. }))
            .count()
    }

    fn tracked(&self) -> usize {
        self.lock().records.len()
    }

    fn is_outstanding(&self, secret: &[u8; JOIN_TOKEN_BYTES]) -> bool {
        matches!(
            self.lock().records.get(secret),
            Some(Record::Outstanding { .. })
        )
    }
}

/// SHA-256 digest helper.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    const NOW: i64 = 1_800_000_000;

    fn spki(seed: u8) -> [u8; 32] {
        JoinToken::spki_binding(&[seed; 16])
    }

    #[test]
    fn mint_and_redeem_roundtrip() {
        let store = InMemoryJoinTokenStore::new();
        let digest = spki(1);
        let token = store.mint(&digest, 300, NOW).unwrap();
        assert_eq!(token.spki_sha256(), &digest);
        assert_eq!(token.issued_at(), NOW);
        assert_eq!(token.expires_at(), NOW + 300);
        assert_eq!(token.ttl_secs(), 300);
        assert_eq!(token.secret().len(), JOIN_TOKEN_BYTES);
        assert!(store.is_outstanding(token.secret()));

        let grant = store.redeem(token.secret(), &digest, NOW + 1).unwrap();
        assert_eq!(grant.spki_sha256, digest);
        assert_eq!(grant.token_issued_at, NOW);
        assert_eq!(grant.redeemed_at, NOW + 1);
        assert_eq!(grant.token_id, token.token_id());
        assert!(!store.is_outstanding(token.secret()));
        assert_eq!(store.outstanding(), 0);
    }

    #[test]
    fn tokens_are_random_and_secrets_never_debug() {
        let store = InMemoryJoinTokenStore::new();
        let a = store.mint(&spki(2), 60, NOW).unwrap();
        let b = store.mint(&spki(2), 60, NOW).unwrap();
        assert_ne!(a.secret(), b.secret());
        assert_ne!(a.token_id(), b.token_id());
        let rendered = format!("{a:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&a.secret_hex()));
    }

    #[test]
    fn double_redeem_rejected() {
        let store = InMemoryJoinTokenStore::new();
        let digest = spki(3);
        let token = store.mint(&digest, 60, NOW).unwrap();
        let first = store.redeem(token.secret(), &digest, NOW + 1).unwrap();
        assert_eq!(first.redeemed_at, NOW + 1);
        assert_eq!(
            store.redeem(token.secret(), &digest, NOW + 2),
            Err(JoinError::Replayed {
                redeemed_at: NOW + 1
            })
        );
        // Tombstone keeps the token tracked until swept.
        assert_eq!(store.tracked(), 1);
        assert_eq!(store.outstanding(), 0);
    }

    #[test]
    fn expiry_honored_strictly() {
        let store = InMemoryJoinTokenStore::new();
        let digest = spki(4);
        let token = store.mint(&digest, 600, NOW).unwrap();
        assert_eq!(token.expires_at(), NOW + 600);
        // Last valid instant is expires_at - 1.
        let other = store.mint(&digest, 600, NOW).unwrap();
        assert!(store.redeem(other.secret(), &digest, NOW + 599).is_ok());
        assert_eq!(
            store.redeem(token.secret(), &digest, NOW + 600),
            Err(JoinError::Expired {
                now: NOW + 600,
                expires_at: NOW + 600
            })
        );
        // Expired redemption removes the record.
        assert!(!store.is_outstanding(token.secret()));
        assert_eq!(store.tracked(), 1);
    }

    #[test]
    fn wrong_spki_rejected_and_token_survives() {
        let store = InMemoryJoinTokenStore::new();
        let digest = spki(5);
        let token = store.mint(&digest, 300, NOW).unwrap();
        assert_eq!(
            store.redeem(token.secret(), &spki(6), NOW + 1),
            Err(JoinError::SpkiMismatch)
        );
        // Not consumed: the legitimate holder can still redeem.
        assert!(store.is_outstanding(token.secret()));
        assert!(store.redeem(token.secret(), &digest, NOW + 2).is_ok());
    }

    #[test]
    fn ttl_over_ten_minutes_refused_and_boundary_allowed() {
        let store = InMemoryJoinTokenStore::new();
        let digest = spki(7);
        assert_eq!(
            store
                .mint(&digest, JOIN_TOKEN_MAX_TTL_SECS + 1, NOW)
                .unwrap_err(),
            JoinError::TtlTooLong {
                requested_secs: JOIN_TOKEN_MAX_TTL_SECS + 1,
                max_secs: JOIN_TOKEN_MAX_TTL_SECS
            }
        );
        assert_eq!(JOIN_TOKEN_MAX_TTL_SECS, 600);
        let boundary = store.mint(&digest, JOIN_TOKEN_MAX_TTL_SECS, NOW).unwrap();
        assert_eq!(boundary.ttl_secs(), 600);
        assert_eq!(
            store.mint(&digest, 0, NOW).unwrap_err(),
            JoinError::TtlNonPositive { ttl_secs: 0 }
        );
        assert_eq!(
            store.mint(&digest, -5, NOW).unwrap_err(),
            JoinError::TtlNonPositive { ttl_secs: -5 }
        );
    }

    #[test]
    fn unknown_and_malformed_tokens_rejected() {
        let store = InMemoryJoinTokenStore::new();
        let digest = spki(8);
        let token = store.mint(&digest, 60, NOW).unwrap();
        let mut wrong = *token.secret();
        wrong[31] ^= 0x01;
        assert_eq!(
            store.redeem(&wrong, &digest, NOW + 1),
            Err(JoinError::UnknownToken)
        );
        assert_eq!(
            store.redeem(&[], &digest, NOW + 1),
            Err(JoinError::TokenLength {
                expected: JOIN_TOKEN_BYTES,
                got: 0
            })
        );
        assert_eq!(
            store.redeem(&[0u8; 16], &digest, NOW + 1),
            Err(JoinError::TokenLength {
                expected: JOIN_TOKEN_BYTES,
                got: 16
            })
        );
    }

    #[test]
    fn sweep_removes_expired_and_replay_after_sweep_is_unknown() {
        let store = InMemoryJoinTokenStore::new();
        let digest = spki(9);
        let used = store.mint(&digest, 60, NOW).unwrap();
        let unused = store.mint(&digest, 60, NOW).unwrap();
        let live = store.mint(&digest, 600, NOW + 200).unwrap();
        store.redeem(used.secret(), &digest, NOW + 1).unwrap();
        assert!(store.is_outstanding(unused.secret()));
        assert_eq!(store.tracked(), 3);

        // At NOW+60 both 60 s records are exactly expired (valid strictly before expires_at).
        assert_eq!(store.sweep_expired(NOW + 60 - 1), 0);
        assert_eq!(store.sweep_expired(NOW + 60), 2);
        assert_eq!(store.tracked(), 1);
        assert_eq!(store.outstanding(), 1);
        assert!(store.is_outstanding(live.secret()));
        assert_eq!(
            store.redeem(used.secret(), &digest, NOW + 62),
            Err(JoinError::UnknownToken)
        );
    }

    #[test]
    fn concurrent_redeem_consumes_exactly_once() {
        let store = Arc::new(InMemoryJoinTokenStore::new());
        let digest = spki(10);
        let token = store.mint(&digest, 600, NOW).unwrap();
        let secret = *token.secret();

        let threads = 8;
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::new();
        for _ in 0..threads {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store.redeem(&secret, &digest, NOW + 1)
            }));
        }
        let results: Vec<Result<JoinGrant, JoinError>> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread did not panic"))
            .collect();
        let wins = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(wins, 1, "token must be consumed exactly once: {results:?}");
        let replays = results
            .iter()
            .filter(|r| matches!(r, Err(JoinError::Replayed { .. })))
            .count();
        assert_eq!(replays, threads - 1);
    }

    #[test]
    fn spki_binding_is_sha256_of_spki_bytes() {
        let der = b"\x30\x59\x30\x13\x06\x07spki-test-fixture";
        let digest = JoinToken::spki_binding(der);
        let mut hasher = Sha256::new();
        hasher.update(der);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(digest, expected);
        assert_ne!(digest, JoinToken::spki_binding(b"other"));
    }
}
