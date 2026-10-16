//! `relay_auth` — daemon ↔ relay **mutual authentication** over the existing
//! transport stack (rows #145/#146, batch-4 lane J).
//!
//! # What this is
//!
//! Row #145: *"Zero-trust service identity: short-lived workload certs, mutual
//! auth for daemon/mesh/relay, per-request authz"*. This module lands the
//! **daemon↔relay mutual-auth leg**, reusing lane E's fresh seam
//! ([`crate::workload`]): both ends of a relay connection prove a
//! certificate-backed, short-lived, scope-bound workload identity to each
//! other before any session bytes move — the application-layer analogue of
//! mTLS, on top of whatever transport (rustls/TLS, quinn/QUIC) already carries
//! the connection.
//!
//! # Shape: mutual Maskinporten presentation
//!
//! Each side holds a workload identity ([`RelayAuthIdentity`] = `WorkloadKey` +
//! issued SVID leaf chain + `SpiffeId`) and, before the handshake, exchanges a
//! cert-backed assertion for a short-lived scope-bound [`AccessToken`] at the
//! trusted node authority ([`crate::workload::TokenAuthority`]). The handshake
//! then *presents* `{ leaf certificate, access token }` in both directions
//! and each side verifies the peer against the authority it trusts
//! ([`PeerTrust`] = [`TokenVerifier`] + required scopes):
//!
//! ```text
//! daemon (client role)                          relay (server role)
//! ── Hello { leaf, token_d, nonce_d } ─────────► verify token_d (iss/aud/sig/
//!                                               window/required scope relay:write)
//!                                               verify leaf_d: SAN == token_d.sub,
//!                                               SPKI kid == token_d.cnf_kid, window
//! ◄── ServerProof { leaf, token_r, nonce_r,    bind cert key into the transcript
//!         pop_r = sign_r(transcript) } ──
//! verify token_r (required daemon:write) +
//! leaf_r + pop_r
//! ── Confirm { pop_d = sign_d(transcript) } ──► verify pop_d with leaf_d's key
//!                                               (proof of possession)
//! ◄── Established { binding } ─────────────────  both derive the same
//!                                                session binding
//! ```
//!
//! The transcript signed by each side is domain-separated
//! ([`RELAY_AUTH_DOMAIN`]), role-tagged (no reflection), carries **both**
//! nonces and **both** token digests, and is verified with the peer
//! certificate's public key ([`crate::workload::verify_possession`]) — so a
//! captured Hello/ServerProof cannot be replayed onto another connection or
//! reflected back to its author.
//!
//! # Fail closed (typed refusals, no session on any failure)
//!
//! * **no identity → no session** — both entry points take
//!   `Option<&RelayAuthIdentity>` / `Option<AccessToken>` and refuse with
//!   [`RelayAuthError::NoIdentity`] *before* a single byte is produced
//!   ([`ClientMachine::begin`], [`ServerMachine::begin`]).
//! * **token refusals** — delegated wholesale to
//!   [`crate::workload::TokenVerifier::verify`]: wrong issuer/audience,
//!   expired/not-yet-valid, bad signature, missing required scope.
//! * **presentation refusals** — leaf must not be a CA, must be inside its
//!   validity window, its URI SAN must equal the token subject byte-for-byte,
//!   and its SPKI SHA-256 must equal the token `cnf_kid` (so the token is
//!   bound to the key the peer actually holds).
//! * **possession refusals** — the transcript signature must verify under the
//!   *peer certificate's* key; a stolen token alone is useless.
//! * **session-binding check** — the client only accepts the session when the
//!   relay's `Established` binding equals its own derivation
//!   ([`RelayAuthError::BindingMismatch`]).
//!
//! Every failure path returns a typed error and the machines expose
//! [`RelayAuthMessage::rejection`] so the driver can send an explicit
//! `Reject { reason }` instead of closing silently.
//!
//! # Honest scope [partial]
//!
//! * Sans-io: this module owns the protocol, the verification and the typed
//!   refusals; the async driver over `AsyncRead + AsyncWrite` (tokio-rustls /
//!   quinn streams) and the loopback fixtures live in
//!   `tallow-net::relay::identity` — the crate boundary keeps `tallow-svid`
//!   runtime-free (U-201 D-5 sequencing).
//! * No key persistence / rotation: identity material is passed in; custody
//!   stays the existing SVID/vault concern (lane E §OPEN).
//! * Per-request authorization (Cedar) and the mesh leg are **not** here —
//!   held/W5, [target-only] in the lane log.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::issuer::der;
use crate::model::SpiffeId;
use crate::verify::match_san_uri;
use crate::workload::{
    self, mint_assertion, verify_possession, AccessToken, ScopeSet, TokenAuthority, TokenVerifier,
    WorkloadError, WorkloadKey, SIGNATURE_LEN,
};

/// Wire version of [`RelayAuthMessage`].
pub const RELAY_AUTH_VERSION: u8 = 1;
/// Canonical-bytes domain tag (transcripts and session binding).
pub const RELAY_AUTH_DOMAIN: &[u8] = b"tallow-relay-mutual-auth-v1";
/// Random bytes in a handshake nonce.
pub const NONCE_BYTES: usize = 32;
/// Hex length of a handshake nonce.
pub const NONCE_HEX_LEN: usize = NONCE_BYTES * 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way the mutual-auth handshake can fail. All are refusals: no path
/// yields an [`EstablishedSession`] for a peer that failed any check.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RelayAuthError {
    /// The local side has no workload identity (or no token) configured.
    #[error("no local workload identity configured: refusing to open a relay session")]
    NoIdentity,
    /// Unknown wire version.
    #[error("relay-auth wire version {found} unsupported (expected {expected})")]
    Version {
        /// Version found on the wire.
        found: u8,
        /// Version this module speaks.
        expected: u8,
    },
    /// Structurally invalid message (bad hex, wrong nonce length, bad JSON).
    #[error("malformed relay-auth message: {0}")]
    Malformed(String),
    /// A message arrived in the wrong handshake state.
    #[error("unexpected relay-auth message in state {state}: {got}")]
    Order {
        /// The machine's state.
        state: &'static str,
        /// The message kind received.
        got: &'static str,
    },
    /// The peer explicitly refused (it sent `Reject`).
    #[error("peer refused the handshake: {reason}")]
    Rejected {
        /// Reason string the peer sent.
        reason: String,
    },
    /// A workload-layer refusal (token verification, cert parsing, minting).
    #[error(transparent)]
    Workload(#[from] WorkloadError),
    /// The presented leaf certificate did not tie to the presented token.
    #[error("peer presentation refused: {0}")]
    Presentation(String),
    /// The transcript signature did not verify under the peer's cert key.
    #[error("proof of possession refused: {0}")]
    Possession(String),
    /// The relay's `Established` binding does not match the local derivation.
    #[error("session binding mismatch: expected {expected:?}, got {got:?}")]
    BindingMismatch {
        /// Binding the client derived.
        expected: String,
        /// Binding the relay sent.
        got: String,
    },
}

/// Convenience alias.
pub type Result<T, E = RelayAuthError> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Canonical helpers
// ---------------------------------------------------------------------------

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// A fresh handshake nonce: [`NONCE_BYTES`] OS-random bytes, lowercase hex.
pub fn fresh_nonce() -> String {
    use rand::RngCore;
    let mut b = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// True iff `s` is a well-formed nonce ([`NONCE_HEX_LEN`] lowercase hex).
pub fn is_valid_nonce(s: &str) -> bool {
    s.len() == NONCE_HEX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_nonce(nonce: &str) -> Result<()> {
    if is_valid_nonce(nonce) {
        Ok(())
    } else {
        Err(RelayAuthError::Malformed(format!(
            "nonce must be {NONCE_HEX_LEN} lowercase hex chars, got {} chars",
            nonce.len()
        )))
    }
}

/// `sha256` of a token's **canonical signed payload** — the stable transcript
/// digest (JSON re-encoding can never change it).
fn token_digest(token: &AccessToken) -> String {
    sha256_hex(&workload::token_payload(token))
}

/// The transcript each side signs. Fixed field order (client nonce first,
/// client token first) regardless of which side is signing; the `role` field
/// is what makes the two signatures distinct (no reflection).
fn auth_transcript(
    role: &str,
    nonce_client: &str,
    nonce_server: &str,
    token_client: &AccessToken,
    token_server: &AccessToken,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(RELAY_AUTH_DOMAIN);
    push_field(&mut out, role.as_bytes());
    push_field(&mut out, nonce_client.as_bytes());
    push_field(&mut out, nonce_server.as_bytes());
    push_field(&mut out, token_digest(token_client).as_bytes());
    push_field(&mut out, token_digest(token_server).as_bytes());
    out
}

/// Session binding derived independently by both sides: the handshake
/// transcript (minus role) hashed — both sides must agree or the client
/// refuses ([`RelayAuthError::BindingMismatch`]).
fn session_binding(
    nonce_client: &str,
    nonce_server: &str,
    token_client: &AccessToken,
    token_server: &AccessToken,
) -> String {
    let mut out = Vec::new();
    out.extend_from_slice(RELAY_AUTH_DOMAIN);
    push_field(&mut out, b"session");
    push_field(&mut out, nonce_client.as_bytes());
    push_field(&mut out, nonce_server.as_bytes());
    push_field(&mut out, token_digest(token_client).as_bytes());
    push_field(&mut out, token_digest(token_server).as_bytes());
    sha256_hex(&out)
}

// ---------------------------------------------------------------------------
// Wire messages
// ---------------------------------------------------------------------------

/// The handshake messages. JSON is transport only; all signatures cover
/// canonical bytes ([`auth_transcript`]), never this encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayAuthMessage {
    /// client → server: present identity (leaf cert + token) + fresh nonce.
    Hello {
        /// Wire version.
        v: u8,
        /// Workload leaf SVID, DER hex.
        leaf_cert_hex: String,
        /// Short-lived scope-bound access token.
        token: AccessToken,
        /// Client nonce (hex).
        nonce: String,
    },
    /// server → client: the relay's own presentation + its transcript proof.
    ServerProof {
        /// Wire version.
        v: u8,
        /// Relay workload leaf SVID, DER hex.
        leaf_cert_hex: String,
        /// Relay access token.
        token: AccessToken,
        /// Server nonce (hex).
        nonce: String,
        /// Relay's signature over the role="server" transcript, hex.
        pop: String,
    },
    /// client → server: the daemon's transcript proof.
    Confirm {
        /// Wire version.
        v: u8,
        /// Daemon's signature over the role="client" transcript, hex.
        pop: String,
    },
    /// server → client: handshake accepted; carries the session binding.
    Established {
        /// Wire version.
        v: u8,
        /// Derived session binding both sides must agree on.
        binding: String,
    },
    /// Either direction: explicit refusal (no session).
    Reject {
        /// Wire version.
        v: u8,
        /// Typed-reason string.
        reason: String,
    },
}

impl RelayAuthMessage {
    /// The wire version carried by this message.
    pub fn v(&self) -> u8 {
        match self {
            RelayAuthMessage::Hello { v, .. }
            | RelayAuthMessage::ServerProof { v, .. }
            | RelayAuthMessage::Confirm { v, .. }
            | RelayAuthMessage::Established { v, .. }
            | RelayAuthMessage::Reject { v, .. } => *v,
        }
    }

    /// Stable message-kind label (for logs/errors).
    pub fn kind(&self) -> &'static str {
        match self {
            RelayAuthMessage::Hello { .. } => "hello",
            RelayAuthMessage::ServerProof { .. } => "server_proof",
            RelayAuthMessage::Confirm { .. } => "confirm",
            RelayAuthMessage::Established { .. } => "established",
            RelayAuthMessage::Reject { .. } => "reject",
        }
    }

    /// Explicit refusal message carrying a reason.
    pub fn rejection(reason: &str) -> Self {
        RelayAuthMessage::Reject {
            v: RELAY_AUTH_VERSION,
            reason: reason.to_string(),
        }
    }

    /// JSON wire encoding.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| RelayAuthError::Malformed(e.to_string()))
    }

    /// Parse the JSON wire encoding (version checked on processing).
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| RelayAuthError::Malformed(e.to_string()))
    }

    fn check_version(&self) -> Result<()> {
        if self.v() != RELAY_AUTH_VERSION {
            return Err(RelayAuthError::Version {
                found: self.v(),
                expected: RELAY_AUTH_VERSION,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Identity + trust configuration
// ---------------------------------------------------------------------------

/// A side's own workload identity: the key, its issued SVID leaf chain and
/// the identity the leaf asserts. Secret material lives here (no `Debug`).
pub struct RelayAuthIdentity {
    key: WorkloadKey,
    chain: crate::issuer::IssuedChain,
    id: SpiffeId,
}

impl RelayAuthIdentity {
    /// Bind a workload key to its issued chain and identity.
    ///
    /// Refuses at construction, fail closed, when the leaf is missing, is a
    /// CA, its URI SAN does not equal `id` byte-for-byte, or its public key is
    /// not `key`'s — an identity that could never verify is a configuration
    /// error, not a runtime surprise.
    pub fn new(key: WorkloadKey, chain: crate::issuer::IssuedChain, id: SpiffeId) -> Result<Self> {
        let leaf = chain.leaf_der();
        let info = der::parse_cert(leaf.as_ref()).map_err(|e| WorkloadError::CertIdentity {
            reason: format!("leaf certificate DER: {e}"),
        })?;
        if info.is_ca {
            return Err(WorkloadError::CertIdentity {
                reason: "workload leaf must not be a CA".to_string(),
            }
            .into());
        }
        match_san_uri(&info.san_uris, id.as_str()).map_err(|e| WorkloadError::CertIdentity {
            reason: format!("leaf SAN does not equal the workload identity: {e}"),
        })?;
        if info.spki_raw_key != key.public_key_bytes().as_slice() {
            return Err(WorkloadError::KeyCertMismatch.into());
        }
        Ok(Self { key, chain, id })
    }

    /// The workload identity.
    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    /// The leaf SVID certificate, DER hex (what goes on the wire).
    pub fn leaf_cert_hex(&self) -> String {
        hex::encode(self.chain.leaf_der().as_ref())
    }

    /// The workload public key (raw 32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.public_key_bytes()
    }

    /// Sign `message` with the workload key (transcripts).
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.key.sign(message)
    }

    /// Exchange this identity's cert-backed assertion for a short-lived
    /// scope-bound access token at `authority` (the Maskinporten step, reused
    /// verbatim from [`crate::workload`]).
    pub fn obtain_token(
        &self,
        authority: &mut TokenAuthority,
        scopes: &ScopeSet,
        ttl_secs: Option<i64>,
        now: i64,
    ) -> Result<AccessToken> {
        let proof = mint_assertion(
            &self.key,
            &self.chain,
            &self.id,
            authority.endpoint_id(),
            scopes,
            ttl_secs,
            now,
        )?;
        Ok(authority.exchange(&proof, now)?)
    }
}

/// What a side requires of its peer: the trusted authority plus the scopes the
/// peer must hold. Empty scope sets are refused at construction (a peer that
/// proves nothing is a misconfiguration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTrust {
    verifier: TokenVerifier,
    required: ScopeSet,
}

impl PeerTrust {
    /// Trust `authority` and require `required` scopes of the peer.
    pub fn new(authority: &TokenAuthority, required: ScopeSet) -> Result<Self> {
        if required.is_empty() {
            return Err(RelayAuthError::Malformed(
                "peer trust requires a non-empty scope set".to_string(),
            ));
        }
        Ok(Self {
            verifier: authority.verifier(),
            required,
        })
    }

    /// The trusted authority's verifier.
    pub fn verifier(&self) -> &TokenVerifier {
        &self.verifier
    }

    /// The scopes the peer must hold.
    pub fn required(&self) -> &ScopeSet {
        &self.required
    }
}

/// A peer that passed every verification step of this handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeer {
    /// The peer workload identity (token subject; leaf SAN equal to it).
    pub sub: SpiffeId,
    /// Scopes the peer's token grants (superset of the required set).
    pub scopes: ScopeSet,
    /// `sha256(SPKI DER)` of the peer's certificate key (= token `cnf_kid`).
    pub kid: String,
    /// `sha256(leaf certificate DER)` — for logging/correlation.
    pub cert_sha256: String,
}

/// A mutually-authenticated relay session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedSession {
    /// Which side this session object belongs to (`"daemon"` / `"relay"`).
    pub role: &'static str,
    /// The verified peer.
    pub peer: VerifiedPeer,
    /// Derived binding both sides agree on (fresh per handshake).
    pub binding: String,
}

// ---------------------------------------------------------------------------
// Presentation verification (leaf cert ↔ token ↔ key)
// ---------------------------------------------------------------------------

/// Verified peer presentation: the public facts extracted from {leaf, token}.
struct Presentation {
    peer: VerifiedPeer,
    cert_key: [u8; 32],
}

fn decode_hex_exact<const N: usize>(hex_in: &str, what: &str) -> Result<[u8; N]> {
    let bytes =
        hex::decode(hex_in).map_err(|_| RelayAuthError::Malformed(format!("{what}: bad hex")))?;
    let arr: [u8; N] = bytes
        .try_into()
        .map_err(|_| RelayAuthError::Malformed(format!("{what}: expected {N} bytes")))?;
    Ok(arr)
}

/// Verify a peer presentation: token first (all authority checks), then the
/// leaf certificate bound to it, fail closed at every step.
fn verify_presentation(
    leaf_cert_hex: &str,
    token: &AccessToken,
    trust: &PeerTrust,
    now: i64,
) -> Result<Presentation> {
    // 1. Token: issuer/audience/signature/window + required scopes.
    let verified = trust.verifier().verify(token, trust.required(), now)?;

    // 2. Leaf certificate ties to the token.
    let leaf_der = hex::decode(leaf_cert_hex)
        .map_err(|_| RelayAuthError::Presentation("leaf_cert_hex is not valid hex".to_string()))?;
    let info = der::parse_cert(&leaf_der)
        .map_err(|e| RelayAuthError::Presentation(format!("leaf certificate DER: {e}")))?;
    if info.is_ca {
        return Err(RelayAuthError::Presentation(
            "presented leaf is a CA certificate".to_string(),
        ));
    }
    if !(info.not_before <= now && now < info.not_after) {
        return Err(WorkloadError::CertNotValid {
            not_before: info.not_before,
            not_after: info.not_after,
            now,
        }
        .into());
    }
    match_san_uri(&info.san_uris, verified.sub.as_str()).map_err(|e| {
        RelayAuthError::Presentation(format!("leaf SAN does not equal the token subject: {e}"))
    })?;
    let spki = workload::spki_der_from_raw(info.spki_raw_key)?;
    let kid = sha256_hex(&spki);
    if kid != token.cnf_kid {
        return Err(WorkloadError::KidMismatch {
            expected: kid,
            got: token.cnf_kid.clone(),
        }
        .into());
    }
    let cert_key: [u8; 32] = info
        .spki_raw_key
        .try_into()
        .map_err(|_| RelayAuthError::Presentation("certificate key is not 32 bytes".to_string()))?;

    Ok(Presentation {
        peer: VerifiedPeer {
            sub: verified.sub,
            scopes: verified.scopes,
            kid: token.cnf_kid.clone(),
            cert_sha256: sha256_hex(&leaf_der),
        },
        cert_key,
    })
}

/// Verify a transcript signature under the **peer certificate's** key
/// (proof of possession; `verify_possession` also re-checks the `cnf_kid`
/// binding).
fn verify_pop(
    token: &AccessToken,
    cert_key: &[u8; 32],
    transcript: &[u8],
    pop_hex: &str,
) -> Result<()> {
    let sig: [u8; SIGNATURE_LEN] = decode_hex_exact(pop_hex, "pop")?;
    verify_possession(token, cert_key, transcript, &sig)
        .map_err(|e| RelayAuthError::Possession(e.to_string()))
}

// ---------------------------------------------------------------------------
// Client role (the daemon dialling the relay)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    Start,
    HelloSent,
    AwaitEstablished,
    Established,
    Failed,
}

/// The **daemon side** of the handshake (client role).
pub struct ClientMachine<'a> {
    identity: &'a RelayAuthIdentity,
    trust: &'a PeerTrust,
    token: AccessToken,
    nonce: String,
    state: ClientState,
    server_nonce: Option<String>,
    server_token: Option<AccessToken>,
    server_presentation: Option<Presentation>,
    session: Option<EstablishedSession>,
}

impl<'a> ClientMachine<'a> {
    /// Fail-closed entry point: **no identity (or no token) → no session**,
    /// refused before any message is produced. A configured identity starts
    /// the machine (fresh nonce).
    pub fn begin(
        identity: Option<&'a RelayAuthIdentity>,
        trust: &'a PeerTrust,
        token: Option<AccessToken>,
    ) -> Result<Self> {
        let identity = identity.ok_or(RelayAuthError::NoIdentity)?;
        let token = token.ok_or(RelayAuthError::NoIdentity)?;
        Ok(Self {
            identity,
            trust,
            token,
            nonce: fresh_nonce(),
            state: ClientState::Start,
            server_nonce: None,
            server_token: None,
            server_presentation: None,
            session: None,
        })
    }

    /// The state label (for errors/tests).
    pub fn state(&self) -> &'static str {
        match self.state {
            ClientState::Start => "start",
            ClientState::HelloSent => "hello_sent",
            ClientState::AwaitEstablished => "await_established",
            ClientState::Established => "established",
            ClientState::Failed => "failed",
        }
    }

    /// First flight: `Hello { leaf, token, nonce }`.
    pub fn hello(&mut self) -> Result<RelayAuthMessage> {
        if self.state != ClientState::Start {
            return Err(RelayAuthError::Order {
                state: self.state(),
                got: "hello",
            });
        }
        self.state = ClientState::HelloSent;
        Ok(RelayAuthMessage::Hello {
            v: RELAY_AUTH_VERSION,
            leaf_cert_hex: self.identity.leaf_cert_hex(),
            token: self.token.clone(),
            nonce: self.nonce.clone(),
        })
    }

    /// Process the relay's `ServerProof`; on success returns the `Confirm`
    /// flight (the client's own proof of possession). Any failure fails the
    /// machine closed (no session, `Confirm` never produced).
    pub fn on_server_proof(
        &mut self,
        msg: &RelayAuthMessage,
        now: i64,
    ) -> Result<RelayAuthMessage> {
        if self.state != ClientState::HelloSent {
            return Err(RelayAuthError::Order {
                state: self.state(),
                got: msg.kind(),
            });
        }
        match msg {
            RelayAuthMessage::Reject { reason, .. } => {
                self.state = ClientState::Failed;
                Err(RelayAuthError::Rejected {
                    reason: reason.clone(),
                })
            }
            RelayAuthMessage::ServerProof {
                leaf_cert_hex,
                token,
                nonce,
                pop,
                ..
            } => {
                msg.check_version()?;
                check_nonce(nonce).inspect_err(|_| {
                    self.state = ClientState::Failed;
                })?;
                let presentation = verify_presentation(leaf_cert_hex, token, self.trust, now)
                    .inspect_err(|_| {
                        self.state = ClientState::Failed;
                    })?;
                let transcript = auth_transcript("server", &self.nonce, nonce, &self.token, token);
                verify_pop(token, &presentation.cert_key, &transcript, pop).inspect_err(|_| {
                    self.state = ClientState::Failed;
                })?;

                self.server_nonce = Some(nonce.clone());
                self.server_token = Some(token.clone());
                self.server_presentation = Some(presentation);

                let pop_hex = hex::encode(self.identity.sign(&auth_transcript(
                    "client",
                    &self.nonce,
                    nonce,
                    &self.token,
                    token,
                )));
                self.state = ClientState::AwaitEstablished;
                Ok(RelayAuthMessage::Confirm {
                    v: RELAY_AUTH_VERSION,
                    pop: pop_hex,
                })
            }
            other => {
                self.state = ClientState::Failed;
                Err(RelayAuthError::Order {
                    state: "hello_sent",
                    got: other.kind(),
                })
            }
        }
    }

    /// Process the relay's `Established`; the client accepts the session only
    /// if the relay's binding matches its own derivation.
    pub fn on_established(&mut self, msg: &RelayAuthMessage) -> Result<EstablishedSession> {
        if self.state != ClientState::AwaitEstablished {
            return Err(RelayAuthError::Order {
                state: self.state(),
                got: msg.kind(),
            });
        }
        match msg {
            RelayAuthMessage::Reject { reason, .. } => {
                self.state = ClientState::Failed;
                Err(RelayAuthError::Rejected {
                    reason: reason.clone(),
                })
            }
            RelayAuthMessage::Established { binding, .. } => {
                msg.check_version()?;
                let presentation =
                    self.server_presentation
                        .take()
                        .ok_or(RelayAuthError::Order {
                            state: "await_established",
                            got: "established without a verified server proof",
                        })?;
                let expected = session_binding(
                    &self.nonce,
                    self.server_nonce.as_deref().unwrap_or_default(),
                    &self.token,
                    self.server_token
                        .as_ref()
                        .ok_or(RelayAuthError::NoIdentity)?,
                );
                if *binding != expected {
                    self.state = ClientState::Failed;
                    return Err(RelayAuthError::BindingMismatch {
                        expected,
                        got: binding.clone(),
                    });
                }
                let session = EstablishedSession {
                    role: "daemon",
                    peer: presentation.peer,
                    binding: binding.clone(),
                };
                self.state = ClientState::Established;
                self.session = Some(session.clone());
                Ok(session)
            }
            other => {
                self.state = ClientState::Failed;
                Err(RelayAuthError::Order {
                    state: "await_established",
                    got: other.kind(),
                })
            }
        }
    }

    /// The established session, if any.
    pub fn session(&self) -> Option<&EstablishedSession> {
        self.session.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Server role (the relay accepting the daemon)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerState {
    Start,
    AwaitConfirm,
    Established,
    Failed,
}

/// The **relay side** of the handshake (server role).
pub struct ServerMachine<'a> {
    identity: &'a RelayAuthIdentity,
    trust: &'a PeerTrust,
    token: AccessToken,
    nonce: String,
    state: ServerState,
    client_nonce: Option<String>,
    client_token: Option<AccessToken>,
    client_presentation: Option<Presentation>,
    session: Option<EstablishedSession>,
}

impl<'a> ServerMachine<'a> {
    /// Fail-closed entry point: **no identity (or no token) → no session**,
    /// refused before any message is produced.
    pub fn begin(
        identity: Option<&'a RelayAuthIdentity>,
        trust: &'a PeerTrust,
        token: Option<AccessToken>,
    ) -> Result<Self> {
        let identity = identity.ok_or(RelayAuthError::NoIdentity)?;
        let token = token.ok_or(RelayAuthError::NoIdentity)?;
        Ok(Self {
            identity,
            trust,
            token,
            nonce: fresh_nonce(),
            state: ServerState::Start,
            client_nonce: None,
            client_token: None,
            client_presentation: None,
            session: None,
        })
    }

    /// The state label (for errors/tests).
    pub fn state(&self) -> &'static str {
        match self.state {
            ServerState::Start => "start",
            ServerState::AwaitConfirm => "await_confirm",
            ServerState::Established => "established",
            ServerState::Failed => "failed",
        }
    }

    /// Process the daemon's `Hello`; on success returns the relay's
    /// `ServerProof` (its own presentation + transcript proof). The daemon is
    /// **not** authenticated yet — only its `Confirm` completes mutual auth.
    pub fn on_hello(&mut self, msg: &RelayAuthMessage, now: i64) -> Result<RelayAuthMessage> {
        if self.state != ServerState::Start {
            return Err(RelayAuthError::Order {
                state: self.state(),
                got: msg.kind(),
            });
        }
        match msg {
            RelayAuthMessage::Reject { reason, .. } => {
                self.state = ServerState::Failed;
                Err(RelayAuthError::Rejected {
                    reason: reason.clone(),
                })
            }
            RelayAuthMessage::Hello {
                leaf_cert_hex,
                token,
                nonce,
                ..
            } => {
                msg.check_version()?;
                check_nonce(nonce).inspect_err(|_| {
                    self.state = ServerState::Failed;
                })?;
                let presentation = verify_presentation(leaf_cert_hex, token, self.trust, now)
                    .inspect_err(|_| {
                        self.state = ServerState::Failed;
                    })?;

                self.client_nonce = Some(nonce.clone());
                self.client_token = Some(token.clone());
                self.client_presentation = Some(presentation);

                let pop = hex::encode(self.identity.sign(&auth_transcript(
                    "server",
                    nonce,
                    &self.nonce,
                    token,
                    &self.token,
                )));
                self.state = ServerState::AwaitConfirm;
                Ok(RelayAuthMessage::ServerProof {
                    v: RELAY_AUTH_VERSION,
                    leaf_cert_hex: self.identity.leaf_cert_hex(),
                    token: self.token.clone(),
                    nonce: self.nonce.clone(),
                    pop,
                })
            }
            other => {
                self.state = ServerState::Failed;
                Err(RelayAuthError::Order {
                    state: "start",
                    got: other.kind(),
                })
            }
        }
    }

    /// Process the daemon's `Confirm`; on success the relay is authenticated
    /// to the daemon and the relay accepts the session, returning
    /// `Established { binding }`.
    pub fn on_confirm(&mut self, msg: &RelayAuthMessage) -> Result<RelayAuthMessage> {
        if self.state != ServerState::AwaitConfirm {
            return Err(RelayAuthError::Order {
                state: self.state(),
                got: msg.kind(),
            });
        }
        match msg {
            RelayAuthMessage::Reject { reason, .. } => {
                self.state = ServerState::Failed;
                Err(RelayAuthError::Rejected {
                    reason: reason.clone(),
                })
            }
            RelayAuthMessage::Confirm { pop, .. } => {
                msg.check_version()?;
                let client_presentation =
                    self.client_presentation
                        .take()
                        .ok_or(RelayAuthError::Order {
                            state: "await_confirm",
                            got: "confirm before hello",
                        })?;
                let (client_token, client_nonce) =
                    match (self.client_token.as_ref(), self.client_nonce.as_deref()) {
                        (Some(t), Some(n)) => (t, n),
                        _ => {
                            return Err(RelayAuthError::Order {
                                state: "await_confirm",
                                got: "confirm before hello",
                            })
                        }
                    };
                let transcript = auth_transcript(
                    "client",
                    client_nonce,
                    &self.nonce,
                    client_token,
                    &self.token,
                );
                verify_pop(
                    client_token,
                    &client_presentation.cert_key,
                    &transcript,
                    pop,
                )
                .inspect_err(|_| {
                    self.state = ServerState::Failed;
                })?;

                let binding = session_binding(client_nonce, &self.nonce, client_token, &self.token);
                let session = EstablishedSession {
                    role: "relay",
                    peer: client_presentation.peer,
                    binding: binding.clone(),
                };
                self.state = ServerState::Established;
                self.session = Some(session);
                Ok(RelayAuthMessage::Established {
                    v: RELAY_AUTH_VERSION,
                    binding,
                })
            }
            other => {
                self.state = ServerState::Failed;
                Err(RelayAuthError::Order {
                    state: "await_confirm",
                    got: other.kind(),
                })
            }
        }
    }

    /// The established session, if any.
    pub fn session(&self) -> Option<&EstablishedSession> {
        self.session.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::{now_unix, IssuedChain, NodeIssuer};
    use crate::model;
    use crate::policy::ServiceRegistry;
    use crate::workload::{Action, Scope, DIGEST_HEX_LEN};
    use tallow_crypto::sig::ed25519::Ed25519Signer;

    fn t0() -> i64 {
        now_unix()
    }

    fn id(node: &str, svc: &str) -> SpiffeId {
        SpiffeId::new(node, svc).expect("test id")
    }

    fn scope(service: &str, action: Action) -> Scope {
        Scope::new(service, action).expect("test scope")
    }

    fn daemon_scopes() -> ScopeSet {
        ScopeSet::from_scopes([scope("relay", Action::Write)]).unwrap()
    }

    fn relay_scopes() -> ScopeSet {
        ScopeSet::from_scopes([scope("daemon", Action::Write)]).unwrap()
    }

    /// node-01 authority: grants daemon→relay:write, relay→daemon:{write,read}.
    fn authority() -> TokenAuthority {
        let issuer_id = SpiffeId::parse(&model::issuer_san("node-01").unwrap()).unwrap();
        let mut policy = workload::ScopePolicy::empty();
        policy
            .grant_all("daemon", [scope("relay", Action::Write)])
            .unwrap();
        policy
            .grant_all(
                "relay",
                [
                    scope("daemon", Action::Write),
                    scope("daemon", Action::Read),
                ],
            )
            .unwrap();
        TokenAuthority::new(issuer_id, Ed25519Signer::from_seed([7u8; 32]), policy, None).unwrap()
    }

    /// A real SVID leaf identity from the crate's NodeIssuer.
    fn identity(issuer: &mut NodeIssuer, svc: &str) -> RelayAuthIdentity {
        let key = WorkloadKey::generate();
        let id = id("node-01", svc);
        let chain: IssuedChain = issuer
            .issue_workload_leaf_from_spki(&key.spki_der(), &id, None)
            .expect("leaf");
        RelayAuthIdentity::new(key, chain, id).expect("identity")
    }

    /// Full fixture: identities + tokens for both sides + trust configs.
    fn fixture() -> (
        RelayAuthIdentity,
        RelayAuthIdentity,
        AccessToken,
        AccessToken,
        PeerTrust,
        PeerTrust,
    ) {
        let mut issuer = NodeIssuer::generate("node-01").unwrap();
        // "relay" is not in `BUILTIN_SERVICE_NAMES` (which enumerates the
        // in-daemon processes: daemon, job-worker, browser-pool, reader, vault,
        // pkg-runner, mesh-node, cli) — issuing a relay identity takes the
        // explicit operator registration path.
        let mut registry = ServiceRegistry::builtin();
        registry.register("relay").unwrap();
        issuer.set_registry(registry);
        issuer.issue_issuer_intermediate(None).unwrap();
        let daemon = identity(&mut issuer, "daemon");
        let relay = identity(&mut issuer, "relay");
        let mut auth = authority();
        let t = t0();
        let daemon_token = daemon
            .obtain_token(&mut auth, &daemon_scopes(), None, t)
            .expect("daemon token");
        let relay_token = relay
            .obtain_token(&mut auth, &relay_scopes(), None, t)
            .expect("relay token");
        // The daemon requires `relay:…` scope of the token it *sends*; the
        // trust each side applies to its peer is expressed from the peer's
        // token: relay presents daemon:write, daemon presents relay:write.
        let relay_trust_for_daemon = PeerTrust::new(&auth, daemon_scopes()).unwrap();
        let daemon_trust_for_relay = PeerTrust::new(&auth, relay_scopes()).unwrap();
        (
            daemon,
            relay,
            daemon_token,
            relay_token,
            relay_trust_for_daemon,
            daemon_trust_for_relay,
        )
    }

    /// Drive the full 4-flight handshake over an in-memory loopback.
    fn run(
        fixture: &(
            RelayAuthIdentity,
            RelayAuthIdentity,
            AccessToken,
            AccessToken,
            PeerTrust,
            PeerTrust,
        ),
        now_client: i64,
        now_server: i64,
    ) -> (Result<EstablishedSession>, Result<EstablishedSession>) {
        let (daemon, relay, dtoken, rtoken, relay_trust, daemon_trust) = fixture;
        let mut c = ClientMachine::begin(Some(daemon), daemon_trust, Some(dtoken.clone())).unwrap();
        let mut s = ServerMachine::begin(Some(relay), relay_trust, Some(rtoken.clone())).unwrap();
        let hello = c.hello().unwrap();
        let server_proof = match s.on_hello(&hello, now_server) {
            Ok(m) => m,
            Err(e) => return (Err(e.clone()), Err(e)),
        };
        let confirm = match c.on_server_proof(&server_proof, now_client) {
            Ok(m) => m,
            Err(e) => return (Err(e.clone()), Err(e)),
        };
        let established = match s.on_confirm(&confirm) {
            Ok(m) => m,
            Err(e) => return (Err(e.clone()), Err(e)),
        };
        let client_session = c.on_established(&established);
        let server_session = s.session().cloned().ok_or(RelayAuthError::NoIdentity);
        (client_session, server_session)
    }

    #[test]
    fn mutual_auth_loopback_establishes_identical_binding() {
        let fx = fixture();
        let (client, server) = run(&fx, t0(), t0());
        let client = client.expect("client session");
        let server = server.expect("server session");
        assert_eq!(client.role, "daemon");
        assert_eq!(server.role, "relay");
        assert_eq!(
            client.binding, server.binding,
            "both sides derive one binding"
        );
        assert_eq!(client.binding.len(), DIGEST_HEX_LEN);
        assert_eq!(client.peer.sub, id("node-01", "relay"));
        assert_eq!(server.peer.sub, id("node-01", "daemon"));
        assert_eq!(client.peer.scopes, relay_scopes());
        assert_eq!(server.peer.scopes, daemon_scopes());
        let relay_kid = hex::encode(Sha256::digest(
            workload::spki_der_from_raw(&fx.1.public_key_bytes()).unwrap(),
        ));
        assert_eq!(client.peer.kid, relay_kid);
        assert_eq!(client.peer.cert_sha256.len(), DIGEST_HEX_LEN);
        // The wire forms round-trip.
        let wire = RelayAuthMessage::Established {
            v: RELAY_AUTH_VERSION,
            binding: client.binding.clone(),
        };
        let parsed = RelayAuthMessage::from_json(&wire.to_json().unwrap()).unwrap();
        assert_eq!(parsed, wire);
    }

    #[test]
    fn no_identity_fails_closed_without_any_message() {
        let fx = fixture();
        let (daemon, _relay, dtoken, _rtoken, _rt, daemon_trust) = &fx;
        let err = ClientMachine::begin(None, daemon_trust, Some(dtoken.clone()))
            .err()
            .expect("daemon without identity must refuse");
        assert!(matches!(err, RelayAuthError::NoIdentity), "{err:?}");
        let err = ClientMachine::begin(Some(daemon), daemon_trust, None)
            .err()
            .expect("daemon without a token must refuse");
        assert!(matches!(err, RelayAuthError::NoIdentity), "{err:?}");
        let err = ServerMachine::begin(None, &fx.4, None)
            .err()
            .expect("relay without identity");
        assert!(matches!(err, RelayAuthError::NoIdentity), "{err:?}");
    }

    #[test]
    fn expired_token_fails_closed_and_reject_is_wireable() {
        let fx = fixture();
        let (daemon, relay, dtoken, rtoken, relay_trust, daemon_trust) = &fx;
        let mut c = ClientMachine::begin(Some(daemon), daemon_trust, Some(dtoken.clone())).unwrap();
        let mut s = ServerMachine::begin(Some(relay), relay_trust, Some(rtoken.clone())).unwrap();
        let hello = c.hello().unwrap();
        // The daemon token (default 300 s TTL) is long expired here.
        let err = s
            .on_hello(&hello, t0() + 3600)
            .expect_err("expired client token");
        assert!(
            matches!(
                err,
                RelayAuthError::Workload(WorkloadError::TokenExpired { .. })
            ),
            "{err:?}"
        );
        assert_eq!(s.state(), "failed");
        // The relay answers with an explicit Reject; the client refuses too.
        let rej = RelayAuthMessage::rejection(&err.to_string());
        let err = c.on_server_proof(&rej, t0()).expect_err("reject relayed");
        assert!(matches!(err, RelayAuthError::Rejected { .. }), "{err:?}");
        assert!(c.session().is_none() && s.session().is_none(), "no session");
    }

    #[test]
    fn cert_key_not_bound_to_token_fails_closed() {
        let fx = fixture();
        let (daemon, relay, _dtoken, rtoken, relay_trust, daemon_trust) = &fx;
        let mut c = ClientMachine::begin(Some(daemon), daemon_trust, Some(fx.2.clone())).unwrap();
        let mut s = ServerMachine::begin(Some(relay), relay_trust, Some(rtoken.clone())).unwrap();
        let mut hello = c.hello().unwrap();
        // Attacker swaps in a second valid leaf (same SAN) for a *different*
        // key while keeping the victim's token: the cnf_kid binding must catch
        // it even though the SAN matches.
        let mut issuer = NodeIssuer::generate("node-01").unwrap();
        let mut registry = crate::policy::ServiceRegistry::builtin();
        let _ = registry.register("relay");
        issuer.set_registry(registry);
        issuer.issue_issuer_intermediate(None).unwrap();
        let other = identity(&mut issuer, "daemon");
        let RelayAuthMessage::Hello { leaf_cert_hex, .. } = &mut hello else {
            unreachable!()
        };
        *leaf_cert_hex = other.leaf_cert_hex();
        let err = s.on_hello(&hello, t0()).expect_err("presentation mismatch");
        assert!(
            matches!(
                err,
                RelayAuthError::Workload(WorkloadError::KidMismatch { .. })
            ),
            "{err:?}"
        );
        assert_eq!(s.state(), "failed");
        assert!(s.session().is_none());
    }

    #[test]
    fn bad_proof_of_possession_fails_closed() {
        let fx = fixture();
        let (daemon, relay, dtoken, rtoken, relay_trust, daemon_trust) = &fx;
        let mut c = ClientMachine::begin(Some(daemon), daemon_trust, Some(dtoken.clone())).unwrap();
        let mut s = ServerMachine::begin(Some(relay), relay_trust, Some(rtoken.clone())).unwrap();
        let hello = c.hello().unwrap();
        let server_proof = s.on_hello(&hello, t0()).unwrap();
        let mut confirm = c.on_server_proof(&server_proof, t0()).unwrap();
        let RelayAuthMessage::Confirm { pop, .. } = &mut confirm else {
            unreachable!()
        };
        // Flip a byte: a captured token without the key must not authenticate.
        let mut bytes = hex::decode(pop.as_str()).unwrap();
        bytes[0] ^= 0x01;
        *pop = hex::encode(bytes);
        let err = s.on_confirm(&confirm).expect_err("bad pop");
        assert!(matches!(err, RelayAuthError::Possession(_)), "{err:?}");
        assert_eq!(s.state(), "failed");
        assert!(s.session().is_none());
    }

    #[test]
    fn insufficient_peer_scope_fails_closed() {
        let fx = fixture();
        let (daemon, relay, dtoken, _rtoken, relay_trust, daemon_trust) = &fx;
        // The relay holds only `daemon:read` — the daemon requires
        // `daemon:write` of it, so the client must refuse the ServerProof.
        let mut auth = authority();
        let weak = relay
            .obtain_token(
                &mut auth,
                &ScopeSet::from_scopes([scope("daemon", Action::Read)]).unwrap(),
                None,
                t0(),
            )
            .unwrap();
        let mut c = ClientMachine::begin(Some(daemon), daemon_trust, Some(dtoken.clone())).unwrap();
        let mut s = ServerMachine::begin(Some(relay), relay_trust, Some(weak)).unwrap();
        let hello = c.hello().unwrap();
        let server_proof = s.on_hello(&hello, t0()).unwrap();
        let err = c
            .on_server_proof(&server_proof, t0())
            .expect_err("insufficient scope");
        assert!(
            matches!(
                err,
                RelayAuthError::Workload(WorkloadError::ScopeMissing { .. })
            ),
            "{err:?}"
        );
        assert!(c.session().is_none());
    }

    #[test]
    fn tampered_binding_fails_closed() {
        let fx = fixture();
        let (daemon, relay, dtoken, rtoken, relay_trust, daemon_trust) = &fx;
        let mut c = ClientMachine::begin(Some(daemon), daemon_trust, Some(dtoken.clone())).unwrap();
        let mut s = ServerMachine::begin(Some(relay), relay_trust, Some(rtoken.clone())).unwrap();
        let hello = c.hello().unwrap();
        let server_proof = s.on_hello(&hello, t0()).unwrap();
        let confirm = c.on_server_proof(&server_proof, t0()).unwrap();
        let _ = s.on_confirm(&confirm).unwrap();
        let err = c
            .on_established(&RelayAuthMessage::Established {
                v: RELAY_AUTH_VERSION,
                binding: "0".repeat(DIGEST_HEX_LEN),
            })
            .expect_err("binding mismatch");
        assert!(
            matches!(err, RelayAuthError::BindingMismatch { .. }),
            "{err:?}"
        );
        assert!(c.session().is_none());
    }

    #[test]
    fn version_and_shape_refusals() {
        let fx = fixture();
        let (daemon, _relay, dtoken, _rtoken, _rt, daemon_trust) = &fx;
        let mut c = ClientMachine::begin(Some(daemon), daemon_trust, Some(dtoken.clone())).unwrap();
        let _ = c.hello().unwrap();
        let err = c
            .on_server_proof(
                &RelayAuthMessage::ServerProof {
                    v: 2,
                    leaf_cert_hex: "00".to_string(),
                    token: fx.3.clone(),
                    nonce: "0".repeat(NONCE_HEX_LEN),
                    pop: "00".to_string(),
                },
                t0(),
            )
            .expect_err("version");
        assert!(matches!(err, RelayAuthError::Version { .. }), "{err:?}");

        let mut c2 =
            ClientMachine::begin(Some(daemon), daemon_trust, Some(dtoken.clone())).unwrap();
        let _ = c2.hello().unwrap();
        let err = c2
            .on_server_proof(
                &RelayAuthMessage::ServerProof {
                    v: RELAY_AUTH_VERSION,
                    leaf_cert_hex: "00".to_string(),
                    token: fx.3.clone(),
                    nonce: "not-a-nonce".to_string(),
                    pop: "00".to_string(),
                },
                t0(),
            )
            .expect_err("malformed nonce");
        assert!(matches!(err, RelayAuthError::Malformed(_)), "{err:?}");

        // Empty required scope set is a misconfiguration, refused up front.
        let err = PeerTrust::new(&authority(), ScopeSet::empty()).expect_err("empty trust");
        assert!(matches!(err, RelayAuthError::Malformed(_)), "{err:?}");
    }
}
