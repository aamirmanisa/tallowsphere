//! Cross-domain release gate — a boundary model over the existing policy cores.
//!
//! The policy cores answer three questions well and separately:
//! [`crate::access_class`] (*may this audience take material of this class
//! out?*), [`crate::caveats`] (*how far may an admissible release travel?*),
//! and [`crate::redaction`] (*what exactly leaves?*). None of them models the
//! **boundary the material is crossing**. This module supplies that model and
//! composes the cores in one ordered, fail-closed decision.
//!
//! # Why a boundary model
//!
//! A transfer is characterised by four properties of the crossing, not by the
//! name of the mechanism that performs it: *chokepoint*, *directionality*,
//! *inspection* and *retention*. Every documented cross-boundary failure in the
//! public record is a boundary-model failure rather than a material-model one —
//! a mandated intercept interface inherited by an adversary, a dissemination
//! marking rendered but never evaluated, a collection pipe asked to carry more
//! than its rate class permits. [`TransferChannel`] makes those properties
//! typed, and [`gate`] makes them binding.
//!
//! # Frozen stage order
//!
//! [`gate`] evaluates six stages and the **first refusal wins**:
//!
//! 1. plan validity, then lineage (a declared class looser than an ancestor is
//!    a downgrade and needs explicit review);
//! 2. channel admission ([`TransferChannel::parse`]);
//! 3. **channel obligations** — rate class, sanitisation precondition,
//!    directionality, per-archetype required fields;
//! 4. the access-class gate ([`check_export`]);
//! 5. the caveat gate ([`release_check`]);
//! 6. release: the summary marking and the receipt hash.
//!
//! Stage 3 deliberately precedes stage 4. A refusal at stage 3 is about the
//! *boundary*, not the payload: open material must not reach a non-bulk channel
//! merely because nothing about it is sensitive. Running the class gate first
//! would permit exactly that.
//!
//! Stage 4 precedes stage 5 because [`crate::caveats`] documents the
//! dependency: caveats *restrict what the class gate already admitted and can
//! never widen it*.
//!
//! # Documented rules
//!
//! * **Deny-by-default.** An unknown channel, an unparseable caveat string, a
//!   missing required field, or a malformed plan is a refusal — never an
//!   ignore. There is no "warn and continue" path.
//! * **Rate class.** A channel with `bulk_ok == false` refuses any payload
//!   larger than [`DEFAULT_PAYLOAD_CAP_BITS`] (overridable per plan). A
//!   channel measured in bits per second is not a bulk transfer path.
//! * **Sanitisation precondition.** A channel with `inspected == false` may
//!   carry only material that is either attested pre-sanitised or accompanied
//!   by redaction rules. A pipe that cannot inspect cannot enforce hygiene
//!   later, so hygiene is a precondition.
//! * **Caveats restrict only.** They are evaluated to *refuse*; they never
//!   grant. Empty caveat list means unconstrained by this module.
//! * **Pure.** No I/O, no clock, no globals. `now_ms` and every input are
//!   caller-supplied so a decision is reproducible from its record.
//!
//! # Scope
//!
//! This module decides; it never transmits. It opens no sockets, executes
//! nothing, and handles no credentials. Composing the released derivative and
//! the tamper-evident receipt is [`crate::enforcement`]'s job; this module
//! supplies the decision and the payload the receipt commits to.

use std::fmt;

use crate::kt_log::{KtLog, payload_hash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::access_class::{AccessClass, Audience, check_export};
use crate::caveats::{Caveat, release_check, summary_marking};

/// How long `release` waits for another writer to finish with the same `--kt-log` before it refuses.
/// Overridable through `SLUICE_KT_LOCK_WAIT_MS`, which is what lets the test exercise the refusal
/// without spending the default; the wait exists because a brief overlap is normal and turning it
/// into a failed release would be worse than queueing, while past the bound refusing is fail-closed.
const KT_LOG_LOCK_WAIT_MS: u64 = 10_000;
/// Poll interval while waiting. Small enough that a quick append hands over promptly.
const KT_LOG_LOCK_POLL_MS: u64 = 20;

/// An exclusive lock over one receipt log, held across the whole read-modify-write of an append.
///
/// `kt_log`'s append reads the head, chains onto it, and writes — and the library documents that it
/// takes no lock (`src/kt_log.rs:52`, "no file locking is performed"). Two `release` processes
/// opening the same `--kt-log` therefore both chain onto the same head and both write the same
/// `seq`; the log then cannot be reopened at all (`kt-log: seq mismatch at position 1`), while BOTH
/// processes exit 0. Measured before this existed: 5 of 8 rounds, and in none of them was a line
/// torn — the write is atomic, the read-modify-write is not. Fail-closed on read and fail-OPEN on
/// write is the wrong way round for a boundary whose whole product is evidence.
///
/// The exclusion lives here, in the writer, and not in the log: `kt_log` keeps its documented
/// behaviour, and the product states a protocol of its own — one writer at a time per `--kt-log`,
/// enforced rather than assumed. `flock(2)` on the log's own inode rather than a sidecar lock file,
/// because R-CLI-10 allows writes only to `--out` and the `--kt-log` path; it is also released by the
/// kernel when the holder dies, so there is no stale lock for an operator to clear by hand.
#[derive(Debug)]
struct ReceiptLogLock {
    file: std::fs::File,
}

impl ReceiptLogLock {
    fn wait_ms() -> u64 {
        std::env::var("SLUICE_KT_LOCK_WAIT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(KT_LOG_LOCK_WAIT_MS)
    }

    fn acquire(log_path: &Path) -> Result<Self, DraftError> {
        Self::acquire_with_wait(log_path, Self::wait_ms())
    }

    fn acquire_with_wait(log_path: &Path, wait: u64) -> Result<Self, DraftError> {
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(log_path)
            .map_err(|e| {
                DraftError::Io(format!(
                    "cannot open the KT log '{}': {e}",
                    log_path.display()
                ))
            })?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(wait);
        loop {
            // SAFETY: `file` owns a valid descriptor for as long as this guard lives.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { file });
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(DraftError::Io(format!(
                    "cannot lock the KT log '{}': {err}",
                    log_path.display()
                )));
            }
            if std::time::Instant::now() >= deadline {
                return Err(DraftError::Io(format!(
                    "another release holds the KT log '{}' — refusing rather than chaining a receipt \
                     onto a head another writer may have moved (waited {wait} ms; SLUICE_KT_LOCK_WAIT_MS \
                     raises the wait)",
                    log_path.display()
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(KT_LOG_LOCK_POLL_MS));
        }
    }
}

impl Drop for ReceiptLogLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // The kernel releases this on exit anyway; unlocking here keeps a same-process test honest
        // and makes the guard's scope the thing that defines the critical section.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Domain separator between the previous hash and the canonical payload —
/// the same rule [`crate::ledger_events`] uses, so the two chains splice
/// nothing across the boundary.
const UNIT_SEP: u8 = 0x1f;

/// First-entry marker for a receipt chain.
pub const GENESIS: &str = "GENESIS";

/// Payload budget for a channel whose `bulk_ok` is `false`, in bits.
pub const DEFAULT_PAYLOAD_CAP_BITS: u64 = 4096;

// ── The channel model ────────────────────────────────────────────────────────

/// The boundary a release crosses. One variant per transfer class in the
/// public cross-domain taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransferChannel {
    /// Bulk bearer: an in-line copy at a carrier or landing point.
    Bearer,
    /// Provider-assisted collection / a mandated intercept interface.
    Compelled,
    /// A pull from a compromised endpoint.
    Endpoint,
    /// Physical media carried by a person.
    Physical,
    /// A covert channel crossing an air gap.
    Covert,
    /// A coalition exchange boundary (diode or guard).
    Coalition,
}

impl TransferChannel {
    /// Every archetype, in taxonomy order.
    pub const ALL: [TransferChannel; 6] = [
        TransferChannel::Bearer,
        TransferChannel::Compelled,
        TransferChannel::Endpoint,
        TransferChannel::Physical,
        TransferChannel::Covert,
        TransferChannel::Coalition,
    ];

    /// Stable lowercase token; also the wire form used by a release plan.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransferChannel::Bearer => "bearer",
            TransferChannel::Compelled => "compelled",
            TransferChannel::Endpoint => "endpoint",
            TransferChannel::Physical => "physical",
            TransferChannel::Covert => "covert",
            TransferChannel::Coalition => "coalition",
        }
    }

    /// Parse the wire token. `None` is a refusal at the caller, never a
    /// silent default.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// `true` when the boundary physically enforces one-way flow.
    pub fn one_way(&self) -> bool {
        !matches!(self, TransferChannel::Bearer | TransferChannel::Compelled)
    }

    /// `true` when something inspects content at the crossing.
    pub fn inspected(&self) -> bool {
        matches!(self, TransferChannel::Coalition)
    }

    /// Retention posture: `"buffer"` (short retention + retrospective query),
    /// `"target"` (retained for a named target), or `"none"`.
    pub fn retention(&self) -> &'static str {
        match self {
            TransferChannel::Bearer | TransferChannel::Coalition => "buffer",
            TransferChannel::Compelled | TransferChannel::Endpoint => "target",
            TransferChannel::Physical | TransferChannel::Covert => "none",
        }
    }

    /// `true` when **no rate cap is imposed** on this boundary.
    ///
    /// Not a claim about volume, and the name is the only place that ambiguity
    /// lives. The research's class 3 (endpoint) is explicitly a *low-rate*
    /// channel — "~kb/s–Mb/s sustained, bounded by stealth" — and belongs to its
    /// **risk** group rather than its volume group ("classes 1, 2 and 6 carry the
    /// volume; classes 3, 4 and 5 carry the risk"). Yet a sub-kilobyte cap would
    /// be meaningless for a host pull, so `true` is correct here while "may carry
    /// bulk" would be false.
    ///
    /// The cap exists for exactly one archetype, the one whose **physics** makes
    /// bulk impossible: class 5 measures in bits per second. Read this as "the
    /// rate class does not apply", never as "this is a bulk channel".
    pub fn bulk_ok(&self) -> bool {
        !matches!(self, TransferChannel::Covert)
    }

    /// Plan fields this archetype requires to be non-empty.
    pub fn requires(&self) -> &'static [&'static str] {
        match self {
            TransferChannel::Bearer => &[],
            TransferChannel::Compelled => &["warrant_ref"],
            TransferChannel::Endpoint => &["staging_manifest"],
            TransferChannel::Physical => &["media_hash"],
            // Covert's obligation is the RATE CLASS, not a required field:
            // `payload_cap_bits` is optional-with-default in the plan schema,
            // so the cap is enforced (overridably) rather than demanded.
            TransferChannel::Covert => &[],
            TransferChannel::Coalition => &["marking_emitted"],
        }
    }

    /// The transfer class this archetype derives from.
    pub fn source(&self) -> &'static str {
        match self {
            TransferChannel::Bearer => "class 1 - bulk bearer interception",
            TransferChannel::Compelled => "class 2 - provider-assisted / mandated intercept",
            TransferChannel::Endpoint => "class 3 - endpoint compromise pull",
            TransferChannel::Physical => "class 4 - physical / sneakernet",
            TransferChannel::Covert => "class 5 - covert channel / air-gap crossing",
            TransferChannel::Coalition => "class 6 - cross-domain diode / guard",
        }
    }
}

impl fmt::Display for TransferChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── The plan ─────────────────────────────────────────────────────────────────

/// The artifact being released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Source path, recorded for the audit line (never opened by this module).
    pub path: String,
    /// Lowercase hex sha256 of the artifact bytes.
    pub sha256: String,
    /// Artifact size in bytes; the rate-class input.
    pub bytes: u64,
}

/// One ancestor of the artifact, for downgrade detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageEntry {
    /// Classification the ancestor carried.
    pub class: AccessClass,
}

/// Where the material came from and how tightly it is held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// Originator tag.
    pub origin: String,
    /// Access class. Missing ⇒ the caller should use
    /// [`AccessClass::default_to_tightest`].
    pub class: AccessClass,
    /// Dissemination caveats, in canonical markings
    /// (`NO-THIRD-PARTY` | `ORCON` | `REL-<role>`).
    #[serde(default)]
    pub caveats: Vec<String>,
    /// Active embargo window vetoes every export.
    #[serde(default)]
    pub embargo_active: bool,
    /// Ancestors, tightest-first is not required; any entry tighter than
    /// `class` is a downgrade.
    #[serde(default)]
    pub lineage: Vec<LineageEntry>,
}

/// The crossing being requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    /// Who receives the release.
    pub audience: Audience,
    /// Which boundary it crosses, as the wire token. Deliberately a `String`:
    /// an unrecognised token must reach [`gate`] and be refused with
    /// `deny.channel-unknown` — not fail deserialization with an untyped serde
    /// error, which would leave the operator without a stable refusal code.
    pub channel: String,
    /// The role the release is made *for*, unlocking `REL-<role>`.
    #[serde(default)]
    pub role: Option<String>,
    /// The originator's explicit approval, unlocking `ORCON`.
    #[serde(default)]
    pub originator_approved: bool,
    /// Redaction rules attached to the release (counted, not applied here).
    #[serde(default)]
    pub redaction_rules: Vec<RedactionRef>,
    /// Attestation that the material was sanitised before reaching the pipe.
    #[serde(default)]
    pub presanitized: bool,
    /// `false` declares a return path; refused on a one-way channel.
    #[serde(default = "default_true")]
    pub egress_only: bool,
    /// Overrides [`DEFAULT_PAYLOAD_CAP_BITS`] for a non-bulk channel.
    #[serde(default)]
    pub payload_cap_bits: Option<u64>,
    /// Required by [`TransferChannel::Compelled`].
    #[serde(default)]
    pub warrant_ref: Option<String>,
    /// Required by [`TransferChannel::Endpoint`].
    #[serde(default)]
    pub staging_manifest: Option<String>,
    /// Required by [`TransferChannel::Physical`].
    #[serde(default)]
    pub media_hash: Option<String>,
    /// Required by [`TransferChannel::Coalition`].
    #[serde(default)]
    pub marking_emitted: bool,
}

/// A redaction rule reference. The gate counts these; applying them is
/// [`crate::redaction`]'s job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionRef {
    /// Field name the rule targets.
    pub field: String,
    /// Redaction mode. The gate does not interpret it — it counts rules — but
    /// the plan schema carries it, so it must parse. Rejecting it would make a
    /// plan written to the documented schema unloadable.
    #[serde(default)]
    pub mode: Option<String>,
}

fn default_true() -> bool {
    true
}

/// A complete release plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePlan {
    /// The artifact.
    pub artifact: Artifact,
    /// Its provenance.
    pub provenance: Provenance,
    /// The requested crossing.
    pub release: ReleaseRequest,
    /// **[R5] The predecessor this release continues from, when it opens a new segment.**
    ///
    /// Set to the `close_entry_hash` a `rotate` reported. This lives in the PLAN rather than behind a CLI
    /// flag, and that is a correction rather than a preference: `receipt_payload` is recomputed at verify
    /// time from the plan, so a flag carrying it would make a legitimate continuation receipt fail to
    /// reconstruct — and a failed reconstruction is indistinguishable from tampering.
    ///
    /// Absent is the common case and adds no bytes to the canonical payload, which is why existing plans,
    /// the golden log and the 31 vectors are unaffected.
    #[serde(default)]
    pub continues: Option<String>,
}

// ── The verdict ──────────────────────────────────────────────────────────────

/// The decision.
///
/// Serializes as `"ALLOW"` / `"DENY"` — the documented verdict schema uses those
/// tokens, so the wire form and [`Decision::as_str`] are one token space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    /// The release may proceed.
    Allow,
    /// It may not; [`Verdict::code`] says why.
    Deny,
}

/// Which stage produced a refusal. Stable tokens so audit tooling never parses
/// message text.
///
/// Each variant's wire token **is** its [`Stage::as_str`] token; a test pins
/// that, so the JSON and the human line can never diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stage {
    /// Stage 0 — plan validity and lineage.
    #[serde(rename = "0.plan")]
    Plan,
    /// Stage 1 — channel admission.
    #[serde(rename = "1.channel")]
    Channel,
    /// Stage 2 — channel obligations.
    #[serde(rename = "2.obligation")]
    Obligation,
    /// Stage 3 — the access-class gate.
    #[serde(rename = "3.class")]
    Class,
    /// Stage 4 — the caveat gate.
    #[serde(rename = "4.caveat")]
    Caveat,
    /// Stage 5 — release and receipt.
    #[serde(rename = "5.receipt")]
    Receipt,
}

impl Stage {
    /// The frozen evaluation order. A trace walks this; it must not be
    /// re-ordered independently of [`gate`].
    pub const ORDER: [Stage; 6] = [
        Stage::Plan,
        Stage::Channel,
        Stage::Obligation,
        Stage::Class,
        Stage::Caveat,
        Stage::Receipt,
    ];

    /// Position in [`Stage::ORDER`]. [`gate`] short-circuits, so every stage
    /// with a lower index necessarily *passed* when this one decided.
    pub fn index(&self) -> usize {
        match self {
            Stage::Plan => 0,
            Stage::Channel => 1,
            Stage::Obligation => 2,
            Stage::Class => 3,
            Stage::Caveat => 4,
            Stage::Receipt => 5,
        }
    }

    /// Human label for a stage trace.
    pub fn label(&self) -> &'static str {
        match self {
            Stage::Plan => "plan + lineage",
            Stage::Channel => "channel admission",
            Stage::Obligation => "channel obligations",
            Stage::Class => "access-class gate",
            Stage::Caveat => "caveat gate",
            Stage::Receipt => "release + receipt",
        }
    }

    /// Stable machine token.
    pub fn as_str(&self) -> &'static str {
        match self {
            Stage::Plan => "0.plan",
            Stage::Channel => "1.channel",
            Stage::Obligation => "2.obligation",
            Stage::Class => "3.class",
            Stage::Caveat => "4.caveat",
            Stage::Receipt => "5.receipt",
        }
    }
}

/// One gate outcome: the decision, a stable code, the stage that produced it,
/// a human sentence, the summary marking, and (on allow) the receipt hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// Allow or deny.
    pub decision: Decision,
    /// Stable machine code; the automation surface.
    pub code: String,
    /// The stage that decided.
    pub stage: Stage,
    /// Human sentence. Never localized, never parsed.
    pub detail: String,
    /// [`summary_marking`] of the release's caveats.
    pub marking: String,
    /// Receipt hash, `None` on a refusal.
    pub receipt_hash: Option<String>,
}

impl Decision {
    /// `ALLOW` / `DENY`, the tokens the verdict schema uses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
        }
    }
}

impl Verdict {
    fn deny(code: &'static str, stage: Stage, detail: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            code: code.to_string(),
            stage,
            detail: detail.into(),
            marking: "NONE".to_string(),
            receipt_hash: None,
        }
    }

    /// `true` when the release may proceed.
    pub fn is_allow(&self) -> bool {
        self.decision == Decision::Allow
    }
}

// ── Canonical caveat markings ────────────────────────────────────────────────

const CODE_NO_THIRD_PARTY: &str = "NO-THIRD-PARTY";
const CODE_ORCON: &str = "ORCON";
const REL_PREFIX: &str = "REL-";

/// Parse a canonical summary marking into a typed [`Caveat`].
///
/// Accepts exactly `NO-THIRD-PARTY`, `ORCON`, and `REL-<role>` (a bare `REL-`
/// carries an empty role, which [`release_check`] then refuses for every
/// non-operator audience). Anything else returns `None` — the caller refuses
/// with `deny.caveat-unparseable` rather than dropping the restriction.
pub fn parse_caveat_marking(raw: &str) -> Option<Caveat> {
    let s = raw.trim();
    if s == CODE_NO_THIRD_PARTY {
        return Some(Caveat::NoThirdParty);
    }
    if s == CODE_ORCON {
        return Some(Caveat::OriginatorControlled);
    }
    if let Some(role) = s.strip_prefix(REL_PREFIX) {
        return Some(Caveat::RoleReleasable {
            role: role.to_string(),
        });
    }
    None
}

// ── Receipt hashing ──────────────────────────────────────────────────────────

/// The plan's caveats as parsed values, refusing on a non-canonical code (C-2).
///
/// This is the single source of the marking that BOTH the verdict and the committed payload
/// render. Before F.23 the payload rendered `summary_marking(&[])` — a hardcoded `NONE` — so a
/// caveated release committed a payload that understated its handling caveats while the verdict
/// reported the truth, and verification could not see the difference because it recomputed the
/// same wrong canonical. A non-canonical code is a refusal here, never an ignore: silently
/// dropping it would produce exactly the same defect from the other direction.
pub fn parsed_caveats(plan: &ReleasePlan) -> Result<Vec<Caveat>, DraftError> {
    plan.provenance
        .caveats
        .iter()
        .map(|raw| {
            parse_caveat_marking(raw).ok_or_else(|| {
                DraftError::Denied(Verdict::deny(
                    "deny.caveat-unparseable",
                    Stage::Caveat,
                    format!(
                        "non-canonical caveat '{raw}' - refusing rather than committing a \
                         marking that omits it"
                    ),
                ))
            })
        })
        .collect()
}

/// Canonical JSON of the committed payload: keys lexicographic, no whitespace.
/// Mirrors [`crate::ledger_events::canonical_bytes`]'s rule.
pub fn canonical_payload(plan: &ReleasePlan, caveats: &[Caveat]) -> String {
    let payload = serde_json::json!({
        "actor": "sluice",
        "artifact_sha256": plan.artifact.sha256,
        "audience": plan.release.audience.as_str(),
        "channel": plan.release.channel.as_str(),
        "class": plan.provenance.class.as_str(),
        "decision": "ALLOW",
        "marking": summary_marking(caveats),
        "origin": plan.provenance.origin,
        "redactions": plan.release.redaction_rules.len(),
    });
    let mut payload = payload;
    // [R5] Included ONLY when present, so a plan without a predecessor yields the same canonical bytes it
    // always did — which keeps the golden-log fence and the 31 vectors honest across this change.
    if let Some(c) = plan.continues.as_deref() {
        payload
            .as_object_mut()
            .expect("payload is an object")
            .insert(
                String::from("continues"),
                serde_json::Value::String(c.to_string()),
            );
    }
    // serde_json's Value map is BTreeMap by default (no preserve_order feature
    // dependence here) — sort explicitly so the rule does not ride a feature.
    let mut keys: Vec<&String> = payload
        .as_object()
        .expect("payload is an object")
        .keys()
        .collect();
    keys.sort();
    let mut out = String::from("{");
    for (i, k) in keys.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(k).expect("key encodes"));
        out.push(':');
        out.push_str(&serde_json::to_string(&payload[k]).expect("value encodes"));
    }
    out.push('}');
    out
}

/// `hex(sha256(prev_utf8 || 0x1F || canonical))` — the chain rule shared with
/// [`crate::ledger_events`].
pub fn receipt_hash(canonical: &str, prev_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update([UNIT_SEP]);
    h.update(canonical.as_bytes());
    format!("{:x}", h.finalize())
}

// ── S6–S8: the write half — release composition, and from-disk verification ──

/// Lowercase hex sha256 of `bytes`.
///
/// Separate from [`receipt_hash`] on purpose: that one is a *chain* rule over a
/// text preimage, this one is a plain file digest. Conflating them is how a
/// receipt ends up bound to something other than the bytes it names.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Why composing a release produced no derivative.
///
/// The variants are distinct because the exit contract distinguishes them: a
/// **decision** refusal carries a code from the closed set, an **I/O** failure
/// carries none (R-CLI-12). Collapsing the two would let automation treat
/// "the disk was full" as "the boundary refused".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DraftError {
    /// The gate refused the plan. The verdict rides along with its code.
    Denied(Verdict),
    /// The bytes at the artifact path do not hash to the plan's claim. Carries a
    /// code: it is a decision *about the material*, not an infrastructure fault.
    ArtifactMismatch { claimed: String, actual: String },
    /// The world failed — unreadable artifact, unwritable output, refused log.
    Io(String),
}

impl DraftError {
    /// `Some(code)` for a decision, `None` for an infrastructure failure.
    pub fn code(&self) -> Option<&str> {
        match self {
            DraftError::Denied(v) => Some(v.code.as_str()),
            DraftError::ArtifactMismatch { .. } => Some("deny.artifact-mismatch"),
            DraftError::Io(_) => None,
        }
    }

    /// The verdict this error *is*, when it is a boundary refusal rather than an
    /// infrastructure failure. `deny.artifact-mismatch` is raised by the release path, not by
    /// [`gate`], so it is not a `Denied` variant — but it is a refusal with a code, and a coded
    /// refusal must reach the same machine-readable rendering as every other deny: otherwise the one
    /// code only `release` can emit exists as a text line, and a caller cannot tell the boundary
    /// refusing from a full disk. The criterion is exactly [`DraftError::code`]: `None` means there is
    /// no verdict to render (R-CLI-12 reserves the no-code exit for infrastructure).
    pub fn verdict(&self) -> Option<Verdict> {
        match self {
            DraftError::Denied(v) => Some(v.clone()),
            DraftError::ArtifactMismatch { claimed, actual } => Some(Verdict::deny(
                "deny.artifact-mismatch",
                Stage::Receipt,
                format!("the plan claims {claimed}, the bytes hash to {actual}"),
            )),
            DraftError::Io(_) => None,
        }
    }
}

impl std::fmt::Display for DraftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DraftError::Denied(v) => write!(f, "{} {} — {}", v.decision.as_str(), v.code, v.detail),
            DraftError::ArtifactMismatch { claimed, actual } => write!(
                f,
                "deny.artifact-mismatch — the plan claims {claimed}, the bytes hash to {actual}"
            ),
            DraftError::Io(m) => write!(f, "{m}"),
        }
    }
}

/// Where a receipt's timestamp came from. R-CLI-9: `--now-ms` makes a receipt
/// reproducible, and **the receipt records which** — otherwise a reproducible
/// run and a live one are indistinguishable after the fact, and the moment a
/// receipt stops being replayable can never be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClockSource {
    /// Supplied via `--now-ms`: the receipt is reproducible from its inputs.
    Supplied,
    /// Read from the system clock: the receipt is live and unique to this run.
    System,
}

impl ClockSource {
    /// Stable token for audit lines and tables.
    pub fn as_str(&self) -> &'static str {
        match self {
            ClockSource::Supplied => "supplied",
            ClockSource::System => "system",
        }
    }
}

/// A composed release: what was written, and the evidence for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Released {
    /// Always [`Decision::Allow`] — a release exists only when the gate allowed
    /// it. Carried so that **one** consumer schema can read the output of
    /// `check` and `release` alike (R-CLI-6), rather than needing two shapes for
    /// the same field.
    pub decision: Decision,
    /// [`summary_marking`] of the release's caveats, as the gate rendered it.
    pub marking: String,
    /// The canonical payload the receipt commits to.
    pub canonical: String,
    /// `receipt_hash(canonical, prev_hash)` — this crate's chain convention.
    pub receipt_hash: String,
    /// The chain head the receipt chained onto ([`GENESIS`] with no log).
    pub prev_hash: String,
    /// Where the derivative was written.
    pub derivative_path: String,
    /// sha256 of the derivative **as re-read from disk**, never of the buffer.
    pub derivative_sha256: String,
    /// KT log position, when a log was supplied.
    pub kt_seq: Option<u64>,
    /// KT chain hash of the appended entry, when a log was supplied.
    pub kt_entry_hash: Option<String>,
    /// The timestamp written on the receipt entry. `None` when no log was given:
    /// there is then no receipt to timestamp, and reporting a value nothing
    /// recorded would be a false record rather than a missing one. R-CLI-9.
    pub receipt_timestamp: Option<u64>,
    /// Where that timestamp came from — `Some(Supplied)` for a reproducible
    /// `--now-ms` receipt, `Some(System)` for a live one, `None` with no log.
    /// The pairing with `receipt_timestamp` is what makes R-CLI-9 checkable
    /// after the fact instead of merely asserted at write time.
    pub receipt_clock: Option<ClockSource>,
}

/// The exact JSON value appended to the KT log for one decision.
///
/// Reconstructible from the plan **alone**, and that is the whole point. The log
/// stores only `payload_hash`, so verification recomputes this value from the
/// plan, serializes it identically, and compares hashes — nothing has to be
/// stored beside the log, and nothing is trusted from memory.
pub fn receipt_payload(plan: &ReleasePlan, caveats: &[Caveat]) -> serde_json::Value {
    serde_json::json!({
        "actor": "sluice",
        "decision": "ALLOW",
        "canonical": canonical_payload(plan, caveats),
    })
}

/// Compose the release. **This one opens the artifact.**
///
/// [`Artifact::path`] is documented "never opened by this module". That is true
/// of the pure gate and deliberately false here: the write half must release the
/// bytes that are on disk, not the digest the plan asserts about them.
///
/// Order, fail-closed at every step:
///
/// 1. `gate(plan)` first, so a refusal writes nothing and reads nothing beyond
///    the plan itself.
/// 2. Read the artifact and hash **those** bytes. A mismatch is
///    `deny.artifact-mismatch` — a receipt for the wrong bytes is worse than no
///    receipt, because it launders a decision about something else.
/// 3. Append the receipt entry to the KT log, chaining onto its current head, so
///    the receipt is bound to the log state it was made against. The evidence is
///    written **before** the material: if the derivative cannot be written, the
///    record of the attempt still exists and can be reconciled.
/// 4. Write the derivative byte-identical into `out_dir` and re-read it, so the
///    digest reported is the digest of the file rather than of a buffer that may
///    never have reached the disk.
pub fn release(
    plan: &ReleasePlan,
    out_dir: &Path,
    kt_log: Option<&Path>,
    now_ms: Option<u64>,
) -> Result<Released, DraftError> {
    // 1. The decision.
    let verdict = gate(plan);
    if !verdict.is_allow() {
        return Err(DraftError::Denied(verdict));
    }

    // 2. The bytes, not the claim.
    let bytes = std::fs::read(&plan.artifact.path).map_err(|e| {
        DraftError::Io(format!(
            "cannot read artifact '{}': {e}",
            plan.artifact.path
        ))
    })?;
    let actual = sha256_hex(&bytes);
    if actual != plan.artifact.sha256 {
        return Err(DraftError::ArtifactMismatch {
            claimed: plan.artifact.sha256.clone(),
            actual,
        });
    }

    // 3. Evidence before material. The caveats are parsed fail-closed here so the marking the
    //    receipt commits is computed once, from the same values the verdict rendered (F.23).
    let caveats = parsed_caveats(plan)?;
    let canonical = canonical_payload(plan, &caveats);
    let mut prev_hash = GENESIS.to_string();
    let mut kt_seq = None;
    let mut kt_entry_hash = None;
    let mut receipt_timestamp = None;
    let mut receipt_clock = None;
    if let Some(log_path) = kt_log {
        // R-CLI-10 keeps us writing only to --out and the --kt-log path, and the lock is the log's
        // own inode for that reason. Held for the whole window below: open, read the head, append.
        let _writer = ReceiptLogLock::acquire(log_path)?;
        let mut log = KtLog::open(log_path)
            .map_err(|e| DraftError::Io(format!("cannot open the KT log: {e}")))?;
        prev_hash = log.head_hash();
        let line = serde_json::to_vec(&receipt_payload(plan, &caveats))
            .map_err(|e| DraftError::Io(format!("cannot encode the receipt: {e}")))?;
        // R-CLI-9: record WHICH clock produced the timestamp, not only its
        // value — a supplied timestamp is what makes the receipt replayable.
        let (ts, clock) = match now_ms {
            Some(ms) => (ms, ClockSource::Supplied),
            None => (now_millis(), ClockSource::System),
        };
        let entry = log
            .append_at(&line, ts)
            .map_err(|e| DraftError::Io(format!("cannot append the receipt: {e}")))?;
        kt_seq = Some(entry.seq);
        kt_entry_hash = Some(entry.entry_hash.clone());
        receipt_timestamp = Some(ts);
        receipt_clock = Some(clock);
    }
    let receipt = receipt_hash(&canonical, &prev_hash);

    // 4. The material.
    std::fs::create_dir_all(out_dir)
        .map_err(|e| DraftError::Io(format!("cannot create {}: {e}", out_dir.display())))?;
    let name = Path::new(&plan.artifact.path)
        .file_name()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| std::ffi::OsString::from("derivative"));
    let dest = out_dir.join(name);
    std::fs::write(&dest, &bytes)
        .map_err(|e| DraftError::Io(format!("cannot write {}: {e}", dest.display())))?;
    let written = std::fs::read(&dest)
        .map_err(|e| DraftError::Io(format!("cannot re-read {}: {e}", dest.display())))?;

    // `verdict` was computed at the top and accepted; reuse it rather than
    // re-deciding, so `Released.marking` is provably the gate's own rendering.
    Ok(Released {
        decision: verdict.decision,
        marking: verdict.marking,
        canonical,
        receipt_hash: receipt,
        prev_hash,
        derivative_path: dest.display().to_string(),
        derivative_sha256: sha256_hex(&written),
        kt_seq,
        kt_entry_hash,
        receipt_timestamp,
        receipt_clock,
    })
}
/// The segment-closing payload — A1's only new payload kind.
///
/// [R4] Its bytes are built here and hashed into the log entry like any other payload, and the log stores
/// ONLY that hash (`kt_log`'s entry has no payload field). So these bytes exist nowhere in the log: the
/// operator's record is the only place they can live, and `verify --segment-close` is given them back to
/// check `payload_hash(payload) == <entry>.payload_hash`. Nothing about a segment is self-described by
/// the log, which is why the record is required input to verification rather than an audit trail.
pub fn segment_close_payload(
    segment: u64,
    entries: usize,
    last_receipt_hash: &str,
    reason: &str,
    prev_segment_close: Option<&str>,
) -> String {
    let v = serde_json::json!({
        "kind": "segment-close",
        "segment": segment,
        "entries": entries,
        "last_receipt_hash": last_receipt_hash,
        "reason": reason,
        "prev_segment_close": prev_segment_close,
    });
    v.to_string()
}

/// What a record-side check of a closing entry concluded.
#[derive(Debug, serde::Serialize)]
pub struct SegmentCloseCheck {
    pub segment: u64,
    pub entries: usize,
    pub last_receipt_hash: String,
    /// The predecessor the record declares, if any — and what the plan must agree with (§3 of the join).
    pub predecessor: Option<String>,
}

/// Check a closing entry against the record that carries its payload — A1's "[R4]" half.
///
/// The log stores only `payload_hash(payload)`; the bytes live in the operator's record. So this is the
/// only place the two can be brought together, and it is why the record is required input to
/// verification rather than an audit trail. Two distinct things are checked, and both are needed:
///
/// 1. **The bytes are the ones the log hashed** — `payload_hash(payload) == <last entry>.payload_hash`.
///    This is what ties this record line to this log; without it any payload would do.
/// 2. **The fields describe the segment it claims to close** — the declared `entries` must be the number
///    of receipts before the closing entry, and the declared `last_receipt_hash` must be the entry hash
///    of the last receipt. A payload that hashes correctly but declares the wrong segment is a
///    self-consistent lie, and only this second comparison catches it.
pub fn verify_segment_close(
    kt_log: &std::path::Path,
    payload: &str,
    plan_continues: Option<&str>,
) -> Result<SegmentCloseCheck, DraftError> {
    // READ-ONLY: this path only reads the chain. `KtLog::open` is the WRITE path
    // (create + append + 0600 tightening), so a read-only account — the anchor, verifying the head
    // it is about to record — could never verify with it. See `KtLog::open_read_only`.
    let log = KtLog::open_read_only(kt_log)
        .map_err(|e| DraftError::Io(format!("cannot open the KT log: {e}")))?;
    let count = log.len();
    if count == 0 {
        return Err(DraftError::Io(String::from(
            "verify --segment-close: the log has no entries, so nothing closed it",
        )));
    }
    let last_hash = log.entries()[count - 1].payload_hash.clone();

    let stored_payload_hash = payload_hash(payload.as_bytes());
    if stored_payload_hash != last_hash {
        return Err(DraftError::Io(format!(
            "verify --segment-close: the record's payload hashes to {stored_payload_hash}, but the log's \
             last entry stores {last_hash} — this payload is not the one that entry committed to"
        )));
    }

    let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| {
        DraftError::Io(format!(
            "verify --segment-close: the payload is not valid JSON ({e}) — pass the bytes `rotate` \
             printed, verbatim"
        ))
    })?;
    let segment = v.get("segment").and_then(|x| x.as_u64()).ok_or_else(|| {
        DraftError::Io(String::from(
            "verify --segment-close: the payload has no `segment`",
        ))
    })?;
    let declared_entries = v.get("entries").and_then(|x| x.as_u64()).ok_or_else(|| {
        DraftError::Io(String::from(
            "verify --segment-close: the payload has no `entries`",
        ))
    })?;
    let declared_tip = v
        .get("last_receipt_hash")
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            DraftError::Io(String::from(
                "verify --segment-close: the payload has no `last_receipt_hash`",
            ))
        })?
        .to_string();

    // The closing entry is itself the last entry, so the receipts it closed are the ones before it.
    if declared_entries as usize != count - 1 {
        return Err(DraftError::Io(format!(
            "verify --segment-close: the record says this segment closed at {declared_entries} \
             receipt(s), but the log holds {} before the closing entry",
            count - 1
        )));
    }
    let actual_tip = log.entries()[count - 2].entry_hash.clone();
    if actual_tip != declared_tip {
        return Err(DraftError::Io(format!(
            "verify --segment-close: the record says the segment ended at {declared_tip}, but the last \
             receipt before the closing entry is {actual_tip}"
        )));
    }

    // 3. **THE JOIN.** The record says whether this segment continues an earlier one, in
    //    `prev_segment_close`; the plan says the same thing from the other side, in `continues`. The two
    //    declarations must agree — including both being absent — and this is the one thing the record buys
    //    beyond tail-loss detection. A1 §3's re-rooted-at-`GENESIS` class is invisible in the file alone,
    //    and a file that declares no predecessor while the record says it has one is a refusal.
    let declared_prev = v
        .get("prev_segment_close")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    match (declared_prev.as_deref(), plan_continues) {
        (None, None) => {}
        (Some(rec), Some(p)) if rec == p => {}
        (Some(rec), Some(p)) => {
            return Err(DraftError::Io(format!(
                "verify --segment-close: the record says this segment continues {rec}, but the plan \
                 declares {p} — the two declarations disagree"
            )));
        }
        (Some(rec), None) => {
            return Err(DraftError::Io(format!(
                "verify --segment-close: the record says this segment continues {rec}, but no plan that \
                 declares it was given — this is the re-rooted case the record exists to catch"
            )));
        }
        (None, Some(p)) => {
            return Err(DraftError::Io(format!(
                "verify --segment-close: the plan declares it continues {p}, but the record's closing \
                 payload declares no predecessor — the record does not corroborate the continuation"
            )));
        }
    }

    Ok(SegmentCloseCheck {
        segment,
        entries: declared_entries as usize,
        predecessor: declared_prev,
        last_receipt_hash: declared_tip,
    })
}

/// What a rotation reports to the operator — everything the record needs, including the payload verbatim.
#[derive(Debug, serde::Serialize)]
pub struct Rotated {
    pub segment: u64,
    pub entries: usize,
    pub last_receipt_hash: String,
    pub close_entry_hash: String,
    pub close_payload: String,
}

/// Rotate a receipt log: append the segment-closing entry, and report what the record must carry.
///
/// `expect_tip` is REQUIRED and validated exactly as `verify --expect-tip` validates its anchor. It is not
/// ceremony: with no in-band marker in the log there is no way for the writer to tell an already-closed
/// segment from an open one, so a second `rotate` would silently append a second closing entry and
/// nothing in the file could say which came first. Requiring the caller to state the current head makes
/// that mistake refuse, naming both hashes, exactly as a stale anchor does.
pub fn rotate(
    kt_log: &std::path::Path,
    expect_tip: Option<&str>,
    reason: &str,
    segment: u64,
    prev_segment_close: Option<&str>,
) -> Result<Rotated, DraftError> {
    let tip = expect_tip.ok_or_else(|| {
        DraftError::Io(String::from(
            "rotate needs --expect-tip <hash>: the head you believe this segment ended at",
        ))
    })?;
    if tip.len() != 64 || !tip.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(DraftError::Io(format!(
            "rotate: --expect-tip must be exactly 64 lowercase hex, got {tip:?}"
        )));
    }

    // Same exclusion as `release`: the lock is the log's own inode (R-CLI-10 permits no third write
    // target), held across the whole read-head-then-append window.
    let _writer = ReceiptLogLock::acquire(kt_log)?;
    let mut log =
        KtLog::open(kt_log).map_err(|e| DraftError::Io(format!("cannot open the KT log: {e}")))?;
    if log.entries().is_empty() {
        return Err(DraftError::Io(String::from(
            "rotate: the log has no entries, so there is no segment to close",
        )));
    }
    let head = log.head_hash();
    if head != tip {
        return Err(DraftError::Io(format!(
            "rotate: the log's head is {head}, but --expect-tip says {tip} — refusing to close a segment \
             that is not the one you named"
        )));
    }

    let entries = log.len();
    let payload = segment_close_payload(segment, entries, &head, reason, prev_segment_close);
    let entry = log
        .append_at(payload.as_bytes(), now_millis())
        .map_err(|e| DraftError::Io(format!("cannot append the closing entry: {e}")))?;

    Ok(Rotated {
        segment,
        entries,
        last_receipt_hash: head,
        close_entry_hash: entry.entry_hash.clone(),
        close_payload: payload,
    })
}

/// What a from-disk verification found. Every field is recomputed; nothing is
/// carried over from the process that wrote the release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verified {
    /// Entries in the log, re-parsed from disk.
    pub entries: usize,
    /// The chain head, recomputed.
    pub tip_hash: String,
    /// The anchor this verification was checked against, when the caller supplied one.
    pub tip_anchor: Option<String>,
    /// Whether the recomputed head equalled the anchor. Always `Some(true)` when an anchor was
    /// supplied: a mismatch is a refusal, never a report, so it cannot appear in this field.
    pub tip_matches_anchor: Option<bool>,
    /// Position of the entry committing to this plan's recomputed payload.
    pub matched_seq: Option<u64>,
    /// That entry's chain hash.
    pub matched_entry_hash: Option<String>,
    /// `receipt_hash(canonical, matched_entry.prev_hash)` — the receipt the
    /// gate *would* have produced for this plan against this log.
    pub recomputed_receipt_hash: Option<String>,
    /// sha256 of the derivative file, recomputed from its bytes.
    pub derivative_sha256: Option<String>,
    /// Whether the derivative still matches the plan's claim.
    pub derivative_matches_plan: Option<bool>,
}

/// Re-read the receipt log from disk and recompute (S8, R-CLI-8).
///
/// `KtLog::open` re-parses every line and verifies the whole chain before it
/// hands back a handle, so an edited log cannot even be read. On top of that:
///
///   * given a plan, the receipt payload is recomputed **from the plan** and its
///     hash matched against the entries — that is what binds a decision to the
///     chain, and it needs nothing stored alongside the log;
///   * given a derivative, the file's sha256 is recomputed and compared to the
///     plan's claim, from the file and not from memory;
///   * given `--expect-tip`, the recomputed head is compared against that anchor —
///     the mechanism the spec's S8 calls for, since a chain cannot detect the loss
///     of its own tail.
pub fn verify(
    kt_log: &Path,
    plan: Option<&ReleasePlan>,
    derivative: Option<&Path>,
    expect_tip: Option<&str>,
) -> Result<Verified, String> {
    // THE ANCHOR IS VALIDATED BEFORE THE LOG IS TOUCHED. A value that cannot be a head (the shape
    // this product prints is 64 lowercase hex characters) must not be compared to one: reporting a
    // malformed anchor as "the chain ends somewhere else" would dress a typo up as tampering, which
    // is the worst possible failure for an evidence tool. Format first, then the comparison.
    if let Some(anchor) = expect_tip {
        let well_formed = anchor.len() == 64
            && anchor
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !well_formed {
            return Err(format!(
                "--expect-tip {anchor:?} is not a 64-character lowercase hex hash — an anchor that \
                 cannot be a head cannot be compared to one"
            ));
        }
    }
    // A MISSING LOG IS NOT AN EMPTY CHAIN. `KtLog::open` tolerates `NotFound` so that `release` can
    // start a chain; `verify` reads one BACK, and an absent audit trail must not read as a
    // successfully verified one. `check` sets the precedent for the same class — "a missing plan is
    // an error, not an empty default" — and C-2 is fail-closed everywhere. Before this check,
    // `verify --kt-log /nope.log` exited 0 with `entries: 0` and the genesis tip: a fail-open on
    // absence, which is the one failure a release gate may not have.
    if !kt_log.exists() {
        return Err(format!(
            "the KT log '{}' does not exist — there is no receipt chain to verify",
            kt_log.display()
        ));
    }
    // READ-ONLY: `verify` reads the receipt chain back and never appends. The write path required
    // write permission on the log — which the anchor account must never have (it would let the
    // anchor corrupt the very chain it attests). See `KtLog::open_read_only`.
    let log = KtLog::open_read_only(kt_log)
        .map_err(|e| format!("cannot open the KT log '{}': {e}", kt_log.display()))?;
    log.verify_chain()
        .map_err(|e| format!("the receipt chain does not verify: {e}"))?;

    // A HASH CHAIN CANNOT SEE THE LOSS OF ITS OWN TAIL. Cut a log on a line boundary and what is
    // left is a shorter chain that verifies perfectly — the entries all still commit to each other.
    // That is why the spec's S8 settles on "a truncated log is detected (tail truncation needs the
    // exported head)": the head has to come from somewhere the log does not control. This is that
    // anchor. Given one, a truncated or replaced tail stops being invisible; without one, the same
    // log still verifies and `Verified::tip_anchor` records that nothing external was checked.
    let tip = log.head_hash();
    if let Some(anchor) = expect_tip.filter(|a| *a != tip.as_str()) {
        return Err(format!(
            "the log's head is {tip}, but --expect-tip says {anchor} — the chain ends somewhere \
             other than where the anchor says it ends (a lost or replaced tail, which the chain on \
             its own cannot see)"
        ));
    }

    let mut matched_seq = None;
    let mut matched_entry_hash = None;
    let mut recomputed_receipt_hash = None;
    if let Some(plan) = plan {
        // The marking is part of what the chain commits, so re-deriving the caveats must
        // reproduce it exactly as release() computed it (F.23).
        let caveats = parsed_caveats(plan).map_err(|e| e.to_string())?;
        let canonical = canonical_payload(plan, &caveats);
        let line = serde_json::to_vec(&receipt_payload(plan, &caveats))
            .map_err(|e| format!("cannot encode the recomputed payload: {e}"))?;
        let want = payload_hash(&line);
        for entry in log.entries() {
            if entry.payload_hash == want {
                matched_seq = Some(entry.seq);
                matched_entry_hash = Some(entry.entry_hash.clone());
                recomputed_receipt_hash = Some(receipt_hash(&canonical, &entry.prev_hash));
                break;
            }
        }
    }

    let mut derivative_sha256 = None;
    let mut derivative_matches_plan = None;
    if let Some(path) = derivative {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read derivative '{}': {e}", path.display()))?;
        let actual = sha256_hex(&bytes);
        derivative_sha256 = Some(actual.clone());
        if let Some(plan) = plan {
            derivative_matches_plan = Some(actual == plan.artifact.sha256);
        }
    }

    Ok(Verified {
        entries: log.len(),
        tip_hash: tip,
        tip_anchor: expect_tip.map(str::to_string),
        tip_matches_anchor: expect_tip.map(|_| true),
        matched_seq,
        matched_entry_hash,
        recomputed_receipt_hash,
        derivative_sha256,
        derivative_matches_plan,
    })
}

// ── The gate ─────────────────────────────────────────────────────────────────

/// Evaluate one release plan. Pure; the first refusal wins.
/// Exactly 64 lowercase hex characters — the only form a hash may take on the wire.
fn is_hash64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn gate(plan: &ReleasePlan) -> Verdict {
    // [R5] A named predecessor must be well formed. Checked with the other plan-validity rules, so a
    // malformed value never reaches a receipt or an append.
    if let Some(c) = plan.continues.as_deref()
        && !is_hash64(c)
    {
        return Verdict::deny(
            "deny.plan-invalid",
            Stage::Plan,
            format!("the plan names a predecessor {c:?} that is not 64 lowercase hex"),
        );
    }
    // Stage 1 — plan validity and lineage.
    if plan.artifact.sha256.len() != 64
        || !plan
            .artifact
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Verdict::deny(
            "deny.plan-invalid",
            Stage::Plan,
            "artifact.sha256 is not a 64-character lowercase hex digest",
        );
    }
    for anc in &plan.provenance.lineage {
        if anc.class > plan.provenance.class {
            return Verdict::deny(
                "deny.lineage-downgrade",
                Stage::Plan,
                format!(
                    "declared class {} is looser than ancestor class {} — explicit \
                     downgrade review required",
                    plan.provenance.class.as_str(),
                    anc.class.as_str()
                ),
            );
        }
    }

    // Stage 2 — channel admission. The token is parsed here rather than at
    // deserialization so that an unknown channel is a refusal with a code.
    let channel = match TransferChannel::parse(&plan.release.channel) {
        Some(c) => c,
        None => {
            return Verdict::deny(
                "deny.channel-unknown",
                Stage::Channel,
                format!(
                    "{:?} is not a known channel archetype ({})",
                    plan.release.channel,
                    TransferChannel::ALL
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
    };

    // Stage 3 — channel obligations, before the class gate by design.
    if let Some(v) = channel_obligations(plan, channel) {
        return v;
    }

    // Stage 4 — the access-class gate.
    if let Err(reason) = check_export(
        plan.provenance.class,
        plan.release.audience,
        plan.provenance.embargo_active,
    ) {
        return Verdict::deny(reason.code(), Stage::Class, reason.to_string());
    }

    // Stage 5 — the caveat gate.
    let mut caveats: Vec<Caveat> = Vec::with_capacity(plan.provenance.caveats.len());
    for raw in &plan.provenance.caveats {
        match parse_caveat_marking(raw) {
            Some(c) => caveats.push(c),
            None => {
                return Verdict::deny(
                    "deny.caveat-unparseable",
                    Stage::Caveat,
                    format!(
                        "caveat {raw:?} is not a canonical marking \
                         (NO-THIRD-PARTY | ORCON | REL-<role>)"
                    ),
                );
            }
        }
    }
    if let Err(err) = release_check(
        &caveats,
        plan.release.audience,
        plan.release.role.as_deref(),
        plan.release.originator_approved,
    ) {
        return Verdict::deny(err.code(), Stage::Caveat, err.to_string());
    }

    // Stage 6 — release.
    let marking = summary_marking(&caveats);
    let hash = receipt_hash(&canonical_payload(plan, &caveats), GENESIS);
    Verdict {
        decision: Decision::Allow,
        code: "allow".to_string(),
        stage: Stage::Receipt,
        detail: format!(
            "released to {} over {}",
            plan.release.audience.as_str(),
            plan.release.channel.as_str()
        ),
        marking,
        receipt_hash: Some(hash),
    }
}

/// Stage 3. Channel admission and the archetype's control obligations.
fn channel_obligations(plan: &ReleasePlan, ch: TransferChannel) -> Option<Verdict> {
    let rel = &plan.release;

    if !ch.bulk_ok() {
        let cap = rel.payload_cap_bits.unwrap_or(DEFAULT_PAYLOAD_CAP_BITS) / 8;
        if plan.artifact.bytes > cap {
            return Some(Verdict::deny(
                "deny.channel-rate-class",
                Stage::Obligation,
                format!(
                    "channel {ch} is non-bulk (rate class); payload {} B exceeds the {cap} B cap",
                    plan.artifact.bytes
                ),
            ));
        }
    }

    if !ch.inspected() && !rel.presanitized && rel.redaction_rules.is_empty() {
        return Some(Verdict::deny(
            "deny.channel-uninspected-unsanitized",
            Stage::Obligation,
            format!(
                "channel {ch} does not inspect content; material must be attested \
                 pre-sanitised or carry redaction rules"
            ),
        ));
    }

    if ch.one_way() && !rel.egress_only {
        return Some(Verdict::deny(
            "deny.channel-directionality",
            Stage::Obligation,
            format!("channel {ch} is one-way enforced; the plan declares a return path"),
        ));
    }

    let missing = |what: &str| {
        Some(Verdict::deny(
            "deny.channel-obligation",
            Stage::Obligation,
            format!("channel {ch} requires {what}"),
        ))
    };
    if ch.requires().contains(&"warrant_ref") && rel.warrant_ref.as_deref().unwrap_or("").is_empty()
    {
        return missing("a warrant reference");
    }
    if ch.requires().contains(&"staging_manifest")
        && rel.staging_manifest.as_deref().unwrap_or("").is_empty()
    {
        return missing("a staging manifest");
    }
    if ch.requires().contains(&"media_hash") && rel.media_hash.as_deref().unwrap_or("").is_empty() {
        return missing("a media hash");
    }
    if ch.requires().contains(&"marking_emitted") && !rel.marking_emitted {
        return Some(Verdict::deny(
            "deny.channel-obligation",
            Stage::Obligation,
            format!("channel {ch} requires the summary marking to be emitted"),
        ));
    }
    None
}

/// Parse a plan from JSON — the entry point for anything read from disk.
///
/// A parse failure (unknown key, missing section, wrong type) is a refusal
/// carrying `deny.plan-invalid`, never a bare serde error: the operator always
/// gets a stable code. Semantic checks (digest shape, lineage) live in
/// [`gate`] and are deliberately *not* duplicated here.
pub fn parse_plan(json: &str) -> Result<ReleasePlan, Verdict> {
    serde_json::from_str::<ReleasePlan>(json).map_err(|e| {
        Verdict::deny(
            "deny.plan-invalid",
            Stage::Plan,
            format!("plan does not parse against the documented schema: {e}"),
        )
    })
}

/// Parse and decide in one call — the whole read-only path the CLI needs.
pub fn check_json(json: &str) -> Verdict {
    match parse_plan(json) {
        Ok(plan) => gate(&plan),
        Err(v) => v,
    }
}

/// Parse a channel token, refusing loudly rather than defaulting.
pub fn parse_channel(token: &str) -> Result<TransferChannel, Verdict> {
    TransferChannel::parse(token).ok_or_else(|| {
        Verdict::deny(
            "deny.channel-unknown",
            Stage::Channel,
            format!(
                "{token:?} is not a known channel archetype ({})",
                TransferChannel::ALL
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // BEGIN GENERATED CASES — regenerate with tools/gen_cases.py, do not hand-edit.
    #[rustfmt::skip] // generated table — keep one row per line
    const CASES: &[&str] = &[
        "P1|positive|Open|Public|||0|coalition|512|1|1||||1||0|1|ALLOW|allow|",
        "P2|positive|Research|Teammate|||0|physical|512|1|1||bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb||1||0|1|ALLOW|allow|",
        "P3|positive|Open|ThirdParty|REL-beta|beta|0|coalition|512|1|1||||1||0|1|ALLOW|allow|",
        "P4|positive|Open|Teammate|||0|endpoint|512|1|1|||m-7|1||0|1|ALLOW|allow|",
        "P5|positive|Open|Public|||0|bearer|512|1|0||||1||0|1|ALLOW|allow|",
        "P6|positive|Open|Public|||0|covert|2048|1|1||||1||0|1|ALLOW|allow|65536",
        "P7|positive|Open|Operator|NO-THIRD-PARTY;REL-alpha|alpha|0|coalition|512|1|1||||1||0|1|ALLOW|allow|",
        "N1|negative|Sealed|Public|||0|coalition|512|1|1||||1||0|1|DENY|deny.sealed|",
        "N2|negative|Restricted|Operator|||0|coalition|512|1|1||||1||0|1|DENY|deny.no-export-path|",
        "N3|negative|Research|Public|||0|coalition|512|1|1||||1||0|1|DENY|deny.audience-not-admitted|",
        "N4|negative|Open|Public|||0|coalition|512|1|1||||1||1|1|DENY|deny.embargo-active|",
        "N5|negative|Open|ThirdParty|NO-THIRD-PARTY||0|coalition|512|1|1||||1||0|1|DENY|deny.caveat|",
        "N6|negative|Open|Teammate|ORCON||0|coalition|512|1|1||||1||0|1|DENY|deny.caveat|",
        "N7|negative|Open|ThirdParty|REL-alpha|beta|0|coalition|512|1|1||||1||0|1|DENY|deny.caveat|",
        "N8|negative|Open|Public|need-to-know||0|coalition|512|1|1||||1||0|1|DENY|deny.caveat-unparseable|",
        "N9|negative|Open|Teammate|||0|covert|1048576|1|1||||1||0|1|DENY|deny.channel-rate-class|",
        "N10|negative|Open|Teammate|||0|endpoint|512|0|1|||m-1|1||0|1|DENY|deny.channel-uninspected-unsanitized|",
        "N11|negative|Open|Operator|||0|compelled|512|1|1||||1||0|1|DENY|deny.channel-obligation|",
        "N12|negative|Open|Teammate|||0|physical|512|1|1||||1||0|1|DENY|deny.channel-obligation|",
        "N13|negative|Open|Public|||0|carrier-pigeon|512|1|1||||1||0|1|DENY|deny.channel-unknown|",
        "N14|negative||Public|||0|coalition|512|1|1||||1||0|0|DENY|deny.plan-invalid|",
        "N15|negative|Open|Public|||0|coalition|512|1|1||||1|Sealed|0|1|DENY|deny.lineage-downgrade|",
        "N16|negative|Open|Public|||0|coalition|10|1|1||||1||0|0|DENY|deny.plan-invalid|",
        "N17|negative|Sealed|Public|||0|coalition|512|1|1||||1||1|1|DENY|deny.embargo-active|",
        "N18|negative|Open|Public|||0|coalition|512|1|1||||1|Research|0|1|DENY|deny.lineage-downgrade|",
        "A1|adversarial|Open|ThirdParty|NO-THIRD-PARTY||0|coalition|512|1|1||||1||0|1|DENY|deny.caveat|",
        "A2|adversarial|Open|Operator|ORCON||0|coalition|512|1|1||||1||0|1|DENY|deny.caveat|",
        "A3|adversarial|Open|Public|||0|coalition|512|1|1||||1||0|1|ALLOW|allow|",
        "A4|adversarial|Open|Teammate|||0|covert|512|1|1||||1||0|1|ALLOW|allow|",
        "A5|adversarial|Open|Teammate|||0|covert|513|1|1||||1||0|1|DENY|deny.channel-rate-class|",
        "A6|adversarial|Open|Teammate|||0|physical|512|1|0||bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb||1||0|1|DENY|deny.channel-directionality|",
    ];
    #[rustfmt::skip] // generated table — keep one row per line
    const PLANS: &[(&str, &str, &str, &str)] = &[
        ("P1", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "ALLOW", "allow"),
        ("P2", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Research\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-2\"},\"release\":{\"audience\":\"Teammate\",\"channel\":\"physical\",\"marking_emitted\":true,\"media_hash\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"presanitized\":true}}", "ALLOW", "allow"),
        ("P3", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[\"REL-beta\"],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-3\"},\"release\":{\"audience\":\"ThirdParty\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true,\"role\":\"beta\"}}", "ALLOW", "allow"),
        ("P4", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Teammate\",\"channel\":\"endpoint\",\"marking_emitted\":true,\"presanitized\":false,\"redaction_rules\":[{\"field\":\"ssn\",\"mode\":\"remove\"}],\"staging_manifest\":\"m-7\"}}", "ALLOW", "allow"),
        ("P5", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Public\",\"channel\":\"bearer\",\"egress_only\":false,\"marking_emitted\":true,\"presanitized\":true}}", "ALLOW", "allow"),
        ("P6", "{\"artifact\":{\"bytes\":2048,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Public\",\"channel\":\"covert\",\"marking_emitted\":true,\"payload_cap_bits\":65536,\"presanitized\":true}}", "ALLOW", "allow"),
        ("P7", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[\"NO-THIRD-PARTY\",\"REL-alpha\"],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-7\"},\"release\":{\"audience\":\"Operator\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true,\"role\":\"alpha\"}}", "ALLOW", "allow"),
        ("N1", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Sealed\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.sealed"),
        ("N2", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Restricted\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Operator\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.no-export-path"),
        ("N3", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Research\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.audience-not-admitted"),
        ("N4", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":true,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.embargo-active"),
        ("N5", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[\"NO-THIRD-PARTY\"],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"ThirdParty\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.caveat"),
        ("N6", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[\"ORCON\"],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Teammate\",\"channel\":\"coalition\",\"marking_emitted\":true,\"originator_approved\":false,\"presanitized\":true}}", "DENY", "deny.caveat"),
        ("N7", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[\"REL-alpha\"],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"ThirdParty\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true,\"role\":\"beta\"}}", "DENY", "deny.caveat"),
        ("N8", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[\"need-to-know\"],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.caveat-unparseable"),
        ("N9", "{\"artifact\":{\"bytes\":1048576,\"path\":\"/vault/x\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Teammate\",\"channel\":\"covert\",\"egress_only\":true,\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.channel-rate-class"),
        ("N10", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Teammate\",\"channel\":\"endpoint\",\"marking_emitted\":true,\"presanitized\":false,\"staging_manifest\":\"m-1\"}}", "DENY", "deny.channel-uninspected-unsanitized"),
        ("N11", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Operator\",\"channel\":\"compelled\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.channel-obligation"),
        ("N12", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Teammate\",\"channel\":\"physical\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.channel-obligation"),
        ("N13", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Public\",\"channel\":\"carrier-pigeon\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.channel-unknown"),
        ("N14", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.plan-invalid"),
        ("N15", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[{\"class\":\"Sealed\"}],\"origin\":\"c\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.lineage-downgrade"),
        ("N16", "{\"artifact\":{\"bytes\":10,\"path\":\"/vault/x\",\"sha256\":\"deadbeef\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.plan-invalid"),
        ("N17", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Sealed\",\"embargo_active\":true,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.embargo-active"),
        ("N18", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[{\"class\":\"Open\"},{\"class\":\"Research\"}],\"origin\":\"c\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.lineage-downgrade"),
        ("A1", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[\"NO-THIRD-PARTY\"],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"ThirdParty\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.caveat"),
        ("A2", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[\"ORCON\"],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Operator\",\"channel\":\"coalition\",\"marking_emitted\":true,\"originator_approved\":false,\"presanitized\":true}}", "DENY", "deny.caveat"),
        ("A3", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"c\"},\"release\":{\"audience\":\"Public\",\"channel\":\"coalition\",\"marking_emitted\":true,\"presanitized\":true}}", "ALLOW", "allow"),
        ("A4", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/x\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Teammate\",\"channel\":\"covert\",\"egress_only\":true,\"marking_emitted\":true,\"presanitized\":true}}", "ALLOW", "allow"),
        ("A5", "{\"artifact\":{\"bytes\":513,\"path\":\"/vault/x\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Teammate\",\"channel\":\"covert\",\"egress_only\":true,\"marking_emitted\":true,\"presanitized\":true}}", "DENY", "deny.channel-rate-class"),
        ("A6", "{\"artifact\":{\"bytes\":512,\"path\":\"/vault/artifact.json\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"provenance\":{\"caveats\":[],\"class\":\"Open\",\"embargo_active\":false,\"lineage\":[],\"origin\":\"collector-1\"},\"release\":{\"audience\":\"Teammate\",\"channel\":\"physical\",\"egress_only\":false,\"marking_emitted\":true,\"media_hash\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"presanitized\":true}}", "DENY", "deny.channel-directionality"),
    ];
    // END GENERATED CASES

    /// Field order, positional, `|`-joined:
    /// 0 id · 1 group · 2 class · 3 audience · 4 caveats(';') · 5 role ·
    /// 6 approved · 7 channel · 8 bytes · 9 sanitized · 10 egress_only ·
    /// 11 warrant · 12 media_hash · 13 staging · 14 marking_emitted ·
    /// 15 lineage_class (tightest ancestor) · 16 embargo · 17 plan_ok(1) ·
    /// 18 expect.decision · 19 expect.code · 20 payload_cap_bits (empty = default)
    fn plan_from_row(row: &str) -> (ReleasePlan, String, String) {
        let f: Vec<&str> = row.split('|').collect();
        assert_eq!(f.len(), 21, "row {row:?} has {} fields, want 21", f.len());
        let classes = [
            ("Open", AccessClass::Open),
            ("Research", AccessClass::Research),
            ("Restricted", AccessClass::Restricted),
            ("Sealed", AccessClass::Sealed),
        ];
        let audiences = [
            ("Public", Audience::Public),
            ("ThirdParty", Audience::ThirdParty),
            ("Teammate", Audience::Teammate),
            ("Operator", Audience::Operator),
        ];
        let class = classes
            .iter()
            .find(|(t, _)| *t == f[2])
            .map(|(_, c)| *c)
            .unwrap_or(AccessClass::Open);
        let audience = audiences
            .iter()
            .find(|(t, _)| *t == f[3])
            .map(|(_, a)| *a)
            .unwrap_or(Audience::Public);
        let lineage = if f[15].is_empty() {
            Vec::new()
        } else {
            vec![LineageEntry {
                class: classes
                    .iter()
                    .find(|(t, _)| *t == f[15])
                    .map(|(_, c)| *c)
                    .unwrap_or(AccessClass::Open),
            }]
        };
        let plan = ReleasePlan {
            artifact: Artifact {
                path: format!("/vault/{}.json", f[0]),
                sha256: "a".repeat(64),
                bytes: f[8].parse().expect("bytes"),
            },
            provenance: Provenance {
                origin: "collector-1".to_string(),
                class,
                caveats: if f[4].is_empty() {
                    Vec::new()
                } else {
                    f[4].split(';').map(str::to_string).collect()
                },
                embargo_active: f[16] == "1",
                lineage,
            },
            release: ReleaseRequest {
                audience,
                channel: f[7].to_string(),
                role: if f[5].is_empty() {
                    None
                } else {
                    Some(f[5].to_string())
                },
                originator_approved: f[6] == "1",
                redaction_rules: Vec::new(),
                presanitized: f[9] == "1",
                egress_only: f[10] == "1",
                payload_cap_bits: f[20].parse::<u64>().ok(),
                warrant_ref: non_empty(f[11]),
                staging_manifest: non_empty(f[13]),
                media_hash: non_empty(f[12]),
                marking_emitted: f[14] == "1",
            },
            continues: None,
        };
        (plan, f[18].to_string(), f[19].to_string())
    }

    fn non_empty(s: &str) -> Option<String> {
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    }

    #[test]
    fn battery_matches_the_reference_vectors() {
        // Rows the typed `ReleasePlan` cannot express (a structurally invalid
        // plan is not a plan). They are covered by the reference rung; pinning
        // the set here means a silently dropped vector fails this test.
        const UNREPRESENTABLE: &[&str] = &["N14", "N16"];

        let mut pass = 0usize;
        let mut failures: Vec<String> = Vec::new();
        let mut skipped: Vec<String> = Vec::new();
        for row in CASES {
            let f: Vec<&str> = row.split('|').collect();
            let id = f[0];
            if f[17] != "1" {
                skipped.push(id.to_string());
                continue;
            }
            let (plan, want_decision, want_code) = plan_from_row(row);
            let v = gate(&plan);
            let got = format!(
                "{}|{}",
                match v.decision {
                    Decision::Allow => "ALLOW",
                    Decision::Deny => "DENY",
                },
                v.code
            );
            if got == format!("{want_decision}|{want_code}") {
                pass += 1;
            } else {
                failures.push(format!(
                    "{id}: want {want_decision}|{want_code}, got {got} ({})",
                    v.detail
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "gate battery: {} passed, {} failed:\n{}",
            pass,
            failures.len(),
            failures.join("\n")
        );
        assert_eq!(
            skipped,
            UNREPRESENTABLE
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            "the set of structurally-unrepresentable vectors changed — reconcile \
             with tools/vectors.json before adjusting this pin"
        );
        println!(
            "sluice battery: {pass}/{} representable cases passed ({skipped:?} are \
             plan-structure cases covered by the reference rung only)",
            CASES.len()
        );
    }

    /// The generator keeps malformed-plan rows out of the typed table (they
    /// cannot be expressed as a valid `ReleasePlan`); this asserts the table
    /// therefore contains only expressible rows, so the battery's denominator
    /// is honest.
    fn caseless_plan_ok(row: &str) -> bool {
        let f: Vec<&str> = row.split('|').collect();
        !f[2].is_empty() && !f[3].is_empty() && !f[7].is_empty()
    }

    // ── Stage-order pins ────────────────────────────────────────────────────

    /// F.23 — RED before it was GREEN. The marking the receipt COMMITS must be the marking
    /// the verdict REPORTS. They diverged on every caveated release: `canonical_payload`
    /// rendered `summary_marking(&[])` — hardcoded to `NONE` — while the verdict rendered the
    /// plan's real marking. Verification could not see it, because it recomputed the same
    /// wrong canonical: an append-only, hash-chained record silently understated the handling
    /// caveats of the very material it existed to be evidence about.
    #[test]
    fn the_committed_payload_carries_the_real_marking() {
        let mut p = base();
        p.provenance.caveats = vec!["REL-beta".to_string()];
        p.release.audience = Audience::ThirdParty;
        p.release.role = Some("beta".to_string());

        let v = gate(&p);
        assert!(v.is_allow(), "P3's shape must stay releasable: {}", v.code);
        assert_eq!(
            v.marking, "REL-beta",
            "the verdict renders the plan's marking"
        );

        let caveats = parsed_caveats(&p).expect("canonical codes parse");
        let canon: serde_json::Value =
            serde_json::from_str(&canonical_payload(&p, &caveats)).expect("canonical is JSON");
        assert_eq!(
            canon["marking"].as_str(),
            Some(v.marking.as_str()),
            "the payload must not commit a marking the verdict did not report"
        );
    }

    fn base() -> ReleasePlan {
        ReleasePlan {
            artifact: Artifact {
                path: "/vault/a.json".to_string(),
                sha256: "a".repeat(64),
                bytes: 512,
            },
            provenance: Provenance {
                origin: "collector-1".to_string(),
                class: AccessClass::Open,
                caveats: Vec::new(),
                embargo_active: false,
                lineage: Vec::new(),
            },
            release: ReleaseRequest {
                audience: Audience::Public,
                channel: TransferChannel::Coalition.as_str().to_string(),
                role: None,
                originator_approved: false,
                redaction_rules: Vec::new(),
                presanitized: true,
                egress_only: true,
                payload_cap_bits: None,
                warrant_ref: None,
                staging_manifest: None,
                media_hash: None,
                marking_emitted: true,
            },
            continues: None,
        }
    }

    // ── S6/S7/S8: the write half ─────────────────────────────────────────────

    /// A unique scratch directory per test, under `std::env::temp_dir()` and
    /// shared with nothing, so these can run in parallel with the rest.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sluice-test-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    /// A plan whose artifact is a REAL 512-byte file this test just wrote, so
    /// `release` has something on disk to re-hash. `base()` already claims 512.
    fn plan_with_real_artifact(dir: &std::path::Path) -> (ReleasePlan, Vec<u8>) {
        let bytes = b"BC".repeat(256);
        let path = dir.join("a.json");
        std::fs::write(&path, &bytes).expect("write the artifact");
        let mut p = base();
        p.artifact.path = path.display().to_string();
        p.artifact.sha256 = sha256_hex(&bytes);
        assert_eq!(p.artifact.bytes, bytes.len() as u64);
        (p, bytes)
    }

    /// Grounded outside this implementation: `printf '' | sha256sum` and
    /// `printf 'abc' | sha256sum` — the same externally computed constants
    /// `src/enforcement.rs`'s tests use. A digest helper checked only against
    /// its own output proves nothing about its correctness.
    #[test]
    fn sha256_hex_matches_externally_computed_constants() {
        const SHA256_EMPTY: &str =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(sha256_hex(b""), SHA256_EMPTY);
        assert_eq!(sha256_hex(b"abc"), SHA256_ABC);
        // It must not be the *chain* rule: that one folds in a previous hash and
        // a 0x1F separator, so the two can never be interchangeable.
        assert_ne!(sha256_hex(b"abc"), receipt_hash("abc", ""));
        // And the file digest is length-independent of the preimage's format.
        assert_eq!(sha256_hex(&b"BC".repeat(256)).len(), 64);
    }

    /// The payload is a pure function of the plan, and `verify` rests entirely
    /// on `serde_json::to_vec` producing the SAME bytes from the same plan —
    /// that equality IS the binding between a decision and the chain.
    #[test]
    fn receipt_payload_is_deterministic_and_reconstructible() {
        let p = base();
        assert_eq!(
            serde_json::to_vec(&receipt_payload(&p, &[])).expect("encode"),
            serde_json::to_vec(&receipt_payload(&base(), &[])).expect("encode"),
            "two constructions of the same plan must serialize to identical bytes"
        );
        assert_eq!(
            receipt_payload(&p, &[])["decision"],
            Decision::Allow.as_str(),
            "the payload's decision must be the gate's own wire token, not a literal that can drift"
        );
        assert_eq!(
            receipt_payload(&p, &[])["canonical"],
            canonical_payload(&p, &[]),
            "the payload must commit to the canonical form the chain rule hashes"
        );
    }

    /// R-CLI-12 as a property: a decision refusal carries a code, an
    /// infrastructure failure carries none. Collapsing the two would let
    /// automation read "the disk was full" as "the boundary refused".
    #[test]
    fn draft_error_codes_separate_decisions_from_infrastructure() {
        let mut sealed = base();
        sealed.provenance.class = AccessClass::Sealed;
        let verdict = gate(&sealed);
        assert!(!verdict.is_allow());
        assert_eq!(
            DraftError::Denied(verdict.clone()).code(),
            Some(verdict.code.as_str())
        );
        assert_eq!(
            DraftError::ArtifactMismatch {
                claimed: "a".into(),
                actual: "b".into()
            }
            .code(),
            Some("deny.artifact-mismatch")
        );
        assert_eq!(
            DraftError::Io("no space left on device".into()).code(),
            None,
            "an infrastructure failure is not a verdict and must carry no code"
        );
    }

    /// A coded refusal must reach the renderer as a *verdict*, not as a text line. The criterion is
    /// `code()`: `deny.artifact-mismatch` is raised by the release path, so it is not a `Denied`
    /// variant — but it is still a refusal with a code, and before this it never reached JSON at all.
    #[test]
    fn a_coded_error_is_a_verdict_and_a_codeless_one_is_not() {
        let verdict = DraftError::ArtifactMismatch {
            claimed: "a".repeat(64),
            actual: "b".repeat(64),
        }
        .verdict()
        .expect("a coded refusal must have a verdict");
        assert_eq!(verdict.code, "deny.artifact-mismatch");
        assert_eq!(verdict.stage, Stage::Receipt);
        assert!(!verdict.is_allow());
        assert!(
            verdict.detail.contains(&"a".repeat(64)),
            "the verdict must carry what disagreed: {}",
            verdict.detail
        );
        assert!(
            DraftError::Io("no space left on device".into())
                .verdict()
                .is_none(),
            "an infrastructure failure has no verdict to render"
        );
    }

    /// A missing log is not an empty chain. `KtLog::open` tolerates `NotFound` so `release` can start
    /// a chain; `verify` reads one BACK, and an absent audit trail must not read as a verified one.
    /// Before this check, `verify --kt-log /nope.log` exited 0 with `entries: 0` and the genesis tip.
    #[test]
    fn verify_refuses_a_missing_log() {
        let dir = scratch("verify-missing");
        let absent = dir.join("never-written.jsonl");
        assert!(!absent.exists());
        let err =
            verify(&absent, None, None, None).expect_err("a missing log must not verify as empty");
        assert!(
            err.contains("does not exist") && err.contains("never-written.jsonl"),
            "the error must say which log is absent: {err}"
        );
    }

    /// Refusals precede composition: a refused plan never creates the output
    /// directory, and an unreadable artifact is IO rather than a verdict.
    #[test]
    fn release_refuses_before_it_writes_anything() {
        let dir = scratch("refuse");
        let out = dir.join("out");

        let mut sealed = base();
        sealed.provenance.class = AccessClass::Sealed;
        sealed.artifact.path = dir.join("never-read.json").display().to_string();
        match release(&sealed, &out, None, Some(0)) {
            Err(DraftError::Denied(v)) => assert_eq!(v.code, "deny.sealed"),
            other => panic!("the gate must decide first, got {other:?}"),
        }
        assert!(
            !out.exists(),
            "a refusal must not create the output directory"
        );

        let mut missing = base();
        missing.artifact.path = dir.join("absent.json").display().to_string();
        let out2 = dir.join("out2");
        match release(&missing, &out2, None, Some(0)) {
            Err(DraftError::Io(_)) => {}
            other => panic!("a missing artifact is infrastructure, got {other:?}"),
        }
        assert!(!out2.exists());
    }

    /// A plan whose claim does not match the bytes is refused with a decision
    /// code, and nothing is written. A receipt for the wrong bytes is worse
    /// than no receipt: it launders a decision about something else.
    #[test]
    fn release_refuses_an_artifact_that_does_not_match_the_plan() {
        let dir = scratch("mismatch");
        let (mut plan, bytes) = plan_with_real_artifact(&dir);
        plan.artifact.sha256 = "b".repeat(64);
        let out = dir.join("out");
        match release(&plan, &out, None, None) {
            Err(DraftError::ArtifactMismatch { claimed, actual }) => {
                assert_eq!(claimed, "b".repeat(64));
                assert_eq!(actual, sha256_hex(&bytes));
            }
            other => panic!("expected an artifact mismatch, got {other:?}"),
        }
        assert!(
            !out.exists(),
            "nothing may be written when the bytes do not match the claim"
        );
    }

    /// With no log there is nowhere to record a receipt, so the gate reports one
    /// onto its own genesis rather than inventing a chain.
    /// R-CLI-9's second clause, in both directions: `--now-ms` yields a receipt
    /// marked reproducible and the absence of it yields one marked live — with
    /// the timestamp actually recorded ON the entry either way, since a report
    /// that disagrees with the record would be worse than no report.
    #[test]
    fn the_receipt_records_which_clock_produced_it() {
        let dir = scratch("clock");
        let (plan, _) = plan_with_real_artifact(&dir);

        let supplied = release(&plan, &dir.join("s"), Some(&dir.join("s.ktlog")), Some(42))
            .expect("release with --now-ms");
        assert_eq!(supplied.receipt_clock, Some(ClockSource::Supplied));
        assert_eq!(supplied.receipt_timestamp, Some(42));
        let s_log = KtLog::open(dir.join("s.ktlog")).expect("open");
        assert_eq!(
            s_log.entries()[0].timestamp,
            42,
            "the supplied timestamp must be the one ON the entry, not merely in the report"
        );

        let live = release(&plan, &dir.join("l"), Some(&dir.join("l.ktlog")), None)
            .expect("release without --now-ms");
        assert_eq!(live.receipt_clock, Some(ClockSource::System));
        assert!(
            live.receipt_timestamp.is_some(),
            "a live clock is still recorded"
        );
        let l_log = KtLog::open(dir.join("l.ktlog")).expect("open");
        assert_eq!(
            l_log.entries()[0].timestamp,
            live.receipt_timestamp.expect("recorded")
        );
    }

    #[test]
    fn release_without_a_log_reports_a_receipt_and_records_nothing() {
        let dir = scratch("nolog");
        let (plan, _) = plan_with_real_artifact(&dir);
        let r = release(&plan, &dir.join("out"), None, Some(0)).expect("release");
        // No log means no receipt, so there is no timestamp to claim — reporting
        // one would be a false record rather than a missing one.
        assert_eq!(r.receipt_timestamp, None);
        assert_eq!(r.receipt_clock, None);
        assert_eq!(r.prev_hash, GENESIS);
        assert_eq!(r.kt_seq, None);
        assert_eq!(r.kt_entry_hash, None);
        assert_eq!(
            r.receipt_hash,
            receipt_hash(&canonical_payload(&plan, &[]), GENESIS)
        );
        assert!(
            !dir.join("r.ktlog").exists(),
            "no log was asked for, so none may appear"
        );
    }

    /// The write half end to end, in-crate: the receipt commits to the bytes on
    /// disk, and `verify` recomputes it from the plan and the log without
    /// trusting anything the writer held in memory. The CLI script exercises the
    /// same path from outside; this keeps it honest at the library boundary.
    #[test]
    fn release_then_verify_round_trips_from_disk() {
        let dir = scratch("roundtrip");
        let (plan, bytes) = plan_with_real_artifact(&dir);
        let log = dir.join("r.ktlog");
        let out = dir.join("out");

        let released = release(&plan, &out, Some(&log), Some(1_700_000_000_000)).expect("release");
        assert_eq!(released.kt_seq, Some(0));
        assert_eq!(released.derivative_sha256, sha256_hex(&bytes));
        // R-CLI-6: the release record carries the verdict's own token, so one
        // consumer schema reads `check` and `release` output alike.
        assert_eq!(released.decision, Decision::Allow);
        assert_eq!(released.decision.as_str(), "ALLOW");
        assert_eq!(released.marking, gate(&plan).marking);
        // R-CLI-9: `--now-ms` was supplied, and the record says so.
        assert_eq!(released.receipt_timestamp, Some(1_700_000_000_000));
        assert_eq!(released.receipt_clock, Some(ClockSource::Supplied));
        assert_eq!(released.receipt_clock.map(|c| c.as_str()), Some("supplied"));

        // Two distinct "no prior entry" token spaces, and they are not equal:
        // with a log the receipt chains onto the LOG's genesis hash — which is
        // also the entry's own prev_hash, and that is what lets verify recompute
        // the receipt from the entry alone.
        assert_ne!(released.prev_hash, GENESIS);
        let reopened = KtLog::open(&log).expect("the log reopens and its chain verifies");
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.entries()[0].prev_hash, released.prev_hash);

        // The derivative is on disk, byte-identical.
        let written = std::fs::read(&released.derivative_path).expect("read the derivative");
        assert_eq!(sha256_hex(&written), sha256_hex(&bytes));

        // verify(): recomputed from the plan and the log, not from `released`.
        let derivative = std::path::Path::new(&released.derivative_path);
        let v = verify(&log, Some(&plan), Some(derivative), None).expect("verify");
        assert_eq!(v.entries, 1);
        assert_eq!(
            v.matched_seq,
            Some(0),
            "the recomputed payload must match the entry"
        );
        assert_eq!(
            v.recomputed_receipt_hash.as_deref(),
            Some(released.receipt_hash.as_str()),
            "the receipt recomputed from the entry must equal the published one"
        );
        assert_eq!(v.derivative_matches_plan, Some(true));

        // A file tamper leaves the chain half intact while failing the file half.
        // That asymmetry is exactly why the CLI's exit status has to fold in
        // BOTH, rather than only the chain match.
        let mut tampered = written.clone();
        tampered.push(b'X');
        std::fs::write(&released.derivative_path, &tampered).expect("tamper the derivative");
        let v2 = verify(&log, Some(&plan), Some(derivative), None).expect("verify");
        assert_eq!(
            v2.matched_seq,
            Some(0),
            "the chain half is unaffected by a file tamper"
        );
        assert_eq!(
            v2.derivative_matches_plan,
            Some(false),
            "the tamper must be detected"
        );

        // A different plan finds no entry, which is what makes the match meaningful.
        let mut other = plan.clone();
        other.provenance.origin = "collector-2".to_string();
        let v3 = verify(&log, Some(&other), None, None).expect("verify");
        assert_eq!(
            v3.matched_seq, None,
            "an unrelated plan must not match an entry"
        );

        // A log that EXISTS and holds nothing verifies as empty. A log that does NOT exist is an
        // error: "empty" and "absent" are different claims, and conflating them is the fail-open this
        // test used to assert — the file below was never written, `verify` still returned 0 entries
        // with the genesis tip, and the CLI exited 0 on a log that was not there.
        let empty = dir.join("empty.ktlog");
        std::fs::write(&empty, "").expect("create a genuinely empty log");
        let v4 = verify(&empty, None, None, None).expect("an empty log is valid");
        assert_eq!(v4.entries, 0);
        assert_eq!(v4.tip_hash, crate::kt_log::genesis_hash());

        let absent = dir.join("absent.ktlog");
        assert!(!absent.exists());
        assert!(
            verify(&absent, None, None, None).is_err(),
            "an absent log is not an empty chain"
        );
    }

    /// THE TAIL A CHAIN CANNOT SEE. Cut a log on a line boundary and the entries that remain still
    /// commit to each other: the chain verifies, one receipt short, and reports nothing wrong. That
    /// is exactly why the spec's S8 settles on "a truncated log is detected (tail truncation needs
    /// the exported head)" — the head has to come from somewhere the log does not control.
    /// `--expect-tip` is that head. With it the lost tail is refused; without it the same file still
    /// verifies and the result says no anchor was checked, which is a different claim.
    #[test]
    fn an_anchor_catches_the_tail_a_chain_cannot() {
        let dir = scratch("anchor");
        let (plan, _) = plan_with_real_artifact(&dir);
        let log = dir.join("a.ktlog");
        // Two entries, so cutting the last line removes a receipt rather than emptying the log.
        release(
            &plan,
            &dir.join("out1"),
            Some(&log),
            Some(1_700_000_000_000),
        )
        .expect("release 1");
        release(
            &plan,
            &dir.join("out2"),
            Some(&log),
            Some(1_700_000_001_000),
        )
        .expect("release 2");

        let full = verify(&log, None, None, None).expect("verify the whole log");
        assert_eq!(full.entries, 2);
        assert_eq!(
            full.tip_anchor, None,
            "no anchor was given, and the result says so"
        );
        assert_eq!(full.tip_matches_anchor, None);
        let true_tip = full.tip_hash.clone();

        // Truncate on a line boundary: the last receipt is gone and nothing complains.
        let raw = std::fs::read(&log).expect("read the log");
        let last = raw
            .iter()
            .rposition(|b| *b == b'\n')
            .expect("a trailing newline");
        let prev = raw[..last]
            .iter()
            .rposition(|b| *b == b'\n')
            .expect("a second line");
        let truncated = dir.join("cut.ktlog");
        std::fs::write(&truncated, &raw[..=prev]).expect("write the truncated log");

        let torn = verify(&truncated, None, None, None).expect("the shorter chain verifies");
        assert_eq!(
            torn.entries, 1,
            "one receipt is gone and the chain does not notice"
        );
        assert_ne!(
            torn.tip_hash, true_tip,
            "the head moved with the missing tail"
        );

        // With the anchor, the same file is refused — naming both what it found and what was claimed.
        let err = verify(&truncated, None, None, Some(&true_tip))
            .expect_err("the anchor must catch the lost tail");
        assert!(
            err.contains(&true_tip),
            "the refusal must name the anchor: {err}"
        );
        assert!(err.contains(&torn.tip_hash), "and the head it found: {err}");

        // A matching anchor is not an error, and the result records that something outside the log
        // was checked — otherwise "verified against an anchor" and "verified alone" would look alike.
        let ok = verify(&log, None, None, Some(&true_tip)).expect("the matching anchor verifies");
        assert_eq!(ok.entries, 2);
        assert_eq!(ok.tip_anchor.as_deref(), Some(true_tip.as_str()));
        assert_eq!(ok.tip_matches_anchor, Some(true));

        // A value that cannot be a head is refused BEFORE the log is read: a typo must never be
        // reported as a tampered chain, and the check precedes even the absent-log check.
        for bad in [
            &true_tip[..63],
            true_tip.as_str().to_uppercase().as_str(),
            "zz",
        ] {
            let err = verify(&log, None, None, Some(bad))
                .expect_err("a malformed anchor is refused as malformed");
            assert!(err.contains("64-character lowercase hex"), "{bad:?}: {err}");
        }
        let err = verify(&dir.join("nope.ktlog"), None, None, Some("zz"))
            .expect_err("the anchor's format is checked before the log is touched");
        assert!(err.contains("64-character lowercase hex"), "{err}");
    }

    /// A SEEDED FUZZER OVER THE PLAN PARSER — the one surface that takes input from outside.
    ///
    /// Not three hand-written malformed plans: the plans the gate itself uses, mutated by an xorshift
    /// PRNG across the shapes a byte string can take — truncation, deletion, insertion, structural
    /// characters, NUL, multi-byte UTF-8 split across a boundary, and the splice of two seeds — while
    /// asserting the properties that must hold for EVERY input rather than the ones that happen to
    /// hold for the inputs somebody thought of:
    ///
    ///   1. `parse_plan` never panics;
    ///   2. every failure is a REFUSAL, not an error: `deny.plan-invalid` at `Stage::Plan`, which is
    ///      what keeps a malformed plan a boundary decision instead of an infrastructure crash;
    ///   3. parsing is deterministic — the same bytes decide the same thing twice;
    ///   4. a plan that IS accepted survives the whole gate without panicking, and re-encodes to the
    ///      wire form that parses back to the same plan. The parser is the door and the gate is the
    ///      room; a fuzzer that stops at the door tests half the surface, and a plan that cannot make
    ///      the round trip is a receipt nobody could reproduce.
    ///
    /// Deterministic by construction — a fixed seed, no clock, no filesystem — so a failure is
    /// reproducible from the iteration printed in it. `SLUICE_FUZZ_ITERS` raises the budget; the
    /// default keeps `cargo test --lib sluice::` fast, which is what makes this *wired* (gate 1 runs
    /// it every regression pass) rather than a script nobody invokes.
    #[test]
    fn the_plan_parser_never_panics_and_every_failure_is_a_refusal() {
        fn xorshift(state: &mut u64) -> u64 {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            x
        }

        // Seeds: real plans in the wire form the CLI receives, plus the degenerate documents a
        // parser is most often wrong about.
        let mut seeds: Vec<String> = Vec::new();
        let mut plain = base();
        seeds.push(serde_json::to_string(&plain).expect("a plan encodes"));
        plain.artifact.bytes = 4096;
        plain.provenance.caveats = vec!["NO-THIRD-PARTY".to_string()];
        seeds.push(serde_json::to_string(&plain).expect("a plan encodes"));
        for degenerate in ["{}", "[]", "null", "0", "", "{\"artifact\":{}}"] {
            seeds.push(degenerate.to_string());
        }

        let iters: usize = std::env::var("SLUICE_FUZZ_ITERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20_000);
        let mut state: u64 = 0x5EED_1234_ABCD_9876;
        let structure = b"{}[],:\"\\ \n\ttruefalse0123456789.-+e";

        for i in 0..iters {
            let mut buf = seeds[(xorshift(&mut state) as usize) % seeds.len()]
                .clone()
                .into_bytes();
            let ops = 1 + (xorshift(&mut state) % 4) as usize;
            for _ in 0..ops {
                if buf.is_empty() {
                    break;
                }
                let at = (xorshift(&mut state) as usize) % buf.len();
                match xorshift(&mut state) % 5 {
                    0 => {
                        buf.remove(at);
                    }
                    1 => {
                        buf.insert(
                            at,
                            structure[(xorshift(&mut state) as usize) % structure.len()],
                        );
                    }
                    2 => buf.insert(at, 0),
                    3 => {
                        // A multi-byte character, inserted as bytes: a reader that slices by byte
                        // rather than by character is the classic way to panic on UTF-8.
                        let ch = ['é', 'ß', '☃', '😀'][(xorshift(&mut state) as usize) % 4];
                        buf.splice(at..at, ch.to_string().bytes());
                    }
                    _ => buf.truncate(at),
                }
            }
            if xorshift(&mut state) % 8 == 0 {
                // Splice two seeds: structural mismatches no single mutation reaches.
                let other = seeds[(xorshift(&mut state) as usize) % seeds.len()].as_bytes();
                let (cut, mid) = (buf.len() / 2, other.len() / 2);
                let mut spliced = buf[..cut].to_vec();
                spliced.extend_from_slice(&other[mid..]);
                buf = spliced;
            }
            let Ok(text) = String::from_utf8(buf) else {
                continue;
            };
            let shown: String = text.chars().take(120).collect();

            let first = parse_plan(&text);
            match &first {
                Err(v) => {
                    assert_eq!(
                        v.code, "deny.plan-invalid",
                        "iteration {i}: a parse failure must be the documented refusal, not {} — {shown:?}",
                        v.code
                    );
                    assert_eq!(
                        v.stage,
                        Stage::Plan,
                        "iteration {i}: a parse failure must fail at the plan stage — {shown:?}"
                    );
                    assert!(
                        !v.detail.is_empty(),
                        "iteration {i}: a refusal with no reason — {shown:?}"
                    );
                }
                Ok(plan) => {
                    let _ = gate(plan);
                    let again = serde_json::to_string(plan).expect("an accepted plan re-encodes");
                    assert_eq!(
                        parse_plan(&again).ok().as_ref(),
                        Some(plan),
                        "iteration {i}: an accepted plan must round-trip through the wire form — {shown:?}"
                    );
                }
            }
            assert_eq!(
                format!("{:?}", parse_plan(&text)),
                format!("{first:?}"),
                "iteration {i}: parsing is not deterministic — {shown:?}"
            );
        }
        println!(
            "  {iters} mutated plans: no panic; every failure a refusal at the plan stage; every \
             acceptance survived the gate and round-tripped through the wire form"
        );
    }

    /// TWO WRITERS, ONE LOG, NO CORRUPTION. This is the deterministic, in-process form of the
    /// failure measured from outside: eight rounds of two concurrent `release` processes into one
    /// `--kt-log` left a chain that could not be reopened in five of them, with **both** processes
    /// exiting 0. The append is a read-modify-write — read the head, chain onto it, write — and
    /// `kt_log` documents that it takes no lock, so both writers chained onto the same head and wrote
    /// the same `seq`. `release` now holds an exclusive lock over the log for that whole window.
    ///
    /// Seeded threads rather than processes: `flock` excludes separate open descriptions, which two
    /// threads taking their own `open` are, so the exclusion under test is the real one; and it stays
    /// fast enough to run on every regression pass, which is what makes it a check rather than a
    /// race someone re-measures by hand.
    #[test]
    fn rotate_appends_a_close_entry_and_reports_the_payload_verbatim() {
        let dir = scratch("rotate");
        let log_path = dir.join("r.ktlog");
        {
            let mut log = KtLog::open(&log_path).expect("open a fresh log");
            log.append_at(b"{\"a\":1}", 1000)
                .expect("append the first receipt");
            log.append_at(b"{\"b\":2}", 1001)
                .expect("append the second");
        }
        let tip = KtLog::open(&log_path).expect("reopen").head_hash();
        let r = rotate(&log_path, Some(&tip), "manual", 7, None).expect("rotate the segment");

        assert_eq!(r.entries, 2, "the closing entry is not itself a receipt");
        assert_eq!(
            r.last_receipt_hash, tip,
            "the head the segment ended at is reported, not recomputed"
        );

        let after = KtLog::open(&log_path).expect("the chain must still verify after a close");
        assert_eq!(
            after.len(),
            3,
            "the close entry is appended, not written elsewhere"
        );
        assert_eq!(
            after.head_hash(),
            r.close_entry_hash,
            "the tip is the closing entry"
        );

        // [R4] THE CONTRACT: the log stores the payload HASH and nothing else, so the record's verbatim
        // copy is the only place the bytes exist. If these two ever disagree the record cannot check a
        // closing entry at all, which is why this is asserted rather than assumed.
        let stored = after
            .entries()
            .last()
            .expect("the closing entry")
            .payload_hash
            .clone();
        assert_eq!(
            payload_hash(r.close_payload.as_bytes()),
            stored,
            "the payload the record will carry must hash to the entry the log wrote"
        );
    }

    #[test]
    fn a_continuation_is_committed_by_the_plan_and_an_absent_one_changes_nothing() {
        let mut plan = base();
        plan.continues = Some("a".repeat(64));
        let canon = canonical_payload(&plan, &[]);
        assert!(
            canon.contains("continues"),
            "the canonical must carry the predecessor: {canon}"
        );
        assert!(canon.contains(&"a".repeat(64)), "and its value verbatim");
        let plain = base();
        assert!(!canonical_payload(&plain, &[]).contains("continues"));
        assert_eq!(
            canonical_payload(&plain, &[]),
            canonical_payload(&base(), &[])
        );
    }

    #[test]
    fn a_malformed_continuation_is_refused_by_the_pure_gate() {
        let upper = "A".repeat(64);
        let short = "a".repeat(63);
        for bad in ["", "nothex", upper.as_str(), short.as_str()] {
            let mut plan = base();
            plan.continues = Some(bad.to_string());
            let v = gate(&plan);
            assert!(
                !matches!(v.decision, Decision::Allow),
                "a malformed continuation must refuse, got {v:?} for {bad:?}"
            );
        }
        let mut ok = base();
        ok.continues = Some("0".repeat(64));
        let v = gate(&ok);
        assert!(
            !format!("{v:?}").contains("predecessor"),
            "a well-formed predecessor must not be what refuses it: {v:?}"
        );
    }

    #[test]
    fn a_continuation_the_record_declares_must_be_the_one_the_plan_declares() {
        let dir = scratch("join-check");
        let log_path = dir.join("j.ktlog");
        let prev = "a".repeat(64);
        {
            let mut log = KtLog::open(&log_path).expect("open a fresh log");
            log.append_at(b"{\"a\":1}", 1000).expect("first receipt");
        }
        let tip = KtLog::open(&log_path).expect("reopen").head_hash();
        let r = rotate(&log_path, Some(&tip), "manual", 2, Some(&prev)).expect("rotate");

        // both sides declare the same predecessor: the join holds
        let ok = verify_segment_close(&log_path, &r.close_payload, Some(&prev))
            .expect("agreeing declarations must check out");
        assert_eq!(ok.predecessor.as_deref(), Some(prev.as_str()));

        // the plan declares a DIFFERENT predecessor: two declarations, one of them wrong
        let other = "b".repeat(64);
        assert!(
            verify_segment_close(&log_path, &r.close_payload, Some(&other)).is_err(),
            "the two declarations disagree, so this must refuse"
        );

        // THE CASE A3 §8 NAMES: the record says continuation, the plan says none. A1 §3's
        // re-rooted-at-GENESIS class is invisible in the file; this is what catches it.
        let e = verify_segment_close(&log_path, &r.close_payload, None)
            .expect_err("a continuation with no plan declaring it must refuse");
        let msg = format!("{e}");
        assert!(
            msg.contains("re-rooted"),
            "the refusal must name the class: {msg}"
        );
    }

    #[test]
    fn a_plan_declaring_a_continuation_the_record_does_not_is_also_refused() {
        let dir = scratch("join-check-mirror");
        let log_path = dir.join("m.ktlog");
        {
            let mut log = KtLog::open(&log_path).expect("open a fresh log");
            log.append_at(b"{\"a\":1}", 1000).expect("first receipt");
        }
        let tip = KtLog::open(&log_path).expect("reopen").head_hash();
        // a closing entry that declares NO predecessor
        let r = rotate(&log_path, Some(&tip), "manual", 2, None).expect("rotate");
        let claimed = "c".repeat(64);
        assert!(
            verify_segment_close(&log_path, &r.close_payload, Some(&claimed)).is_err(),
            "the plan claims a continuation the record does not corroborate"
        );
        verify_segment_close(&log_path, &r.close_payload, None)
            .expect("no continuation on either side must check out");
    }

    #[test]
    fn a_close_payload_is_confirmed_by_the_log_and_a_self_consistent_lie_is_not() {
        let dir = scratch("close-check");
        let log_path = dir.join("c.ktlog");
        {
            let mut log = KtLog::open(&log_path).expect("open a fresh log");
            log.append_at(b"{\"a\":1}", 1000).expect("first receipt");
            log.append_at(b"{\"b\":2}", 1001).expect("second receipt");
        }
        let tip = KtLog::open(&log_path).expect("reopen").head_hash();
        let r = rotate(&log_path, Some(&tip), "manual", 7, None).expect("rotate");

        // 1. the bytes the record carries are the bytes the log hashed
        let ok = verify_segment_close(&log_path, &r.close_payload, None)
            .expect("the record must check out");
        assert_eq!((ok.segment, ok.entries), (7, 2));
        assert_eq!(ok.last_receipt_hash, tip);
        assert_eq!(ok.predecessor, None, "this segment declares no predecessor");

        // 2. a payload that hashes correctly but declares the WRONG segment must still refuse: only the
        //    field comparison catches this, which is why both checks exist.
        let lie = serde_json::json!({
            "kind": "segment-close",
            "segment": 7,
            "entries": 1,                       // the log holds 2 receipts before the close
            "last_receipt_hash": tip,
            "reason": "manual",
            "prev_segment_close": null,
        })
        .to_string();
        let log2 = dir.join("c2.ktlog");
        {
            let mut l = KtLog::open(&log2).expect("open");
            l.append_at(b"{\"a\":1}", 1000).expect("first receipt");
            l.append_at(b"{\"b\":2}", 1001).expect("second receipt");
            l.append_at(lie.as_bytes(), 1002)
                .expect("append the lying close entry");
        }
        let e = verify_segment_close(&log2, &lie, None)
            .expect_err("a payload declaring the wrong receipt count must refuse");
        assert!(
            format!("{e}").contains("receipt(s)"),
            "the refusal must name the field: {e}"
        );

        // 3. and a payload the log never committed to refuses on the hash
        let e2 = verify_segment_close(&log_path, &lie, None)
            .expect_err("a payload whose bytes the log never hashed must refuse");
        assert!(
            format!("{e2}").contains("not the one that entry committed to"),
            "{e2}"
        );
    }

    #[test]
    fn rotate_refuses_a_stale_or_malformed_expect_tip() {
        let dir = scratch("rotate-stale");
        let log_path = dir.join("s.ktlog");
        {
            let mut log = KtLog::open(&log_path).expect("open a fresh log");
            log.append_at(b"{\"a\":1}", 1000).expect("append");
        }
        // A valid-shaped anchor that is not the head: refused, naming both.
        let wrong = "0".repeat(64);
        let e = rotate(&log_path, Some(&wrong), "manual", 1, None)
            .expect_err("a stale tip must refuse");
        assert!(
            format!("{e}").contains("--expect-tip"),
            "the refusal must name the flag: {e}"
        );
        // And a malformed one never reaches the log.
        let e2 = rotate(&log_path, Some("nothex"), "manual", 1, None).expect_err("malformed");
        assert!(format!("{e2}").contains("64 lowercase hex"), "{e2}");
        // Neither refusal may have written anything.
        assert_eq!(
            KtLog::open(&log_path).expect("still verifies").len(),
            1,
            "a refusal writes nothing"
        );
    }

    #[test]
    fn concurrent_releases_onto_one_log_never_break_the_chain() {
        let dir = scratch("concurrent");
        let (plan, _) = plan_with_real_artifact(&dir);
        let log = dir.join("shared.ktlog");
        let writers = 8;

        let handles: Vec<_> = (0..writers)
            .map(|i| {
                let plan = plan.clone();
                let log = log.clone();
                let out = dir.join(format!("out-{i}"));
                std::thread::spawn(move || {
                    release(&plan, &out, Some(&log), Some(1_700_000_000_000 + i as u64))
                        .map(|r| r.kt_seq)
                })
            })
            .collect();
        let seqs: Vec<Option<u64>> = handles
            .into_iter()
            .map(|h| h.join().expect("a writer thread panicked"))
            .collect::<Result<_, _>>()
            .expect(
                "every writer must succeed — the lock serialises them, it does not refuse them",
            );

        // The chain must reopen, hold one entry per writer, and carry every seq exactly once.
        let reopened = KtLog::open(&log).expect("the chain must verify after concurrent appends");
        assert_eq!(reopened.len(), writers);
        let mut sorted: Vec<u64> = seqs.iter().map(|s| s.expect("an entry")).collect();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            (0..writers as u64).collect::<Vec<_>>(),
            "each writer must have taken a distinct seq — duplicates are the corruption"
        );
        assert_eq!(
            verify(&log, None, None, None).expect("verify").entries,
            writers
        );
    }

    /// A HELD LOCK QUEUES, THEN REFUSES — and writes nothing in the meantime. Fail-closed on write is
    /// the property that matters: an unwritable or busy `--kt-log` stops the release before any receipt
    /// exists, so the audit trail never describes a boundary decision that did not happen.
    #[test]
    fn a_held_lock_queues_the_second_writer_and_writes_nothing_meanwhile() {
        fn lines(path: &Path) -> usize {
            std::fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .count()
        }
        let dir = scratch("lock-held");
        let (plan, _) = plan_with_real_artifact(&dir);
        let log = dir.join("held.ktlog");

        let held = ReceiptLogLock::acquire(&log).expect("the first writer takes the lock");
        let (p2, l2, o2) = (plan.clone(), log.clone(), dir.join("out"));
        let writer = std::thread::spawn(move || {
            release(&p2, &o2, Some(&l2), Some(1_700_000_000_000)).map(|r| r.kt_seq)
        });
        // Absence of a write can only be shown by looking while it is still pending. The queue is the
        // point: a brief overlap is normal, and refusing on first contact would fail both writers for
        // nothing.
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            lines(&log),
            0,
            "a queued release writes nothing while another holds the log"
        );
        assert!(
            !writer.is_finished(),
            "it must still be waiting, not refused"
        );

        drop(held);
        let seq = writer
            .join()
            .expect("no panic")
            .expect("the queued release succeeds once the log is free");
        assert_eq!(
            seq,
            Some(0),
            "and it chains onto the head it read under the lock"
        );
        assert_eq!(lines(&log), 1);

        // Past the bound, the same situation is a refusal rather than a hang. Exercised on the guard
        // so the test does not spend the product's ten seconds.
        let held_again = ReceiptLogLock::acquire(&log).expect("re-acquire");
        let err = ReceiptLogLock::acquire_with_wait(&log, 40)
            .expect_err("a held lock must time out rather than chain blindly");
        assert!(
            err.to_string().contains("another release holds"),
            "the refusal must name what is in the way: {err}"
        );
        drop(held_again);
        ReceiptLogLock::acquire_with_wait(&log, 40).expect("the lock is a guard, not a latch");
    }

    /// A RECEIPT LOG WRITTEN BY THE CURRENT ENGINE, PINNED BYTE FOR BYTE — the fence any change to the
    /// receipt format has to pass.
    ///
    /// `verify` does not merely re-hash what is stored: it **recomputes** the canonical payload from the
    /// plan and re-derives the chain, which is what makes a doctored log detectable. The price of that
    /// design is that changing the payload's shape breaks the verification of every receipt already
    /// written — silently, because a recomputation that differs only in a new field still produces a
    /// well-formed hash, just not the one in the log. So the format is now fenced by a log frozen at this
    /// revision: if a later change adds, renames or reorders a payload field, this test fails and says
    /// which entry no longer derives.
    ///
    /// The log and the plan are inlined rather than read from the artifact directory: the fixture has to
    /// be exactly these bytes, so it must not be able to drift with the filesystem. Regenerating it is a
    /// deliberate act — a new constant committed alongside the format change, with the old one kept until
    /// the old receipts are out of their retention window.
    #[test]
    fn a_log_written_by_an_earlier_engine_still_verifies() {
        const GOLDEN_LOG_V1: &str = concat!(
            r#"{"seq":0,"prev_hash":"8527fb1b6c5c116b378cac10ecc330ebca0ba3e3d2e7ee5f23a0644504403014","#,
            r#""payload_hash":"6f2286bdf5796faf3f998fe2aeaf9da9b34eda6fac9c192dc9b3a3a77fea84bf","#,
            r#""timestamp":1700000000000,"#,
            r#""entry_hash":"fd62ce00c57e954d5ba02e9ee643dd9e2a18136446937e6517b60cee978793ac"}"#,
            "\n"
        );
        const GOLDEN_TIP_V1: &str =
            "fd62ce00c57e954d5ba02e9ee643dd9e2a18136446937e6517b60cee978793ac";
        const GOLDEN_PAYLOAD_HASH_V1: &str =
            "6f2286bdf5796faf3f998fe2aeaf9da9b34eda6fac9c192dc9b3a3a77fea84bf";
        // The plan as it was released, with only the artifact's PATH repointed at this test's scratch
        // directory — the path is not part of what the payload commits (the digest is), so the canonical
        // bytes are untouched by the move.
        const GOLDEN_PLAN_V1: &str = r#"{"artifact": {"bytes": 4096, "path": "ARTIFACT", "sha256": "f302957da5220938a7e3e51a8718c79b9e00dc13ab2119e8cfc978f041720382"}, "provenance": {"caveats": [], "class": "Open", "embargo_active": false, "lineage": [], "origin": "collector-1"}, "release": {"audience": "Public", "channel": "coalition", "marking_emitted": true, "presanitized": true}}"#;

        let dir = scratch("golden-v1");
        let artifact = dir.join("small.bin");
        std::fs::write(&artifact, vec![0u8; 4096]).expect("write the artifact the plan names");
        let plan_path = dir.join("plan.json");
        std::fs::write(
            &plan_path,
            GOLDEN_PLAN_V1.replace("ARTIFACT", &artifact.display().to_string()),
        )
        .expect("write the plan");
        let log_path = dir.join("golden.ktlog");
        std::fs::write(&log_path, GOLDEN_LOG_V1).expect("write the golden log");

        let plan = parse_plan(&std::fs::read_to_string(&plan_path).expect("read the plan"))
            .expect("the golden plan parses");
        let verified = verify(&log_path, Some(&plan), None, None).expect(concat!(
            "a log written by an earlier engine must still verify — if this fails, the ",
            "receipt format changed and every receipt already on disk is unverifiable"
        ));
        assert_eq!(verified.entries, 1);
        assert_eq!(
            verified.tip_hash, GOLDEN_TIP_V1,
            "the tip must be the frozen one"
        );

        // AND THE RECOMPUTATION ITSELF IS PINNED — the assertion that actually fences the format.
        // Measured, not assumed: with the two checks above and nothing else, adding a field to
        // `canonical_payload` left this test GREEN, because the chain hashes what the entry *stores*:
        // a changed recomputation still produces an intact chain and a well-formed hash. This line is
        // what fails against that mutation, and it was proved by running the mutation (below, in the
        // commit message) rather than by reasoning about it.
        assert_eq!(
            payload_hash(&serde_json::to_vec(&receipt_payload(&plan, &[])).expect("encode")),
            GOLDEN_PAYLOAD_HASH_V1,
            "the canonical payload recomputed from the plan no longer matches the one this log commits"
        );
        // And the fence fails loudly if the stored bytes are what changed rather than the recomputation.
        assert!(
            std::fs::read_to_string(&log_path)
                .expect("read")
                .starts_with(GOLDEN_LOG_V1.trim_end())
        );
    }

    #[test]
    fn obligation_pre_empts_class_for_open_material() {
        // Open material on a non-bulk channel: the refusal must be about the
        // boundary, not the payload.
        let mut p = base();
        p.release.channel = TransferChannel::Covert.as_str().to_string();
        p.artifact.bytes = 1_048_576;
        let v = gate(&p);
        assert_eq!(v.code, "deny.channel-rate-class");
        assert_eq!(v.stage, Stage::Obligation);
    }

    #[test]
    fn class_gate_pre_empts_caveat_gate() {
        // Research+Public is refused by the class gate even when a caveat would
        // also refuse; the class gate's code must be the one reported.
        let mut p = base();
        p.provenance.class = AccessClass::Research;
        p.provenance.caveats = vec!["NO-THIRD-PARTY".to_string()];
        let v = gate(&p);
        assert_eq!(v.code, "deny.audience-not-admitted");
        assert_eq!(v.stage, Stage::Class);
    }

    #[test]
    fn embargo_pre_empts_sealed_in_the_class_gate() {
        // Pins check_export's order as written at src/access_class.rs:348.
        let mut p = base();
        p.provenance.class = AccessClass::Sealed;
        p.provenance.embargo_active = true;
        let v = gate(&p);
        assert_eq!(v.code, "deny.embargo-active");
    }

    #[test]
    fn caveat_laundering_is_refused() {
        // The case the shipped release path admits: Open material marked
        // NO-THIRD-PARTY must not reach a third party.
        let mut p = base();
        p.provenance.class = AccessClass::Open;
        p.provenance.caveats = vec!["NO-THIRD-PARTY".to_string()];
        p.release.audience = Audience::ThirdParty;
        let v = gate(&p);
        assert_eq!(v.code, "deny.caveat");
        assert_eq!(v.stage, Stage::Caveat);
    }

    #[test]
    fn caveats_restrict_only() {
        // An empty caveat list is unconstrained: caveats never widen, but they
        // must not narrow either.
        let v = gate(&base());
        assert!(
            v.is_allow(),
            "empty caveats must not restrict: {}",
            v.detail
        );
    }

    #[test]
    fn covert_boundary_pair() {
        let mut p = base();
        p.release.channel = TransferChannel::Covert.as_str().to_string();
        p.artifact.bytes = DEFAULT_PAYLOAD_CAP_BITS / 8;
        assert!(gate(&p).is_allow(), "at the cap must be allowed");
        p.artifact.bytes += 1;
        assert_eq!(gate(&p).code, "deny.channel-rate-class");
    }

    #[test]
    fn unparseable_caveat_is_refused_not_dropped() {
        let mut p = base();
        p.provenance.caveats = vec!["need-to-know".to_string()];
        assert_eq!(gate(&p).code, "deny.caveat-unparseable");
    }

    #[test]
    fn one_way_channel_refuses_a_declared_return_path() {
        let mut p = base();
        p.release.channel = TransferChannel::Physical.as_str().to_string();
        p.release.media_hash = Some("b".repeat(64));
        p.release.egress_only = false;
        assert_eq!(gate(&p).code, "deny.channel-directionality");
    }

    #[test]
    fn receipt_is_deterministic_and_chainable() {
        let p = base();
        let v1 = gate(&p);
        let v2 = gate(&p);
        assert_eq!(v1.receipt_hash, v2.receipt_hash, "same plan, same receipt");
        let canon = canonical_payload(&p, &[]);
        let chained = receipt_hash(&canon, v1.receipt_hash.as_deref().unwrap());
        assert_ne!(chained, v1.receipt_hash.clone().unwrap());
        assert_eq!(chained.len(), 64);
    }

    #[test]
    fn marking_renders_canonical_codes() {
        let mut p = base();
        p.provenance.caveats = vec!["REL-beta".to_string()];
        p.release.audience = Audience::ThirdParty;
        p.release.role = Some("beta".to_string());
        let v = gate(&p);
        assert!(v.is_allow(), "{}", v.detail);
        assert_eq!(v.marking, "REL-beta");
    }

    #[test]
    fn unknown_channel_token_is_refused_by_the_gate() {
        // The typed plan cannot *hold* a bad token as an archetype, so the
        // token is parsed inside `gate()`; this pins that path end to end.
        let mut p = base();
        p.release.channel = "carrier-pigeon".to_string();
        let v = gate(&p);
        assert_eq!(v.code, "deny.channel-unknown");
        assert_eq!(v.stage, Stage::Channel);
    }

    #[test]
    fn unknown_channel_token_is_refused() {
        let e = parse_channel("carrier-pigeon").unwrap_err();
        assert_eq!(e.code, "deny.channel-unknown");
    }

    #[test]
    fn channel_table_is_totally_ordered_over_all_archetypes() {
        for c in TransferChannel::ALL {
            assert_eq!(TransferChannel::parse(c.as_str()), Some(c));
            assert!(!c.source().is_empty());
            assert!(!c.retention().is_empty());
        }
    }

    #[test]
    fn wire_tokens_match_as_str() {
        // One token space per enum: the JSON an operator sees and the token the
        // code reports must be the same string.
        for d in [Decision::Allow, Decision::Deny] {
            let js = serde_json::to_value(d).expect("Decision encodes");
            assert_eq!(js.as_str(), Some(d.as_str()), "{d:?}");
        }
        for st in Stage::ORDER {
            let js = serde_json::to_value(st).expect("Stage encodes");
            assert_eq!(js.as_str(), Some(st.as_str()), "{st:?}");
        }
    }

    #[test]
    fn stage_order_and_index_agree() {
        for (i, st) in Stage::ORDER.iter().enumerate() {
            assert_eq!(st.index(), i, "{st:?} index disagrees with ORDER");
            assert!(!st.label().is_empty());
        }
    }

    // ── Strict plan parsing (S4) ────────────────────────────────────────────

    fn good_plan_value() -> serde_json::Value {
        serde_json::json!({
            "artifact": {
                "path": "/vault/a.json",
                "sha256": "a".repeat(64),
                "bytes": 512
            },
            "provenance": {
                "origin": "collector-1",
                "class": "Open",
                "caveats": [],
                "embargo_active": false,
                "lineage": []
            },
            "release": {
                "audience": "Public",
                "channel": "coalition",
                "presanitized": true,
                "marking_emitted": true
            }
        })
    }

    #[test]
    fn a_valid_plan_parses_and_reaches_a_decision() {
        let v = check_json(&good_plan_value().to_string());
        assert!(v.is_allow(), "{} — {}", v.code, v.detail);
    }

    #[test]
    fn an_unknown_key_is_refused_at_every_level() {
        // Top-level, section-level, and nested — strict parse is recursive.
        for (label, mutate) in [("top", 0), ("section", 1), ("nested", 2)] {
            let mut val = good_plan_value();
            match mutate {
                0 => val["surprise"] = serde_json::json!(1),
                1 => val["release"]["surprise"] = serde_json::json!(1),
                _ => val["artifact"]["surprise"] = serde_json::json!(1),
            }
            let v = check_json(&val.to_string());
            assert_eq!(v.code, "deny.plan-invalid", "{label}: {}", v.detail);
            assert_eq!(v.stage, Stage::Plan);
        }
    }

    #[test]
    fn each_missing_required_section_is_refused() {
        for section in ["artifact", "provenance", "release"] {
            let mut val = good_plan_value();
            val.as_object_mut().expect("object").remove(section);
            let v = check_json(&val.to_string());
            assert_eq!(
                v.code, "deny.plan-invalid",
                "dropping {section}: {}",
                v.detail
            );
        }
    }

    #[test]
    fn a_malformed_digest_is_refused_by_stage_one() {
        for bad in [
            "a".repeat(63),
            "a".repeat(65),
            "Z".repeat(64),
            String::new(),
        ] {
            let mut val = good_plan_value();
            val["artifact"]["sha256"] = serde_json::json!(bad);
            let v = check_json(&val.to_string());
            assert_eq!(v.code, "deny.plan-invalid", "{:?}: {}", bad.len(), v.detail);
        }
    }

    #[test]
    fn a_redaction_rule_in_the_documented_shape_parses() {
        // The plan schema says `{field, mode}`. A gate that refuses `mode` as an
        // unknown key cannot load a plan written to its own spec.
        let mut val = good_plan_value();
        val["release"]["channel"] = serde_json::json!("endpoint");
        val["release"]["staging_manifest"] = serde_json::json!("m-7");
        val["release"]["presanitized"] = serde_json::json!(false);
        val["release"]["redaction_rules"] = serde_json::json!([{"field": "ssn", "mode": "remove"}]);
        let v = check_json(&val.to_string());
        assert!(v.is_allow(), "{} — {}", v.code, v.detail);
    }

    /// The wire-format battery: every vector, through the path the CLI uses.
    /// This is the rung the pipe-row table cannot be — it reaches `serde`, so it
    /// covers `N14` (missing section) and `N16` (malformed digest) which no
    /// `plan_from_row` shape can express.
    #[test]
    fn wire_format_battery_covers_every_vector() {
        let mut pass = 0usize;
        let mut failures: Vec<String> = Vec::new();
        for (id, json, want_decision, want_code) in PLANS {
            let v = check_json(json);
            let got = format!("{}|{}", v.decision.as_str(), v.code);
            if got == format!("{want_decision}|{want_code}") {
                pass += 1;
            } else {
                failures.push(format!(
                    "{id}: want {want_decision}|{want_code}, got {got} ({})",
                    v.detail
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "wire-format battery: {} passed, {} failed:\n{}",
            pass,
            failures.len(),
            failures.join("\n")
        );
        println!(
            "sluice wire-format battery: {pass}/{} cases passed (JSON -> serde -> gate)",
            PLANS.len()
        );
    }

    /// Every field an archetype *declares* as required must actually be
    /// enforced. A declaration the gate ignores tells an operator to supply
    /// something the gate never checks — and `channels` prints it as a
    /// requirement. This caught `Covert => ["payload_cap_bits"]`, a field the
    /// schema marks optional and `channel_obligations` never inspected.
    #[test]
    fn every_declared_requirement_is_enforced() {
        for ch in TransferChannel::ALL {
            for field in ch.requires() {
                let mut p = base();
                p.provenance.class = AccessClass::Open;
                p.release.channel = ch.as_str().to_string();
                // Everything else satisfied, so only `field` can refuse.
                p.release.presanitized = true;
                p.release.egress_only = true;
                p.release.marking_emitted = true;
                p.artifact.bytes = 1;
                match *field {
                    // Left empty by `base()` already.
                    "warrant_ref" | "staging_manifest" | "media_hash" => {}
                    "marking_emitted" => p.release.marking_emitted = false,
                    // If a future archetype declares a field this test cannot
                    // empty, fail loudly rather than skipping it.
                    other => panic!("requires() names {other:?}, which this test cannot empty"),
                }
                let v = gate(&p);
                assert!(
                    !v.is_allow(),
                    "{ch} declares {field:?} required, but the gate allowed a plan without it"
                );
                assert_eq!(
                    v.code, "deny.channel-obligation",
                    "{ch}/{field}: refused, but not as an unmet obligation"
                );
            }
        }
    }

    // ── D.4 regression gates, pinned through the gate ───────────────────────

    /// D.4 gate 3: the class matrix is unchanged. A layer that *composes*
    /// `check_export` must not become a side door around it — so this asserts
    /// the matrix at the gate's surface, not at the core's.
    #[test]
    fn the_class_matrix_is_unchanged_through_the_gate() {
        for audience in Audience::ALL {
            for (class, want) in [
                (AccessClass::Restricted, "deny.no-export-path"),
                (AccessClass::Sealed, "deny.sealed"),
            ] {
                let mut p = base();
                p.provenance.class = class;
                p.release.audience = audience;
                let v = gate(&p);
                assert_eq!(
                    v.decision,
                    Decision::Deny,
                    "{class:?}/{audience:?} was admitted by the gate"
                );
                assert_eq!(v.code, want, "{class:?}/{audience:?}");
                assert_eq!(v.stage, Stage::Class, "{class:?}/{audience:?}");
            }
        }

        // The read/export asymmetry is real and must survive: the operator may
        // READ restricted material but may not EXPORT it. A gate that conflated
        // the two would either leak or over-block.
        assert!(crate::access_class::may_read(
            AccessClass::Restricted,
            Audience::Operator
        ));
        assert!(
            !crate::access_class::may_export(AccessClass::Restricted, Audience::Operator, false),
            "Restricted acquired an export path"
        );

        // Sealed admits nobody — not to read, not to export, at any audience.
        for audience in Audience::ALL {
            assert!(
                !crate::access_class::may_read(AccessClass::Sealed, audience),
                "Sealed became readable by {audience:?}"
            );
        }

        // And the gate never says ALLOW for either class, as a whole-surface
        // check across every archetype (not just the fixture channel).
        for ch in TransferChannel::ALL {
            for class in [AccessClass::Restricted, AccessClass::Sealed] {
                let mut p = base();
                p.provenance.class = class;
                p.release.channel = ch.as_str().to_string();
                p.release.media_hash = Some("b".repeat(64));
                p.release.warrant_ref = Some("w-1".to_string());
                p.release.staging_manifest = Some("m-1".to_string());
                assert!(
                    !gate(&p).is_allow(),
                    "{class:?} reached {ch} through the gate"
                );
            }
        }
    }
}
