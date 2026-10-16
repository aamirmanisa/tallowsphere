// stdlib/pec.tl — Privacy-Enhancing Computation types (Phase 46)
//
// Unified PEC namespace delegating to ZkCircuit, MpcSession, FheKey,
// plus new MixChannel, Rosenpass, Ech, and MLS primitives.

// ── MetaPrivate<T> ──────────────────────────────────────────────────────────
// Higher-order privacy type requiring PEC context for all computation.
// Values of MetaPrivate<T> cannot be printed, logged, or sent unencrypted.
// They must flow through ZK proofs, MPC sessions, FHE, or DP mechanisms.

type MetaPrivate<T> = private T

// ── SealedData ──────────────────────────────────────────────────────────────
// Algorithm-versioned encrypted data (Phase 45).

struct SealedData {
    ciphertext:     String,
    algorithm:      String,
    version:        i32,
    sealed_at:      String,
}

// SealedData.seal(data, algorithm, version) -> SealedData
// SealedData.unseal(sealed) -> { plaintext, algorithm, version }

// ── CryptoAgility ───────────────────────────────────────────────────────────
// Algorithm migration helper.

struct MigratedData {
    data:           String,
    from_algorithm: String,
    to_algorithm:   String,
    migrated_at:    String,
}

// CryptoAgility.migrate(data, from_algo, to_algo) -> MigratedData

// ── HybridCert ──────────────────────────────────────────────────────────────
// Dual-key certificate (classical + PQC).

struct HybridCert {
    cert_id:        String,
    classical_algo: String,
    classical_key:  String,
    pqc_algo:       String,
    pqc_key:        String,
    issued_at:      String,
}

// HybridCert.generate(classical_algo, pqc_algo) -> HybridCert

// ── KeyRotation ─────────────────────────────────────────────────────────────
// Automated key rotation schedule.

struct RotationSchedule {
    key_id:           String,
    period_days:      i32,
    created_at:       i64,
    next_rotation_at: i64,
    needs_rotation:   bool,
}

// KeyRotation.create(key_id, rotation_period_days) -> RotationSchedule
// KeyRotation.check(schedule) -> bool (needs_rotation)

// ── HarvestGuard ────────────────────────────────────────────────────────────
// Protection against Harvest-Now-Decrypt-Later (HNDL) attacks.

struct ProtectedData {
    ciphertext:         String,
    algorithm:          String,
    min_security_years: i32,
    quantum_safe:       bool,
    protected_at:       String,
}

// HarvestGuard.protect(data, min_security_years) -> ProtectedData

// ── QuantumKeyDistribution ──────────────────────────────────────────────────
// Simulated QKD key exchange.

struct QkdSession {
    alice_id:     String,
    bob_id:       String,
    shared_key:   String,
    protocol:     String,
    established:  bool,
}

// QuantumKeyDistribution.session(alice_id, bob_id) -> QkdSession

// ── PqcMigration ────────────────────────────────────────────────────────────
// Migration audit report.

struct MigrationReport {
    total_algorithms:    i32,
    classical_count:     i32,
    pqc_count:           i32,
    hybrid_count:        i32,
    migration_progress:  String,
    recommendations:     []String,
}

// PqcMigration.audit(program_info) -> MigrationReport

// ── MixChannel ──────────────────────────────────────────────────────────────
// Anonymous communication via mix network layered encryption.

struct MixChannel {
    channel_id: String,
    hops:       i32,
    created_at: String,
}

// MixChannel.create(hops) -> MixChannel
// MixChannel.send(channel, message) -> String (encrypted layered message)
// MixChannel.receive(channel, encrypted) -> String (plaintext)

// ── Rosenpass ───────────────────────────────────────────────────────────────
// Post-quantum WireGuard handshake (simulated).

struct RosenpassSession {
    session_id:    String,
    peer_public:   String,
    shared_secret: String,
    protocol:      String,
    established:   bool,
}

// Rosenpass.handshake(peer_public) -> RosenpassSession

// ── Ech ─────────────────────────────────────────────────────────────────────
// Encrypted Client Hello (TLS extension).

// TlsConn.enable_ech() -> TlsConn with ECH enabled

// ── MlsGroup ────────────────────────────────────────────────────────────────
// MLS group key management (RFC 9420 shape).
// Epoch-based TreeKEM key derivation (simulated via BLAKE3).

struct MlsGroup {
    group_id:   String,
    epoch:      i32,
    members:    []String,
    group_key:  String,
}

// MlsGroup.create(group_id) -> MlsGroup
// MlsGroup.add_member(group, member_id) -> MlsGroup
// MlsGroup.remove_member(group, member_id) -> MlsGroup
// MlsGroup.encrypt(group, message) -> String
// MlsGroup.decrypt(group, encrypted) -> String
// MlsGroup.epoch(group) -> i32
