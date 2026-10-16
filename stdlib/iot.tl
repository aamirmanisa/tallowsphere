// Tallow Standard Library — IoT Security (Phase 44)
// IoT-specific security types: firmware signing, secure OTA updates,
// device identity management, and lightweight cryptography for constrained devices.
//
// All types are interpreter sentinels — no stdlib module dispatch needed.

// ── FirmwareSigner — Firmware signing and verification ──────────────────────
// FirmwareSigner.sign(data: String, key: String) -> SignedFirmware
//   Signs firmware data with the given key and returns a signed firmware struct.

struct SignedFirmware {
    data:       String,
    signature:  String,
    key_id:     String,
    algorithm:  String,
    signed_at:  String,
    size_bytes: i64,
}

// ── SecureOta — Secure over-the-air update packages ─────────────────────────
// SecureOta.create(version: String, firmware_hash: String) -> OtaPackage
// SecureOta.verify(package: OtaPackage, public_key: String) -> bool

struct OtaPackage {
    version:       String,
    firmware_hash: String,
    created_at:    String,
    signature:     String,
    verified:      bool,
    size_bytes:    i64,
}

// ── DeviceIdentity — Device identity and attestation ────────────────────────
// DeviceIdentity.create(device_id: String) -> DeviceIdentity
// DeviceIdentity.attest(identity: DeviceIdentity) -> AttestationResult

struct DeviceIdentity {
    device_id:    String,
    certificate:  String,
    public_key:   String,
    created_at:   String,
    trust_level:  String,
}

struct AttestationResult {
    device_id:   String,
    attested:    bool,
    trust_level: String,
    timestamp:   String,
    nonce:       String,
}

// ── LightweightCrypto — Crypto for constrained IoT devices ──────────────────
// LightweightCrypto.encrypt(data: String, key: String, algo: String) -> String
//   Supported algos: "ascon", "photon", "gift"
// LightweightCrypto.decrypt(ciphertext: String, key: String, algo: String) -> String

// Note: In the interpreter, lightweight crypto is simulated via BLAKE3
// domain-separated hashing. Real implementations would use the actual
// ASCON-128, PHOTON-Beetle, and GIFT-COFB algorithms.
