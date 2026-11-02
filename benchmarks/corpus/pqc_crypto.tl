// Tallow Post-Quantum Cryptography Demo
// Real ML-KEM-768 (NIST FIPS 203) key encapsulation

fn main() {
    print("═══════════════════════════════════════════")
    print("  Tallow PQC Crypto — ML-KEM-768 Demo")
    print("═══════════════════════════════════════════")
    print("")

    // Generate a real ML-KEM-768 keypair
    let kp = KeyPair.generate()
    print("Algorithm: {kp.algo}")
    print("Public key:  {kp.public_key.len} bytes")
    print("Secret key:  {kp.secret_key.len} bytes")

    // Show first few bytes of public key as hex
    let pk_hex = kp.public_key.hex()
    let preview = pk_hex.slice(0, 40)
    print("Public key hex (first 20 bytes): {preview}...")

    print("")
    print("── Key Encapsulation ──────────────────────")

    // Sender: encapsulate a shared secret using the public key
    let enc = kp.encapsulate()
    let ciphertext = enc.ciphertext
    let sender_secret = enc.shared_secret

    print("Ciphertext:     {ciphertext.len} bytes")
    print("Shared secret:  {sender_secret.len} bytes")
    print("Sender secret:  {sender_secret.hex()}")

    print("")
    print("── Key Decapsulation ─────────────────────")

    // Receiver: decapsulate using the secret key
    let receiver_secret = kp.decapsulate(ciphertext)
    print("Receiver secret: {receiver_secret.hex()}")

    // Verify both sides derived the same key
    let match_result = if sender_secret.hex() == receiver_secret.hex() {
        "MATCH — both parties share the same secret key"
    } else {
        "MISMATCH — key agreement failed"
    }
    print("")
    print("Result: {match_result}")

    print("")
    print("═══════════════════════════════════════════")
    print("  Post-quantum secure key exchange complete")
    print("  Ready for AES-256 symmetric encryption")
    print("═══════════════════════════════════════════")
}
