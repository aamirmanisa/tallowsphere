// Privacy types: `private` and `secret`.
//
// A `private` value (Email, Phone, SSN, ... or any `type X = private T`) may
// not be printed, logged, or interpolated raw — it must pass through
// .redact(), .hash(), or .mask() first. A `secret` value (Password, Token,
// ... or `type X = secret T`) may never appear in a string at all.
//
// The failing counterparts live in tests/fixtures/privacy_invalid.tl.
//
// Run: tallow run examples/privacy_valid.tl

type Email = private String

fn log_user(email: Email) {
    // Raw print(email) would be a compile error; this is the safe path.
    print(email.redact())
}

fn main() {
    print("=== private type ===")

    let contact = "user@example.com" as Email
    log_user(contact)

    // Each transform returns a safe String.
    print("hash: {contact.hash()}")
    print("mask: {contact.mask()}")

    print("=== built-in private types ===")

    let phone: Phone = "555-0100" as Phone
    let ip: IPAddress = "10.0.0.7" as IPAddress
    print("phone: {phone.mask()}")
    print("ip:    {ip.redact()}")

    print("=== secret values ===")

    // A secret is usable, but only through redaction/hashing — it can never
    // be interpolated directly.
    let pw = "correct horse battery staple" as Password
    print("redacted: {pw.redact()}")
    print("hash:     {pw.hash()}")
}
