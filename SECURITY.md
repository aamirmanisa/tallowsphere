# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

Use GitHub's private vulnerability reporting — it is the only reporting channel:

https://github.com/aamirmanisa/tallowsphere/security/advisories/new

1. Go to the Security tab of this repository
2. Click "Report a vulnerability"
3. Fill in the details

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 72 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**:
  - Critical: 7 days
  - High: 30 days
  - Medium: 90 days
  - Low: Next release

### Disclosure Policy

We follow coordinated disclosure with a 90-day embargo period. After 90 days, or after a fix is released (whichever comes first), the vulnerability details will be published.

### Scope

In scope:
- Tallow compiler (lexer, parser, type checker, codegen, interpreter)
- All compiler passes (legal, privacy, agent, safety, etc.)
- Package manager (resolver, registry client, archive handling)
- Browser automation module (CDP client, session management)
- TallowTransfer (QUIC, encryption, erasure coding)
- Cryptographic implementations
- LSP server

Out of scope:
- Third-party dependencies (report to upstream maintainers)
- Social engineering
- Denial of service via resource exhaustion (compile-time bombs)

### Recognition

Security researchers who responsibly disclose vulnerabilities will be credited in the advisory and release notes (unless they prefer anonymity).

## Cryptography Notice

Tallow includes cryptographic software:
- AES-256-GCM (via aes-gcm crate)
- ChaCha20-Poly1305 (via chacha20poly1305 crate)
- BLAKE3 (via blake3 crate)
- Argon2id (via argon2 crate)
- Ed25519 (via ed25519-dalek crate)
- X25519 (via x25519-dalek crate)
- ML-KEM (via ml-kem crate)
- ML-DSA (via ml-dsa crate)

This software may be subject to export controls. See LICENSE for details.
