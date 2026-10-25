# Key rotation — runbook and rehearsal

Scope: every long-lived key class the crypto-integration plan introduces, plus
the credential vault that already exists. The drill is executed by
`tests/rotation_drill.rs` against a sandbox; no production key is touched by the
test.

## 1. Row of key classes

| Class | Where it lives | Rotation is | Evidence |
|---|---|---|---|
| Credential vault entries | `src/vault/credential.rs` (ChaCha20-Poly1305, per-process key + OS random nonce) | **In place**: `rotate(name, new_password)` re-seals with a fresh nonce and the new secret | `tests/rotation_drill.rs::vault_rotation_reseals_and_changes_the_secret` |
| age identity / recipient | `src/age.rs` (X25519, C2SP age) | **Replace the keypair.** Nothing re-encrypts old containers: anything already sealed stays readable by the old identity, which is exactly what "rotation" means for an asymmetric key | `tests/rotation_drill.rs::age_rotation_does_not_reopen_old_containers` |
| OPAQUE credential (RFC 9807) | `src/opaque.rs` | **Re-register.** OPAQUE has no in-place password update in this implementation; the server record is bound to the OPRF output at registration. A "rotate" that only changes the client's password produces a record that can never log in | `tests/rotation_drill.rs::opaque_password_change_requires_reregistration` |
| MLS group keys | `src/mls.rs` | **Epoch-driven**: adding/removing a member or committing advances the epoch and derives new keys automatically. No manual rotation exists or is wanted | `examples/mls_probe.rs` (epoch 0 → 1 on add) |
| Release signing | operator-held | Out of scope for an automated drill: it needs the production signing key and an operator present | — |

## 2. Procedure (credential vault)

1. Take the entry name and the new secret from the operator's secret store —
   **never from argv** (argv is world-readable in `/proc`).
2. `CredentialVault::rotate(name, new_secret)`.
3. Verify: `get(name)` returns the new secret; the old secret fails against the
   live service.
4. Record the event in the audit log with the entry name and a timestamp — not
   the secret, and not a hash of it.

## 3. Procedure (age identity)

1. Generate a new keypair (`crypto.age_keygen`).
2. Publish the new recipient to every sender.
3. Keep the old identity available for the retention window so existing
   containers remain readable; then destroy it.
4. Re-encrypt anything that must survive the old identity's destruction.

## 4. Procedure (OPAQUE)

1. Delete the old server record.
2. Run the registration flow again with the same credential identifier.
3. Old sessions are unaffected (they hold a session key, not the record).

## 5. What this runbook does **not** claim

It has not been executed against production keys. The drill proves the
mechanisms behave as described on a sandbox; a production rotation still needs
the operator's secrets and their confirmation that the downstream service
accepted the new credential.
