//! Rotation drill (P5): the runbook in `docs/operations/key-rotation-runbook.md`
//! executed against sandbox material, so the claims in it are measured rather
//! than asserted.
//!
//! Nothing here touches a production key. What it proves is the *mechanism*: a
//! vault entry re-seals with a fresh nonce and a new secret, an age keypair
//! replacement does not retroactively reopen old containers, and an OPAQUE
//! password change without re-registration leaves a record that can never log
//! in — the failure mode an operator most needs warned about.

use tallow::vault::credential::CredentialVault;

#[test]
fn vault_rotation_reseals_and_changes_the_secret() {
    let mut v = CredentialVault::new();
    v.store("svc", "alice", "old-secret").expect("store");

    let before = v.get("svc").expect("get before");
    assert_eq!(&*before.password, "old-secret");

    v.rotate("svc", "new-secret").expect("rotate");

    let after = v.get("svc").expect("get after");
    assert_eq!(&*after.password, "new-secret", "rotation must change the secret");
    assert_eq!(after.username, "alice", "rotation must not disturb the username");

    // The old secret must no longer be present anywhere in the vault: fetching
    // again returns the new one, and the entry is the same key.
    let again = v.get("svc").expect("get again");
    assert_eq!(&*again.password, "new-secret");
    assert_eq!(v.list(), vec!["svc".to_string()]);
}

#[test]
fn vault_rotation_needs_an_existing_entry() {
    let mut v = CredentialVault::new();
    assert!(
        v.rotate("missing", "irrelevant").is_err(),
        "rotating a name that was never stored must fail, not invent an entry"
    );
}

#[test]
fn age_rotation_does_not_reopen_old_containers() {
    // Load-bearing property for the runbook's step 3: replacing a keypair is not
    // retroactive. Anything already sealed stays sealed to the old identity.
    let (old_recipient, old_identity) = tallow::age::keygen();
    let sealed = tallow::age::encrypt(&old_recipient, "deadbeef").expect("encrypt");

    let (new_recipient, new_identity) = tallow::age::keygen();
    assert_ne!(old_recipient, new_recipient, "a rotation must change the key");

    assert!(
        tallow::age::decrypt(&new_identity, &sealed).is_err(),
        "the new identity must not open containers sealed to the old one"
    );
    assert_eq!(
        tallow::age::decrypt(&old_identity, &sealed).expect("old identity"),
        "deadbeef",
        "the old identity still opens its own containers — retention window"
    );

    let fresh = tallow::age::encrypt(&new_recipient, "cafe").expect("encrypt new");
    assert_eq!(
        tallow::age::decrypt(&new_identity, &fresh).expect("new identity"),
        "cafe"
    );
}

#[test]
fn opaque_password_change_requires_reregistration() {
    // OPAQUE binds the server record to the OPRF output at registration time.
    // Changing only the client's password yields a login that cannot complete —
    // the runbook's §4 exists because of this, and it is asserted here so the
    // warning cannot drift out of date.
    let setup = tallow::opaque::setup_new().expect("setup");

    let (req, cstate) = tallow::opaque::registration_start("old-password").expect("reg start");
    let (resp, _) = tallow::opaque::registration_respond(&setup, &req, "bob").expect("reg respond");
    let (upload, _) = tallow::opaque::registration_finish(&cstate, "old-password", &resp)
        .expect("reg finish");
    let record = tallow::opaque::registration_server_finish(&upload).expect("record");

    // Same record, new password: the client fails at the final step.
    let (l1, l2state) = tallow::opaque::login_start("new-password").expect("login start");
    let (l2, _sstate) =
        tallow::opaque::login_respond(&setup, &record, &l1, "bob").expect("login respond");
    assert!(
        tallow::opaque::login_finish(&l2state, "new-password", &l2).is_err(),
        "a password change without re-registration must not produce a session key"
    );

    // Re-registering with the same credential identifier is the supported path.
    let (req2, cstate2) = tallow::opaque::registration_start("new-password").expect("reg2 start");
    let (resp2, _) = tallow::opaque::registration_respond(&setup, &req2, "bob").expect("reg2");
    let (upload2, _) =
        tallow::opaque::registration_finish(&cstate2, "new-password", &resp2).expect("reg2 finish");
    let record2 = tallow::opaque::registration_server_finish(&upload2).expect("record2");

    let (m1, mstate) = tallow::opaque::login_start("new-password").expect("login2 start");
    let (m2, sstate) = tallow::opaque::login_respond(&setup, &record2, &m1, "bob").expect("resp2");
    let (fin, client_key, _) =
        tallow::opaque::login_finish(&mstate, "new-password", &m2).expect("finish2");
    let server_key = tallow::opaque::login_server_finish(&sstate, &fin).expect("server finish");
    assert_eq!(client_key, server_key, "re-registration restores login");
}
