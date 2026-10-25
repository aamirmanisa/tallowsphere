//! MLS (RFC 9420) via `openmls` — group messaging with forward secrecy.
//!
//! # Scope, stated precisely
//!
//! This is a **single-process group registry**: a group lives in memory for the
//! life of the runtime and is addressed by handle. Serializing an MLS group and
//! its key material across processes is a separate problem (it needs the
//! provider's key store, not just the group object), and pretending otherwise
//! would produce a handle that silently fails later. Cross-process persistence is
//! listed as open in the plan, not faked here.
//!
//! # What is implemented
//!
//! Key packages, group creation, adding a member, joining from a Welcome,
//! application messages, and epoch tracking — the core of MLS. Ciphersuite is
//! the openmls default for the RustCrypto provider.

use std::collections::HashMap;
use std::sync::Mutex;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;

type Provider = OpenMlsRustCrypto;

struct Member {
    provider: Provider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    group: MlsGroup,
}

static REGISTRY: Mutex<Option<HashMap<String, Member>>> = Mutex::new(None);

/// Members that have published a key package but not yet joined a group.
/// The provider has to be the *same* one that created the key package: the
/// private keys for the advertised package live in its storage, and a fresh
/// provider cannot complete the Welcome (openmls reports `NoMatchingKeyPackage`).
type Pending = (Provider, SignatureKeyPair, CredentialWithKey);

static PENDING: Mutex<Option<HashMap<String, Pending>>> = Mutex::new(None);

fn pending_registry<T>(f: impl FnOnce(&mut HashMap<String, Pending>) -> T) -> T {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn ciphersuite() -> Ciphersuite {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
}

fn registry<T>(f: impl FnOnce(&mut HashMap<String, Member>) -> T) -> T {
    let mut guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn hex(bytes: &[u8]) -> String {
    crate::opaque::hex(bytes)
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    crate::opaque::unhex(s)
}

use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

/// A fresh credential + signing keypair for one member.
fn new_member(identity: &str) -> Result<(Provider, SignatureKeyPair, CredentialWithKey), String> {
    let provider = Provider::default();
    let signature_keys = SignatureKeyPair::new(SignatureScheme::ED25519)
        .map_err(|e| format!("mls: signature keypair: {e:?}"))?;
    signature_keys
        .store(provider.storage())
        .map_err(|e| format!("mls: storing signature key: {e:?}"))?;
    let credential = BasicCredential::new(identity.as_bytes().to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.public().into(),
    };
    Ok((provider, signature_keys, credential_with_key))
}

fn key_package(
    provider: &Provider,
    signer: &SignatureKeyPair,
    credential: &CredentialWithKey,
) -> Result<KeyPackage, String> {
    KeyPackage::builder()
        .build(ciphersuite(), provider, signer, credential.clone())
        .map(|b| b.key_package().clone())
        .map_err(|e| format!("mls: key package: {e:?}"))
}

/// Publish a key package for `identity`. Returns `(pending_handle, kp_hex)`;
/// pass the handle to `join_from_welcome` once someone adds you.
pub fn key_package_new(identity: &str) -> Result<(String, String), String> {
    let (provider, signer, credential) = new_member(identity)?;
    let kp = key_package(&provider, &signer, &credential)?;
    let handle = format!("mls-pending-{}", crate::opaque::hex(&rand_bytes(12)));
    pending_registry(|m| m.insert(handle.clone(), (provider, signer, credential)));
    Ok((
        handle,
        hex(&kp
            .tls_serialize_detached()
            .map_err(|e| format!("mls: kp encode: {e:?}"))?),
    ))
}

/// Create a group with `identity` as its only member. Returns
/// `(handle, key_package_hex)` so another party can be added.
pub fn create_group(identity: &str) -> Result<(String, String), String> {
    let (provider, signer, credential) = new_member(identity)?;
    let kp = key_package(&provider, &signer, &credential)?;

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite())
        .use_ratchet_tree_extension(true)
        .build();
    let group = MlsGroup::new(&provider, &signer, &config, credential.clone())
        .map_err(|e| format!("mls: group create: {e:?}"))?;

    let handle = format!("mls-{}", crate::opaque::hex(&rand_bytes(12)));
    registry(|m| {
        m.insert(
            handle.clone(),
            Member {
                provider,
                signer,
                credential,
                group,
            },
        )
    });
    Ok((handle, hex(&kp.tls_serialize_detached().map_err(|e| format!("mls: kp encode: {e:?}"))?)))
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand_core_06::{OsRng, RngCore};
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    b
}

/// Add a member (identified by their key package) and return the Welcome that
/// lets them join, plus the new epoch.
pub fn add_member(handle: &str, key_package_hex: &str) -> Result<(String, u64), String> {
    let kp_bytes = unhex(key_package_hex)?;
    let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())
        .map_err(|e| format!("mls: key package decode: {e:?}"))?;

    registry(|m| {
        let member = m
            .get_mut(handle)
            .ok_or_else(|| format!("mls: unknown group handle `{handle}`"))?;
        // Validation needs the crypto provider, which lives with the member.
        let kp = kp_in
            .clone()
            .validate(member.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| format!("mls: key package invalid: {e:?}"))?;
        let commit = member
            .group
            .commit_builder()
            .propose_adds(vec![kp])
            .load_psks(member.provider.storage())
            .map_err(|e| format!("mls: load psks: {e:?}"))?
            .build(
                member.provider.rand(),
                member.provider.crypto(),
                &member.signer,
                |_| true,
            )
            .map_err(|e| format!("mls: commit build: {e:?}"))?
            .stage_commit(&member.provider)
            .map_err(|e| format!("mls: stage commit: {e:?}"))?;
        member
            .group
            .merge_pending_commit(&member.provider)
            .map_err(|e| format!("mls: merge commit: {e:?}"))?;
        // `into_welcome()` returns the inner Welcome body; the wire message
        // (version + wire format + body) is what a receiver can deserialize.
        let welcome = commit
            .into_welcome_msg()
            .ok_or_else(|| "mls: commit produced no welcome".to_string())?;
        let bytes = welcome
            .tls_serialize_detached()
            .map_err(|e| format!("mls: welcome encode: {e:?}"))?;
        Ok((hex(&bytes), member.group.epoch().as_u64()))
    })
}

/// Join a group from a Welcome message, using the handle returned by
/// `key_package_new`. Returns the joined member's handle and the epoch.
pub fn join_from_welcome(pending_handle: &str, welcome_hex: &str) -> Result<(String, u64), String> {
    let (provider, signer, credential) = pending_registry(|m| m.remove(pending_handle))
        .ok_or_else(|| format!("mls: unknown pending handle `{pending_handle}`"))?;
    let bytes = unhex(welcome_hex)?;
    let welcome = MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
        .map_err(|e| format!("mls: welcome decode: {e:?}"))?;
    let welcome = match welcome.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err("mls: that message is not a Welcome".into()),
    };
    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let group = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
        .map_err(|e| format!("mls: welcome processing: {e:?}"))?
        .into_group(&provider)
        .map_err(|e| format!("mls: joining: {e:?}"))?;

    let epoch = group.epoch().as_u64();
    let handle = format!("mls-{}", crate::opaque::hex(&rand_bytes(12)));
    registry(|m| {
        m.insert(
            handle.clone(),
            Member {
                provider,
                signer,
                credential,
                group,
            },
        )
    });
    Ok((handle, epoch))
}

/// Encrypt an application message; returns the wire bytes and the epoch.
pub fn encrypt(handle: &str, plaintext_hex: &str) -> Result<(String, u64), String> {
    let pt = unhex(plaintext_hex)?;
    registry(|m| {
        let member = m
            .get_mut(handle)
            .ok_or_else(|| format!("mls: unknown group handle `{handle}`"))?;
        let out = member
            .group
            .create_message(&member.provider, &member.signer, &pt)
            .map_err(|e| format!("mls: encrypt: {e:?}"))?;
        let bytes = out
            .tls_serialize_detached()
            .map_err(|e| format!("mls: message encode: {e:?}"))?;
        Ok((hex(&bytes), member.group.epoch().as_u64()))
    })
}

/// Process an incoming message. Returns `(kind, plaintext_hex, epoch)` where kind
/// is `application` or `proposal`/`commit` for handshake messages. Handshake
/// messages are merged so the epoch advances.
pub fn process(handle: &str, message_hex: &str) -> Result<(String, String, u64), String> {
    let bytes = unhex(message_hex)?;
    let message = MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
        .map_err(|e| format!("mls: message decode: {e:?}"))?;
    registry(|m| {
        let member = m
            .get_mut(handle)
            .ok_or_else(|| format!("mls: unknown group handle `{handle}`"))?;
        let protocol = message
            .try_into_protocol_message()
            .map_err(|e| format!("mls: not a protocol message: {e:?}"))?;
        let processed = member
            .group
            .process_message(&member.provider, protocol)
            .map_err(|e| format!("mls: process: {e:?}"))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                Ok(("application".to_string(), hex(&app.into_bytes()), member.group.epoch().as_u64()))
            }
            ProcessedMessageContent::ProposalMessage(p) => {
                member
                    .group
                    .store_pending_proposal(member.provider.storage(), *p)
                    .map_err(|e| format!("mls: store proposal: {e:?}"))?;
                Ok(("proposal".to_string(), String::new(), member.group.epoch().as_u64()))
            }
            ProcessedMessageContent::StagedCommitMessage(c) => {
                member
                    .group
                    .merge_staged_commit(&member.provider, *c)
                    .map_err(|e| format!("mls: merge commit: {e:?}"))?;
                Ok(("commit".to_string(), String::new(), member.group.epoch().as_u64()))
            }
            _ => Err("mls: unsupported message content".to_string()),
        }
    })
}

/// Number of members in the group, and the current epoch.
pub fn group_info(handle: &str) -> Result<(usize, u64), String> {
    registry(|m| {
        let member = m
            .get(handle)
            .ok_or_else(|| format!("mls: unknown group handle `{handle}`"))?;
        Ok((member.group.members().count(), member.group.epoch().as_u64()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_members_exchange_an_application_message() {
        let (alice, alice_kp) = create_group("alice").expect("create");
        let (bob_pending, bob_kp) = key_package_new("bob").expect("bob kp");

        let (welcome, epoch_after_add) = add_member(&alice, &bob_kp).expect("add bob");
        assert_eq!(epoch_after_add, 1, "adding a member advances the epoch");

        let (bob, bob_epoch) = join_from_welcome(&bob_pending, &welcome).expect("join");
        assert_eq!(bob_epoch, 1);

        let (ciphertext, _) = encrypt(&alice, "68656c6c6f").expect("encrypt");
        let (kind, plaintext, _) = process(&bob, &ciphertext).expect("decrypt");
        assert_eq!(kind, "application");
        assert_eq!(plaintext, "68656c6c6f", "bob reads what alice wrote");

        let (_, epoch) = group_info(&bob).expect("info");
        assert_eq!(epoch, 1);
        let _ = alice_kp;
    }

    #[test]
    fn an_outsider_cannot_read_the_group() {
        let (alice, _) = create_group("alice").expect("create");
        let (mallory, _) = create_group("mallory").expect("mallory");
        let (ciphertext, _) = encrypt(&alice, "01").expect("encrypt");
        assert!(
            process(&mallory, &ciphertext).is_err(),
            "a member of another group must not decrypt this traffic"
        );
    }
}
