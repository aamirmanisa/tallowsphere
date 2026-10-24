//! OPAQUE (RFC 9807) via `opaque-ke` — the real augmented PAKE, replacing the
//! Argon2id + Ed25519 envelope that used to answer to `crypto.opaque_*`.
//!
//! # Shape of the surface
//!
//! OPAQUE is a message-passing protocol, so the language surface is too: each
//! step takes the previous message (hex) and returns the next message plus the
//! opaque state it must carry forward. States and messages are serialized as
//! JSON and hex-encoded, because the runtime has no byte-buffer value; the JSON
//! is internal to this module and never crosses the wire.
//!
//! Registration:  start → respond → finish → server_finish
//! Login:         start → respond → finish → server_finish
//!
//! # Ciphersuite
//!
//! OPRF and key exchange over ristretto255 with TripleDH/SHA-512 — the crate's
//! default pairing, which is what its test vectors and examples use.
//!
//! The key-stretching function is `Identity`: OPAQUE's KSF runs client-side on
//! the password before the OPRF, so this is a hardening parameter, not a
//! correctness one. A memory-hard KSF (Argon2id) belongs here before this is
//! used against a real credential store; it is called out in the plan rather
//! than silently defaulted, because changing it later invalidates every
//! registration record.

use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand_core_06::OsRng;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct Cs;

impl CipherSuite for Cs {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

fn enc<T: Serialize>(v: &T, what: &str) -> Result<String, String> {
    serde_json::to_vec(v)
        .map(|b| hex(&b))
        .map_err(|e| format!("opaque: serializing {what}: {e}"))
}

fn dec<T: DeserializeOwned>(s: &str, what: &str) -> Result<T, String> {
    let bytes = unhex(s)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("opaque: parsing {what}: {e}"))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.len() % 2 != 0 {
        return Err("opaque: hex input has an odd length".into());
    }
    let b = t.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char)
            .to_digit(16)
            .ok_or_else(|| "opaque: invalid hex digit".to_string())?;
        let lo = (b[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| "opaque: invalid hex digit".to_string())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Fresh server setup (the OPRF seed + keypair). Production keeps this in an
/// HSM; this surface returns it so a deployment can wrap it immediately.
pub fn setup_new() -> Result<String, String> {
    let setup = ServerSetup::<Cs>::new(&mut OsRng);
    enc(&setup, "server setup")
}

pub fn registration_start(password: &str) -> Result<(String, String), String> {
    let start = ClientRegistration::<Cs>::start(&mut OsRng, password.as_bytes())
        .map_err(|e| format!("opaque: registration start failed: {e:?}"))?;
    Ok((enc(&start.message, "registration request")?, enc(&start.state, "client state")?))
}

pub fn registration_respond(
    setup_hex: &str,
    request_hex: &str,
    credential_id: &str,
) -> Result<(String, String), String> {
    let setup: ServerSetup<Cs> = dec(setup_hex, "server setup")?;
    let request: RegistrationRequest<Cs> = dec(request_hex, "registration request")?;
    let start = ServerRegistration::<Cs>::start(&setup, request, credential_id.as_bytes())
        .map_err(|e| format!("opaque: registration respond failed: {e:?}"))?;
    Ok((enc(&start.message, "registration response")?, String::new()))
}

pub fn registration_finish(
    state_hex: &str,
    password: &str,
    response_hex: &str,
) -> Result<(String, String), String> {
    let state: ClientRegistration<Cs> = dec(state_hex, "client state")?;
    let response: RegistrationResponse<Cs> = dec(response_hex, "registration response")?;
    let finish = state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| format!("opaque: registration finish failed: {e:?}"))?;
    Ok((
        enc(&finish.message, "registration upload")?,
        hex(&finish.export_key),
    ))
}

/// The server stores this record, keyed by credential identifier.
pub fn registration_server_finish(upload_hex: &str) -> Result<String, String> {
    let upload: RegistrationUpload<Cs> = dec(upload_hex, "registration upload")?;
    let record = ServerRegistration::<Cs>::finish(upload);
    enc(&record, "registration record")
}

pub fn login_start(password: &str) -> Result<(String, String), String> {
    let start = ClientLogin::<Cs>::start(&mut OsRng, password.as_bytes())
        .map_err(|e| format!("opaque: login start failed: {e:?}"))?;
    Ok((
        enc(&start.message, "credential request")?,
        enc(&start.state, "client login state")?,
    ))
}

pub fn login_respond(
    setup_hex: &str,
    record_hex: &str,
    request_hex: &str,
    credential_id: &str,
) -> Result<(String, String), String> {
    let setup: ServerSetup<Cs> = dec(setup_hex, "server setup")?;
    let record: ServerRegistration<Cs> = dec(record_hex, "registration record")?;
    let request: CredentialRequest<Cs> = dec(request_hex, "credential request")?;
    let start = ServerLogin::start(
        &mut OsRng,
        &setup,
        Some(record),
        request,
        credential_id.as_bytes(),
        ServerLoginParameters::default(),
    )
    .map_err(|e| format!("opaque: login respond failed: {e:?}"))?;
    Ok((
        enc(&start.message, "credential response")?,
        enc(&start.state, "server login state")?,
    ))
}

pub fn login_finish(
    state_hex: &str,
    password: &str,
    response_hex: &str,
) -> Result<(String, String, String), String> {
    let state: ClientLogin<Cs> = dec(state_hex, "client login state")?;
    let response: CredentialResponse<Cs> = dec(response_hex, "credential response")?;
    let finish = state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|e| format!("opaque: login finish failed: {e:?}"))?;
    Ok((
        enc(&finish.message, "credential finalization")?,
        hex(&finish.session_key),
        hex(&finish.export_key),
    ))
}

pub fn login_server_finish(state_hex: &str, finalization_hex: &str) -> Result<String, String> {
    let state: ServerLogin<Cs> = dec(state_hex, "server login state")?;
    let finalization: CredentialFinalization<Cs> = dec(finalization_hex, "credential finalization")?;
    let finish = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|e| format!("opaque: server login finish failed: {e:?}"))?;
    Ok(hex(&finish.session_key))
}

/// Ciphersuite description, so a caller can record what a credential was
/// registered under (changing it invalidates every record).
pub fn suite_name() -> &'static str {
    "OPAQUE(ristretto255, TripleDH/SHA-512, KSF=Identity) — RFC 9807"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(password: &str, cred: &str) -> (String, String) {
        let setup = setup_new().expect("setup");
        let (req, cstate) = registration_start(password).expect("reg start");
        let (resp, _) = registration_respond(&setup, &req, cred).expect("reg respond");
        let (upload, _export_key) =
            registration_finish(&cstate, password, &resp).expect("reg finish");
        let record = registration_server_finish(&upload).expect("record");
        (setup, record)
    }

    #[test]
    fn a_full_registration_and_login_yields_the_same_session_key() {
        let password = "correct horse battery staple";
        let (setup, record) = register(password, "alice");
        let (req, cstate) = login_start(password).expect("login start");
        let (resp, sstate) = login_respond(&setup, &record, &req, "alice").expect("login respond");
        let (fin, client_key, _export) =
            login_finish(&cstate, password, &resp).expect("login finish");
        let server_key = login_server_finish(&sstate, &fin).expect("server finish");
        assert_eq!(client_key, server_key, "both ends derive the same session key");
        assert_eq!(client_key.len(), 128, "64-byte key (SHA-512) in hex");
    }

    #[test]
    fn the_wrong_password_fails_at_the_client() {
        let (setup, record) = register("right", "bob");
        let (req, cstate) = login_start("wrong").expect("login start");
        let (resp, _sstate) = login_respond(&setup, &record, &req, "bob").expect("respond");
        let err = login_finish(&cstate, "wrong", &resp);
        assert!(err.is_err(), "a wrong password must not produce a session key");
    }

    #[test]
    fn a_record_from_a_different_setup_cannot_complete_a_login() {
        // The server may hand back a response (it holds no MAC to check yet);
        // what must fail is the client's verification of it, or the server's
        // final check. Accept either, but the session must not be established.
        let (_setup_a, record_a) = register("pw", "carol");
        let setup_b = setup_new().expect("setup b");
        let (req, cstate) = login_start("pw").expect("login start");
        let Ok((resp, sstate)) = login_respond(&setup_b, &record_a, &req, "carol") else {
            return; // rejected at the server: also a pass
        };
        let client = login_finish(&cstate, "pw", &resp);
        match client {
            Err(_) => {}
            Ok((fin, client_key, _)) => {
                let server = login_server_finish(&sstate, &fin);
                assert!(
                    server.is_err(),
                    "a foreign record must not yield a matching session key                      (client {client_key})"
                );
            }
        }
    }
}
