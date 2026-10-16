//! Protocol-level benchmarks (P1): transfer AEAD throughput + wire routing cost.
//!
//! Baselines for the optimization roadmap: chunk encryption/decryption MB/s
//! and the relay routing path's decode + re-encode cost for `Targeted` frames
//! (the cost center the zero-copy routing work will remove).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tallow_crypto::file::{decrypt_chunk_scoped, derive_transfer_subkey, encrypt_chunk_scoped};
use tallow_crypto::CipherSuite;
use tallow_protocol::wire::Message;

const SIZES: &[usize] = &[4 * 1024, 64 * 1024, 1024 * 1024, 4 * 1024 * 1024];

fn bench_transfer_aead(c: &mut Criterion) {
    let session_key = [7u8; 32];
    let transfer_id = [3u8; 16];
    // Sanity-check the subkey derivation path once (not timed).
    let _subkey = derive_transfer_subkey(&session_key, &transfer_id);

    let mut group = c.benchmark_group("transfer_aead");
    for &size in SIZES {
        let data = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt_scoped", size),
            &data,
            |b, data| {
                b.iter(|| {
                    encrypt_chunk_scoped(
                        &session_key,
                        &transfer_id,
                        data,
                        0,
                        CipherSuite::Aes256Gcm,
                    )
                    .expect("encrypt")
                })
            },
        );
        let enc =
            encrypt_chunk_scoped(&session_key, &transfer_id, &data, 0, CipherSuite::Aes256Gcm)
                .expect("encrypt");
        group.bench_with_input(BenchmarkId::new("decrypt_scoped", size), &enc, |b, enc| {
            b.iter(|| {
                decrypt_chunk_scoped(&session_key, &transfer_id, enc, CipherSuite::Aes256Gcm)
                    .expect("decrypt")
            })
        });
    }
    group.finish();
}

fn bench_wire_targeted(c: &mut Criterion) {
    let payload = vec![0x5Au8; 4 * 1024 * 1024];
    let msg = Message::Targeted {
        from_peer: 1,
        to_peer: 2,
        payload,
    };
    let encoded = postcard::to_stdvec(&msg).expect("encode");

    let mut group = c.benchmark_group("wire_targeted_4mib");
    group.throughput(Throughput::Bytes(encoded.len() as u64));
    group.bench_function("encode", |b| {
        b.iter(|| postcard::to_stdvec(&msg).expect("encode"))
    });
    group.bench_function("decode", |b| {
        b.iter(|| postcard::from_bytes::<Message>(&encoded).expect("decode"))
    });
    group.bench_function("decode_reencode", |b| {
        b.iter(|| {
            let decoded = postcard::from_bytes::<Message>(&encoded).expect("decode");
            postcard::to_stdvec(&decoded).expect("encode")
        })
    });
    group.finish();
}

fn bench_room_id(c: &mut Criterion) {
    use tallow_protocol::room::code::{
        derive_room_id_v2, generate_passcode, is_v3_passcode, resolve_room_id,
    };

    let code = "K7M2QP";
    let mut group = c.benchmark_group("room_id");

    // Argon2id at Profile::Room (64 MiB / t=3 / p=1) — ~0.25 s native, so few
    // samples on purpose: this bench is for documentation of the cost, not for
    // tight confidence intervals.
    group.sample_size(10);
    group.bench_function("derive_room_id_v2_argon2id", |b| {
        b.iter(|| derive_room_id_v2(black_box(code)));
    });
    group.bench_function("resolve_room_id_v3", |b| {
        b.iter(|| resolve_room_id(black_box(code)));
    });

    // Cheap shape checks — full sample count.
    group.sample_size(100);
    group.bench_function("is_v3_passcode", |b| {
        b.iter(|| is_v3_passcode(black_box(code)));
    });
    group.bench_function("generate_passcode", |b| {
        b.iter(generate_passcode);
    });

    group.finish();
}

/// The composed handshake a user actually waits for: CPace (initiator +
/// responder) mixed with the hybrid ML-KEM-1024 + X25519 KEM, over the full
/// `HandshakeInit → HandshakeResponse → HandshakeKem` round trip.
fn bench_handshake(c: &mut Criterion) {
    use tallow_protocol::kex::{ReceiverHandshake, SenderHandshake};
    use tallow_protocol::room::code::derive_room_id_v2;

    let phrase = "K7M2QP";
    let room_id = derive_room_id_v2(phrase);

    let mut group = c.benchmark_group("handshake");
    group.sample_size(10);
    group.bench_function("full_roundtrip_cpace_hybrid_kem", |b| {
        b.iter(|| {
            let mut sender = SenderHandshake::new(phrase, &room_id);
            let mut receiver = ReceiverHandshake::new(phrase, &room_id);

            let init = sender.init().expect("init");
            let (protocol_version, suite_code, kem_capabilities, cpace_public, sender_nonce) =
                match init {
                    Message::HandshakeInit {
                        protocol_version,
                        suite_code,
                        kem_capabilities,
                        cpace_public,
                        nonce,
                    } => (
                        protocol_version,
                        suite_code,
                        kem_capabilities,
                        cpace_public,
                        nonce,
                    ),
                    other => panic!("expected HandshakeInit, got {other:?}"),
                };

            let response = receiver
                .process_init(
                    protocol_version,
                    // v8 (checklist 5.2): the suite code the initiator declared, refused if
                    // unknown. Carried through from the init rather than defaulted — a bench
                    // that hard-codes it would measure a handshake the wire never performs.
                    suite_code,
                    &kem_capabilities,
                    &cpace_public,
                    &sender_nonce,
                )
                .expect("process_init");
            let (selected_kem, resp_cpace, resp_kem_pk, resp_nonce) = match response {
                Message::HandshakeResponse {
                    selected_kem,
                    cpace_public,
                    kem_public_key,
                    nonce,
                } => (selected_kem, cpace_public, kem_public_key, nonce),
                other => panic!("expected HandshakeResponse, got {other:?}"),
            };

            let (kem_msg, _sender_key) = sender
                .process_response(selected_kem, &resp_cpace, &resp_kem_pk, &resp_nonce)
                .expect("process_response");
            let (kem_ciphertext, confirmation) = match kem_msg {
                Message::HandshakeKem {
                    kem_ciphertext,
                    confirmation,
                } => (kem_ciphertext, confirmation),
                other => panic!("expected HandshakeKem, got {other:?}"),
            };

            receiver
                .process_kem(&kem_ciphertext, &confirmation)
                .expect("process_kem")
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_transfer_aead,
    bench_wire_targeted,
    bench_room_id,
    bench_handshake
);
criterion_main!(benches);
