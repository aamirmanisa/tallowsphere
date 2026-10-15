//! Protocol-level benchmarks (P1): transfer AEAD throughput + wire routing cost.
//!
//! Baselines for the optimization roadmap: chunk encryption/decryption MB/s
//! and the relay routing path's decode + re-encode cost for `Targeted` frames
//! (the cost center the zero-copy routing work will remove).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
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

criterion_group!(benches, bench_transfer_aead, bench_wire_targeted);
criterion_main!(benches);
