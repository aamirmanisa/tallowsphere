//! Cryptography benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use tallow_crypto::{
    hash::blake3,
    kem::{mlkem::MlKem, x25519::X25519KeyPair},
    symmetric::{aes_encrypt, chacha_encrypt},
};

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash/blake3");

    for size in [1024, 65536, 1048576] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("{} bytes", size), &data, |b, data| {
            b.iter(|| blake3::hash(black_box(data)));
        });
    }

    group.finish();
}

fn bench_aes_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric/aes-gcm");
    let key = [0u8; 32];
    let nonce = [1u8; 12];

    for size in [1024, 65536, 1048576] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("{} bytes", size), &data, |b, data| {
            b.iter(|| aes_encrypt(black_box(&key), &nonce, black_box(data), &[]));
        });
    }

    group.finish();
}

fn bench_chacha20(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric/chacha20");
    let key = [0u8; 32];
    let nonce = [1u8; 12];

    for size in [1024, 65536, 1048576] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("{} bytes", size), &data, |b, data| {
            b.iter(|| chacha_encrypt(black_box(&key), &nonce, black_box(data), &[]));
        });
    }

    group.finish();
}

fn bench_mlkem(c: &mut Criterion) {
    let mut group = c.benchmark_group("kem/ml-kem-1024");

    group.bench_function("keygen", |b| {
        b.iter(|| MlKem::keygen().unwrap());
    });

    let (pk, sk) = MlKem::keygen().unwrap();

    group.bench_function("encapsulate", |b| {
        b.iter(|| MlKem::encapsulate(black_box(&pk)));
    });

    let (ct, _ss) = MlKem::encapsulate(&pk).unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| MlKem::decapsulate(black_box(&sk), black_box(&ct)));
    });

    group.finish();
}

fn bench_x25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("kem/x25519");

    group.bench_function("keygen", |b| {
        b.iter(X25519KeyPair::generate);
    });

    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    group.bench_function("diffie-hellman", |b| {
        b.iter(|| alice.diffie_hellman(black_box(bob.public_key())).unwrap());
    });

    group.finish();
}

fn bench_file_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("file/encryption");
    let key = [0u8; 32];

    for chunk_size in [65536, 262144, 1048576] {
        let data = vec![0u8; chunk_size];
        group.throughput(Throughput::Bytes(chunk_size as u64));
        group.bench_with_input(format!("{} byte chunks", chunk_size), &data, |b, data| {
            b.iter(|| {
                tallow_crypto::file::encrypt_chunk(
                    black_box(&key),
                    black_box(data),
                    0,
                    tallow_crypto::symmetric::CipherSuite::Aes256Gcm,
                )
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_blake3,
    bench_aes_gcm,
    bench_chacha20,
    bench_mlkem,
    bench_x25519,
    bench_file_encryption
);
criterion_main!(benches);
