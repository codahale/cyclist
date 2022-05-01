use aead::{Aead, NewAead, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use sha2::{Digest, Sha256};

use cyclist::keccak::{K12Hash, K12Keyed, KeccakHash, KeccakKeyed, M14Hash, M14Keyed};
use cyclist::xoodoo::{XoodyakHash, XoodyakKeyed};

const MB: usize = 1024 * 1024;

fn hash_benchmarks(c: &mut Criterion) {
    let mut hashing = c.benchmark_group("hash");
    hashing.throughput(Throughput::Bytes(MB as u64));
    hashing.bench_with_input("xoodyak", &[0u8; MB], |b, block| {
        b.iter(|| {
            let mut st = XoodyakHash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    hashing.bench_with_input("keccak", &[0u8; MB], |b, block| {
        b.iter(|| {
            let mut st = KeccakHash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    hashing.bench_with_input("k12", &[0u8; MB], |b, block| {
        b.iter(|| {
            let mut st = K12Hash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    hashing.bench_with_input("m14", &[0u8; MB], |b, block| {
        b.iter(|| {
            let mut st = M14Hash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    hashing.bench_with_input("sha256", &[0u8; MB], |b, block| {
        b.iter(|| {
            let mut digest = Sha256::default();
            digest.update(block);
            digest.finalize()
        })
    });
    hashing.finish();
}

fn aead_benchmarks(c: &mut Criterion) {
    let mut aead = c.benchmark_group("aead");
    aead.throughput(Throughput::Bytes(MB as u64));
    aead.bench_with_input("xoodyak", &[0u8; MB], |b, block| {
        b.iter(|| {
            let mut st = XoodyakKeyed::new(&[0u8; 32], None, None, None);
            st.seal(block)
        })
    });
    aead.bench_with_input("keccak", &[0u8; MB], |b, block| {
        b.iter(|| {
            let mut st = KeccakKeyed::new(&[0u8; 32], None, None, None);
            st.seal(block)
        })
    });
    aead.bench_with_input("k12", &[0u8; MB], |b, block| {
        b.iter(|| {
            let mut st = K12Keyed::new(&[0u8; 32], None, None, None);
            st.seal(block)
        })
    });
    aead.bench_with_input("m14", &[0u8; MB], |b, block| {
        b.iter(|| {
            let mut st = M14Keyed::new(&[0u8; 32], None, None, None);
            st.seal(block)
        })
    });
    aead.bench_with_input("chacha20poly1305", &[0u8; MB], |b, block| {
        let k = [7u8; 32];
        let n = [8u8; 12];
        b.iter(|| {
            let chacha = ChaCha20Poly1305::new(&k.into());
            chacha.encrypt(
                &n.into(),
                Payload {
                    msg: block,
                    aad: &[],
                },
            )
        })
    });
    aead.bench_with_input("aes-256-gcm", &[0u8; MB], |b, block| {
        let k = [7u8; 32];
        let n = [8u8; 12];
        b.iter(|| {
            let chacha = Aes256Gcm::new(&k.into());
            chacha.encrypt(
                &n.into(),
                Payload {
                    msg: block,
                    aad: &[],
                },
            )
        })
    });
    aead.finish();
}

criterion_group!(benches, hash_benchmarks, aead_benchmarks);
criterion_main!(benches);
