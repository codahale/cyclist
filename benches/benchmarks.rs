use aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use sha2::{Digest, Sha256, Sha512};

use cyclist::keccak::{
    K12Hash, K12Keyed, Keccak, KeccakHash, KeccakKeyed, M14Hash, M14Keyed, K12, M14,
};
use cyclist::xoodoo::{Xoodoo, XoodyakHash, XoodyakKeyed, Xoofff};
use cyclist::Permutation;

const INPUT: usize = 100 * 1024;

fn hash_benchmarks(c: &mut Criterion) {
    let mut hashing = c.benchmark_group("hash");
    hashing.throughput(Throughput::Bytes(INPUT as u64));

    hashing.bench_with_input("xoodyak", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = XoodyakHash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    hashing.bench_with_input("keccak", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = KeccakHash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    hashing.bench_with_input("sha256", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut digest = Sha256::default();
            digest.update(block);
            digest.finalize()
        })
    });
    hashing.bench_with_input("sha512", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut digest = Sha512::default();
            digest.update(block);
            digest.finalize()
        })
    });
    hashing.bench_with_input("m14", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = M14Hash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    hashing.bench_with_input("k12", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = K12Hash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    hashing.finish();
}

fn aead_benchmarks(c: &mut Criterion) {
    let mut aead = c.benchmark_group("aead");
    aead.throughput(Throughput::Bytes(INPUT as u64));
    aead.bench_with_input("aes-256-gcm", &[0u8; INPUT], |b, block| {
        let k = [7u8; 32];
        let n = [8u8; 12];
        b.iter(|| {
            let aes = Aes256Gcm::new(&k.into());
            aes.encrypt(
                &n.into(),
                Payload {
                    msg: block,
                    aad: &[],
                },
            )
        })
    });
    aead.bench_with_input("aes-128-gcm", &[0u8; INPUT], |b, block| {
        let k = [7u8; 16];
        let n = [8u8; 12];
        b.iter(|| {
            let aes = Aes128Gcm::new(&k.into());
            aes.encrypt(
                &n.into(),
                Payload {
                    msg: block,
                    aad: &[],
                },
            )
        })
    });
    aead.bench_with_input("chacha20poly1305", &[0u8; INPUT], |b, block| {
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
    aead.bench_with_input("xoodyak", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = XoodyakKeyed::new(&[0u8; 32], None, None, None);
            st.seal(block)
        })
    });
    aead.bench_with_input("keccak", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = KeccakKeyed::new(&[0u8; 32], None, None, None);
            st.seal(block)
        })
    });
    aead.bench_with_input("m14", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = M14Keyed::new(&[0u8; 32], None, None, None);
            st.seal(block)
        })
    });
    aead.bench_with_input("k12", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = K12Keyed::new(&[0u8; 32], None, None, None);
            st.seal(block)
        })
    });
    aead.finish();
}

fn permutation_benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("permutation");
    g.throughput(Throughput::Bytes(200));
    g.bench_function("keccak", |b| {
        let mut state = Keccak::new_state();
        b.iter(|| {
            Keccak::permute(&mut state);
        })
    });
    g.bench_function("m14", |b| {
        let mut state = M14::new_state();
        b.iter(|| {
            M14::permute(&mut state);
        })
    });
    g.bench_function("k12", |b| {
        let mut state = K12::new_state();
        b.iter(|| {
            K12::permute(&mut state);
        })
    });
    g.throughput(Throughput::Bytes(48));
    g.bench_function("xoodoo", |b| {
        let mut state = Xoodoo::new_state();
        b.iter(|| {
            Xoodoo::permute(&mut state);
        })
    });
    g.bench_function("xoofff", |b| {
        let mut state = Xoofff::new_state();
        b.iter(|| {
            Xoofff::permute(&mut state);
        })
    });
    g.finish();
}

criterion_group!(
    benches,
    hash_benchmarks,
    aead_benchmarks,
    permutation_benchmarks
);
criterion_main!(benches);
