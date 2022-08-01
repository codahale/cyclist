use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_512;
use strobe_rs::{SecParam, Strobe};

use cyclist::keccyak::{
    KeccakF1600, KeccakP1600_12, KeccakP1600_14, Keccyak128Hash, Keccyak128Keyed, Keccyak256Hash,
    Keccyak256Keyed, KeccyakMaxHash, KeccyakMaxKeyed,
};
use cyclist::xoodyak::{Xoodoo, XoodyakHash, XoodyakKeyed};
use cyclist::{Cyclist, Permutation};

const INPUT: usize = 100 * 1024;

fn hash_benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash");
    g.sample_size(1_000);
    g.throughput(Throughput::Bytes(INPUT as u64));

    g.bench_with_input("Xoodyak", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = XoodyakHash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    g.bench_with_input("strobe-256", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = Strobe::new(b"example", SecParam::B256);
            st.send_clr(block, false);
            let mut mac = [0u8; 32];
            st.send_mac(&mut mac, false);
            mac
        })
    });
    g.bench_with_input("strobe-128", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = Strobe::new(b"example", SecParam::B128);
            st.send_clr(block, false);
            let mut mac = [0u8; 32];
            st.send_mac(&mut mac, false);
            mac
        })
    });
    g.bench_with_input("SHA-3", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut digest = Sha3_512::default();
            digest.update(block);
            digest.finalize()
        })
    });
    g.bench_with_input("SHA-256", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut digest = Sha256::default();
            digest.update(block);
            digest.finalize()
        })
    });
    g.bench_with_input("SHA-512", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut digest = Sha512::default();
            digest.update(block);
            digest.finalize()
        })
    });
    g.bench_with_input("KeccyakMax", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = KeccyakMaxHash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    g.bench_with_input("Keccyak256", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = Keccyak256Hash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    g.bench_with_input("Keccyak128", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = Keccyak128Hash::default();
            st.absorb(block);
            st.squeeze(32)
        })
    });
    g.finish();
}

fn aead_benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("aead");
    g.sample_size(1_000);
    g.throughput(Throughput::Bytes(INPUT as u64));
    g.bench_with_input("AES-256-GCM", &[0u8; INPUT], |b, block| {
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
    g.bench_with_input("AES-128-GCM", &[0u8; INPUT], |b, block| {
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
    g.bench_with_input("strobe-256", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = Strobe::new(b"example", SecParam::B256);
            let mut out = vec![0u8; block.len() + 16];
            out[..block.len()].copy_from_slice(block);
            st.send_enc(&mut out[..block.len()], false);
            st.send_mac(&mut out[block.len()..], false);
            out
        })
    });
    g.bench_with_input("strobe-128", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = Strobe::new(b"example", SecParam::B128);
            let mut out = vec![0u8; block.len() + 16];
            out[..block.len()].copy_from_slice(block);
            st.send_enc(&mut out[..block.len()], false);
            st.send_mac(&mut out[block.len()..], false);
            out
        })
    });
    g.bench_with_input("ChaCha20Poly1305", &[0u8; INPUT], |b, block| {
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
    g.bench_with_input("Xoodyak", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = XoodyakKeyed::new(&[0u8; 32], None, None);
            st.seal(block)
        })
    });
    g.bench_with_input("KeccyakMax", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = KeccyakMaxKeyed::new(&[0u8; 32], None, None);
            st.seal(block)
        })
    });
    g.bench_with_input("Keccyak256", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = Keccyak256Keyed::new(&[0u8; 32], None, None);
            st.seal(block)
        })
    });
    g.bench_with_input("Keccyak128", &[0u8; INPUT], |b, block| {
        b.iter(|| {
            let mut st = Keccyak128Keyed::new(&[0u8; 32], None, None);
            st.seal(block)
        })
    });
    g.finish();
}

fn permutation_benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("permutation");
    g.sample_size(1_000);
    g.throughput(Throughput::Bytes(200));
    g.bench_function("Keccak-f1600", |b| {
        let mut state = KeccakF1600::default();
        b.iter(|| state.permute())
    });
    g.bench_function("Keccak-p1600-14", |b| {
        let mut state = KeccakP1600_14::default();
        b.iter(|| state.permute())
    });
    g.bench_function("Keccak-p1600-12", |b| {
        let mut state = KeccakP1600_12::default();
        b.iter(|| state.permute())
    });
    g.throughput(Throughput::Bytes(48));
    g.bench_function("Xoodoo", |b| {
        let mut state = Xoodoo::default();
        b.iter(|| state.permute())
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
