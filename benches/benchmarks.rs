use criterion::{criterion_group, criterion_main, Criterion};

use cyclist::keccak::{KeccakHash, KeccakKeyed};
use cyclist::xoodoo::{XoodyakHash, XoodyakKeyed};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Xoodyak hash", |b| {
        let mut out = [0u8; 64];
        let mut st = XoodyakHash::default();
        b.iter(|| {
            st.absorb(b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. ");
            st.squeeze_mut(&mut out);
            out
        })
    });

    c.bench_function("Xoodyak keyed", |b| {
        let mut out = [0u8; 64];
        let mut st = XoodyakKeyed::new(b"key", None,None, None);
        b.iter(|| {
            st.absorb(b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. ");
            st.squeeze_mut(&mut out);
            out
        })
    });

    c.bench_function("Keccak hash", |b| {
        let mut out = [0u8; 64];
        let mut st = KeccakHash::default();
        b.iter(|| {
            st.absorb(b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. ");
            st.squeeze_mut(&mut out);
            out
        })
    });

    c.bench_function("Keccak keyed", |b| {
        let mut out = [0u8; 64];
        let mut st = KeccakKeyed::new(b"key", None,None, None);
        b.iter(|| {
            st.absorb(b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. ");
            st.squeeze_mut(&mut out);
            out
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
