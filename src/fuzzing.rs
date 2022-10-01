#![cfg(all(test, feature = "std", feature = "xoodyak"))]

use proptest::collection::vec;
use proptest::prelude::*;

use crate::xoodyak::XoodyakHash;
use crate::Cyclist;

#[derive(Clone, Debug, PartialEq)]
enum HashOp {
    Absorb(Vec<u8>),
    Squeeze(usize),
}

#[derive(Clone, Debug, PartialEq)]
struct HashTranscript {
    ops: Vec<HashOp>,
}

fn apply_hash_transcript(transcript: &HashTranscript) -> Vec<u8> {
    let mut hash = XoodyakHash::default();
    let mut squeezed = Vec::new();

    for op in &transcript.ops {
        match op {
            HashOp::Absorb(data) => {
                hash.absorb(data);
            }
            HashOp::Squeeze(n) => {
                let out = hash.squeeze(*n);
                squeezed.extend_from_slice(&out);
            }
        }
    }

    squeezed.extend_from_slice(&hash.squeeze(16));
    squeezed
}

fn arb_data() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..200)
}

fn arb_hash_op() -> impl Strategy<Value = HashOp> {
    prop_oneof![arb_data().prop_map(HashOp::Absorb), (1usize..256).prop_map(HashOp::Squeeze),]
}

prop_compose! {
    fn arb_hash_transcript()(ops in vec(arb_hash_op(), 0..62)) -> HashTranscript {
        HashTranscript { ops }
    }
}

proptest! {
    #[test]
    fn hash_transcript_consistency(t0 in arb_hash_transcript(), t1 in arb_hash_transcript()) {
        let out0 = apply_hash_transcript(&t0);
        let out1 = apply_hash_transcript(&t1);

        if t0 == t1 {
            assert_eq!(out0, out1);
        } else  {
            assert_ne!(out0, out1);
        }
    }
}
