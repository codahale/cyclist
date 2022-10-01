#![cfg(all(test, feature = "std", feature = "xoodyak"))]

use proptest::collection::vec;
use proptest::prelude::*;

use crate::xoodyak::{XoodyakHash, XoodyakKeyed};
use crate::Cyclist;

#[derive(Clone, Debug, PartialEq)]
enum HashOp {
    Absorb(Vec<u8>),
    Squeeze(usize),
}

#[derive(Clone, Debug, PartialEq)]
enum KeyedOp {
    Absorb(Vec<u8>),
    Squeeze(usize),
    Crypt(Vec<u8>),
    Ratchet,
}

#[derive(Clone, Debug, PartialEq)]
struct HashTranscript {
    ops: Vec<HashOp>,
}

#[derive(Clone, Debug, PartialEq)]
struct KeyedTranscript {
    key: Vec<u8>,
    nonce: Vec<u8>,
    counter: Vec<u8>,
    ops: Vec<KeyedOp>,
}

fn apply_hash_transcript(transcript: HashTranscript) -> Vec<u8> {
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

fn apply_keyed_transcript(transcript: KeyedTranscript) {
    let mut outbound_squeezed = Vec::new();
    let mut inbound_squeezed = Vec::new();

    let inbound_ops = {
        let mut outbound =
            XoodyakKeyed::new(&transcript.key, &transcript.nonce, &transcript.counter);
        let ops = transcript
            .ops
            .iter()
            .map(|op| match op {
                KeyedOp::Absorb(data) => {
                    outbound.absorb(data);
                    KeyedOp::Absorb(data.to_vec())
                }
                KeyedOp::Squeeze(n) => {
                    let out = outbound.squeeze(*n);
                    outbound_squeezed.extend_from_slice(&out);
                    KeyedOp::Squeeze(*n)
                }
                KeyedOp::Crypt(plaintext) => {
                    let ciphertext = outbound.encrypt(plaintext);
                    KeyedOp::Crypt(ciphertext)
                }
                KeyedOp::Ratchet => {
                    outbound.ratchet();
                    KeyedOp::Ratchet
                }
            })
            .collect::<Vec<KeyedOp>>();
        outbound_squeezed.extend_from_slice(&outbound.squeeze(16));
        ops
    };

    let outbound_ops = {
        let mut inbound =
            XoodyakKeyed::new(&transcript.key, &transcript.nonce, &transcript.counter);
        let ops = inbound_ops
            .into_iter()
            .map(|op| match op {
                KeyedOp::Absorb(data) => {
                    inbound.absorb(&data);
                    KeyedOp::Absorb(data)
                }
                KeyedOp::Squeeze(n) => {
                    let out = inbound.squeeze(n);
                    inbound_squeezed.extend_from_slice(&out);
                    KeyedOp::Squeeze(n)
                }
                KeyedOp::Crypt(ciphertext) => {
                    let plaintext = inbound.decrypt(&ciphertext);
                    KeyedOp::Crypt(plaintext)
                }
                KeyedOp::Ratchet => {
                    inbound.ratchet();
                    KeyedOp::Ratchet
                }
            })
            .collect::<Vec<KeyedOp>>();
        inbound_squeezed.extend_from_slice(&inbound.squeeze(16));
        ops
    };

    assert_eq!(outbound_squeezed, inbound_squeezed);
    assert_eq!(transcript.ops, outbound_ops);
}

fn arb_data() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..200)
}

fn arb_key() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 1..16)
}

fn arb_nonce() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..16)
}

fn arb_counter() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..16)
}

fn arb_hash_op() -> impl Strategy<Value = HashOp> {
    prop_oneof![arb_data().prop_map(HashOp::Absorb), (1usize..256).prop_map(HashOp::Squeeze),]
}

fn arb_keyed_op() -> impl Strategy<Value = KeyedOp> {
    prop_oneof![
        arb_data().prop_map(KeyedOp::Absorb),
        (1usize..256).prop_map(KeyedOp::Squeeze),
        arb_data().prop_map(KeyedOp::Crypt),
        Just(KeyedOp::Ratchet),
    ]
}

prop_compose! {
    fn arb_hash_transcript()(ops in vec(arb_hash_op(), 0..62)) -> HashTranscript {
        HashTranscript { ops }
    }
}

prop_compose! {
    fn arb_keyed_transcript()(key in arb_key(), nonce in arb_nonce(), counter in arb_counter(), ops in vec(arb_keyed_op(), 0..62)) -> KeyedTranscript {
        KeyedTranscript{ key, nonce, counter, ops }
    }
}

proptest! {
    #[test]
    fn hash_transcript_consistency(t0 in arb_hash_transcript(), t1 in arb_hash_transcript()) {
        let eq = t0 == t1;
        let out0 = apply_hash_transcript(t0);
        let out1 = apply_hash_transcript(t1);

        if eq {
            assert_eq!(out0, out1);
        } else  {
            assert_ne!(out0, out1);
        }
    }

    #[test]
    fn keyed_transcript_symmetry(t in arb_keyed_transcript()) {
        apply_keyed_transcript(t);
    }
}
