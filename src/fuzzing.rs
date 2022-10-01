#![cfg(all(test, feature = "std", feature = "xoodyak"))]

use std::iter;

use proptest::collection::vec;
use proptest::prelude::*;

use crate::xoodyak::{XoodyakHash, XoodyakKeyed};
use crate::Cyclist;

/// An input operation for Cyclist's hash mode.
#[derive(Clone, Debug, PartialEq)]
enum HashOp {
    Absorb(Vec<u8>),
    Squeeze(usize),
}

/// An output from Cyclist's hash mode.
#[derive(Clone, Debug, PartialEq)]
enum HashOutput {
    Squeezed(Vec<u8>),
}

/// A transcript of input operations for Cyclist's hash mode.
#[derive(Clone, Debug, PartialEq)]
struct HashTranscript {
    ops: Vec<HashOp>,
}

/// An input operation for Cyclist's keyed mode.
#[derive(Clone, Debug, PartialEq)]
enum KeyedOp {
    Absorb(Vec<u8>),
    Squeeze(usize),
    Encrypt(Vec<u8>),
    Decrypt(Vec<u8>),
    Ratchet,
}

/// An output from Cyclist's keyed mode.
#[derive(Clone, Debug, PartialEq)]
enum KeyedOutput {
    Squeezed(Vec<u8>),
    Encrypted(Vec<u8>),
    Decrypted(Vec<u8>),
}

/// A transcript of input operations for Cyclist's keyed mode, plus shared key, nonce, and counter.
#[derive(Clone, Debug, PartialEq)]
struct KeyedTranscript {
    key: Vec<u8>,
    nonce: Vec<u8>,
    counter: Vec<u8>,
    ops: Vec<KeyedOp>,
}

/// Apply the transcript's operations to Xoodyak in hash mode, plus a final `Squeeze(16)` to
/// establish the duplex's final state, and return the duplex's outputs.
fn apply_hash_transcript(transcript: &HashTranscript) -> Vec<HashOutput> {
    let mut hash = XoodyakHash::default();
    transcript
        .ops
        .iter()
        .chain(iter::once(&HashOp::Squeeze(16)))
        .flat_map(|op| match op {
            HashOp::Absorb(data) => {
                hash.absorb(data);
                None
            }
            HashOp::Squeeze(n) => Some(HashOutput::Squeezed(hash.squeeze(*n))),
        })
        .collect()
}

/// Apply the transcript's operations to Xoodyak in keyed mode, plus a final `Squeeze(16)` to
/// establish the duplex's final state, and return the duplex's outputs.
fn apply_keyed_transcript(transcript: &KeyedTranscript) -> Vec<KeyedOutput> {
    let mut keyed = XoodyakKeyed::new(&transcript.key, &transcript.nonce, &transcript.counter);
    transcript
        .ops
        .iter()
        .chain(iter::once(&KeyedOp::Squeeze(16)))
        .flat_map(|op| match op {
            KeyedOp::Absorb(data) => {
                keyed.absorb(data);
                None
            }
            KeyedOp::Squeeze(n) => Some(KeyedOutput::Squeezed(keyed.squeeze(*n))),
            KeyedOp::Encrypt(data) => Some(KeyedOutput::Encrypted(keyed.encrypt(data))),
            KeyedOp::Decrypt(data) => Some(KeyedOutput::Decrypted(keyed.decrypt(data))),
            KeyedOp::Ratchet => {
                keyed.ratchet();
                None
            }
        })
        .collect()
}

/// Apply the transcript's operations to two duplexes--`outbound` and `inbound`--checking that both
/// duplexes can correctly encrypt and decrypt each other's outputs and remain synchronized.
fn check_keyed_transcript_symmetry(transcript: &KeyedTranscript) {
    let mut outbound = XoodyakKeyed::new(&transcript.key, &transcript.nonce, &transcript.counter);
    let mut inbound = XoodyakKeyed::new(&transcript.key, &transcript.nonce, &transcript.counter);

    for op in &transcript.ops {
        match op {
            KeyedOp::Absorb(data) => {
                outbound.absorb(data);
                inbound.absorb(data);
            }
            KeyedOp::Squeeze(n) => {
                assert_eq!(outbound.squeeze(*n), inbound.squeeze(*n));
            }
            KeyedOp::Encrypt(plaintext) => {
                assert_eq!(plaintext, &inbound.decrypt(&outbound.encrypt(plaintext)));
            }
            KeyedOp::Decrypt(ciphertext) => {
                assert_eq!(ciphertext, &inbound.encrypt(&outbound.decrypt(ciphertext)));
            }
            KeyedOp::Ratchet => {
                outbound.ratchet();
                inbound.ratchet();
            }
        }
    }

    assert_eq!(outbound.squeeze(16), inbound.squeeze(16));
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
        arb_data().prop_map(KeyedOp::Encrypt),
        arb_data().prop_map(KeyedOp::Decrypt),
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
        let out0 = apply_hash_transcript(&t0);
        let out1 = apply_hash_transcript(&t1);

        if t0 == t1 {
            assert_eq!(out0, out1);
        } else  {
            assert_ne!(out0, out1);
        }
    }

    #[test]
    fn keyed_transcript_consistency(t0 in arb_keyed_transcript(), t1 in arb_keyed_transcript()) {
        let out0 = apply_keyed_transcript(&t0);
        let out1 = apply_keyed_transcript(&t1);

        if t0 == t1 {
            assert_eq!(out0, out1);
        } else  {
            assert_ne!(out0, out1);
        }
    }

    #[test]
    fn keyed_transcript_symmetry(t in arb_keyed_transcript()) {
        check_keyed_transcript_symmetry(&t);
    }
}
