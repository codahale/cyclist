#![cfg(all(test, feature = "std", feature = "xoodyak"))]

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

/// Apply the transcript's operations to Xoodyak in hash mode and return the duplex's outputs.
fn apply_hash_transcript(transcript: &HashTranscript) -> Vec<HashOutput> {
    let mut hash = XoodyakHash::default();
    transcript
        .ops
        .iter()
        .flat_map(|op| match op {
            HashOp::Absorb(data) => {
                hash.absorb(data);
                None
            }
            HashOp::Squeeze(n) => Some(HashOutput::Squeezed(hash.squeeze(*n))),
        })
        .collect()
}

/// Apply the transcript's operations to Xoodyak in keyed mode and return the duplex's outputs.
fn apply_keyed_transcript(transcript: &KeyedTranscript) -> Vec<KeyedOutput> {
    let mut keyed = XoodyakKeyed::new(&transcript.key, &transcript.nonce, &transcript.counter);
    transcript
        .ops
        .iter()
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

/// An arbitrary byte string with length 0..200.
fn arb_data() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..200)
}
/// An arbitrary hash mode operation.
fn arb_hash_op() -> impl Strategy<Value = HashOp> {
    prop_oneof![arb_data().prop_map(HashOp::Absorb), (1usize..256).prop_map(HashOp::Squeeze),]
}

/// An arbitrary keyed mode operation.
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
    /// A transcript of 0..62 arbitrary hash operations terminated with a `Squeeze(16)` operation to
    /// capture the duplex's final state.
    fn arb_hash_transcript()(mut ops in vec(arb_hash_op(), 0..62)) -> HashTranscript {
        ops.push(HashOp::Squeeze(16));
        HashTranscript { ops }
    }
}

prop_compose! {
    /// A transcript of 0..62 arbitrary keyed operations terminated with a `Squeeze(16)` operation
    /// to capture the duplex's final state.
    fn arb_keyed_transcript()(
        key in vec(any::<u8>(), 1..16),
        nonce in vec(any::<u8>(), 0..16),
        counter in vec(any::<u8>(), 0..16),
        mut ops in vec(arb_keyed_op(), 0..62),
    ) -> KeyedTranscript {
        ops.push(KeyedOp::Squeeze(16));
        KeyedTranscript{ key, nonce, counter, ops }
    }
}

proptest! {
    /// Any two equal hash mode transcripts must produce equal outputs. Any two different
    /// transcripts must produce different outputs.
    #[test]
    fn hash_transcript_consistency(t0 in arb_hash_transcript(), t1 in arb_hash_transcript()) {
        let out0 = apply_hash_transcript(&t0);
        let out1 = apply_hash_transcript(&t1);

        if t0 == t1 {
            prop_assert_eq!(out0, out1);
        } else  {
            prop_assert_ne!(out0, out1);
        }
    }

    /// Any two equal keyed mode transcripts must produce equal outputs. Any two different
    /// transcripts must produce different outputs.
    #[test]
    fn keyed_transcript_consistency(t0 in arb_keyed_transcript(), t1 in arb_keyed_transcript()) {
        let out0 = apply_keyed_transcript(&t0);
        let out1 = apply_keyed_transcript(&t1);

        if t0 == t1 {
            prop_assert_eq!(out0, out1);
        } else  {
            prop_assert_ne!(out0, out1);
        }
    }

    /// For any transcript, reversible outputs (e.g. encrypt/decrypt) must be symmetric.
    #[test]
    fn keyed_transcript_symmetry(t in arb_keyed_transcript()) {
        let mut outbound = XoodyakKeyed::new(&t.key, &t.nonce, &t.counter);
        let mut inbound = XoodyakKeyed::new(&t.key, &t.nonce, &t.counter);

        for op in &t.ops {
            match op {
                KeyedOp::Absorb(data) => {
                    outbound.absorb(data);
                    inbound.absorb(data);
                }
                KeyedOp::Squeeze(n) => {
                    prop_assert_eq!(outbound.squeeze(*n), inbound.squeeze(*n));
                }
                KeyedOp::Encrypt(plaintext) => {
                    prop_assert_eq!(plaintext, &inbound.decrypt(&outbound.encrypt(plaintext)));
                }
                KeyedOp::Decrypt(ciphertext) => {
                    prop_assert_eq!(ciphertext, &inbound.encrypt(&outbound.decrypt(ciphertext)));
                }
                KeyedOp::Ratchet => {
                    outbound.ratchet();
                    inbound.ratchet();
                }
            }
        }

        prop_assert_eq!(outbound.squeeze(16), inbound.squeeze(16));
    }
}
