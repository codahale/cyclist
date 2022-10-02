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
fn apply_hash_transcript(t: &HashTranscript) -> Vec<HashOutput> {
    let mut hash = XoodyakHash::default();
    t.ops
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
fn apply_keyed_transcript(t: &KeyedTranscript) -> Vec<KeyedOutput> {
    let mut keyed = XoodyakKeyed::new(&t.key, &t.nonce, &t.counter);
    t.ops
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

/// Apply the transcript's operations to Xoodyak in keyed mode and return the transcript's inverse
/// and the duplex's squeezed outputs.
fn invert_keyed_transcript(t: &KeyedTranscript) -> (KeyedTranscript, Vec<Vec<u8>>) {
    let mut keyed = XoodyakKeyed::new(&t.key, &t.nonce, &t.counter);
    let mut squeezed = Vec::new();
    let ops = t
        .ops
        .iter()
        .map(|op| match op {
            KeyedOp::Absorb(data) => {
                keyed.absorb(data);
                KeyedOp::Absorb(data.to_vec())
            }
            KeyedOp::Squeeze(n) => {
                squeezed.push(keyed.squeeze(*n));
                KeyedOp::Squeeze(*n)
            }
            KeyedOp::Encrypt(plaintext) => KeyedOp::Decrypt(keyed.decrypt(plaintext)),
            KeyedOp::Decrypt(ciphertext) => KeyedOp::Encrypt(keyed.encrypt(ciphertext)),
            KeyedOp::Ratchet => {
                keyed.ratchet();
                KeyedOp::Ratchet
            }
        })
        .collect();
    (
        KeyedTranscript {
            key: t.key.clone(),
            nonce: t.nonce.clone(),
            counter: t.counter.clone(),
            ops,
        },
        squeezed,
    )
}

/// An arbitrary byte string with length 0..200.
fn data() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..200)
}
/// An arbitrary hash mode operation.
fn hash_op() -> impl Strategy<Value = HashOp> {
    prop_oneof![(1usize..256).prop_map(HashOp::Squeeze), data().prop_map(HashOp::Absorb),]
}

/// An arbitrary keyed mode operation.
fn keyed_op() -> impl Strategy<Value = KeyedOp> {
    prop_oneof![
        Just(KeyedOp::Ratchet),
        (1usize..256).prop_map(KeyedOp::Squeeze),
        data().prop_map(KeyedOp::Absorb),
        data().prop_map(KeyedOp::Encrypt),
        data().prop_map(KeyedOp::Decrypt),
    ]
}

prop_compose! {
    /// A transcript of 0..62 arbitrary hash operations terminated with a `Squeeze(16)` operation to
    /// capture the duplex's final state.
    fn hash_transcript()(mut ops in vec(hash_op(), 0..62)) -> HashTranscript {
        ops.push(HashOp::Squeeze(16));
        HashTranscript { ops }
    }
}

prop_compose! {
    /// A transcript of 0..62 arbitrary keyed operations terminated with a `Squeeze(16)` operation
    /// to capture the duplex's final state.
    fn keyed_transcript()(
        key in vec(any::<u8>(), 1..16),
        nonce in vec(any::<u8>(), 0..16),
        counter in vec(any::<u8>(), 0..16),
        mut ops in vec(keyed_op(), 0..62),
    ) -> KeyedTranscript {
        ops.push(KeyedOp::Squeeze(16));
        KeyedTranscript{ key, nonce, counter, ops }
    }
}

proptest! {
    /// Any two equal hash mode transcripts must produce equal outputs. Any two different
    /// transcripts must produce different outputs.
    #[test]
    fn hash_transcript_consistency(t0 in hash_transcript(), t1 in hash_transcript()) {
        let out0 = apply_hash_transcript(&t0);
        let out1 = apply_hash_transcript(&t1);

        if t0 == t1 {
            prop_assert_eq!(out0, out1, "equal transcripts produced different outputs");
        } else  {
            prop_assert_ne!(out0, out1, "different transcripts produced equal outputs");
        }
    }

    /// Any two equal keyed mode transcripts must produce equal outputs. Any two different
    /// transcripts must produce different outputs.
    #[test]
    fn keyed_transcript_consistency(t0 in keyed_transcript(), t1 in keyed_transcript()) {
        let out0 = apply_keyed_transcript(&t0);
        let out1 = apply_keyed_transcript(&t1);

        if t0 == t1 {
            prop_assert_eq!(out0, out1, "equal transcripts produced different outputs");
        } else  {
            prop_assert_ne!(out0, out1, "different transcripts produced equal outputs");
        }
    }

    /// For any transcript, reversible outputs (e.g. encrypt/decrypt) must be symmetric.
    #[test]
    fn keyed_transcript_symmetry(t in keyed_transcript()) {
        let (t_inv, a) = invert_keyed_transcript(&t);
        let (t_p, b) = invert_keyed_transcript(&t_inv);

        prop_assert_eq!(t, t_p, "non-commutative transcript inversion");
        prop_assert_eq!(a, b, "different squeezed outputs");
    }
}
