//! Xoodyak, the official Cyclist selection.
//!
//! Uses the [Xoodoo] permutation to provide ~128-bit security.
use byteorder::{ByteOrder, LittleEndian};
use zeroize::Zeroize;

use crate::{CyclistHash, CyclistKeyed, Permutation};

/// Xoodyak in hash mode.
pub type XoodyakHash = CyclistHash<Xoodoo, { 384 / 8 }, { (384 - 256) / 8 }>;

/// Xoodyak in keyed mode.
pub type XoodyakKeyed = CyclistKeyed<
    Xoodoo,
    { 384 / 8 },
    { (384 - 32) / 8 },  // R_absorb=b-W
    { (384 - 192) / 8 }, // R_squeeze=b-c
    16,
    16,
>;

/// The generic Xoodoo-p permutation, parameterized with the number of rounds.
#[derive(Clone)]
#[repr(align(4))]
pub struct Xoodoo([u8; 48]);

impl Default for Xoodoo {
    fn default() -> Self {
        Xoodoo([0u8; 48])
    }
}

impl AsRef<[u8; 48]> for Xoodoo {
    fn as_ref(&self) -> &[u8; 48] {
        &self.0
    }
}

impl AsMut<[u8; 48]> for Xoodoo {
    fn as_mut(&mut self) -> &mut [u8; 48] {
        &mut self.0
    }
}

impl Zeroize for Xoodoo {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl Permutation<48> for Xoodoo {
    #[inline(always)]
    fn permute(&mut self) {
        // Load state into lanes.
        let mut st = [0u32; 12];
        LittleEndian::read_u32_into(&self.0, &mut st);

        // Perform the pemutation.
        xoodoo_p::xoodoo::<{ xoodoo_p::MAX_ROUNDS }>(&mut st);

        // Load lanes into state.
        LittleEndian::write_u32_into(&st, &mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use crate::Cyclist;

    use super::*;

    #[test]
    fn supercop_aead_round_3_test_vector() {
        // from https://github.com/XKCP/XKCP/blob/2a8d2311a830ab3037f8c7ef2511e5c7cc032127/tests/SUPERCOP/Xoodyak_aead_round3/selftest.c
        let key = [
            0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f, 0x00, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97,
            0x88, 0x79,
        ];
        let nonce = [
            0x6b, 0x4c, 0x2d, 0x0e, 0xef, 0xd0, 0xb1, 0x92, 0x72, 0x53, 0x34, 0x15, 0xf6, 0xd7,
            0xb8, 0x99,
        ];
        let ad = [0x32, 0xf3, 0xb4, 0x75, 0x35, 0xf6];
        let plaintext = [0xe4, 0x65, 0xe5, 0x66, 0xe6, 0x67, 0xe7];
        let ciphertext = [
            0x6e, 0x68, 0x08, 0x1c, 0x7e, 0xac, 0xbf, 0x72, 0xe2, 0xa6, 0x77, 0xa6, 0x0e, 0x44,
            0x27, 0x48, 0xd7, 0xa8, 0x6e, 0x78, 0x8e, 0xb9, 0xd4,
        ];

        let mut x = XoodyakKeyed::new(&key, Some(&nonce), None);
        x.absorb(&ad);
        let ciphertext_p = x.seal(&plaintext);
        assert_eq!(&ciphertext, ciphertext_p.as_slice());

        let mut x = XoodyakKeyed::new(&key, Some(&nonce), None);
        x.absorb(&ad);
        let plaintext_p = x.open(&ciphertext);
        assert_eq!(Some(plaintext.to_vec()), plaintext_p);
    }

    #[test]
    fn supercop_hash_test_vector() {
        // from https://github.com/XKCP/XKCP/blob/2a8d2311a830ab3037f8c7ef2511e5c7cc032127/tests/SUPERCOP/Xoodyak_hash/selftest.c
        let message = [0x11, 0x97, 0x13, 0xCC, 0x83, 0xEE, 0xEF];
        let digest = [
            0x99, 0x9d, 0x58, 0x65, 0xb0, 0xdd, 0x9f, 0xa3, 0x09, 0x73, 0x36, 0x5f, 0xec, 0xf0,
            0x41, 0x77, 0x8d, 0x04, 0x49, 0xa1, 0xb0, 0xc5, 0x5b, 0x74, 0x36, 0x60, 0x83, 0x1a,
            0x7d, 0x50, 0x25, 0xee,
        ];

        let mut x = XoodyakHash::default();
        x.absorb(&message);
        let digest_p = x.squeeze(32);

        assert_eq!(&digest, digest_p.as_slice());
    }

    #[test]
    fn round_trip() {
        let mut d = XoodyakKeyed::new(b"ok then", None, None);
        let m = b"it's a deal".to_vec();
        let c = d.seal(&m);

        let mut d = XoodyakKeyed::new(b"ok then", None, None);
        let p = d.open(&c);

        assert_eq!(Some(m), p);
    }
}
