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

/// The full Xoodoo permutation with 12 rounds.
pub type Xoodoo = XoodooP<12>;

/// The reduced Xoodoo\[6\] permutation with 6 rounds.
pub type Xoodoo6 = XoodooP<6>;

/// The generic Xoodoo-p permutation, parameterized with the number of rounds.
#[derive(Clone)]
#[repr(align(4))]
pub struct XoodooP<const R: usize>([u8; 48]);

impl<const R: usize> Default for XoodooP<R> {
    fn default() -> Self {
        XoodooP([0u8; 48])
    }
}

impl<const R: usize> AsRef<[u8; 48]> for XoodooP<R> {
    fn as_ref(&self) -> &[u8; 48] {
        &self.0
    }
}

impl<const R: usize> AsMut<[u8; 48]> for XoodooP<R> {
    fn as_mut(&mut self) -> &mut [u8; 48] {
        &mut self.0
    }
}

impl<const R: usize> Zeroize for XoodooP<R> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<const R: usize> Permutation<48> for XoodooP<R> {
    #[inline(always)]
    fn permute(&mut self) {
        // Load state into lanes.
        let mut st = [0u32; 12];
        LittleEndian::read_u32_into(&self.0, &mut st);

        // Load lanes into registers.
        let mut st00 = st[0];
        let mut st01 = st[1];
        let mut st02 = st[2];
        let mut st03 = st[3];
        let mut st04 = st[4];
        let mut st05 = st[5];
        let mut st06 = st[6];
        let mut st07 = st[7];
        let mut st08 = st[8];
        let mut st09 = st[9];
        let mut st10 = st[10];
        let mut st11 = st[11];

        // Perform last R rounds.
        for &round_key in &ROUND_KEYS[MAX_ROUNDS - R..MAX_ROUNDS] {
            let p0 = st00 ^ st04 ^ st08;
            let p1 = st01 ^ st05 ^ st09;
            let p2 = st02 ^ st06 ^ st10;
            let p3 = st03 ^ st07 ^ st11;

            let e0 = p3.rotate_left(5) ^ p3.rotate_left(14);
            let e1 = p0.rotate_left(5) ^ p0.rotate_left(14);
            let e2 = p1.rotate_left(5) ^ p1.rotate_left(14);
            let e3 = p2.rotate_left(5) ^ p2.rotate_left(14);

            let tmp0 = e0 ^ st00 ^ round_key;
            let tmp1 = e1 ^ st01;
            let tmp2 = e2 ^ st02;
            let tmp3 = e3 ^ st03;
            let tmp4 = e3 ^ st07;
            let tmp5 = e0 ^ st04;
            let tmp6 = e1 ^ st05;
            let tmp7 = e2 ^ st06;
            let tmp8 = (e0 ^ st08).rotate_left(11);
            let tmp9 = (e1 ^ st09).rotate_left(11);
            let tmp10 = (e2 ^ st10).rotate_left(11);
            let tmp11 = (e3 ^ st11).rotate_left(11);

            st00 = (!tmp4 & tmp8) ^ tmp0;
            st01 = (!tmp5 & tmp9) ^ tmp1;
            st02 = (!tmp6 & tmp10) ^ tmp2;
            st03 = (!tmp7 & tmp11) ^ tmp3;

            st04 = ((!tmp8 & tmp0) ^ tmp4).rotate_left(1);
            st05 = ((!tmp9 & tmp1) ^ tmp5).rotate_left(1);
            st06 = ((!tmp10 & tmp2) ^ tmp6).rotate_left(1);
            st07 = ((!tmp11 & tmp3) ^ tmp7).rotate_left(1);

            st08 = ((!tmp2 & tmp6) ^ tmp10).rotate_left(8);
            st09 = ((!tmp3 & tmp7) ^ tmp11).rotate_left(8);
            st10 = ((!tmp0 & tmp4) ^ tmp8).rotate_left(8);
            st11 = ((!tmp1 & tmp5) ^ tmp9).rotate_left(8);
        }

        // Load registers into lanes.
        st[0] = st00;
        st[1] = st01;
        st[2] = st02;
        st[3] = st03;
        st[4] = st04;
        st[5] = st05;
        st[6] = st06;
        st[7] = st07;
        st[8] = st08;
        st[9] = st09;
        st[10] = st10;
        st[11] = st11;

        // Load lanes into state.
        LittleEndian::write_u32_into(&st, &mut self.0);
    }
}

const MAX_ROUNDS: usize = 12;

const ROUND_KEYS: [u32; MAX_ROUNDS] = [
    0x00000058, 0x00000038, 0x000003C0, 0x000000D0, 0x00000120, 0x00000014, 0x00000060, 0x0000002C,
    0x00000380, 0x000000F0, 0x000001A0, 0x00000012,
];

#[cfg(test)]
mod tests {
    use crate::Cyclist;

    use super::*;

    #[test]
    fn xoodoo_kat() {
        // test vector produced by XKCP rev 2a8d2311a830ab3037f8c7ef2511e5c7cc032127
        let mut state = Xoodoo::default();
        state.permute();
        assert_eq!(
            state.as_ref(),
            &[
                0x8d, 0xd8, 0xd5, 0x89, 0xbf, 0xfc, 0x63, 0xa9, 0x19, 0x2d, 0x23, 0x1b, 0x14, 0xa0,
                0xa5, 0xff, 0x06, 0x81, 0xb1, 0x36, 0xfe, 0xc1, 0xc7, 0xaf, 0xbe, 0x7c, 0xe5, 0xae,
                0xbd, 0x40, 0x75, 0xa7, 0x70, 0xe8, 0x86, 0x2e, 0xc9, 0xb7, 0xf5, 0xfe, 0xf2, 0xad,
                0x4f, 0x8b, 0x62, 0x40, 0x4f, 0x5e,
            ]
        );
    }

    #[test]
    fn xoodoo6_kat() {
        // test vector produced by XKCP rev 2a8d2311a830ab3037f8c7ef2511e5c7cc032127
        let mut state = Xoodoo6::default();
        state.permute();
        assert_eq!(
            state.as_ref(),
            &[
                0xa3, 0xce, 0xc9, 0x28, 0x60, 0x4f, 0x20, 0xad, 0xd6, 0xd0, 0xc3, 0x2e, 0xc5, 0xc7,
                0x50, 0xf0, 0x25, 0x12, 0xdc, 0x08, 0x04, 0x23, 0x99, 0x61, 0x2d, 0x40, 0x0d, 0x9e,
                0x9b, 0x9b, 0xd5, 0x42, 0xfc, 0x14, 0x61, 0x1e, 0x97, 0xb6, 0x6e, 0x18, 0x7f, 0xbc,
                0xdb, 0x35, 0x4e, 0x10, 0xf9, 0xa1,
            ]
        );
    }

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
