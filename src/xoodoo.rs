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
        let mut st = [0u32; 12];
        LittleEndian::read_u32_into(&self.0, &mut st);
        for &round_key in &ROUND_KEYS[..R] {
            round(&mut st, round_key);
        }
        LittleEndian::write_u32_into(&st, &mut self.0);
    }
}

#[inline(always)]
fn round(st: &mut [u32; 12], round_key: u32) {
    let p0 = st[0] ^ st[4] ^ st[8];
    let p1 = st[1] ^ st[5] ^ st[9];
    let p2 = st[2] ^ st[6] ^ st[10];
    let p3 = st[3] ^ st[7] ^ st[11];

    let e0 = p3.rotate_left(5) ^ p3.rotate_left(14);
    let e1 = p0.rotate_left(5) ^ p0.rotate_left(14);
    let e2 = p1.rotate_left(5) ^ p1.rotate_left(14);
    let e3 = p2.rotate_left(5) ^ p2.rotate_left(14);

    let tmp0 = e0 ^ st[0] ^ round_key;
    let tmp1 = e1 ^ st[1];
    let tmp2 = e2 ^ st[2];
    let tmp3 = e3 ^ st[3];
    let tmp4 = e3 ^ st[7];
    let tmp5 = e0 ^ st[4];
    let tmp6 = e1 ^ st[5];
    let tmp7 = e2 ^ st[6];
    let tmp8 = (e0 ^ st[8]).rotate_left(11);
    let tmp9 = (e1 ^ st[9]).rotate_left(11);
    let tmp10 = (e2 ^ st[10]).rotate_left(11);
    let tmp11 = (e3 ^ st[11]).rotate_left(11);

    st[0] = (!tmp4 & tmp8) ^ tmp0;
    st[1] = (!tmp5 & tmp9) ^ tmp1;
    st[2] = (!tmp6 & tmp10) ^ tmp2;
    st[3] = (!tmp7 & tmp11) ^ tmp3;

    st[4] = ((!tmp8 & tmp0) ^ tmp4).rotate_left(1);
    st[5] = ((!tmp9 & tmp1) ^ tmp5).rotate_left(1);
    st[6] = ((!tmp10 & tmp2) ^ tmp6).rotate_left(1);
    st[7] = ((!tmp11 & tmp3) ^ tmp7).rotate_left(1);

    st[8] = ((!tmp2 & tmp6) ^ tmp10).rotate_left(8);
    st[9] = ((!tmp3 & tmp7) ^ tmp11).rotate_left(8);
    st[10] = ((!tmp0 & tmp4) ^ tmp8).rotate_left(8);
    st[11] = ((!tmp1 & tmp5) ^ tmp9).rotate_left(8);
}

const ROUND_KEYS: [u32; 12] = [
    0x00000058, 0x00000038, 0x000003C0, 0x000000D0, 0x00000120, 0x00000014, 0x00000060, 0x0000002C,
    0x00000380, 0x000000F0, 0x000001A0, 0x00000012,
];

#[cfg(test)]
mod tests {
    use crate::Cyclist;

    use super::*;

    #[test]
    fn nist_lwc_round_3_test_vectors() {
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

        let mut x = XoodyakKeyed::new(&key, Some(&nonce), None, None);
        x.absorb(&ad);
        let ciphertext_p = x.seal(&plaintext);
        assert_eq!(&ciphertext, ciphertext_p.as_slice());

        let mut x = XoodyakKeyed::new(&key, Some(&nonce), None, None);
        x.absorb(&ad);
        let plaintext_p = x.open(&ciphertext);
        assert_eq!(Some(plaintext.to_vec()), plaintext_p);
    }

    #[test]
    fn hash_test_vector() {
        let mut hash = XoodyakHash::default();
        let m = b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
        let mut out = [0u8; 32];
        hash.absorb(&m[..]);
        hash.squeeze_mut(&mut out);
        assert_eq!(
            out,
            [
                144, 82, 141, 27, 59, 215, 34, 104, 197, 106, 251, 142, 112, 235, 111, 168, 19, 6,
                112, 222, 160, 168, 230, 38, 27, 229, 248, 179, 94, 227, 247, 25
            ]
        );
        hash.absorb(&m[..]);
        hash.squeeze_mut(&mut out);
        assert_eq!(
            out,
            [
                102, 50, 250, 132, 79, 91, 248, 161, 121, 248, 225, 33, 105, 159, 111, 230, 135,
                252, 43, 228, 152, 41, 58, 242, 211, 252, 29, 234, 181, 0, 196, 220
            ]
        );
    }

    #[test]
    fn test_encrypt() {
        let mut st = XoodyakKeyed::new(b"key", None, None, None);
        let st0 = st.clone();
        let m = b"message";
        let mut c = *m;
        st.encrypt_mut(&mut c);

        let mut st = st0.clone();
        let mut m2 = c;
        st.decrypt_mut(&mut m2);
        assert_eq!(m, &m2);

        let mut st = st0.clone();
        st.ratchet();
        let mut m2 = c;
        st.decrypt_mut(&mut m2);
        assert_ne!(&m[..], m2.as_slice());

        let c0 = c;
        let mut st = st0.clone();
        st.decrypt_mut(&mut c);
        assert_eq!(&m[..], &c[..]);

        let mut st = st0;
        st.encrypt_mut(&mut c);
        assert_eq!(c0, c);

        let mut tag = [0u8; 32];
        st.squeeze_mut(&mut tag);
        assert_eq!(
            tag,
            [
                10, 175, 140, 82, 142, 109, 23, 111, 201, 232, 32, 52, 122, 46, 254, 206, 236, 54,
                97, 165, 40, 85, 166, 91, 124, 88, 26, 144, 100, 250, 243, 157
            ]
        );
    }

    #[test]
    fn round_trip() {
        let mut d = XoodyakKeyed::new(b"ok then", None, None, None);
        let m = b"it's a deal".to_vec();
        let c = d.seal(&m);

        let mut d = XoodyakKeyed::new(b"ok then", None, None, None);
        let p = d.open(&c);

        assert_eq!(Some(m), p);
    }
}
