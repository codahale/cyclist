use byteorder::{ByteOrder, LittleEndian};

use crate::{CyclistHash, CyclistKeyed, Permutation};

const B: usize = 384;
const W: usize = 4;

/// Xoodyak in hash mode.
pub type XoodyakHash = CyclistHash<Xoodoo, { B / 8 }, { ((B - 256) / W * W) / 8 }>;

/// Xoodyak in keyed mode.
pub type XoodyakKeyed = CyclistKeyed<
    Xoodoo,
    { B / 8 },
    { ((B - 32) / W * W) / 8 }, // keep at least 32 bits at the end of the state
    { ((B - 192) / W * W) / 8 }, // max(c=192,32)
    16,
    16,
>;

/// The Xoodoo permutation.
#[derive(Clone)]
pub struct Xoodoo;

impl Permutation<48> for Xoodoo {
    #[inline(always)]
    fn permute(state: &mut [u8; 48]) {
        let mut st = [0u32; 12];
        LittleEndian::read_u32_into(state.as_slice(), &mut st);
        for &round_key in &ROUND_KEYS {
            round(&mut st, round_key);
        }
        LittleEndian::write_u32_into(&st, state.as_mut_slice());
    }
}

#[inline(always)]
fn round(st: &mut [u32; 12], round_key: u32) {
    let p = [
        st[0] ^ st[4] ^ st[8],
        st[1] ^ st[5] ^ st[9],
        st[2] ^ st[6] ^ st[10],
        st[3] ^ st[7] ^ st[11],
    ];

    let e = [
        p[3].rotate_left(5) ^ p[3].rotate_left(14),
        p[0].rotate_left(5) ^ p[0].rotate_left(14),
        p[1].rotate_left(5) ^ p[1].rotate_left(14),
        p[2].rotate_left(5) ^ p[2].rotate_left(14),
    ];

    let mut tmp = [0u32; 12];

    tmp[0] = e[0] ^ st[0] ^ round_key;
    tmp[1] = e[1] ^ st[1];
    tmp[2] = e[2] ^ st[2];
    tmp[3] = e[3] ^ st[3];

    tmp[4] = e[3] ^ st[7];
    tmp[5] = e[0] ^ st[4];
    tmp[6] = e[1] ^ st[5];
    tmp[7] = e[2] ^ st[6];

    tmp[8] = (e[0] ^ st[8]).rotate_left(11);
    tmp[9] = (e[1] ^ st[9]).rotate_left(11);
    tmp[10] = (e[2] ^ st[10]).rotate_left(11);
    tmp[11] = (e[3] ^ st[11]).rotate_left(11);

    st[0] = (!tmp[4] & tmp[8]) ^ tmp[0];
    st[1] = (!tmp[5] & tmp[9]) ^ tmp[1];
    st[2] = (!tmp[6] & tmp[10]) ^ tmp[2];
    st[3] = (!tmp[7] & tmp[11]) ^ tmp[3];

    st[4] = ((!tmp[8] & tmp[0]) ^ tmp[4]).rotate_left(1);
    st[5] = ((!tmp[9] & tmp[1]) ^ tmp[5]).rotate_left(1);
    st[6] = ((!tmp[10] & tmp[2]) ^ tmp[6]).rotate_left(1);
    st[7] = ((!tmp[11] & tmp[3]) ^ tmp[7]).rotate_left(1);

    st[8] = ((!tmp[2] & tmp[6]) ^ tmp[10]).rotate_left(8);
    st[9] = ((!tmp[3] & tmp[7]) ^ tmp[11]).rotate_left(8);
    st[10] = ((!tmp[0] & tmp[4]) ^ tmp[8]).rotate_left(8);
    st[11] = ((!tmp[1] & tmp[5]) ^ tmp[9]).rotate_left(8);
}

const ROUND_KEYS: [u32; 12] = [
    0x058, 0x038, 0x3c0, 0x0d0, 0x120, 0x014, 0x060, 0x02c, 0x380, 0x0f0, 0x1a0, 0x012,
];

#[cfg(test)]
mod tests {
    use super::*;

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
