//! A collection of Keccak-_p_ based permutations and Cyclist schemes.
//!
//! The three varieties of Cyclist schemes are:
//!
//! 1. [KeccakHash] and [KeccakKeyed], which use the full Keccak-f\[1600\] permutation and are
//!    parameterized to offer ~256-bit security with a very conservative design.
//! 2. [M14Hash] and [M14Keyed], which use the 14-round Keccak-f\[1600,14\] permutation are are
//!    parameterized to offer ~256-bit security with a performance-oriented design.
//! 3. [K12Hash] and [K12Keyed], which use the 12-round Keccak-f\[1600,12\] permutation and are
//!    parameterized to offer ~128-bit security with a performance-oriented design.
//!
//! Parameters were chosen based on the discussion of the
//! [Motorist](https://keccak.team/files/Keyakv2-doc2.2.pdf) construction, of which Cyclist is a
//! refinement, and both of which rely on the sponge and fully-keyed sponge security arguments.
//! Specifically, hash rates are calculated as `b-2k` for `k` bits of security, keyed absorb rates
//! are calculated as `b-W` where `W` is 64 bits for ~256-bit security and 32 bits for ~128-bit
//! security, and keyed squeeze rates are calculated as `b-k` for `k` bits of security.

use byteorder::{ByteOrder, LittleEndian};
use zeroize::Zeroize;

use crate::{CyclistHash, CyclistKeyed, Permutation};

/// A Cyclist hash using Keccak-f\[1600\] and r=576 (the same as SHA-3), offering 256-bit security
/// and a very conservative design.
pub type KeccakHash = CyclistHash<Keccak, { 1600 / 8 }, { 576 / 8 }>;

/// A keyed Cyclist using Keccak-f\[1600\] and r_absorb=1536/r_squeeze=1344, offering 256-bit
/// security and a very conservative design.
pub type KeccakKeyed = CyclistKeyed<
    Keccak,
    { 1600 / 8 },
    { (1600 - 64) / 8 },  // R_kin=b-W
    { (1600 - 256) / 8 }, // R_kout=b-c
    32,
    32,
>;

/// A Cyclist hash using Keccak-f\[1600,14\] and r=1088 (the same as MarsupilamiFourteen), offering
/// 256-bit security and a performance-oriented design.
pub type M14Hash = CyclistHash<M14, { 1600 / 8 }, { (1600 - 512) / 8 }>;

/// A keyed Cyclist using Keccak-f\[1600,14\] and r_absorb=1536/r_squeeze=1344, offering 256-bit
/// security and a performance-oriented design.
pub type M14Keyed = CyclistKeyed<
    M14,
    { 1600 / 8 },
    { (1600 - 64) / 8 },  // R_kin=b-W
    { (1600 - 256) / 8 }, // R_kout=b-c
    32,
    32,
>;

/// A Cyclist hash using Keccak-f\[1600,12\] and r=1344 (the same as KangarooTwelve), offering
/// 128-bit security and a performance-oriented design.
pub type K12Hash = CyclistHash<K12, { 1600 / 8 }, { (1600 - 256) / 8 }>;

/// A keyed Cyclist using Keccak-f\[1600,12\] and r_absorb=1568/r_squeeze=1408, offering 128-bit
/// security and a performance-oriented design.
pub type K12Keyed = CyclistKeyed<
    K12,
    { 1600 / 8 },
    { (1600 - 32) / 8 },  // R_kin=b-W
    { (1600 - 192) / 8 }, // R_kout=b-c
    16,
    16,
>;

/// The KangarooTwelve permutation of Keccak-f\[1600,12\].
pub type K12 = KeccakP<12>;

/// The MarsupalamiFourteen permutation of Keccak-f\[1600,14\].
pub type M14 = KeccakP<14>;

/// The full Keccak-f\[1600\] permutation with 24 rounds.
pub type Keccak = KeccakP<24>;

/// The generic Keccak-p permutation, parameterized with 0≤R≤24 rounds.
#[derive(Clone)]
#[repr(align(8))]
pub struct KeccakP<const R: usize>([u8; 200]);

impl<const R: usize> Default for KeccakP<R> {
    fn default() -> Self {
        KeccakP([0u8; 200])
    }
}

impl<const R: usize> AsRef<[u8; 200]> for KeccakP<R> {
    fn as_ref(&self) -> &[u8; 200] {
        &self.0
    }
}

impl<const R: usize> AsMut<[u8; 200]> for KeccakP<R> {
    fn as_mut(&mut self) -> &mut [u8; 200] {
        &mut self.0
    }
}

impl<const R: usize> Zeroize for KeccakP<R> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const R: usize> Permutation<200> for KeccakP<R> {
    #[inline(always)]
    fn permute(&mut self) {
        let mut lanes = [0u64; 25];
        LittleEndian::read_u64_into(&self.0, &mut lanes);
        keccak1600::<R>(&mut lanes);
        LittleEndian::write_u64_into(&lanes, &mut self.0);
    }
}

#[inline(always)]
#[allow(clippy::unreadable_literal)]
fn keccak1600<const R: usize>(lanes: &mut [u64; 25]) {
    macro_rules! repeat4 {
        ($e: expr) => {
            $e;
            $e;
            $e;
            $e;
        };
    }

    macro_rules! repeat5 {
        ($e: expr) => {
            $e;
            $e;
            $e;
            $e;
            $e;
        };
    }

    macro_rules! repeat6 {
        ($e: expr) => {
            $e;
            $e;
            $e;
            $e;
            $e;
            $e;
        };
    }

    macro_rules! repeat24 {
        ($e: expr, $s: expr) => {
            repeat6!({
                $e;
                $s;
            });
            repeat6!({
                $e;
                $s;
            });
            repeat6!({
                $e;
                $s;
            });
            repeat5!({
                $e;
                $s;
            });
            $e;
        };
    }

    macro_rules! for5 {
        ($v: expr, $s: expr, $e: expr) => {
            $v = 0;
            repeat4!({
                $e;
                $v += $s;
            });
            $e;
        };
    }

    const MAX_ROUNDS: usize = 24;

    const ROUND_KEYS: [u64; MAX_ROUNDS] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    // (0..24).map(|t| ((t+1)*(t+2)/2) % 64)
    const RHO: [u32; MAX_ROUNDS] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PI: [usize; MAX_ROUNDS] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    let mut c = [0u64; 5];
    let (mut x, mut y): (usize, usize);

    for round_key in &ROUND_KEYS[(MAX_ROUNDS - R)..] {
        // θ
        for5!(x, 1, {
            c[x] = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
        });

        for5!(x, 1, {
            for5!(y, 5, {
                lanes[x + y] ^= c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            });
        });

        // ρ and π
        let mut a = lanes[1];
        x = 0;
        repeat24!(
            {
                c[0] = lanes[PI[x]];
                lanes[PI[x]] = a.rotate_left(RHO[x]);
            },
            {
                a = c[0];
                x += 1;
            }
        );

        // χ
        for5!(y, 5, {
            for5!(x, 1, {
                c[x] = lanes[x + y];
            });
            for5!(x, 1, {
                lanes[x + y] = c[x] ^ ((!c[(x + 1) % 5]) & c[(x + 2) % 5]);
            });
        });

        // ι
        lanes[0] ^= round_key;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_kat() {
        let mut state = Keccak::default();
        state.permute();
        assert_eq!(
            state.as_ref(),
            &[
                0xe7, 0xdd, 0xe1, 0x40, 0x79, 0x8f, 0x25, 0xf1, 0x8a, 0x47, 0xc0, 0x33, 0xf9, 0xcc,
                0xd5, 0x84, 0xee, 0xa9, 0x5a, 0xa6, 0x1e, 0x26, 0x98, 0xd5, 0x4d, 0x49, 0x80, 0x6f,
                0x30, 0x47, 0x15, 0xbd, 0x57, 0xd0, 0x53, 0x62, 0x05, 0x4e, 0x28, 0x8b, 0xd4, 0x6f,
                0x8e, 0x7f, 0x2d, 0xa4, 0x97, 0xff, 0xc4, 0x47, 0x46, 0xa4, 0xa0, 0xe5, 0xfe, 0x90,
                0x76, 0x2e, 0x19, 0xd6, 0x0c, 0xda, 0x5b, 0x8c, 0x9c, 0x05, 0x19, 0x1b, 0xf7, 0xa6,
                0x30, 0xad, 0x64, 0xfc, 0x8f, 0xd0, 0xb7, 0x5a, 0x93, 0x30, 0x35, 0xd6, 0x17, 0x23,
                0x3f, 0xa9, 0x5a, 0xeb, 0x03, 0x21, 0x71, 0x0d, 0x26, 0xe6, 0xa6, 0xa9, 0x5f, 0x55,
                0xcf, 0xdb, 0x16, 0x7c, 0xa5, 0x81, 0x26, 0xc8, 0x47, 0x03, 0xcd, 0x31, 0xb8, 0x43,
                0x9f, 0x56, 0xa5, 0x11, 0x1a, 0x2f, 0xf2, 0x01, 0x61, 0xae, 0xd9, 0x21, 0x5a, 0x63,
                0xe5, 0x05, 0xf2, 0x70, 0xc9, 0x8c, 0xf2, 0xfe, 0xbe, 0x64, 0x11, 0x66, 0xc4, 0x7b,
                0x95, 0x70, 0x36, 0x61, 0xcb, 0x0e, 0xd0, 0x4f, 0x55, 0x5a, 0x7c, 0xb8, 0xc8, 0x32,
                0xcf, 0x1c, 0x8a, 0xe8, 0x3e, 0x8c, 0x14, 0x26, 0x3a, 0xae, 0x22, 0x79, 0x0c, 0x94,
                0xe4, 0x09, 0xc5, 0xa2, 0x24, 0xf9, 0x41, 0x18, 0xc2, 0x65, 0x04, 0xe7, 0x26, 0x35,
                0xf5, 0x16, 0x3b, 0xa1, 0x30, 0x7f, 0xe9, 0x44, 0xf6, 0x75, 0x49, 0xa2, 0xec, 0x5c,
                0x7b, 0xff, 0xf1, 0xea,
            ]
        );
    }

    #[test]
    fn m14_kat() {
        let mut state = M14::default();
        state.permute();
        assert_eq!(
            state.as_ref(),
            &[
                0xf4, 0x39, 0xae, 0x25, 0x60, 0x5c, 0x05, 0x93, 0xa5, 0xf3, 0x72, 0x67, 0xc1, 0x77,
                0xba, 0xff, 0xea, 0x51, 0x5a, 0x55, 0xd5, 0x61, 0xed, 0x51, 0xcc, 0xf0, 0xe5, 0x5c,
                0x83, 0xd0, 0x58, 0x53, 0x3e, 0xfb, 0x72, 0xdf, 0x77, 0xac, 0x01, 0xae, 0x50, 0x9a,
                0x12, 0xac, 0x85, 0x7f, 0x76, 0xe0, 0x64, 0xf0, 0xd0, 0x9c, 0x50, 0x02, 0x0b, 0xce,
                0xca, 0x7f, 0xf5, 0xf6, 0x4b, 0xce, 0xcf, 0xf7, 0xe1, 0x16, 0x83, 0x90, 0xf1, 0xb1,
                0x81, 0xac, 0x53, 0x05, 0x59, 0x89, 0xa3, 0xf0, 0xeb, 0x4d, 0x03, 0x3b, 0x18, 0xfa,
                0xe8, 0x2c, 0x09, 0x86, 0xad, 0xc2, 0xd9, 0xa4, 0x44, 0x16, 0x59, 0x4e, 0xdd, 0xa0,
                0x1c, 0x26, 0x69, 0xa3, 0xb0, 0x2a, 0x96, 0x45, 0xa8, 0x1a, 0x10, 0x8c, 0x19, 0xd3,
                0xce, 0x10, 0x2c, 0x58, 0x4a, 0x47, 0x01, 0x61, 0x39, 0x0d, 0xe9, 0x3a, 0x62, 0x48,
                0x16, 0x86, 0xd6, 0x7a, 0x05, 0x09, 0x32, 0xe4, 0x65, 0xe4, 0x32, 0xe5, 0x1a, 0x19,
                0x81, 0xaa, 0xb6, 0x3b, 0xe2, 0xb7, 0xa6, 0x42, 0x55, 0x5e, 0x54, 0xe9, 0xbc, 0x78,
                0x3c, 0xa5, 0x72, 0xae, 0x31, 0x42, 0x94, 0x80, 0x81, 0x8d, 0x64, 0x26, 0x86, 0xa7,
                0x6e, 0xcd, 0xfc, 0x0c, 0xf6, 0x94, 0x55, 0x41, 0x88, 0x28, 0xc2, 0x11, 0xa3, 0x98,
                0xb0, 0xe0, 0xe8, 0xae, 0x31, 0xe1, 0x85, 0xd2, 0x17, 0x6f, 0x50, 0x11, 0x90, 0x99,
                0xe1, 0xd0, 0xf8, 0x43,
            ]
        );
    }

    #[test]
    fn k12_kat() {
        let mut state = K12::default();
        state.permute();
        assert_eq!(
            state.as_ref(),
            &[
                0x17, 0x86, 0xa7, 0xb9, 0x38, 0x54, 0x5e, 0x8e, 0x1e, 0xd0, 0x59, 0xf2, 0x50, 0x6a,
                0xcd, 0xd9, 0x35, 0x1f, 0xa9, 0x52, 0xc6, 0xe7, 0xb8, 0x87, 0xc5, 0xe0, 0xe4, 0xcd,
                0x67, 0xe0, 0x93, 0x10, 0x45, 0x5a, 0xd9, 0xf2, 0x90, 0xab, 0x33, 0xb0, 0x45, 0x1a,
                0xdd, 0xa8, 0x72, 0x2f, 0xa7, 0xe0, 0x9c, 0x2f, 0x67, 0x14, 0xaa, 0x80, 0x37, 0xc5,
                0x1d, 0x07, 0x51, 0x00, 0xf5, 0x47, 0xdd, 0x3e, 0xcc, 0x8a, 0x17, 0x0c, 0x31, 0x1d,
                0xa3, 0xb3, 0xa0, 0xaa, 0x57, 0x92, 0xa5, 0x86, 0xb5, 0x79, 0x9b, 0xf9, 0xb1, 0xb3,
                0x3d, 0x7c, 0x4a, 0xbc, 0x93, 0x67, 0x8a, 0xe6, 0x63, 0x40, 0x87, 0x68, 0x66, 0x25,
                0x0e, 0x2e, 0x33, 0x03, 0x6c, 0x5c, 0xda, 0x30, 0xf0, 0xb9, 0x02, 0x12, 0xaa, 0x9c,
                0x9f, 0x7a, 0xcf, 0x2b, 0x78, 0x9a, 0x3b, 0x5f, 0x23, 0x79, 0xae, 0x61, 0xe0, 0xc1,
                0x36, 0xe5, 0xec, 0x87, 0x3c, 0xb7, 0x18, 0xb6, 0xe9, 0x6d, 0xc2, 0x8a, 0x91, 0x70,
                0xf1, 0xd1, 0xbe, 0x2a, 0xb7, 0x24, 0xed, 0xda, 0x53, 0xbd, 0xab, 0x6a, 0x5a, 0xe1,
                0x2e, 0x2c, 0x6a, 0x41, 0xc1, 0xbf, 0xaf, 0x52, 0x09, 0xb9, 0x36, 0xe0, 0xcf, 0xc6,
                0xd7, 0x60, 0x70, 0xdc, 0x17, 0x36, 0x50, 0x45, 0xe4, 0x7a, 0x9f, 0xc2, 0xb2, 0x11,
                0x56, 0x62, 0x7a, 0x64, 0x30, 0x2c, 0xdb, 0x71, 0x36, 0xd4, 0x1c, 0xa0, 0x2c, 0x22,
                0x76, 0x0d, 0xfd, 0xcf,
            ]
        );
    }

    #[test]
    fn round_trip() {
        let mut d = KeccakKeyed::new(b"ok then", None, None, None);
        let m = b"it's a deal".to_vec();
        let c = d.seal(&m);

        let mut d = KeccakKeyed::new(b"ok then", None, None, None);
        let p = d.open(&c);

        assert_eq!(Some(m), p);
    }
}
