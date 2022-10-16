#![cfg(feature = "keccyak")]

//! A collection of Cyclist/Keccak-_p_ (aka Keccyak) schemes.
//!
//! The four schemes are:
//!
//! 1. [`KeccyakMaxHash`] and [`KeccyakMaxKeyed`], which use the full Keccak-f\[1600\] permutation,
//!    are parameterized to offer ~256-bit security with a very conservative design.
//! 2. [`Keccyak256Hash`] and [`Keccyak256Keyed`], which use the 14-round Keccak-p\[1600,14\]
//!    permutation, are parameterized to offer ~256-bit security with a performance-oriented design.
//! 3. [`Keccyak128Hash`] and [`Keccyak128Keyed`], which use the 12-round Keccak-p\[1600,12\]
//!    permutation, are parameterized to offer ~128-bit security with a performance-oriented design.
//! 4. [`KeccyakMinHash`] and [`KeccyakMinKeyed`], which use the 10-round Keccak-p\[1600,10\]
//!    permutation, are parameterized to offer ~128-bit security with a very performance-oriented
//!    design.
//!
//! Parameters were chosen based on the discussion of the
//! [Motorist](https://keccak.team/files/Keyakv2-doc2.2.pdf) construction, of which Cyclist is a
//! refinement, and both of which rely on the sponge and fully-keyed sponge security arguments.
//! Specifically, hash rates are calculated as `b-2k` for `k` bits of security, keyed absorb rates
//! are calculated as `b-W` where `W` is 64 bits for ~256-bit security and 32 bits for ~128-bit
//! security, and keyed squeeze rates are calculated as `b-k` for `k` bits of security.
//!
//! **N.B:** This is not a published configuration for Cyclist and there are no official security
//! analyses or specifications.

use crate::macros::{bytes_to_lanes, lanes_to_bytes};
use crate::{CyclistHash, CyclistKeyed, Permutation};

/// A Cyclist hash using Keccak-f\[1600\] and `r=1088`, offering 256-bit security and a very
/// conservative design.
pub type KeccyakMaxHash = CyclistHash<KeccakF1600, { 1600 / 8 }, { (1600 - 512) / 8 }>;

/// A keyed Cyclist using Keccak-f\[1600\] and `r_absorb=1536`/`r_squeeze=1344`, offering 256-bit
/// security and a very conservative design.
pub type KeccyakMaxKeyed = CyclistKeyed<
    KeccakF1600,
    { 1600 / 8 },
    { (1600 - 64) / 8 },  // R_absorb=b-W
    { (1600 - 256) / 8 }, // R_squeeze=b-c
    32,
    32,
>;

/// A Cyclist hash using Keccak-p\[1600,14\] and `r=1088`, offering 256-bit security and a
/// performance-oriented design.
pub type Keccyak256Hash = CyclistHash<KeccakP1600_14, { 1600 / 8 }, { (1600 - 512) / 8 }>;

/// A keyed Cyclist using Keccak-p\[1600,14\] and `r_absorb=1536`/`r_squeeze=1344`, offering 256-bit
/// security and a performance-oriented design.
pub type Keccyak256Keyed = CyclistKeyed<
    KeccakP1600_14,
    { 1600 / 8 },
    { (1600 - 64) / 8 },  // R_absorb=b-W
    { (1600 - 256) / 8 }, // R_squeeze=b-c
    32,
    32,
>;

/// A Cyclist hash using Keccak-p\[1600,12\] and `r=1344`, offering 128-bit security and a
/// performance-oriented design.
pub type Keccyak128Hash = CyclistHash<KeccakP1600_12, { 1600 / 8 }, { (1600 - 256) / 8 }>;

/// A keyed Cyclist using Keccak-p\[1600,12\] and `r_absorb=1568`/`r_squeeze=1408`, offering 128-bit
/// security and a performance-oriented design.
pub type Keccyak128Keyed = CyclistKeyed<
    KeccakP1600_12,
    { 1600 / 8 },
    { (1600 - 32) / 8 },  // R_absorb=b-W
    { (1600 - 192) / 8 }, // R_squeeze=b-c
    16,
    16,
>;

/// A Cyclist hash using Keccak-p\[1600,10\] and `r=1344`, offering 128-bit security and a
/// very performance-oriented design.
pub type KeccyakMinHash = CyclistHash<KeccakP1600_10, { 1600 / 8 }, { (1600 - 256) / 8 }>;

/// A keyed Cyclist using Keccak-p\[1600,10\] and `r_absorb=1568`/`r_squeeze=1408`, offering 128-bit
/// security and a very performance-oriented design.
pub type KeccyakMinKeyed = CyclistKeyed<
    KeccakP1600_10,
    { 1600 / 8 },
    { (1600 - 32) / 8 },  // R_absorb=b-W
    { (1600 - 192) / 8 }, // R_squeeze=b-c
    16,
    16,
>;

/// The Keccak-p\[1600,10\] permutation (aka KitTen).
#[derive(Clone, Debug)]
#[repr(align(8))]
pub struct KeccakP1600_10([u8; 200]);

impl Default for KeccakP1600_10 {
    fn default() -> Self {
        KeccakP1600_10([0u8; 200])
    }
}

impl AsRef<[u8; 200]> for KeccakP1600_10 {
    fn as_ref(&self) -> &[u8; 200] {
        &self.0
    }
}

impl AsMut<[u8; 200]> for KeccakP1600_10 {
    fn as_mut(&mut self) -> &mut [u8; 200] {
        &mut self.0
    }
}

impl Permutation<200> for KeccakP1600_10 {
    #[inline(always)]
    fn permute(&mut self) {
        let mut lanes = [0u64; 25];
        bytes_to_lanes!(u64, self.0, lanes);
        keccak_p::keccak_p1600_10(&mut lanes);
        lanes_to_bytes!(u64, lanes, self.0);
    }
}

/// The Keccak-p\[1600,12\] permutation from the KangarooTwelve XOF/hash function.
#[derive(Clone, Debug)]
#[repr(align(8))]
pub struct KeccakP1600_12([u8; 200]);

impl Default for KeccakP1600_12 {
    fn default() -> Self {
        KeccakP1600_12([0u8; 200])
    }
}

impl AsRef<[u8; 200]> for KeccakP1600_12 {
    fn as_ref(&self) -> &[u8; 200] {
        &self.0
    }
}

impl AsMut<[u8; 200]> for KeccakP1600_12 {
    fn as_mut(&mut self) -> &mut [u8; 200] {
        &mut self.0
    }
}

impl Permutation<200> for KeccakP1600_12 {
    #[inline(always)]
    fn permute(&mut self) {
        let mut lanes = [0u64; 25];
        bytes_to_lanes!(u64, self.0, lanes);
        keccak_p::keccak_p1600_12(&mut lanes);
        lanes_to_bytes!(u64, lanes, self.0);
    }
}

/// The Keccak-p\[1600,14\] permutation from the MarsupilamiFourteen XOF/hash function.
#[derive(Clone, Debug)]
#[repr(align(8))]
pub struct KeccakP1600_14([u8; 200]);

impl Default for KeccakP1600_14 {
    fn default() -> Self {
        KeccakP1600_14([0u8; 200])
    }
}

impl AsRef<[u8; 200]> for KeccakP1600_14 {
    fn as_ref(&self) -> &[u8; 200] {
        &self.0
    }
}

impl AsMut<[u8; 200]> for KeccakP1600_14 {
    fn as_mut(&mut self) -> &mut [u8; 200] {
        &mut self.0
    }
}

impl Permutation<200> for KeccakP1600_14 {
    #[inline(always)]
    fn permute(&mut self) {
        let mut lanes = [0u64; 25];
        bytes_to_lanes!(u64, self.0, lanes);
        keccak_p::keccak_p1600_14(&mut lanes);
        lanes_to_bytes!(u64, lanes, self.0);
    }
}

/// The Keccak-f\[1600\] permutation from the SHA-3 hash algorithm.
#[derive(Clone, Debug)]
#[repr(align(8))]
pub struct KeccakF1600([u8; 200]);

impl Default for KeccakF1600 {
    fn default() -> Self {
        KeccakF1600([0u8; 200])
    }
}

impl AsRef<[u8; 200]> for KeccakF1600 {
    fn as_ref(&self) -> &[u8; 200] {
        &self.0
    }
}

impl AsMut<[u8; 200]> for KeccakF1600 {
    fn as_mut(&mut self) -> &mut [u8; 200] {
        &mut self.0
    }
}

impl Permutation<200> for KeccakF1600 {
    #[inline(always)]
    fn permute(&mut self) {
        let mut lanes = [0u64; 25];
        bytes_to_lanes!(u64, self.0, lanes);
        keccak_p::keccak_f1600(&mut lanes);
        lanes_to_bytes!(u64, lanes, self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut d = KeccyakMaxKeyed::new(b"ok then", b"", b"");
        let m = b"it's a deal".to_vec();
        let c = d.seal(&m);

        let mut d = KeccyakMaxKeyed::new(b"ok then", b"", b"");
        let p = d.open(&c);

        assert_eq!(Some(m), p);
    }
}
