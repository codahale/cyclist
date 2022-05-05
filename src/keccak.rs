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
    { (1600 - 64) / 8 },  // R_absorb=b-W
    { (1600 - 256) / 8 }, // R_squeeze=b-c
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
    { (1600 - 64) / 8 },  // R_absorb=b-W
    { (1600 - 256) / 8 }, // R_squeeze=b-c
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
    { (1600 - 32) / 8 },  // R_absorb=b-W
    { (1600 - 192) / 8 }, // R_squeeze=b-c
    16,
    16,
>;

/// The KangarooTwelve permutation of Keccak-f\[1600,12\].
pub type K12 = KeccakP<12>;

/// The MarsupilamiFourteen permutation of Keccak-f\[1600,14\].
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

/// A port of XKCP's `K1600-plain-64bits-ua` implementation of Keccak-f\[1600\]. It optimizes
/// performance by unrolling and merge two rounds; as a result, only even numbers of rounds are
/// supported.
#[inline(always)]
fn keccak1600<const R: usize>(lanes: &mut [u64; 25]) {
    debug_assert!(R % 2 == 0, "only even numbers of rounds allowed");

    let mut a_ba = lanes[0];
    let mut a_be = lanes[1];
    let mut a_bi = lanes[2];
    let mut a_bo = lanes[3];
    let mut a_bu = lanes[4];
    let mut a_ga = lanes[5];
    let mut a_ge = lanes[6];
    let mut a_gi = lanes[7];
    let mut a_go = lanes[8];
    let mut a_gu = lanes[9];
    let mut a_ka = lanes[10];
    let mut a_ke = lanes[11];
    let mut a_ki = lanes[12];
    let mut a_ko = lanes[13];
    let mut a_ku = lanes[14];
    let mut a_ma = lanes[15];
    let mut a_me = lanes[16];
    let mut a_mi = lanes[17];
    let mut a_mo = lanes[18];
    let mut a_mu = lanes[19];
    let mut a_sa = lanes[20];
    let mut a_se = lanes[21];
    let mut a_si = lanes[22];
    let mut a_so = lanes[23];
    let mut a_su = lanes[24];
    let mut b_ba: u64;
    let mut b_be: u64;
    let mut b_bi: u64;
    let mut b_bo: u64;
    let mut b_bu: u64;
    let mut b_ga: u64;
    let mut b_ge: u64;
    let mut b_gi: u64;
    let mut b_go: u64;
    let mut b_gu: u64;
    let mut b_ka: u64;
    let mut b_ke: u64;
    let mut b_ki: u64;
    let mut b_ko: u64;
    let mut b_ku: u64;
    let mut b_ma: u64;
    let mut b_me: u64;
    let mut b_mi: u64;
    let mut b_mo: u64;
    let mut b_mu: u64;
    let mut b_sa: u64;
    let mut b_se: u64;
    let mut b_si: u64;
    let mut b_so: u64;
    let mut b_su: u64;
    let mut c_a = a_ba ^ a_ga ^ a_ka ^ a_ma ^ a_sa;
    let mut c_e = a_be ^ a_ge ^ a_ke ^ a_me ^ a_se;
    let mut c_i = a_bi ^ a_gi ^ a_ki ^ a_mi ^ a_si;
    let mut c_o = a_bo ^ a_go ^ a_ko ^ a_mo ^ a_so;
    let mut c_u = a_bu ^ a_gu ^ a_ku ^ a_mu ^ a_su;
    let mut d_a: u64;
    let mut d_e: u64;
    let mut d_i: u64;
    let mut d_o: u64;
    let mut d_u: u64;
    let mut e_ba: u64;
    let mut e_be: u64;
    let mut e_bi: u64;
    let mut e_bo: u64;
    let mut e_bu: u64;
    let mut e_ga: u64;
    let mut e_ge: u64;
    let mut e_gi: u64;
    let mut e_go: u64;
    let mut e_gu: u64;
    let mut e_ka: u64;
    let mut e_ke: u64;
    let mut e_ki: u64;
    let mut e_ko: u64;
    let mut e_ku: u64;
    let mut e_ma: u64;
    let mut e_me: u64;
    let mut e_mi: u64;
    let mut e_mo: u64;
    let mut e_mu: u64;
    let mut e_sa: u64;
    let mut e_se: u64;
    let mut e_si: u64;
    let mut e_so: u64;
    let mut e_su: u64;

    for i in ((MAX_ROUNDS - R)..MAX_ROUNDS).step_by(2) {
        d_a = c_u ^ c_e.rotate_left(1);
        d_e = c_a ^ c_i.rotate_left(1);
        d_i = c_e ^ c_o.rotate_left(1);
        d_o = c_i ^ c_u.rotate_left(1);
        d_u = c_o ^ c_a.rotate_left(1);
        a_ba ^= d_a;
        b_ba = a_ba;
        a_ge ^= d_e;
        b_be = a_ge.rotate_left(44);
        a_ki ^= d_i;
        b_bi = a_ki.rotate_left(43);
        a_mo ^= d_o;
        b_bo = a_mo.rotate_left(21);
        a_su ^= d_u;
        b_bu = a_su.rotate_left(14);
        e_ba = b_ba ^ ((!b_be) & b_bi);
        e_ba ^= ROUND_KEYS[i];
        c_a = e_ba;
        e_be = b_be ^ ((!b_bi) & b_bo);
        c_e = e_be;
        e_bi = b_bi ^ ((!b_bo) & b_bu);
        c_i = e_bi;
        e_bo = b_bo ^ ((!b_bu) & b_ba);
        c_o = e_bo;
        e_bu = b_bu ^ ((!b_ba) & b_be);
        c_u = e_bu;
        a_bo ^= d_o;
        b_ga = a_bo.rotate_left(28);
        a_gu ^= d_u;
        b_ge = a_gu.rotate_left(20);
        a_ka ^= d_a;
        b_gi = a_ka.rotate_left(3);
        a_me ^= d_e;
        b_go = a_me.rotate_left(45);
        a_si ^= d_i;
        b_gu = a_si.rotate_left(61);
        e_ga = b_ga ^ ((!b_ge) & b_gi);
        c_a ^= e_ga;
        e_ge = b_ge ^ ((!b_gi) & b_go);
        c_e ^= e_ge;
        e_gi = b_gi ^ ((!b_go) & b_gu);
        c_i ^= e_gi;
        e_go = b_go ^ ((!b_gu) & b_ga);
        c_o ^= e_go;
        e_gu = b_gu ^ ((!b_ga) & b_ge);
        c_u ^= e_gu;
        a_be ^= d_e;
        b_ka = a_be.rotate_left(1);
        a_gi ^= d_i;
        b_ke = a_gi.rotate_left(6);
        a_ko ^= d_o;
        b_ki = a_ko.rotate_left(25);
        a_mu ^= d_u;
        b_ko = a_mu.rotate_left(8);
        a_sa ^= d_a;
        b_ku = a_sa.rotate_left(18);
        e_ka = b_ka ^ ((!b_ke) & b_ki);
        c_a ^= e_ka;
        e_ke = b_ke ^ ((!b_ki) & b_ko);
        c_e ^= e_ke;
        e_ki = b_ki ^ ((!b_ko) & b_ku);
        c_i ^= e_ki;
        e_ko = b_ko ^ ((!b_ku) & b_ka);
        c_o ^= e_ko;
        e_ku = b_ku ^ ((!b_ka) & b_ke);
        c_u ^= e_ku;
        a_bu ^= d_u;
        b_ma = a_bu.rotate_left(27);
        a_ga ^= d_a;
        b_me = a_ga.rotate_left(36);
        a_ke ^= d_e;
        b_mi = a_ke.rotate_left(10);
        a_mi ^= d_i;
        b_mo = a_mi.rotate_left(15);
        a_so ^= d_o;
        b_mu = a_so.rotate_left(56);
        e_ma = b_ma ^ ((!b_me) & b_mi);
        c_a ^= e_ma;
        e_me = b_me ^ ((!b_mi) & b_mo);
        c_e ^= e_me;
        e_mi = b_mi ^ ((!b_mo) & b_mu);
        c_i ^= e_mi;
        e_mo = b_mo ^ ((!b_mu) & b_ma);
        c_o ^= e_mo;
        e_mu = b_mu ^ ((!b_ma) & b_me);
        c_u ^= e_mu;
        a_bi ^= d_i;
        b_sa = a_bi.rotate_left(62);
        a_go ^= d_o;
        b_se = a_go.rotate_left(55);
        a_ku ^= d_u;
        b_si = a_ku.rotate_left(39);
        a_ma ^= d_a;
        b_so = a_ma.rotate_left(41);
        a_se ^= d_e;
        b_su = a_se.rotate_left(2);
        e_sa = b_sa ^ ((!b_se) & b_si);
        c_a ^= e_sa;
        e_se = b_se ^ ((!b_si) & b_so);
        c_e ^= e_se;
        e_si = b_si ^ ((!b_so) & b_su);
        c_i ^= e_si;
        e_so = b_so ^ ((!b_su) & b_sa);
        c_o ^= e_so;
        e_su = b_su ^ ((!b_sa) & b_se);
        c_u ^= e_su;
        d_a = c_u ^ c_e.rotate_left(1);
        d_e = c_a ^ c_i.rotate_left(1);
        d_i = c_e ^ c_o.rotate_left(1);
        d_o = c_i ^ c_u.rotate_left(1);
        d_u = c_o ^ c_a.rotate_left(1);
        e_ba ^= d_a;
        b_ba = e_ba;
        e_ge ^= d_e;
        b_be = e_ge.rotate_left(44);
        e_ki ^= d_i;
        b_bi = e_ki.rotate_left(43);
        e_mo ^= d_o;
        b_bo = e_mo.rotate_left(21);
        e_su ^= d_u;
        b_bu = e_su.rotate_left(14);
        a_ba = b_ba ^ ((!b_be) & b_bi);
        a_ba ^= ROUND_KEYS[i + 1];
        c_a = a_ba;
        a_be = b_be ^ ((!b_bi) & b_bo);
        c_e = a_be;
        a_bi = b_bi ^ ((!b_bo) & b_bu);
        c_i = a_bi;
        a_bo = b_bo ^ ((!b_bu) & b_ba);
        c_o = a_bo;
        a_bu = b_bu ^ ((!b_ba) & b_be);
        c_u = a_bu;
        e_bo ^= d_o;
        b_ga = e_bo.rotate_left(28);
        e_gu ^= d_u;
        b_ge = e_gu.rotate_left(20);
        e_ka ^= d_a;
        b_gi = e_ka.rotate_left(3);
        e_me ^= d_e;
        b_go = e_me.rotate_left(45);
        e_si ^= d_i;
        b_gu = e_si.rotate_left(61);
        a_ga = b_ga ^ ((!b_ge) & b_gi);
        c_a ^= a_ga;
        a_ge = b_ge ^ ((!b_gi) & b_go);
        c_e ^= a_ge;
        a_gi = b_gi ^ ((!b_go) & b_gu);
        c_i ^= a_gi;
        a_go = b_go ^ ((!b_gu) & b_ga);
        c_o ^= a_go;
        a_gu = b_gu ^ ((!b_ga) & b_ge);
        c_u ^= a_gu;
        e_be ^= d_e;
        b_ka = e_be.rotate_left(1);
        e_gi ^= d_i;
        b_ke = e_gi.rotate_left(6);
        e_ko ^= d_o;
        b_ki = e_ko.rotate_left(25);
        e_mu ^= d_u;
        b_ko = e_mu.rotate_left(8);
        e_sa ^= d_a;
        b_ku = e_sa.rotate_left(18);
        a_ka = b_ka ^ ((!b_ke) & b_ki);
        c_a ^= a_ka;
        a_ke = b_ke ^ ((!b_ki) & b_ko);
        c_e ^= a_ke;
        a_ki = b_ki ^ ((!b_ko) & b_ku);
        c_i ^= a_ki;
        a_ko = b_ko ^ ((!b_ku) & b_ka);
        c_o ^= a_ko;
        a_ku = b_ku ^ ((!b_ka) & b_ke);
        c_u ^= a_ku;
        e_bu ^= d_u;
        b_ma = e_bu.rotate_left(27);
        e_ga ^= d_a;
        b_me = e_ga.rotate_left(36);
        e_ke ^= d_e;
        b_mi = e_ke.rotate_left(10);
        e_mi ^= d_i;
        b_mo = e_mi.rotate_left(15);
        e_so ^= d_o;
        b_mu = e_so.rotate_left(56);
        a_ma = b_ma ^ ((!b_me) & b_mi);
        c_a ^= a_ma;
        a_me = b_me ^ ((!b_mi) & b_mo);
        c_e ^= a_me;
        a_mi = b_mi ^ ((!b_mo) & b_mu);
        c_i ^= a_mi;
        a_mo = b_mo ^ ((!b_mu) & b_ma);
        c_o ^= a_mo;
        a_mu = b_mu ^ ((!b_ma) & b_me);
        c_u ^= a_mu;
        e_bi ^= d_i;
        b_sa = e_bi.rotate_left(62);
        e_go ^= d_o;
        b_se = e_go.rotate_left(55);
        e_ku ^= d_u;
        b_si = e_ku.rotate_left(39);
        e_ma ^= d_a;
        b_so = e_ma.rotate_left(41);
        e_se ^= d_e;
        b_su = e_se.rotate_left(2);
        a_sa = b_sa ^ ((!b_se) & b_si);
        c_a ^= a_sa;
        a_se = b_se ^ ((!b_si) & b_so);
        c_e ^= a_se;
        a_si = b_si ^ ((!b_so) & b_su);
        c_i ^= a_si;
        a_so = b_so ^ ((!b_su) & b_sa);
        c_o ^= a_so;
        a_su = b_su ^ ((!b_sa) & b_se);
        c_u ^= a_su;
    }

    lanes[0] = a_ba;
    lanes[1] = a_be;
    lanes[2] = a_bi;
    lanes[3] = a_bo;
    lanes[4] = a_bu;
    lanes[5] = a_ga;
    lanes[6] = a_ge;
    lanes[7] = a_gi;
    lanes[8] = a_go;
    lanes[9] = a_gu;
    lanes[10] = a_ka;
    lanes[11] = a_ke;
    lanes[12] = a_ki;
    lanes[13] = a_ko;
    lanes[14] = a_ku;
    lanes[15] = a_ma;
    lanes[16] = a_me;
    lanes[17] = a_mi;
    lanes[18] = a_mo;
    lanes[19] = a_mu;
    lanes[20] = a_sa;
    lanes[21] = a_se;
    lanes[22] = a_si;
    lanes[23] = a_so;
    lanes[24] = a_su;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_kat() {
        // test vector produced by XKCP rev 2a8d2311a830ab3037f8c7ef2511e5c7cc032127
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
        // test vector produced by XKCP rev 2a8d2311a830ab3037f8c7ef2511e5c7cc032127
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
        // test vector produced by XKCP rev 2a8d2311a830ab3037f8c7ef2511e5c7cc032127
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
        let mut d = KeccakKeyed::new(b"ok then", None, None);
        let m = b"it's a deal".to_vec();
        let c = d.seal(&m);

        let mut d = KeccakKeyed::new(b"ok then", None, None);
        let p = d.open(&c);

        assert_eq!(Some(m), p);
    }
}
