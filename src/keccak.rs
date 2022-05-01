use crate::{CyclistHash, CyclistKeyed, Permutation};
use byteorder::{ByteOrder, LittleEndian};

/// A Cyclist hash using Keccak-f\[1600\] and r=576 (the same as SHA-3).
pub type KeccakHash = CyclistHash<Keccak<24>, 200, 72>;

/// A keyed Cyclist using Keccak-f\[1600\] and r_absorb=1472/r_squeeze=800.
pub type KeccakKeyed = CyclistKeyed<Keccak<24>, 200, { 200 - 16 }, { 200 / 2 }, 32, 16>;

/// A Cyclist hash using Keccak-f\[1600,14\] and r=1088 (the same as MarsupilamiFourteen).
pub type M14Hash = CyclistHash<Keccak<14>, 200, 136>;

/// A keyed Cyclist using Keccak-f\[1600,14\] and r_absorb=1536/r_squeeze=800.
pub type M14Keyed = CyclistKeyed<Keccak<14>, 200, { 200 - 8 }, { 200 / 2 }, 32, 16>;

/// A Cyclist hash using Keccak-f\[1600,12\] and r=1344 (the same as KangarooTwelve).
pub type K12Hash = CyclistHash<Keccak<12>, 200, 168>;

/// A keyed Cyclist using Keccak-f\[1600,12\] and r_absorb=1568/r_squeeze=800.
pub type K12Keyed = CyclistKeyed<Keccak<12>, 200, { 200 - 4 }, { 200 / 2 }, 16, 16>;

#[derive(Clone)]
#[repr(align(8))]
pub struct Keccak<const R: usize>([u8; 200]);

impl<const R: usize> Default for Keccak<R> {
    fn default() -> Self {
        Keccak([0u8; 200])
    }
}

impl<const R: usize> Permutation<200> for Keccak<R> {
    fn state(&self) -> &[u8; 200] {
        &self.0
    }

    fn state_mut(&mut self) -> &mut [u8; 200] {
        &mut self.0
    }

    #[inline(always)]
    fn permute(&mut self) {
        let mut st = [0u64; 25];
        LittleEndian::read_u64_into(&self.0, &mut st);
        keccak1600::<R>(&mut st);
        LittleEndian::write_u64_into(&st, &mut self.0);
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

    const RC: [u64; MAX_ROUNDS] = [
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

    #[allow(clippy::needless_range_loop)]
    for round in 0..R {
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
        lanes[0] ^= RC[round + (MAX_ROUNDS - R)];
    }
}

#[cfg(test)]
mod tests {
    use crate::keccak::KeccakKeyed;

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
