use byteorder::{ByteOrder, LittleEndian};

use crate::{keccak1600, CyclistHash, CyclistKeyed, Permutation};

pub type K12Hash = CyclistHash<KangarooTwelve, 200, { 200 - (32 * 2) }>;

pub type K12Keyed = CyclistKeyed<KangarooTwelve, 200, { 200 - (32 / 4) }, { 200 / 2 }, 32, 16>;

#[derive(Clone)]
#[repr(align(8))]
pub struct KangarooTwelve([u8; 200]);

impl Default for KangarooTwelve {
    fn default() -> Self {
        KangarooTwelve([0u8; 200])
    }
}

impl Permutation<200> for KangarooTwelve {
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
        keccak1600::permute::<12>(&mut st);
        LittleEndian::write_u64_into(&st, &mut self.0);
    }
}
