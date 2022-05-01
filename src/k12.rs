use crate::{keccak1600, CyclistHash, CyclistKeyed, Permutation};
use byteorder::{ByteOrder, LittleEndian};

pub type K12Hash = CyclistHash<KangarooTwelve, { 200 - (32 * 2) }>;

pub type K12Keyed = CyclistKeyed<KangarooTwelve, { 200 - (32 / 4) }, { 200 / 2 }, 32, 16>;

#[derive(Clone, Default)]
pub struct KangarooTwelve([u64; 25]);

impl Permutation for KangarooTwelve {
    type State = [u64; 25];

    const WIDTH: usize = 200;

    #[inline(always)]
    fn state(&self) -> &Self::State {
        &self.0
    }

    #[inline(always)]
    fn state_mut(&mut self) -> &mut Self::State {
        &mut self.0
    }

    #[inline(always)]
    fn permute(&mut self) {
        LittleEndian::from_slice_u64(&mut self.0);
        keccak1600::permute::<12>(&mut self.0);
        LittleEndian::from_slice_u64(&mut self.0);
    }
}
