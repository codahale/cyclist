use rawbytes::RawBytes;

use crate::{keccak1600, CyclistHash, CyclistKeyed, Permutation};

pub type K12Hash = CyclistHash<KangarooTwelve, { 200 - (32 * 2) }>;

pub type K12Keyed = CyclistKeyed<KangarooTwelve, { 200 - (32 / 4) }, { 200 / 2 }, 32, 16>;

#[derive(Clone, Default)]
pub struct KangarooTwelve([u64; 25]);

impl Permutation for KangarooTwelve {
    const WIDTH: usize = 200;

    fn bytes_view(&self) -> &[u8] {
        RawBytes::bytes_view(&self.0)
    }

    fn bytes_view_mut(&mut self) -> &mut [u8] {
        RawBytes::bytes_view_mut(&mut self.0)
    }

    fn endian_swap(&mut self) {
        if cfg!(target_endian = "big") {
            for n in self.0.iter_mut() {
                *n = n.to_le();
            }
        }
    }

    fn permute(&mut self) {
        keccak1600::permute::<12>(&mut self.0)
    }
}
