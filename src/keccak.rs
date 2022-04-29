use rawbytes::RawBytes;

use crate::{CyclistHash, CyclistKeyed, Permutation};

pub type KeccakHash = CyclistHash<Keccak, 200, 168, 168>;

pub type KeccakKeyed = CyclistKeyed<Keccak, 200, 192, 100, 32, 16>;

#[derive(Clone, Default)]
pub struct Keccak([u64; 25]);

impl Permutation<200> for Keccak {
    fn bytes_view(&self) -> &[u8] {
        RawBytes::bytes_view(&self.0)
    }

    fn bytes_view_mut(&mut self) -> &mut [u8] {
        RawBytes::bytes_view_mut(&mut self.0)
    }

    fn endian_swap(&mut self) {
        for word in self.0.iter_mut() {
            *word = (*word).to_le()
        }
    }

    fn permute(&mut self) {
        keccak::f1600(&mut self.0)
    }
}
