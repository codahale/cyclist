use rawbytes::RawBytes;

use crate::{keccak1600, CyclistHash, CyclistKeyed, Permutation};

pub type KeccakHash = CyclistHash<Keccak, { 200 - (32 * 2) }>;

pub type KeccakKeyed = CyclistKeyed<Keccak, { 200 - (32 / 4) }, { 200 / 2 }, 32, 16>;

#[derive(Clone, Default)]
pub struct Keccak([u64; 25]);

impl Permutation for Keccak {
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
        keccak1600::permute::<24>(&mut self.0)
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
