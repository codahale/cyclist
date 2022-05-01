use crate::{keccak1600, CyclistHash, CyclistKeyed, Permutation};
use byteorder::{ByteOrder, LittleEndian};

pub type KeccakHash = CyclistHash<Keccak, { 200 - (32 * 2) }>;

pub type KeccakKeyed = CyclistKeyed<Keccak, { 200 - (32 / 4) }, { 200 / 2 }, 32, 16>;

#[derive(Clone, Default)]
pub struct Keccak([u64; 25]);

impl Permutation for Keccak {
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
        keccak1600::permute::<24>(&mut self.0);
        LittleEndian::from_slice_u64(&mut self.0);
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
