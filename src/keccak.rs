use crate::{keccak1600, CyclistHash, CyclistKeyed, Permutation};
use byteorder::{ByteOrder, LittleEndian};

pub type KeccakHash = CyclistHash<Keccak, 200, { 200 - (32 * 2) }>;

pub type KeccakKeyed = CyclistKeyed<Keccak, 200, { 200 - (32 / 4) }, { 200 / 2 }, 32, 16>;

#[derive(Clone)]
#[repr(align(8))]
pub struct Keccak([u8; 200]);

impl Default for Keccak {
    fn default() -> Self {
        Keccak([0u8; 200])
    }
}

impl Permutation<200> for Keccak {
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
        keccak1600::permute::<24>(&mut st);
        LittleEndian::write_u64_into(&st, &mut self.0);
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
