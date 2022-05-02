#![cfg_attr(not(feature = "std"), no_std)]

use std::marker::PhantomData;

use subtle::{ConstantTimeEq, CtOption};
use zeroize::ZeroizeOnDrop;

pub mod keccak;
pub mod xoodoo;

/// A permutation bijectively maps all blocks of the given width to other blocks of the given width.
pub trait Permutation<const WIDTH: usize>: Clone {
    /// Returns a new state.
    #[inline(always)]
    fn new_state() -> [u8; WIDTH] {
        [0u8; WIDTH]
    }

    /// Permute the given state.
    fn permute(state: &mut [u8; WIDTH]);
}

/// The core implementation of the Cyclist mode. Parameterized with the permutation algorithm, the
/// permutation width, whether the mode is keyed or not, the absorb rate, the squeeze rate, and the
/// ratchet rate.
#[derive(Clone, Debug, ZeroizeOnDrop)]
struct CyclistCore<
    P,
    const WIDTH: usize,
    const KEYED: bool,
    const ABSORB_RATE: usize,
    const SQUEEZE_RATE: usize,
    const RATCHET_RATE: usize,
> where
    P: Permutation<WIDTH>,
{
    state: [u8; WIDTH],
    up: bool,
    #[zeroize(skip)]
    _permutation: PhantomData<P>,
}

impl<
        P,
        const WIDTH: usize,
        const KEYED: bool,
        const ABSORB_RATE: usize,
        const SQUEEZE_RATE: usize,
        const RATCHET_RATE: usize,
    > CyclistCore<P, WIDTH, KEYED, ABSORB_RATE, SQUEEZE_RATE, RATCHET_RATE>
where
    P: Permutation<WIDTH>,
{
    /// Returns a new Cyclist instance.
    fn new() -> Self {
        debug_assert!(ABSORB_RATE.max(SQUEEZE_RATE) + 2 <= WIDTH);

        CyclistCore {
            state: P::new_state(),
            up: true,
            _permutation: PhantomData::default(),
        }
    }

    /// Adds the given byte to the state at the given offset.
    #[inline(always)]
    fn add_byte(&mut self, byte: u8, offset: usize) {
        self.state[offset] ^= byte;
    }

    /// Adds the given bytes to the beginning of the state.
    #[inline(always)]
    fn add_bytes(&mut self, bytes: &[u8]) {
        for (st_byte, byte) in self.state.iter_mut().zip(bytes) {
            *st_byte ^= byte;
        }
    }

    /// Fills the given mutable slice with bytes from the state.
    #[inline(always)]
    fn extract_bytes(&mut self, out: &mut [u8]) {
        out.copy_from_slice(&self.state[..out.len()]);
    }

    /// Initiate the UP mode with a block of data and a domain separator.
    #[inline(always)]
    fn up(&mut self, out: Option<&mut [u8]>, cu: u8) {
        debug_assert!(out.as_ref().map(|x| x.len()).unwrap_or(0) <= SQUEEZE_RATE);
        self.up = true;
        if KEYED {
            self.add_byte(cu, WIDTH - 1);
        }
        P::permute(&mut self.state);
        if let Some(out) = out {
            self.extract_bytes(out);
        }
    }

    /// Initiate the DOWN mode with a block of data and a domain separator.
    #[inline(always)]
    fn down(&mut self, bin: Option<&[u8]>, cd: u8) {
        debug_assert!(bin.as_ref().map(|x| x.len()).unwrap_or(0) <= ABSORB_RATE);
        self.up = false;
        if let Some(bin) = bin {
            self.add_bytes(bin);
            self.add_byte(0x01, bin.len());
        } else {
            self.add_byte(0x01, 0);
        }
        if KEYED {
            self.add_byte(cd, WIDTH - 1);
        } else {
            self.add_byte(cd & 0x01, WIDTH - 1);
        }
    }

    /// Absorb a block of data at the given rate with the given DOWN mode domain separator.
    #[inline]
    fn absorb_any(&mut self, bin: &[u8], rate: usize, cd: u8) {
        let mut chunks_it = bin.chunks(rate);
        if !self.up {
            self.up(None, 0x00)
        }
        self.down(chunks_it.next(), cd);
        for chunk in chunks_it {
            self.up(None, 0x00);
            self.down(Some(chunk), 0x00);
        }
    }

    /// Squeeze a block of data with the given UP mode domain separator.
    #[inline]
    fn squeeze_any(&mut self, out: &mut [u8], cu: u8) {
        let mut chunks_it = out.chunks_mut(SQUEEZE_RATE);
        self.up(chunks_it.next(), cu);
        for chunk in chunks_it {
            self.down(None, 0x00);
            self.up(Some(chunk), 0x00);
        }
    }

    /// Absorb the given slice of data.
    #[inline(always)]
    fn absorb(&mut self, bin: &[u8]) {
        self.absorb_any(bin, ABSORB_RATE, 0x03);
    }

    /// Fill the given mutable slice with squeezed data.
    #[inline(always)]
    fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.squeeze_any(out, 0x40);
    }

    /// Return `n` bytes of squeezed data.
    #[cfg(feature = "std")]
    fn squeeze(&mut self, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        self.squeeze_mut(&mut b);
        b
    }

    /// Fill the given mutable slice with squeezed key data.
    #[inline(always)]
    fn squeeze_key_mut(&mut self, out: &mut [u8]) {
        self.squeeze_any(out, 0x20);
    }

    /// Return `n` bytes of squeezed key data.
    #[cfg(feature = "std")]
    fn squeeze_key(&mut self, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        self.squeeze_key_mut(&mut b);
        b
    }
}

/// A Cyclist object in hash mode. Parameterized with the permutation algorithm, the
/// permutation width, and the hash rate.
#[derive(Clone, Debug)]
pub struct CyclistHash<P, const WIDTH: usize, const HASH_RATE: usize>
where
    P: Permutation<WIDTH>,
{
    core: CyclistCore<P, WIDTH, false, HASH_RATE, HASH_RATE, 0>,
}

impl<P, const WIDTH: usize, const HASH_RATE: usize> Default for CyclistHash<P, WIDTH, HASH_RATE>
where
    P: Permutation<WIDTH>,
{
    fn default() -> Self {
        CyclistHash {
            core: CyclistCore::new(),
        }
    }
}

impl<P, const WIDTH: usize, const HASH_RATE: usize> CyclistHash<P, WIDTH, HASH_RATE>
where
    P: Permutation<WIDTH>,
{
    /// Absorb the given slice.
    pub fn absorb(&mut self, bin: &[u8]) {
        self.core.absorb(bin);
    }

    /// Fill the given mutable slice with squeezed data.
    pub fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_mut(out);
    }

    /// Return `n` bytes of squeezed data.
    #[cfg(feature = "std")]
    pub fn squeeze(&mut self, n: usize) -> Vec<u8> {
        self.core.squeeze(n)
    }

    /// Fill the given mutable slice with squeezed key data.
    pub fn squeeze_key_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_key_mut(out);
    }

    /// Return `n` bytes of squeezed key data.
    #[cfg(feature = "std")]
    pub fn squeeze_key(&mut self, n: usize) -> Vec<u8> {
        self.core.squeeze_key(n)
    }
}

/// A Cyclist object in keyed mode. Parameterized with the permutation algorithm, the
/// permutation width, the absorb rate, the squeeze rate, the ratchet rate, and the length of
/// authentication tags.
#[derive(Clone, Debug)]
pub struct CyclistKeyed<
    P,
    const WIDTH: usize,
    const ABSORB_RATE: usize,
    const SQUEEZE_RATE: usize,
    const RATCHET_RATE: usize,
    const TAG_LEN: usize,
> where
    P: Permutation<WIDTH>,
{
    core: CyclistCore<P, WIDTH, true, ABSORB_RATE, SQUEEZE_RATE, RATCHET_RATE>,
}

impl<
        P,
        const WIDTH: usize,
        const ABSORB_RATE: usize,
        const SQUEEZE_RATE: usize,
        const RATCHET_RATE: usize,
        const TAG_LEN: usize,
    > CyclistKeyed<P, WIDTH, ABSORB_RATE, SQUEEZE_RATE, RATCHET_RATE, TAG_LEN>
where
    P: Permutation<WIDTH>,
{
    /// Creates a new [CyclistKeyed] instance with the given key, optional nonce, optional key ID,
    /// and optional counter.
    pub fn new(
        key: &[u8],
        nonce: Option<&[u8]>,
        key_id: Option<&[u8]>,
        counter: Option<&[u8]>,
    ) -> Self {
        let mut core =
            CyclistCore::<P, WIDTH, true, ABSORB_RATE, SQUEEZE_RATE, RATCHET_RATE>::new();
        let key_id_len = key_id.unwrap_or_default().len();
        let nonce_len = nonce.unwrap_or_default().len();
        assert!(
            key.len() + key_id_len + nonce_len < ABSORB_RATE,
            "key, key_id, and nonce must be < {}",
            ABSORB_RATE,
        );

        let mut iv = [0u8; ABSORB_RATE];
        let key_len = key.len();
        iv[..key_len].copy_from_slice(key);
        let mut iv_len = key_len;

        iv[iv_len] = key_id_len as u8;
        iv_len += 1;

        if let Some(key_id) = key_id {
            let key_id_len = key_id.len();
            iv[iv_len..iv_len + key_id_len].copy_from_slice(key_id);
            iv_len += key_id_len;
        }

        if let Some(nonce) = nonce {
            let nonce_len = nonce.len();
            iv[iv_len..iv_len + nonce_len].copy_from_slice(nonce);
            iv_len += nonce_len;
        }

        core.absorb_any(&iv[..iv_len], ABSORB_RATE, 0x02);

        if let Some(counter) = counter {
            core.absorb_any(counter, 1, 0x00)
        }

        CyclistKeyed { core }
    }

    /// Absorb the given slice.
    pub fn absorb(&mut self, bin: &[u8]) {
        self.core.absorb(bin);
    }

    // Fill the given mutable slice with squeezed data.
    pub fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_mut(out);
    }

    /// Return `n` bytes of squeezed data.
    #[cfg(feature = "std")]
    pub fn squeeze(&mut self, n: usize) -> Vec<u8> {
        self.core.squeeze(n)
    }

    // Fill the given mutable slice with squeezed key data.
    pub fn squeeze_key_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_key_mut(out);
    }

    /// Return `n` bytes of squeezed key data.
    #[cfg(feature = "std")]
    pub fn squeeze_key(&mut self, n: usize) -> Vec<u8> {
        self.core.squeeze_key(n)
    }

    /// Encrypt the given mutable slice in place.
    pub fn encrypt_mut(&mut self, in_out: &mut [u8]) {
        let mut tmp = [0u8; SQUEEZE_RATE];
        let mut cu = 0x80;
        for in_out_chunk in in_out.chunks_mut(SQUEEZE_RATE) {
            self.core.up(Some(&mut tmp), cu);
            cu = 0x00;
            self.core.down(Some(in_out_chunk), 0x00);
            for (in_out_chunk_byte, tmp_byte) in in_out_chunk.iter_mut().zip(&tmp) {
                *in_out_chunk_byte ^= *tmp_byte;
            }
        }
    }

    /// Return an encrypted copy of the given slice.
    #[cfg(feature = "std")]
    pub fn encrypt(&mut self, bin: &[u8]) -> Vec<u8> {
        let mut c = bin.to_vec();
        self.encrypt_mut(&mut c);
        c
    }

    /// Decrypt the given mutable slice in place.
    pub fn decrypt_mut(&mut self, in_out: &mut [u8]) {
        let mut tmp = [0u8; SQUEEZE_RATE];
        let mut cu = 0x80;
        for in_out_chunk in in_out.chunks_mut(SQUEEZE_RATE) {
            self.core.up(Some(&mut tmp), cu);
            cu = 0x00;
            for (in_out_chunk_byte, tmp_byte) in in_out_chunk.iter_mut().zip(&tmp) {
                *in_out_chunk_byte ^= *tmp_byte;
            }
            self.core.down(Some(in_out_chunk), 0x00);
        }
    }

    /// Return an decrypted copy of the given slice.
    #[cfg(feature = "std")]
    pub fn decrypt(&mut self, bin: &[u8]) -> Vec<u8> {
        let mut c = bin.to_vec();
        self.decrypt_mut(&mut c);
        c
    }

    /// Ratchet the state, providing forward secrecy.
    pub fn ratchet(&mut self) {
        let mut rolled_key = [0u8; RATCHET_RATE];
        self.core.squeeze_any(&mut rolled_key, 0x10);
        self.core.absorb_any(&rolled_key, RATCHET_RATE, 0x00);
    }

    /// Seal the given mutable slice in place. The last `TAG_LEN` bytes of the slice will be
    /// overwritten with the authentication tag.
    pub fn seal_mut(&mut self, in_out: &mut [u8]) {
        let (c, t) = in_out.split_at_mut(in_out.len() - TAG_LEN);
        self.encrypt_mut(c);
        self.squeeze_mut(t);
    }

    /// Returns a sealed copy of the given slice. The returned [Vec] will be `TAG_LEN` bytes longer
    /// than `bin`.
    #[cfg(feature = "std")]
    pub fn seal(&mut self, bin: &[u8]) -> Vec<u8> {
        let mut c = vec![0u8; bin.len() + TAG_LEN];
        c[..bin.len()].copy_from_slice(bin);
        self.seal_mut(&mut c);
        c
    }

    /// Opens the given mutable slice in place. Returns `true` if the input was authenticated. The
    /// last `TAG_LEN` bytes of the slice will be unmodified.
    #[must_use]
    pub fn open_mut(&mut self, in_out: &mut [u8]) -> bool {
        let (c, t) = in_out.split_at_mut(in_out.len() - TAG_LEN);
        self.decrypt_mut(c);
        let mut t_p = [0u8; TAG_LEN];
        self.squeeze_mut(&mut t_p);
        t.ct_eq(&t_p).into()
    }

    /// Returns an unsealed copy of the given slice, or `None` if the ciphertext cannot be
    /// authenticated.
    #[cfg(feature = "std")]
    pub fn open(&mut self, bin: &[u8]) -> Option<Vec<u8>> {
        let mut c = bin[..bin.len() - TAG_LEN].to_vec();
        self.decrypt_mut(&mut c);

        let t = &bin[bin.len() - TAG_LEN..];
        let mut t_p = [0u8; TAG_LEN];
        self.squeeze_mut(&mut t_p);
        CtOption::new(c, t.ct_eq(&t_p)).into()
    }
}
