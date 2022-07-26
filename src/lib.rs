//! Cyclist is a mode of operation on top of a full-state keyed duplex construction which provides
//! fine-grained symmetric-key cryptographic services via stateful objects.
//!
//! # Message Digests
//!
//! ```rust
//! use cyclist::Cyclist;
//! use cyclist::xoodyak::XoodyakHash;
//!
//! let mut hash = XoodyakHash::default();
//! hash.absorb(b"This is an input message!");
//! let digest = hash.squeeze(16);
//!
//! assert_eq!(digest, vec![24, 79, 57, 49, 133, 57, 228, 222, 11, 95, 145, 57, 76, 16, 16, 122]);
//! ```
//!
//! # Message Authentication Codes
//!
//! ```rust
//! use cyclist::Cyclist;
//! use cyclist::xoodyak::XoodyakKeyed;
//!
//! let mut mac = XoodyakKeyed::new(b"This is a secret key!", None, None);
//! mac.absorb(b"This is an input message!");
//! let tag = mac.squeeze(16);
//!
//! assert_eq!(tag, vec![51, 9, 222, 84, 128, 163, 130, 40, 35, 128, 18, 50, 94, 35, 18, 220]);
//! ```
//!
//! # Authenticated Encryption And Data
//!
//! ```rust
//! use cyclist::Cyclist;
//! use cyclist::xoodyak::XoodyakKeyed;
//!
//! let mut aead = XoodyakKeyed::new(b"This is a secret key!", Some(b"This is a nonce!"), None);
//! aead.absorb(b"This is authenticated data!");
//! let ciphertext = aead.seal(b"This is the plaintext!");
//!
//! assert_eq!(ciphertext, vec![97, 247, 123, 78, 11, 4, 150, 39, 135, 111, 17, 144, 2, 213, 214, 67, 129, 74, 235, 106, 181, 3, 167, 200, 108, 162, 56, 51, 224, 223, 216, 143, 88, 206, 100, 125, 51, 44]);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]

use subtle::ConstantTimeEq;
#[cfg(feature = "std")]
use subtle::CtOption;
use zeroize::Zeroize;

#[cfg(feature = "keccyak")]
pub mod keccyak;
#[cfg(feature = "xoodyak")]
pub mod xoodyak;

/// A permutation bijectively maps all blocks of the given width to other blocks of the given width.
pub trait Permutation<const WIDTH: usize>:
    Clone + Default + AsRef<[u8; WIDTH]> + AsMut<[u8; WIDTH]> + Zeroize
{
    /// Adds the given byte to the state at the given offset.
    #[inline(always)]
    fn add_byte(&mut self, byte: u8, offset: usize) {
        self.as_mut()[offset] ^= byte;
    }

    /// Adds the given bytes to the beginning of the state.
    #[inline(always)]
    fn add_bytes(&mut self, bytes: &[u8]) {
        for (st_byte, byte) in self.as_mut().iter_mut().zip(bytes) {
            *st_byte ^= byte;
        }
    }

    /// Fills the given mutable slice with bytes from the state.
    #[inline(always)]
    fn extract_bytes(&mut self, out: &mut [u8]) {
        out.copy_from_slice(&self.as_ref()[..out.len()]);
    }

    /// Permutes the given state.
    fn permute(&mut self);
}

/// Cyclist operations which are common to both hash and keyed modes.
pub trait Cyclist {
    /// Returns the number of bytes which can be absorbed before the state is permuted.
    fn absorb_rate(&self) -> usize;

    /// Returns the number of bytes which can be squeezed before the state is permuted.
    fn squeeze_rate(&self) -> usize;

    /// Absorbs the given slice.
    fn absorb(&mut self, bin: &[u8]);

    /// Extends a previous absorb operation with the given slice.
    ///
    /// The previous absorb operation must have been done with a slice whose length is evenly
    /// divisible by the absorb rate in order for the two operations to be commutative.
    fn absorb_more(&mut self, bin: &[u8]);

    /// Fill the given mutable slice with squeezed data.
    fn squeeze_mut(&mut self, out: &mut [u8]);

    /// Extends a previous squeeze operation with the given mutable slice.
    ///
    /// The previous squeeze operation must have produced a number of bytes that is evenly divisible
    /// by the squeeze rate in order for the two operations to be commutative.
    fn squeeze_more_mut(&mut self, out: &mut [u8]);

    /// Fills the given mutable slice with squeezed key data.
    fn squeeze_key_mut(&mut self, out: &mut [u8]);

    /// Returns `n` bytes of squeezed data.
    #[cfg(feature = "std")]
    fn squeeze(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        self.squeeze_mut(&mut out);
        out
    }

    /// Extends a previous squeeze operation with an additional `n` bytes of squeezed data.
    ///
    /// The previous squeeze operation must have produced a number of bytes that is evenly divisible
    /// by the squeeze rate in order for the two operations to be commutative.
    #[cfg(feature = "std")]
    fn squeeze_more(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        self.squeeze_more_mut(&mut out);
        out
    }

    /// Returns `n` bytes of squeezed key data.
    #[cfg(feature = "std")]
    fn squeeze_key(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        self.squeeze_key_mut(&mut out);
        out
    }
}

/// The core implementation of the Cyclist mode. Parameterized with the permutation algorithm, the
/// permutation width, whether the mode is keyed or not, the absorb rate, the squeeze rate, and the
/// ratchet rate.
#[derive(Clone, Debug)]
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
    state: P,
    up: bool,
}

impl<
        P,
        const WIDTH: usize,
        const KEYED: bool,
        const ABSORB_RATE: usize,
        const SQUEEZE_RATE: usize,
        const RATCHET_RATE: usize,
    > Zeroize for CyclistCore<P, WIDTH, KEYED, ABSORB_RATE, SQUEEZE_RATE, RATCHET_RATE>
where
    P: Permutation<WIDTH>,
{
    fn zeroize(&mut self) {
        self.up.zeroize();
        self.state.zeroize();
    }
}

impl<
        P,
        const WIDTH: usize,
        const KEYED: bool,
        const ABSORB_RATE: usize,
        const SQUEEZE_RATE: usize,
        const RATCHET_RATE: usize,
    > Drop for CyclistCore<P, WIDTH, KEYED, ABSORB_RATE, SQUEEZE_RATE, RATCHET_RATE>
where
    P: Permutation<WIDTH>,
{
    fn drop(&mut self) {
        self.zeroize();
    }
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
            state: P::default(),
            up: true,
        }
    }

    /// Initiates the UP mode with an optional block of data and a domain separator.
    #[inline(always)]
    fn up(&mut self, out: Option<&mut [u8]>, cu: u8) {
        debug_assert!(out.as_ref().map(|x| x.len()).unwrap_or(0) <= SQUEEZE_RATE);
        if KEYED {
            self.state.add_byte(cu, WIDTH - 1);
        }
        P::permute(&mut self.state);
        self.up = true;
        if let Some(out) = out {
            self.state.extract_bytes(out);
        }
    }

    /// Initiates the DOWN mode with an optional block of data and a domain separator.
    #[inline(always)]
    fn down(&mut self, bin: Option<&[u8]>, cd: u8) {
        debug_assert!(bin.as_ref().map(|x| x.len()).unwrap_or(0) <= ABSORB_RATE);
        if let Some(bin) = bin {
            self.state.add_bytes(bin);
            self.state.add_byte(0x01, bin.len());
        } else {
            self.state.add_byte(0x01, 0);
        }
        self.state
            .add_byte(if KEYED { cd } else { cd & 0x01 }, WIDTH - 1);
        self.up = false;
    }

    /// Absorbs a slice of data at the given rate with the given DOWN mode domain separator.
    #[inline]
    fn absorb_any(&mut self, bin: &[u8], rate: usize, cd: u8) {
        let mut chunks_it = bin.chunks(rate);
        if !self.up {
            self.up(None, 0x00);
        }
        self.down(chunks_it.next(), cd);
        for chunk in chunks_it {
            self.up(None, 0x00);
            self.down(Some(chunk), 0x00);
        }
    }

    /// Squeezes into a slice of data with the given UP mode domain separator.
    #[inline]
    fn squeeze_any(&mut self, out: &mut [u8], cu: u8) {
        let mut chunks_it = out.chunks_mut(SQUEEZE_RATE);
        self.up(chunks_it.next(), cu);
        for chunk in chunks_it {
            self.down(None, 0x00);
            self.up(Some(chunk), 0x00);
        }
    }

    /// Absorbs the given slice of data.
    #[inline(always)]
    fn absorb(&mut self, bin: &[u8]) {
        self.absorb_any(bin, ABSORB_RATE, 0x03);
    }

    /// Extends a previous absorb with more data.
    #[inline(always)]
    fn absorb_more(&mut self, bin: &[u8]) {
        for chunk in bin.chunks(ABSORB_RATE) {
            self.up(None, 0x00);
            self.down(Some(chunk), 0x00);
        }
    }

    /// Fills the given mutable slice with squeezed data.
    #[inline(always)]
    fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.squeeze_any(out, 0x40);
    }

    /// Extends a previous squeeze with more data.
    #[inline(always)]
    fn squeeze_more_mut(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(SQUEEZE_RATE) {
            self.down(None, 0x00);
            self.up(Some(chunk), 0x00);
        }
    }

    /// Fills the given mutable slice with squeezed key data.
    #[inline(always)]
    fn squeeze_key_mut(&mut self, out: &mut [u8]) {
        self.squeeze_any(out, 0x20);
    }
}

/// A Cyclist object in hash mode. Parameterized with the permutation algorithm, the permutation
/// width, and the hash rate.
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

impl<P, const WIDTH: usize, const HASH_RATE: usize> Cyclist for CyclistHash<P, WIDTH, HASH_RATE>
where
    P: Permutation<WIDTH>,
{
    fn absorb_rate(&self) -> usize {
        HASH_RATE
    }

    fn squeeze_rate(&self) -> usize {
        HASH_RATE
    }

    fn absorb(&mut self, bin: &[u8]) {
        self.core.absorb(bin);
    }

    fn absorb_more(&mut self, bin: &[u8]) {
        self.core.absorb_more(bin);
    }

    fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_mut(out);
    }

    fn squeeze_more_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_more_mut(out);
    }

    fn squeeze_key_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_key_mut(out);
    }
}

/// A Cyclist object in keyed mode. Parameterized with the permutation algorithm, the permutation
/// width, the absorb rate, the squeeze rate, the ratchet rate, and the length of authentication
/// tags.
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
    /// Creates a new [`CyclistKeyed`] instance with the given key, optional nonce, and optional
    /// counter.
    pub fn new(key: &[u8], nonce: Option<&[u8]>, counter: Option<&[u8]>) -> Self {
        let mut core =
            CyclistCore::<P, WIDTH, true, ABSORB_RATE, SQUEEZE_RATE, RATCHET_RATE>::new();
        let nonce = nonce.unwrap_or_default();
        assert!(
            key.len() + nonce.len() < ABSORB_RATE - 1,
            "key and nonce must be < {}",
            ABSORB_RATE - 1,
        );

        // Initialize a buffer for the initial state.
        let mut state = [0u8; ABSORB_RATE];
        let mut state_len = 0;

        // Append the key to the initial state.
        state[state_len..state_len + key.len()].copy_from_slice(key);
        state_len += key.len();

        // Append the nonce to the initial state.
        state[state_len..state_len + nonce.len()].copy_from_slice(nonce);
        state_len += nonce.len();

        // Set the last byte of the initial state to the key length.
        state[state_len] = key.len() as u8;
        state_len += 1;

        // Absorb the initial state.
        core.absorb_any(&state[..state_len], ABSORB_RATE, 0x02);

        // If given a counter, trickle it in one byte at a time.
        if let Some(counter) = counter {
            core.absorb_any(counter, 1, 0x00);
        }

        CyclistKeyed { core }
    }

    /// Encrypts the given mutable slice in place.
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

    /// Returns an encrypted copy of the given slice.
    #[cfg(feature = "std")]
    pub fn encrypt(&mut self, bin: &[u8]) -> Vec<u8> {
        let mut c = bin.to_vec();
        self.encrypt_mut(&mut c);
        c
    }

    /// Decrypts the given mutable slice in place.
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

    /// Returns an decrypted copy of the given slice.
    #[cfg(feature = "std")]
    pub fn decrypt(&mut self, bin: &[u8]) -> Vec<u8> {
        let mut c = bin.to_vec();
        self.decrypt_mut(&mut c);
        c
    }

    /// Ratchets the state, providing forward secrecy.
    pub fn ratchet(&mut self) {
        let mut rolled_key = [0u8; RATCHET_RATE];
        self.core.squeeze_any(&mut rolled_key, 0x10);
        self.core.absorb_any(&rolled_key, RATCHET_RATE, 0x00);
    }

    /// Seals the given mutable slice in place.
    ///
    /// The last `TAG_LEN` bytes of the slice will be overwritten with the authentication tag.
    pub fn seal_mut(&mut self, in_out: &mut [u8]) {
        let (c, t) = in_out.split_at_mut(in_out.len() - TAG_LEN);
        self.encrypt_mut(c);
        self.squeeze_mut(t);
    }

    /// Returns a sealed copy of the given slice.
    ///
    /// The returned [Vec] will be `TAG_LEN` bytes longer than `bin`.
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

impl<
        P,
        const WIDTH: usize,
        const ABSORB_RATE: usize,
        const SQUEEZE_RATE: usize,
        const RATCHET_RATE: usize,
        const TAG_LEN: usize,
    > Cyclist for CyclistKeyed<P, WIDTH, ABSORB_RATE, SQUEEZE_RATE, RATCHET_RATE, TAG_LEN>
where
    P: Permutation<WIDTH>,
{
    fn absorb_rate(&self) -> usize {
        ABSORB_RATE
    }

    fn squeeze_rate(&self) -> usize {
        SQUEEZE_RATE
    }

    fn absorb(&mut self, bin: &[u8]) {
        self.core.absorb(bin);
    }

    fn absorb_more(&mut self, bin: &[u8]) {
        self.core.absorb_more(bin);
    }

    fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_mut(out);
    }

    fn squeeze_more_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_more_mut(out);
    }

    fn squeeze_key_mut(&mut self, out: &mut [u8]) {
        self.core.squeeze_key_mut(out);
    }
}

#[cfg(test)]
mod tests {
    use crate::xoodyak::XoodyakHash;

    use super::*;

    #[test]
    fn absorbing_more() {
        let mut st = XoodyakHash::default();
        let mut input = vec![20u8; st.absorb_rate() * 3];
        input.extend([39u8; 17]);
        st.absorb(&input);
        let one = st.squeeze(10);

        let mut st = XoodyakHash::default();
        st.absorb(&vec![20u8; st.absorb_rate() * 3]);
        st.absorb_more(&[39u8; 17]);
        let two = st.squeeze(10);

        assert_eq!(one, two);
    }

    #[test]
    fn squeezing_more() {
        let mut st = XoodyakHash::default();
        let one = st.squeeze(st.absorb_rate() * 3 + 17);

        let mut st = XoodyakHash::default();
        let mut two = st.squeeze(st.absorb_rate() * 3);
        two.extend(st.squeeze_more(17));

        assert_eq!(one, two);
    }
}
