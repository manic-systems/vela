use std::num::NonZeroU64;

use crate::config;

/// Deterministic PRNG for build-time choices.
pub struct Rng {
   /// Current splitmix64 state.
   state: u64,
}

impl Rng {
   /// Creates a generator from a seed.
   #[inline]
   #[must_use]
   pub const fn new(seed: u64) -> Self {
      Self {
         state: seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
      }
   }

   /// Returns the next 64 bit output.
   #[inline]
   pub const fn next_u64(&mut self) -> u64 {
      self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
      let mut mix = self.state;
      mix = (mix ^ (mix >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
      mix = (mix ^ (mix >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
      mix ^ (mix >> 31)
   }

   /// Returns the upper 32 bits as a new output.
   #[inline]
   #[expect(
      clippy::as_conversions,
      reason = "keeps upper 32 bits after shifting right by 32"
   )]
   pub const fn next_u32(&mut self) -> u32 {
      (self.next_u64() >> 32) as u32
   }

   /// Returns fresh pseudorandom bits as an `i32`.
   #[inline]
   pub const fn next_i32(&mut self) -> i32 {
      self.next_u32().cast_signed()
   }

   /// Uniform over `0..n`. Returns 0 when `n` is 0 so callers never have to
   /// special-case an empty pool.
   #[inline]
   #[expect(
      clippy::as_conversions,
      clippy::cast_possible_truncation,
      reason = "modulo by n yields less than n which fits in usize for pool indexing"
   )]
   pub const fn below(&mut self, n: usize) -> usize {
      if n == 0 {
         0
      } else {
         (self.next_u64() % n as u64) as usize
      }
   }

   /// Returns true with the given percentage chance.
   #[inline]
   pub const fn chance(&mut self, percent: config::Percentage) -> bool {
      self.next_u32() % 100_u32 < percent.get()
   }

   /// Non-zero seed for the runtime keystream. Zero is a fixed point of
   /// xorshift64 and would emit a constant keystream.
   #[inline]
   pub const fn next_nonzero_u64(&mut self) -> NonZeroU64 {
      loop {
         let candidate = self.next_u64();
         if let Some(value) = NonZeroU64::new(candidate) {
            return value;
         }
      }
   }
}

/// Build-time encryption stream, mirrored by the runtime decryptor in
/// [`crate::emit`]. Both implementations must produce the same bytes for a
/// given seed.
pub struct KeyStream {
   /// Current xorshift64 state.
   state: u64,
}

impl KeyStream {
   /// Creates a keystream from a nonzero seed.
   #[inline]
   #[must_use]
   pub const fn new(seed: NonZeroU64) -> Self {
      Self { state: seed.get() }
   }

   /// Returns the next keystream byte.
   #[inline]
   #[expect(
      clippy::as_conversions,
      clippy::cast_possible_truncation,
      reason = "keeps low 8 bits of xorshift64 state"
   )]
   pub const fn next_byte(&mut self) -> u8 {
      self.state ^= self.state << 13_u32;
      self.state ^= self.state >> 7_u32;
      self.state ^= self.state << 17_u32;
      self.state as u8
   }

   /// Xors bytes in place with the keystream.
   #[inline]
   pub fn apply(seed: NonZeroU64, bytes: &mut [u8]) {
      let mut stream = Self::new(seed);
      for byte in bytes.iter_mut() {
         *byte ^= stream.next_byte();
      }
   }
}
