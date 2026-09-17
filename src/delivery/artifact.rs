use std::{
   fmt,
   io,
   num::NonZeroUsize,
   str::{
      FromStr,
      from_utf8,
   },
};

use brotli::{
   BrotliCompress,
   enc::BrotliEncoderParams,
};
use sha2::{
   Digest as _,
   Sha256,
};
use thiserror::Error;

use crate::{
   TransformError,
   prepare::Prepared,
};

pub const CONTENT_TYPE: &str = "application/wasm";
pub const CACHE_CONTROL: &str = "no-store";
pub const VARY: &str = "Accept-Encoding";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PreparationError {
   #[error("rewriting a delivery variant")]
   Rewrite(#[source] TransformError),
   #[error("compressing a delivery variant")]
   Compress(#[source] io::Error),
   #[error("{encoding:?} variant has {bytes} bytes, exceeding the limit of {limit}")]
   TooLarge {
      encoding: Encoding,
      bytes:    usize,
      limit:    usize,
   },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Encoding {
   Identity,
   Brotli,
}

impl Encoding {
   #[inline]
   #[must_use]
   pub const fn content_encoding(self) -> Option<&'static str> {
      match self {
         Self::Identity => None,
         Self::Brotli => Some("br"),
      }
   }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quality(u8);

#[derive(Debug, Error)]
#[error("Brotli quality must be between 0 and 11")]
pub struct InvalidQuality;

impl TryFrom<u8> for Quality {
   type Error = InvalidQuality;

   #[inline]
   fn try_from(value: u8) -> Result<Self, Self::Error> {
      if value > 11 {
         return Err(InvalidQuality);
      }

      Ok(Self(value))
   }
}

impl FromStr for Quality {
   type Err = InvalidQuality;

   #[inline]
   fn from_str(value: &str) -> Result<Self, Self::Err> {
      Self::try_from(value.parse::<u8>().map_err(|_error| InvalidQuality)?)
   }
}

impl fmt::Display for Quality {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      self.0.fmt(f)
   }
}

#[derive(Debug, Clone, Copy)]
pub struct Compression {
   pub quality:          Quality,
   pub max_wasm_bytes:   NonZeroUsize,
   pub max_brotli_bytes: NonZeroUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VariantId([u8; 32]);

#[derive(Debug, Error)]
#[error("variant identity must contain 64 hexadecimal digits")]
pub struct InvalidId;

impl FromStr for VariantId {
   type Err = InvalidId;

   #[inline]
   fn from_str(value: &str) -> Result<Self, Self::Err> {
      if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
         return Err(InvalidId);
      }

      let mut bytes = [0_u8; 32];

      for (digits, slot) in value.as_bytes().as_chunks::<2>().0.iter().zip(&mut bytes) {
         let pair = from_utf8(digits).map_err(|_error| InvalidId)?;
         *slot = u8::from_str_radix(pair, 16).map_err(|_error| InvalidId)?;
      }

      Ok(Self(bytes))
   }
}

impl fmt::Display for VariantId {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      for byte in &self.0 {
         write!(f, "{byte:02x}")?;
      }

      Ok(())
   }
}

#[derive(Debug)]
pub struct Variant {
   /// Both encodings share the identity of the uncompressed module.
   id:     VariantId,
   /// Kept for reproducing a delivery without retaining a separate manifest.
   seed:   u64,
   /// Hosts without Brotli support must receive the same module.
   wasm:   Box<[u8]>,
   /// Compression finishes before the worker publishes this variant.
   brotli: Box<[u8]>,
}

impl Variant {
   /// Both representations are ready before a variant can enter the delivery
   /// pool.
   ///
   /// # Errors
   ///
   /// Returns rewrite, compression or size errors without publishing partial
   /// output.
   #[inline]
   pub fn prepare(
      input: &Prepared,
      seed: u64,
      compression: Compression,
   ) -> Result<Self, PreparationError> {
      let (wasm, _) = input.rewrite(seed).map_err(PreparationError::Rewrite)?;

      if wasm.len() > compression.max_wasm_bytes.get() {
         return Err(PreparationError::TooLarge {
            encoding: Encoding::Identity,
            bytes:    wasm.len(),
            limit:    compression.max_wasm_bytes.get(),
         });
      }

      let params = BrotliEncoderParams {
         quality: i32::from(compression.quality.0),
         size_hint: wasm.len(),
         ..BrotliEncoderParams::default()
      };
      let mut compressed = Vec::new();
      BrotliCompress(&mut wasm.as_slice(), &mut compressed, &params)
         .map_err(PreparationError::Compress)?;

      if compressed.len() > compression.max_brotli_bytes.get() {
         return Err(PreparationError::TooLarge {
            encoding: Encoding::Brotli,
            bytes:    compressed.len(),
            limit:    compression.max_brotli_bytes.get(),
         });
      }

      Ok(Self {
         id: VariantId(Sha256::digest(&wasm).into()),
         seed,
         wasm: wasm.into_boxed_slice(),
         brotli: compressed.into_boxed_slice(),
      })
   }

   #[inline]
   #[must_use]
   pub const fn id(&self) -> VariantId {
      self.id
   }

   #[inline]
   #[must_use]
   pub const fn seed(&self) -> u64 {
      self.seed
   }

   #[inline]
   #[must_use]
   pub fn bytes(&self, encoding: Encoding) -> &[u8] {
      match encoding {
         Encoding::Identity => &self.wasm,
         Encoding::Brotli => &self.brotli,
      }
   }
}
