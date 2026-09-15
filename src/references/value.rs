use std::collections::BTreeSet;

use walrus::ir::{
   BinaryOp,
   InstrLocId,
   UnaryOp,
};

use crate::config::AnalysisReason;

/// Loop-carried arithmetic can otherwise enumerate the entire i32 domain.
const VALUES_LIMIT: usize = 8;
/// Losing marker provenance must not also lose numeric facts needed for
/// staging.
const ORIGINS_LIMIT: usize = 128;

/// Unknown includes every possible i32 value, regardless of its diagnostic
/// causes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Values {
   /// A nonempty set covers every reachable alternative represented by this
   /// fact.
   Known(BTreeSet<u32>),
   /// Diagnostic causes never narrow the unknown value's possible aliases.
   Unknown(BTreeSet<AnalysisReason>),
}

/// An abstract wasm32 value and the constants that contributed to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Word {
   /// Arithmetic wraps at the Wasm operand width.
   pub values:  Values,
   /// Original locations survive subsequent control flow rewriting.
   pub origins: Option<BTreeSet<InstrLocId>>,
}

impl Word {
   /// Implicit local zeros have no original constant instruction to rewrite.
   pub fn constant(value: u32, location: Option<InstrLocId>) -> Self {
      Self {
         values:  Values::Known(BTreeSet::from([value])),
         origins: Some(location.into_iter().collect()),
      }
   }

   /// Missing facts must never establish disjointness from an encrypted
   /// segment.
   pub fn unknown(reason: AnalysisReason) -> Self {
      Self {
         values:  Values::Unknown(BTreeSet::from([reason])),
         origins: Some(BTreeSet::new()),
      }
   }

   /// Only a complete finite set can rule out a segment alias.
   pub const fn known(&self) -> Option<&BTreeSet<u32>> {
      match self.values {
         Values::Known(ref values) => Some(values),
         Values::Unknown(_) => None,
      }
   }

   /// Alternatives must describe the same local or stack slot on reachable
   /// paths.
   pub fn join(&mut self, incoming: &Self, reason: AnalysisReason) -> bool {
      let mut changed = join_origins(&mut self.origins, incoming.origins.as_ref());

      match self.values {
         Values::Known(ref mut target) => {
            match incoming.values {
               Values::Known(ref source) => {
                  let previous = target.len();
                  target.extend(source);
                  changed |= target.len() != previous;

                  if target.len() > VALUES_LIMIT {
                     self.values =
                        Values::Unknown(BTreeSet::from([reason, AnalysisReason::ValueLimit]));
                  }
               },
               Values::Unknown(ref source) => {
                  let mut reasons = source.clone();
                  reasons.insert(reason);
                  self.values = Values::Unknown(reasons);
                  changed = true;
               },
            }
         },
         Values::Unknown(ref mut target) => {
            match incoming.values {
               Values::Unknown(ref source) => {
                  let previous = target.len();
                  target.extend(source);
                  changed |= target.len() != previous;
               },
               Values::Known(_) => changed |= target.insert(reason),
            }
         },
      }

      changed
   }

   /// Bounds provenance growth on long arithmetic chains.
   pub fn binary(mut left: Self, right: Self, op: BinaryOp) -> Self {
      join_origins(&mut left.origins, right.origins.as_ref());
      left.values = match (left.values, right.values) {
         (Values::Known(lhs), Values::Known(rhs)) => {
            let mut output = BTreeSet::new();

            for first in lhs {
               for second in &rhs {
                  let Some(value) = binary_value(first, *second, op) else {
                     return Self {
                        values:  Values::Unknown(BTreeSet::from([
                           AnalysisReason::UnsupportedInstruction,
                        ])),
                        origins: left.origins,
                     };
                  };
                  output.insert(value);

                  if output.len() > VALUES_LIMIT {
                     return Self {
                        values:  Values::Unknown(BTreeSet::from([AnalysisReason::ValueLimit])),
                        origins: left.origins,
                     };
                  }
               }
            }

            Values::Known(output)
         },
         (Values::Unknown(mut lhs), Values::Unknown(rhs)) => {
            lhs.extend(rhs);
            Values::Unknown(lhs)
         },
         (Values::Unknown(reasons), Values::Known(_))
         | (Values::Known(_), Values::Unknown(reasons)) => Values::Unknown(reasons),
      };
      left
   }

   /// Unsupported operand widths cannot supply an exact wasm32 address.
   pub fn unary(mut self, op: UnaryOp) -> Self {
      if let Values::Known(ref values) = self.values {
         self.values = values
            .iter()
            .map(|value| unary_value(*value, op))
            .collect::<Option<BTreeSet<_>>>()
            .map_or_else(
               || Values::Unknown(BTreeSet::from([AnalysisReason::UnsupportedInstruction])),
               Values::Known,
            );
      }

      self
   }

   /// Wasm conditions use zero for false and every other i32 bit pattern for
   /// true.
   pub fn truth(&self) -> (bool, bool) {
      match self.values {
         Values::Known(ref values) => (values.contains(&0), values.iter().any(|value| *value != 0)),
         Values::Unknown(_) => (true, true),
      }
   }
}

/// Once provenance overflows, later joins cannot restore a complete origin set.
fn join_origins(
   target: &mut Option<BTreeSet<InstrLocId>>,
   incoming: Option<&BTreeSet<InstrLocId>>,
) -> bool {
   let Some(ref mut locations) = *target else {
      return false;
   };
   let Some(source) = incoming else {
      *target = None;
      return true;
   };
   let previous = locations.len();
   locations.extend(source);
   let changed = locations.len() != previous;

   if locations.len() > ORIGINS_LIMIT {
      *target = None;
   }

   changed
}

/// Wasm integer overflow wraps, except signed division overflow which traps.
#[expect(
   clippy::wildcard_enum_match_arm,
   reason = "unsupported arithmetic loses precision"
)]
fn binary_value(left: u32, right: u32, op: BinaryOp) -> Option<u32> {
   Some(match op {
      BinaryOp::I32Add => left.wrapping_add(right),
      BinaryOp::I32Sub => left.wrapping_sub(right),
      BinaryOp::I32Mul => left.wrapping_mul(right),
      BinaryOp::I32DivU => left.checked_div(right)?,
      BinaryOp::I32DivS => {
         left
            .cast_signed()
            .checked_div(right.cast_signed())?
            .cast_unsigned()
      },
      BinaryOp::I32RemU => left.checked_rem(right)?,
      BinaryOp::I32RemS => {
         (right != 0).then(|| {
            left
               .cast_signed()
               .wrapping_rem(right.cast_signed())
               .cast_unsigned()
         })?
      },
      BinaryOp::I32And => left & right,
      BinaryOp::I32Or => left | right,
      BinaryOp::I32Xor => left ^ right,
      BinaryOp::I32Shl => left.wrapping_shl(right),
      BinaryOp::I32ShrU => left.wrapping_shr(right),
      BinaryOp::I32ShrS => left.cast_signed().wrapping_shr(right).cast_unsigned(),
      BinaryOp::I32Rotl => left.rotate_left(right),
      BinaryOp::I32Rotr => left.rotate_right(right),
      BinaryOp::I32Eq => u32::from(left == right),
      BinaryOp::I32Ne => u32::from(left != right),
      BinaryOp::I32LtU => u32::from(left < right),
      BinaryOp::I32LtS => u32::from(left.cast_signed() < right.cast_signed()),
      BinaryOp::I32LeU => u32::from(left <= right),
      BinaryOp::I32LeS => u32::from(left.cast_signed() <= right.cast_signed()),
      BinaryOp::I32GtU => u32::from(left > right),
      BinaryOp::I32GtS => u32::from(left.cast_signed() > right.cast_signed()),
      BinaryOp::I32GeU => u32::from(left >= right),
      BinaryOp::I32GeS => u32::from(left.cast_signed() >= right.cast_signed()),
      _ => return None,
   })
}

#[expect(
   clippy::wildcard_enum_match_arm,
   reason = "unsupported arithmetic loses precision"
)]
/// Wasm sign extension operates on the low bits of an i32 operand.
fn unary_value(value: u32, op: UnaryOp) -> Option<u32> {
   Some(match op {
      UnaryOp::I32Eqz => u32::from(value == 0),
      UnaryOp::I32Clz => value.leading_zeros(),
      UnaryOp::I32Ctz => value.trailing_zeros(),
      UnaryOp::I32Popcnt => value.count_ones(),
      UnaryOp::I32Extend8S => ((value << 24).cast_signed() >> 24).cast_unsigned(),
      UnaryOp::I32Extend16S => ((value << 16).cast_signed() >> 16).cast_unsigned(),
      _ => return None,
   })
}
