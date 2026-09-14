use std::collections::HashSet;

use walrus::{
   ConstExpr,
   ConstOp,
   DataId,
   DataKind,
   FunctionId,
   FunctionKind,
   Module,
   ir,
};

/// Where an active data segment lands in linear memory.
#[derive(Debug, Clone, Copy)]
pub enum Anchor {
   /// Fixed base address in linear memory.
   Absolute(i32),
   /// An address relative to a global supplied by the loader. Encryption can
   /// use the base at runtime, but lazy staging can't match it to literal
   /// addresses before instantiation.
   Relocatable {
      /// Global supplying the runtime base address.
      base:   walrus::GlobalId,
      /// Byte displacement from the base global.
      offset: i32,
   },
}

/// Active data segment with its memory placement.
#[derive(Debug, Clone, Copy)]
pub struct Segment {
   /// Identity of the segment in the module.
   pub id:     DataId,
   /// Where the segment lands in linear memory.
   pub anchor: Anchor,
   /// Length of the segment in bytes.
   pub len:    usize,
}

impl Segment {
   /// Start address when the segment has a fixed placement.
   #[inline]
   #[must_use]
   pub const fn start(&self) -> Option<i32> {
      match self.anchor {
         Anchor::Absolute(start) => Some(start),
         Anchor::Relocatable { .. } => None,
      }
   }

   /// Checks absolute segment addresses. Relocatable segments always return
   /// false because their base is only known at instantiation.
   #[inline]
   #[must_use]
   pub fn contains(&self, address: i32) -> bool {
      let Some(origin) = self.start() else {
         return false;
      };
      let Ok(length) = i64::try_from(self.len) else {
         return false;
      };
      let distance = i64::from(address.cast_unsigned()) - i64::from(origin.cast_unsigned());
      distance >= 0 && distance < length
   }

   /// Whether literal addresses can identify this segment for lazy decryption.
   #[inline]
   #[must_use]
   pub const fn stageable(&self) -> bool {
      matches!(self.anchor, Anchor::Absolute(_))
   }
}

/// Active, non-empty data segments at a constant or a global-relative address.
///
/// Passive segments are skipped because `memory.init` chooses their address and
/// initialization time at runtime.
#[inline]
#[must_use]
pub fn segments(module: &Module) -> Vec<Segment> {
   module
      .data
      .iter()
      .filter(|data| !data.value.is_empty())
      .filter_map(|data| {
         let anchor = anchor_of(active_offset(data)?)?;

         Some(Segment {
            id: data.id(),
            anchor,
            len: data.value.len(),
         })
      })
      .collect()
}

/// Independently encrypted segments cannot share bytes in the initialized
/// memory.
#[inline]
#[must_use]
pub fn disjoint(module: &Module) -> bool {
   let placements = module
      .data
      .iter()
      .filter(|data| !data.value.is_empty())
      .filter_map(|data| active_offset(data).map(|offset| (anchor_of(offset), data.value.len())))
      .collect::<Vec<_>>();
   let relative = |anchor: Anchor| {
      match anchor {
         Anchor::Absolute(offset) => (None, offset.cast_unsigned()),
         Anchor::Relocatable { base, offset } => (Some(base), offset.cast_unsigned()),
      }
   };
   for (index, &(left, left_len)) in placements.iter().enumerate() {
      for &(right, right_len) in &placements[index + 1..] {
         let Some((left_anchor, right_anchor)) = left.zip(right) else {
            return false;
         };
         let (left_base, left_at) = relative(left_anchor);
         let (right_base, right_at) = relative(right_anchor);
         let (Ok(left_length), Ok(right_length)) =
            (u64::try_from(left_len), u64::try_from(right_len))
         else {
            return false;
         };
         if left_base != right_base
            || u64::from(right_at.wrapping_sub(left_at)) < left_length
            || u64::from(left_at.wrapping_sub(right_at)) < right_length
         {
            return false;
         }
      }
   }
   true
}

/// The offset an active segment is initialised at.
const fn active_offset(data: &walrus::Data) -> Option<&ConstExpr> {
   match data.kind {
      DataKind::Active { ref offset, .. } => Some(offset),
      DataKind::Passive => None,
   }
}

/// Reads the placement of one segment offset.
const fn anchor_of(offset: &ConstExpr) -> Option<Anchor> {
   match *offset {
      ConstExpr::Value(ir::Value::I32(start)) => Some(Anchor::Absolute(start)),
      ConstExpr::Global(base) => Some(Anchor::Relocatable { base, offset: 0 }),
      // `global.get $base; i32.const n; i32.add` is what a relocatable module emits for every
      // segment past the first.
      ConstExpr::Extended(ref ops) => {
         if let [
            ConstOp::GlobalGet(base),
            ConstOp::I32Const(displacement),
            ConstOp::I32Add,
         ] = *ops.as_slice()
         {
            Some(Anchor::Relocatable {
               base,
               offset: displacement,
            })
         } else {
            None
         }
      },
      ConstExpr::Value(_) | ConstExpr::RefNull(_) | ConstExpr::RefFunc(_) => None,
   }
}

/// Sequences owned by `Block`, `Loop` and `IfElse`, entry first.
///
/// Branches reference existing sequences, so following them would visit the
/// same body again.
#[inline]
#[must_use]
pub fn all_seqs(func: &walrus::LocalFunction) -> Vec<ir::InstrSeqId> {
   let mut found = vec![func.entry_block()];
   let mut cursor = 0;

   while cursor < found.len() {
      let seq = found[cursor];
      cursor += 1;

      for entry in &func.block(seq).instrs {
         let instr = &entry.0;

         if let ir::Instr::Block(ref block) = *instr {
            found.push(block.seq);
         } else if let ir::Instr::Loop(ref block) = *instr {
            found.push(block.seq);
         } else if let ir::Instr::IfElse(ref block) = *instr {
            found.push(block.consequent);
            found.push(block.alternative);
         }
      }
   }

   found
}

/// Identifiers of functions defined in this module.
#[inline]
#[must_use]
pub fn local_func_ids(module: &Module) -> Vec<FunctionId> {
   module
      .funcs
      .iter()
      .filter(|func| matches!(func.kind, FunctionKind::Local(_)))
      .map(walrus::Function::id)
      .collect()
}

/// Segments referenced by 32-bit little-endian values anywhere in data.
///
/// Static pointer tables can refer to data without an `i32.const` in any
/// function. These targets are decrypted at startup because the code scan can't
/// tell when a pointer will be followed.
#[inline]
#[must_use]
pub fn data_resident_pointers(module: &Module, segments: &[Segment]) -> HashSet<DataId> {
   let mut forced = HashSet::new();

   for data in module.data.iter() {
      let bytes = &data.value;

      for window in bytes.array_windows::<4>() {
         let candidate = i32::from_le_bytes(*window);

         for segment in segments.iter().filter(|seg| seg.contains(candidate)) {
            forced.insert(segment.id);
         }
      }
   }

   forced
}
