use std::collections::{
   HashMap,
   hash_map::Entry,
};

use thiserror::Error;
use walrus::{
   ConstExpr,
   ConstOp,
   ElementId,
   ElementItems,
   ElementKind,
   FunctionId,
   FunctionKind,
   GlobalId,
   Module,
   TableId,
   ir,
};

use crate::{
   Rewriter,
   analysis,
   config::CodePass,
};

/// Failures when growing the indirect call table.
#[derive(Debug, Error)]
pub enum TableError {
   /// Added entry would overflow the 32 bit index space.
   #[error("indirect table index exceeds wasm32 with {entries} entries starting at {start}")]
   IndexOverflow {
      /// Start index the overflow was computed from.
      start:   u32,
      /// Number of entries already assigned.
      entries: usize,
   },
   /// Table segment no longer holds functions.
   #[error("indirect table segment {0:?} no longer contains functions")]
   InvalidSegment(ElementId),
   /// Dylink data is invalid or its table reservation would overflow.
   #[error("invalid or overflowing dylink table reservation when adding {added} entries")]
   Reservation {
      /// Number of entries requested for the reservation.
      added: u32,
   },
}

/// Rewrites direct calls as table dispatches.
///
/// The marker pass can then replace the table indices with arithmetic.
///
/// # Errors
///
/// Returns an error when added entries exceed the table or dylink size
/// limit.
#[inline]
pub fn run(rewriter: &mut Rewriter<'_>) -> Result<(), TableError> {
   let module = &mut rewriter.module;
   let rng = &mut rewriter.rng;
   let config = rewriter.config;
   let generated = &rewriter.generated;
   let report = &mut rewriter.report;
   let functions = &mut rewriter.functions;
   let dispatch_marker = rewriter.dispatch_marker;
   let table = function_table(module);
   let Some(slot) = Slotting::find(module, table) else {
      return Ok(());
   };

   let mut assigned = HashMap::<FunctionId, u32>::new();
   let mut order = Vec::<FunctionId>::new();
   let mut promoted = 0_usize;

   for id in analysis::local_func_ids(module) {
      let Some(function) = functions
         .get_mut(&id)
         .filter(|entry| entry.passes.contains(&CodePass::Indirect))
      else {
         continue;
      };

      let FunctionKind::Local(ref outer) = module.funcs.get(id).kind else {
         continue;
      };

      for seq in analysis::all_seqs(outer) {
         let FunctionKind::Local(ref inner) = module.funcs.get(id).kind else {
            continue;
         };

         let targets = inner
            .block(seq)
            .instrs
            .iter()
            .enumerate()
            .filter_map(|(at, pair)| {
               let ir::Instr::Call(ref call) = pair.0 else {
                  return None;
               };
               (!generated.contains(&call.func)).then_some((at, call.func))
            })
            .filter(|_| rng.chance(config.indirect_ratio))
            .collect::<Vec<(usize, FunctionId)>>();

         // Rewritten back to front so the recorded positions stay valid as
         // the sequence grows.
         for (at, callee) in targets.into_iter().rev() {
            let ty = module.funcs.get(callee).ty();
            let index = match assigned.entry(callee) {
               Entry::Occupied(entry) => *entry.get(),
               Entry::Vacant(entry) => {
                  let displacement = u32::try_from(order.len()).map_err(|_error| {
                     TableError::IndexOverflow {
                        start:   slot.start,
                        entries: order.len(),
                     }
                  })?;
                  let next =
                     slot
                        .start
                        .checked_add(displacement)
                        .ok_or(TableError::IndexOverflow {
                           start:   slot.start,
                           entries: order.len(),
                        })?;
                  order.push(callee);
                  *entry.insert(next)
               },
            };

            let FunctionKind::Local(ref mut patched) = module.funcs.get_mut(id).kind else {
               continue;
            };
            let mut body = patched.builder_mut().instr_seq(seq);
            let instrs = body.instrs_mut();

            instrs[at] = (
               ir::CallIndirect { ty, table }.into(),
               ir::InstrLocId::default(),
            );
            instrs.splice(
               at..at,
               slot.index_of(index).into_iter().map(|instr| {
                  let location = if matches!(instr, ir::Instr::Const(_)) {
                     dispatch_marker
                  } else {
                     ir::InstrLocId::default()
                  };
                  (instr, location)
               }),
            );
            promoted += 1;
            function.calls_promoted += 1;
         }
      }
   }

   if order.is_empty() {
      return Ok(());
   }

   slot.commit(module, table, order)?;
   report.calls_promoted = promoted;
   Ok(())
}

/// Table placement for added entries and their runtime dispatch indices.
///
/// Relocatable entries must extend the module's own segment and use its
/// `__table_base` for dispatch. Absolute indices could overwrite slots assigned
/// to another module by the loader.
struct Slotting {
   /// Base global of the segment being extended, or `None` when the offset is
   /// absolute.
   base:   Option<GlobalId>,
   /// Index of the first added entry, relative to `base`.
   start:  u32,
   /// Segment to extend, or a fresh segment when the table is local.
   target: Target,
}

/// Segment to extend, or a fresh segment when the table is local.
enum Target {
   /// Extend this existing segment.
   Extend(ElementId),
   /// Add a segment to a locally defined table.
   Fresh,
}

impl Slotting {
   /// Finds the segment to extend.
   fn find(module: &Module, table: TableId) -> Option<Self> {
      let mut best = Option::<(ElementId, Option<GlobalId>, u32)>::None;

      for element in module.elements.iter() {
         let ElementKind::Active {
            table: owner,
            ref offset,
         } = element.kind
         else {
            continue;
         };
         let ElementItems::Functions(ref items) = element.items else {
            continue;
         };
         if owner != table {
            continue;
         }

         let (base, at) = decompose(offset)?;
         let extent = at.checked_add(u32::try_from(items.len()).ok()?)?;

         if best.as_ref().is_none_or(|&(_, _, seen)| extent > seen) {
            best = Some((element.id(), base, extent));
         }
      }

      if let Some((element, base, extent)) = best {
         return Some(Self {
            base,
            start: extent,
            target: Target::Extend(element),
         });
      }

      // Without an existing segment, the imported table gives us no base for
      // placing entries in the module's reserved region.
      let definition = module.tables.get(table);
      if definition.import.is_some() {
         return None;
      }

      Some(Self {
         base:   None,
         start:  u32::try_from(definition.initial).ok()?,
         target: Target::Fresh,
      })
   }

   /// Forms the runtime dispatch index for an added entry.
   fn index_of(&self, index: u32) -> Vec<ir::Instr> {
      self.base.map_or_else(
         || {
            vec![
               ir::Const {
                  value: ir::Value::I32(index.cast_signed()),
               }
               .into(),
            ]
         },
         |global| {
            vec![
               ir::GlobalGet { global }.into(),
               ir::Const {
                  value: ir::Value::I32(index.cast_signed()),
               }
               .into(),
               ir::Binop {
                  op: ir::BinaryOp::I32Add,
               }
               .into(),
            ]
         },
      )
   }

   /// Extends the segment and grows the table reservation.
   fn commit(
      self,
      module: &mut Module,
      table: TableId,
      order: Vec<FunctionId>,
   ) -> Result<(), TableError> {
      let added = u32::try_from(order.len()).map_err(|_error| {
         TableError::IndexOverflow {
            start:   self.start,
            entries: order.len(),
         }
      })?;

      match self.target {
         Target::Extend(element) => {
            let ElementItems::Functions(ref mut items) = module.elements.get_mut(element).items
            else {
               return Err(TableError::InvalidSegment(element));
            };
            items.extend(order);
         },
         Target::Fresh => {
            module.elements.add(
               ElementKind::Active {
                  table,
                  offset: ConstExpr::Value(ir::Value::I32(self.start.cast_signed())),
               },
               ElementItems::Functions(order),
            );
         },
      }

      let definition = module.tables.get_mut(table);
      let needed = u64::from(self.start) + u64::from(added);

      // An imported table's declared minimum is a demand on the host, not a
      // reservation.
      if definition.import.is_none() {
         definition.initial = definition.initial.max(needed);
         if let Some(maximum) = definition.maximum.as_mut() {
            *maximum = (*maximum).max(needed);
         }
      }

      grow_dylink_table(module, added)
   }
}

/// Splits an element segment offset into a base global and a constant
/// displacement.
const fn decompose(offset: &ConstExpr) -> Option<(Option<GlobalId>, u32)> {
   match *offset {
      ConstExpr::Value(ir::Value::I32(at)) => Some((None, at.cast_unsigned())),
      ConstExpr::Global(base) => Some((Some(base), 0_u32)),
      ConstExpr::Extended(ref ops) => {
         if let [
            ConstOp::GlobalGet(base),
            ConstOp::I32Const(at),
            ConstOp::I32Add,
         ] = *ops.as_slice()
         {
            Some((Some(base), at.cast_unsigned()))
         } else {
            None
         }
      },
      ConstExpr::Value(_) | ConstExpr::RefNull(_) | ConstExpr::RefFunc(_) => None,
   }
}

/// Raises the table reservation a dynamic loader makes for this module.
///
/// The loader uses `dylink.0` to reserve table space. Added entries must fit
/// within that reservation or they can overlap the next module.
fn grow_dylink_table(module: &mut Module, added: u32) -> Result<(), TableError> {
   let Some(section) = module.customs.remove_raw("dylink.0") else {
      return Ok(());
   };

   let rewritten =
      bump_table_size(&section.data, added).ok_or(TableError::Reservation { added })?;
   module.customs.add(walrus::RawCustomSection {
      name: "dylink.0".to_owned(),
      data: rewritten,
   });
   Ok(())
}

/// `dylink.0` is a sequence of `(id, size, payload)` subsections. Subsection 1
/// is `WASM_DYLINK_MEM_INFO`, four LEB128 values of memory size, memory
/// alignment, table size, and table alignment.
fn bump_table_size(data: &[u8], added: u32) -> Option<Vec<u8>> {
   let mut cursor = 0_usize;
   let mut out = Vec::with_capacity(data.len().saturating_add(4_usize));

   while cursor < data.len() {
      let (id, id_end) = read_leb(data, cursor)?;
      let (size, payload_at) = read_leb(data, id_end)?;
      let size_len = usize::try_from(size).ok()?;
      let payload_end = payload_at.checked_add(size_len)?;
      let payload = data.get(payload_at..payload_end)?;

      if id != 1 {
         out.extend_from_slice(data.get(cursor..payload_end)?);
         cursor = payload_end;
         continue;
      }

      let (memory_size, memory_end) = read_leb(payload, 0_usize)?;
      let (memory_align, table_at) = read_leb(payload, memory_end)?;
      let (table_size, align_at) = read_leb(payload, table_at)?;
      let (table_align, rest_at) = read_leb(payload, align_at)?;

      let mut body = Vec::new();
      write_leb(&mut body, memory_size);
      write_leb(&mut body, memory_align);
      write_leb(&mut body, table_size.checked_add(added)?);
      write_leb(&mut body, table_align);
      body.extend_from_slice(payload.get(rest_at..)?);

      write_leb(&mut out, id);
      write_leb(&mut out, u32::try_from(body.len()).ok()?);
      out.extend_from_slice(&body);
      cursor = payload_end;
   }

   Some(out)
}

/// Reads one LEB128 value and the offset past it.
fn read_leb(data: &[u8], mut at: usize) -> Option<(u32, usize)> {
   let mut value = 0_u32;
   let mut shift = 0_u32;

   loop {
      let byte = *data.get(at)?;
      at = at.checked_add(1_usize)?;
      value |= u32::from(byte & 0x7F).checked_shl(shift)?;

      if byte & 0x80 == 0 {
         return Some((value, at));
      }

      shift = shift.checked_add(7_u32)?;
      if shift >= 32 {
         return None;
      }
   }
}

/// Appends one LEB128 value.
#[expect(
   clippy::as_conversions,
   reason = "the seven bit LEB128 payload fits in a byte"
)]
fn write_leb(out: &mut Vec<u8>, mut value: u32) {
   loop {
      let byte = (value & 0x7F) as u8;
      value >>= 7_u32;

      if value == 0 {
         out.push(byte);
         return;
      }

      out.push(byte | 0x80);
   }
}

/// Existing table or a fresh local one when the module has none.
fn function_table(module: &mut Module) -> TableId {
   if let Ok(Some(table)) = module.tables.main_function_table() {
      return table;
   }

   module
      .tables
      .add_local(false, 0, None, walrus::RefType::FUNCREF)
}
