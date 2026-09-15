use std::collections::{
   BTreeMap,
   BTreeSet,
};

use walrus::{
   ConstExpr,
   GlobalKind,
   LocalId,
   Module,
   ir::{
      Instr,
      InstrLocId,
      Value,
   },
};

use crate::{
   config::AnalysisReason,
   references::value::{
      Values,
      Word,
   },
};

/// Locals and operands known along one straight-line path.
#[derive(Clone)]
pub struct Frame {
   /// Missing operands are unknown when our stack model cannot describe them.
   pub operands: Vec<Word>,
   /// Unlisted locals may be zero only at function entry.
   pub locals:   BTreeMap<LocalId, Word>,
}

impl Frame {
   /// Retaining branch frames must consume budget as well as executing
   /// instructions.
   pub fn cost(&self) -> usize {
      self
         .operands
         .iter()
         .chain(self.locals.values())
         .fold(1_usize, |total, word| {
            let values = match word.values {
               Values::Known(ref values) => values.len(),
               Values::Unknown(ref reasons) => reasons.len(),
            };
            total.saturating_add(1 + values + word.origins.as_ref().map_or(0, BTreeSet::len))
         })
   }

   /// Consumes an abstract operand without inferring a value from missing
   /// state.
   pub fn pop(&mut self) -> Word {
      self
         .operands
         .pop()
         .unwrap_or_else(|| Word::unknown(AnalysisReason::UnsupportedInstruction))
   }

   /// Wasm call and branch tuples preserve declaration order on the operand
   /// stack.
   pub fn take(&mut self, count: usize) -> Option<Vec<Word>> {
      let start = self.operands.len().checked_sub(count)?;
      Some(self.operands.split_off(start))
   }

   /// Propagates integer facts without making assumptions about memory
   /// contents.
   #[expect(
      clippy::wildcard_enum_match_arm,
      reason = "other instructions are handled by the memory scan"
   )]
   pub fn value(&mut self, module: &Module, instruction: &Instr, location: InstrLocId) -> bool {
      match *instruction {
         Instr::Const(ref constant) => {
            self.operands.push(match constant.value {
               Value::I32(value) => Word::constant(value.cast_unsigned(), Some(location)),
               _ => Word::unknown(AnalysisReason::UnsupportedInstruction),
            });
         },
         Instr::LocalGet(ref get) => {
            self.operands.push(
               self
                  .locals
                  .get(&get.local)
                  .cloned()
                  .unwrap_or_else(|| Word::unknown(AnalysisReason::UnsupportedInstruction)),
            );
         },
         Instr::LocalSet(ref set) => {
            let value = self.pop();
            self.locals.insert(set.local, value);
         },
         Instr::LocalTee(ref tee) => {
            let value = self
               .operands
               .last()
               .cloned()
               .unwrap_or_else(|| Word::unknown(AnalysisReason::UnsupportedInstruction));
            self.locals.insert(tee.local, value);
         },
         Instr::GlobalGet(ref get) => {
            let global = module.globals.get(get.global);
            let value = match global.kind {
               GlobalKind::Local(ConstExpr::Value(Value::I32(value))) if !global.mutable => {
                  Word::constant(value.cast_unsigned(), None)
               },
               _ => Word::unknown(AnalysisReason::GlobalValue),
            };
            self.operands.push(value);
         },
         Instr::Binop(ref binary) => {
            let right = self.pop();
            let left = self.pop();
            self.operands.push(Word::binary(left, right, binary.op));
         },
         Instr::Unop(ref unary) => {
            let operand = self.pop();
            self.operands.push(operand.unary(unary.op));
         },
         Instr::Select(_) => {
            let (zero, nonzero) = self.pop().truth();
            let alternative = self.pop();
            let mut consequent = self.pop();

            if nonzero {
               if zero {
                  consequent.join(&alternative, AnalysisReason::BranchMerge);
               }

               self.operands.push(consequent);
            } else {
               self.operands.push(alternative);
            }
         },
         _ => return false,
      }

      true
   }

   /// Child sequences may change locals and branch with different stack values.
   pub fn join(&mut self, incoming: &Self, reason: AnalysisReason) -> Option<bool> {
      if self.operands.len() != incoming.operands.len()
         || self.locals.len() != incoming.locals.len()
      {
         return None;
      }

      let mut changed = false;

      for (target, source) in self.operands.iter_mut().zip(&incoming.operands) {
         changed |= target.join(source, reason);
      }

      for (local, source) in &incoming.locals {
         changed |= self.locals.get_mut(local)?.join(source, reason);
      }

      Some(changed)
   }
}
