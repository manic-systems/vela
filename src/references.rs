use std::{
   collections::{
      BTreeMap,
      BTreeSet,
   },
   iter,
};

use walrus::{
   DataId,
   FunctionId,
   FunctionKind,
   GlobalKind,
   LocalId,
   Module,
   ir,
};

use crate::{
   analysis,
   analysis::Segment,
   stack,
};

/// Memory uses proven within individual instruction sequences.
#[derive(Default)]
pub struct References {
   /// Functions requiring each segment before entry.
   pub functions:  BTreeMap<DataId, BTreeSet<FunctionId>>,
   /// Input constants contributing to a resolved data address.
   pub addresses:  BTreeSet<ir::InstrLocId>,
   /// Memory effects whose possible aliases require eager decryption.
   pub unresolved: usize,
}

/// A known wasm32 value and the constants that contributed to it.
#[derive(Clone)]
struct Word {
   /// Arithmetic wraps at the Wasm operand width.
   value:   u32,
   /// Original locations survive subsequent control flow rewriting.
   origins: BTreeSet<ir::InstrLocId>,
}

impl Word {
   /// Bounds provenance growth on long arithmetic chains.
   #[expect(
      clippy::wildcard_enum_match_arm,
      reason = "unsupported arithmetic loses precision"
   )]
   fn binary(mut left: Self, right: Self, op: ir::BinaryOp) -> Option<Self> {
      left.value = match op {
         ir::BinaryOp::I32Add => left.value.wrapping_add(right.value),
         ir::BinaryOp::I32Sub => left.value.wrapping_sub(right.value),
         ir::BinaryOp::I32Mul => left.value.wrapping_mul(right.value),
         ir::BinaryOp::I32And => left.value & right.value,
         ir::BinaryOp::I32Or => left.value | right.value,
         ir::BinaryOp::I32Xor => left.value ^ right.value,
         ir::BinaryOp::I32Shl => left.value.wrapping_shl(right.value),
         ir::BinaryOp::I32ShrU => left.value.wrapping_shr(right.value),
         ir::BinaryOp::I32ShrS => {
            left
               .value
               .cast_signed()
               .wrapping_shr(right.value)
               .cast_unsigned()
         },
         ir::BinaryOp::I32Rotl => left.value.rotate_left(right.value),
         ir::BinaryOp::I32Rotr => left.value.rotate_right(right.value),
         _ => return None,
      };
      left.origins.extend(right.origins);
      (left.origins.len() <= 128).then_some(left)
   }
}

/// Locals and operands known along one straight-line path.
struct Frame {
   /// Missing operands are unknown when our stack model cannot describe them.
   operands: Vec<Option<Word>>,
   /// Unlisted locals may be zero only at function entry.
   locals:   BTreeMap<LocalId, Option<Word>>,
   /// Structured control flow invalidates the entry initialization assumption.
   entry:    bool,
}

impl Frame {
   /// Consumes an abstract operand without inferring a value from missing
   /// state.
   fn pop(&mut self) -> Option<Word> {
      self.operands.pop().flatten()
   }

   /// Propagates integer facts without making assumptions about memory
   /// contents.
   #[expect(
      clippy::wildcard_enum_match_arm,
      reason = "other instructions are handled by the memory scan"
   )]
   fn value(&mut self, module: &Module, instruction: &ir::Instr, location: ir::InstrLocId) -> bool {
      match *instruction {
         ir::Instr::Const(ref constant) => {
            self.operands.push(match constant.value {
               ir::Value::I32(value) => {
                  Some(Word {
                     value:   value.cast_unsigned(),
                     origins: BTreeSet::from([location]),
                  })
               },
               _ => None,
            });
         },
         ir::Instr::LocalGet(ref get) => {
            let word = self.locals.get(&get.local).cloned().unwrap_or_else(|| {
               (self.entry && module.locals.get(get.local).ty() == walrus::ValType::I32).then(
                  || {
                     Word {
                        value:   0,
                        origins: BTreeSet::new(),
                     }
                  },
               )
            });
            self.operands.push(word);
         },
         ir::Instr::LocalSet(ref set) => {
            let word = self.pop();
            self.locals.insert(set.local, word);
         },
         ir::Instr::LocalTee(ref tee) => {
            self
               .locals
               .insert(tee.local, self.operands.last().cloned().flatten());
         },
         ir::Instr::GlobalGet(ref get) => {
            let global = module.globals.get(get.global);
            let word = match global.kind {
               GlobalKind::Local(walrus::ConstExpr::Value(ir::Value::I32(value)))
                  if !global.mutable =>
               {
                  Some(Word {
                     value:   value.cast_unsigned(),
                     origins: BTreeSet::new(),
                  })
               },
               _ => None,
            };
            self.operands.push(word);
         },
         ir::Instr::Binop(ref binary) => {
            let right = self.pop();
            let left = self.pop();
            self.operands.push(
               left
                  .zip(right)
                  .and_then(|(lhs, rhs)| Word::binary(lhs, rhs, binary.op)),
            );
         },
         _ => return false,
      }
      true
   }

   /// Child sequences may change locals and branch with different stack values.
   fn forget(&mut self) {
      self.operands.fill(None);
      self.locals.clear();
      self.entry = false;
   }
}

impl References {
   /// Resolves memory operands before encryption or inserted runtime code.
   #[inline]
   pub fn analyze(module: &Module, segments: &[Segment]) -> Self {
      let mut references = Self::default();
      for id in analysis::local_func_ids(module) {
         let function = module.funcs.get(id).kind.unwrap_local();
         for sequence in analysis::all_seqs(function) {
            references.scan(module, segments, id, sequence);
         }
      }
      references
   }

   /// Wide accesses can cross segment boundaries even when their base lies
   /// outside either one.
   fn access(
      &mut self,
      segments: &[Segment],
      function: FunctionId,
      address: Option<&Word>,
      offset: u64,
      length: Option<u32>,
   ) {
      if length == Some(0) {
         return;
      }
      let Some((word, size)) = address.zip(length) else {
         self.unresolved += 1;
         return;
      };
      let Some(start) = u64::from(word.value).checked_add(offset) else {
         self.unresolved += 1;
         return;
      };
      let end = start.saturating_add(u64::from(size));
      for segment in segments {
         let Some(origin) = segment.start() else {
            continue;
         };
         let base = u64::from(origin.cast_unsigned());
         let Ok(extent) = u64::try_from(segment.len) else {
            self.unresolved += 1;
            continue;
         };
         if start < base.saturating_add(extent) && base < end {
            self
               .functions
               .entry(segment.id)
               .or_default()
               .insert(function);
            self.addresses.extend(word.origins.iter().copied());
         }
      }
   }

   /// Pointer arguments and returned addresses need gates before they leave
   /// their defining function.
   fn escape(&mut self, segments: &[Segment], function: FunctionId, word: Option<&Word>) {
      if word.is_some() {
         self.access(segments, function, word, 0, Some(1));
      }
   }

   /// Sequence boundaries discard facts rather than guessing branch or loop
   /// values.
   #[expect(
      clippy::wildcard_enum_match_arm,
      reason = "the stack model handles non-memory instructions conservatively"
   )]
   fn scan(
      &mut self,
      module: &Module,
      segments: &[Segment],
      id: FunctionId,
      sequence: ir::InstrSeqId,
   ) {
      let function = module.funcs.get(id).kind.unwrap_local();
      let block = function.block(sequence);
      let parameters = match block.ty {
         ir::InstrSeqType::Simple(_) => 0,
         ir::InstrSeqType::MultiValue(signature) => module.types.get(signature).params().len(),
      };
      let mut frame = Frame {
         operands: vec![None; parameters],
         locals:   function.args.iter().map(|local| (*local, None)).collect(),
         entry:    sequence == function.entry_block(),
      };

      for &(ref instruction, location) in &block.instrs {
         if frame.value(module, instruction, location) {
            continue;
         }
         match *instruction {
            ir::Instr::GlobalSet(_) => self.escape(segments, id, frame.pop().as_ref()),
            ir::Instr::Load(ref load) => {
               self.access(
                  segments,
                  id,
                  frame.pop().as_ref(),
                  load.arg.offset,
                  Some(load.kind.width()),
               );
               frame.operands.push(None);
            },
            ir::Instr::Store(ref store) => {
               self.escape(segments, id, frame.pop().as_ref());
               self.access(
                  segments,
                  id,
                  frame.pop().as_ref(),
                  store.arg.offset,
                  Some(store.kind.width()),
               );
            },
            ir::Instr::MemoryCopy(_) | ir::Instr::MemoryFill(_) | ir::Instr::MemoryInit(_) => {
               let length = frame.pop().map(|word| word.value);
               let source = frame.pop();
               let destination = frame.pop();
               if matches!(*instruction, ir::Instr::MemoryCopy(_)) {
                  self.access(segments, id, source.as_ref(), 0, length);
               }
               self.access(segments, id, destination.as_ref(), 0, length);
            },
            ir::Instr::Call(ref call) => {
               let callee = module.funcs.get(call.func);
               let signature = module.types.get(callee.ty());
               if matches!(callee.kind, FunctionKind::Import(_)) {
                  self.unresolved += 1;
               }
               for _ in signature.params() {
                  self.escape(segments, id, frame.pop().as_ref());
               }
               frame
                  .operands
                  .extend(signature.results().iter().map(|_result| None));
            },
            ir::Instr::Return(_) => {
               for word in &frame.operands {
                  self.escape(segments, id, word.as_ref());
               }
               break;
            },
            ir::Instr::Br(_) | ir::Instr::BrTable(_) | ir::Instr::Unreachable(_) => break,
            _ => {
               if matches!(*instruction, ir::Instr::CallIndirect(_)) {
                  self.unresolved += 1;
               }
               let Ok((pops, pushes)) = stack::effect(module, function, instruction) else {
                  self.unresolved += 1;
                  break;
               };
               frame
                  .operands
                  .truncate(frame.operands.len().saturating_sub(pops));
               frame.operands.extend(iter::repeat_n(None, pushes));
               if matches!(
                  *instruction,
                  ir::Instr::Block(_) | ir::Instr::Loop(_) | ir::Instr::IfElse(_)
               ) {
                  frame.forget();
               }
            },
         }
      }
      if sequence == function.entry_block() {
         for word in &frame.operands {
            self.escape(segments, id, word.as_ref());
         }
      }
   }
}
