use walrus::ir;

use crate::config::FlattenRejection;

/// Stack depth after each instruction, relative to sequence entry, plus whether
/// the sequence terminates.
pub struct Trace {
   /// Stack depth after each instruction relative to entry.
   pub depths:     Vec<i32>,
   /// A final `br`, `br_table`, `return` or `unreachable` prevents fallthrough.
   /// The last `depths` entry is measured before that instruction.
   pub terminated: bool,
}

impl Trace {
   /// Operand stack depth through a sequence, relative to its entry.
   ///
   /// Flattening cuts at depth zero. Unmodelled effects report
   /// [`FlattenRejection::UnsupportedInstruction`], while a bad or overflowing
   /// depth reports [`FlattenRejection::StackMismatch`]. Code after a
   /// terminator reports [`FlattenRejection::NonFinalTerminator`], where the
   /// stack is polymorphic. Final terminators are allowed for compiled
   /// blocks ending in `br`.
   #[inline]
   pub fn analyze(
      module: &walrus::Module,
      func: &walrus::LocalFunction,
      seq: ir::InstrSeqId,
   ) -> Result<Self, FlattenRejection> {
      let instrs = &func.block(seq).instrs;
      let mut depth = 0_i32;
      let mut trace = Vec::with_capacity(instrs.len());

      for (index, pair) in instrs.iter().enumerate() {
         let instr = &pair.0;

         if terminates(instr) {
            if index + 1 != instrs.len() {
               return Err(FlattenRejection::NonFinalTerminator);
            }

            trace.push(depth);
            return Ok(Self {
               depths:     trace,
               terminated: true,
            });
         }

         let (pops, pushes) = effect(module, func, instr)?;
         depth = depth
            .checked_sub(i32::try_from(pops).map_err(|_error| FlattenRejection::StackMismatch)?)
            .ok_or(FlattenRejection::StackMismatch)?;

         if depth < 0_i32 {
            return Err(FlattenRejection::StackMismatch);
         }

         depth = depth
            .checked_add(i32::try_from(pushes).map_err(|_error| FlattenRejection::StackMismatch)?)
            .ok_or(FlattenRejection::StackMismatch)?;
         trace.push(depth);
      }

      Ok(Self {
         depths:     trace,
         terminated: false,
      })
   }
}

/// Whether control never falls off the end of this instruction.
const fn terminates(instr: &ir::Instr) -> bool {
   matches!(
      instr,
      ir::Instr::Br(_) | ir::Instr::BrTable(_) | ir::Instr::Return(_) | ir::Instr::Unreachable(_)
   )
}

/// Net stack effect as (pops, pushes).
#[expect(clippy::wildcard_enum_match_arm, reason = "it's huge")]
#[inline]
pub fn effect(
   module: &walrus::Module,
   func: &walrus::LocalFunction,
   instr: &ir::Instr,
) -> Result<(usize, usize), FlattenRejection> {
   let arity = |seq: ir::InstrSeqType| {
      match seq {
         ir::InstrSeqType::Simple(result) => (0, usize::from(result.is_some())),
         ir::InstrSeqType::MultiValue(id) => {
            let signature = module.types.get(id);
            (signature.params().len(), signature.results().len())
         },
      }
   };

   let (pops, pushes) = match *instr {
      ir::Instr::Const(_)
      | ir::Instr::LocalGet(_)
      | ir::Instr::GlobalGet(_)
      | ir::Instr::MemorySize(_)
      | ir::Instr::TableSize(_)
      | ir::Instr::RefNull(_)
      | ir::Instr::RefFunc(_) => (0, 1),
      // `br_if` consumes its condition. Any values the target expects stay on the stack in both
      // the taken and untaken cases, so they do not enter the net effect.
      ir::Instr::LocalSet(_)
      | ir::Instr::GlobalSet(_)
      | ir::Instr::Drop(_)
      | ir::Instr::BrIf(_) => (1, 0),
      ir::Instr::DataDrop(_) | ir::Instr::AtomicFence(_) => (0, 0),
      ir::Instr::LocalTee(_)
      | ir::Instr::Unop(_)
      | ir::Instr::Load(_)
      | ir::Instr::MemoryGrow(_)
      | ir::Instr::TableGet(_)
      | ir::Instr::RefIsNull(_) => (1, 1),
      ir::Instr::Binop(_) | ir::Instr::TableGrow(_) => (2, 1),
      ir::Instr::Store(_) | ir::Instr::TableSet(_) => (2, 0),
      ir::Instr::TernOp(_) | ir::Instr::Select(_) => (3, 1),
      ir::Instr::MemoryCopy(_)
      | ir::Instr::MemoryFill(_)
      | ir::Instr::MemoryInit(_)
      | ir::Instr::TableFill(_) => (3, 0),
      ir::Instr::Call(ref call) => {
         let signature = module.types.get(module.funcs.get(call.func).ty());
         (signature.params().len(), signature.results().len())
      },
      ir::Instr::CallIndirect(ref call) => {
         let signature = module.types.get(call.ty);
         (signature.params().len() + 1, signature.results().len())
      },
      ir::Instr::Block(ref block) => arity(func.block(block.seq).ty),
      ir::Instr::Loop(ref block) => arity(func.block(block.seq).ty),
      ir::Instr::IfElse(ref block) => {
         let (params, results) = arity(func.block(block.consequent).ty);
         (params + 1, results)
      },
      _ => return Err(FlattenRejection::UnsupportedInstruction),
   };

   Ok((pops, pushes))
}
