use std::collections::{
   BTreeMap,
   BTreeSet,
};

use walrus::{
   FunctionId,
   FunctionKind,
   LocalFunction,
   LocalId,
   Module,
   TypeId,
   ValType,
   ir::{
      Block,
      BrTable,
      Instr,
      InstrLocId,
      InstrSeqId,
      InstrSeqType,
      Loop,
   },
};

use crate::{
   analysis,
   config::AnalysisReason,
   references::{
      frame::Frame,
      solver::{
         CallInput,
         References,
         Solver,
      },
      value::{
         Values,
         Word,
      },
   },
   stack,
};

/// Walrus labels keep their identity when branch depths differ between paths.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Point {
   /// Labels identify both sequence entries and branch destinations.
   sequence: InstrSeqId,
   /// Block exits resume after the instruction owning the child sequence.
   index:    usize,
}

/// Loop branches resume at the header while normal loop exits fall through.
#[derive(Clone, Copy)]
enum Continuation {
   /// A function label exits the invocation rather than resuming its caller's
   /// stack.
   Return,
   /// Branches and normal exits share a block's continuation.
   Block(Point),
   /// Only normal exits use this continuation, backedges reuse the loop entry.
   Loop(Point),
}

/// Wasm block inputs and outputs can have different arities.
struct Sequence {
   /// The owning instruction determines the destination after normal
   /// completion.
   continuation: Continuation,
   /// Loop backedges carry inputs rather than the loop's result tuple.
   parameters:   usize,
   /// Branches out of ordinary blocks carry this tuple.
   results:      usize,
}

/// Control signatures do not depend on the values used to specialize a
/// function.
pub struct Flow {
   /// Branch targets refer to this original ownership tree.
   sequences: BTreeMap<InstrSeqId, Sequence>,
   /// Wasm initializes non-argument locals once per invocation, never per
   /// block.
   locals:    BTreeMap<LocalId, Word>,
}

impl Flow {
   /// Parsed functions own their child sequences even when those children are
   /// unreachable.
   #[expect(
      clippy::wildcard_enum_match_arm,
      reason = "only structured instructions own sequences"
   )]
   pub fn new(module: &Module, function: &LocalFunction) -> Self {
      let mut flow = Self {
         sequences: BTreeMap::new(),
         locals:    BTreeMap::new(),
      };
      let mut insert = |sequence, continuation| {
         let (parameters, results) = match function.block(sequence).ty {
            InstrSeqType::Simple(result) => (0, usize::from(result.is_some())),
            InstrSeqType::MultiValue(signature) => {
               let shape = module.types.get(signature);
               (shape.params().len(), shape.results().len())
            },
         };
         flow.sequences.insert(sequence, Sequence {
            continuation,
            parameters,
            results,
         });
      };
      insert(function.entry_block(), Continuation::Return);

      for sequence in analysis::all_seqs(function) {
         for (index, &(ref instruction, _location)) in
            function.block(sequence).instrs.iter().enumerate()
         {
            let next = Point {
               sequence,
               index: index + 1,
            };

            match *instruction {
               Instr::Block(ref block) => insert(block.seq, Continuation::Block(next)),
               Instr::Loop(ref block) => insert(block.seq, Continuation::Loop(next)),
               Instr::IfElse(ref conditional) => {
                  insert(conditional.consequent, Continuation::Block(next));
                  insert(conditional.alternative, Continuation::Block(next));
               },
               _ => {},
            }

            let local = match *instruction {
               Instr::LocalGet(ref get) => get.local,
               Instr::LocalSet(ref set) => set.local,
               Instr::LocalTee(ref tee) => tee.local,
               _ => continue,
            };
            let value = if module.locals.get(local).ty() == ValType::I32 {
               Word::constant(0, None)
            } else {
               Word::unknown(AnalysisReason::UnsupportedInstruction)
            };
            flow.locals.insert(local, value);
         }
      }

      flow
   }
}

/// A returning summary is published only after the current worklist drains.
pub struct Scan {
   /// Every reached memory effect survives even when no path returns.
   pub references: References,
   /// Absence suspends callers without inventing a value for recursive calls.
   pub returned:   Option<Vec<Word>>,
   /// Registration happens after scanning so summaries cannot change mid-scan.
   pub calls:      Vec<CallInput>,
   /// The next call context inherits this budget instead of receiving a fresh
   /// one.
   pub remaining:  usize,
}

impl Scan {
   /// Each context starts with fresh locals and a snapshot of callee summaries.
   pub fn run(solver: &Solver<'_>, index: usize, remaining: usize) -> Self {
      let context = &solver.contexts[index];
      let function = solver
         .module
         .funcs
         .get(context.function)
         .kind
         .unwrap_local();
      let flow = &solver.flows[&context.function];
      let mut locals = flow.locals.clone();

      for (local, argument) in function.args.iter().zip(&context.arguments) {
         locals.insert(*local, argument.clone());
      }

      let entry = function.entry_block();
      let point = Point {
         sequence: entry,
         index:    0,
      };
      let mut walker = Walker {
         solver,
         function,
         id: context.function,
         flow,
         bases: BTreeMap::from([(entry, 0)]),
         states: BTreeMap::from([(point, Frame {
            operands: Vec::new(),
            locals,
         })]),
         pending: BTreeSet::from([point]),
         output: Self {
            references: References::default(),
            returned: None,
            calls: Vec::new(),
            remaining,
         },
      };

      while let Some(next) = walker.pending.pop_first() {
         let frame = walker.states[&next].clone();
         walker.scan(next, frame);

         if walker.output.remaining == 0 {
            break;
         }
      }

      walker.output
   }
}

/// Branch joins share state only within a single abstract invocation.
struct Walker<'scan, 'module> {
   /// Callee summaries stay immutable until this invocation finishes scanning.
   solver:   &'scan Solver<'module>,
   /// Runtime helper insertion must follow analysis of this original body.
   function: &'module LocalFunction,
   /// Gate ownership remains the input function across all argument contexts.
   id:       FunctionId,
   /// Block signatures are reused between value specializations.
   flow:     &'scan Flow,
   /// Wasm branches discard temporaries above the target label's entry height.
   bases:    BTreeMap<InstrSeqId, usize>,
   /// Saved entry states must survive transfer so later paths can widen them.
   states:   BTreeMap<Point, Frame>,
   /// Stable order keeps convergence and budget exhaustion reproducible.
   pending:  BTreeSet<Point>,
   /// The caller receives no references to the temporary worklist.
   output:   Scan,
}

impl Walker<'_, '_> {
   /// Branch duplication consumes the shared budget before retaining another
   /// frame.
   fn enqueue(&mut self, point: Point, frame: Frame) {
      let Some(remaining) = self.output.remaining.checked_sub(frame.cost()) else {
         self.output.remaining = 0;
         self.output.references.issue(
            (self.id, InstrLocId::default()),
            AnalysisReason::AnalysisLimit,
         );
         return;
      };
      self.output.remaining = remaining;

      let reason = if point.index == 0
         && matches!(
            self.flow.sequences[&point.sequence].continuation,
            Continuation::Loop(_)
         ) {
         AnalysisReason::LoopValue
      } else {
         AnalysisReason::BranchMerge
      };

      if let Some(existing) = self.states.get_mut(&point) {
         match existing.join(&frame, reason) {
            Some(true) => {
               self.pending.insert(point);
            },
            Some(false) => {},
            None => self.unsupported(InstrLocId::default()),
         }
      } else {
         self.states.insert(point, frame);
         self.pending.insert(point);
      }
   }

   /// Block parameters remain on the operand stack above the saved label
   /// height.
   fn enter(&mut self, sequence: InstrSeqId, frame: Frame, location: InstrLocId) {
      let Some(base) = frame
         .operands
         .len()
         .checked_sub(self.flow.sequences[&sequence].parameters)
      else {
         self.unsupported(location);
         return;
      };

      self.bases.insert(sequence, base);
      self.enqueue(Point { sequence, index: 0 }, frame);
   }

   /// Returned pointers can be observed by a host before another guest access.
   fn returned(&mut self, values: Vec<Word>, location: InstrLocId) {
      for value in &values {
         self
            .output
            .references
            .escape(self.solver.segments, (self.id, location), value);
      }

      if let Some(ref mut prior) = self.output.returned {
         for (target, incoming) in prior.iter_mut().zip(&values) {
            target.join(incoming, AnalysisReason::ReturnValue);
         }
      } else {
         self.output.returned = Some(values);
      }
   }

   /// A Wasm return discards temporaries below the function's result tuple.
   fn finish(&mut self, mut frame: Frame, location: InstrLocId) {
      let count = self
         .solver
         .module
         .types
         .get(self.function.ty())
         .results()
         .len();

      if let Some(values) = frame.take(count) {
         self.returned(values, location);
      } else {
         self.unsupported(location);
      }
   }

   /// An unsupported effect cannot establish that a function never returns.
   fn unsupported(&mut self, location: InstrLocId) {
      self
         .output
         .references
         .issue((self.id, location), AnalysisReason::UnsupportedInstruction);
      let count = self
         .solver
         .module
         .types
         .get(self.function.ty())
         .results()
         .len();
      self.returned(
         vec![Word::unknown(AnalysisReason::UnsupportedInstruction); count],
         location,
      );
   }

   /// Loop backedges carry parameters while block exits carry results.
   fn transfer(
      &mut self,
      target: InstrSeqId,
      mut frame: Frame,
      branch: bool,
      location: InstrLocId,
   ) {
      let shape = &self.flow.sequences[&target];
      let repeat = branch && matches!(shape.continuation, Continuation::Loop(_));
      let arity = if repeat {
         shape.parameters
      } else {
         shape.results
      };
      let Some(values) = frame.take(arity) else {
         self.unsupported(location);
         return;
      };
      let base = self.bases[&target];

      if base > frame.operands.len() {
         self.unsupported(location);
         return;
      }

      frame.operands.truncate(base);
      frame.operands.extend(values);

      match shape.continuation {
         Continuation::Return => self.finish(frame, location),
         Continuation::Loop(_) if repeat => {
            self.enqueue(
               Point {
                  sequence: target,
                  index:    0,
               },
               frame,
            );
         },
         Continuation::Block(next) | Continuation::Loop(next) => self.enqueue(next, frame),
      }
   }

   /// A pending recursive summary is different from a completed unknown return
   /// value.
   fn call(&mut self, function: FunctionId, frame: &mut Frame, location: InstrLocId) -> bool {
      let callee = self.solver.module.funcs.get(function);
      let signature = self.solver.module.types.get(callee.ty());
      let Some(arguments) = frame.take(signature.params().len()) else {
         self.unsupported(location);
         return false;
      };

      for argument in &arguments {
         self
            .output
            .references
            .escape(self.solver.segments, (self.id, location), argument);
      }

      if matches!(callee.kind, FunctionKind::Import(_)) {
         self
            .output
            .references
            .issue((self.id, location), AnalysisReason::ImportedCall);

         frame.operands.extend(
            signature
               .results()
               .iter()
               .map(|_kind| Word::unknown(AnalysisReason::ReturnValue)),
         );
         return true;
      }

      let summary = self
         .solver
         .lookup(function, &arguments)
         .and_then(|index| self.solver.contexts[index].returned.as_ref());
      self.output.calls.push(CallInput {
         function,
         arguments,
      });

      if let Some(values) = summary {
         frame.operands.extend(values.iter().cloned());
         true
      } else {
         false
      }
   }

   /// An unresolved target may access memory without receiving a pointer
   /// argument.
   fn dynamic_call(&mut self, signature: TypeId, frame: &mut Frame, location: InstrLocId) {
      self
         .output
         .references
         .issue((self.id, location), AnalysisReason::DynamicCall);
      let shape = self.solver.module.types.get(signature);
      frame.pop();

      for _parameter in shape.params() {
         let argument = frame.pop();
         self
            .output
            .references
            .escape(self.solver.segments, (self.id, location), &argument);
      }

      frame.operands.extend(
         shape
            .results()
            .iter()
            .map(|_kind| Word::unknown(AnalysisReason::ReturnValue)),
      );
   }

   /// Bulk lengths and instruction widths both constrain segment aliases.
   #[expect(
      clippy::wildcard_enum_match_arm,
      reason = "only memory and escaping values need gates"
   )]
   fn memory_effect(
      &mut self,
      instruction: &Instr,
      frame: &mut Frame,
      location: InstrLocId,
   ) -> bool {
      let site = (self.id, location);

      match *instruction {
         Instr::GlobalSet(_) => {
            self
               .output
               .references
               .escape(self.solver.segments, site, &frame.pop());
         },
         Instr::Load(ref load) => {
            self.output.references.access(
               self.solver.segments,
               site,
               &frame.pop(),
               load.arg.offset,
               &Word::constant(load.kind.width(), None),
            );
            frame
               .operands
               .push(Word::unknown(AnalysisReason::MemoryValue));
         },
         Instr::Store(ref store) => {
            self
               .output
               .references
               .escape(self.solver.segments, site, &frame.pop());
            self.output.references.access(
               self.solver.segments,
               site,
               &frame.pop(),
               store.arg.offset,
               &Word::constant(store.kind.width(), None),
            );
         },
         Instr::MemoryCopy(_) | Instr::MemoryFill(_) | Instr::MemoryInit(_) => {
            let length = frame.pop();
            let source = frame.pop();
            let destination = frame.pop();

            if matches!(*instruction, Instr::MemoryCopy(_)) {
               self
                  .output
                  .references
                  .access(self.solver.segments, site, &source, 0, &length);
            }

            self
               .output
               .references
               .access(self.solver.segments, site, &destination, 0, &length);
         },
         _ => return false,
      }

      true
   }

   /// Unknown selectors must reach every distinct label, including the default.
   fn branch_table(&mut self, table: &BrTable, mut frame: Frame, location: InstrLocId) {
      let targets = match frame.pop().values {
         Values::Known(values) => {
            values
               .into_iter()
               .map(|value| {
                  usize::try_from(value)
                     .ok()
                     .and_then(|index| table.blocks.get(index))
                     .copied()
                     .unwrap_or(table.default)
               })
               .collect::<BTreeSet<_>>()
         },
         Values::Unknown(_) => {
            table
               .blocks
               .iter()
               .copied()
               .chain([table.default])
               .collect()
         },
      };

      for target in targets {
         self.transfer(target, frame.clone(), true, location);
      }
   }

   /// Sequence boundaries merge facts rather than guessing branch or loop
   /// values.
   #[expect(
      clippy::wildcard_enum_match_arm,
      reason = "the stack model handles non-memory instructions conservatively"
   )]
   fn scan(&mut self, point: Point, mut frame: Frame) {
      let block = self.function.block(point.sequence);

      for &(ref instruction, location) in &block.instrs[point.index..] {
         if self.output.remaining == 0 {
            self
               .output
               .references
               .issue((self.id, location), AnalysisReason::AnalysisLimit);
            return;
         }

         self.output.remaining -= 1;

         if frame.value(self.solver.module, instruction, location)
            || self.memory_effect(instruction, &mut frame, location)
         {
            continue;
         }

         match *instruction {
            Instr::Block(Block { seq }) | Instr::Loop(Loop { seq }) => {
               self.enter(seq, frame, location);
               return;
            },
            Instr::IfElse(ref conditional) => {
               let (zero, nonzero) = frame.pop().truth();

               if zero && nonzero {
                  self.enter(conditional.consequent, frame.clone(), location);
                  self.enter(conditional.alternative, frame, location);
               } else if nonzero {
                  self.enter(conditional.consequent, frame, location);
               } else {
                  self.enter(conditional.alternative, frame, location);
               }

               return;
            },
            Instr::Br(ref branch) => {
               self.transfer(branch.block, frame, true, location);
               return;
            },
            Instr::BrIf(ref branch) => {
               let (zero, nonzero) = frame.pop().truth();

               if nonzero {
                  if !zero {
                     self.transfer(branch.block, frame, true, location);
                     return;
                  }

                  self.transfer(branch.block, frame.clone(), true, location);
               }
            },
            Instr::BrTable(ref table) => {
               self.branch_table(table, frame, location);
               return;
            },
            Instr::Return(_) => {
               self.finish(frame, location);
               return;
            },
            Instr::Unreachable(_) => return,
            Instr::Call(ref call) => {
               if !self.call(call.func, &mut frame, location) {
                  return;
               }
            },
            Instr::ReturnCall(ref call) => {
               if self.call(call.func, &mut frame, location) {
                  self.finish(frame, location);
               }

               return;
            },
            Instr::CallIndirect(ref call) => self.dynamic_call(call.ty, &mut frame, location),
            Instr::CallRef(ref call) => self.dynamic_call(call.ty, &mut frame, location),
            Instr::ReturnCallIndirect(ref call) => {
               self.dynamic_call(call.ty, &mut frame, location);
               self.finish(frame, location);
               return;
            },
            Instr::ReturnCallRef(ref call) => {
               self.dynamic_call(call.ty, &mut frame, location);
               self.finish(frame, location);
               return;
            },
            _ => {
               let Ok((pops, pushes)) =
                  stack::effect(self.solver.module, self.function, instruction)
               else {
                  self.unsupported(location);
                  return;
               };

               if frame.take(pops).is_none() {
                  self.unsupported(location);
                  return;
               }

               frame.operands.extend(vec![
                  Word::unknown(AnalysisReason::UnsupportedInstruction);
                  pushes
               ]);
            },
         }
      }

      self.transfer(point.sequence, frame, false, block.end);
   }
}
