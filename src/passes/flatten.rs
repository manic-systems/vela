use std::{
   iter::repeat_with,
   mem::take,
};

use walrus::{
   ConstExpr,
   FunctionBuilder,
   FunctionId,
   FunctionKind,
   LocalId,
   Module,
   ValType,
   ir,
};

use crate::{
   Rewriter,
   analysis,
   config::{
      CodePass,
      Config,
      FlattenRejection,
      FunctionReport,
      Report,
   },
   rng::Rng,
   stack::Trace,
};

/// Rewrites instruction sequences as `br_table` dispatch loops.
///
/// walrus keeps branch targets as `ir::InstrSeqId` references, so wrapping
/// regions in new blocks doesn't change their targets. Existing branches
/// still target a block within the region or an enclosing sequence, which
/// lets us flatten each sequence without rebuilding the function's
/// control flow.
#[inline]
pub fn run(rewriter: &mut Rewriter<'_>) {
   let module = &mut rewriter.module;
   let rng = &mut rewriter.rng;
   let config = rewriter.config;
   let dispatch_marker = rewriter.dispatch_marker;
   let report = &mut rewriter.report;
   let functions = &mut rewriter.functions;
   let mut key = None;

   for id in analysis::local_func_ids(module) {
      let Some(function) = functions
         .get_mut(&id)
         .filter(|entry| entry.passes.contains(&CodePass::Flatten))
      else {
         continue;
      };

      let FunctionKind::Local(ref func) = module.funcs.get(id).kind else {
         continue;
      };

      let entry = func.entry_block();
      let targets = analysis::all_seqs(func)
         .into_iter()
         .map(|seq| (seq, func.block(seq).ty))
         .collect::<Vec<(ir::InstrSeqId, ir::InstrSeqType)>>();

      for (seq, ty) in targets {
         if seq != entry && !matches!(ty, ir::InstrSeqType::Simple(None)) {
            refuse(report, function, FlattenRejection::BlockSignature);
            continue;
         }
         if !rng.chance(config.flatten_ratio) {
            continue;
         }

         match Plan::build(module, id, seq, rng, config) {
            Ok(plan) => {
               let source = config.evolve_dispatch.then(|| {
                  let helper = *key.get_or_insert_with(|| {
                     let global = module.globals.add_local(
                        ValType::I32,
                        true,
                        false,
                        ConstExpr::Value(ir::Value::I32(rng.next_i32())),
                     );
                     let mut builder =
                        FunctionBuilder::new(&mut module.types, &[], &[ValType::I32]);

                     if config.debug_names {
                        builder.name("vela_dispatch_key".to_owned());
                     }

                     builder
                        .func_body()
                        .global_get(global)
                        .i32_const(rng.next_i32() | 1)
                        .binop(ir::BinaryOp::I32Add)
                        .global_set(global)
                        .global_get(global)
                        .i32_const(rng.next_i32() & 31)
                        .binop(ir::BinaryOp::I32Rotl);

                     builder.finish(Vec::new(), &mut module.funcs)
                  });

                  rewriter.generated.insert(helper);
                  report.seqs_evolving += 1;
                  function.seqs_evolving += 1;
                  helper
               });

               let regions = plan.apply(module, rng, dispatch_marker, source);
               report.seqs_flattened += 1;
               report.flatten_regions += regions;
               function.seqs_flattened += 1;
               function.flatten_regions += regions;
            },
            Err(reason) => refuse(report, function, reason),
         }
      }
   }
}

/// Counts one refused sequence globally and for its function.
fn refuse(report: &mut Report, function: &mut FunctionReport, reason: FlattenRejection) {
   report.seqs_unflattenable += 1;
   *function.flatten_refusals.entry(reason).or_default() += 1;
}

/// Where a region hands control on. Every region ends in a branch, so the
/// dispatch loop never falls through to its own end.
fn tail(
   logical: usize,
   count: usize,
   mut next: Vec<(ir::Instr, ir::InstrLocId)>,
   result: Option<LocalId>,
   dispatch: ir::InstrSeqId,
   exit: ir::InstrSeqId,
) -> Vec<(ir::Instr, ir::InstrLocId)> {
   if logical + 1 == count {
      let mut last = Vec::new();
      if let Some(local) = result {
         last.push((ir::LocalSet { local }.into(), ir::InstrLocId::default()));
      }
      last.push((ir::Br { block: exit }.into(), ir::InstrLocId::default()));
      return last;
   }

   next.push((ir::Br { block: dispatch }.into(), ir::InstrLocId::default()));
   next
}

/// Generated control instructions have no original source location.
fn flat(
   instrs: impl IntoIterator<Item = ir::Instr>,
) -> impl Iterator<Item = (ir::Instr, ir::InstrLocId)> {
   instrs
      .into_iter()
      .map(|instr| (instr, ir::InstrLocId::default()))
}

/// Regions come back as `Option`s because flatten takes each one out of its
/// original position instead of leaving it in place.
fn split(
   instrs: Vec<(ir::Instr, ir::InstrLocId)>,
   cuts: &[usize],
) -> Vec<Option<Vec<(ir::Instr, ir::InstrLocId)>>> {
   let mut remaining = instrs;
   let mut regions = Vec::with_capacity(cuts.len() + 1);

   for cut in cuts.iter().rev() {
      regions.push(Some(remaining.split_off(*cut)));
   }

   regions.push(Some(remaining));
   regions.reverse();
   regions
}

/// Validated cut points, computed before any instructions are moved.
struct Plan {
   /// Function holding the sequence being flattened.
   func:   FunctionId,
   /// Sequence the cut points apply to.
   seq:    ir::InstrSeqId,
   /// Ordered ascending so `split` can carve from the back without shifting
   /// indices already computed for earlier cuts.
   cuts:   Vec<usize>,
   /// `Some` only when the sequence is the function entry, the one place a
   /// spilled result local is needed.
   result: Option<ValType>,
}

impl Plan {
   /// Returns the number of regions the sequence was split into.
   fn apply(
      self,
      module: &mut Module,
      rng: &mut Rng,
      dispatch_marker: ir::InstrLocId,
      key: Option<FunctionId>,
   ) -> usize {
      let state = module.locals.add(ValType::I32);
      let epoch = key.map(|source| (module.locals.add(ValType::I32), source));
      let result = self.result.map(|ty| module.locals.add(ty));
      let encode = |value: i32| {
         let mut instructions = Vec::new();

         if let Some((local, func)) = epoch {
            instructions.extend(flat([
               ir::Call { func }.into(),
               ir::LocalTee { local }.into(),
            ]));
         }

         instructions.push((
            ir::Const {
               value: ir::Value::I32(value),
            }
            .into(),
            dispatch_marker,
         ));

         if epoch.is_some() {
            instructions.extend(flat([ir::Binop {
               op: ir::BinaryOp::I32Xor,
            }
            .into()]));
         }

         instructions.extend(flat([ir::LocalSet { local: state }.into()]));
         instructions
      };

      let func = module.funcs.get_mut(self.func).kind.unwrap_local_mut();
      let builder = func.builder_mut();
      let mut regions = split(take(builder.instr_seq(self.seq).instrs_mut()), &self.cuts);
      let count = regions.len();

      let exit = builder
         .dangling_instr_seq(ir::InstrSeqType::Simple(None))
         .id();
      let dispatch = builder
         .dangling_instr_seq(ir::InstrSeqType::Simple(None))
         .id();
      let cases = repeat_with(|| {
         builder
            .dangling_instr_seq(ir::InstrSeqType::Simple(None))
            .id()
      })
      .take(count)
      .collect::<Vec<ir::InstrSeqId>>();

      // `slots[k]` maps physical block position `k` to its logical region.
      let mut slots = (0..count).collect::<Vec<usize>>();
      for index in (1..count).rev() {
         slots.swap(index, rng.below(index + 1));
      }

      #[expect(
         clippy::expect_used,
         reason = "slots is a permutation of 0..count, so every logical index has a position"
      )]
      let table = (0..count)
         .map(|logical| {
            cases[slots
               .iter()
               .position(|slot| *slot == logical)
               .expect("permutation")]
         })
         .collect::<Box<[ir::InstrSeqId]>>();

      let mut selector = builder.instr_seq(cases[0]);
      selector.local_get(state);

      if let Some((local, _)) = epoch {
         selector.local_get(local).binop(ir::BinaryOp::I32Xor);
      }

      selector.br_table(table, exit);

      // A branch to `cases[level]` exits that block and enters the region
      // placed after it. The outermost region sits directly in the
      // dispatch loop.
      for level in 0..count {
         let logical = slots[level];
         let container = if level + 1 < count {
            cases[level + 1]
         } else {
            dispatch
         };

         let mut container_body = builder.instr_seq(container);
         container_body.instr(ir::Block { seq: cases[level] });
         let body = container_body.instrs_mut();
         #[expect(
            clippy::expect_used,
            reason = "a region missing here means a logical index was visited twice, a real bug \
                      that propagating None via `?` would hide rather than surface"
         )]
         body.extend(regions[logical].take().expect("region moved once"));
         body.extend(tail(
            logical,
            count,
            encode(i32::try_from(logical).unwrap_or(i32::MAX).saturating_add(1)),
            result,
            dispatch,
            exit,
         ));
      }

      builder.instr_seq(exit).instr(ir::Loop { seq: dispatch });

      let mut head = encode(0_i32);
      head.push((ir::Block { seq: exit }.into(), ir::InstrLocId::default()));
      if let Some(local) = result {
         head.push((ir::LocalGet { local }.into(), ir::InstrLocId::default()));
      }

      builder.instr_seq(self.seq).instrs_mut().extend(head);

      count
   }

   /// Returns the validated cut points, or the reason the sequence stays whole.
   fn build(
      module: &Module,
      func_id: FunctionId,
      seq: ir::InstrSeqId,
      rng: &mut Rng,
      config: &Config,
   ) -> Result<Self, FlattenRejection> {
      let func = module.funcs.get(func_id).kind.unwrap_local();

      let is_entry = func.entry_block() == seq;
      let results = module.types.get(func.ty()).results();

      // The entry sequence's result is spilled to one local. Multiple return
      // values would require separate locals.
      if is_entry && results.len() > 1 {
         return Err(FlattenRejection::MultipleResults);
      }

      let trace = Trace::analyze(module, func, seq)?;
      let expected = if is_entry {
         i32::try_from(results.len()).map_err(|_error| FlattenRejection::StackMismatch)?
      } else {
         0_i32
      };

      // A terminating sequence has no fallthrough stack depth to match.
      if !trace.terminated && trace.depths.last().copied().unwrap_or(0_i32) != expected {
         return Err(FlattenRejection::StackMismatch);
      }

      let depths = trace.depths;
      let mut candidates = (1..depths.len())
         .filter(|position| depths[position - 1] == 0_i32)
         .collect::<Vec<usize>>();

      if candidates.is_empty() {
         return Err(FlattenRejection::NoCuts);
      }

      for index in (1..candidates.len()).rev() {
         candidates.swap(index, rng.below(index + 1));
      }
      candidates.truncate(config.max_regions.max(2) - 1);
      candidates.sort_unstable();

      Ok(Self {
         func: func_id,
         seq,
         cuts: candidates,
         result: is_entry.then(|| results.first().copied()).flatten(),
      })
   }
}
