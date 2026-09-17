use walrus::{
   FunctionId,
   FunctionKind,
   ir,
};

use crate::{
   Rewriter,
   analysis,
   config::CodePass,
   mba::Synth,
};

/// Adds never-taken branches at sequence entries.
///
/// Only entries without block parameters are eligible, so insertion starts
/// with an empty operand stack and doesn't need a stack analysis.
#[inline]
pub fn run(rewriter: &mut Rewriter<'_>, readonly: Option<FunctionId>) {
   let module = &mut rewriter.module;
   let rng = &mut rewriter.rng;
   let config = rewriter.config;
   let pool = &rewriter.pool;
   let report = &mut rewriter.report;
   let functions = &mut rewriter.functions;
   let synth = Synth::new(pool.values());

   for id in analysis::local_func_ids(module) {
      let Some(function) = functions
         .get_mut(&id)
         .filter(|entry| entry.passes.contains(&CodePass::Opaque))
      else {
         continue;
      };

      let FunctionKind::Local(ref func) = module.funcs.get(id).kind else {
         continue;
      };
      let entry = func.entry_block();

      let landing = analysis::all_seqs(func)
         .into_iter()
         .filter(|seq| *seq == entry || matches!(func.block(*seq).ty, ir::InstrSeqType::Simple(_)))
         .filter(|_| rng.chance(config.opaque_ratio))
         .collect::<Vec<_>>();

      for seq in landing {
         let Some(expr) = synth.opaque_false(rng) else {
            continue;
         };

         let mut lowered = Vec::new();

         if let Some(check) = readonly {
            lowered.push(ir::Call { func: check }.into());
            report.readonly_checks += 1;
         }

         pool.lower(&expr, &mut lowered);

         let FunctionKind::Local(ref mut func_mut) = module.funcs.get_mut(id).kind else {
            continue;
         };
         let builder = func_mut.builder_mut();

         let consequent = {
            let mut arm = builder.dangling_instr_seq(ir::InstrSeqType::Simple(None));
            arm.instr(ir::Unreachable {});
            arm.id()
         };
         let alternative = builder
            .dangling_instr_seq(ir::InstrSeqType::Simple(None))
            .id();

         lowered.push(
            ir::IfElse {
               consequent,
               alternative,
            }
            .into(),
         );

         builder.instr_seq(seq).instrs_mut().splice(
            0..0,
            lowered
               .into_iter()
               .map(|instr| (instr, ir::InstrLocId::default())),
         );

         report.opaque_inserted += 1;
         function.opaque_inserted += 1;
      }
   }
}
