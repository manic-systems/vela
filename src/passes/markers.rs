use walrus::{
   FunctionId,
   FunctionKind,
   ir,
};

use crate::{
   Rewriter,
   analysis,
   config::CodePass,
   mba,
};

/// Replaces selected `i32.const` operands with arithmetic over the global
/// pool.
///
/// Evaluate each expression against the mixed pool before emission. Keep the
/// original constant if the result doesn't match.
#[inline]
pub fn run(rewriter: &mut Rewriter<'_>, readonly: Option<FunctionId>) {
   let module = &mut rewriter.module;
   let rng = &mut rewriter.rng;
   let config = rewriter.config;
   let pool = &rewriter.pool;
   let proven = &rewriter.references.addresses;
   let report = &mut rewriter.report;
   let functions = &mut rewriter.functions;
   let dispatch_marker = rewriter.dispatch_marker;
   let synth = mba::Synth::new(pool.values());
   report.pool_size = pool.values().len();

   for id in analysis::local_func_ids(module) {
      let Some(function) = functions
         .get_mut(&id)
         .filter(|entry| entry.passes.contains(&CodePass::Markers))
      else {
         continue;
      };

      let FunctionKind::Local(ref func) = module.funcs.get(id).kind else {
         continue;
      };

      for seq in analysis::all_seqs(func) {
         let FunctionKind::Local(ref seq_func) = module.funcs.get(id).kind else {
            continue;
         };
         let instrs = &seq_func.block(seq).instrs;

         let chosen = instrs
            .iter()
            .enumerate()
            .filter_map(|(at, pair)| {
               let (ref instr, _) = *pair;
               let ir::Instr::Const(ref konst) = *instr else {
                  return None;
               };
               let ir::Value::I32(value) = konst.value else {
                  return None;
               };
               let dispatch = pair.1 == dispatch_marker;
               let addressed = proven.contains(&pair.1);

               (config.markers_all || dispatch || addressed).then_some((at, value, dispatch))
            })
            .collect::<Vec<(usize, i32, bool)>>();

         for (at, value, dispatch) in chosen.into_iter().rev() {
            let Some(expr) = synth.checked(rng, value, config.marker_depth.get(), config.integrity)
            else {
               report.markers_skipped += 1;
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
            let mut body = func_mut.builder_mut().instr_seq(seq);
            let sequence = body.instrs_mut();

            sequence.splice(
               at..=at,
               lowered
                  .into_iter()
                  .map(|instr| (instr, ir::InstrLocId::default())),
            );
            report.markers_rewritten += 1;
            function.markers_rewritten += 1;
            if dispatch {
               report.dispatch_markers_rewritten += 1;
               function.dispatch_markers_rewritten += 1;
            }
         }
      }
   }
}
