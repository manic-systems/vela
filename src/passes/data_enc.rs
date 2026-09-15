use std::collections::{
   BTreeMap,
   BTreeSet,
};

use walrus::{
   FunctionId,
   ir,
};

use crate::{
   Rewriter,
   analysis,
   config::{
      EagerReason,
      SegmentReport,
      UnresolvedUse,
   },
   emit::Decryptor,
   rng::KeyStream,
};

/// Decrypt calls that have to run before anything else, flattened into the
/// init function.
#[inline]
pub fn run(rewriter: &mut Rewriter<'_>) -> Vec<ir::Instr> {
   plan_staging(rewriter);
   let module = &mut rewriter.module;
   let rng = &mut rewriter.rng;
   let config = rewriter.config;
   let report = &mut rewriter.report;
   let segments = &rewriter.segments;
   let generated = &mut rewriter.generated;
   let Some(memory) = module.memories.iter().next().map(walrus::Memory::id) else {
      return Vec::new();
   };
   report.segments_total = segments.len();

   if segments.is_empty() {
      return Vec::new();
   }

   let references = &rewriter.references.functions;

   let decryptor = Decryptor::new(module, memory, config.debug_names);
   generated.insert(decryptor.id());
   let mut eager = Vec::<ir::Instr>::new();
   let mut gates = Vec::<(analysis::Segment, FunctionId)>::new();

   for (segment, details) in segments.iter().zip(&report.segments) {
      let seed = rng.next_nonzero_u64();
      let data = module.data.get_mut(segment.id);
      KeyStream::apply(seed, &mut data.value);

      report.segments_encrypted += 1;
      report.bytes_encrypted += segment.len;

      if details.startup_may_decrypt {
         report.bytes_startup_upper_bound += segment.len;
      }

      if !details.eager_reasons.is_empty() {
         report.segments_forced_eager += 1;
         report.bytes_eager += segment.len;
         decryptor.call(segment, seed, &mut eager);
         continue;
      }

      report.segments_lazy += 1;
      report.bytes_lazy += segment.len;
      let gate = decryptor.gate(module, segment, seed);
      generated.insert(gate);
      gates.push((*segment, gate));
   }

   for (segment, gate) in gates {
      let Some(callers) = references.get(&segment.id) else {
         continue;
      };

      for caller in callers {
         if generated.contains(caller) {
            continue;
         }

         let &mut walrus::FunctionKind::Local(ref mut func) =
            &mut module.funcs.get_mut(*caller).kind
         else {
            continue;
         };

         let entry = func.entry_block();
         func.builder_mut().instr_seq(entry).instrs_mut().insert(
            0,
            (ir::Call { func: gate }.into(), ir::InstrLocId::default()),
         );
      }
   }

   eager
}

/// Both analyses read plaintext, so they have to run before a single byte
/// is encrypted.
fn plan_staging(rewriter: &mut Rewriter<'_>) {
   let module = &rewriter.module;
   let references = &rewriter.references;
   let report = &mut rewriter.report;
   let function_indices = module
      .funcs
      .iter()
      .enumerate()
      .map(|(index, function)| (function.id(), index))
      .collect::<BTreeMap<_, _>>();
   let segment_indices = module
      .data
      .iter()
      .enumerate()
      .map(|(index, data)| (data.id(), index))
      .collect::<BTreeMap<_, _>>();
   report.unresolved_memory_uses = references.unresolved.len();
   report.unresolved = references
      .unresolved
      .iter()
      .map(|(&(function, location), reasons)| {
         UnresolvedUse {
            function:    function_indices[&function],
            instruction: (!location.is_default()).then(|| location.data()),
            reasons:     reasons.clone(),
         }
      })
      .collect();

   let pointed_at = analysis::data_resident_pointers(module, &rewriter.segments);

   for segment in &rewriter.segments {
      let callers = references.functions.get(&segment.id);
      let eager_reasons = [
         (EagerReason::Requested, !rewriter.config.lazy),
         (
            EagerReason::UnresolvedMemory,
            !references.unresolved.is_empty(),
         ),
         (EagerReason::Relocatable, !segment.stageable()),
         (EagerReason::DataPointer, pointed_at.contains(&segment.id)),
         (
            EagerReason::Unreferenced,
            callers.is_none_or(BTreeSet::is_empty),
         ),
      ]
      .into_iter()
      .filter_map(|(reason, applies)| applies.then_some(reason))
      .collect::<BTreeSet<_>>();
      let startup_may_decrypt = !eager_reasons.is_empty()
         || callers.is_some_and(|functions| {
            functions
               .iter()
               .any(|function| references.startup.contains(function))
         });
      report.segments.push(SegmentReport {
         index: segment_indices[&segment.id],
         bytes: segment.len,
         functions: callers
            .into_iter()
            .flatten()
            .map(|function| function_indices[function])
            .collect(),
         eager_reasons,
         startup_may_decrypt,
      });
   }
}
