use walrus::{
   FunctionId,
   ir,
};

use crate::{
   Rewriter,
   analysis,
   emit::Decryptor,
   rng::KeyStream,
};

/// Decrypt calls that have to run before anything else, flattened into the
/// init function.
#[inline]
pub fn run(rewriter: &mut Rewriter<'_>) -> Vec<ir::Instr> {
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

   // Both analyses read plaintext, so they have to run before a single byte
   // is encrypted.
   let references = &rewriter.references.functions;
   report.unresolved_memory_uses = rewriter.references.unresolved;
   let pointed_at = analysis::data_resident_pointers(module, segments);

   let decryptor = Decryptor::new(module, memory, config.debug_names);
   generated.insert(decryptor.id());
   let mut eager = Vec::<ir::Instr>::new();
   let mut gates = Vec::<(analysis::Segment, FunctionId)>::new();

   for segment in segments {
      let seed = rng.next_nonzero_u64();
      let data = module.data.get_mut(segment.id);
      KeyStream::apply(seed, &mut data.value);

      report.segments_encrypted += 1;
      report.bytes_encrypted += segment.len;

      let can_stage = config.lazy
         && rewriter.references.unresolved == 0
         && segment.stageable()
         && !pointed_at.contains(&segment.id)
         && references
            .get(&segment.id)
            .is_some_and(|set| !set.is_empty());

      if !can_stage {
         report.segments_forced_eager += 1;
         decryptor.call(segment, seed, &mut eager);
         continue;
      }

      report.segments_lazy += 1;
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
