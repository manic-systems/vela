use std::collections::{
   BTreeMap,
   BTreeSet,
};

use walrus::{
   Data,
   Function,
   FunctionId,
   Module,
   ir::InstrLocId,
};

use crate::{
   Rewriter,
   TransformError,
   config::{
      AnalysisReason,
      Config,
      FunctionReport,
      Report,
   },
   references::solver::References,
};

pub struct Prepared {
   /// Reparsing identical bytes preserves instruction offsets in the cached
   /// proofs.
   wasm:       Box<[u8]>,
   /// A new seed cannot change the selection or the analysis assumptions.
   config:     Config,
   /// Fresh reports retain the original indices and start with zero rewrite
   /// counts.
   catalog:    Vec<FunctionReport>,
   /// Arena IDs belong to one parse, so cached edges use input indices instead.
   uses:       Vec<(usize, Vec<usize>)>,
   /// These locations are byte offsets rather than arena IDs.
   addresses:  BTreeSet<InstrLocId>,
   /// Unknown effects must survive reuse or lazy staging becomes unsound.
   unresolved: Vec<(usize, InstrLocId, BTreeSet<AnalysisReason>)>,
   /// Startup reachability is independent of the rewrite seed.
   startup:    Vec<usize>,
}

impl Prepared {
   /// The input and all options except the per-rewrite seed remain fixed.
   ///
   /// # Errors
   ///
   /// Returns the same input and selection errors as [`crate::transform`].
   #[inline]
   pub fn new(wasm: Vec<u8>, config: Config) -> Result<Self, TransformError> {
      let Rewriter {
         module,
         functions,
         references,
         ..
      } = Rewriter::new(&wasm, &config, config.seed, None)?;
      let function_indices = module
         .funcs
         .iter()
         .enumerate()
         .map(|(index, function)| (function.id(), index))
         .collect::<BTreeMap<_, _>>();
      let data_indices = module
         .data
         .iter()
         .enumerate()
         .map(|(index, data)| (data.id(), index))
         .collect::<BTreeMap<_, _>>();
      let uses = references
         .functions
         .into_iter()
         .map(|(data, callers)| {
            (
               data_indices[&data],
               callers
                  .into_iter()
                  .map(|function| function_indices[&function])
                  .collect(),
            )
         })
         .collect();
      let unresolved = references
         .unresolved
         .into_iter()
         .map(|((function, location), reasons)| (function_indices[&function], location, reasons))
         .collect();
      let startup = references
         .startup
         .into_iter()
         .map(|function| function_indices[&function])
         .collect();

      Ok(Self {
         wasm: wasm.into_boxed_slice(),
         config,
         catalog: functions.into_values().collect(),
         uses,
         addresses: references.addresses,
         unresolved,
         startup,
      })
   }

   /// Semantic verification belongs to the caller's build-time workload.
   ///
   /// # Errors
   ///
   /// Returns rewrite or placement errors without producing a partial variant.
   #[inline]
   pub fn rewrite(&self, seed: u64) -> Result<(Vec<u8>, Report), TransformError> {
      Rewriter::new(&self.wasm, &self.config, seed, Some(self))?.run()
   }

   /// Reports are copied because each variant owns its counters.
   pub(crate) fn functions(&self, module: &Module) -> BTreeMap<FunctionId, FunctionReport> {
      let functions = module.funcs.iter().map(Function::id).collect::<Vec<_>>();
      self
         .catalog
         .iter()
         .map(|report| (functions[report.index], report.clone()))
         .collect()
   }

   /// Proofs are remapped only onto a fresh parse of this preparation's bytes.
   pub(crate) fn references(&self, module: &Module) -> References {
      let functions = module.funcs.iter().map(Function::id).collect::<Vec<_>>();
      let data = module.data.iter().map(Data::id).collect::<Vec<_>>();

      References {
         functions:  self
            .uses
            .iter()
            .map(|&(index, ref callers)| {
               (
                  data[index],
                  callers.iter().map(|caller| functions[*caller]).collect(),
               )
            })
            .collect(),
         addresses:  self.addresses.clone(),
         unresolved: self
            .unresolved
            .iter()
            .map(|&(function, location, ref reasons)| {
               ((functions[function], location), reasons.clone())
            })
            .collect(),
         startup:    self
            .startup
            .iter()
            .map(|function| functions[*function])
            .collect(),
      }
   }
}
