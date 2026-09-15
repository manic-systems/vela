use std::collections::{
   BTreeMap,
   BTreeSet,
};

use walrus::{
   ConstExpr,
   ConstOp,
   DataId,
   ElementItems,
   ExportItem,
   FunctionId,
   FunctionKind,
   GlobalKind,
   Module,
   ir::{
      InstrLocId,
      RefFunc,
      Visitor,
      dfs_in_order,
   },
};

use crate::{
   analysis::{
      self,
      Segment,
   },
   config::AnalysisReason,
   references::{
      flow::{
         Flow,
         Scan,
      },
      value::{
         Values,
         Word,
      },
   },
};

/// Extra call shapes share an unknown-argument summary instead of growing the
/// cache.
const CONTEXT_LIMIT: usize = 16;
/// Exhaustion must disable lazy staging even if an unfinished summary looks
/// precise.
const WORK_LIMIT: usize = 1_000_000;

/// Memory uses proven across control flow and direct calls.
#[derive(Default)]
pub struct References {
   /// Functions requiring each segment before entry.
   pub functions:  BTreeMap<DataId, BTreeSet<FunctionId>>,
   /// Input constants contributing to a resolved data address.
   pub addresses:  BTreeSet<InstrLocId>,
   /// Memory effects whose possible aliases require eager decryption.
   pub unresolved: BTreeMap<(FunctionId, InstrLocId), BTreeSet<AnalysisReason>>,
   /// Wasm start can invoke lazy gates before the host receives the instance.
   pub startup:    BTreeSet<FunctionId>,
}

impl References {
   /// Resolves memory operands before encryption or inserted runtime code.
   #[inline]
   pub fn analyze(module: &Module, segments: &[Segment]) -> Self {
      Solver::new(module, segments).solve()
   }

   /// Repeated worklist visits must not count the same memory use twice.
   pub fn issue(&mut self, site: (FunctionId, InstrLocId), reason: AnalysisReason) {
      self.unresolved.entry(site).or_default().insert(reason);
   }

   /// Effects from every reachable call context constrain the same emitted
   /// function.
   pub fn extend(&mut self, incoming: Self) {
      for (segment, functions) in incoming.functions {
         self.functions.entry(segment).or_default().extend(functions);
      }

      self.addresses.extend(incoming.addresses);

      for (site, reasons) in incoming.unresolved {
         self.unresolved.entry(site).or_default().extend(reasons);
      }

      self.startup.extend(incoming.startup);
   }

   /// Wide accesses can cross segment boundaries even when their base lies
   /// outside either one.
   pub fn access(
      &mut self,
      segments: &[Segment],
      site: (FunctionId, InstrLocId),
      address: &Word,
      offset: u64,
      length: &Word,
   ) {
      if matches!(&length.values, Values::Known(sizes) if sizes.iter().all(|size| *size == 0)) {
         return;
      }

      let (Some(addresses), Some(lengths)) = (address.known(), length.known()) else {
         let reasons = self.unresolved.entry(site).or_default();

         if let Values::Unknown(ref unknown) = address.values {
            reasons.extend(unknown);
         }

         if let Values::Unknown(ref unknown) = length.values {
            reasons.extend(unknown);
            reasons.insert(AnalysisReason::UnknownLength);
         }

         return;
      };

      for location in addresses {
         let Some(start) = u64::from(*location).checked_add(offset) else {
            self.issue(site, AnalysisReason::UnsupportedInstruction);
            continue;
         };

         for size in lengths.iter().filter(|size| **size != 0) {
            let end = start.saturating_add(u64::from(*size));

            for segment in segments {
               let Some(origin) = segment.start() else {
                  continue;
               };

               let base = u64::from(origin.cast_unsigned());
               let Ok(extent) = u64::try_from(segment.len) else {
                  self.issue(site, AnalysisReason::UnsupportedInstruction);
                  continue;
               };

               if start < base.saturating_add(extent) && base < end {
                  self.functions.entry(segment.id).or_default().insert(site.0);

                  if let Some(ref origins) = address.origins {
                     self.addresses.extend(origins);
                  }
               }
            }
         }
      }
   }

   /// Pointer arguments and returned addresses need gates before they leave
   /// their defining function.
   pub fn escape(&mut self, segments: &[Segment], site: (FunctionId, InstrLocId), word: &Word) {
      self.access(segments, site, word, 0, &Word::constant(1, None));
   }
}

/// Analysis specialization never creates a second emitted function.
pub struct Context {
   /// The original identity also owns the eventual decryption gates.
   pub function:   FunctionId,
   /// Equal numeric inputs share provenance from every caller.
   pub arguments:  Vec<Word>,
   /// Absence means no returning path has been established yet, not an unknown
   /// result.
   pub returned:   Option<Vec<Word>>,
   /// Callee changes invalidate these contexts even across recursive edges.
   pub callers:    BTreeSet<usize>,
   /// Effects accumulate monotonically while return summaries converge.
   pub references: References,
   /// Ordinary exports may share a context with the original start function.
   pub startup:    bool,
}

/// Deferred registration keeps a scan on one consistent summary snapshot.
pub struct CallInput {
   /// Imported targets never enter the local summary cache.
   pub function:  FunctionId,
   /// Operand order follows the Wasm signature, not stack pop order.
   pub arguments: Vec<Word>,
}

/// All summaries belong to one immutable input module and one rewrite.
pub struct Solver<'module> {
   /// Runtime helpers must not participate in proofs about input code.
   pub module:      &'module Module,
   /// These placements describe plaintext before encryption mutates data.
   pub segments:    &'module [Segment],
   /// Indices remain stable while recursion adds more contexts.
   pub contexts:    Vec<Context>,
   /// Control signatures are shared across argument specializations.
   pub flows:       BTreeMap<FunctionId, Flow>,
   /// The last slot beyond the specialization limit is the conservative
   /// fallback.
   pub by_function: BTreeMap<FunctionId, Vec<usize>>,
   /// Stable ordering makes budget exhaustion independent of hash
   /// randomization.
   pub pending:     BTreeSet<usize>,
   /// Entry imports can have effects without any local instruction location.
   pub references:  References,
   /// Recursive reevaluation shares the same budget as first visits.
   pub remaining:   usize,
}

impl<'module> Solver<'module> {
   /// Hosts can supply arbitrary arguments to exports and escaped function
   /// references.
   fn new(module: &'module Module, segments: &'module [Segment]) -> Self {
      let mut solver = Self {
         module,
         segments,
         contexts: Vec::new(),
         flows: analysis::local_func_ids(module)
            .into_iter()
            .map(|function| {
               (
                  function,
                  Flow::new(module, module.funcs.get(function).kind.unwrap_local()),
               )
            })
            .collect(),
         by_function: BTreeMap::new(),
         pending: BTreeSet::new(),
         references: References::default(),
         remaining: WORK_LIMIT,
      };

      for function in roots(module) {
         let signature = module.types.get(module.funcs.get(function).ty());
         let arguments = signature
            .params()
            .iter()
            .map(|_kind| Word::unknown(AnalysisReason::Argument))
            .collect();
         solver.register(
            CallInput {
               function,
               arguments,
            },
            None,
            module.start == Some(function),
         );
      }

      solver
   }

   /// Provenance is excluded from identity so equal values do not multiply
   /// contexts.
   pub fn lookup(&self, function: FunctionId, arguments: &[Word]) -> Option<usize> {
      let candidates = self.by_function.get(&function)?;

      candidates
         .iter()
         .copied()
         .find(|index| {
            self.contexts[*index]
               .arguments
               .iter()
               .zip(arguments)
               .all(|(existing, incoming)| existing.known() == incoming.known())
         })
         .or_else(|| (candidates.len() > CONTEXT_LIMIT).then(|| candidates[CONTEXT_LIMIT]))
   }

   /// A capped function still needs one summary covering every discarded
   /// argument shape.
   fn register(&mut self, mut input: CallInput, caller: Option<usize>, startup: bool) {
      if !matches!(
         self.module.funcs.get(input.function).kind,
         FunctionKind::Local(_)
      ) {
         self.references.issue(
            (input.function, InstrLocId::default()),
            AnalysisReason::ImportedCall,
         );
         return;
      }

      let existing = self.lookup(input.function, &input.arguments);

      if self
         .by_function
         .get(&input.function)
         .is_some_and(|indices| indices.len() >= CONTEXT_LIMIT)
         && existing.is_none_or(|index| {
            self.by_function[&input.function].get(CONTEXT_LIMIT) == Some(&index)
         })
      {
         input
            .arguments
            .fill(Word::unknown(AnalysisReason::ContextLimit));
      }

      let index = if let Some(index) = existing {
         let context = &mut self.contexts[index];
         let mut changed = false;

         for (target, incoming) in context.arguments.iter_mut().zip(&input.arguments) {
            changed |= target.join(incoming, AnalysisReason::BranchMerge);
         }

         if startup && !context.startup {
            context.startup = true;
            changed = true;
         }

         if changed {
            self.pending.insert(index);
         }

         index
      } else {
         let index = self.contexts.len();
         self.contexts.push(Context {
            function: input.function,
            arguments: input.arguments,
            returned: None,
            callers: BTreeSet::new(),
            references: References::default(),
            startup,
         });
         self
            .by_function
            .entry(input.function)
            .or_default()
            .push(index);
         self.pending.insert(index);
         index
      };

      if let Some(parent) = caller {
         let context = &mut self.contexts[index];

         if context.callers.insert(parent) && context.returned.is_some() {
            self.pending.insert(parent);
         }
      }
   }

   /// Unfinished calls suspend their continuation until a returning path
   /// becomes known.
   fn solve(mut self) -> References {
      while let Some(index) = self.pending.pop_first() {
         let scanned = Scan::run(&self, index, self.remaining);
         self.remaining = scanned.remaining;
         let context = &mut self.contexts[index];
         context.references.extend(scanned.references);
         let mut changed = false;

         if let Some(values) = scanned.returned {
            if let Some(ref mut prior) = context.returned {
               for (target, incoming) in prior.iter_mut().zip(&values) {
                  changed |= target.join(incoming, AnalysisReason::ReturnValue);
               }
            } else {
               context.returned = Some(values);
               changed = true;
            }
         }

         if changed {
            self.pending.extend(&context.callers);
         }

         let startup = context.startup;

         for input in scanned.calls {
            self.register(input, Some(index), startup);
         }

         if self.remaining == 0 {
            self.references.issue(
               (self.contexts[index].function, InstrLocId::default()),
               AnalysisReason::AnalysisLimit,
            );
            break;
         }
      }

      for context in self.contexts {
         if context.startup {
            self.references.startup.insert(context.function);
         }

         self.references.extend(context.references);
      }

      self.references
   }
}

/// Walrus can encode function references in instructions and constant
/// expressions.
fn roots(module: &Module) -> BTreeSet<FunctionId> {
   /// References can escape through tables, globals, or host calls.
   struct Escaped<'roots>(&'roots mut BTreeSet<FunctionId>);

   impl Visitor<'_> for Escaped<'_> {
      fn visit_ref_func(&mut self, instr: &RefFunc) {
         self.0.insert(instr.func);
      }
   }

   let mut roots = module
      .exports
      .iter()
      .filter_map(|export| {
         if let ExportItem::Function(function) = export.item {
            Some(function)
         } else {
            None
         }
      })
      .collect::<BTreeSet<_>>();
   roots.extend(module.start);

   for element in module.elements.iter() {
      match element.items {
         ElementItems::Functions(ref functions) => roots.extend(functions),
         ElementItems::Expressions(_, ref expressions) => {
            for expression in expressions {
               referenced_functions(expression, &mut roots);
            }
         },
      }
   }

   for global in module.globals.iter() {
      if let GlobalKind::Local(ref expression) = global.kind {
         referenced_functions(expression, &mut roots);
      }
   }

   for table in module.tables.iter() {
      if let Some(ref expression) = table.init {
         referenced_functions(expression, &mut roots);
      }
   }

   for function in analysis::local_func_ids(module) {
      let local = module.funcs.get(function).kind.unwrap_local();
      dfs_in_order(&mut Escaped(&mut roots), local, local.entry_block());
   }

   roots
}

/// Extended constant expressions may hide references inside GC initializers.
fn referenced_functions(expression: &ConstExpr, roots: &mut BTreeSet<FunctionId>) {
   match *expression {
      ConstExpr::RefFunc(function) => {
         roots.insert(function);
      },
      ConstExpr::Extended(ref operations) => {
         for operation in operations {
            if let ConstOp::RefFunc(function) = *operation {
               roots.insert(function);
            }
         }
      },
      ConstExpr::Value(_) | ConstExpr::Global(_) | ConstExpr::RefNull(_) => {},
   }
}
