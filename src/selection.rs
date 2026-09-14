use std::collections::{
   BTreeMap,
   BTreeSet,
};

use walrus::{
   FunctionId,
   ir,
};

use crate::{
   TransformError,
   analysis,
   config,
   config::{
      CodePass,
      FunctionReport,
      FunctionSelector,
   },
};

/// Selection uses input identities before rewriting adds helper functions.
pub fn resolve(
   module: &walrus::Module,
   config: &config::Config,
) -> Result<BTreeMap<FunctionId, FunctionReport>, TransformError> {
   let mut functions = catalog(module);
   for selectors in config
      .pass_functions
      .values()
      .chain([&config.functions, &config.exclude_reachable])
   {
      roots(&functions, selectors)?;
   }
   let excluded = if config.exclude_reachable.is_empty() {
      BTreeSet::new()
   } else {
      reachable(module, roots(&functions, &config.exclude_reachable)?)?
   };
   for (pass, enabled) in [
      (CodePass::Indirect, config.indirect_calls),
      (CodePass::Markers, config.markers),
      (CodePass::Flatten, config.flatten),
      (CodePass::Opaque, config.opaque),
   ] {
      if !enabled {
         continue;
      }
      let selectors = config
         .pass_functions
         .get(&pass)
         .unwrap_or(&config.functions);
      let selected = roots(&functions, selectors)?;
      let expanded = if config.include_callees {
         reachable(module, selected)?
      } else {
         selected
      };
      for (id, report) in &mut functions {
         if expanded.contains(id) && !excluded.contains(id) {
            report.passes.insert(pass);
         }
      }
   }
   Ok(functions)
}

/// Reports retain original indices even when a function is excluded.
fn catalog(module: &walrus::Module) -> BTreeMap<FunctionId, FunctionReport> {
   module.funcs.iter().enumerate().filter_map(|(index, function)| {
      let walrus::FunctionKind::Local(ref local) = function.kind else {
         return None;
      };
      let exports = module.exports.iter()
         .filter(|export| matches!(export.item, walrus::ExportItem::Function(id) if id == function.id()))
         .map(|export| export.name.clone()).collect();
      let instructions_before = analysis::all_seqs(local).iter()
         .map(|sequence| local.block(*sequence).instrs.len()).sum();
      Some((function.id(), FunctionReport {
         index,
         name: function.name.clone(),
         exports,
         passes: BTreeSet::new(),
         instructions_before,
         instructions_after: instructions_before,
         calls_promoted: 0,
         markers_rewritten: 0,
         dispatch_markers_rewritten: 0,
         seqs_flattened: 0,
         flatten_regions: 0,
         flatten_refusals: BTreeMap::new(),
         opaque_inserted: 0,
      }))
   }).collect()
}

/// Explicit selectors must resolve even when their pass is disabled.
fn roots(
   functions: &BTreeMap<FunctionId, FunctionReport>,
   selectors: &[FunctionSelector],
) -> Result<BTreeSet<FunctionId>, TransformError> {
   if selectors.is_empty() {
      return Ok(functions.keys().copied().collect());
   }
   let mut selected = BTreeSet::new();
   for selector in selectors {
      let mut matched = false;
      for (id, function) in functions {
         let applies = match *selector {
            FunctionSelector::Name(ref name) => {
               function.name.as_ref() == Some(name) || function.exports.contains(name)
            },
            FunctionSelector::Index(index) => function.index == index,
         };
         if applies {
            selected.insert(*id);
            matched = true;
         }
      }
      if !matched {
         return Err(TransformError::UnknownFunction(selector.clone()));
      }
   }
   Ok(selected)
}

/// Dynamic calls and host callbacks prevent a complete local reachability
/// proof.
#[expect(
   clippy::wildcard_enum_match_arm,
   reason = "only call instructions add graph edges"
)]
#[expect(
   clippy::expect_used,
   reason = "every traversed id belongs to this module"
)]
fn reachable(
   module: &walrus::Module,
   roots: BTreeSet<FunctionId>,
) -> Result<BTreeSet<FunctionId>, TransformError> {
   let mut pending = roots.into_iter().collect::<Vec<_>>();
   let mut visited = BTreeSet::new();
   while let Some(id) = pending.pop() {
      if !visited.insert(id) {
         continue;
      }
      let unresolved = || {
         TransformError::UnresolvedCallees {
            function: module
               .funcs
               .iter()
               .position(|function| function.id() == id)
               .expect("function belongs to the module"),
         }
      };
      let walrus::FunctionKind::Local(ref local) = module.funcs.get(id).kind else {
         return Err(unresolved());
      };
      for sequence in analysis::all_seqs(local) {
         for instruction in &local.block(sequence).instrs {
            match instruction.0 {
               ir::Instr::Call(ir::Call { func })
               | ir::Instr::ReturnCall(ir::ReturnCall { func }) => pending.push(func),
               ir::Instr::CallIndirect(_)
               | ir::Instr::ReturnCallIndirect(_)
               | ir::Instr::CallRef(_)
               | ir::Instr::ReturnCallRef(_) => return Err(unresolved()),
               _ => {},
            }
         }
      }
   }
   Ok(visited)
}
