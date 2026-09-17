//! A post-link obfuscator for WebAssembly.
//!
//! vela rewrites compiled `.wasm` modules. Enabled passes run in this order.
//!
//! 1. Encrypt supported active data segments, with decryption at startup or
//!    first use.
//! 2. Replace selected direct calls with table dispatches.
//! 3. Flatten instruction sequences into `br_table` dispatch loops.
//! 4. Rewrite selected constants as arithmetic over mutable globals.
//! 5. Insert never-taken branches.
//!
//! The pool is initialized before decryption and the original start function.
//! Lazy staging delays decryption but leaves plaintext in memory afterward.
//! The module ships its decryption code and seeds, so this isn't a protection
//! boundary.
//!
//! Run vela after `wasm-opt`, which can simplify the added arithmetic.

/// Data segment locations and function references.
mod analysis;
/// Placement checks for shared imported memories and tables.
mod audit;
pub mod config;
/// Runtime decryption helpers and Wasm opcode conversions.
mod emit;
/// Arithmetic expressions built from marker globals.
mod mba;
mod passes;
/// Marker globals and their startup mixing code.
mod pool;
/// Proven memory uses by input instruction location.
mod references;
/// Seeded randomness and the segment encryption byte stream.
mod rng;
/// Input function selection and direct-call reachability.
mod selection;
/// Operand stack tracking for flattening cuts.
mod stack;
pub mod verify;
/// Each verifier instance consumes the same host script independently.
mod verify_host;
/// Aggregate resource accounting for verification.
mod verify_limits;
/// Typed messages exchanged with the verification process.
mod verify_wire;
pub mod worker;
/// Linux process limits and deadline-aware worker communication.
#[cfg(target_os = "linux")]
mod worker_process;

use std::{
   collections::{
      BTreeMap,
      HashSet,
   },
   error::Error as StdError,
};

use thiserror::Error;
use walrus::{
   FunctionId,
   Module,
   ir,
};

use crate::{
   analysis::Segment,
   config::{
      Config,
      FunctionReport,
      FunctionSelector,
      Report,
   },
   pool::Pool,
   references::solver::References,
   rng::Rng,
};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransformError {
   #[error("input module is too large to assign instruction locations")]
   InputTooLarge,
   #[error("function selector matched no local function {0}")]
   UnknownFunction(FunctionSelector),
   #[error("cannot prove callees of input function #{function}")]
   UnresolvedCallees { function: usize },
   #[error("parsing input module")]
   Parse(#[source] Box<dyn StdError + Send + Sync>),
   #[error("expected at most one memory, found {0}")]
   MultipleMemories(usize),
   #[error("64-bit memories are unsupported")]
   Memory64,
   #[error("reserving indirect call table entries")]
   Table(#[source] Box<dyn StdError + Send + Sync>),
   #[error("cannot prove active data segments have disjoint placements")]
   DataPlacement,
   #[error("data integrity requires data encryption and marker rewriting")]
   IntegrityPasses,
   #[error("data integrity requires encrypted bytes and at least one rewritten marker")]
   IntegrityCoverage,
   #[error("output violates placement rules\n{}", .0.join("\n"))]
   Placement(Vec<String>),
}

/// Runs every enabled pass over `wasm` in a fixed order and returns the
/// rewritten module bytes alongside a report of what each pass did.
///
/// # Errors
///
/// Returns an error for malformed wasm, unsupported memories, invalid table
/// reservations, placement faults, unmatched selectors or unresolved graph
/// reachability.
#[inline]
pub fn transform(wasm: &[u8], config: &Config) -> Result<(Vec<u8>, Report), TransformError> {
   Rewriter::new(wasm, config)?.run()
}

/// Shared state for one module rewrite.
struct Rewriter<'config> {
   /// Input function selection and counters retained across passes.
   functions:       BTreeMap<FunctionId, FunctionReport>,
   /// walrus uses input byte offsets for locations, leaving this value free for
   /// generated operands.
   dispatch_marker: ir::InstrLocId,
   /// Module being rewritten.
   module:          Module,
   /// Random stream shared by the enabled passes.
   rng:             Rng,
   /// Pass selection and rewrite parameters.
   config:          &'config Config,
   /// Marker globals and their values after startup mixing.
   pool:            Pool,
   /// Supported data segment locations captured before rewriting.
   segments:        Vec<Segment>,
   /// Proven memory uses captured before rewriting.
   references:      References,
   /// Runtime helpers excluded from call promotion and flattening.
   generated:       HashSet<FunctionId>,
   /// Counts collected by each pass.
   report:          Report,
}

impl<'config> Rewriter<'config> {
   /// Parses the input and prepares shared rewrite state.
   fn new(wasm: &[u8], config: &'config Config) -> Result<Self, TransformError> {
      if config.data_integrity && (!config.data_enc || !config.markers) {
         return Err(TransformError::IntegrityPasses);
      }

      let mut module =
         Module::from_buffer(wasm).map_err(|source| TransformError::Parse(source.into()))?;
      let memories = module.memories.iter().count();
      if memories > 1 {
         return Err(TransformError::MultipleMemories(memories));
      }
      if module.memories.iter().any(|memory| memory.memory64) {
         return Err(TransformError::Memory64);
      }

      let location = u32::try_from(wasm.len()).map_err(|_error| TransformError::InputTooLarge)?;
      if location == u32::MAX {
         return Err(TransformError::InputTooLarge);
      }
      let dispatch_marker = ir::InstrLocId::new(location);
      let functions = selection::resolve(&module, config)?;

      let mut rng = Rng::new(config.seed);
      let segments = analysis::segments(&module);
      if config.data_enc && !segments.is_empty() && !analysis::disjoint(&module) {
         return Err(TransformError::DataPlacement);
      }

      let references = References::analyze(&module, &segments);

      let pool = Pool::build(
         &mut module,
         &mut rng,
         config.pool_size,
         config.debug_names,
         config.evolve_pool,
      );

      Ok(Self {
         functions,
         dispatch_marker,
         module,
         rng,
         config,
         pool,
         segments,
         references,
         generated: HashSet::new(),
         report: Report::default(),
      })
   }

   /// Runs the enabled passes, checks placement and emits the module.
   fn run(mut self) -> Result<(Vec<u8>, Report), TransformError> {
      let eager = if self.config.data_enc {
         passes::data_enc::run(&mut self)
      } else {
         Vec::new()
      };
      self.initialize(eager);

      if self.config.indirect_calls {
         passes::indirect::run(&mut self)
            .map_err(|source| TransformError::Table(Box::new(source)))?;
      }

      // Run before markers so recorded locations also reach dispatch states,
      // and before opaque predicates so they can be inserted inside
      // dispatch regions.
      if self.config.flatten {
         passes::flatten::run(&mut self);
      }

      // The seed helper must remain untouched because it establishes the
      // values marker expressions use.
      if self.config.markers {
         passes::markers::run(&mut self);
      }

      if self.config.opaque {
         passes::opaque::run(&mut self);
      }

      if self.config.data_integrity
         && (self.report.bytes_integrity == 0 || self.report.markers_rewritten == 0)
      {
         return Err(TransformError::IntegrityCoverage);
      }

      let faults = audit::placement(&self.module);
      if !faults.is_empty() {
         return Err(TransformError::Placement(faults));
      }
      for (id, mut function) in self.functions {
         if let walrus::FunctionKind::Local(ref local) = self.module.funcs.get(id).kind {
            function.instructions_after = analysis::all_seqs(local)
               .iter()
               .map(|sequence| local.block(*sequence).instrs.len())
               .sum();
         }
         self.report.functions.push(function);
      }
      Ok((self.module.emit_wasm(), self.report))
   }

   /// Chains the pool seeding, the eager decrypts and whatever start function
   /// the module already had into a single entry point.
   fn initialize(&mut self, eager: Vec<ir::Instr>) {
      let previous = self.module.start.take();

      let mut builder = walrus::FunctionBuilder::new(&mut self.module.types, &[], &[]);
      if self.config.debug_names {
         builder.name("vela_init".to_owned());
      }

      let mut body = builder.func_body();
      body.instr(ir::Call {
         func: self.pool.seed_func(),
      });

      for instr in eager {
         body.instr(instr);
      }

      if let Some(start) = previous {
         body.instr(ir::Call { func: start });
      }

      let init = builder.finish(Vec::new(), &mut self.module.funcs);
      self.module.start = Some(init);
      self.generated.insert(init);
      self.generated.insert(self.pool.seed_func());
      self.generated.extend(self.pool.readers());
   }
}
