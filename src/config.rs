use std::{
   collections::{
      BTreeMap,
      BTreeSet,
   },
   fmt,
   num::ParseIntError,
   str::FromStr,
};

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParameterError {
   #[error("expected an unsigned integer")]
   Integer(#[source] ParseIntError),
   #[error("percentage must be between 0 and 100, got {0}")]
   Percentage(u32),
   #[error("marker depth must be between 0 and 64, got {0}")]
   MarkerDepth(u32),
   #[error("pool size must be at least 2, got {0}")]
   PoolSize(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Percentage(u32);

impl Percentage {
   #[inline]
   #[must_use]
   pub const fn get(self) -> u32 {
      self.0
   }
}

impl TryFrom<u32> for Percentage {
   type Error = ParameterError;

   #[inline]
   fn try_from(value: u32) -> Result<Self, Self::Error> {
      if value > 100 {
         return Err(ParameterError::Percentage(value));
      }
      Ok(Self(value))
   }
}

impl FromStr for Percentage {
   type Err = ParameterError;

   #[inline]
   fn from_str(value: &str) -> Result<Self, Self::Err> {
      Self::try_from(value.parse::<u32>().map_err(ParameterError::Integer)?)
   }
}

impl fmt::Display for Percentage {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      self.0.fmt(f)
   }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkerDepth(u32);

impl MarkerDepth {
   #[inline]
   #[must_use]
   pub const fn get(self) -> u32 {
      self.0
   }
}

impl TryFrom<u32> for MarkerDepth {
   type Error = ParameterError;

   #[inline]
   fn try_from(value: u32) -> Result<Self, Self::Error> {
      if value > 64 {
         return Err(ParameterError::MarkerDepth(value));
      }
      Ok(Self(value))
   }
}

impl FromStr for MarkerDepth {
   type Err = ParameterError;

   #[inline]
   fn from_str(value: &str) -> Result<Self, Self::Err> {
      Self::try_from(value.parse::<u32>().map_err(ParameterError::Integer)?)
   }
}

impl fmt::Display for MarkerDepth {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      self.0.fmt(f)
   }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSize(usize);

impl PoolSize {
   #[inline]
   #[must_use]
   pub const fn get(self) -> usize {
      self.0
   }
}

impl TryFrom<usize> for PoolSize {
   type Error = ParameterError;

   #[inline]
   fn try_from(value: usize) -> Result<Self, Self::Error> {
      if value < 2 {
         return Err(ParameterError::PoolSize(value));
      }
      Ok(Self(value))
   }
}

impl FromStr for PoolSize {
   type Err = ParameterError;

   #[inline]
   fn from_str(value: &str) -> Result<Self, Self::Err> {
      Self::try_from(value.parse::<usize>().map_err(ParameterError::Integer)?)
   }
}

impl fmt::Display for PoolSize {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      self.0.fmt(f)
   }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FunctionSelector {
   Name(String),
   Index(usize),
}

impl FromStr for FunctionSelector {
   type Err = ParseIntError;

   #[inline]
   fn from_str(value: &str) -> Result<Self, Self::Err> {
      value.strip_prefix('#').map_or_else(
         || Ok(Self::Name(value.to_owned())),
         |index| index.parse().map(Self::Index),
      )
   }
}

impl fmt::Display for FunctionSelector {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match *self {
         Self::Name(ref name) => f.write_str(name),
         Self::Index(index) => write!(f, "#{index}"),
      }
   }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CodePass {
   Indirect,
   Markers,
   Flatten,
   Opaque,
}

impl fmt::Display for CodePass {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match *self {
         Self::Indirect => "calls",
         Self::Markers => "markers",
         Self::Flatten => "flatten",
         Self::Opaque => "opaque",
      })
   }
}

/// Which passes run, and how hard they push.
#[derive(Debug, Clone)]
#[expect(
   clippy::struct_excessive_bools,
   reason = "each bool independently toggles one pass, a state machine would only obscure that"
)]
pub struct Config {
   /// Input functions selected by name, export or index, with an empty list
   /// selecting all.
   pub functions:         Vec<FunctionSelector>,
   /// Per-pass function lists. A present entry overrides the global list for
   /// that pass, an empty entry selects all functions and an absent entry
   /// inherits the global list.
   pub pass_functions:    BTreeMap<CodePass, Vec<FunctionSelector>>,
   /// Each code-pass root set expands through direct calls.
   pub include_callees:   bool,
   /// Roots and their reachable callees stay out of every code pass,
   /// including overrides.
   pub exclude_reachable: Vec<FunctionSelector>,
   pub seed:              u64,
   pub data_enc:          bool,
   pub integrity:         bool,
   /// Decrypt eligible segments on first use. Targets of pointers stored in
   /// data stay eager because the code scan can't tell when they'll be read.
   pub lazy:              bool,
   pub markers:           bool,
   pub evolve_pool:       bool,
   /// Recursion depth of each marker expression. Higher depths add more
   /// arithmetic and global reads, up to a depth of 64.
   pub marker_depth:      MarkerDepth,
   /// Size of the global pool the marker expressions draw from.
   pub pool_size:         PoolSize,
   /// Rewrite every i32 constant, not only data addresses and indirect call
   /// indices.
   pub markers_all:       bool,
   pub indirect_calls:    bool,
   /// Percentage of eligible direct calls promoted to `call_indirect`.
   pub indirect_ratio:    Percentage,
   pub opaque:            bool,
   pub opaque_ratio:      Percentage,
   /// Rewrite instruction sequences as `br_table` dispatch loops.
   pub flatten:           bool,
   pub evolve_dispatch:   bool,
   /// Percentage of eligible sequences flattened.
   pub flatten_ratio:     Percentage,
   /// Upper bound on regions a single sequence is cut into.
   pub max_regions:       usize,
   /// Name generated functions for debugging. Disabled by default because names
   /// such as `vela_decrypt` identify the runtime helpers in the binary.
   pub debug_names:       bool,
}

impl Default for Config {
   #[inline]
   fn default() -> Self {
      Self {
         functions:         Vec::new(),
         pass_functions:    BTreeMap::new(),
         include_callees:   false,
         exclude_reachable: Vec::new(),
         seed:              0,
         data_enc:          true,
         integrity:         false,
         lazy:              true,
         markers:           true,
         evolve_pool:       false,
         marker_depth:      MarkerDepth(2),
         pool_size:         PoolSize(8),
         markers_all:       false,
         indirect_calls:    true,
         indirect_ratio:    Percentage(60),
         opaque:            false,
         opaque_ratio:      Percentage(20),
         flatten:           false,
         evolve_dispatch:   false,
         flatten_ratio:     Percentage(70),
         max_regions:       6,
         debug_names:       false,
      }
   }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum FlattenRejection {
   BlockSignature,
   MultipleResults,
   UnsupportedInstruction,
   NonFinalTerminator,
   StackMismatch,
   NoCuts,
}

impl fmt::Display for FlattenRejection {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match *self {
         Self::BlockSignature => "block signature",
         Self::MultipleResults => "multiple results",
         Self::UnsupportedInstruction => "unsupported instruction",
         Self::NonFinalTerminator => "code after terminator",
         Self::StackMismatch => "stack mismatch",
         Self::NoCuts => "no empty-stack cuts",
      })
   }
}

#[derive(Debug, Clone)]
pub struct FunctionReport {
   pub index:                      usize,
   pub name:                       Option<String>,
   pub exports:                    Vec<String>,
   pub passes:                     BTreeSet<CodePass>,
   pub instructions_before:        usize,
   pub instructions_after:         usize,
   pub calls_promoted:             usize,
   pub markers_rewritten:          usize,
   pub dispatch_markers_rewritten: usize,
   pub seqs_flattened:             usize,
   pub seqs_evolving:              usize,
   pub flatten_regions:            usize,
   pub flatten_refusals:           BTreeMap<FlattenRejection, usize>,
   pub opaque_inserted:            usize,
}

impl fmt::Display for FunctionReport {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(
         f,
         "#{} {}",
         self.index,
         self.name.as_deref().unwrap_or("<unnamed>")
      )?;
      if !self.exports.is_empty() {
         write!(f, " [{}]", self.exports.join(", "))?;
      }
      write!(
         f,
         " instructions {} -> {}",
         self.instructions_before, self.instructions_after
      )?;
      if self.passes.is_empty() {
         return f.write_str(" excluded");
      }
      let selected = self
         .passes
         .iter()
         .map(ToString::to_string)
         .collect::<Vec<_>>()
         .join(", ");
      write!(
         f,
         " selected {selected}, calls {}, markers {} ({} dispatch), flattened {} ({} evolving) \
          into {} regions, opaque {}",
         self.calls_promoted,
         self.markers_rewritten,
         self.dispatch_markers_rewritten,
         self.seqs_flattened,
         self.seqs_evolving,
         self.flatten_regions,
         self.opaque_inserted
      )?;
      for (reason, count) in &self.flatten_refusals {
         write!(f, ", {reason} {count}")?;
      }
      Ok(())
   }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum AnalysisReason {
   Argument,
   ReturnValue,
   GlobalValue,
   MemoryValue,
   UnsupportedInstruction,
   ImportedCall,
   DynamicCall,
   BranchMerge,
   LoopValue,
   ValueLimit,
   ContextLimit,
   AnalysisLimit,
   UnknownLength,
}

impl fmt::Display for AnalysisReason {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match *self {
         Self::Argument => "unknown argument",
         Self::ReturnValue => "unknown return value",
         Self::GlobalValue => "unknown global",
         Self::MemoryValue => "value loaded from memory",
         Self::UnsupportedInstruction => "unsupported instruction",
         Self::ImportedCall => "imported call",
         Self::DynamicCall => "dynamic call",
         Self::BranchMerge => "branch merge",
         Self::LoopValue => "changing loop value",
         Self::ValueLimit => "value set limit",
         Self::ContextLimit => "call context limit",
         Self::AnalysisLimit => "analysis work limit",
         Self::UnknownLength => "unknown access length",
      })
   }
}

#[derive(Debug)]
pub struct UnresolvedUse {
   pub function:    usize,
   pub instruction: Option<u32>,
   pub reasons:     BTreeSet<AnalysisReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EagerReason {
   Requested,
   UnresolvedMemory,
   Relocatable,
   DataPointer,
   Unreferenced,
}

impl fmt::Display for EagerReason {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match *self {
         Self::Requested => "eager requested",
         Self::UnresolvedMemory => "unresolved memory use",
         Self::Relocatable => "relocatable placement",
         Self::DataPointer => "pointer stored in data",
         Self::Unreferenced => "no proven reference",
      })
   }
}

#[derive(Debug)]
pub struct SegmentReport {
   pub index:               usize,
   pub bytes:               usize,
   pub functions:           Vec<usize>,
   pub eager_reasons:       BTreeSet<EagerReason>,
   pub startup_may_decrypt: bool,
}

impl fmt::Display for UnresolvedUse {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "unresolved #{}", self.function)?;

      if let Some(location) = self.instruction {
         write!(f, " at {location:#x}")?;
      }

      for reason in &self.reasons {
         write!(f, ", {reason}")?;
      }

      Ok(())
   }
}

impl fmt::Display for SegmentReport {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      let staging = if self.eager_reasons.is_empty() {
         "lazy"
      } else {
         "eager"
      };
      write!(f, "segment #{} {} bytes, {staging}", self.index, self.bytes)?;

      for reason in &self.eager_reasons {
         write!(f, ", {reason}")?;
      }

      if !self.functions.is_empty() {
         f.write_str(", functions")?;

         for function in &self.functions {
            write!(f, " #{function}")?;
         }
      }

      if self.startup_may_decrypt {
         f.write_str(", may decrypt during startup")?;
      }

      Ok(())
   }
}

/// What each pass did, so the CLI can report something more useful than "done".
#[derive(Debug, Default)]
pub struct Report {
   pub functions:                  Vec<FunctionReport>,
   pub segments:                   Vec<SegmentReport>,
   pub unresolved:                 Vec<UnresolvedUse>,
   pub segments_total:             usize,
   pub segments_encrypted:         usize,
   pub segments_lazy:              usize,
   pub segments_forced_eager:      usize,
   pub unresolved_memory_uses:     usize,
   pub bytes_encrypted:            usize,
   pub bytes_integrity:            usize,
   pub globals_integrity:          usize,
   pub globals_total:              usize,
   pub bytes_eager:                usize,
   pub bytes_lazy:                 usize,
   pub bytes_startup_upper_bound:  usize,
   pub markers_rewritten:          usize,
   pub dispatch_markers_rewritten: usize,
   pub markers_skipped:            usize,
   pub calls_promoted:             usize,
   pub opaque_inserted:            usize,
   pub seqs_flattened:             usize,
   pub seqs_evolving:              usize,
   pub flatten_regions:            usize,
   pub seqs_unflattenable:         usize,
   pub pool_size:                  usize,
}

impl fmt::Display for Report {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      writeln!(
         f,
         "data      {}/{} segments encrypted, {} bytes",
         self.segments_encrypted, self.segments_total, self.bytes_encrypted
      )?;
      writeln!(
         f,
         "staging   {} lazy, {} forced eager, {} unresolved memory uses",
         self.segments_lazy, self.segments_forced_eager, self.unresolved_memory_uses
      )?;

      if self.bytes_integrity != 0 || self.globals_integrity != 0 {
         writeln!(
            f,
            "integrity {} encrypted bytes and {}/{} initial globals folded into markers",
            self.bytes_integrity, self.globals_integrity, self.globals_total
         )?;
      }

      writeln!(
         f,
         "bytes     {} lazy, {} eager, {} startup upper bound",
         self.bytes_lazy, self.bytes_eager, self.bytes_startup_upper_bound
      )?;
      writeln!(
         f,
         "markers   {} constants rewritten ({} dispatch) over a pool of {}, {} left alone",
         self.markers_rewritten,
         self.dispatch_markers_rewritten,
         self.pool_size,
         self.markers_skipped
      )?;
      writeln!(
         f,
         "calls     {} direct calls promoted to indirect",
         self.calls_promoted
      )?;
      writeln!(
         f,
         "opaque    {} bogus branches inserted",
         self.opaque_inserted
      )?;
      write!(
         f,
         "flatten   {} sequences into {} dispatch regions, {} evolving, {} not safely splittable",
         self.seqs_flattened, self.flatten_regions, self.seqs_evolving, self.seqs_unflattenable
      )
   }
}
