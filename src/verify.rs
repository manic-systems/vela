use std::{
   collections::BTreeMap,
   error::Error as StdError,
   fmt,
};

use serde::{
   Deserialize,
   Serialize,
};
use thiserror::Error;
use wasmi::{
   Nullable,
   TrapCode,
   Val,
   ValType,
   errors,
};

use crate::verify_host::HostState;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ModuleSide {
   Original,
   Rewritten,
}

impl fmt::Display for ModuleSide {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match *self {
         Self::Original => "original",
         Self::Rewritten => "rewritten",
      })
   }
}

#[derive(Debug, Error)]
#[non_exhaustive]
#[expect(clippy::error_impl_error, reason = "it's never imported directly")]
pub enum Error {
   #[error("{side} module exceeded its verification budget for {resource}")]
   LimitExceeded {
      side:     ModuleSide,
      resource: Resource,
   },
   #[error("parsing {side} module for verification")]
   Parse {
      side:   ModuleSide,
      #[source]
      source: wasmi::Error,
   },
   #[error("instantiating {side} module for verification")]
   Instantiate {
      side:   ModuleSide,
      #[source]
      source: wasmi::Error,
   },
   #[error("preparing host import {name} for {side} module")]
   Import {
      side:   ModuleSide,
      name:   String,
      #[source]
      source: Box<dyn StdError + Send + Sync>,
   },
   #[error("zero-argument exports differ, missing {missing:?}, added {added:?}")]
   ExportSet {
      missing: Vec<String>,
      added:   Vec<String>,
   },
   #[error("no zero-argument exports to compare")]
   NoExports,
   #[error("verification is inconclusive because every compared call trapped")]
   AllTrapped,
   #[error("checking the host script for {side} module")]
   HostScript {
      side:   ModuleSide,
      #[source]
      source: wasmi::Error,
   },
   #[error("scenario contains no calls or nonempty memory reads")]
   EmptyScenario,
   #[error("memory export {name} is unavailable in {side} module")]
   MissingMemory { side: ModuleSide, name: String },
   #[error("accessing memory {name} in {side} module")]
   MemoryAccess {
      side:   ModuleSide,
      name:   String,
      #[source]
      source: errors::MemoryError,
   },
   #[error("export {name} is unavailable in {side} module")]
   MissingExport { side: ModuleSide, name: String },
   #[error("calling export {name} in {side} module")]
   Call {
      side:   ModuleSide,
      name:   String,
      #[source]
      source: wasmi::Error,
   },
   #[error("comparing results of export {name} in {side} module")]
   UnsupportedResult {
      side:   ModuleSide,
      name:   String,
      #[source]
      source: UnsupportedValue,
   },
}

#[derive(Debug, Error)]
#[error("cannot compare non-null {0:?} values across instances")]
pub struct UnsupportedValue(ValType);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Value {
   I32(i32),
   I64(i64),
   F32(u32),
   F64(u64),
   V128(u128),
   NullFuncRef,
   NullExternRef,
}

impl From<&Value> for Val {
   #[inline]
   fn from(value: &Value) -> Self {
      match *value {
         Value::I32(inner) => Self::I32(inner),
         Value::I64(inner) => Self::I64(inner),
         Value::F32(bits) => Self::F32(f32::from_bits(bits).into()),
         Value::F64(bits) => Self::F64(f64::from_bits(bits).into()),
         Value::V128(inner) => Self::V128(inner.into()),
         Value::NullFuncRef => Self::FuncRef(Nullable::Null),
         Value::NullExternRef => Self::ExternRef(Nullable::Null),
      }
   }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
   /// Fuel is shared by initialization and every call in one module's run.
   pub fuel:           u64,
   /// Linear memory allocations share this byte budget within each module.
   pub memory_bytes:   usize,
   /// Tables share this element budget within each module.
   pub table_elements: usize,
   /// Captured memory reads share this byte budget within each module.
   pub read_bytes:     usize,
}

impl Default for Limits {
   #[inline]
   fn default() -> Self {
      Self {
         fuel:           100_000_000,
         memory_bytes:   64 * 1024 * 1024,
         table_elements: 1_000_000,
         read_bytes:     16 * 1024 * 1024,
      }
   }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Resource {
   Fuel,
   Memory,
   Tables,
   Reads,
   ProcessMemory,
}

impl fmt::Display for Resource {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match *self {
         Self::Fuel => "fuel",
         Self::Memory => "linear memory",
         Self::Tables => "table elements",
         Self::Reads => "captured memory bytes",
         Self::ProcessMemory => "process memory",
      })
   }
}

/// Import scripts cover initialization and every call in one verification
/// workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportCall {
   pub module:    String,
   pub name:      String,
   pub arguments: Vec<Value>,
   pub results:   Vec<Value>,
   pub memory:    Vec<ImportMemory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ImportMemory {
   Read {
      name:     String,
      offset:   usize,
      expected: Vec<u8>,
   },
   Write {
      name:   String,
      offset: usize,
      bytes:  Vec<u8>,
   },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HostImports {
   #[default]
   Zero,
   Script(Vec<ImportCall>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
   pub memory_base: i32,
   pub table_base:  i32,
   pub limits:      Limits,
   pub imports:     HostImports,
}

impl Default for HostConfig {
   #[inline]
   fn default() -> Self {
      Self {
         memory_base: IMPORT_BASE,
         table_base:  IMPORT_BASE,
         limits:      Limits::default(),
         imports:     HostImports::Zero,
      }
   }
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Action {
   Call {
      name:      String,
      arguments: Vec<Value>,
   },
   WriteMemory {
      name:   String,
      offset: usize,
      bytes:  Vec<u8>,
   },
   ReadMemory {
      name:   String,
      offset: usize,
      len:    usize,
   },
}

impl TryFrom<&Val> for Value {
   type Error = UnsupportedValue;

   #[inline]
   fn try_from(value: &Val) -> Result<Self, Self::Error> {
      Ok(match *value {
         Val::I32(inner) => Self::I32(inner),
         Val::I64(inner) => Self::I64(inner),
         Val::F32(inner) => Self::F32(inner.to_bits()),
         Val::F64(inner) => Self::F64(inner.to_bits()),
         Val::V128(inner) => Self::V128(inner.as_u128()),
         Val::FuncRef(Nullable::Null) => Self::NullFuncRef,
         Val::ExternRef(Nullable::Null) => Self::NullExternRef,
         Val::FuncRef(Nullable::Val(_)) => {
            return Err(UnsupportedValue(ValType::FuncRef));
         },
         Val::ExternRef(Nullable::Val(_)) => {
            return Err(UnsupportedValue(ValType::ExternRef));
         },
      })
   }
}

impl fmt::Display for Value {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match *self {
         Self::I32(value) => write!(f, "i32({value})"),
         Self::I64(value) => write!(f, "i64({value})"),
         Self::F32(bits) => write!(f, "f32({bits:#010x})"),
         Self::F64(bits) => write!(f, "f64({bits:#018x})"),
         Self::V128(bits) => write!(f, "v128({bits:#034x})"),
         Self::NullFuncRef => f.write_str("null funcref"),
         Self::NullExternRef => f.write_str("null externref"),
      }
   }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CallOutcome {
   Returned(Vec<Value>),
   Trapped(
      #[serde(
         serialize_with = "crate::verify_wire::serialize_trap",
         deserialize_with = "crate::verify_wire::deserialize_trap"
      )]
      TrapCode,
   ),
}

impl fmt::Display for CallOutcome {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match *self {
         Self::Returned(ref values) => {
            f.write_str("(")?;
            for (index, value) in values.iter().enumerate() {
               if index != 0 {
                  f.write_str(", ")?;
               }
               value.fmt(f)?;
            }
            f.write_str(")")
         },
         Self::Trapped(kind) => write!(f, "trapped with {kind}"),
      }
   }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDigest {
   /// FNV-1a hash of the memory bytes.
   hash: u64,
   /// Number of bytes hashed.
   len:  usize,
}

impl fmt::Display for MemoryDigest {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "{:016x} over {} bytes", self.hash, self.len)
   }
}

/// One observable compared between the original and the rewritten module.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Comparison {
   Export {
      name:   String,
      before: CallOutcome,
      after:  CallOutcome,
   },
   Bytes {
      name:   String,
      offset: usize,
      before: Vec<u8>,
      after:  Vec<u8>,
   },
   /// Memory differences are advisory because unused segments can remain
   /// encrypted under lazy staging.
   Memory {
      before: Option<MemoryDigest>,
      after:  Option<MemoryDigest>,
   },
}

impl Comparison {
   #[must_use]
   #[inline]
   pub fn agrees(&self) -> bool {
      match *self {
         Self::Export {
            ref before,
            ref after,
            ..
         } => before == after,
         Self::Memory {
            ref before,
            ref after,
         } => before == after,
         Self::Bytes {
            ref before,
            ref after,
            ..
         } => before == after,
      }
   }

   #[must_use]
   #[inline]
   pub const fn is_advisory(&self) -> bool {
      matches!(*self, Self::Memory { .. })
   }
}

impl fmt::Display for Comparison {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match *self {
         Self::Export {
            ref name,
            ref before,
            ref after,
         } => write!(f, "{name} changed from {before} to {after}"),
         Self::Bytes {
            ref name,
            offset,
            ref before,
            ref after,
         } => {
            write!(
               f,
               "memory {name} at {offset} differs over {} bytes",
               before.len().max(after.len())
            )
         },
         Self::Memory {
            ref before,
            ref after,
         } => {
            write!(
               f,
               "linear memory changed from {} to {}",
               before
                  .as_ref()
                  .map_or_else(|| "unreachable".to_owned(), ToString::to_string),
               after
                  .as_ref()
                  .map_or_else(|| "unreachable".to_owned(), ToString::to_string)
            )
         },
      }
   }
}

/// Default base used for imported `__memory_base` and `__table_base` globals.
///
/// Zero would make absolute offsets look correct in the stub host, hiding
/// placement mistakes.
const IMPORT_BASE: i32 = 64;

/// Stub tables and memories are sized past the module's own segments plus
/// [`IMPORT_BASE`], which a stub built to the declared minimum would reject.
const STUB_HEADROOM: u32 = 4096;

/// Runs both modules and compares every zero-argument export, then linear
/// memory.
///
/// Encryption and marker errors can leave a module valid but change its
/// results, so validation alone can't check these rewrites.
///
/// # Errors
///
/// Fails if either module can't execute, the export sets differ, or a result
/// can't be compared across instances, or its budget is exhausted. All-trap
/// agreement and incomplete host scripts also fail. Requires a zero-argument
/// export.
#[inline]
#[expect(
   clippy::pub_with_shorthand,
   reason = "crate visibility keeps verification behind the worker boundary"
)]
pub(crate) fn compare(
   before: &[u8],
   after: &[u8],
   host: &HostConfig,
) -> Result<Vec<Comparison>, Error> {
   let original = Execution::new(before, ModuleSide::Original, host)?.run()?;
   let rewritten = Execution::new(after, ModuleSide::Rewritten, host)?.run()?;

   let missing = original
      .exports
      .keys()
      .filter(|name| !rewritten.exports.contains_key(*name))
      .cloned()
      .collect::<Vec<_>>();
   let added = rewritten
      .exports
      .keys()
      .filter(|name| !original.exports.contains_key(*name))
      .cloned()
      .collect::<Vec<_>>();
   if !missing.is_empty() || !added.is_empty() {
      return Err(Error::ExportSet { missing, added });
   }
   if original.exports.is_empty() {
      return Err(Error::NoExports);
   }

   if original.exports.iter().all(|(name, outcome)| {
      matches!(*outcome, CallOutcome::Trapped(_)) && *outcome == rewritten.exports[name]
   }) {
      return Err(Error::AllTrapped);
   }

   let mut results = original
      .exports
      .into_iter()
      .zip(rewritten.exports)
      .map(|((name, before_value), (_, after_value))| {
         Comparison::Export {
            name,
            before: before_value,
            after: after_value,
         }
      })
      .collect::<Vec<Comparison>>();

   results.push(Comparison::Memory {
      before: original.memory,
      after:  rewritten.memory,
   });

   Ok(results)
}

/// Runs an ordered scenario once per module, comparing calls and requested
/// memory bytes.
///
/// # Errors
///
/// Fails for missing exports, invalid arguments or memory ranges, unsupported
/// results, failed instantiation, exhausted budgets, incomplete host scripts,
/// all-trap agreement without observed bytes, or no calls or nonempty reads.
#[inline]
#[expect(
   clippy::pub_with_shorthand,
   reason = "crate visibility keeps verification behind the worker boundary"
)]
pub(crate) fn compare_scenario(
   before: &[u8],
   after: &[u8],
   actions: &[Action],
   host: &HostConfig,
) -> Result<Vec<Comparison>, Error> {
   if !actions.iter().any(|action| {
      match *action {
         Action::Call { .. } => true,
         Action::ReadMemory { len, .. } => len > 0,
         Action::WriteMemory { .. } => false,
      }
   }) {
      return Err(Error::EmptyScenario);
   }

   let mut original = Execution::new(before, ModuleSide::Original, host)?;
   let mut rewritten = Execution::new(after, ModuleSide::Rewritten, host)?;
   let original_instance = original.instantiate()?;
   let rewritten_instance = rewritten.instantiate()?;
   let mut comparisons = Vec::new();
   for action in actions {
      match *action {
         Action::Call {
            ref name,
            ref arguments,
         } => {
            comparisons.push(Comparison::Export {
               name:   name.clone(),
               before: original.call(original_instance, name, arguments)?,
               after:  rewritten.call(rewritten_instance, name, arguments)?,
            });
         },
         Action::WriteMemory {
            ref name,
            offset,
            ref bytes,
         } => {
            original.write_memory(original_instance, name, offset, bytes)?;
            rewritten.write_memory(rewritten_instance, name, offset, bytes)?;
         },
         Action::ReadMemory {
            ref name,
            offset,
            len,
         } => {
            comparisons.push(Comparison::Bytes {
               name: name.clone(),
               offset,
               before: original.read_memory(original_instance, name, offset, len)?,
               after: rewritten.read_memory(rewritten_instance, name, offset, len)?,
            });
         },
      }
   }
   original.finish_script()?;
   rewritten.finish_script()?;

   if comparisons.iter().all(|comparison| {
      match *comparison {
         Comparison::Export {
            before: CallOutcome::Trapped(before_trap),
            after: CallOutcome::Trapped(after_trap),
            ..
         } => before_trap == after_trap,
         Comparison::Bytes {
            before: ref before_bytes,
            after: ref after_bytes,
            ..
         } => before_bytes.is_empty() && after_bytes.is_empty(),
         Comparison::Export { .. } | Comparison::Memory { .. } => false,
      }
   }) {
      return Err(Error::AllTrapped);
   }

   comparisons.push(Comparison::Memory {
      before: original.memory_digest(original_instance),
      after:  rewritten.memory_digest(rewritten_instance),
   });
   Ok(comparisons)
}

/// Results from executing one module.
struct Outcome {
   /// Export name and result per zero-argument export.
   exports: BTreeMap<String, CallOutcome>,
   /// Digest of reachable linear memory after running the exports.
   memory:  Option<MemoryDigest>,
}

/// One module and its deterministic verifier host.
struct Execution<'host> {
   /// Compiled module awaiting instantiation.
   module: wasmi::Module,
   /// Runtime state shared by the instance and host stubs.
   store:  wasmi::Store<HostState<'host>>,
   /// Host definitions used to satisfy module imports.
   linker: wasmi::Linker<HostState<'host>>,
   /// Module identity included in verification errors.
   side:   ModuleSide,
}

impl<'host> Execution<'host> {
   /// Compiles a module and prepares its host imports.
   #[expect(
      clippy::expect_used,
      clippy::unwrap_in_result,
      reason = "fuel is enabled on this engine"
   )]
   fn new(wasm: &[u8], side: ModuleSide, host: &'host HostConfig) -> Result<Self, Error> {
      let mut config = wasmi::Config::default();
      config.consume_fuel(true);
      let engine = wasmi::Engine::new(&config);
      let module =
         wasmi::Module::new(&engine, wasm).map_err(|source| Error::Parse { side, source })?;
      let mut store = wasmi::Store::new(&engine, HostState::new(host));
      store.limiter(|state| &mut state.budget);
      store.set_fuel(host.limits.fuel).expect("fuel is enabled");
      let linker = <wasmi::Linker<HostState<'host>>>::new(&engine);

      let mut execution = Self {
         module,
         store,
         linker,
         side,
      };
      execution.stub_imports(host).map_err(|error| {
         execution
            .store
            .data()
            .budget
            .exceeded()
            .map_or(error, |resource| Error::LimitExceeded { side, resource })
      })?;
      Ok(execution)
   }

   /// Instantiates once, calls every zero-argument export in name order,
   /// then digests linear memory.
   ///
   /// Memory is hashed after the calls so any lazy decryption they trigger has
   /// finished.
   fn run(mut self) -> Result<Outcome, Error> {
      let mut names = self
         .module
         .exports()
         .filter_map(|export| {
            let func = export.ty().func()?;
            func.params().is_empty().then(|| export.name().to_owned())
         })
         .collect::<Vec<String>>();
      names.sort_unstable();

      let instance = self.instantiate()?;

      let mut exports = BTreeMap::new();

      for name in names {
         let outcome = self.call(instance, &name, &[])?;
         exports.insert(name, outcome);
      }

      self.finish_script()?;
      let memory = self.memory_digest(instance);
      Ok(Outcome { exports, memory })
   }

   /// Skipped callbacks must fail even when all guest results happen to agree.
   fn finish_script(&self) -> Result<(), Error> {
      self.store.data().finish().map_err(|source| {
         Error::HostScript {
            side: self.side,
            source,
         }
      })
   }

   /// Start runs once so later scenario actions observe the same instance
   /// state.
   fn instantiate(&mut self) -> Result<wasmi::Instance, Error> {
      self
         .linker
         .instantiate_and_start(&mut self.store, &self.module)
         .map_err(|source| {
            if let Some(error) = self.limit_error(&source) {
               return error;
            }
            Error::Instantiate {
               side: self.side,
               source,
            }
         })
   }

   /// Runtime traps remain observable outcomes rather than host invocation
   /// failures.
   fn call(
      &mut self,
      instance: wasmi::Instance,
      name: &str,
      arguments: &[Value],
   ) -> Result<CallOutcome, Error> {
      let func = instance.get_func(&self.store, name).ok_or_else(|| {
         Error::MissingExport {
            side: self.side,
            name: name.to_owned(),
         }
      })?;
      let inputs = arguments.iter().map(Val::from).collect::<Vec<_>>();
      let mut outputs = vec![Val::I32(0); func.ty(&self.store).results().len()];
      match func.call(&mut self.store, &inputs, &mut outputs) {
         Ok(()) => {
            let values = outputs
               .iter()
               .map(Value::try_from)
               .collect::<Result<_, _>>()
               .map_err(|source| {
                  Error::UnsupportedResult {
                     side: self.side,
                     name: name.to_owned(),
                     source,
                  }
               })?;
            Ok(CallOutcome::Returned(values))
         },
         Err(source) => {
            if let Some(error) = self.limit_error(&source) {
               return Err(error);
            }
            source.as_trap_code().map_or_else(
               || {
                  Err(Error::Call {
                     side: self.side,
                     name: name.to_owned(),
                     source,
                  })
               },
               |kind| Ok(CallOutcome::Trapped(kind)),
            )
         },
      }
   }

   /// Host budget failures cannot establish equivalent guest behavior.
   fn limit_error(&self, source: &wasmi::Error) -> Option<Error> {
      self
         .store
         .data()
         .budget
         .exceeded()
         .or_else(|| {
            match source.as_trap_code() {
               Some(TrapCode::OutOfFuel) => Some(Resource::Fuel),
               Some(TrapCode::OutOfSystemMemory) => Some(Resource::ProcessMemory),
               _ => None,
            }
         })
         .map(|resource| {
            Error::LimitExceeded {
               side: self.side,
               resource,
            }
         })
   }

   /// Scenario memory names refer to the module's public host interface.
   fn export_memory(&self, instance: wasmi::Instance, name: &str) -> Result<wasmi::Memory, Error> {
      instance.get_memory(&self.store, name).ok_or_else(|| {
         Error::MissingMemory {
            side: self.side,
            name: name.to_owned(),
         }
      })
   }

   /// Bounds are checked before copying so an invalid length cannot trigger a
   /// large allocation.
   fn read_memory(
      &mut self,
      instance: wasmi::Instance,
      name: &str,
      offset: usize,
      len: usize,
   ) -> Result<Vec<u8>, Error> {
      let memory = self.export_memory(instance, name)?;
      let end = offset
         .checked_add(len)
         .filter(|end| *end <= memory.data(&self.store).len())
         .ok_or_else(|| {
            Error::MemoryAccess {
               side:   self.side,
               name:   name.to_owned(),
               source: errors::MemoryError::OutOfBoundsAccess,
            }
         })?;
      if !self.store.data_mut().budget.capture(len) {
         return Err(Error::LimitExceeded {
            side:     self.side,
            resource: Resource::Reads,
         });
      }
      Ok(memory.data(&self.store)[offset..end].to_vec())
   }

   /// Writes share the same memory seen by subsequent calls and reads.
   fn write_memory(
      &mut self,
      instance: wasmi::Instance,
      name: &str,
      offset: usize,
      bytes: &[u8],
   ) -> Result<(), Error> {
      self
         .export_memory(instance, name)?
         .write(&mut self.store, offset, bytes)
         .map_err(|source| {
            Error::MemoryAccess {
               side: self.side,
               name: name.to_owned(),
               source,
            }
         })
   }

   /// Digests reachable linear memory, preferring the instance export over the
   /// stub.
   fn memory_digest(&self, instance: wasmi::Instance) -> Option<MemoryDigest> {
      let located = instance
         .exports(&self.store)
         .find_map(wasmi::Export::into_memory)
         .or_else(|| {
            self
               .linker
               .get(&self.store, "env", "memory")
               .and_then(wasmi::Extern::into_memory)
         });

      let memory = located?;
      let bytes = memory.data(&self.store);
      Some(MemoryDigest {
         hash: fnv1a(bytes),
         len:  bytes.len(),
      })
   }

   /// Both modules receive the same import expectations. Scripted memory
   /// effects use caller exports, but reentrant guest calls are not modeled.
   fn stub_imports(&mut self, host: &HostConfig) -> Result<(), Error> {
      let side = self.side;
      for import in self.module.imports() {
         let (module_name, field) = (import.module().to_owned(), import.name().to_owned());
         let import_error = |source| {
            Error::Import {
               side,
               name: format!("{module_name}.{field}"),
               source,
            }
         };

         let item: wasmi::Extern = match *import.ty() {
            wasmi::ExternType::Func(ref func_ty) => {
               let signature = func_ty.clone();
               let results_ty = signature.results().to_vec();
               let import_module = module_name.clone();
               let import_name = field.clone();

               wasmi::Func::new(
                  &mut self.store,
                  signature,
                  move |mut caller, params, results| {
                     HostState::call(
                        &mut caller,
                        &import_module,
                        &import_name,
                        params,
                        &results_ty,
                        results,
                     )
                  },
               )
               .into()
            },
            wasmi::ExternType::Global(global_ty) => {
               let base = match field.as_str() {
                  "__memory_base" => host.memory_base,
                  "__table_base" => host.table_base,
                  _ => 0_i32,
               };
               let value = match global_ty.content() {
                  ValType::I32 => Val::I32(base),
                  ValType::I64 => Val::I64(i64::from(base)),
                  rest @ (ValType::F32
                  | ValType::F64
                  | ValType::V128
                  | ValType::FuncRef
                  | ValType::ExternRef) => Val::default_for_ty(rest),
               };
               wasmi::Global::new(&mut self.store, value, global_ty.mutability()).into()
            },
            wasmi::ExternType::Memory(memory_ty) => {
               let maximum = memory_ty.maximum();
               let minimum = (memory_ty.minimum() + 1).min(maximum.unwrap_or(u64::MAX));
               let mut shape = wasmi::MemoryType::builder();
               shape.min(minimum).max(maximum).memory64(memory_ty.is_64());
               let roomy = shape
                  .build()
                  .map_err(|source| import_error(Box::new(source)))?;

               wasmi::Memory::new(&mut self.store, roomy)
                  .map_err(|source| import_error(Box::new(source)))?
                  .into()
            },
            wasmi::ExternType::Table(table_ty) => {
               let maximum = table_ty
                  .maximum()
                  .map(u32::try_from)
                  .transpose()
                  .map_err(|source| import_error(Box::new(source)))?;
               let minimum = u32::try_from(table_ty.minimum())
                  .map_err(|source| import_error(Box::new(source)))?
                  .max(STUB_HEADROOM)
                  .min(maximum.unwrap_or(u32::MAX));

               wasmi::Table::new(
                  &mut self.store,
                  wasmi::TableType::new(table_ty.element(), minimum, maximum),
                  wasmi::Ref::default_for_ty(table_ty.element()),
               )
               .map_err(|source| import_error(Box::new(source)))?
               .into()
            },
         };

         self
            .linker
            .define(&module_name, &field, item)
            .map_err(|source| import_error(Box::new(source)))?;
      }

      Ok(())
   }
}

/// Hashes bytes with FNV-1a for memory comparison.
fn fnv1a(bytes: &[u8]) -> u64 {
   bytes.iter().fold(0xCBF2_9CE4_8422_2325, |hash, byte| {
      (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01B3)
   })
}
