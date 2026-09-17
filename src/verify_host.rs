use wasmi::{
   Caller,
   Val,
   ValType,
};

use crate::{
   verify::{
      HostConfig,
      HostImports,
      ImportMemory,
      Value,
   },
   verify_limits::Budget,
};

/// Each instance owns its cursor over shared host expectations.
pub struct HostState<'host> {
   /// Initialization and later callbacks share the instance's resource limits.
   pub budget:   Budget,
   /// Both instances borrow these expectations for the entire workload.
   pub imports:  &'host HostImports,
   /// A callback advances only after its entire script succeeds.
   pub consumed: usize,
}

impl<'host> HostState<'host> {
   /// Immutable expectations outlive both executions without copying their
   /// values.
   pub const fn new(host: &'host HostConfig) -> Self {
      Self {
         budget:   Budget::new(host.limits),
         imports:  &host.imports,
         consumed: 0,
      }
   }

   /// Script failures are host errors, never guest traps that could count as
   /// agreement.
   pub fn call(
      caller: &mut Caller<'_, Self>,
      module: &str,
      name: &str,
      arguments: &[Val],
      result_types: &[ValType],
      results: &mut [Val],
   ) -> Result<(), wasmi::Error> {
      let imports = caller.data().imports;
      let HostImports::Script(ref calls) = *imports else {
         for (slot, result_type) in results.iter_mut().zip(result_types) {
            *slot = Val::default_for_ty(*result_type);
         }

         return Ok(());
      };
      let position = caller.data().consumed;
      let expected = calls.get(position).ok_or_else(|| {
         wasmi::Error::new(format!(
            "unexpected import #{position} {module}.{name}, script exhausted"
         ))
      })?;

      if expected.module != module || expected.name != name {
         return Err(wasmi::Error::new(format!(
            "import #{position} expected {}.{}, received {module}.{name}",
            expected.module, expected.name,
         )));
      }

      if arguments.len() != expected.arguments.len() {
         return Err(wasmi::Error::new(format!(
            "import #{position} {module}.{name} argument count differs"
         )));
      }

      for (index, (actual, wanted)) in arguments.iter().zip(&expected.arguments).enumerate() {
         let value = Value::try_from(actual).map_err(|source| {
            wasmi::Error::new(format!(
               "import #{position} {module}.{name} argument #{index}, {source}"
            ))
         })?;

         if value != *wanted {
            return Err(wasmi::Error::new(format!(
               "import #{position} {module}.{name} argument #{index} expected {wanted}, received \
                {value}",
            )));
         }
      }

      if expected.results.len() != result_types.len() {
         return Err(wasmi::Error::new(format!(
            "import #{position} {module}.{name} result count differs"
         )));
      }

      for (index, ((wanted, result_type), slot)) in expected
         .results
         .iter()
         .zip(result_types)
         .zip(results)
         .enumerate()
      {
         let value = Val::from(wanted);

         if value.ty() != *result_type {
            return Err(wasmi::Error::new(format!(
               "import #{position} {module}.{name} has the wrong type for result #{index}"
            )));
         }

         *slot = value;
      }

      apply_memory(caller, position, &expected.memory)?;
      caller.data_mut().consumed += 1;
      Ok(())
   }

   /// An unconsumed expectation means the guest omitted observable host
   /// behavior.
   pub fn finish(&self) -> Result<(), wasmi::Error> {
      if let HostImports::Script(ref calls) = *self.imports
         && self.consumed != calls.len()
      {
         return Err(wasmi::Error::new(format!(
            "host script has {} unconsumed imports",
            calls.len() - self.consumed,
         )));
      }

      Ok(())
   }
}

/// Host mismatches cannot count as matching guest traps.
fn apply_memory(
   caller: &mut Caller<'_, HostState<'_>>,
   position: usize,
   actions: &[ImportMemory],
) -> Result<(), wasmi::Error> {
   for (index, action) in actions.iter().enumerate() {
      let (name, offset) = match *action {
         ImportMemory::Read {
            ref name, offset, ..
         }
         | ImportMemory::Write {
            ref name, offset, ..
         } => (name, offset),
      };
      let memory = caller
         .get_export(name)
         .and_then(wasmi::Extern::into_memory)
         .ok_or_else(|| {
            wasmi::Error::new(format!(
               "import #{position} memory action #{index} has no exported memory {name}"
            ))
         })?;

      match *action {
         ImportMemory::Read { ref expected, .. } => {
            let end = offset
               .checked_add(expected.len())
               .filter(|end| *end <= memory.data_size(&*caller))
               .ok_or_else(|| {
                  wasmi::Error::new(format!(
                     "import #{position} memory read #{index} is out of bounds"
                  ))
               })?;

            if !caller.data_mut().budget.capture(expected.len()) {
               return Err(wasmi::Error::new(
                  "host memory reads exceed the verification budget",
               ));
            }

            if memory.data(&*caller)[offset..end] != *expected {
               return Err(wasmi::Error::new(format!(
                  "import #{position} memory read #{index} differs from the expected bytes"
               )));
            }
         },
         ImportMemory::Write { ref bytes, .. } => {
            memory
               .write(&mut *caller, offset, bytes)
               .map_err(|source| {
                  wasmi::Error::new(format!(
                     "import #{position} memory write #{index} failed, {source}"
                  ))
               })?;
         },
      }
   }

   Ok(())
}
