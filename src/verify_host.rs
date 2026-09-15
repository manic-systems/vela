use wasmi::{
   Val,
   ValType,
};

use crate::{
   verify::{
      HostConfig,
      HostImports,
      Value,
   },
   verify_limits::Budget,
};

/// Host callbacks cannot share a cursor between the original and rewritten
/// instance.
pub struct HostState<'host> {
   /// Initialization and later callbacks share the instance's resource limits.
   pub budget:   Budget,
   /// Both instances borrow these expectations for the entire workload.
   pub imports:  &'host HostImports,
   /// A callback advances only after all its inputs and outputs validate.
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
      &mut self,
      module: &str,
      name: &str,
      arguments: &[Val],
      result_types: &[ValType],
      results: &mut [Val],
   ) -> Result<(), wasmi::Error> {
      let HostImports::Script(ref calls) = *self.imports else {
         for (slot, result_type) in results.iter_mut().zip(result_types) {
            *slot = Val::default_for_ty(*result_type);
         }

         return Ok(());
      };
      let position = self.consumed;
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

      self.consumed += 1;
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
