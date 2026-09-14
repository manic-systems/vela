use wasmi::{
   ResourceLimiter,
   errors::{
      MemoryError,
      TableError,
   },
};
use wasmi_core::LimiterError;

use crate::verify::{
   Limits,
   Resource,
};

/// Aggregate guest and capture budget for one verification run.
pub struct Budget {
   /// Declared caps for guest growth and retained reads.
   limits:           Limits,
   /// Total memory bytes currently accounted to live memories.
   used_memory:      usize,
   /// Total table elements currently accounted to live tables.
   used_elements:    usize,
   /// Last permitted memory growth awaiting failure rollback.
   pending_memory:   usize,
   /// Last permitted table growth awaiting failure rollback.
   pending_elements: usize,
   /// First resource to exceed its budget if any.
   exceeded:         Option<Resource>,
   /// Total retained read bytes captured so far.
   captured_bytes:   usize,
}

impl Budget {
   /// Creates a new budget from the given limits.
   #[must_use]
   pub const fn new(limits: Limits) -> Self {
      Self {
         limits,
         used_memory: 0,
         used_elements: 0,
         pending_memory: 0,
         pending_elements: 0,
         exceeded: None,
         captured_bytes: 0,
      }
   }

   /// Returns the resource that first exceeded its budget if any.
   #[must_use]
   pub const fn exceeded(&self) -> Option<Resource> {
      self.exceeded
   }

   /// Accounts for retained read bytes and reports whether they fit.
   #[must_use]
   pub fn capture(&mut self, len: usize) -> bool {
      match self.captured_bytes.checked_add(len) {
         Some(total) if total <= self.limits.read_bytes => {
            self.captured_bytes = total;
            true
         },
         Some(_) | None => {
            self.exceeded.get_or_insert(Resource::Reads);
            false
         },
      }
   }
}

impl ResourceLimiter for Budget {
   fn memory_growing(
      &mut self,
      current: usize,
      desired: usize,
      maximum: Option<usize>,
   ) -> Result<bool, LimiterError> {
      self.pending_memory = 0;
      if maximum.is_some_and(|max| desired > max) {
         return Ok(true);
      }
      let growth = desired.saturating_sub(current);
      match self.used_memory.checked_add(growth) {
         Some(total) if total <= self.limits.memory_bytes => {
            self.used_memory = total;
            self.pending_memory = growth;
            Ok(true)
         },
         Some(_) | None => {
            self.exceeded.get_or_insert(Resource::Memory);
            Err(LimiterError::ResourceLimiterDeniedAllocation)
         },
      }
   }

   fn table_growing(
      &mut self,
      current: usize,
      desired: usize,
      maximum: Option<usize>,
   ) -> Result<bool, LimiterError> {
      self.pending_elements = 0;
      if maximum.is_some_and(|max| desired > max) {
         return Ok(true);
      }
      let growth = desired.saturating_sub(current);
      match self.used_elements.checked_add(growth) {
         Some(total) if total <= self.limits.table_elements => {
            self.used_elements = total;
            self.pending_elements = growth;
            Ok(true)
         },
         Some(_) | None => {
            self.exceeded.get_or_insert(Resource::Tables);
            Err(LimiterError::ResourceLimiterDeniedAllocation)
         },
      }
   }

   fn memory_grow_failed(&mut self, error: &MemoryError) -> Result<(), LimiterError> {
      self.used_memory = self.used_memory.saturating_sub(self.pending_memory);
      self.pending_memory = 0;
      if matches!(*error, MemoryError::OutOfSystemMemory) {
         self.exceeded.get_or_insert(Resource::ProcessMemory);
         return Err(LimiterError::ResourceLimiterDeniedAllocation);
      }
      Ok(())
   }

   fn table_grow_failed(&mut self, error: &TableError) -> Result<(), LimiterError> {
      self.used_elements = self.used_elements.saturating_sub(self.pending_elements);
      self.pending_elements = 0;
      if matches!(*error, TableError::OutOfSystemMemory) {
         self.exceeded.get_or_insert(Resource::ProcessMemory);
         return Err(LimiterError::ResourceLimiterDeniedAllocation);
      }
      Ok(())
   }

   fn instances(&self) -> usize {
      1
   }

   fn tables(&self) -> usize {
      16
   }

   fn memories(&self) -> usize {
      16
   }
}
