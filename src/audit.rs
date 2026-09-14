use walrus::ir;

/// Rejects absolute `i32` offsets in active segments on imported memories or
/// tables.
///
/// Execution comparison can miss misplaced entries because a module running
/// alone reads back its own writes. The conflict appears when another module
/// shares the memory or table.
#[must_use]
#[inline]
pub fn placement(module: &walrus::Module) -> Vec<String> {
   let mut faults = Vec::new();

   for element in module.elements.iter() {
      let walrus::ElementKind::Active {
         ref table,
         ref offset,
      } = element.kind
      else {
         continue;
      };

      if module.tables.get(*table).import.is_none() {
         continue;
      }

      if matches!(offset, walrus::ConstExpr::Value(ir::Value::I32(_))) {
         faults.push(
            "element segment for imported table sits at an absolute index; a relocatable module \
             places its entries relative to __table_base"
               .to_owned(),
         );
      }
   }

   for data in module.data.iter() {
      let walrus::DataKind::Active {
         ref memory,
         ref offset,
      } = data.kind
      else {
         continue;
      };

      if module.memories.get(*memory).import.is_none() {
         continue;
      }

      if matches!(offset, walrus::ConstExpr::Value(ir::Value::I32(_))) {
         faults.push(
            "data segment for imported memory sits at an absolute address; a relocatable module \
             places its data relative to __memory_base"
               .to_owned(),
         );
      }
   }

   faults
}
