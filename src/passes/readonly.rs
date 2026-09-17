//! Declarations use zero-based input data-segment indices and promise that
//! bytes never legitimately change, including during startup and host
//! callbacks.

use walrus::{
   FunctionBuilder,
   FunctionId,
   MemoryId,
   Module,
   ValType,
   ir::{
      BinaryOp,
      ExtendedLoad,
      InstrSeqType,
      LoadKind,
      MemArg,
      UnaryOp,
   },
};

use crate::{
   Rewriter,
   TransformError,
   analysis::{
      Anchor,
      Segment,
   },
   config::Config,
   emit::CHECKSUM_FACTOR,
};

/// Base globals must stay immutable because each check reevaluates placement.
#[inline]
pub fn validate(
   module: &Module,
   config: &Config,
   segments: &[Segment],
) -> Result<(), TransformError> {
   if config.readonly_segments.is_empty() {
      return Ok(());
   }

   if !config.integrity {
      return Err(TransformError::ReadOnlyIntegrity);
   }

   let data = module.data.iter().collect::<Vec<_>>();

   for &index in &config.readonly_segments {
      let segment = data
         .get(index)
         .and_then(|entry| segments.iter().find(|segment| segment.id == entry.id()))
         .ok_or(TransformError::ReadOnlySegment(index))?;

      if let Anchor::Relocatable { base, .. } = segment.anchor
         && module.globals.get(base).mutable
      {
         return Err(TransformError::ReadOnlySegment(index));
      }
   }

   Ok(())
}

/// Expected bytes must be captured before encryption or guest startup.
#[inline]
pub fn run(rewriter: &mut Rewriter<'_>) -> Result<Option<FunctionId>, TransformError> {
   let Some(&first) = rewriter.config.readonly_segments.first() else {
      return Ok(None);
   };

   let fold = rewriter
      .pool
      .integrity_func()
      .ok_or(TransformError::ReadOnlyIntegrity)?;

   let module = &mut rewriter.module;
   let memory = module
      .memories
      .iter()
      .next()
      .ok_or(TransformError::ReadOnlySegment(first))?
      .id();

   let checksum = scanner(module, memory, fold, rewriter.config.debug_names);
   rewriter.generated.insert(checksum);
   let mut builder = FunctionBuilder::new(&mut module.types, &[], &[]);

   if rewriter.config.debug_names {
      builder.name("vela_readonly".to_owned());
   }

   let mut body = builder.func_body();

   for (index, data) in module.data.iter().enumerate() {
      if !rewriter.config.readonly_segments.contains(&index) {
         continue;
      }

      let segment = rewriter
         .segments
         .iter()
         .find(|segment| segment.id == data.id())
         .ok_or(TransformError::ReadOnlySegment(index))?;

      let expected_hash = data.value.iter().fold(0_i32, |accumulator, byte| {
         (accumulator ^ i32::from(*byte)).wrapping_mul(CHECKSUM_FACTOR)
      });

      match segment.anchor {
         Anchor::Absolute(start) => {
            body.i32_const(start);
         },
         Anchor::Relocatable { base, offset } => {
            body.global_get(base);

            if offset != 0_i32 {
               body.i32_const(offset).binop(BinaryOp::I32Add);
            }
         },
      }

      let length = u32::try_from(segment.len)
         .map_err(|_error| TransformError::ReadOnlySegment(index))?
         .cast_signed();

      body
         .i32_const(length)
         .i32_const(expected_hash)
         .call(checksum);

      rewriter.report.readonly_segments.push(index);
      rewriter.report.bytes_readonly += segment.len;
   }

   let check = builder.finish(Vec::new(), &mut module.funcs);
   rewriter.generated.insert(check);
   Ok(Some(check))
}

/// Restoring bytes cannot clear the pool's shared mismatch latch.
fn scanner(module: &mut Module, memory: MemoryId, fold: FunctionId, names: bool) -> FunctionId {
   let ptr = module.locals.add(ValType::I32);
   let len = module.locals.add(ValType::I32);
   let expected = module.locals.add(ValType::I32);
   let hash = module.locals.add(ValType::I32);
   let mut builder = FunctionBuilder::new(&mut module.types, &[ValType::I32; 3], &[]);

   if names {
      builder.name("vela_readonly_checksum".to_owned());
   }

   builder
      .func_body()
      .block(InstrSeqType::Simple(None), |done| {
         let done_id = done.id();

         done.loop_(InstrSeqType::Simple(None), |walk| {
            let walk_id = walk.id();
            walk.local_get(len).unop(UnaryOp::I32Eqz).br_if(done_id);

            walk
               .local_get(hash)
               .local_get(ptr)
               .load(
                  memory,
                  LoadKind::I32_8 {
                     kind: ExtendedLoad::ZeroExtend,
                  },
                  MemArg {
                     align:  1,
                     offset: 0,
                  },
               )
               .binop(BinaryOp::I32Xor)
               .i32_const(CHECKSUM_FACTOR)
               .binop(BinaryOp::I32Mul)
               .local_set(hash)
               .local_get(ptr)
               .i32_const(1)
               .binop(BinaryOp::I32Add)
               .local_set(ptr)
               .local_get(len)
               .i32_const(1)
               .binop(BinaryOp::I32Sub)
               .local_set(len)
               .br(walk_id);
         });
      });

   builder
      .func_body()
      .local_get(hash)
      .local_get(expected)
      .binop(BinaryOp::I32Xor)
      .call(fold);

   builder.finish(vec![ptr, len, expected], &mut module.funcs)
}
