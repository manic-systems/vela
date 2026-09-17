use std::num::NonZeroU64;

use walrus::{
   InstrSeqBuilder,
   LocalId,
   ValType,
   ir,
   ir::{
      BinaryOp,
      Binop,
      Br,
      BrIf,
      Const,
      ExtendedLoad,
      GlobalGet,
      Instr,
      InstrSeqType,
      Load,
      LoadKind,
      LocalGet,
      LocalSet,
      MemArg,
      Store,
      StoreKind,
      UnaryOp,
      Unop,
      Value,
   },
};

use crate::{
   analysis,
   mba::BinKind,
   pool::Pool,
};

/// Odd multiplication preserves single-byte differences in the checksum.
pub const CHECKSUM_FACTOR: i32 = 16_777_619;

/// Maps a marker operator to its wasm binary opcode.
impl From<BinKind> for BinaryOp {
   #[inline]
   fn from(kind: BinKind) -> Self {
      match kind {
         BinKind::Add => Self::I32Add,
         BinKind::Sub => Self::I32Sub,
         BinKind::Mul => Self::I32Mul,
         BinKind::Xor => Self::I32Xor,
         BinKind::And => Self::I32And,
         BinKind::Or => Self::I32Or,
         BinKind::RotL => Self::I32Rotl,
      }
   }
}

/// Runtime decryption function and its call helpers.
pub struct Decryptor {
   /// Function called to decrypt a segment in place.
   func:  walrus::FunctionId,
   /// Whether generated gates receive debug names.
   names: bool,
}

impl Decryptor {
   /// Checksums cover ciphertext once, before guest code can mutate plaintext.
   #[inline]
   pub fn new(
      module: &mut walrus::Module,
      memory: walrus::MemoryId,
      names: bool,
      pool: &Pool,
   ) -> Self {
      let mut params = vec![ValType::I32, ValType::I32, ValType::I64];
      if pool.integrity_func().is_some() {
         params.push(ValType::I32);
      }

      let mut builder = walrus::FunctionBuilder::new(&mut module.types, &params, &[]);

      let ptr = module.locals.add(ValType::I32);
      let len = module.locals.add(ValType::I32);
      let seed = module.locals.add(ValType::I64);
      let state = module.locals.add(ValType::I64);
      let integrity = pool.integrity_func().map(|fold| {
         (
            module.locals.add(ValType::I32),
            module.locals.add(ValType::I32),
            module.locals.add(ValType::I32),
            fold,
         )
      });

      if names {
         builder.name("vela_decrypt".to_owned());
      }

      builder
         .func_body()
         .instr(LocalGet { local: seed })
         .instr(LocalSet { local: state })
         .block(InstrSeqType::Simple(None), |done| {
            let done_id = done.id();

            done.loop_(InstrSeqType::Simple(None), |walk| {
               let walk_id = walk.id();

               walk
                  .instr(LocalGet { local: len })
                  .instr(Unop {
                     op: UnaryOp::I32Eqz,
                  })
                  .instr(BrIf { block: done_id });

               stream_step(walk, state);

               walk
                  .instr(LocalGet { local: ptr })
                  .instr(LocalGet { local: ptr })
                  .instr(Load {
                     memory,
                     kind: LoadKind::I32_8 {
                        kind: ExtendedLoad::ZeroExtend,
                     },
                     arg: MemArg {
                        align:  1,
                        offset: 0,
                     },
                  });

               if let Some((_, hash, byte, _)) = integrity {
                  walk
                     .local_tee(byte)
                     .local_get(hash)
                     .binop(BinaryOp::I32Xor)
                     .i32_const(CHECKSUM_FACTOR)
                     .binop(BinaryOp::I32Mul)
                     .local_set(hash)
                     .local_get(byte);
               }

               walk
                  .instr(LocalGet { local: state })
                  .instr(Unop {
                     op: UnaryOp::I32WrapI64,
                  })
                  .instr(Binop {
                     op: BinaryOp::I32Xor,
                  })
                  .instr(Store {
                     memory,
                     kind: StoreKind::I32_8 { atomic: false },
                     arg: MemArg {
                        align:  1,
                        offset: 0,
                     },
                  });

               walk
                  .local_get(ptr)
                  .i32_const(1)
                  .binop(BinaryOp::I32Add)
                  .local_set(ptr)
                  .local_get(len)
                  .i32_const(1)
                  .binop(BinaryOp::I32Sub)
                  .local_set(len)
                  .instr(Br { block: walk_id });
            });
         });

      let mut arguments = vec![ptr, len, seed];

      if let Some((expected, hash, _, fold)) = integrity {
         builder
            .func_body()
            .local_get(hash)
            .local_get(expected)
            .binop(BinaryOp::I32Xor)
            .call(fold);

         arguments.push(expected);
      }

      let func = builder.finish(arguments, &mut module.funcs);
      Self { func, names }
   }

   /// Returns the runtime decryptor's function ID.
   #[inline]
   pub const fn id(&self) -> walrus::FunctionId {
      self.func
   }

   /// A call to `vela_decrypt` for one segment, as a flat instruction run.
   ///
   /// Relocatable data must use the same base global as its data segment so
   /// decryption follows the loader's placement.
   #[inline]
   pub fn call(
      &self,
      segment: &analysis::Segment,
      seed: NonZeroU64,
      checksum: Option<i32>,
      out: &mut Vec<Instr>,
   ) {
      match segment.anchor {
         analysis::Anchor::Absolute(start) => {
            out.push(
               Const {
                  value: Value::I32(start),
               }
               .into(),
            );
         },
         analysis::Anchor::Relocatable { base, offset } => {
            out.push(GlobalGet { global: base }.into());
            if offset != 0_i32 {
               out.push(
                  Const {
                     value: Value::I32(offset),
                  }
                  .into(),
               );
               out.push(
                  Binop {
                     op: BinaryOp::I32Add,
                  }
                  .into(),
               );
            }
         },
      }

      #[expect(
         clippy::cast_possible_truncation,
         clippy::cast_possible_wrap,
         clippy::as_conversions,
         reason = "wasm memory lengths are represented as i32 in the instruction format"
      )]
      let len = segment.len as i32;
      out.push(
         Const {
            value: Value::I32(len),
         }
         .into(),
      );
      out.push(
         Const {
            value: Value::I64(seed.get().cast_signed()),
         }
         .into(),
      );

      if let Some(expected) = checksum {
         out.push(
            Const {
               value: Value::I32(expected),
            }
            .into(),
         );
      }

      out.push(ir::Call { func: self.func }.into());
   }

   /// A once-only decrypt for a single segment, called at the entry of every
   /// function that names an address inside it.
   pub fn gate(
      &self,
      module: &mut walrus::Module,
      segment: &analysis::Segment,
      seed: NonZeroU64,
      checksum: Option<i32>,
   ) -> walrus::FunctionId {
      let done = module.globals.add_local(
         walrus::ValType::I32,
         true,
         false,
         walrus::ConstExpr::Value(ir::Value::I32(0)),
      );

      let mut builder = walrus::FunctionBuilder::new(&mut module.types, &[], &[]);
      if self.names {
         builder.name(format!(
            "vela_gate_{:#x}",
            segment.start().unwrap_or_default()
         ));
      }

      let mut body = Vec::new();
      self.call(segment, seed, checksum, &mut body);

      builder
         .func_body()
         .instr(ir::GlobalGet { global: done })
         .instr(ir::Unop {
            op: ir::UnaryOp::I32Eqz,
         })
         .if_else(
            ir::InstrSeqType::Simple(None),
            |then| {
               then
                  .instr(ir::Const {
                     value: ir::Value::I32(1),
                  })
                  .instr(ir::GlobalSet { global: done });
               for instr in body {
                  then.instr(instr);
               }
            },
            |_| {},
         );

      builder.finish(Vec::new(), &mut module.funcs)
   }
}

/// Must match the xorshift sequence in [`crate::rng::KeyStream`].
fn stream_step(body: &mut InstrSeqBuilder<'_>, state: LocalId) {
   for (shift, op) in [
      (13, BinaryOp::I64Shl),
      (7, BinaryOp::I64ShrU),
      (17, BinaryOp::I64Shl),
   ] {
      body
         .local_get(state)
         .local_get(state)
         .i64_const(shift)
         .binop(op)
         .binop(BinaryOp::I64Xor)
         .local_set(state);
   }
}
