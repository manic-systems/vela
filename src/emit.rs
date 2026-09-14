use std::num::NonZeroU64;

use walrus::{
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
};

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
   /// Builds the runtime decryptor, `(ptr: i32, len: i32, seed: i64) -> ()`.
   ///
   /// Its byte stream must match [`crate::rng::KeyStream`], which encrypts the
   /// segments at build time. A mismatch leaves corrupt bytes in linear memory.
   #[inline]
   pub fn new(module: &mut walrus::Module, memory: walrus::MemoryId, names: bool) -> Self {
      let mut builder = walrus::FunctionBuilder::new(
         &mut module.types,
         &[ValType::I32, ValType::I32, ValType::I64],
         &[],
      );

      let ptr = module.locals.add(ValType::I32);
      let len = module.locals.add(ValType::I32);
      let seed = module.locals.add(ValType::I64);
      let state = module.locals.add(ValType::I64);

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

               for (shift, op) in [
                  (13, BinaryOp::I64Shl),
                  (7, BinaryOp::I64ShrU),
                  (17, BinaryOp::I64Shl),
               ] {
                  walk
                     .instr(LocalGet { local: state })
                     .instr(LocalGet { local: state })
                     .instr(Const {
                        value: Value::I64(shift),
                     })
                     .instr(Binop { op })
                     .instr(Binop {
                        op: BinaryOp::I64Xor,
                     })
                     .instr(LocalSet { local: state });
               }

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
                  })
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
                  .instr(LocalGet { local: ptr })
                  .instr(Const {
                     value: Value::I32(1),
                  })
                  .instr(Binop {
                     op: BinaryOp::I32Add,
                  })
                  .instr(LocalSet { local: ptr })
                  .instr(LocalGet { local: len })
                  .instr(Const {
                     value: Value::I32(1),
                  })
                  .instr(Binop {
                     op: BinaryOp::I32Sub,
                  })
                  .instr(LocalSet { local: len })
                  .instr(Br { block: walk_id });
            });
         });

      let func = builder.finish(vec![ptr, len, seed], &mut module.funcs);
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
   pub fn call(&self, segment: &analysis::Segment, seed: NonZeroU64, out: &mut Vec<Instr>) {
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
      out.push(ir::Call { func: self.func }.into());
   }

   /// A once-only decrypt for a single segment, called at the entry of every
   /// function that names an address inside it.
   pub fn gate(
      &self,
      module: &mut walrus::Module,
      segment: &analysis::Segment,
      seed: NonZeroU64,
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
      self.call(segment, seed, &mut body);

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
