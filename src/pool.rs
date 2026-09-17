use std::iter::repeat_with;

use walrus::{
   ConstExpr,
   FunctionBuilder,
   FunctionId,
   GlobalId,
   Module,
   ValType,
   ir::{
      BinaryOp,
      Binop,
      Call,
      Const,
      GlobalGet,
      GlobalSet,
      Instr,
      LocalGet,
      LocalSet,
      LocalTee,
      UnaryOp,
      Unop,
      Value,
   },
};

use crate::{
   config::PoolSize,
   mba::Expr,
   rng::Rng,
};

/// Mutable globals and their values after startup mixing.
///
/// Marker expressions use mixed logical values, not the emitted initializers.
pub struct Pool {
   /// Readers advance packed state without changing the logical value.
   slots:     Vec<(GlobalId, Option<FunctionId>)>,
   /// Mixed values visible to marker expressions at runtime.
   values:    Vec<i32>,
   /// Startup function that mixes globals before use.
   seed_func: FunctionId,
}

impl Pool {
   /// Lowers an expression into walrus instructions.
   #[inline]
   pub fn lower(&self, expr: &Expr, out: &mut Vec<Instr>) {
      match *expr {
         Expr::Const(value) => {
            out.push(
               Const {
                  value: Value::I32(value),
               }
               .into(),
            );
         },
         Expr::Global(slot) => {
            let (global, reader) = self.slots[slot];

            out.push(
               reader.map_or_else(|| GlobalGet { global }.into(), |func| Call { func }.into()),
            );
         },
         Expr::Bin(kind, ref lhs, ref rhs) => {
            self.lower(lhs, out);
            self.lower(rhs, out);
            out.push(Binop { op: kind.into() }.into());
         },
      }
   }

   /// Generated readers must stay outside the code passes that call them.
   #[inline]
   pub fn readers(&self) -> impl Iterator<Item = FunctionId> + '_ {
      self.slots.iter().filter_map(|entry| entry.1)
   }

   /// Returns mixed pool values for evaluation.
   #[inline]
   pub fn values(&self) -> &[i32] {
      &self.values
   }

   /// Returns the startup mixing function.
   #[inline]
   pub const fn seed_func(&self) -> FunctionId {
      self.seed_func
   }

   /// Emits globals plus a startup mixer and tracks mixed values.
   #[inline]
   pub fn build(
      module: &mut Module,
      rng: &mut Rng,
      requested: PoolSize,
      names: bool,
      evolve: bool,
   ) -> Self {
      let size = requested.get();

      let mut values = repeat_with(|| rng.next_i32())
         .take(size)
         .collect::<Vec<i32>>();
      let globals = values
         .iter()
         .map(|value| {
            let initial = if evolve {
               Value::I64(i64::from(value.cast_unsigned()))
            } else {
               Value::I32(*value)
            };

            module.globals.add_local(
               if evolve { ValType::I64 } else { ValType::I32 },
               true,
               false,
               ConstExpr::Value(initial),
            )
         })
         .collect::<Vec<GlobalId>>();

      let mixers = repeat_with(|| rng.next_i32())
         .take(size)
         .collect::<Vec<i32>>();

      let readers = evolve.then(|| {
         globals
            .iter()
            .enumerate()
            .map(|(index, global)| {
               build_reader(
                  module,
                  *global,
                  rng.next_i32() | 1,
                  names.then(|| format!("vela_pool_{index}")),
               )
            })
            .collect::<Vec<_>>()
      });

      let mut builder = FunctionBuilder::new(&mut module.types, &[], &[]);

      if names {
         builder.name("vela_seed".to_owned());
      }

      let mut body = builder.func_body();

      for index in 0..size {
         let next = (index + 1) % size;

         for slot in [index, next] {
            if let Some(ref functions) = readers {
               body.instr(Call {
                  func: functions[slot],
               });
            } else {
               body.instr(GlobalGet {
                  global: globals[slot],
               });
            }
         }

         body
            .instr(Binop {
               op: BinaryOp::I32Xor,
            })
            .instr(Const {
               value: Value::I32(mixers[index]),
            })
            .instr(Binop {
               op: BinaryOp::I32Add,
            });

         if evolve {
            let mask = u64::from(rng.next_i32().cast_unsigned());

            body
               .instr(Unop {
                  op: UnaryOp::I64ExtendUI32,
               })
               .instr(Const {
                  value: Value::I64(32),
               })
               .instr(Binop {
                  op: BinaryOp::I64Shl,
               })
               .instr(Const {
                  value: Value::I64(((mask << 32) | mask).cast_signed()),
               })
               .instr(Binop {
                  op: BinaryOp::I64Xor,
               });
         }

         body.instr(GlobalSet {
            global: globals[index],
         });

         // The final iteration reads slot 0 after it's been mixed. The
         // build-time values must follow the same update order as the emitted
         // instructions.
         values[index] = (values[index] ^ values[next]).wrapping_add(mixers[index]);
      }

      let seed_func = builder.finish(Vec::new(), &mut module.funcs);

      Self {
         slots: globals
            .into_iter()
            .enumerate()
            .map(|(index, global)| (global, readers.as_ref().map(|functions| functions[index])))
            .collect(),
         values,
         seed_func,
      }
   }
}

/// A single global write keeps both shares valid even when execution traps.
fn build_reader(
   module: &mut Module,
   global: GlobalId,
   step: i32,
   debug_name: Option<String>,
) -> FunctionId {
   let snapshot = module.locals.add(ValType::I64);
   let logical = module.locals.add(ValType::I32);
   let mask = module.locals.add(ValType::I32);
   let mut builder = FunctionBuilder::new(&mut module.types, &[], &[ValType::I32]);

   if let Some(name) = debug_name {
      builder.name(name);
   }

   builder
      .func_body()
      .instr(GlobalGet { global })
      .instr(LocalTee { local: snapshot })
      .instr(Const {
         value: Value::I64(32),
      })
      .instr(Binop {
         op: BinaryOp::I64ShrU,
      })
      .instr(LocalGet { local: snapshot })
      .instr(Binop {
         op: BinaryOp::I64Xor,
      })
      .instr(Unop {
         op: UnaryOp::I32WrapI64,
      })
      .instr(LocalSet { local: logical })
      .instr(LocalGet { local: snapshot })
      .instr(Unop {
         op: UnaryOp::I32WrapI64,
      })
      .instr(Const {
         value: Value::I32(step),
      })
      .instr(Binop {
         op: BinaryOp::I32Add,
      })
      .instr(LocalTee { local: mask })
      .instr(Unop {
         op: UnaryOp::I64ExtendUI32,
      })
      .instr(LocalGet { local: logical })
      .instr(LocalGet { local: mask })
      .instr(Binop {
         op: BinaryOp::I32Xor,
      })
      .instr(Unop {
         op: UnaryOp::I64ExtendUI32,
      })
      .instr(Const {
         value: Value::I64(32),
      })
      .instr(Binop {
         op: BinaryOp::I64Shl,
      })
      .instr(Binop {
         op: BinaryOp::I64Or,
      })
      .instr(GlobalSet { global })
      .instr(LocalGet { local: logical });

   builder.finish(Vec::new(), &mut module.funcs)
}
