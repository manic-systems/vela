use std::iter::repeat_with;

use walrus::{
   ir,
   ir::{
      Binop,
      Const,
      GlobalGet,
      Instr,
      Value,
   },
};

use crate::{
   config,
   mba::Expr,
   rng,
};

/// Mutable globals and their values after startup mixing.
///
/// Marker expressions use the mixed values. The emitted globals contain the
/// initial values, so reading those alone isn't enough to evaluate a marker.
pub struct Pool {
   /// Emitted mutable globals backing each pool slot.
   globals:   Vec<walrus::GlobalId>,
   /// Mixed values visible to marker expressions at runtime.
   values:    Vec<i32>,
   /// Startup function that mixes globals before use.
   seed_func: walrus::FunctionId,
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
            out.push(
               GlobalGet {
                  global: self.global(slot),
               }
               .into(),
            );
         },
         Expr::Bin(kind, ref lhs, ref rhs) => {
            self.lower(lhs, out);
            self.lower(rhs, out);
            out.push(Binop { op: kind.into() }.into());
         },
      }
   }

   /// Returns the walrus global for a pool slot.
   #[inline]
   pub fn global(&self, slot: usize) -> walrus::GlobalId {
      self.globals[slot]
   }

   /// Returns mixed pool values for evaluation.
   #[inline]
   pub fn values(&self) -> &[i32] {
      &self.values
   }

   /// Returns the startup mixing function.
   #[inline]
   pub const fn seed_func(&self) -> walrus::FunctionId {
      self.seed_func
   }

   /// Emits globals plus a startup mixer and tracks mixed values.
   #[inline]
   pub fn build(
      module: &mut walrus::Module,
      rng: &mut rng::Rng,
      requested: config::PoolSize,
      names: bool,
   ) -> Self {
      let size = requested.get();

      let mut values = repeat_with(|| rng.next_i32())
         .take(size)
         .collect::<Vec<i32>>();
      let globals = values
         .iter()
         .map(|value| {
            module.globals.add_local(
               walrus::ValType::I32,
               true,
               false,
               walrus::ConstExpr::Value(ir::Value::I32(*value)),
            )
         })
         .collect::<Vec<walrus::GlobalId>>();

      let mixers = repeat_with(|| rng.next_i32())
         .take(size)
         .collect::<Vec<i32>>();

      let mut builder = walrus::FunctionBuilder::new(&mut module.types, &[], &[]);
      if names {
         builder.name("vela_seed".to_owned());
      }
      let mut body = builder.func_body();

      for index in 0..size {
         let next = (index + 1) % size;

         body
            .instr(ir::GlobalGet {
               global: globals[index],
            })
            .instr(ir::GlobalGet {
               global: globals[next],
            })
            .instr(ir::Binop {
               op: ir::BinaryOp::I32Xor,
            })
            .instr(ir::Const {
               value: ir::Value::I32(mixers[index]),
            })
            .instr(ir::Binop {
               op: ir::BinaryOp::I32Add,
            })
            .instr(ir::GlobalSet {
               global: globals[index],
            });

         // The final iteration reads slot 0 after it's been mixed. The
         // build-time values must follow the same update order as the emitted
         // instructions.
         values[index] = (values[index] ^ values[next]).wrapping_add(mixers[index]);
      }

      let seed_func = builder.finish(Vec::new(), &mut module.funcs);

      Self {
         globals,
         values,
         seed_func,
      }
   }
}
