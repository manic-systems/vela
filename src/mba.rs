use crate::rng;

/// A synthesised expression over the global pool. Kept independent of walrus so
/// it can be evaluated at build time before anything is emitted.
#[derive(Debug, Clone)]
pub enum Expr {
   /// A literal value with no pool reads.
   Const(i32),
   /// Index into the global pool, not a walrus `GlobalId`. The pass maps it at
   /// emit time.
   Global(usize),
   /// Two subexpressions joined by a binary operator.
   Bin(BinKind, Box<Self>, Box<Self>),
}

/// Binary operators usable in marker expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinKind {
   /// Wrapping addition.
   Add,
   /// Wrapping subtraction.
   Sub,
   /// Wrapping multiplication.
   Mul,
   /// Bitwise exclusive or.
   Xor,
   /// Bitwise and.
   And,
   /// Bitwise or.
   Or,
   /// Left rotation with the count masked to 5 bits.
   RotL,
}

impl Expr {
   /// Evaluates the expression against pool values.
   #[inline]
   #[must_use]
   pub fn eval(&self, pool: &[i32]) -> i32 {
      match *self {
         Self::Const(value) => value,
         Self::Global(slot) => pool[slot],
         Self::Bin(kind, ref lhs, ref rhs) => {
            let evaluated = (lhs.eval(pool), rhs.eval(pool));
            match kind {
               BinKind::Add => evaluated.0.wrapping_add(evaluated.1),
               BinKind::Sub => evaluated.0.wrapping_sub(evaluated.1),
               BinKind::Mul => evaluated.0.wrapping_mul(evaluated.1),
               BinKind::Xor => evaluated.0 ^ evaluated.1,
               BinKind::And => evaluated.0 & evaluated.1,
               BinKind::Or => evaluated.0 | evaluated.1,
               BinKind::RotL => evaluated.0.rotate_left(evaluated.1.cast_unsigned() & 31),
            }
         },
      }
   }

   /// Number of global reads, used to report how much of the pool a rewrite
   /// actually touches.
   #[inline]
   #[must_use]
   pub fn global_reads(&self) -> usize {
      match *self {
         Self::Const(_) => 0,
         Self::Global(_) => 1,
         Self::Bin(_, ref lhs, ref rhs) => lhs.global_reads() + rhs.global_reads(),
      }
   }
}

/// Builds expressions that evaluate to a requested constant using values
/// already sitting in the global pool.
pub struct Synth<'pool> {
   /// Pool values expressions may read from.
   pool: &'pool [i32],
}

impl<'pool> Synth<'pool> {
   /// Borrows pool values for later synthesis.
   #[inline]
   #[must_use]
   pub const fn new(pool: &'pool [i32]) -> Self {
      Self { pool }
   }

   /// Synthesise an expression equal to `target`.
   ///
   /// Each level combines pool globals with a residual and recurses on that
   /// residual. Callers must check the result against the pool before emission.
   #[inline]
   #[expect(
      clippy::as_conversions,
      clippy::cast_possible_truncation,
      clippy::cast_possible_wrap,
      reason = "below(31) + 1 yields 1..=31 which fits in i32"
   )]
   pub fn build(&self, rng: &mut rng::Rng, target: i32, depth: u32) -> Expr {
      if depth == 0 || self.pool.is_empty() {
         return Expr::Const(target);
      }

      let slot = rng.below(self.pool.len());
      let value = self.pool[slot];
      let global = Expr::Global(slot);

      let (kind, residual) = match rng.below(6) {
         0 => (BinKind::Xor, target ^ value),
         1 => (BinKind::Add, target.wrapping_sub(value)),
         2 => (BinKind::Sub, target.wrapping_add(value)),
         3 => {
            let other = rng.below(self.pool.len());
            let combined = value.wrapping_mul(self.pool[other]);
            return self.wrap(
               rng,
               BinKind::Xor,
               Expr::Bin(
                  BinKind::Mul,
                  Box::new(global),
                  Box::new(Expr::Global(other)),
               ),
               target ^ combined,
               depth,
            );
         },
         4 => {
            let other = rng.below(self.pool.len());
            let combined = value | self.pool[other];
            return self.wrap(
               rng,
               BinKind::Xor,
               Expr::Bin(BinKind::Or, Box::new(global), Box::new(Expr::Global(other))),
               target ^ combined,
               depth,
            );
         },
         _ => {
            let amount = (rng.below(31) + 1) as i32;
            let rotated = value.rotate_left(amount.cast_unsigned());
            return self.wrap(
               rng,
               BinKind::Xor,
               Expr::Bin(
                  BinKind::RotL,
                  Box::new(global),
                  Box::new(Expr::Const(amount)),
               ),
               target ^ rotated,
               depth,
            );
         },
      };

      let rest = self.build(rng, residual, depth - 1);
      match kind {
         // `target - value + value`, so the global is the right operand of the subtraction.
         BinKind::Sub => Expr::Bin(BinKind::Sub, Box::new(rest), Box::new(global)),
         BinKind::Add
         | BinKind::Mul
         | BinKind::Xor
         | BinKind::And
         | BinKind::Or
         | BinKind::RotL => Expr::Bin(kind, Box::new(global), Box::new(rest)),
      }
   }

   /// Rebuilds the residual side of a two-global template.
   #[inline]
   fn wrap(&self, rng: &mut rng::Rng, kind: BinKind, lhs: Expr, residual: i32, depth: u32) -> Expr {
      let rest = self.build(rng, residual, depth - 1);
      Expr::Bin(kind, Box::new(lhs), Box::new(rest))
   }

   /// Returns an expression only if it reads the pool and evaluates to
   /// `target`. Otherwise the caller can keep the original constant.
   #[inline]
   pub fn checked(&self, rng: &mut rng::Rng, target: i32, depth: u32) -> Option<Expr> {
      let expr = self.build(rng, target, depth);
      (expr.eval(self.pool) == target && expr.global_reads() > 0).then_some(expr)
   }

   /// A condition built from a pool global that always evaluates to false.
   #[inline]
   pub fn opaque_false(&self, rng: &mut rng::Rng) -> Option<Expr> {
      if self.pool.is_empty() {
         return None;
      }

      let slot = rng.below(self.pool.len());
      let global = || Box::new(Expr::Global(slot));

      // `x & ~x` remains zero even if the pool changes.
      let expr = Expr::Bin(
         BinKind::And,
         global(),
         Box::new(Expr::Bin(BinKind::Xor, global(), Box::new(Expr::Const(!0)))),
      );

      (expr.eval(self.pool) == 0).then_some(expr)
   }
}
