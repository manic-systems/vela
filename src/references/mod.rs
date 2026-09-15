/// Walrus labels retain their stack signatures when reached by branches.
mod flow;
/// Locals belong to an invocation while operand values cross block boundaries.
mod frame;
/// Direct calls share summaries without sharing their caller's local state.
pub mod solver;
/// Finite alternatives bound loop convergence without assuming a particular
/// path.
mod value;
