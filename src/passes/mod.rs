//! Transformation passes applied to the module in pipeline order.

/// Encrypted segments and their early decryption calls.
pub mod data_enc;
/// Control flow flattening through dispatch loops.
pub mod flatten;
/// Direct calls rewritten as table dispatches.
pub mod indirect;
/// Constants replaced with marker pool arithmetic.
pub mod markers;
/// Never taken branches at sequence entries.
pub mod opaque;
