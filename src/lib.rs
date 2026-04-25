use plonky2::iop::target::Target;

pub mod builder;
pub mod circuit_utils;
pub mod generators;
pub mod hook;
// SECURITY NOTE: the `keccak_stark` module (and the
// `generators::stark_proof_generator`) have not yet been migrated to plonky2
// 1.x's starky API (CTL flow, prove/verify signatures, StarkProofTarget gained
// a `degree_bits` field). They are gated behind `cfg(not(feature =
// "not-constrain-keccak"))` so consumers that opt out of the STARK constraint
// can still use the gadget API (`BuilderKeccak256`, `solidity_keccak256`).
//
// Building with the STARK constraint enabled (the default) requires the legacy
// 0.2.x starky and currently fails on this branch — the migration is tracked
// upstream.
#[cfg(not(feature = "not-constrain-keccak"))]
pub mod keccak_stark;
pub mod utils;

pub type U32Target = Target;
