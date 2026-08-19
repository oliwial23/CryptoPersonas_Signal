//! Core of the Cryptographic Personas system: shared type aliases, all
//! zk circuits/predicates, persona derivation, server parameter generation with a
//! disk cache, and the benchmark instrumentation both sides write to.

pub mod circuits;
pub mod params;
pub mod persona;
pub mod privpass;
pub mod timing;
pub mod types;

pub use types::*;
