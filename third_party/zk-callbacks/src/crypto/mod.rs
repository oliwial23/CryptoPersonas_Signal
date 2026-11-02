//! Generic traits for cryptographic primitives.
//!
//! This module provides generic traits for specific cryptographic primitives necessary to the
//! system. For example, zk-callbacks relies on rerandomizable public keys for callbacks, along
//! with IND-CPA encryption (which can also be done in zero-knowledge).

/// Traits for IND-CPA encryption and authenticated encryption with signatures.
pub mod enc;

/// Traits for hashing in zero knowledge.
pub mod hash;

/// Traits for public key rerandomizable signatures.
pub mod rr;
