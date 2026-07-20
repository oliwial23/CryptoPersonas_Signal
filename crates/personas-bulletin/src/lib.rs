//! Bulletin-board implementations for the Cryptographic Personas system.
//!
//! A bulletin is what zk-callbacks proves membership against: the object bulletin
//! (registered user commitments) and the callback bulletin (posted callback tickets).
//! [`http::BulNet`] is the as-a-service bulletin — a thin HTTP view onto the server's
//! centralized store.

pub mod http;
pub mod merkle;
pub mod replica;

pub use http::BulNet;
pub use merkle::{MerkleObjStore, MerklePath};
