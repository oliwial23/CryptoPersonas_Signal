//! Specific implementations of bulletins, cryptography, and user objects.
//!
//! This module contains of mainly different structures for storing user objects and callback
//! tickets with efficient proofs.
//!
//! Additionally, this module has some specific cryptography implementations which can be used
//! within the system.

/// Structures for centralized storage and services.
pub mod centralized;

/// Structures for decentralized storage and services.
pub mod decentralized;

/// Testing "dummy" object and callback storage to test bulletin and proof code.
pub mod dummy;
/// Objects that implement [`HasherZK`](`super::crypto::hash::HasherZK`).
pub mod hash;
#[doc(hidden)]
pub mod userdata;
