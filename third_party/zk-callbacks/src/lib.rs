//! `zk-callbacks` is a generic framework for constructing anonymous reputation systems. It is an
//! implementation of the framework from [zk-Promises](https://eprint.iacr.org/2024/1260), along with some common cryptography primitives and storage systems.
//!
//! The callbacks system consists of generic traits and objects to represent user objects and
//! commitments, callbacks, and bulletins. The generic framework provides a layer by which users
//! can create proofs of method execution and callback scans, and allows arbitrary state in user
//! data. The generic framework is built off of `arkworks` and allows for any base field and proof
//! system supported by arkworks, including `bn254` and `bls12-381`.
//!
//! For additional information, take a look at the documentation and the examples.
//!
//! ## Design
//!
//! zk-callbacks relies on Rust's generic types and trait system, which permits the library to be
//! flexible with bulletins and objects. Data stored within a user object implements
//! the [`UserData`](`generic::user::UserData`) trait. Wrapping such data within a
//! [`User`](`generic::user::User`) object, one can then perform a wide range of functions (make
//! callbacks, scan callbacks, prove methods). The [`User`](`generic::user::User`) object provides
//! all bookkeeping fields within a user object. It maintains a list of callbacks, a nonce,
//! nullifier, and scanning data.
//!
//! Separately, zk-callbacks also holds a host of different bulletin and service traits to check membership,
//! store user objects and callbacks, and store interaction data. For example, a user may interact
//! with a [`ServiceProvider`](`generic::service::ServiceProvider`) by making a forum post, and
//! update their object stored on a [`UserBul`](`generic::bulletin::UserBul`). In the future, the
//! service may then call a callback by interacting with a
//! [`CallbackBul`](`generic::bulletin::CallbackBul`).
//!
//! Outside of the generic types and traits, [`impls`] contains some default and simple implementations of the
//! previous traits and those described in the paper. It contains some implementations of
//! [`UserData`](`generic::user::UserData`) for simple objects, along with some data structures for
//! the bulletins, such as a [`SigObjStore`](`impls::centralized::ds::sigstore::SigObjStore`) and
//! some more cryptography.
//!
//! # Examples
//!
//! For a first example, see `examples/simple.rs`, which gives a walkthrough of a single
//! centralized setting.
//!
//! More examples are coming! (when?)
#![deny(missing_docs)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(associated_type_defaults)]
#![feature(type_alias_impl_trait)]
#![feature(doc_cfg)]
pub mod crypto;
pub mod generic;
pub mod impls;

#[doc(hidden)]
pub mod util;

/// Struct macro to construct in-circuit representations, derive `UserData`, and add necessary
/// implementations for scanning.
///
/// This macro takes in one argument (the field), and a second optional argument (the in-circuit
/// representation). If the second argument is not provided, this macro will construct an
/// in-circuit representation of the structure.
///
/// ```rust
/// use ark_bls12_381::Fr;
/// use zk_callbacks::scannable_zk_object;
///
/// #[scannable_zk_object(Fr)]
/// #[derive(Default)]
/// struct Data {
///     karma: Fr,
///     is_banned: bool,
///     reputation: u8,
/// }
/// ```
///
/// If an in-circuit representation already exists, one may use the additional argument to pass
/// this in.
///
/// ```rust
/// # use ark_bls12_381::Fr;
/// # use zk_callbacks::scannable_zk_object;
/// #
/// # use ark_r1cs_std::{
/// #     alloc::{AllocVar, AllocationMode},
/// #     boolean::Boolean,
/// #     convert::ToConstraintFieldGadget,
/// #     prelude::UInt8,
/// # };
/// # use ark_relations::{
/// #     ns,
/// #     r1cs::{Namespace, SynthesisError},
/// # };
/// # use std::borrow::Borrow;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// #[scannable_zk_object(Fr, DataVar)]
/// #[derive(Default)]
/// struct Data {
///     karma: Fr,
///     is_banned: bool,
///     reputation: u8,
/// }
///
/// #[derive(Clone)]
/// struct DataVar {
///     karma: FpVar<Fr>,
///     is_banned: Boolean<Fr>,
///     reputation: UInt8<Fr>,
/// }
///
/// impl AllocVar<Data, Fr> for DataVar {
///     fn new_variable<K: Borrow<Data>>(
///         cs: impl Into<Namespace<Fr>>,
///         f: impl FnOnce() -> Result<K, SynthesisError>,
///         mode: AllocationMode
///     ) -> Result<Self, SynthesisError> {
///         let ns = cs.into();
///         let cs = ns.cs();
///         let res=  f();
///         res.and_then(|rec| {
///             let rec = rec.borrow();
///             let karma = FpVar::new_variable(ns!(cs, "karma"), || Ok(rec.karma), mode)?;
///             let is_banned = Boolean::new_variable(ns!(cs, "is_banned"), || Ok(rec.is_banned),
///             mode)?;
///
///             Ok(Self {
///                 karma,
///                 is_banned,
///                 reputation: UInt8::constant(0),
///             })
///         })
///     }
/// }
/// ```
pub use zk_object::scannable_zk_object;

/// Struct macro to construct in-circuit representations and derive `UserData`.
///
/// This macro takes in one argument (the field), and a second optional argument (the in-circuit
/// representation). If the second argument is not provided, this macro will construct an
/// in-circuit representation of the structure.
///
/// Do not use this macro if you also need to scan user objects. While this allows for more
/// flexibility with types, these objects will not necessarily implement conditional selection or
/// equality, and therefore they cannot be used when calling `scan_callbacks`.
///
/// ```rust
/// use ark_bls12_381::Fr;
/// use zk_callbacks::zk_object;
///
/// #[zk_object(Fr)]
/// #[derive(Default)]
/// struct Data {
///     karma: Fr,
///     is_banned: bool,
///     reputation: u8,
/// }
/// ```
///
/// If an in-circuit representation already exists, one may use the additional argument to pass
/// this in.
///
/// ```rust
/// # use ark_bls12_381::Fr;
/// # use zk_callbacks::zk_object;
/// #
/// # use ark_r1cs_std::{
/// #     alloc::{AllocVar, AllocationMode},
/// #     boolean::Boolean,
/// #     convert::ToConstraintFieldGadget,
/// #     prelude::UInt8,
/// # };
/// # use ark_relations::{
/// #     ns,
/// #     r1cs::{Namespace, SynthesisError},
/// # };
/// # use std::borrow::Borrow;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// #[zk_object(Fr, DataVar)]
/// #[derive(Default)]
/// struct Data {
///     karma: Fr,
///     is_banned: bool,
///     reputation: u8,
/// }
///
/// #[derive(Clone)]
/// struct DataVar {
///     karma: FpVar<Fr>,
///     is_banned: Boolean<Fr>,
///     reputation: UInt8<Fr>,
/// }
///
/// impl AllocVar<Data, Fr> for DataVar {
///     fn new_variable<K: Borrow<Data>>(
///         cs: impl Into<Namespace<Fr>>,
///         f: impl FnOnce() -> Result<K, SynthesisError>,
///         mode: AllocationMode
///     ) -> Result<Self, SynthesisError> {
///         let ns = cs.into();
///         let cs = ns.cs();
///         let res=  f();
///         res.and_then(|rec| {
///             let rec = rec.borrow();
///             let karma = FpVar::new_variable(ns!(cs, "karma"), || Ok(rec.karma), mode)?;
///             let is_banned = Boolean::new_variable(ns!(cs, "is_banned"), || Ok(rec.is_banned),
///             mode)?;
///
///             Ok(Self {
///                 karma,
///                 is_banned,
///                 reputation: UInt8::constant(0),
///             })
///         })
///     }
/// }
/// ```
pub use zk_object::zk_object;
