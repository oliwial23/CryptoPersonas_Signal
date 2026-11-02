//! Generic structures and traits for interactions between users, bulletins, and services.
//!
//! This module consists of structures and traits for generic interactions. The most important
//! object is the [`User`](`user::User`) object, which wraps any struct implementing
//! [`UserData`](`user::UserData`). A `User` consists of all the data associated with a user,
//! including the data itself, the nullifier and nonce, and the list of callbacks. The main
//! functions of interest are implemented on top of [`User`](`user::User`), which produce proofs of
//!
//!* Adding callbacks to the user (and performing some method)
//!* Scanning callbacks and checking if they have been called (if so, performing some
//!        method).
//!
//! This are encapsulated within the [`User::interact`](`user::User::interact`) function, which
//! allows users to make a state change while producing a proof.
//!
//! Additionally, this module has traits associated to bulletins and services. This allows for:
//!
//!* Inserting commitments to users in a bulletin.
//!* "Calling" callbacks by posting the callback ticket to a callback bulletin.
//!* Sending a proof with a callback and interacting with a service.
//!

#[cfg(feature = "asynchr")]
#[cfg(any(feature = "asynchr", doc))]
#[doc(cfg(feature = "asynchr"))]
mod asynchr;

/// Traits for implementing bulletins for objects and callbacks.
///
/// This module consists of traits and associated functions for object and callback bulletins.
/// These objects may then be used within any `exec_method_create_cb` or `scan_callback` to produce
/// proofs.
///
/// The public bulletins should be implemented by network handles for user clients. User and
/// callback bulletins can be used by servers to append values and verify proofs.
pub mod bulletin;

/// Objects for tickets and callback commitments.
pub mod callbacks;

/// Objects and structs for folding scans using PSE's Sonobe.
#[cfg(feature = "folding")]
#[cfg(any(feature = "folding", doc))]
#[doc(cfg(feature = "folding"))]
pub mod fold;

/// Structs and abstractions associated with interactions.
///
/// The main objects are [`Callback`](`interaction::Callback`) and
/// [`Interaction`](`interaction::Interaction`). The first captures a generic callback function
/// (note: this is not a ticket). The latter describes an interaction, which includes a method,
/// predicate, and created callback tickets.
pub mod interaction;

/// Types and structs for use within zero knowledge objects.
///
/// These types are used within zk-objects and the callbacks system frequently to ensure users
/// don't "double spend", ensure callback ticket lists are correct, serialize users, associate
/// identification for callback functions, and more. The bookkeeping values are stored within the
/// [`ZKFields`](`object::ZKFields`) struct, which keeps track of all the important cryptography
/// under the hood.
pub mod object;

/// Structs and functions associated to scanning user objects.
///
/// These structs provide the public and private arguments to prove a scan occured. Additionally,
/// this module includes functions to apply a scan and prove a scan has occurred.
pub mod scan;

/// Contains traits and types associated with service providers and services.
///
/// This module consists of the [`ServiceProvider`](`service::ServiceProvider`) trait, which implements necessary functions for
/// services to
///
/// 1. call a callback function (in other words, force an update on a user).
/// 2. Store interactions (when a user makes a post, a service must log that post for future
///    updates).
pub mod service;

/// Contains structs associated to users and results of proofs done on user objects.
///
/// Specifically,
/// this module contains the [`User`](`user::User`) object and the [`UserData`](`user::UserData`) trait, which are integral to the
/// system.
pub mod user;
