/// Signatures with in-circuit verification.
pub mod sig;

/// A range store which is signed for nonmembership proofs.
pub mod sigrange;

/// A signature store. One can verify membership through proof of knowledge of a signature from the
/// service.
pub mod sigstore;
