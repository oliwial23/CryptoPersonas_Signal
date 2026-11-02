/// The necessary cryptography for callback tickets in a centralized setting.
///
/// When a service
/// provider also controls the bulletins, no signing is necessary.
pub mod crypto;

/// Data structures in the centralized setting.
pub mod ds;
