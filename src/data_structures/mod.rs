//!
//!
//! The `data_structures` module mainly consists of representations of polynomials.
//!
//! This module provides traits that the sumcheck protocol accept as input, and provides
//! several common implementations of those traits for convenience. In practice, users
//! might need to implement the traits by themselves.
//!
//! For example, user might implement `MLExtension` as a reference to their own GKR circuit,
//! so that the sumcheck protocol does not need to copy the data.
//!

pub use impl_ml_extension::{
    GKRAsLink, MLExtensionArray, MLExtensionRefArray, SparseMLExtensionHashMap,
};
/// some test helpers
#[cfg(test)]
pub use impl_ml_extension::tests;
pub use impl_random::{AsDummyFeedable, Blake2s512Rng};

/// traits of data representations of multilinear extensions
pub mod ml_extension;

/// protocol
pub(crate) mod protocol;

/// high-level abstraction of randomness
pub mod random;

// mod impl_log_gkr_mask;
/// implementation of multilinear extensions
mod impl_ml_extension;
/// implementation of random
mod impl_random;
/// mask used by gkr prover for zero knowledge proof
// pub mod mask;
/// field (used only for testing)
#[cfg(test)]
pub mod test_field;
