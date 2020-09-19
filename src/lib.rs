#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
//! A crate for sum-check protocol of GKR functions
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, private_in_public, variant_size_differences)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_mut)]
#![deny(missing_docs)]
#![deny(unused_imports)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use, const_err)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub use error::Error;

/// macros
#[macro_use]
mod macros;

/// error for this crate
mod error;

pub mod gkr_round_sumcheck;

pub mod ml_sumcheck;

/// data structures
pub mod data_structures;


#[cfg(test)]
mod tests {}
