//! Count Sumcheck Protocol

/// Data structures for Count Sumcheck
pub mod data_structures;
/// The Count Sumcheck protocol
pub mod sumcheck;
/// End to End test for Count Sumcheck
#[cfg(test)]
mod test;
/// SRS construction and Key generation for Count Sumcheck
pub mod trusted_setup;
/// Common functions for Count Sumcheck
pub mod utils;
