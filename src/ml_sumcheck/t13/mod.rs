//!Implementation of linear sumcheck by Thaler '13
//!
//! [Source](https://link.springer.com/chapter/10.1007/978-3-642-40084-1_5)

pub use fs::*;
pub(crate) use prover::*;
pub(crate) use verifier::*;

mod fs;
mod msg;
mod prover;
mod verifier;
