//! AHP protocol for multilinear sumcheck

use ark_ff::Field;
use ark_std::marker::PhantomData;

pub mod indexer;
pub mod prover;
pub mod verifier;

/// Algebraic Holographic Proof defined in [T13](https://eprint.iacr.org/2013/351).
pub struct AHPForMLSumcheck<F: Field> {
    #[doc(hidden)]
    _marker: PhantomData<F>,
}
