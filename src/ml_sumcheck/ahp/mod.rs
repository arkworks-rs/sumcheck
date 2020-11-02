//! AHP protocol for multilinear sumcheck

use ark_ff::Field;
use ark_std::marker::PhantomData;

pub mod prover;
pub mod verifier;
pub mod indexer;

/// Algebraic Holographic Proof defined in [T13](https://link.springer.com/chapter/10.1007/978-3-642-40084-1_5).
pub struct AHPForMLSumcheck<F: Field> {
    #[doc(hidden)] _marker: PhantomData<F>
}


