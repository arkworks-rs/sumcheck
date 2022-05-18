//! Interactive Proof Protocol used for Multilinear Sumcheck

use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

pub mod prover;
pub mod verifier;
pub use crate::ml_sumcheck::data_structures::{ListOfProductsOfPolynomials, PolynomialInfo};
/// Interactive Proof for Multilinear Sumcheck
pub struct IPForMLSumcheck<F: PrimeField> {
    #[doc(hidden)]
    _marker: PhantomData<F>,
}
