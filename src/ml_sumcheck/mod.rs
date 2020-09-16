//! Sumcheck protocol for products of multilinear extension.
//!
//! More details can be found in the documentation of [`MLSumcheck`](trait.MLSumcheck.html)

use algebra_core::{CanonicalDeserialize, CanonicalSerialize, Field};

use crate::data_structures::ml_extension::MLExtension;
use algebra_core::vec::Vec;
pub mod t13;

/// ### Sumcheck protocol for products of multilinear functions
/// [Source](https://link.springer.com/chapter/10.1007/978-3-642-40084-1_5)
/// This protocols calculate and prove the sum of a multilinear function with `n` variables over
/// a hypercube of dimension `n` (i.e. {0,1}^n). The arithmetic is performed over finite field `F`.
///
/// * `F`: Field
///
/// ### Example Usage
/// ```
/// use linear_sumcheck::ml_sumcheck::t13::{T13Sumcheck, T13Subclaim}; // an implementation of MLSumcheck
/// use algebra::{test_rng, UniformRand};
/// use linear_sumcheck::ml_sumcheck::{MLSumcheck, MLSumcheckSubclaim};
/// use linear_sumcheck::data_structures::MLExtensionArray;
/// use linear_sumcheck::data_structures::ml_extension::MLExtension;
/// type F = algebra::bls12_377::Fr;  // specify the field. any valid field should work here.
/// // create a degree-7 multilinear polynomial with 5 multiplicands
/// let mut rng = test_rng();
/// let poly: Vec<_> = (0..5).map(|_|{
///     let arr: Vec<_> = (0..(1<<7)).map(|_|F::rand(&mut rng)).collect();
///     MLExtensionArray::from_slice(&arr).unwrap()
/// }).collect();
/// // generate claim and proof
/// let (claim, proof) = T13Sumcheck::generate_claim_and_proof(&poly).unwrap();
///
/// // verify proof
/// let subclaim: T13Subclaim<F>= T13Sumcheck::verify_proof(&claim, &proof).unwrap();
///
/// // verifying the subclaim need access to the polynomial, see documentation
///
/// ```
///
pub trait MLSumcheck<F>
where
    F: Field,
{
    /// Claim of the sum
    type Claim: MLSumcheckClaim<F>;
    /// proof of the claim
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize;
    /// error type
    type Error: algebra_core::Error + From<crate::Error>;
    /// subclaim outputted: if the claim is true, the subclaim should be true
    type SubClaim: MLSumcheckSubclaim<F>;

    /// Calculate the sum of the polynomial and generate the proof.
    /// * `poly`: product of multilinear functions represented by an iterator of multilinear function
    fn generate_claim_and_proof<P: MLExtension<F>>(
        poly: &[P],
    ) -> Result<(Self::Claim, Self::Proof), Self::Error>;

    /// verify if proof correctly proves the claim. Return error if the proof is trivially wrong, or the claim or proof does not
    /// make sense. Return subclaim in the way that the subclaim is true if and only if the original claim is true.
    fn verify_proof(
        claim: &Self::Claim,
        proof: &Self::Proof,
    ) -> Result<Self::SubClaim, Self::Error>;
}

/// Claim of MLSumcheck
pub trait MLSumcheckClaim<F>: Clone + CanonicalSerialize + CanonicalDeserialize {
    /// the asserted sum of the polynomial
    fn asserted_sum(&self) -> F;
    /// number of variables of polynomial
    fn num_variables(&self) -> u32;
    /// number of multiplicands of polynomial
    fn num_multiplicands(&self) -> u32;
}

/// subclaim of the MLSumcheck
///
/// The subclaim consists of a point on the dimension-n hypercube and the expected evaluation of that point
/// in the finite field.
pub trait MLSumcheckSubclaim<F>: Clone + CanonicalSerialize + CanonicalDeserialize {
    /// a point on dimension-n hypercube, where n is the number of variables of the polynomial
    fn evaluation_point(&self) -> Vec<F>;
    /// get expected evaluation on the point in the finite field
    fn expected_evaluations(&self) -> F;
}

#[cfg(all(test, feature="std"))]
pub mod tests {
    use algebra::{test_rng, Field};

    use crate::data_structures::ml_extension::MLExtension;
    use crate::data_structures::MLExtensionArray;
    use crate::ml_sumcheck::{MLSumcheck, MLSumcheckSubclaim};

    pub fn test_ml_proc_completeness<F: Field, S: MLSumcheck<F>>() {
        const NV: usize = 9;
        const NM: usize = 5;
        let mut rng = test_rng();
        let poly: Vec<_> = (0..NM)
            .map(|_| MLExtensionArray::from_slice(&fill_vec!(1 << NV, F::rand(&mut rng))).unwrap())
            .collect();
        let (claim, proof) = S::generate_claim_and_proof(&poly).unwrap();
        let subclaim = S::verify_proof(&claim, &proof).unwrap();

        // verify subclaim
        let expected_evs = poly
            .iter()
            .map(|p| p.eval_at(&subclaim.evaluation_point()))
            .scan(F::one(), |state, x| {
                *state *= x.unwrap();
                Some(*state)
            })
            .last()
            .unwrap();
        assert_eq!(subclaim.expected_evaluations(), expected_evs);
    }
}
