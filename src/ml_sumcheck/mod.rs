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
/// # use linear_sumcheck::ml_sumcheck::t13::{T13Sumcheck, T13Subclaim}; // an implementation of MLSumcheck
/// # use algebra::{test_rng, UniformRand};
/// # use linear_sumcheck::ml_sumcheck::{MLSumcheck, MLSumcheckSubclaim};
/// # use linear_sumcheck::data_structures::MLExtensionArray;
/// # use linear_sumcheck::data_structures::ml_extension::MLExtension;
/// # type F = algebra::bls12_377::Fr;  // specify the field. any valid field should work here.
/// # let mut rng = test_rng();
/// // create a 7-variate multilinear polynomial with 5 multiplicands
/// let poly: Vec<_> = (0..5).map(|_|{
///     let arr: Vec<_> = (0..(1<<7)).map(|_|F::rand(&mut rng)).collect();
///     MLExtensionArray::from_slice(&arr).unwrap()
/// }).collect();
/// // create a 7-variate multilinear polynomial with 3 multiplicands
/// let poly2: Vec<_> = (0..3).map(|_|{
///     let arr: Vec<_> = (0..(1<<7)).map(|_|F::rand(&mut rng)).collect();
///     MLExtensionArray::from_slice(&arr).unwrap()
/// }).collect();
/// // generate claim and proof
/// let (claim, proof) = T13Sumcheck::generate_claim_and_proof(&[&poly,&poly2]).unwrap();
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
    /// * `poly`: array of product of multilinear functions represented by an iterator of multilinear function.
    /// the polynomial we want to prove is those products added together.
    fn generate_claim_and_proof<P: MLExtension<F>>(
        poly: &[&[P]],
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
    /// maximum number of multiplicands of polynomial
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

#[cfg(test)]
pub mod tests {
    use crate::data_structures::ml_extension::MLExtension;
    use crate::data_structures::MLExtensionArray;
    use crate::ml_sumcheck::{MLSumcheck, MLSumcheckSubclaim};
    use algebra::{test_rng, Field};
    use ark_std::vec::Vec;

    pub fn test_ml_proc_completeness<F: Field, S: MLSumcheck<F>>() {
        const NV: usize = 9;
        const NM: usize = 5;
        const NM2: usize = 3;
        let mut rng = test_rng();
        let poly: Vec<_> = (0..NM)
            .map(|_| MLExtensionArray::from_slice(&fill_vec!(1 << NV, F::rand(&mut rng))).unwrap())
            .collect();
        let poly2: Vec<_> = (0..NM2)
            .map(|_| MLExtensionArray::from_slice(&fill_vec!(1 << NV, F::rand(&mut rng))).unwrap())
            .collect();
        let (claim, proof) = S::generate_claim_and_proof(&[&poly, &poly2]).unwrap();
        let subclaim = S::verify_proof(&claim, &proof).unwrap();

        // verify subclaim
        let expected_evs = eval_pmf(&poly, &subclaim.evaluation_point())
            + eval_pmf(&poly2, &subclaim.evaluation_point());
        assert_eq!(subclaim.expected_evaluations(), expected_evs);
    }

    fn eval_pmf<F: Field>(pmf: &[MLExtensionArray<F>], at: &[F]) -> F {
        pmf.iter()
            .map(|p| p.eval_at(at))
            .scan(F::one(), |state, x| {
                *state *= x.unwrap();
                Some(*state)
            })
            .last()
            .unwrap()
    }
}
