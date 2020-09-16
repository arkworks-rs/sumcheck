//! Sumcheck Protocol for GKR Round Function.
//!
//! More details can be found in the documentation of [`GKRRoundSumcheck`](trait.GKRRoundSumcheck.html).

use algebra_core::{CanonicalDeserialize, CanonicalSerialize, Field};

pub(crate) use prover::Prover;
pub(crate) use verifier::{GKRFuncVerifierSubclaim, Verifier};

use crate::data_structures::ml_extension::{MLExtension, SparseMLExtension};

pub mod xzzps19;

/// Interactive Prover Trait
pub(crate) mod prover;
/// Interactive Verifier Trait
pub(crate) mod verifier;

/// #### Sumcheck protocol for GKR Round Functions
///
/// GKR round function is of form `f1(g,x,y)*f2(x)*f3(y)` with dimension `L`.
/// `g`,`x`,`y` is a vector of length `L`, where `g` is fixed. `f1`'s domain is a hypercube of
/// dimension `3L` on finite field `F`. `f2`,`f3` are polynomials whose domains are
/// a hypercube of dimension `L` on finite field `F`.
///
///
/// * `F`: Field
/// * `S`: Data representation of sparse multilinear extension
/// * `D`: Data representation of dense multilinear extension
pub trait GKRRoundSumcheck<F, S, D>
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    /// The asserted sum of the GKR function when `g` is fixed at a given value.
    type Claim: GKRRoundClaim<F>;
    /// The proof of the claim that can be verified offline.
    type Proof: GKRRoundProof;
    /// type of Error
    type Error: algebra_core::Error + From<crate::Error>;
    /// The output of the function `verify_proof`. If the claim is true, then the subclaim must be true.
    type SubClaim: GKRRoundSubClaim<F>;
    /// Given the GKR function and fixed point `g`, calculate the sum and generate a claim of the sum.
    /// * `f1`: component of GKR round function     
    /// * `f2`: component of GKR round function
    /// * `f3`: component of GKR round function
    /// `g`: fixed point
    fn generate_claim(f1: &S, f2: &D, f3: &D, g: &[F]) -> Result<Self::Claim, Self::Error>;
    /// Given the GKR function and fixed point `g`, calculate the sum, generate a claim of the sum,
    /// and generate a proof of this claim.
    /// * `f1`: component of GKR round function     
    /// * `f2`: component of GKR round function
    /// * `f3`: component of GKR round function
    /// `g`: fixed point
    fn generate_claim_and_proof(
        f1: &S,
        f2: &D,
        f3: &D,
        g: &[F],
    ) -> Result<(Self::Claim, Self::Proof), Self::Error>;
    /// Given the claim and proof, verify if the claim is correct. Note that the verifier
    /// does not need to access the GKR. Instead, the function outputs a subclaim. [`Verifying the subclaim`](#method.verify_subclaim)
    /// requires one evaluation of the GKR function.
    fn verify_proof(
        claim: &Self::Claim, //claim
        proof: &Self::Proof,
    ) -> Result<Self::SubClaim, Self::Error>;
    /// verify the subclaim, using one oracle access to the gkr function. If the claim is true, this function will return true.
    fn verify_subclaim(
        f1: &S,
        f2: &D,
        f3: &D,
        claim: &Self::Claim,
        subclaim: &Self::SubClaim,
    ) -> Result<bool, crate::Error> {
        let g = claim.g();
        let _dim = g.len();
        let mut gxy = Vec::new();
        gxy.extend_from_slice(&g);
        gxy.extend_from_slice(&subclaim.x());
        gxy.extend_from_slice(&subclaim.y());

        let f1_ev = unwrap_safe!(f1.eval_at(&gxy));
        let f2_ev = unwrap_safe!(f2.eval_at(&subclaim.x()));
        let f3_ev = unwrap_safe!(f3.eval_at(&subclaim.y()));

        Ok(f1_ev * f2_ev * f3_ev == subclaim.expected_evaluation())
    }
}

/// fixed point g, and the sum of the GKR round function.
pub trait GKRRoundClaim<F: Field>: Clone + CanonicalSerialize + CanonicalDeserialize {
    /// a vector representing fixed point g on the hypercube
    fn g(&self) -> Vec<F>;
    /// the dimension of the GKR function to be proved (number variables of g)
    fn dim(&self) -> u32;
    /// asserted sum of the GKR round function when g is fixed
    fn asserted_sum(&self) -> F;
}

/// proof of the GKRFuncTheorem
pub trait GKRRoundProof: Clone + CanonicalSerialize + CanonicalDeserialize {
    // nothing required
}

/// subclaim: point and evaluation of that GKR
pub trait GKRRoundSubClaim<F: Field>: Clone + CanonicalSerialize + CanonicalDeserialize {
    /// a vector representing a point on hypercube. `x` corresponds to `x` in the [GKR Function](trait.GKRRoundSumcheck.html)
    fn x(&self) -> Vec<F>;
    /// a vector representing a point on hypercube. `y` corresponds to `y` in the [GKR Function](trait.GKRRoundSumcheck.html)
    fn y(&self) -> Vec<F>;
    /// what GKR(g, x, y) should evaluate to
    fn expected_evaluation(&self) -> F;
}

#[cfg(test)]
pub mod tests {
    use algebra::Field;

    use crate::data_structures::ml_extension::{MLExtension, SparseMLExtension};
    use crate::gkr_round_sumcheck::GKRRoundSumcheck;

    pub fn test_gkr_func_proc_completeness<
        F: Field,
        S: SparseMLExtension<F>,
        D: MLExtension<F>,
        P: GKRRoundSumcheck<F, S, D>,
    >(
        f1: &S,
        f2: &D,
        f3: &D,
        g: &[F],
    ) -> Result<(), crate::Error> {
        let (claim, proof) = unwrap_safe!(timeit!(P::generate_claim_and_proof(f1, f2, f3, g)));
        let subclaim = unwrap_safe!(timeit!(P::verify_proof(&claim, &proof)));

        let state = unwrap_safe!(timeit!(P::verify_subclaim(f1, f2, f3, &claim, &subclaim)));

        if !state {
            return Err(crate::Error::Reject(Some(
                "Fail to verify subclaim. ".to_string(),
            )));
        };
        Ok(())
    }
}
