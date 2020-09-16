use std::marker::PhantomData;

use algebra_core::Field;
use algebra_core::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

use crate::data_structures::ml_extension::MLExtension;
use crate::data_structures::protocol::Protocol;
use crate::data_structures::random::{FeedableRNG, RnFg};
use crate::data_structures::Blake2s512Rng;
use crate::ml_sumcheck::t13::msg::{MLLibraPMsg, MLLibraVMsg};
use crate::ml_sumcheck::t13::{MLLibraProver, MLLibraVerifier};
use crate::ml_sumcheck::{MLSumcheck, MLSumcheckClaim, MLSumcheckSubclaim};

/// `thaler13` implementation of sumcheck protocol of product of multilinear functions
pub struct T13Sumcheck<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> MLSumcheck<F> for T13Sumcheck<F> {
    type Claim = T13Claim<F>;
    type Proof = T13Proof<F>;
    type Error = crate::Error;
    type SubClaim = T13Subclaim<F>;

    fn generate_claim_and_proof<P: MLExtension<F>>(
        poly: &[P],
    ) -> Result<(Self::Claim, Self::Proof), Self::Error> {
        let mut prover = unwrap_safe!(MLLibraProver::setup(poly));
        let mut messages = Vec::with_capacity(unwrap_safe!(poly[0].num_variables()));
        let mut rng = Blake2s512Rng::setup();
        while prover.is_active() {
            let msg = prover.get_latest_message();
            let msg = unwrap_safe!(msg);
            messages.push(msg.clone());
            unwrap_safe!(rng.feed(&msg));
            let v_msg = MLLibraVMsg {
                x: rng.random_field(),
            };
            unwrap_safe!(prover.push_message(&v_msg));
        }

        let gen_sum: F = {
            let m = prover.get_message(1).unwrap(); // should be ok
            m.evaluations[0] + m.evaluations[1]
        };

        let claim = Self::Claim {
            num_variables: poly[0].num_variables().unwrap() as u32,
            num_multiplicands: poly.len() as u32,
            sum: gen_sum,
        };
        let proof = Self::Proof {
            prover_messages: messages,
        };
        Ok((claim, proof))
    }

    fn verify_proof(
        claim: &Self::Claim,
        proof: &Self::Proof,
    ) -> Result<Self::SubClaim, Self::Error> {
        let verifier =
            MLLibraVerifier::setup(claim.num_variables, claim.sum, Blake2s512Rng::setup());
        let mut verifier: MLLibraVerifier<_, _> = unwrap_safe!(verifier);
        for msg in &proof.prover_messages {
            unwrap_safe!(verifier.push_message(msg));
        }

        let ev = unwrap_safe!(verifier.subclaim_evaluation_at_fixed_point());
        let fixed_arg = unwrap_safe!(verifier.subclaim_fixed_args());
        Ok(Self::SubClaim {
            fixed_arguments: fixed_arg,
            evaluation: ev,
        })
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
/// Main claim of t13 ML sumcheck
pub struct T13Claim<F: Field> {
    sum: F,
    num_variables: u32,
    num_multiplicands: u32,
}

impl<F: Field> MLSumcheckClaim<F> for T13Claim<F> {
    fn asserted_sum(&self) -> F {
        self.sum
    }

    fn num_variables(&self) -> u32 {
        self.num_variables
    }

    fn num_multiplicands(&self) -> u32 {
        self.num_multiplicands
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
/// Proof of T13 ML Claim
pub struct T13Proof<F: Field> {
    prover_messages: Vec<MLLibraPMsg<F>>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
/// Subclaim of T13 Verifier
pub struct T13Subclaim<F: Field> {
    fixed_arguments: Vec<F>,
    evaluation: F,
}

impl<F: Field> MLSumcheckSubclaim<F> for T13Subclaim<F> {
    fn evaluation_point(&self) -> Vec<F> {
        self.fixed_arguments.to_vec()
    }

    fn expected_evaluations(&self) -> F {
        self.evaluation
    }
}

#[cfg(test)]
mod tests {
    use crate::data_structures::test_field::TestField;
    use crate::ml_sumcheck::t13::fs::T13Sumcheck;
    use crate::ml_sumcheck::tests::test_ml_proc_completeness;

    #[test]
    fn test_comp() {
        test_ml_proc_completeness::<TestField, T13Sumcheck<TestField>>();
    }
}
