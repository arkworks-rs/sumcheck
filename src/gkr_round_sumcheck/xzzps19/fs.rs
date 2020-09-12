use std::marker::PhantomData;

use algebra::io::{Read, Write};
use algebra::{CanonicalDeserialize, CanonicalSerialize, Field, SerializationError};

use crate::data_structures::ml_extension::{MLExtension, SparseMLExtension};
use crate::data_structures::protocol::Protocol;
use crate::data_structures::random::{FeedableRNG, RnFg};
use crate::data_structures::{Blake2s512Rng, GKRAsLink};
use crate::gkr_round_sumcheck::xzzps19::msg::{XZZPS19PMsg, XZZPS19VMsg};
use crate::gkr_round_sumcheck::xzzps19::{XZZPS19Prover, XZZPS19Verifier};
use crate::gkr_round_sumcheck::{
    GKRFuncVerifierSubclaim, GKRRoundClaim, GKRRoundProof, GKRRoundSubClaim, GKRRoundSumcheck,
    Prover, Verifier,
};

/// Linear GKRFunction Sumcheck Protocol introduced by Xie et.al
pub struct XZZPS19Sumcheck<F: Field, S: SparseMLExtension<F>, D: MLExtension<F>> {
    _marker: PhantomData<(F, S, D)>,
}

impl<F, S, D> GKRRoundSumcheck<F, S, D> for XZZPS19Sumcheck<F, S, D>
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    type Claim = XZZPS19Claim<F>;
    type Proof = XZZPS19Proof<F>;
    type Error = crate::Error;
    type SubClaim = XZZPS19SubClaim<F>;

    fn generate_claim(f1: &S, f2: &D, f3: &D, g: &[F]) -> Result<Self::Claim, Self::Error> {
        let gkr = unwrap_safe!(GKRAsLink::new(f1, f2, f3));
        let prover = unwrap_safe!(XZZPS19Prover::setup(&gkr, g));
        Ok(Self::Claim {
            dim: g.len() as u32,
            sum: prover.get_sum(),
            g: g.to_vec(),
        })
    }

    fn generate_claim_and_proof(
        f1: &S,
        f2: &D,
        f3: &D,
        g: &[F],
    ) -> Result<(Self::Claim, Self::Proof), Self::Error> {
        let gkr = unwrap_safe!(GKRAsLink::new(f1, f2, f3));
        let mut prover = unwrap_safe!(XZZPS19Prover::setup(&gkr, g));

        let mut prng = Blake2s512Rng::setup();
        unwrap_safe!(prng.feed(&g));
        unwrap_safe!(prng.feed(&prover.get_sum()));

        let mut messages = Vec::new();
        while prover.is_active() {
            let msg = unwrap_safe!(prover.get_latest_message());
            unwrap_safe!(prng.feed(&msg));
            messages.push(msg);
            let r = XZZPS19VMsg::<F> {
                x: prng.random_field(),
            };
            unwrap_safe!(prover.push_message(&r));
        }
        messages.push(unwrap_safe!(prover.get_latest_message()));

        let proof = Self::Proof {
            prover_msgs: messages,
        };
        let theorem = Self::Claim {
            g: g.to_vec(),
            sum: prover.get_sum(),
            dim: g.len() as u32,
        };
        Ok((theorem, proof))
    }

    fn verify_proof(
        theorem: &Self::Claim,
        proof: &Self::Proof,
    ) -> Result<Self::SubClaim, Self::Error> {
        let prng = Blake2s512Rng::setup();
        let verifier = XZZPS19Verifier::setup(&theorem.g, prng, theorem.sum);
        let mut verifier = unwrap_safe!(verifier);

        for msg in &proof.prover_msgs {
            unwrap_safe!(verifier.push_message(msg))
        }

        let dim = theorem.g.len();
        let subclaim = unwrap_safe!(verifier.get_sub_claim());
        let point = subclaim.point();
        Ok(Self::SubClaim {
            ev: subclaim.should_evaluate_to(),
            x: (&point[..dim]).to_vec(),
            y: (&point[dim..]).to_vec(),
        })
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
/// Theorem used for XZZPS19 gkr function linear sumcheck
pub struct XZZPS19Claim<F: Field> {
    g: Vec<F>,
    dim: u32,
    sum: F,
}

impl<F: Field> GKRRoundClaim<F> for XZZPS19Claim<F> {
    fn g(&self) -> Vec<F> {
        self.g.to_vec()
    }

    fn dim(&self) -> u32 {
        self.dim
    }

    fn asserted_sum(&self) -> F {
        self.sum
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
/// Proof of XZZPS19 gkr function sumcheck
pub struct XZZPS19Proof<F: Field> {
    prover_msgs: Vec<XZZPS19PMsg<F>>,
}

impl<F: Field> GKRRoundProof for XZZPS19Proof<F> {
    //
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
/// Subclaim of gkr function sumcheck
pub struct XZZPS19SubClaim<F: Field> {
    x: Vec<F>,
    y: Vec<F>,
    ev: F,
}

impl<F: Field> GKRRoundSubClaim<F> for XZZPS19SubClaim<F> {
    fn x(&self) -> Vec<F> {
        self.x.to_vec()
    }

    fn y(&self) -> Vec<F> {
        self.y.to_vec()
    }

    fn expected_evaluation(&self) -> F {
        self.ev
    }
}

#[cfg(test)]
mod tests {
    use algebra::{test_rng, UniformRand};

    use crate::data_structures::test_field::TestField;
    use crate::data_structures::tests::random_sparse_poly_fast;
    use crate::data_structures::MLExtensionRefArray;
    use crate::gkr_round_sumcheck::tests::test_gkr_func_proc_completeness;
    use crate::gkr_round_sumcheck::xzzps19::XZZPS19Sumcheck;

    type F = TestField;

    #[test]
    fn test_completeness() {
        const DIM: usize = 15;
        let mut rng = test_rng();
        let f1 = random_sparse_poly_fast(3 * DIM, &mut rng);
        let f2_arr = fill_vec!(1 << DIM, F::rand(&mut rng));
        let f2 = MLExtensionRefArray::from_slice(&f2_arr).unwrap();
        let f3_arr = fill_vec!(1 << DIM, F::rand(&mut rng));
        let f3 = MLExtensionRefArray::from_slice(&f3_arr).unwrap();
        let g = fill_vec!(DIM, F::rand(&mut rng));
        test_gkr_func_proc_completeness::<_, _, _, XZZPS19Sumcheck<_, _, _>>(&f1, &f2, &f3, &g)
            .unwrap();
    }
}
