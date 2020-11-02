//! Verifier
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use crate::ml_sumcheck::ahp::AHPForMLSumcheck;
use rand_core::RngCore;
use crate::ml_sumcheck::ahp::indexer::IndexInfo;
use crate::ml_sumcheck::ahp::prover::ProverMsg;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
/// Verifier Message
pub struct VerifierMsg<F: Field> {
    /// randomness sampled by verifier
    pub randomness: F
}

/// Verifier State
pub struct VerifierState<F: Field> {
    expected: F,
    convinced: bool,
    round: usize,
    nv: usize,
    fixed_args: Vec<F>
}
/// Subclaim when verifier is convinced
pub struct SubClaim<F: Field> {
    /// the multi-dimensional point that this multilinear extension is evaluated to
    pub point: Vec<F>,
    /// the expected evaluation
    pub expected_evaluation: F
}

impl<F: Field> AHPForMLSumcheck<F> {
    /// initialize the verifier
    pub fn verifier_init(index_info: &IndexInfo, asserted_sum: F)
        -> VerifierState<F> {
        VerifierState{
            expected: asserted_sum,
            convinced: false,
            round: 1,
            nv: index_info.num_variables,
            fixed_args: Vec::with_capacity(index_info.num_variables)
        }
    }
    
    /// perform verification at current round, given prover message
    pub fn verify_round<R: RngCore>(prover_msg: &ProverMsg<F>, mut verifier_state: VerifierState<F> ,rng: &mut R)
        -> Result<(Option<VerifierMsg<F>>, VerifierState<F>), crate::Error>{

        if verifier_state.convinced {
            return Err(crate::Error::InvalidOperationError(Some("Verifier is not in active state.".into())));
        }

        let p0 = prover_msg
            .evaluations
            .get(0)
            .ok_or_else(|| crate::Error::InvalidArgumentError(Some(
                "invalid message length".into()
            )))?;

        let p1 = prover_msg
            .evaluations
            .get(1)
            .ok_or_else(|| crate::Error::InvalidArgumentError(Some(
                "invalid message length".into()
            )))?;

        if *p0 + *p1 != verifier_state.expected {
            return Err(crate::Error::Reject(Some("invalid sum".into())));
        }

        let r = F::rand(rng);

        verifier_state.expected = interpolate_deg_n_poly(&prover_msg.evaluations, r);
        verifier_state.fixed_args.push(r);

        if verifier_state.round == verifier_state.nv {
            // accept and close
            verifier_state.convinced = true;
            Ok(
                (None, verifier_state)
            )
        }else{
            verifier_state.round += 1;
            Ok(
                (Some(VerifierMsg{randomness: r}), verifier_state)
            )
        }
    }

    /// get the subclaim when the verifier has convinced the sum
    pub fn subclaim(verifier_state: VerifierState<F>) -> Result<SubClaim<F>, crate::Error>{
        if !verifier_state.convinced {
            return Err(crate::Error::InvalidOperationError(Some("Verifier has not convinced. ".into())));
        }
        return Ok(
            SubClaim{
                point: verifier_state.fixed_args,
                expected_evaluation: verifier_state.expected
            }
        )
    }
    
    /// simulate a verifier message without doing verification
    /// 
    /// Given the same calling context, `random_oracle_round` output exactly the same message as 
    /// `verify_round`
    #[inline]
    pub fn random_oracle_round<R: RngCore>(rng: &mut R) -> VerifierMsg<F> {
        VerifierMsg{randomness: F::rand(rng)}
    } 

}

pub(crate) fn interpolate_deg_n_poly<F: Field>(p_i: &[F], eval_at: F) -> F {
    let mut result = F::zero();
    let mut i = F::zero();
    for term in p_i.iter() {
        let mut term = *term;
        let mut j = F::zero();
        for _ in 0..p_i.len() {
            if j != i {
                term = term * (eval_at - j) / (i - j)
            }
            j += F::one();
        }
        i += F::one();
        result += term;
    }

    result
}