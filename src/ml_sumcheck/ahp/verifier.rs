//! Verifier
use crate::error::invalid_args;
use crate::ml_sumcheck::ahp::indexer::IndexInfo;
use crate::ml_sumcheck::ahp::prover::ProverMsg;
use crate::ml_sumcheck::ahp::AHPForMLSumcheck;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::vec::Vec;
use rand_core::RngCore;
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
/// Verifier Message
pub struct VerifierMsg<F: Field> {
    /// randomness sampled by verifier
    pub randomness: F,
}

/// Verifier State
pub struct VerifierState<F: Field> {
    round: usize,
    nv: usize,
    max_multiplicands: usize,
    finished: bool,
    lagrange_sets: Vec<Vec<F>>,
    randomness: Vec<F>,
}
/// Subclaim when verifier is convinced
pub struct SubClaim<F: Field> {
    /// the multi-dimensional point that this multilinear extension is evaluated to
    pub point: Vec<F>,
    /// the expected evaluation
    pub expected_evaluation: F,
}

impl<F: Field> AHPForMLSumcheck<F> {
    /// initialize the verifier
    pub fn verifier_init(index_info: &IndexInfo) -> VerifierState<F> {
        VerifierState {
            round: 1,
            nv: index_info.num_variables,
            max_multiplicands: index_info.max_multiplicands,
            finished: false,
            lagrange_sets: Vec::with_capacity(index_info.num_variables),
            randomness: Vec::with_capacity(index_info.num_variables),
        }
    }

    /// perform verification at current round, given prover message
    pub fn verify_round<R: RngCore>(
        prover_msg: ProverMsg<F>,
        mut verifier_state: VerifierState<F>,
        rng: &mut R,
    ) -> Result<(Option<VerifierMsg<F>>, VerifierState<F>), crate::Error> {
        if verifier_state.finished {
            return Err(crate::Error::InvalidOperationError(Some(
                "Verifier is already finished.".into(),
            )));
        }
        // commented out code is part of verification, which will be performed when verifying the subclaim

        // let p0 = prover_msg.evaluations.get(0).ok_or_else(|| {
        //     crate::Error::InvalidArgumentError(Some("invalid message length".into()))
        // })?;
        //
        // let p1 = prover_msg.evaluations.get(1).ok_or_else(|| {
        //     crate::Error::InvalidArgumentError(Some("invalid message length".into()))
        // })?;

        // if *p0 + *p1 != verifier_state.expected {
        //     return Err(crate::Error::Reject(Some("invalid sum".into())));
        // }

        let msg = Self::sample_round(rng);
        verifier_state.randomness.push(msg.randomness);
        verifier_state.lagrange_sets.push(prover_msg.evaluations);

        // verifier_state.expected = interpolate_deg_n_poly(&prover_msg.evaluations, r);
        // verifier_state.fixed_args.push(r);

        if verifier_state.round == verifier_state.nv {
            // accept and close
            verifier_state.finished = true;
        } else {
            verifier_state.round += 1;
        }
        Ok((Some(msg), verifier_state))
    }

    /// verify the sumcheck phase, and generate the subclaim
    ///
    /// subclaim is true if and only if the asserted sum is true
    pub fn check_and_generate_subclaim(
        verifier_state: VerifierState<F>,
        asserted_sum: F,
    ) -> Result<SubClaim<F>, crate::Error> {
        if !verifier_state.finished {
            return Err(crate::Error::InvalidOperationError(Some(
                "Verifier has not finished. ".into(),
            )));
        }

        let mut expected = asserted_sum;
        if verifier_state.lagrange_sets.len() != verifier_state.nv {
            return Err(invalid_args("insufficient rounds"));
        }
        for i in 0..verifier_state.nv {
            let evaluations = &verifier_state.lagrange_sets[i];
            if evaluations.len() != verifier_state.max_multiplicands + 1 {
                return Err(invalid_args("incorrect number of evaluations"));
            }
            let p0 = evaluations[0];
            let p1 = evaluations[1];
            if p0 + p1 != expected {
                return Err(crate::Error::Reject(Some("broken midway".into())));
            }
            expected = interpolate_deg_n_poly(evaluations, verifier_state.randomness[i]);
        }

        return Ok(SubClaim {
            point: verifier_state.randomness,
            expected_evaluation: expected,
        });
    }

    /// simulate a verifier message without doing verification
    ///
    /// Given the same calling context, `random_oracle_round` output exactly the same message as
    /// `verify_round`
    #[inline]
    pub fn sample_round<R: RngCore>(rng: &mut R) -> VerifierMsg<F> {
        VerifierMsg {
            randomness: F::rand(rng),
        }
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
