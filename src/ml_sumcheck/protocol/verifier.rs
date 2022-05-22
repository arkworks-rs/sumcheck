//! Verifier
use crate::ml_sumcheck::data_structures::PolynomialInfo;
use crate::ml_sumcheck::protocol::prover::ProverMsg;
use crate::ml_sumcheck::protocol::IPForMLSumcheck;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::rand::RngCore;
use ark_std::vec::Vec;

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
    /// a list storing the univariate polynomial in evaluation form sent by the prover at each round
    polynomials_received: Vec<Vec<F>>,
    /// a list storing the randomness sampled by the verifier at each round
    randomness: Vec<F>,
}
/// Subclaim when verifier is convinced
pub struct SubClaim<F: Field> {
    /// the multi-dimensional point that this multilinear extension is evaluated to
    pub point: Vec<F>,
    /// the expected evaluation
    pub expected_evaluation: F,
}

impl<F: Field> IPForMLSumcheck<F> {
    /// initialize the verifier
    pub fn verifier_init(index_info: &PolynomialInfo) -> VerifierState<F> {
        VerifierState {
            round: 1,
            nv: index_info.num_variables,
            max_multiplicands: index_info.max_multiplicands,
            finished: false,
            polynomials_received: Vec::with_capacity(index_info.num_variables),
            randomness: Vec::with_capacity(index_info.num_variables),
        }
    }

    /// Run verifier at current round, given prover message
    ///
    /// Normally, this function should perform actual verification. Instead, `verify_round` only samples
    /// and stores randomness and perform verifications altogether in `check_and_generate_subclaim` at
    /// the last step.
    pub fn verify_round<R: RngCore>(
        prover_msg: ProverMsg<F>,
        verifier_state: &mut VerifierState<F>,
        rng: &mut R,
    ) -> Option<VerifierMsg<F>> {
        if verifier_state.finished {
            panic!("Incorrect verifier state: Verifier is already finished.");
        }

        // Now, verifier should check if the received P(0) + P(1) = expected. The check is moved to
        // `check_and_generate_subclaim`, and will be done after the last round.

        let msg = Self::sample_round(rng);
        verifier_state.randomness.push(msg.randomness);
        verifier_state
            .polynomials_received
            .push(prover_msg.evaluations);

        // Now, verifier should set `expected` to P(r).
        // This operation is also moved to `check_and_generate_subclaim`,
        // and will be done after the last round.

        if verifier_state.round == verifier_state.nv {
            // accept and close
            verifier_state.finished = true;
        } else {
            verifier_state.round += 1;
        }
        Some(msg)
    }

    /// verify the sumcheck phase, and generate the subclaim
    ///
    /// If the asserted sum is correct, then the multilinear polynomial evaluated at `subclaim.point`
    /// is `subclaim.expected_evaluation`. Otherwise, it is highly unlikely that those two will be equal.
    /// Larger field size guarantees smaller soundness error.
    pub fn check_and_generate_subclaim(
        verifier_state: VerifierState<F>,
        asserted_sum: F,
    ) -> Result<SubClaim<F>, crate::Error> {
        if !verifier_state.finished {
            panic!("Verifier has not finished.");
        }

        let mut expected = asserted_sum;
        if verifier_state.polynomials_received.len() != verifier_state.nv {
            panic!("insufficient rounds");
        }
        for i in 0..verifier_state.nv {
            let evaluations = &verifier_state.polynomials_received[i];
            if evaluations.len() != verifier_state.max_multiplicands + 1 {
                panic!("incorrect number of evaluations");
            }
            let p0 = evaluations[0];
            let p1 = evaluations[1];
            if p0 + p1 != expected {
                return Err(crate::Error::Reject(Some(
                    "Prover message is not consistent with the claim.".into(),
                )));
            }
            expected = interpolate_uni_poly(evaluations, verifier_state.randomness[i]);
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

/// interpolate a uni-variate degree-`p_i.len()-1` polynomial and evaluate this
/// polynomial at `eval_at`:
///   \sum_{i=0}^len p_i * (\prod_{j!=i} (eval_at - j)/(i-j))
pub(crate) fn interpolate_uni_poly<F: Field>(p_i: &[F], eval_at: F) -> F {
    let len = p_i.len();

    let mut evals = vec![];

    let mut prod = eval_at;
    evals.push(eval_at);

    // `prod = \prod_{j} (eval_at - j)`
    for e in 1..len {
        let tmp = eval_at - F::from(e as u64);
        evals.push(tmp);
        prod *= tmp;
    }

    let mut res = F::zero();
    for i in 0..len {
        // `divisor = \prod_{j!=i} (i - j)`
        let divisor = get_divisor::<F>(i, len);

        // It should read `p_i[i] * (prod / evals[i]) / divisor`,
        // and therefore `prod / evals[i] = \prod_{j!=i} (eval_at - j)`.
        //
        // To reduce the number of inversion (as in division), it is
        // rewritten as `p_i[i] * prod / (divisor * evals[i])`.
        res += p_i[i] * prod / (divisor * evals[i]);
    }
    res
}

/// compute \prod_{j!=i) (i-j).
///
/// We know
///  - 2^61 < factorial(20) < 2^62
///  - 2^122 < factorial(33) < 2^123
/// so we will be able to compute the result
///  - for len<=20 with i64
///  - for 20<len<=33 with i128
///  - for len>33 with BigInt
#[inline]
fn get_divisor<F: Field>(i: usize, len: usize) -> F {
    if len <= 20 {
        let mut res = 1i64;
        for j in 0..len {
            if j != i {
                res *= i as i64 - j as i64;
            }
        }
        if res > 0 {
            F::from(res as u64)
        } else {
            -F::from((-res) as u64)
        }
    } else if len <= 33 {
        let mut res = 1i128;
        for j in 0..len {
            if j != i {
                res *= i as i128 - j as i128;
            }
        }
        if res > 0 {
            F::from(res as u128)
        } else {
            -F::from((-res) as u128)
        }
    } else {
        let mut res = F::one();
        for j in 0..len {
            if j != i {
                res *= if i > j {
                    F::from((i as i64 - j as i64) as u64)
                } else {
                    -F::from((j as i64 - i as i64) as u64)
                };
            }
        }
        res
    }
}
