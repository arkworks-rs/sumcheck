use ark_ff::Field;
use linear_sumcheck::data_structures::ml_extension::MLExtension;
use linear_sumcheck::data_structures::MLExtensionArray;
use rand::RngCore;

use crate::ahp::indexer::IndexVK;
use crate::ahp::prover::{
    ProverFifthMessage, ProverFinalMessage, ProverFirstMessage, ProverFourthMessage,
    ProverSecondMessage, ProverThirdMessage,
};
use crate::ahp::MLProofForR1CS;
use crate::data_structures::eq::eq_extension;
use crate::error::{invalid_arg, SResult};
use ark_ec::PairingEngine;
use ark_ff::{One, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::log2;
use linear_sumcheck::ml_sumcheck::ahp::prover::ProverMsg as MLProverMsg;
use linear_sumcheck::ml_sumcheck::ahp::verifier::VerifierMsg as MLVerifierMsg;
use linear_sumcheck::ml_sumcheck::ahp::verifier::VerifierState as MLVerifierState;
use linear_sumcheck::ml_sumcheck::ahp::AHPForMLSumcheck;
use crate::commitment::commit::Commitment;
use crate::commitment::MLPolyCommit;
use crate::ahp::setup::VerifierParameter;
use crate::commitment::open::Proof;

/// r_v: randomness
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierFirstMessage<F: Field> {
    pub r_v: Vec<F>,
}

/// random tor
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierSecondMessage<F: Field> {
    pub tor: Vec<F>,
}

/// the last randomness for MLSumcheck
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierThirdMessage<F: Field> {
    pub last_random_point: F,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierFourthMessage<F: Field> {
    pub r_a: F,
    pub r_b: F,
    pub r_c: F,
}

/// the last randomness for second MLSumcheck
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierFifthMessage<F: Field> {
    pub last_random_point: F,
}

pub struct VerifierFirstState<E: PairingEngine> {
    pub v: Vec<E::Fr>,
    pub log_v: usize,
    pub vk: IndexVK<E::Fr>,
}

pub struct VerifierSecondState<E: PairingEngine> {
    pub v: Vec<E::Fr>,
    pub log_v: usize,
    pub vk: IndexVK<E::Fr>,
    pub r_v: Vec<E::Fr>,
    pub commit: Commitment<E>, // todo: replace this with real commitment
}

pub struct VerifierThirdState<E: PairingEngine> {
    pub vk: IndexVK<E::Fr>,
    pub commit: Commitment<E>,
    pub tor: Vec<E::Fr>,
    pub v: Vec<E::Fr>,
    pub r_v: Vec<E::Fr>,
    pub z_rv_0: E::Fr,
    pub z_rv_0_proof: Proof<E>
}

/// first sumcheck state
pub struct VerifierFirstSumcheckState<E: PairingEngine> {
    pub vk: IndexVK<E::Fr>,
    pub commit: Commitment<E>,
    pub tor: Vec<E::Fr>,
    pub ml_verifier: MLVerifierState<E::Fr>,
    pub v: Vec<E::Fr>,
    pub r_v: Vec<E::Fr>,
    pub z_rv_0: E::Fr,
    pub z_rv_0_proof: Proof<E>
}

pub struct VerifierFourthState<E: PairingEngine> {
    pub vk: IndexVK<E::Fr>,
    pub commit: Commitment<E>,
    pub tor: Vec<E::Fr>,
    pub first_verifier_state: MLVerifierState<E::Fr>,
    pub v: Vec<E::Fr>,
    pub r_v: Vec<E::Fr>,
    pub z_rv_0: E::Fr,
    pub z_rv_0_proof: Proof<E>
}

pub struct VerifierFifthState<E: PairingEngine> {
    pub vk: IndexVK<E::Fr>,
    pub commit: Commitment<E>,
    pub r_a: E::Fr,
    pub r_b: E::Fr,
    pub r_c: E::Fr,
    pub va: E::Fr,
    pub vb: E::Fr,
    pub vc: E::Fr,
    pub tor: Vec<E::Fr>,
    pub first_verifier_state: MLVerifierState<E::Fr>,
    pub v: Vec<E::Fr>,
    pub r_v: Vec<E::Fr>,
    pub z_rv_0: E::Fr,
    pub z_rv_0_proof: Proof<E>
}

pub struct VerifierSecondSumcheckState<E: PairingEngine> {
    pub vk: IndexVK<E::Fr>,
    pub commit: Commitment<E>,
    pub va: E::Fr,
    pub vb: E::Fr,
    pub vc: E::Fr,
    pub r_a: E::Fr,
    pub r_b: E::Fr,
    pub r_c: E::Fr,
    pub tor: Vec<E::Fr>,
    pub first_verifier_state: MLVerifierState<E::Fr>,
    pub second_verifier_state: MLVerifierState<E::Fr>,
    pub v: Vec<E::Fr>,
    pub r_v: Vec<E::Fr>,
    pub z_rv_0: E::Fr,
    pub z_rv_0_proof: Proof<E>
}

pub type VerifierSixthState<E> = VerifierSecondSumcheckState<E>;

impl<E: PairingEngine> MLProofForR1CS<E> {
    pub fn verifier_init(vk: IndexVK<E::Fr>, v: Vec<E::Fr>) -> SResult<VerifierFirstState<E>> {
        if !v.len().is_power_of_two() || v.len() > vk.matrix_a.num_constraints {
            return Err(invalid_arg("public input should be power of two and has size smaller than number of constraints"));
        }
        let log_v = log2(v.len()) as usize;
        Ok(VerifierFirstState { v, log_v, vk })
    }

    /// receive commitment, generate r_v
    pub fn verify_first_round<R: RngCore>(
        state: VerifierFirstState<E>,
        p_msg: ProverFirstMessage<E>,
        rng: &mut R,
    ) -> SResult<(VerifierSecondState<E>, VerifierFirstMessage<E::Fr>)> {
        let commit = p_msg.commitment;
        let vk = state.vk;

        let msg = Self::sample_first_round(state.log_v, rng);
        let r_v: Vec<_> = msg.r_v.clone();
        let next_state = VerifierSecondState {
            v: state.v,
            log_v: state.log_v,
            vk,
            commit,
            r_v,
        };
        Ok((next_state, msg))
    }

    pub fn sample_first_round<R: RngCore>(
        log_v: usize,
        rng: &mut R,
    ) -> VerifierFirstMessage<E::Fr> {
        let r_v: Vec<_> = (0..log_v).map(|_| E::Fr::rand(rng)).collect();
        VerifierFirstMessage { r_v }
    }

    /// verify of z_rv_0 is correct, and send random tor
    pub fn verify_second_round<R: RngCore>(
        state: VerifierSecondState<E>,
        p_msg: ProverSecondMessage<E>,
        rng: &mut R,
    ) -> SResult<(VerifierThirdState<E>, VerifierSecondMessage<E::Fr>)> {
        let z_rv_0 = p_msg.z_rv_0;
        let z_rv_0_proof = p_msg.proof_for_z_rv_0;
        // verify z_rv_0 is correct using proof (verification done last)
        //
        // let vk = state.vk;
        // let v = MLExtensionArray::from_vec(state.v)?;
        // if v.eval_at(&state.r_v)? != z_rv_0 {
        //     return Err(invalid_arg("public witness is inconsistent with proof"));
        // }

        // let eq = eq_extension(&tor)?;

        let msg = Self::sample_second_round(state.vk.log_n, rng);
        let state = VerifierThirdState {
            vk: state.vk,
            commit: state.commit,
            tor: msg.tor.clone(),
            v: state.v,
            r_v: state.r_v,
            z_rv_0,
            z_rv_0_proof
        };
        Ok((state, msg))
    }

    pub fn sample_second_round<R: RngCore>(
        log_n: usize,
        rng: &mut R,
    ) -> VerifierSecondMessage<E::Fr> {
        let tor: Vec<_> = (0..log_n).map(|_| E::Fr::rand(rng)).collect();
        VerifierSecondMessage { tor }
    }

    /// initial first sumcheck verifier
    pub fn verify_third_round(
        state: VerifierThirdState<E>,
        p_msg: ProverThirdMessage,
    ) -> SResult<(VerifierFirstSumcheckState<E>, Option<MLVerifierMsg<E::Fr>>)> {
        let index_info = p_msg.ml_index_info;
        // sanity check the index info
        if index_info.num_variables != state.vk.log_n {
            return Err(invalid_arg("invalid sumcheck proposal"));
        };
        let ml_verifier = AHPForMLSumcheck::verifier_init(&index_info);
        let next_state = VerifierFirstSumcheckState {
            vk: state.vk,
            commit: state.commit,
            tor: state.tor,
            ml_verifier,
            v: state.v,
            r_v: state.r_v,
            z_rv_0: state.z_rv_0,
            z_rv_0_proof: state.z_rv_0_proof
        };

        Ok((next_state, None))
    }

    #[inline]
    pub fn sample_third_round() -> Option<MLVerifierMsg<E::Fr>> {
        None
    }

    /// sumcheck round except for last round
    pub fn verify_first_sumcheck_ongoing_round<R: RngCore>(
        state: VerifierFirstSumcheckState<E>,
        p_msg: MLProverMsg<E::Fr>,
        rng: &mut R,
    ) -> SResult<(VerifierFirstSumcheckState<E>, Option<MLVerifierMsg<E::Fr>>)> {
        let (v_msg, ml_verifier) = AHPForMLSumcheck::verify_round(p_msg, state.ml_verifier, rng)?;
        let next_state = VerifierFirstSumcheckState {
            ml_verifier,
            tor: state.tor,
            commit: state.commit,
            vk: state.vk,
            v: state.v,
            r_v: state.r_v,
            z_rv_0: state.z_rv_0,
            z_rv_0_proof: state.z_rv_0_proof
        };
        Ok((next_state, v_msg))
    }

    pub fn sample_verify_first_sumcheck_ongoing_round<R: RngCore>(
        rng: &mut R,
    ) -> Option<MLVerifierMsg<E::Fr>> {
        Some(AHPForMLSumcheck::sample_round(rng))
    }
    /// last round of first sumcheck verifier. send last randomness to prover.
    ///
    /// message produced by this round will be received by prover's round_tail function
    pub fn verify_first_sumcheck_final_round<R: RngCore>(
        state: VerifierFirstSumcheckState<E>,
        p_msg: MLProverMsg<E::Fr>,
        rng: &mut R,
    ) -> SResult<(VerifierFourthState<E>, VerifierThirdMessage<E::Fr>)> {
        let (ml_msg, ml_verifier) = AHPForMLSumcheck::verify_round(p_msg, state.ml_verifier, rng)?;
        // let subclaim = AHPForMLSumcheck::subclaim(ml_verifier)?;
        let final_randomness = ml_msg.unwrap().randomness;
        let msg = VerifierThirdMessage {
            last_random_point: final_randomness,
        };
        let next_state = VerifierFourthState {
            vk: state.vk,
            commit: state.commit,
            tor: state.tor,
            first_verifier_state: ml_verifier,
            v: state.v,
            r_v: state.r_v,
            z_rv_0: state.z_rv_0,
            z_rv_0_proof: state.z_rv_0_proof
        };
        Ok((next_state, msg))
    }

    pub fn sample_verify_first_sumcheck_final_round<R: RngCore>(
        rng: &mut R,
    ) -> VerifierThirdMessage<E::Fr> {
        VerifierThirdMessage {
            last_random_point: AHPForMLSumcheck::sample_round(rng).randomness,
        }
    }

    /// receive va, rb, vc, and sample ra, rb, rc for next sumcheck
    pub fn verify_fourth_round<R: RngCore>(
        state: VerifierFourthState<E>,
        p_msg: ProverFourthMessage<E>,
        rng: &mut R,
    ) -> SResult<(VerifierFifthState<E>, VerifierFourthMessage<E::Fr>)> {
        let (va, vb, vc) = (p_msg.va, p_msg.vb, p_msg.vc);
        // verify subclaim
        // let first_subclaim = state.first_subclaim;
        // let r_x = first_subclaim.point;
        // {
        //     let eq = state.eq;
        //     let mut eq_rx: E::Fr = E::Fr::one();
        //     for p in eq.iter() {
        //         eq_rx *= &p.eval_at(&r_x)?;
        //     }
        //     if (va * &vb - &vc) * &eq_rx != first_subclaim.expected_evaluation {
        //         return Err(crate::Error::WrongWitness(Some(
        //             "first sumcheck has wrong subclaim".into(),
        //         )));
        //     }
        // }

        let msg = Self::sample_verify_fourth_round(rng);
        let (r_a, r_b, r_c) = (msg.r_a, msg.r_b, msg.r_c);
        let next_state = VerifierFifthState {
            commit: state.commit,
            vk: state.vk,
            r_a,
            r_b,
            r_c,
            va,
            vb,
            vc,
            tor: state.tor,
            first_verifier_state: state.first_verifier_state,
            v: state.v,
            r_v: state.r_v,
            z_rv_0: state.z_rv_0,
            z_rv_0_proof: state.z_rv_0_proof
        };

        Ok((next_state, msg))
    }

    pub fn sample_verify_fourth_round<R: RngCore>(rng: &mut R) -> VerifierFourthMessage<E::Fr> {
        VerifierFourthMessage {
            r_a: E::Fr::rand(rng),
            r_b: E::Fr::rand(rng),
            r_c: E::Fr::rand(rng),
        }
    }

    /// start second linear sumcheck
    pub fn verify_fifth_round(
        state: VerifierFifthState<E>,
        p_msg: ProverFifthMessage,
    ) -> SResult<(VerifierSecondSumcheckState<E>, Option<MLVerifierMsg<E::Fr>>)> {
        let index_info = p_msg.index_info;
        // sanity check the index info
        if index_info.num_variables != state.vk.log_n {
            return Err(invalid_arg("invalid sumcheck proposal"));
        };
        let ml_verifier = AHPForMLSumcheck::verifier_init(&index_info);

        let next_state = VerifierSecondSumcheckState {
            vk: state.vk,
            commit: state.commit,
            va: state.va,
            vb: state.vb,
            vc: state.vc,
            r_a: state.r_a,
            r_b: state.r_b,
            r_c: state.r_c,
            tor: state.tor,
            first_verifier_state: state.first_verifier_state,
            second_verifier_state: ml_verifier,
            v: state.v,
            r_v: state.r_v,
            z_rv_0: state.z_rv_0,
            z_rv_0_proof: state.z_rv_0_proof
        };

        Ok((next_state, None))
    }

    pub fn sample_verify_fifth_round() -> Option<MLVerifierMsg<E::Fr>> {
        None
    }
    /// doing second sumcheck except for last round
    pub fn verify_second_sumcheck_ongoing_round<R: RngCore>(
        mut state: VerifierSecondSumcheckState<E>,
        p_msg: MLProverMsg<E::Fr>,
        rng: &mut R,
    ) -> SResult<(VerifierSecondSumcheckState<E>, Option<MLVerifierMsg<E::Fr>>)> {
        let (v_msg, ml_verifier) =
            AHPForMLSumcheck::verify_round(p_msg, state.second_verifier_state, rng)?;
        state.second_verifier_state = ml_verifier;
        Ok((state, v_msg))
    }
    #[inline]
    pub fn sample_verify_second_sumcheck_ongoing_round<R: RngCore>(
        rng: &mut R,
    ) -> Option<MLVerifierMsg<E::Fr>> {
        Self::sample_verify_first_sumcheck_ongoing_round(rng)
    }

    /// last round of sumcheck, send final randomness
    pub fn verify_second_sumcheck_final_round<R: RngCore>(
        mut state: VerifierSecondSumcheckState<E>,
        p_msg: MLProverMsg<E::Fr>,
        rng: &mut R,
    ) -> SResult<(VerifierSixthState<E>, VerifierFifthMessage<E::Fr>)> {
        let (ml_final_msg, ml_verifier) =
            AHPForMLSumcheck::verify_round(p_msg, state.second_verifier_state, rng)?;
        // let subclaim = AHPForMLSumcheck::subclaim(ml_verifier)?;
        let final_randomness = ml_final_msg.unwrap().randomness;
        state.second_verifier_state = ml_verifier;

        let msg = VerifierFifthMessage {
            last_random_point: final_randomness,
        };
        Ok((state, msg))
    }

    pub fn sample_verify_second_sumcheck_final_round<R: RngCore>(
        rng: &mut R,
    ) -> VerifierFifthMessage<E::Fr> {
        VerifierFifthMessage {
            last_random_point: AHPForMLSumcheck::sample_round(rng).randomness,
        }
    }

    /// receive z(r_y), verify final claim
    pub fn verify_sixth_round(
        state: VerifierSixthState<E>,
        p_msg: ProverFinalMessage<E>,
        vp: &VerifierParameter<E>
    ) -> SResult<bool> {

        let eq = eq_extension(&state.tor)?;

        // verify if public witness extension asserted by prover is correct
        let mut r_v_0 = state.r_v.clone(); // extend r_v with zero
        r_v_0.extend((0..(state.vk.log_n - ark_std::log2(state.v.len()) as usize)).map(|_|E::Fr::zero()));
        if !MLPolyCommit::verify(vp, &state.commit, &r_v_0, state.z_rv_0, state.z_rv_0_proof)? {
            return Err(invalid_arg("public witness failed in commitment check"));
        };

        let vk = state.vk;
        let v = MLExtensionArray::from_vec(state.v)?;
        if v.eval_at(&state.r_v)? != state.z_rv_0 {
            return Err(invalid_arg("public witness is inconsistent with proof"));
        }

        // verify first sumcheck
        let first_subclaim = AHPForMLSumcheck::check_and_generate_subclaim(
            state.first_verifier_state,
            E::Fr::zero(),
        )?;
        let r_x = first_subclaim.point;
        {
            let mut eq_rx: E::Fr = E::Fr::one();
            for p in eq.iter() {
                eq_rx *= &p.eval_at(&r_x)?;
            }
            if (state.va * &state.vb - &state.vc) * &eq_rx != first_subclaim.expected_evaluation {
                return Err(crate::Error::WrongWitness(Some(
                    "first sumcheck has wrong subclaim".into(),
                )));
            }
        }

        let z_ry = p_msg.z_ry;
        // verify second sumcheck
        let second_claimed_sum =
            state.r_a * &state.va + &(state.r_b * &state.vb) + &(state.r_c * &state.vc);
        let second_subclaim = AHPForMLSumcheck::check_and_generate_subclaim(
            state.second_verifier_state,
            second_claimed_sum,
        )?;
        let expected = second_subclaim.expected_evaluation;
        let (r_a, r_b, r_c) = (state.r_a, state.r_b, state.r_c);
        let r_y = second_subclaim.point;
        let a_rx_ry = vk.matrix_a.eval_on_x(&r_x)?.eval_at(&r_y)?;
        let b_rx_ry = vk.matrix_b.eval_on_x(&r_x)?.eval_at(&r_y)?;
        let c_rx_ry = vk.matrix_c.eval_on_x(&r_x)?.eval_at(&r_y)?;

        let actual = r_a * &a_rx_ry * &z_ry + &(r_b * &b_rx_ry * &z_ry) + &(r_c * &c_rx_ry * &z_ry);
        if expected != actual {
            return Err(crate::Error::WrongWitness(Some(
                "Cannot verify matrix A, B, C".into(),
            )))
        }

        // verify if z_ry is correct using proof
        if !MLPolyCommit::verify(vp, &state.commit, &r_y, z_ry, p_msg.proof_for_z_ry)? {
            return Err(crate::Error::WrongWitness(Some(
                "Cannot verify z_ry".into()
            )))
        };

        Ok(true)
    }
}
