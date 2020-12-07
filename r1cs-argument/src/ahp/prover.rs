use linear_sumcheck::data_structures::ml_extension::{ArithmeticCombination, MLExtension};
use linear_sumcheck::data_structures::MLExtensionArray;
use linear_sumcheck::ml_sumcheck::ahp::indexer::IndexInfo as MLIndexInfo;
use linear_sumcheck::ml_sumcheck::ahp::prover::{
    ProverMsg as MLProverMsg, ProverState as MLProverState,
};
use linear_sumcheck::ml_sumcheck::ahp::verifier::VerifierMsg as MLVerifierMsg;
use linear_sumcheck::ml_sumcheck::ahp::AHPForMLSumcheck;

use crate::ahp::indexer::IndexPK;
use crate::ahp::verifier::{
    VerifierFifthMessage, VerifierFirstMessage, VerifierFourthMessage, VerifierSecondMessage,
    VerifierThirdMessage,
};
use crate::ahp::MLProofForR1CS;
use crate::data_structures::eq::eq_extension;
use crate::error::{invalid_arg, SResult};
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use crate::commitment::commit::Commitment;
use crate::ahp::setup::PublicParameter;
use crate::commitment::MLPolyCommit;
use crate::commitment::open::Proof;
use ark_ff::Zero;
pub struct ProverFirstState<E: PairingEngine> {
    pub v: Vec<E::Fr>,
    pub w: Vec<E::Fr>,
    pub pk: IndexPK<E::Fr>,
}

pub struct ProverSecondState<E: PairingEngine> {
    pub v: Vec<E::Fr>,
    pub w: Vec<E::Fr>,
    pub pk: IndexPK<E::Fr>,
    z: MLExtensionArray<E::Fr>
}

/// state after sending commitment and z_rv_0
pub struct ProverThirdState<E: PairingEngine> {
    pub pk: IndexPK<E::Fr>,
    z: MLExtensionArray<E::Fr>,
}

/// state when prover is doing first sumcheck
pub struct ProverFirstSumcheckState<E: PairingEngine> {
    pub pk: IndexPK<E::Fr>,
    z: MLExtensionArray<E::Fr>,
    sum_az_over_y: MLExtensionArray<E::Fr>,
    sum_bz_over_y: MLExtensionArray<E::Fr>,
    sum_cz_over_y: MLExtensionArray<E::Fr>,
    ml_prover_state: MLProverState<E::Fr>,
}

pub struct ProverFifthState<E: PairingEngine> {
    pub pk: IndexPK<E::Fr>,
    z: MLExtensionArray<E::Fr>,
    r_x: Vec<E::Fr>,
}

pub struct ProverSecondSumcheckState<E: PairingEngine> {
    z: MLExtensionArray<E::Fr>,
    ml_prover_state: MLProverState<E::Fr>,
}

/// first message is the commitment
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverFirstMessage<E: PairingEngine> {
    pub commitment: Commitment<E>
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverSecondMessage<E: PairingEngine> {
    pub z_rv_0: E::Fr,
    pub proof_for_z_rv_0: Proof<E>
}

/// contains some sumcheck info
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverThirdMessage {
    pub ml_index_info: MLIndexInfo,
}

/// va, vb, vc
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverFourthMessage<E: PairingEngine> {
    pub va: E::Fr,
    pub vb: E::Fr,
    pub vc: E::Fr,
}

/// information for second sumcheck
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverFifthMessage {
    pub index_info: MLIndexInfo,
}

/// z(r_y)
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverSixthMessage<E: PairingEngine> {
    pub z_ry: E::Fr,
    pub proof_for_z_ry: Proof<E>
}
/// final message
pub type ProverFinalMessage<E> = ProverSixthMessage<E>;

impl<E: PairingEngine> MLProofForR1CS<E> {
    /// initialize the prover
    /// * `v`: public input, whose size should be power of 2
    pub fn prover_init(
        pk: IndexPK<E::Fr>,
        v: Vec<E::Fr>,
        w: Vec<E::Fr>,
    ) -> SResult<ProverFirstState<E>> {
        if !v.len().is_power_of_two() {
            return Err(invalid_arg("public input should be power of two"));
        }
        if v.len() + w.len() != pk.matrix_a.num_constraints {
            return Err(invalid_arg("|v| + |w| != number of variables"));
        }
        Ok(ProverFirstState { v, w, pk })
    }
    /// send commitment
    pub fn prover_first_round(
        state: ProverFirstState<E>,
        pp: &PublicParameter<E>
    ) -> Result<(ProverSecondState<E>, ProverFirstMessage<E>), crate::Error> {
        let z =
            MLExtensionArray::from_vec(state.v.iter().chain(state.w.iter()).map(|x| *x).collect())?;
        let commitment = MLPolyCommit::commit(pp, z.clone())?;
        Ok((
            ProverSecondState {
                v: state.v,
                w: state.w,
                pk: state.pk,
                z
            },
            ProverFirstMessage {
                commitment,
            },
        ))
    }
    /// receive r_v, send z_rv_0
    pub fn prover_second_round(
        state: ProverSecondState<E>,
        v_msg: VerifierFirstMessage<E::Fr>,
        pp: &PublicParameter<E>
    ) -> Result<(ProverThirdState<E>, ProverSecondMessage<E>), crate::Error> {
        let pk = state.pk;
        let z = state.z;
        let mut r_v = v_msg.r_v;
        // extend r_v with zero
        r_v.extend((0..(z.num_variables()? - ark_std::log2(state.v.len()) as usize)).map(|_|E::Fr::zero()));
        let (z_rv_0, proof, _) = MLPolyCommit::open(pp, z.clone(), &r_v)?;
        let state = ProverThirdState { pk, z };
        let msg = ProverSecondMessage {
            z_rv_0,
            proof_for_z_rv_0: proof,
        };
        Ok((state, msg))
    }
    /// Receive random tor from verifier and prepare for the first sumcheck.
    /// send sumcheck index information
    pub fn prover_third_round(
        state: ProverThirdState<E>,
        v_msg: VerifierSecondMessage<E::Fr>,
    ) -> Result<(ProverFirstSumcheckState<E>, ProverThirdMessage), crate::Error> {
        let tor = v_msg.tor;
        let eq = eq_extension(&tor)?;
        let pk = state.pk;
        let z = state.z;
        let sum_az_over_y = pk.matrix_a.sum_over_y(&z)?;
        let sum_bz_over_y = pk.matrix_b.sum_over_y(&z)?;
        let sum_cz_over_y = pk.matrix_c.sum_over_y(&z)?;

        let mut g_zt_x_first = vec![sum_az_over_y.clone(), sum_bz_over_y.clone()];
        g_zt_x_first.extend(eq.iter().map(|mle| mle.clone()));
        let mut g_zt_x_second = vec![sum_cz_over_y.negate()?];
        g_zt_x_second.extend(eq.iter().map(|mle| mle.clone()));
        let mut g_zt_x = ArithmeticCombination::new(pk.log_n);
        g_zt_x.add_product(g_zt_x_first.into_iter())?;
        g_zt_x.add_product(g_zt_x_second.into_iter())?;
        let ml_index = AHPForMLSumcheck::convert_to_index(g_zt_x)?;
        let ml_index_info = ml_index.info();
        let ml_prover_state = AHPForMLSumcheck::prover_init(&ml_index);

        let next_state = ProverFirstSumcheckState {
            pk,
            z,
            sum_az_over_y,
            sum_bz_over_y,
            sum_cz_over_y,
            ml_prover_state,
        };
        let msg = ProverThirdMessage { ml_index_info };
        Ok((next_state, msg))
    }

    /// first sumcheck
    pub fn prove_first_sumcheck_round(
        mut state: ProverFirstSumcheckState<E>,
        v_msg: Option<MLVerifierMsg<E::Fr>>,
    ) -> Result<(ProverFirstSumcheckState<E>, MLProverMsg<E::Fr>), crate::Error> {
        let (mlp_msg, new_prover_state) =
            AHPForMLSumcheck::prove_round(state.ml_prover_state, &v_msg)?;
        state.ml_prover_state = new_prover_state;
        Ok((state, mlp_msg))
    }

    /// verifier send the final point, prover send va, vb, vc
    pub fn prove_fourth_round(
        state: ProverFirstSumcheckState<E>,
        v_msg: VerifierThirdMessage<E::Fr>,
    ) -> Result<(ProverFifthState<E>, ProverFourthMessage<E>), crate::Error> {
        let mut r_x = state.ml_prover_state.randomness;
        r_x.push(v_msg.last_random_point);

        let va = state.sum_az_over_y.eval_at(&r_x)?;
        let vb = state.sum_bz_over_y.eval_at(&r_x)?;
        let vc = state.sum_cz_over_y.eval_at(&r_x)?;

        let next_state = ProverFifthState {
            z: state.z,
            pk: state.pk,
            r_x,
        };
        let msg = ProverFourthMessage { va, vb, vc };
        Ok((next_state, msg))
    }
    /// receive ra, rb, rc, and prepare for second sumcheck
    pub fn prove_fifth_round(
        state: ProverFifthState<E>,
        v_msg: VerifierFourthMessage<E::Fr>,
    ) -> Result<(ProverSecondSumcheckState<E>, ProverFifthMessage), crate::Error> {
        let r_a = v_msg.r_a;
        let r_b = v_msg.r_b;
        let r_c = v_msg.r_c;
        let r_x = state.r_x;
        let z = state.z;
        let az_rx_on_y = vec![state.pk.matrix_a.eval_on_x(&r_x)?.multiply(r_a)?, z.clone()];
        let bz_rx_on_y = vec![state.pk.matrix_b.eval_on_x(&r_x)?.multiply(r_b)?, z.clone()];
        let cz_rx_on_y = vec![state.pk.matrix_c.eval_on_x(&r_x)?.multiply(r_c)?, z.clone()];
        let mut round2_poly = ArithmeticCombination::new(state.pk.log_n);
        round2_poly.add_product(az_rx_on_y.into_iter())?;
        round2_poly.add_product(bz_rx_on_y.into_iter())?;
        round2_poly.add_product(cz_rx_on_y.into_iter())?;
        let index = AHPForMLSumcheck::convert_to_index(round2_poly)?;
        let ml_prover_state = AHPForMLSumcheck::prover_init(&index);

        let next_state = ProverSecondSumcheckState { z, ml_prover_state };
        let msg = ProverFifthMessage {
            index_info: index.info(),
        };

        Ok((next_state, msg))
    }

    /// second round sumcheck
    pub fn prove_second_sumcheck_round(
        mut state: ProverSecondSumcheckState<E>,
        v_msg: Option<MLVerifierMsg<E::Fr>>,
    ) -> Result<(ProverSecondSumcheckState<E>, MLProverMsg<E::Fr>), crate::Error> {
        let (mlp_msg, new_prover_state) =
            AHPForMLSumcheck::prove_round(state.ml_prover_state, &v_msg)?;
        state.ml_prover_state = new_prover_state;
        Ok((state, mlp_msg))
    }
    /// final round: send z(r_y) and its corresponding proof
    pub fn prove_sixth_round(
        state: ProverSecondSumcheckState<E>,
        v_msg: VerifierFifthMessage<E::Fr>,
        pp: &PublicParameter<E>
    ) -> Result<ProverFinalMessage<E>, crate::Error> {
        let mut r_y = state.ml_prover_state.randomness;
        r_y.push(v_msg.last_random_point);
        let (z_ry, proof_for_z_ry, _) = MLPolyCommit::open(&pp,state.z, &r_y)?;
        let msg = ProverFinalMessage {
            z_ry,
            proof_for_z_ry,
        };
        Ok(msg)
    }
}
