//! Data structures used by GKR Round Sumcheck

use crate::ml_sumcheck::ahp::prover::ProverMsg;
use ark_ff::Field;
use ark_std::vec::Vec;

/// Proof for GKR Round Function
pub struct GKRProof<F: Field> {
    pub(crate) phase1_sumcheck_msgs: Vec<ProverMsg<F>>,
    pub(crate) phase2_sumcheck_msgs: Vec<ProverMsg<F>>,
}
