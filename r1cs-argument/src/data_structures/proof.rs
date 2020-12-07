use crate::ahp::prover::{
    ProverFifthMessage, ProverFirstMessage, ProverFourthMessage, ProverSecondMessage,
    ProverSixthMessage, ProverThirdMessage,
};
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use linear_sumcheck::ml_sumcheck::ahp::prover::ProverMsg as MLProverMsg;

/// message sent by the prover
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: PairingEngine> {
    pub prover_first_message: ProverFirstMessage<E>,
    pub prover_second_message: ProverSecondMessage<E>,
    pub prover_third_message: ProverThirdMessage,
    pub first_sumcheck_messages: Vec<MLProverMsg<E::Fr>>,
    pub prover_fourth_message: ProverFourthMessage<E>,
    pub prover_fifth_message: ProverFifthMessage,
    pub second_sumcheck_messages: Vec<MLProverMsg<E::Fr>>,
    pub prover_sixth_message: ProverSixthMessage<E>,
}
