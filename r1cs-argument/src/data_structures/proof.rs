use crate::ahp::prover::{
    ProverFifthMessage, ProverFirstMessage, ProverFourthMessage, ProverSecondMessage,
    ProverSixthMessage, ProverThirdMessage,
};
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::vec::Vec;
use linear_sumcheck::ml_sumcheck::ahp::prover::ProverMsg as MLProverMsg;
/// message sent by the prover
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: PairingEngine> {
    pub(crate) prover_first_message: ProverFirstMessage<E>,
    pub(crate) prover_second_message: ProverSecondMessage<E>,
    pub(crate) prover_third_message: ProverThirdMessage,
    pub(crate) first_sumcheck_messages: Vec<MLProverMsg<E::Fr>>,
    pub(crate) prover_fourth_message: ProverFourthMessage<E>,
    pub(crate) prover_fifth_message: ProverFifthMessage,
    pub(crate) second_sumcheck_messages: Vec<MLProverMsg<E::Fr>>,
    pub(crate) prover_sixth_message: ProverSixthMessage<E>,
}
