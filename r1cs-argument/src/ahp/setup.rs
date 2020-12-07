use ark_ec::PairingEngine;
use crate::ahp::MLProofForR1CS;
use rand::RngCore;
use crate::commitment::MLPolyCommit;
use crate::error::SResult;

pub type PublicParameter<E> = crate::commitment::data_structures::PublicParameter<E>;
pub type VerifierParameter<E> = crate::commitment::data_structures::VerifierParameter<E>;

impl<E: PairingEngine> MLProofForR1CS<E> {

    /// Setup public parameter and verifier parameter used for this protocol.
    pub fn setup<R: RngCore>(nv: usize, rng: &mut R) -> SResult<(PublicParameter<E>, VerifierParameter<E>)> {
        let (pp, vp, _) = MLPolyCommit::keygen(nv, rng)?;
        Ok((pp, vp))
    }
}