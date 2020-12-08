//! setup method for the protocol
use crate::ahp::MLProofForR1CS;
use crate::commitment::MLPolyCommit;
use crate::error::SResult;
use ark_ec::PairingEngine;
use rand::RngCore;

/// Public parameter used by the prover
pub type PublicParameter<E> = crate::commitment::data_structures::PublicParameter<E>;
/// Verifier parameter used by the verifier
pub type VerifierParameter<E> = crate::commitment::data_structures::VerifierParameter<E>;

impl<E: PairingEngine> MLProofForR1CS<E> {
    /// Setup public parameter and verifier parameter used for this protocol.
    pub fn setup<R: RngCore>(
        nv: usize,
        rng: &mut R,
    ) -> SResult<(PublicParameter<E>, VerifierParameter<E>)> {
        let (pp, vp, _) = MLPolyCommit::keygen(nv, rng)?;
        Ok((pp, vp))
    }
}
