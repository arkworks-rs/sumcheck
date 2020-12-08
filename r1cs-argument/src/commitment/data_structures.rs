//! Data structures used by the commitment scheme
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
#[allow(type_alias_bounds)]
/// Evaluations over {0,1}^n for G1
pub type EvaluationHyperCubeOnG1<E: PairingEngine> = Vec<E::G1Affine>;
#[allow(type_alias_bounds)]
/// Evaluations over {0,1}^n for G2
pub type EvaluationHyperCubeOnG2<E: PairingEngine> = Vec<E::G2Affine>;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
/// Public Parameter used by prover
pub struct PublicParameter<E: PairingEngine> {
    /// number of variables
    pub nv: usize,
    /// pp_k defined by libra
    pub powers_of_g: Vec<EvaluationHyperCubeOnG1<E>>,
    /// pp_h defined by libra
    pub powers_of_h: Vec<EvaluationHyperCubeOnG2<E>>,
    /// generator for G1
    pub g: E::G1Affine,
    /// generator for G2
    pub h: E::G2Affine,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
/// Verifier parameter used by verifier
pub struct VerifierParameter<E: PairingEngine> {
    /// number of variables
    pub nv: usize,
    /// generator of G1
    pub g: E::G1Affine,
    /// generator of G2
    pub h: E::G2Affine,
    /// g^t1, g^t2, ...
    pub g_mask_random: Vec<E::G1Affine>,
}
