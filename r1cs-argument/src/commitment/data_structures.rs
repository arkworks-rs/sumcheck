use ark_ec::PairingEngine;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Read, Write, SerializationError};
#[allow(type_alias_bounds)]
pub type EvaluationHyperCubeOnG1<E: PairingEngine> = Vec<E::G1Affine>;
#[allow(type_alias_bounds)]
pub type EvaluationHyperCubeOnG2<E: PairingEngine> = Vec<E::G2Affine>;


#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParameter<E: PairingEngine> {
    pub nv: usize,
    /// pp_k defined by libra
    pub powers_of_g: Vec<EvaluationHyperCubeOnG1<E>>,
    pub powers_of_h: Vec<EvaluationHyperCubeOnG2<E>>,
    pub g: E::G1Affine,
    pub h: E::G2Affine,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierParameter<E: PairingEngine> {
    pub nv: usize,
    pub g: E::G1Affine,
    pub h: E::G2Affine,
    /// g^t1, g^t2, ...
    pub g_mask_random: Vec<E::G1Affine>,
}