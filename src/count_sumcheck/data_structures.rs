use ark_ec::PairingEngine;

#[derive(Debug, Clone)]
pub struct SRS<E: PairingEngine> {
    pub n_h: usize,
    pub d: usize,
    pub d_gap: usize,
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
    pub s1_g1: Vec<E::G1Affine>,
    pub s2_g2: Vec<E::G2Affine>,
}

pub struct ProverKey<E: PairingEngine> {
    pub srs: SRS<E>,
}

pub struct VerifierKey<E: PairingEngine> {
    pub srs: SRS<E>,
    pub s_commitment: E::G2Affine,
    pub x_d_gap_commitment: E::Fqk,
}

pub struct Proof<E: PairingEngine> {
    pub f_ipc_commitment: E::G1Affine,
}
