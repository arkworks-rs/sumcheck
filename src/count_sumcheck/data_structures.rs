use ark_ec::PairingEngine;

/// Updatable Structured Reference String
#[derive(Debug, Clone)]
pub struct SRS<E: PairingEngine> {
    /// Size of H Domain
    pub n_h: usize,
    /// Security parameter set by the master protocol that uses Count as a subroutine
    pub d: usize,
    /// Security parameter set by the master protocol that uses Count as a subroutine
    pub d_gap: usize,
    /// G1 Generator
    pub g1: E::G1Affine,
    /// G2 generator
    pub g2: E::G2Affine,
    /// Sigma Powers of G1 elements
    pub s1_g1: Vec<E::G1Affine>,
    /// Sigam Powers of G2 elements
    pub s2_g2: Vec<E::G2Affine>,
}

/// ProverKey
pub struct ProverKey<E: PairingEngine> {
    /// Updatable Structured Reference String
    pub srs: SRS<E>,
}

/// VerifierKey
pub struct VerifierKey<E: PairingEngine> {
    /// Updatable Structured Reference String
    pub srs: SRS<E>,
    /// Commitment of S polynomial to G2
    pub s_commitment: E::G2Affine,
    /// Commitment of sigma^d_gap to T
    pub x_d_gap_commitment: E::Fqk,
}

/// Proof
pub struct Proof<E: PairingEngine> {
    /// Commitment of f_ipc poynomial to G1
    pub f_ipc_commitment: E::G1Affine,
}
