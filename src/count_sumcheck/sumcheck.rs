use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::PrimeField;
use ark_poly::univariate::{DensePolynomial, SparsePolynomial};
use ark_std::One;
use std::ops::Mul;

use crate::count_sumcheck::{
    data_structures::{Proof, ProverKey, VerifierKey},
    utils::{commit, compute_s_poly},
};

/// Generates Proof to be spent to verifier by computing and commitmitting f_ipc to G1
pub fn prove<E: PairingEngine>(
    ek: &ProverKey<E>,
    f: &DensePolynomial<E::Fr>,
    v_f: E::Fr,
) -> Proof<E> {
    let ProverKey { srs } = ek;
    let s = compute_s_poly(srs.n_h, srs.d_gap, srs.d);
    let x_d_gap: DensePolynomial<E::Fr> =
        SparsePolynomial::from_coefficients_slice(&[(srs.d_gap, E::Fr::one())]).into();
    let f_ipc = &f.mul(&s.into()) - &(&x_d_gap * (v_f / (E::Fr::from(srs.n_h as u64))));

    let f_ipc_commitment = commit(&srs.s1_g1, &f_ipc);
    Proof { f_ipc_commitment }
}

/// Verifies Proof sent from Prover
pub fn verify<E: PairingEngine>(
    vk: &VerifierKey<E>,
    proof: &Proof<E>,
    f_commitment: E::G1Affine,
    v_f: E::Fr,
) -> bool {
    // can't multiply by scalar in G_T so instead multiply by inverse in G_1 before pairing.
    let n_h = E::Fr::from(vk.srs.n_h as u64);
    let c = (n_h / v_f).into_repr();
    let lhs = E::pairing(f_commitment.mul(c), vk.s_commitment)
        * E::pairing(-proof.f_ipc_commitment.mul(c), vk.srs.s2_g2[0]);
    let rhs = vk.x_d_gap_commitment;
    lhs == rhs
}
