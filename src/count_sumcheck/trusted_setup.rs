use crate::count_sumcheck::{data_structures::{VerifierKey, ProverKey, SRS}, utils::{commit, compute_s_poly}};
use ark_ec::{msm::FixedBaseMSM, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::rand::RngCore;

pub fn derive_keys<E: PairingEngine>(srs: &SRS<E>) -> (ProverKey<E>, VerifierKey<E>) {
    let s = compute_s_poly(srs.n_h, srs.d_gap, srs.d);
    let s_commitment = commit(&srs.s2_g2, &s.into());
    let sigma_d_gap = E::pairing(srs.s1_g1[srs.d_gap - 1], srs.s2_g2[1]);
    let ek = ProverKey { srs: srs.clone() };
    let vk = VerifierKey {
        srs: srs.clone(),
        s_commitment,
        x_d_gap_commitment: sigma_d_gap,
    };
    (ek, vk)
}

pub fn kgen<E: PairingEngine, R: RngCore>(
    n_h: usize,
    d: usize,
    d_gap: usize,
    rng: &mut R,
) -> SRS<E> {
    let g1 = E::G1Projective::prime_subgroup_generator();
    let g2 = E::G2Projective::prime_subgroup_generator();

    let (s1, s2) = get_s1_s2(d, d_gap, n_h, rng);

    SRS {
        n_h,
        d,
        d_gap,
        g1: g1.into(),
        g2: g2.into(),
        s1_g1: mul_gen(&s1, g1),
        s2_g2: mul_gen(&s2, g2),
    }
}

fn mul_gen<F: PrimeField, G: ProjectiveCurve<ScalarField = F>>(
    coeffs: &Vec<F>,
    g: G,
) -> Vec<G::Affine> {
    let window_size = FixedBaseMSM::get_mul_window_size(coeffs.len());
    let scalar_field_size_bits = F::size_in_bits();
    let g1_table = FixedBaseMSM::get_window_table(scalar_field_size_bits, window_size, g);
    let sigma_1_times_g1_projective =
        FixedBaseMSM::multi_scalar_mul(scalar_field_size_bits, window_size, &g1_table, coeffs);

    G::batch_normalization_into_affine(&sigma_1_times_g1_projective)
}

fn get_s1_s2<F: PrimeField, R: RngCore>(
    d: usize,
    d_gap: usize,
    n_h: usize,
    rng: &mut R,
) -> (Vec<F>, Vec<F>) {
    let sigma = F::rand(rng);
    let mut sigma_powers = Vec::with_capacity(d + d_gap);
    let mut current = F::one();
    for _ in 0..=d + d_gap {
        sigma_powers.push(current);
        current *= sigma;
    }

    let mut s1 = sigma_powers[0..=(d + d_gap)].to_vec();
    s1[d_gap] = F::zero();

    let mut s2: Vec<F> = vec![F::zero(); d_gap + 1];
    s2[0] = F::one();
    s2[1] = sigma_powers[1];

    for i in 0..d / n_h {
        let idx = d_gap - (i * n_h);
        s2[idx] = sigma_powers[idx];
    }
    (s1, s2)
}
