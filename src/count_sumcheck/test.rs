use crate::count_sumcheck::{
    sumcheck::{prove, verify},
    trusted_setup::{derive_keys, kgen},
    utils::commit,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::One;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};

#[test]
fn test_count_end_to_end() {
    let rng = &mut ark_std::test_rng();

    let d = 128;
    let d_gap = 128;
    let h_domain = GeneralEvaluationDomain::new(128).unwrap();
    let n_h = h_domain.size();
    let f = DensePolynomial::from_coefficients_slice(&[Fr::one()]);
    let v_f = f.evaluate_over_domain_by_ref(h_domain).evals.iter().sum();

    let srs = kgen(n_h, d, d_gap, rng);
    let f_commitment = commit(&srs.s1_g1, &f);
    let (ek, vk) = derive_keys(&srs);
    let proof = prove(&ek, &f, v_f);
    let proof_is_correct = verify::<Bls12_381>(&vk, &proof, f_commitment, v_f);

    assert!(proof_is_correct);
}
