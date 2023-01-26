use ark_ec::ProjectiveCurve;
use ark_ec::{msm::VariableBaseMSM, AffineCurve};
use ark_ff::PrimeField;
use ark_poly::{
    univariate::{DensePolynomial, SparsePolynomial},
    Polynomial,
};

pub fn commit<F: PrimeField, G: AffineCurve<ScalarField = F>>(
    powers: &[G],
    poly: &DensePolynomial<F>,
) -> G {
    if poly.degree() + 1 > powers.len() {
        panic!(
            "Degree of polynomial is too large for the number of powers provided. Degree: {}, Powers: {}",
            poly.degree(),
            powers.len()
        )
    }

    let coeffs = convert_to_bigints(&poly.coeffs.to_vec());
    VariableBaseMSM::multi_scalar_mul(powers, &coeffs).into_affine()
}

pub fn compute_s_poly<F: PrimeField>(n_h: usize, d_gap: usize, d: usize) -> SparsePolynomial<F> {
    let coeffs = (0..d / n_h).map(|i| (d_gap - n_h * i, F::one())).collect();
    SparsePolynomial::from_coefficients_vec(coeffs)
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    ark_std::cfg_iter!(p).map(|s| s.into_repr()).collect()
}
