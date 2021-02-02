use crate::ml_sumcheck::protocol::{IPForMLSumcheck, ListOfProductsOfPolynomials};
use crate::ml_sumcheck::MLSumcheck;
use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_std::test_rng;
use ark_std::vec::Vec;
use ark_test_curves::bls12_381::Fr;
use rand::Rng;
use rand_core::RngCore;

fn random_product<F: Field, R: RngCore>(
    nv: usize,
    num_multiplicands: usize,
    rng: &mut R,
) -> (Vec<DenseMultilinearExtension<F>>, F) {
    let mut multiplicands = Vec::with_capacity(num_multiplicands);
    for _ in 0..num_multiplicands {
        multiplicands.push(Vec::with_capacity(1 << nv))
    }
    let mut sum = F::zero();

    for _ in 0..(1 << nv) {
        let mut product = F::one();
        for i in 0..num_multiplicands {
            let val = F::rand(rng);
            multiplicands[i].push(val);
            product *= val;
        }
        sum += product;
    }

    return (
        multiplicands
            .into_iter()
            .map(|x| DenseMultilinearExtension::from_evaluations_vec(nv, x))
            .collect(),
        sum,
    );
}

fn random_list_of_products<F: Field, R: RngCore>(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
    rng: &mut R,
) -> (ListOfProductsOfPolynomials<F>, F) {
    let mut sum = F::zero();
    let mut poly = ListOfProductsOfPolynomials::new(nv);
    for _ in 0..num_products {
        let num_multiplicands = rng.gen_range(num_multiplicands_range.0, num_multiplicands_range.1);
        let (product, product_sum) = random_product(nv, num_multiplicands, rng);
        let coefficient = F::rand(rng);
        poly.add_product(product.into_iter(), coefficient);
        sum += product_sum * coefficient;
    }

    (poly, sum)
}

fn test_polynomial(nv: usize, num_multiplicands_range: (usize, usize), num_products: usize) {
    let mut rng = test_rng();
    let (poly, asserted_sum) =
        random_list_of_products::<Fr, _>(nv, num_multiplicands_range, num_products, &mut rng);
    let poly_info = poly.info();
    let proof = MLSumcheck::prove(&poly).expect("fail to prove");
    let subclaim = MLSumcheck::verify(&poly_info, asserted_sum, &proof).expect("fail to verify");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}

fn test_ahp(nv: usize, num_multiplicands_range: (usize, usize), num_products: usize) {
    let mut rng = test_rng();
    let (poly, asserted_sum) =
        random_list_of_products::<Fr, _>(nv, num_multiplicands_range, num_products, &mut rng);
    let poly_info = poly.info();
    let mut prover_state = IPForMLSumcheck::prover_init(&poly);
    let mut verifier_state = IPForMLSumcheck::verifier_init(&poly_info);
    let mut verifier_msg = None;
    for _ in 0..poly.num_variables {
        let result = IPForMLSumcheck::prove_round(prover_state, &verifier_msg);
        prover_state = result.1;
        let (verifier_msg2, verifier_state2) =
            IPForMLSumcheck::verify_round(result.0, verifier_state, &mut rng);
        verifier_msg = verifier_msg2;
        verifier_state = verifier_state2;
    }
    let subclaim = IPForMLSumcheck::check_and_generate_subclaim(verifier_state, asserted_sum)
        .expect("fail to generate subclaim");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}

#[test]
fn test_trivial_polynomial() {
    let nv = 1;
    let num_multiplicands_range = (4, 13);
    let num_products = 5;

    test_polynomial(nv, num_multiplicands_range, num_products);
    test_ahp(nv, num_multiplicands_range, num_products);
}
#[test]
fn test_normal_polynomial() {
    let nv = 12;
    let num_multiplicands_range = (4, 9);
    let num_products = 5;

    test_polynomial(nv, num_multiplicands_range, num_products);
    test_ahp(nv, num_multiplicands_range, num_products);
}
#[test]
#[should_panic]
fn zero_polynomial_should_error() {
    let nv = 0;
    let num_multiplicands_range = (4, 13);
    let num_products = 5;

    test_polynomial(nv, num_multiplicands_range, num_products);
    test_ahp(nv, num_multiplicands_range, num_products);
}

#[test]
fn test_extract_sum() {
    let mut rng = test_rng();
    let (poly, asserted_sum) = random_list_of_products::<Fr, _>(8, (3, 4), 3, &mut rng);

    let proof = MLSumcheck::prove(&poly).expect("fail to prove");
    assert_eq!(MLSumcheck::extract_sum(&proof), asserted_sum);
}
