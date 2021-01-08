use crate::ml_sumcheck::ahp::{AHPForMLSumcheck, ProductsOfMLExtensions};
use crate::ml_sumcheck::MLSumcheck;
use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_std::cmp::max;
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

fn random_combination<F: Field, R: RngCore>(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
    rng: &mut R,
) -> (ProductsOfMLExtensions<F>, F) {
    let mut max_num_multiplicands = 0;
    let mut sum = F::zero();
    let mut comb = ProductsOfMLExtensions::new(nv);
    for _ in 0..num_products {
        let num_multiplicands = rng.gen_range(num_multiplicands_range.0, num_multiplicands_range.1);
        max_num_multiplicands = max(num_multiplicands, max_num_multiplicands);
        let result = random_product(nv, num_multiplicands, rng);
        comb.add_product(result.0.into_iter());
        sum += result.1;
    }

    (comb, sum)
}

fn test_polynomial(nv: usize, num_multiplicands_range: (usize, usize), num_products: usize) {
    let mut rng = test_rng();
    let (comb, asserted_sum) =
        random_combination::<Fr, _>(nv, num_multiplicands_range, num_products, &mut rng);

    let (index_pk, index_vk) = MLSumcheck::index(&comb).expect("Fail to index");
    let proof = MLSumcheck::prove(&index_pk).expect("fail to prove");
    let subclaim = MLSumcheck::verify(&index_vk, asserted_sum, &proof).expect("fail to verify");
    assert!(
        comb.evaluate(&subclaim.point) == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}

fn test_ahp(nv: usize, num_multiplicands_range: (usize, usize), num_products: usize) {
    let mut rng = test_rng();
    let (comb, asserted_sum) =
        random_combination::<Fr, _>(nv, num_multiplicands_range, num_products, &mut rng);
    let index = AHPForMLSumcheck::index(&comb);
    let mut prover_state = AHPForMLSumcheck::prover_init(&index);
    let mut verifier_state = AHPForMLSumcheck::verifier_init(&index.info());
    let mut verifier_msg = None;
    for _ in 0..index.num_variables {
        let result = AHPForMLSumcheck::prove_round(prover_state, &verifier_msg);
        prover_state = result.1;
        let (verifier_msg2, verifier_state2) =
            AHPForMLSumcheck::verify_round(result.0, verifier_state, &mut rng);
        verifier_msg = verifier_msg2;
        verifier_state = verifier_state2;
    }
    let subclaim = AHPForMLSumcheck::check_and_generate_subclaim(verifier_state, asserted_sum)
        .expect("fail to generate subclaim");
    assert!(
        comb.evaluate(&subclaim.point) == subclaim.expected_evaluation,
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
