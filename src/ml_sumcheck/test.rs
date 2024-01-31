use crate::ml_sumcheck::data_structures::ListOfProductsOfPolynomials;
use crate::ml_sumcheck::protocol::IPForMLSumcheck;
use crate::ml_sumcheck::MLSumcheck;
use crate::rng::Blake2b512Rng;
use crate::rng::FeedableRNG;
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::rand::Rng;
use ark_std::rand::RngCore;
use ark_std::rc::Rc;
use ark_std::vec::Vec;
use ark_std::{test_rng, UniformRand};
use ark_test_curves::bls12_381::Fr;

fn random_product<F: Field, R: RngCore>(
    nv: usize,
    num_multiplicands: usize,
    rng: &mut R,
) -> (Vec<Rc<DenseMultilinearExtension<F>>>, F) {
    let mut multiplicands = Vec::with_capacity(num_multiplicands);
    for _ in 0..num_multiplicands {
        multiplicands.push(Vec::with_capacity(1 << nv))
    }
    let mut sum = F::zero();

    for _ in 0..(1 << nv) {
        let mut product = F::one();
        for multiplicand in &mut multiplicands {
            let val = F::rand(rng);
            multiplicand.push(val);
            product *= val;
        }
        sum += product;
    }

    (
        multiplicands
            .into_iter()
            .map(|x| Rc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
            .collect(),
        sum,
    )
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
        let num_multiplicands = rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
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

fn test_protocol(nv: usize, num_multiplicands_range: (usize, usize), num_products: usize) {
    let mut rng = test_rng();
    let (poly, asserted_sum) =
        random_list_of_products::<Fr, _>(nv, num_multiplicands_range, num_products, &mut rng);
    let poly_info = poly.info();
    let mut prover_state = IPForMLSumcheck::prover_init(&poly);
    let mut verifier_state = IPForMLSumcheck::verifier_init(&poly_info);
    let mut verifier_msg = None;
    for _ in 0..poly.num_variables {
        let prover_message = IPForMLSumcheck::prove_round(&mut prover_state, &verifier_msg);
        let verifier_msg2 =
            IPForMLSumcheck::verify_round(prover_message, &mut verifier_state, &mut rng);
        verifier_msg = verifier_msg2;
    }
    let subclaim = IPForMLSumcheck::check_and_generate_subclaim(verifier_state, asserted_sum)
        .expect("fail to generate subclaim");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}

fn test_polynomial_as_subprotocol(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
    prover_rng: &mut impl FeedableRNG<Error = crate::Error>,
    verifier_rng: &mut impl FeedableRNG<Error = crate::Error>,
) {
    let mut rng = test_rng();
    let (poly, asserted_sum) =
        random_list_of_products::<Fr, _>(nv, num_multiplicands_range, num_products, &mut rng);
    let poly_info = poly.info();
    let (proof, prover_state) =
        MLSumcheck::prove_as_subprotocol(prover_rng, &poly).expect("fail to prove");
    let subclaim =
        MLSumcheck::verify_as_subprotocol(verifier_rng, &poly_info, asserted_sum, &proof)
            .expect("fail to verify");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluation,
        "wrong subclaim"
    );
    assert_eq!(prover_state.randomness, subclaim.point);
}

#[test]
fn test_trivial_polynomial() {
    let nv = 1;
    let num_multiplicands_range = (4, 13);
    let num_products = 5;

    for _ in 0..10 {
        test_polynomial(nv, num_multiplicands_range, num_products);
        test_protocol(nv, num_multiplicands_range, num_products);

        let mut prover_rng = Blake2b512Rng::setup();
        prover_rng.feed(b"Test Trivial Works").unwrap();
        let mut verifier_rng = Blake2b512Rng::setup();
        verifier_rng.feed(b"Test Trivial Works").unwrap();
        test_polynomial_as_subprotocol(
            nv,
            num_multiplicands_range,
            num_products,
            &mut prover_rng,
            &mut verifier_rng,
        )
    }
}
#[test]
fn test_normal_polynomial() {
    let nv = 12;
    let num_multiplicands_range = (4, 9);
    let num_products = 5;

    for _ in 0..10 {
        test_polynomial(nv, num_multiplicands_range, num_products);
        test_protocol(nv, num_multiplicands_range, num_products);

        let mut prover_rng = Blake2b512Rng::setup();
        prover_rng.feed(b"Test Trivial Works").unwrap();
        let mut verifier_rng = Blake2b512Rng::setup();
        verifier_rng.feed(b"Test Trivial Works").unwrap();
        test_polynomial_as_subprotocol(
            nv,
            num_multiplicands_range,
            num_products,
            &mut prover_rng,
            &mut verifier_rng,
        )
    }
}
#[test]
#[should_panic]
fn test_normal_polynomial_different_transcripts_fails() {
    let nv = 12;
    let num_multiplicands_range = (4, 9);
    let num_products = 5;

    let mut prover_rng = Blake2b512Rng::setup();
    prover_rng.feed(b"Test Trivial Works").unwrap();
    let mut verifier_rng = Blake2b512Rng::setup();
    verifier_rng.feed(b"Test Trivial Fails").unwrap();
    test_polynomial_as_subprotocol(
        nv,
        num_multiplicands_range,
        num_products,
        &mut prover_rng,
        &mut verifier_rng,
    )
}
#[test]
#[should_panic]
fn zero_polynomial_should_error() {
    let nv = 0;
    let num_multiplicands_range = (4, 13);
    let num_products = 5;

    test_polynomial(nv, num_multiplicands_range, num_products);
}
#[test]
#[should_panic]
fn zero_polynomial_protocol_should_error() {
    let nv = 0;
    let num_multiplicands_range = (4, 13);
    let num_products = 5;

    test_protocol(nv, num_multiplicands_range, num_products);
}

#[test]
fn test_extract_sum() {
    let mut rng = test_rng();
    let (poly, asserted_sum) = random_list_of_products::<Fr, _>(8, (3, 4), 3, &mut rng);

    let proof = MLSumcheck::prove(&poly).expect("fail to prove");
    assert_eq!(MLSumcheck::extract_sum(&proof), asserted_sum);
}

#[test]
/// Test that the memory usage of shared-reference is linear to number of unique MLExtensions
/// instead of total number of multiplicands.
fn test_shared_reference() {
    let mut rng = test_rng();
    let ml_extensions: Vec<_> = (0..5)
        .map(|_| Rc::new(DenseMultilinearExtension::<Fr>::rand(8, &mut rng)))
        .collect();
    let mut poly = ListOfProductsOfPolynomials::new(8);
    poly.add_product(
        vec![
            ml_extensions[2].clone(),
            ml_extensions[3].clone(),
            ml_extensions[0].clone(),
        ],
        Fr::rand(&mut rng),
    );
    poly.add_product(
        vec![
            ml_extensions[1].clone(),
            ml_extensions[4].clone(),
            ml_extensions[4].clone(),
        ],
        Fr::rand(&mut rng),
    );
    poly.add_product(
        vec![
            ml_extensions[3].clone(),
            ml_extensions[2].clone(),
            ml_extensions[1].clone(),
        ],
        Fr::rand(&mut rng),
    );
    poly.add_product(
        vec![ml_extensions[0].clone(), ml_extensions[0].clone()],
        Fr::rand(&mut rng),
    );
    poly.add_product(vec![ml_extensions[4].clone()], Fr::rand(&mut rng));

    assert_eq!(poly.flattened_ml_extensions.len(), 5);

    // test memory usage for prover
    let prover = IPForMLSumcheck::prover_init(&poly);
    assert_eq!(prover.flattened_ml_extensions.len(), 5);
    drop(prover);

    let poly_info = poly.info();
    let proof = MLSumcheck::prove(&poly).expect("fail to prove");
    let asserted_sum = MLSumcheck::extract_sum(&proof);
    let subclaim = MLSumcheck::verify(&poly_info, asserted_sum, &proof).expect("fail to verify");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}
