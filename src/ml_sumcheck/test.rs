use crate::ml_sumcheck::{
    data_structures::ListOfProductsOfPolynomials, protocol::IPForMLSumcheck, MLSumcheck,
};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_std::{
    rand::{Rng, RngCore},
    rc::Rc,
    test_rng,
    vec::Vec,
    UniformRand,
};

fn random_product<F: PrimeField, R: RngCore>(
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
            .map(|x| Rc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
            .collect(),
        sum,
    );
}

fn random_list_of_products<F: PrimeField, R: RngCore>(
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
    let sponge_param = poseidon_parameters();
    let mut sponge = PoseidonSponge::new(&sponge_param);
    let proof = MLSumcheck::prove(&mut sponge.clone(), &poly).expect("fail to prove");
    let subclaim =
        MLSumcheck::verify(&mut sponge, &poly_info, asserted_sum, &proof).expect("fail to verify");
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
    let mut sponge = PoseidonSponge::new(&poseidon_parameters());
    for _ in 0..poly.num_variables {
        let result = IPForMLSumcheck::prove_round(prover_state, &verifier_msg);
        prover_state = result.1;
        let (verifier_msg2, verifier_state2) =
            IPForMLSumcheck::verify_round(result.0, verifier_state, &mut sponge);
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
    test_protocol(nv, num_multiplicands_range, num_products);
}
#[test]
fn test_normal_polynomial() {
    let nv = 12;
    let num_multiplicands_range = (4, 9);
    let num_products = 5;

    test_polynomial(nv, num_multiplicands_range, num_products);
    test_protocol(nv, num_multiplicands_range, num_products);
}
#[test]
#[should_panic]
fn zero_polynomial_should_error() {
    let nv = 0;
    let num_multiplicands_range = (4, 13);
    let num_products = 5;

    test_polynomial(nv, num_multiplicands_range, num_products);
    test_protocol(nv, num_multiplicands_range, num_products);
}

#[test]
fn test_extract_sum() {
    let mut rng = test_rng();
    let (poly, asserted_sum) = random_list_of_products::<Fr, _>(8, (3, 4), 3, &mut rng);
    let sponge_param = poseidon_parameters();
    let mut sponge = PoseidonSponge::new(&sponge_param);
    let proof = MLSumcheck::prove(&mut sponge, &poly).expect("fail to prove");
    assert_eq!(MLSumcheck::extract_sum(&proof), asserted_sum);
}

#[test]
/// Test that the memory usage of shared-reference is linear to number of unique
/// MLExtensions instead of total number of multiplicands.
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
    let sponge_param = poseidon_parameters();
    let proof =
        MLSumcheck::prove(&mut PoseidonSponge::new(&sponge_param), &poly).expect("fail to prove");
    let asserted_sum = MLSumcheck::extract_sum(&proof);
    let subclaim = MLSumcheck::verify(
        &mut PoseidonSponge::new(&sponge_param),
        &poly_info,
        asserted_sum,
        &proof,
    )
    .expect("fail to verify");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}

pub(crate) fn poseidon_parameters() -> PoseidonConfig<Fr> {
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha = 5;
    let rate = 2;

    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        <Fr as PrimeField>::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds,
        partial_rounds,
        0,
    );

    PoseidonConfig::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        rate,
        1,
    )
}
