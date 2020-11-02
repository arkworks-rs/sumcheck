use crate::data_structures::ml_extension::ArithmeticCombination;
use crate::data_structures::test_field::TestField;
use crate::data_structures::MLExtensionArray;
use crate::ml_sumcheck::ahp::AHPForMLSumcheck;
use crate::ml_sumcheck::MLSumcheck;
use ark_ff::{test_rng, Field};
use ark_std::cmp::max;
use rand::Rng;
use rand_core::RngCore;

fn random_product<F: Field, R: RngCore>(
    nv: usize,
    num_multiplicands: usize,
    rng: &mut R,
) -> (Vec<MLExtensionArray<F>>, F) {
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
            .map(|x| MLExtensionArray::from_vec(x).unwrap())
            .collect(),
        sum,
    );
}

fn random_combination<F: Field, R: RngCore>(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
    rng: &mut R,
) -> (ArithmeticCombination<F, MLExtensionArray<F>>, F) {
    let mut max_num_multiplicands = 0;
    let mut sum = F::zero();
    let mut comb = ArithmeticCombination::new(nv);
    for _ in 0..num_products {
        let num_multiplicands = rng.gen_range(num_multiplicands_range.0, num_multiplicands_range.1);
        max_num_multiplicands = max(num_multiplicands, max_num_multiplicands);
        let result = random_product::<F, _>(nv, num_multiplicands, rng);
        comb.add_product(result.0.into_iter()).unwrap();
        sum += result.1;
    }

    (comb, sum)
}

fn test_polynomial(nv: usize, num_multiplicands_range: (usize, usize), num_products: usize) {
    let mut rng = test_rng();
    type F = TestField;
    let (comb, asserted_sum) =
        random_combination::<F, _>(nv, num_multiplicands_range, num_products, &mut rng);

    let (index_pk, index_vk) = MLSumcheck::index(&comb).expect("Fail to index");
    let proof = MLSumcheck::prove(&index_pk).expect("fail to prove");
    let subclaim = MLSumcheck::verify(&index_vk, asserted_sum, &proof).expect("fail to verify");
    assert!(
        comb.eval_at(&subclaim.point).expect("fail to evaluate") == subclaim.expected_evaluation,
        "wrong subclaim"
    );
}

fn test_ahp(nv: usize, num_multiplicands_range: (usize, usize), num_products: usize) {
    let mut rng = test_rng();
    type F = TestField;
    let (comb, asserted_sum) =
        random_combination::<F, _>(nv, num_multiplicands_range, num_products, &mut rng);
    let index = AHPForMLSumcheck::index(&comb).expect("fail to index");
    let mut prover_state = AHPForMLSumcheck::prover_init(&index);
    let mut verifier_state = AHPForMLSumcheck::verifier_init(&index.info(), asserted_sum);
    let mut verifier_msg = None;
    for _ in 0..index.num_variables {
        let result =
            AHPForMLSumcheck::prove_round(prover_state, &verifier_msg).expect("fail to prove");
        prover_state = result.1;
        let (verifier_msg2, verifier_state2) =
            AHPForMLSumcheck::verify_round(&result.0, verifier_state, &mut rng)
                .expect("fail to verify round");
        verifier_msg = verifier_msg2;
        verifier_state = verifier_state2;
    }
    let subclaim = AHPForMLSumcheck::subclaim(verifier_state).expect("fail to generate subclaim");
    assert!(
        comb.eval_at(&subclaim.point).expect("fail to evaluate") == subclaim.expected_evaluation,
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
    let nv = 10;
    let num_multiplicands_range = (4, 9);
    let num_products = 4;

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
