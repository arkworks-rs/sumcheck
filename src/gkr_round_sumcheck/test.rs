use crate::gkr_round_sumcheck::GKRRoundSumcheck;
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_std::test_rng;
use ark_test_curves::bls12_381::Fr;
use rand_core::RngCore;

fn random_gkr_instance<F: Field, R: RngCore>(
    dim: usize,
    rng: &mut R,
) -> (
    SparseMultilinearExtension<F>,
    DenseMultilinearExtension<F>,
    DenseMultilinearExtension<F>,
) {
    (
        SparseMultilinearExtension::rand_with_config(dim * 3, 1 << dim, rng),
        DenseMultilinearExtension::rand(dim, rng),
        DenseMultilinearExtension::rand(dim, rng),
    )
}

fn calculate_sum<F: Field>(
    f1: &SparseMultilinearExtension<F>,
    f2: &DenseMultilinearExtension<F>,
    f3: &DenseMultilinearExtension<F>,
    g: &[F],
) -> F {
    let dim = f2.num_vars;
    assert_eq!(f1.num_vars, 3 * dim);
    assert_eq!(f3.num_vars, dim);
    let f1_g = f1.fix_variables(g);
    let mut sum_xy = F::zero();
    for x in 0..(1 << dim) {
        let f2_x = f2[x];
        let f1_gx = f1_g
            .fix_variables(&index_to_field_element(x, dim))
            .to_dense_multilinear_extension();
        for y in 0..(1 << dim) {
            sum_xy += f1_gx[y] * f2_x * f3[y];
        }
    }
    sum_xy
}

fn index_to_field_element<F: Field>(mut index: usize, mut nv: usize) -> Vec<F> {
    let mut ans = Vec::with_capacity(nv);
    while nv != 0 {
        ans.push(((index & 1) as u64).into());
        index >>= 1;
        nv -= 1;
    }
    ans
}

fn test_circuit<F: Field>(nv: usize) {
    let mut rng = test_rng();
    let (f1, f2, f3) = random_gkr_instance(nv, &mut rng);
    let g: Vec<_> = (0..nv).map(|_| F::rand(&mut rng)).collect();
    let claimed_sum = calculate_sum(&f1, &f2, &f3, &g);
    let proof = GKRRoundSumcheck::prove(&f1, &f2, &f3, &g);
    let result = GKRRoundSumcheck::verify(&f1, &f2, &f3, &g, &proof, claimed_sum)
        .expect("verification failed");
    assert!(result)
}

#[test]
fn test_small() {
    test_circuit::<Fr>(9);
}
