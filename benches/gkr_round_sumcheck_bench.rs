#[macro_use]
extern crate criterion;

use ark_ff::Field;
use ark_linear_sumcheck::gkr_round_sumcheck::GKRRoundSumcheck;
use ark_linear_sumcheck::ml_sumcheck::ahp::ProductsOfMLExtensions;
use ark_linear_sumcheck::ml_sumcheck::MLSumcheck;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_std::ops::Range;
use ark_std::test_rng;
use criterion::{black_box, BenchmarkId, Criterion};

const NUM_VARIABLES_RANGE: Range<usize> = 10..21;

fn prove_bench<F: Field>(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("Prove");
    for nv in NUM_VARIABLES_RANGE {
        group.bench_with_input(BenchmarkId::new("Prove", nv), &nv, |b, &nv| {
            let f1 = SparseMultilinearExtension::rand_with_config(3 * nv, 1 << nv, &mut rng);
            let f2 = DenseMultilinearExtension::rand(nv, &mut rng);
            let f3 = DenseMultilinearExtension::rand(nv, &mut rng);
            let g: Vec<_> = (0..nv).map(|_| F::rand(&mut rng)).collect();
            b.iter(|| {
                GKRRoundSumcheck::prove(
                    black_box(&f1),
                    black_box(&f2),
                    black_box(&f3),
                    black_box(&g),
                )
            });
        });
    }
}

fn verify_bench<F: Field>(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("Verify");
    for nv in NUM_VARIABLES_RANGE {
        group.bench_with_input(
            BenchmarkId::new("Verify (output subclaim)", nv),
            &nv,
            |b, &nv| {
                let f1 = SparseMultilinearExtension::rand_with_config(3 * nv, 1 << nv, &mut rng);
                let f2 = DenseMultilinearExtension::rand(nv, &mut rng);
                let f3 = DenseMultilinearExtension::rand(nv, &mut rng);
                let g: Vec<_> = (0..nv).map(|_| F::rand(&mut rng)).collect();
                let expected_sum = calculate_sum(&f1, &f2, &f3, &g);
                let proof = GKRRoundSumcheck::prove(&f1, &f2, &f3, &g);
                b.iter(|| GKRRoundSumcheck::verify(f2.num_vars, &proof, expected_sum));
            },
        );
    }
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

fn bench_bls_381(c: &mut Criterion) {
    prove_bench::<ark_test_curves::bls12_381::Fr>(c);
    verify_bench::<ark_test_curves::bls12_381::Fr>(c);
}

criterion_group!(benches, bench_bls_381);
criterion_main!(benches);
