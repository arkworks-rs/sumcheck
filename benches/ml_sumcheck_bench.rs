#[macro_use]
extern crate criterion;

use ark_ff::Field;
use ark_linear_sumcheck::ml_sumcheck::ahp::ProductsOfMLExtensions;
use ark_linear_sumcheck::ml_sumcheck::MLSumcheck;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::ops::Range;
use ark_std::test_rng;
use criterion::{black_box, BenchmarkId, Criterion};

const NUM_VARIABLES_RANGE: Range<usize> = 10..21;

fn prove_bench<F: Field>(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("Prove");
    for nv in NUM_VARIABLES_RANGE {
        group.bench_with_input(
            BenchmarkId::new("Prove with 3 multiplicands", nv),
            &nv,
            |b, &nv| {
                let polys: Vec<_> = (0..3)
                    .map(|_| DenseMultilinearExtension::<F>::rand(nv, &mut rng))
                    .collect();
                let mut products = ProductsOfMLExtensions::new(nv);
                products.add_product(polys);
                let (pk, _) = MLSumcheck::index(&products).unwrap();
                b.iter(|| MLSumcheck::prove(black_box(&pk)));
            },
        );
    }
}

fn verify_bench<F: Field>(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("Verify");
    for nv in NUM_VARIABLES_RANGE {
        group.bench_with_input(
            BenchmarkId::new("Verify with 3 multiplicands", nv),
            &nv,
            |b, &nv| {
                let polys: Vec<_> = (0..3)
                    .map(|_| DenseMultilinearExtension::<F>::rand(nv, &mut rng))
                    .collect();
                // calculate expected sum
                let expected_sum = expected_sum(&polys);
                let mut products = ProductsOfMLExtensions::new(nv);
                products.add_product(polys);
                let (pk, vk) = MLSumcheck::index(&products).unwrap();
                let proof = MLSumcheck::prove(&pk).unwrap();
                b.iter(|| MLSumcheck::verify(&vk, black_box(expected_sum), &proof));
            },
        );
    }
}

fn expected_sum<F: Field>(poly: &[DenseMultilinearExtension<F>]) -> F {
    let mut sum = F::zero();
    let nv = poly[0].num_vars;
    for x in 0..(1 << nv) {
        let mut product = F::one();
        for i in 0..poly.len() {
            let val = poly[i][x];
            product *= val;
        }
        sum += product;
    }
    sum
}

fn bench_bls_381(c: &mut Criterion) {
    prove_bench::<ark_test_curves::bls12_381::Fr>(c);
    verify_bench::<ark_test_curves::bls12_381::Fr>(c);
}

criterion_group!(benches, bench_bls_381);
criterion_main!(benches);
