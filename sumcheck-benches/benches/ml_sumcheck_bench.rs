#[macro_use]
extern crate criterion;

use ark_ff::Field;
use ark_linear_sumcheck::ml_sumcheck::protocol::ListOfProductsOfPolynomials;
use ark_linear_sumcheck::ml_sumcheck::MLSumcheck;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::ops::Range;
use ark_std::rc::Rc;
use ark_std::test_rng;
use criterion::{black_box, BenchmarkId, Criterion};

const NUM_VARIABLES_RANGE: Range<usize> = 10..21;

fn prove_bench<F: Field>(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("Prove");
    for nv in NUM_VARIABLES_RANGE {
        group.bench_with_input(BenchmarkId::new("ML", nv), &nv, |b, &nv| {
            let product_1: Vec<_> = (0..3)
                .map(|_| Rc::new(DenseMultilinearExtension::<F>::rand(nv, &mut rng)))
                .collect();
            let product_2: Vec<_> = (0..3)
                .map(|_| Rc::new(DenseMultilinearExtension::<F>::rand(nv, &mut rng)))
                .collect();
            let coefficient_1 = F::rand(&mut rng);
            let coefficient_2 = F::rand(&mut rng);
            let mut products = ListOfProductsOfPolynomials::new(nv);
            products.add_product(product_1, coefficient_1);
            products.add_product(product_2, coefficient_2);
            b.iter(|| MLSumcheck::prove(black_box(&products)));
        });
    }
}

fn verify_bench<F: Field>(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("Verify");
    for nv in NUM_VARIABLES_RANGE {
        group.bench_with_input(BenchmarkId::new("ML", nv), &nv, |b, &nv| {
            let product_1: Vec<_> = (0..3)
                .map(|_| Rc::new(DenseMultilinearExtension::<F>::rand(nv, &mut rng)))
                .collect();
            let product_2: Vec<_> = (0..3)
                .map(|_| Rc::new(DenseMultilinearExtension::<F>::rand(nv, &mut rng)))
                .collect();
            let coefficient_1 = F::rand(&mut rng);
            let coefficient_2 = F::rand(&mut rng);
            // calculate expected sum
            let mut products = ListOfProductsOfPolynomials::new(nv);
            products.add_product(product_1, coefficient_1);
            products.add_product(product_2, coefficient_2);
            let proof = MLSumcheck::prove(&products).unwrap();
            let expected_sum = MLSumcheck::extract_sum(&proof);
            b.iter(|| {
                MLSumcheck::verify(&products.info(), black_box(expected_sum), &proof).unwrap()
            });
        });
    }
}

fn bench_bls_381(c: &mut Criterion) {
    prove_bench::<ark_test_curves::bls12_381::Fr>(c);
    verify_bench::<ark_test_curves::bls12_381::Fr>(c);
}

criterion_group!(benches, bench_bls_381);
criterion_main!(benches);
