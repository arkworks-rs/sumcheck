#[macro_use]
extern crate criterion;

use ark_ff::Field;
use ark_linear_sumcheck::{
    gkr_round_sumcheck::GKRRoundSumcheck,
    rng::{Blake2s512Rng, FeedableRNG},
};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_std::ops::Range;
use criterion::{black_box, BenchmarkId, Criterion};

const NUM_VARIABLES_RANGE: Range<usize> = 10..21;

fn prove_bench<F: Field>(c: &mut Criterion) {
    let mut rng = Blake2s512Rng::setup();

    let mut group = c.benchmark_group("Prove");
    for nv in NUM_VARIABLES_RANGE {
        group.bench_with_input(BenchmarkId::new("GKR", nv), &nv, |b, &nv| {
            let f1 = SparseMultilinearExtension::rand_with_config(3 * nv, 1 << nv, &mut rng);
            let f2 = DenseMultilinearExtension::rand(nv, &mut rng);
            let f3 = DenseMultilinearExtension::rand(nv, &mut rng);
            let g: Vec<_> = (0..nv).map(|_| F::rand(&mut rng)).collect();
            b.iter(|| {
                GKRRoundSumcheck::prove(
                    &mut rng,
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
    let mut rng = Blake2s512Rng::setup();

    let mut group = c.benchmark_group("Verify");
    for nv in NUM_VARIABLES_RANGE {
        group.bench_with_input(BenchmarkId::new("GKR", nv), &nv, |b, &nv| {
            let f1 = SparseMultilinearExtension::rand_with_config(3 * nv, 1 << nv, &mut rng);
            let f2 = DenseMultilinearExtension::rand(nv, &mut rng);
            let f3 = DenseMultilinearExtension::rand(nv, &mut rng);
            let g: Vec<_> = (0..nv).map(|_| F::rand(&mut rng)).collect();
            let proof = GKRRoundSumcheck::prove(&mut rng, &f1, &f2, &f3, &g);
            let expected_sum = proof.extract_sum();
            b.iter(|| GKRRoundSumcheck::verify(&mut rng, f2.num_vars, &proof, expected_sum));
        });
    }
}

fn bench_bls_381(c: &mut Criterion) {
    prove_bench::<ark_test_curves::bls12_381::Fr>(c);
    verify_bench::<ark_test_curves::bls12_381::Fr>(c);
}

criterion_group!(benches, bench_bls_381);
criterion_main!(benches);
