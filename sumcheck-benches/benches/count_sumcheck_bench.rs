use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};
use ark_std::{test_rng, One};
use count_sumcheck::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::StdRng;
use std::ops::Range;

const P_RANGE: Range<usize> = 2..128;

pub struct CountBench<E: PairingEngine> {
    pub d_gap: usize,
    pub h_domain: GeneralEvaluationDomain<E::Fr>,
    pub n_h: usize,
    pub f: DensePolynomial<E::Fr>,
    pub v_f: E::Fr,
    pub srs: SRS<E>,
    pub keys: (ProverKey<E>, VerifierKey<E>),
    pub proof: Proof<E>,
    pub f_commitment: E::G1Affine,
}

fn setup<'a, E: PairingEngine>(deg_f: usize, rng: &'a mut StdRng) -> CountBench<E> {
    let d = deg_f + 1;
    let dgap = 2 * d;
    let hdomain = GeneralEvaluationDomain::new(d).unwrap();
    let nh = hdomain.size();
    // Since deg(S) = d_gap and deg(f_ipc) <= d_gap + d, deg(f) <= d see pg. 13
    let f_poly = DensePolynomial::from_coefficients_vec(vec![E::Fr::one(); deg_f]);
    let vf = f_poly
        .evaluate_over_domain_by_ref(hdomain)
        .evals
        .iter()
        .sum();
    let srs_calc = kgen(nh, d, dgap, rng);
    let keys_calc = derive_keys(&srs_calc);
    let proof_calc = prove(&keys_calc.0, &f_poly, vf);
    let f_commit = commit(&srs_calc.s1_g1, &f_poly);
    CountBench {
        d_gap: dgap,
        h_domain: hdomain,
        n_h: nh,
        f: f_poly,
        v_f: vf,
        srs: srs_calc,
        keys: keys_calc,
        proof: proof_calc,
        f_commitment: f_commit,
    }
}

fn prove_bench<E: PairingEngine>(c: &mut Criterion) {
    let rng = &mut test_rng();

    let mut p = c.benchmark_group("Prove");
    for i in P_RANGE {
        let d = setup::<E>(i, rng);
        p.bench_with_input(BenchmarkId::new("Count: Prove", i), &d, |b, d| {
            b.iter(|| prove(black_box(&d.keys.0), black_box(&d.f), black_box(d.v_f)))
        });
    }
}

fn verify_bench<E: PairingEngine>(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut v = c.benchmark_group("Verify");
    for i in P_RANGE {
        let d = setup::<E>(i, rng);
        v.bench_with_input(BenchmarkId::new("Count: Verify", i), &d, |b, d| {
            b.iter(|| {
                verify(
                    black_box(&d.keys.1),
                    black_box(&d.proof),
                    black_box(d.f_commitment),
                    black_box(d.v_f),
                )
            })
        });
    }
}

fn bench_bls_381(c: &mut Criterion) {
    prove_bench::<Bls12_381>(c);
    verify_bench::<Bls12_381>(c);
}

criterion_group!(benches, bench_bls_381);
criterion_main!(benches);
