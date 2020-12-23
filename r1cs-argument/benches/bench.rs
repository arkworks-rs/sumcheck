#[macro_use]
extern crate criterion;
#[macro_use]
extern crate json;

use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_std::fs::File;
use ark_std::io::Write;
use ark_std::ops::Range;
use ark_std::test_rng;
use criterion::{BenchmarkId, Criterion};
use r1cs_argument::ahp::MLProofForR1CS;
use r1cs_argument::test_utils::generate_circuit_with_random_input;
use r1cs_argument::MLArgumentForR1CS;

type E = Bls12_381;
const LOG_NUM_CONSTRAINTS: Range<usize> = 10..21;
fn setup_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Setup");
    let mut rng = test_rng();

    for log_num_constraint in LOG_NUM_CONSTRAINTS {
        group.bench_with_input(
            BenchmarkId::new("Setup", log_num_constraint),
            &log_num_constraint,
            |b, i| {
                b.iter(|| {
                    MLProofForR1CS::<E>::setup(*i, &mut rng).expect("fail to setup");
                })
            },
        );
    }
    group.finish();
}

fn prove_bench(c: &mut Criterion) {
    let offset = LOG_NUM_CONSTRAINTS.start;
    let mut rng = test_rng();
    let parameters: Vec<_> = LOG_NUM_CONSTRAINTS
        .map(|nv| MLProofForR1CS::<E>::setup(nv, &mut rng).expect("fail to setup"))
        .collect();
    let circuits: Vec<_> = LOG_NUM_CONSTRAINTS
        .map(|nv| {
            generate_circuit_with_random_input::<<E as PairingEngine>::Fr, _>(
                32,
                (1 << nv) - 32,
                true,
                0,
                &mut rng,
            )
        })
        .collect();
    let pks: Vec<_> = circuits
        .iter()
        .map(|(cs, _, _)| {
            let matrices = cs.to_matrices().unwrap();
            MLArgumentForR1CS::<E>::index(matrices.a, matrices.b, matrices.c)
                .expect("Fail to index")
        })
        .collect();
    let mut group = c.benchmark_group("Prove");
    for log_num_constraint in LOG_NUM_CONSTRAINTS {
        group.bench_with_input(
            BenchmarkId::new("Prove", log_num_constraint),
            &log_num_constraint,
            |b, &nv| {
                b.iter(|| {
                    let v = circuits[nv - offset].1.clone();
                    let w = circuits[nv - offset].2.clone();
                    let pk = pks[nv - offset].clone();
                    let pp = &parameters[nv - offset].0;
                    assert_eq!(pk.log_n, nv);
                    assert_eq!(v.len() + w.len(), 1 << nv);
                    MLArgumentForR1CS::prove(pk, v, w, pp).expect("fail to prove")
                })
            },
        );
    }
}

fn verify_bench(c: &mut Criterion) {
    let mut rng = test_rng();
    let offset = LOG_NUM_CONSTRAINTS.start;
    let parameters: Vec<_> = LOG_NUM_CONSTRAINTS
        .map(|nv| MLProofForR1CS::<E>::setup(nv, &mut rng).expect("fail to setup"))
        .collect();
    let circuits: Vec<_> = LOG_NUM_CONSTRAINTS
        .map(|nv| {
            generate_circuit_with_random_input::<<E as PairingEngine>::Fr, _>(
                32,
                (1 << nv) - 32,
                true,
                0,
                &mut rng,
            )
        })
        .collect();
    let pks: Vec<_> = circuits
        .iter()
        .map(|(cs, _, _)| {
            let matrices = cs.to_matrices().unwrap();
            MLArgumentForR1CS::<E>::index(matrices.a, matrices.b, matrices.c)
                .expect("Fail to index")
        })
        .collect();
    let mut group = c.benchmark_group("Verify");
    let proofs: Vec<_> = LOG_NUM_CONSTRAINTS
        .map(|nv| {
            let v = circuits[nv - offset].1.clone();
            let w = circuits[nv - offset].2.clone();
            let pk = pks[nv - offset].clone();
            let pp = &parameters[nv - offset].0;
            assert_eq!(pk.log_n, nv);
            assert_eq!(v.len() + w.len(), 1 << nv);
            MLArgumentForR1CS::prove(pk, v, w, pp).expect("fail to prove")
        })
        .collect();
    for log_num_constraint in LOG_NUM_CONSTRAINTS {
        group.bench_with_input(
            BenchmarkId::new("Verify", log_num_constraint),
            &log_num_constraint,
            |b, &nv| {
                b.iter(|| {
                    let vk = pks[nv - offset].vk();
                    let v = circuits[nv - offset].1.clone();
                    let proof = proofs[nv - offset].clone();
                    let vp = &parameters[nv - offset].1;
                    MLArgumentForR1CS::verify(vk, v, proof, vp)
                })
            },
        );
    }
}

fn communication_bench(_c: &mut Criterion) {
    use ark_serialize::CanonicalSerialize;

    let mut target_file =
        File::create("target/criterion/comm_bench_result.json").expect("cannot create file");
    let mut rng = test_rng();
    let offset = LOG_NUM_CONSTRAINTS.start;
    let parameters: Vec<_> = LOG_NUM_CONSTRAINTS
        .map(|nv| MLProofForR1CS::<E>::setup(nv, &mut rng).expect("fail to setup"))
        .collect();
    let circuits: Vec<_> = LOG_NUM_CONSTRAINTS
        .map(|nv| {
            generate_circuit_with_random_input::<<E as PairingEngine>::Fr, _>(
                32,
                (1 << nv) - 32,
                true,
                0,
                &mut rng,
            )
        })
        .collect();
    let pks: Vec<_> = circuits
        .iter()
        .map(|(cs, _, _)| {
            let matrices = cs.to_matrices().unwrap();
            MLArgumentForR1CS::<E>::index(matrices.a, matrices.b, matrices.c)
                .expect("Fail to index")
        })
        .collect();
    let proofs: Vec<_> = LOG_NUM_CONSTRAINTS
        .map(|nv| {
            let v = circuits[nv - offset].1.clone();
            let w = circuits[nv - offset].2.clone();
            let pk = pks[nv - offset].clone();
            let pp = &parameters[nv - offset].0;
            assert_eq!(pk.log_n, nv);
            assert_eq!(v.len() + w.len(), 1 << nv);
            MLArgumentForR1CS::prove(pk, v, w, pp).expect("fail to prove")
        })
        .collect();
    let mut statistics = Vec::new();
    for nv in LOG_NUM_CONSTRAINTS {
        let i = nv - offset;
        let comm_cost: usize = proofs[i].serialized_size();
        statistics.push(object! {
            nv: nv,
            comm_cost: comm_cost
        })
    }
    let json_data = json::stringify(statistics);
    target_file
        .write(json_data.as_bytes())
        .expect("cannot write");
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = setup_bench,prove_bench,verify_bench,communication_bench
}
criterion_main!(benches);
