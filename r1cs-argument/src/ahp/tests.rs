use crate::ahp::MLProofForR1CS;
use crate::error::SResult;
use crate::test_utils::{generate_circuit_with_random_input, TestCurve, TestCurveFr};
use ark_ff::test_rng;
use rand::RngCore;
use crate::commitment::MLPolyCommit;

fn test_circuit<R: RngCore>(log_n: usize, log_v: usize, rng: &mut R) -> SResult<()> {
    let num_public = 1 << log_v;
    let num_private = (1 << log_n) - num_public;

    let (pp, vp, _) = MLPolyCommit::keygen(log_n, rng)?;

    let (r1cs, v, w) =
        generate_circuit_with_random_input::<TestCurveFr, _>(num_public, num_private, true, 1, rng);

    let matrices = r1cs.to_matrices().unwrap();
    let pk = MLProofForR1CS::<TestCurve>::index(matrices.a, matrices.b, matrices.c)?;

    let vk = pk.vk();

    let ps = MLProofForR1CS::<TestCurve>::prover_init(pk, v.to_vec(), w)?;
    let vs = MLProofForR1CS::verifier_init(vk, v)?;

    let (ps, pm) = MLProofForR1CS::prover_first_round(ps, &pp)?;
    let (vs, vm) = MLProofForR1CS::verify_first_round(vs, pm, rng)?;

    let (ps, pm) = MLProofForR1CS::prover_second_round(ps, vm, &pp)?;
    let (vs, vm) = MLProofForR1CS::verify_second_round(vs, pm, rng)?;

    let (mut ps, pm) = MLProofForR1CS::prover_third_round(ps, vm)?;
    let (mut vs, mut vm) = MLProofForR1CS::verify_third_round(vs, pm)?;

    for _ in 0..(log_n - 1) {
        let (ps_new, pm) = MLProofForR1CS::prove_first_sumcheck_round(ps, vm)?;
        ps = ps_new;
        let (vs_new, vm_new) = MLProofForR1CS::verify_first_sumcheck_ongoing_round(vs, pm, rng)?;
        vs = vs_new;
        vm = vm_new;
    }

    let (ps, pm) = MLProofForR1CS::prove_first_sumcheck_round(ps, vm)?;
    let (vs, vm) = MLProofForR1CS::verify_first_sumcheck_final_round(vs, pm, rng)?;

    let (ps, pm) = MLProofForR1CS::prove_fourth_round(ps, vm)?;
    let (vs, vm) = MLProofForR1CS::verify_fourth_round(vs, pm, rng)?;

    let (mut ps, pm) = MLProofForR1CS::prove_fifth_round(ps, vm)?;
    let (mut vs, mut vm) = MLProofForR1CS::verify_fifth_round(vs, pm)?;

    for _ in 0..(log_n - 1) {
        let (ps_new, pm) = MLProofForR1CS::prove_second_sumcheck_round(ps, vm)?;
        ps = ps_new;
        let (vs_new, vm_new) = MLProofForR1CS::verify_second_sumcheck_ongoing_round(vs, pm, rng)?;
        vs = vs_new;
        vm = vm_new;
    }

    let (ps, pm) = MLProofForR1CS::prove_second_sumcheck_round(ps, vm)?;
    let (vs, vm) = MLProofForR1CS::verify_second_sumcheck_final_round(vs, pm, rng)?;

    let pm = MLProofForR1CS::prove_sixth_round(ps, vm, &pp)?;
    let result = MLProofForR1CS::verify_sixth_round(vs, pm, &vp)?;

    if result {
        Ok(())
    } else {
        Err(crate::Error::WrongWitness(Some("cannot verify".into())))
    }
}

#[test]
fn test_small() {
    test_circuit(8, 2, &mut test_rng()).expect("fail to test small");
}
